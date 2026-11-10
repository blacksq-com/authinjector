//! The socket listener and the request pipeline.
//!
//! Order is fixed and every step can only refuse:
//!
//!   identity (kernel) -> upstream known? -> caller permitted? -> method/path
//!   allowed? -> within rate? -> inject -> forward -> audit
//!
//! 🔴 EVERY EXIT WRITES AN AUDIT LINE, refusals included. A broker that only
//! logged successes would make a caller probing the allowlist invisible, which
//! is exactly the traffic worth seeing.
//!
//! 🔴 THE FIRST PATH SEGMENT IS THE KEY'S ADDRESS, VERBATIM. `/tavily/search`
//! reaches the `default` label and `/tavily:personal/search` the `personal`
//! one, because `config::instance_key` built the map with exactly those
//! strings. There is no label-resolution step here to disagree with the one in
//! config.rs, because there is no second step at all.

use std::collections::HashMap;
use std::convert::Infallible;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixListener;

use crate::audit::{Audit, Outcome};
use crate::config::Policy;
use crate::peer::{self, Caller};
use crate::proxy::Forwarder;
use crate::ratelimit::RateLimiter;
use crate::secret::Secret;

pub struct Broker {
    pub policy: Policy,
    pub secrets: HashMap<String, Secret>,
    pub audit: Audit,
    pub limiter: RateLimiter,
    pub forwarder: Forwarder,
}

/// systemd passes an already-bound socket as fd 3 (PROTOCOL.md; see
/// authinjector.socket). Taking it from systemd means the broker never needs
/// write permission in /run and cannot widen its own access.
fn listener_from_systemd() -> Option<std::os::unix::net::UnixListener> {
    let fds: i32 = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if fds < 1 {
        return None;
    }
    // SAFETY: systemd guarantees fd 3 is a bound listening socket when
    // LISTEN_FDS >= 1, and we take ownership of it exactly once.
    Some(unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) })
}

pub async fn serve(broker: Arc<Broker>, fallback_path: Option<&Path>) -> std::io::Result<()> {
    let std_listener = match listener_from_systemd() {
        Some(l) => {
            eprintln!("authinjector: listening on the socket systemd passed (fd 3)");
            l
        }
        None => {
            let p = fallback_path.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no LISTEN_FDS from systemd and no --socket given",
                )
            })?;
            let _ = std::fs::remove_file(p);
            let l = std::os::unix::net::UnixListener::bind(p)?;
            // The same mode systemd gives the socket (SocketMode=0660): the
            // owner and its group may connect, nobody else. Without this a
            // self-bound socket (a container, a dev run) took the umask, and
            // 0755 lets no other user connect at all.
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660))?;
            }
            eprintln!("authinjector: listening on {}", p.display());
            l
        }
    };
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;

    loop {
        let (stream, _) = listener.accept().await?;

        // 🔴 Identity is read from the kernel, once, per connection, before a
        // single byte of the request is parsed.
        let caller = match peer::caller_of(&stream) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("authinjector: refusing a connection with unreadable peer creds: {e}");
                continue;
            }
        };

        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle(Arc::clone(&broker), caller.clone(), req));
            if let Err(e) = hyper::server::conn::http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("authinjector: connection error: {e}");
            }
        });
    }
}

fn plain(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(format!("{msg}\n"))))
        .unwrap()
}

fn json(status: StatusCode, v: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap()
}

/// Split `/{upstream}/{rest}` into its two parts. `{upstream}` is the whole
/// first segment, label and all: `tavily` or `tavily:personal`.
pub fn split_target(uri_path: &str) -> Option<(&str, &str)> {
    let rest = uri_path.strip_prefix('/')?;
    match rest.find('/') {
        Some(i) => Some((&rest[..i], &rest[i..])),
        None if !rest.is_empty() => Some((rest, "/")),
        None => None,
    }
}

/// The service half of an upstream id, for the "did you mean a label?" hint.
fn service_of(id: &str) -> &str {
    id.split_once(':').map(|(s, _)| s).unwrap_or(id)
}

async fn handle(
    broker: Arc<Broker>,
    caller: Caller,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let started = Instant::now();
    let method = req.method().as_str().to_string();
    let full_path = req.uri().path().to_string();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| full_path.clone());

    // Health/introspection: what this caller may do, and nothing else.
    if full_path == "/_broker/health" {
        return Ok(json(
            StatusCode::OK,
            serde_json::json!({
                "ok": true,
                "caller": caller.name,
                "upstreams": broker.policy.visible_to(&caller.name),
            }),
        ));
    }

    let ms = |s: Instant| s.elapsed().as_millis() as u64;

    // Deliver a key the broker already holds to where it is USED — a Worker's
    // secrets, a GitHub repo's or environment's. The value goes from this
    // process straight to the destination's API and is never in the answer.
    // See push.rs for why the destination allowlist belongs to the KEY.
    if full_path == "/_broker/push" {
        if method != "POST" {
            return Ok(plain(StatusCode::METHOD_NOT_ALLOWED, "POST a {source, dest} body"));
        }
        let body = match req.into_body().collect().await {
            Ok(c) => c.to_bytes().to_vec(),
            Err(_) => return Ok(plain(StatusCode::BAD_REQUEST, "could not read the request body")),
        };
        let parsed: crate::push::PushRequest = match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => {
                return Ok(plain(
                    StatusCode::BAD_REQUEST,
                    &format!("expected {{\"source\": \"…\", \"dest\": \"…\"}}: {e}"),
                ))
            }
        };

        // A Turnstile widget's secret is minted by Cloudflare, not configured
        // here: fetched and delivered in one step, never answered. See push.rs.
        if parsed.source.starts_with(crate::push::TURNSTILE_SOURCE) {
            let (sitekey, via, dest) =
                match crate::push::authorize_turnstile(&broker.policy, &caller.name, &parsed) {
                    Ok(t) => t,
                    Err((status, msg)) => {
                        let code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
                        broker.audit.record(
                            &caller.name, caller.uid, &parsed.source, "PUSH", &parsed.dest, status, 0, 0,
                            ms(started), 0.0, "-", Outcome::CallerNotPermitted,
                        );
                        return Ok(plain(code, &msg));
                    }
                };
            if !broker.limiter.check(&caller.name, &via.id, via.per_minute) {
                return Ok(plain(StatusCode::TOO_MANY_REQUESTS, "rate limit for cloudflare-rw"));
            }
            let Some(credential) = broker.secrets.get(&via.id) else {
                return Ok(plain(StatusCode::INTERNAL_SERVER_ERROR, "a configured key is missing"));
            };
            let via_ctx = crate::push::Via { forwarder: &broker.forwarder, upstream: via, credential };
            let result = crate::push::deliver_turnstile(&via_ctx, &sitekey, &dest).await;
            let (status, outcome) = if result.is_ok() { (200, Outcome::Forwarded) } else { (502, Outcome::UpstreamError) };
            broker.audit.record(
                &caller.name, caller.uid, &parsed.source, "PUSH", &dest.describe(), status, 0, 0,
                ms(started), 0.0, &via.policy_id(), outcome,
            );
            return Ok(match result {
                Ok(()) => json(
                    StatusCode::OK,
                    serde_json::json!({ "ok": true, "source": parsed.source, "dest": dest.describe(), "via": via.id }),
                ),
                Err(e) => json(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({ "ok": false, "dest": dest.describe(), "error": e.to_string() }),
                ),
            });
        }

        // Who may push what, to where. No network yet: a refusal costs nothing
        // and never touches the destination.
        let (source, via, dest) = match crate::push::authorize(&broker.policy, &caller.name, &parsed) {
            Ok(t) => t,
            Err((status, msg)) => {
                let code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
                broker.audit.record(
                    &caller.name, caller.uid, &parsed.source, "PUSH", &parsed.dest, status, 0, 0,
                    ms(started), 0.0, "-", Outcome::CallerNotPermitted,
                );
                return Ok(plain(code, &msg));
            }
        };

        // A push spends the SOURCE key's budget: one delivery, one unit. It is
        // the same limiter an ordinary call answers to, so a loop that pushes
        // cannot outrun one that fetches.
        if !broker.limiter.check(&caller.name, &source.id, source.per_minute) {
            broker.audit.record(
                &caller.name, caller.uid, &source.id, "PUSH", &dest.describe(), 429, 0, 0,
                ms(started), 0.0, &source.policy_id(), Outcome::RateLimited,
            );
            return Ok(plain(StatusCode::TOO_MANY_REQUESTS, "rate limit for this key"));
        }

        let (Some(value), Some(credential)) =
            (broker.secrets.get(&source.id), broker.secrets.get(&via.id))
        else {
            return Ok(plain(StatusCode::INTERNAL_SERVER_ERROR, "a configured key is missing"));
        };
        let via_ctx = crate::push::Via { forwarder: &broker.forwarder, upstream: via, credential };

        return Ok(match crate::push::deliver(&via_ctx, &dest, value).await {
            Ok(()) => {
                broker.audit.record(
                    &caller.name, caller.uid, &source.id, "PUSH", &dest.describe(), 200, 0, 0,
                    ms(started), 0.0, &source.policy_id(), Outcome::Forwarded,
                );
                json(
                    StatusCode::OK,
                    serde_json::json!({
                        "ok": true,
                        "source": source.id,
                        "dest": dest.describe(),
                        "via": via.id,
                    }),
                )
            }
            Err(e) => {
                broker.audit.record(
                    &caller.name, caller.uid, &source.id, "PUSH", &dest.describe(), 502, 0, 0,
                    ms(started), 0.0, &source.policy_id(), Outcome::UpstreamError,
                );
                json(
                    StatusCode::BAD_GATEWAY,
                    serde_json::json!({ "ok": false, "dest": dest.describe(), "error": e.to_string() }),
                )
            }
        });
    }

    let Some((up_id, rest)) = split_target(&full_path) else {
        broker.audit.record(&caller.name, caller.uid, "-", &method, &full_path, 404, 0, 0, ms(started), 0.0, "-", Outcome::UnknownUpstream);
        return Ok(plain(StatusCode::NOT_FOUND, "no upstream in path"));
    };

    let Some(upstream) = broker.policy.get(up_id) else {
        broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, 404, 0, 0, ms(started), 0.0, "-", Outcome::UnknownUpstream);
        // A bare `/tavily` when every Tavily key is labelled is the one
        // near-miss worth explaining: the service IS configured, just not
        // under the default label.
        let siblings = broker.policy.labels_for(service_of(up_id));
        let msg = if siblings.is_empty() {
            "unknown upstream".to_string()
        } else {
            format!("unknown upstream — configured as: {}", siblings.join(", "))
        };
        return Ok(plain(StatusCode::NOT_FOUND, &msg));
    };
    let pid = upstream.policy_id();

    if !upstream.permits_caller(&caller.name) {
        broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, 403, 0, 0, ms(started), 0.0, &pid, Outcome::CallerNotPermitted);
        return Ok(plain(StatusCode::FORBIDDEN, "caller not permitted for this upstream"));
    }

    if !upstream.permits(&method, rest) {
        // 405 when the path is known but the method is not; 403 otherwise.
        // Stage 5 test 2 distinguishes these.
        let (code, outcome) = if upstream.path_known_method_wrong(rest) {
            (StatusCode::METHOD_NOT_ALLOWED, Outcome::MethodNotAllowed)
        } else {
            (StatusCode::FORBIDDEN, Outcome::PathNotAllowed)
        };
        broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, code.as_u16(), 0, 0, ms(started), 0.0, &pid, outcome);
        return Ok(plain(code, "not allowed by policy"));
    }

    // 🔴 The bucket is the INSTANCE, so two labelled keys for one service have
    // genuinely separate quotas. Sharing one would let a caller exhaust the
    // budget of an account it may not even be permitted to use.
    if !broker.limiter.check(&caller.name, up_id, upstream.per_minute) {
        let retry = broker.limiter.retry_after(&caller.name, up_id);
        broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, 429, 0, 0, ms(started), 0.0, &pid, Outcome::RateLimited);
        let mut r = plain(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        r.headers_mut().insert("retry-after", retry.to_string().parse().unwrap());
        return Ok(r);
    }

    // Keyed by instance id: the key lives beside its own label in config.toml.
    let Some(secret) = broker.secrets.get(up_id) else {
        // Unreachable: startup refuses to serve with an unresolved ref.
        broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, 503, 0, 0, ms(started), 0.0, &pid, Outcome::UpstreamError);
        return Ok(plain(StatusCode::SERVICE_UNAVAILABLE, "credential not available"));
    };

    let in_headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
        .collect();

    let body = match req.into_body().collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(e) => {
            broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, 400, 0, 0, ms(started), 0.0, &pid, Outcome::UpstreamError);
            eprintln!("authinjector: could not read request body: {e}");
            return Ok(plain(StatusCode::BAD_REQUEST, "unreadable body"));
        }
    };
    let bytes_in = body.len();

    // The upstream path keeps the caller's query string; the audit line does
    // not (audit::path_only), which is what keeps a query-mode credential --
    // and any the caller sent -- out of the log.
    let onward = match path_and_query.strip_prefix(&format!("/{up_id}")) {
        Some("") | None => rest.to_string(),
        Some(s) => s.to_string(),
    };

    match broker.forwarder.forward(upstream, &method, &onward, &in_headers, body, secret).await {
        Ok(resp) => {
            // 🔴 Turnstile widget responses carry the widget's SECRET; it is
            // replaced before the caller sees it (push.rs::redact_turnstile).
            let (body, redacted) = crate::push::redact_turnstile(&upstream.base_url, rest, resp.body);
            let bytes_out = body.len();
            broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, resp.status, bytes_in, bytes_out, ms(started), upstream.cost_per_call_cad, &pid, Outcome::Forwarded);
            let mut out = Response::builder().status(resp.status);
            // 🔴 Strip the injected credential out of the response headers
            // before the caller sees them -- a redirect from a query-mode
            // upstream echoes the request URL, credential and all.
            for (k, v) in crate::inject::scrub_response_headers(resp.headers, upstream) {
                // hop-by-hop headers must not be forwarded verbatim
                if matches!(k.to_ascii_lowercase().as_str(), "transfer-encoding" | "connection" | "keep-alive" | "upgrade") {
                    continue;
                }
                // A rewritten body has a different length.
                if redacted && matches!(k.to_ascii_lowercase().as_str(), "content-length" | "content-encoding" | "etag") {
                    continue;
                }
                out = out.header(k, v);
            }
            Ok(out.body(Full::new(Bytes::from(body))).unwrap())
        }
        Err(e) => {
            broker.audit.record(&caller.name, caller.uid, up_id, &method, &full_path, 502, bytes_in, 0, ms(started), 0.0, &pid, Outcome::UpstreamError);
            eprintln!("authinjector: {e}");
            Ok(plain(StatusCode::BAD_GATEWAY, "upstream unreachable"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_upstream_from_the_rest_of_the_path() {
        assert_eq!(split_target("/tavily/search"), Some(("tavily", "/search")));
        assert_eq!(split_target("/psi/v5/runPagespeed"), Some(("psi", "/v5/runPagespeed")));
    }

    #[test]
    fn a_label_travels_in_the_first_segment() {
        assert_eq!(split_target("/tavily:personal/search"), Some(("tavily:personal", "/search")));
        assert_eq!(split_target("/tavily:personal"), Some(("tavily:personal", "/")));
    }

    #[test]
    fn a_colon_later_in_the_path_is_left_alone() {
        // Google's Places API really does use one: /v1/places:searchText.
        assert_eq!(
            split_target("/places/v1/places:searchText"),
            Some(("places", "/v1/places:searchText"))
        );
    }

    #[test]
    fn a_bare_upstream_targets_its_root() {
        assert_eq!(split_target("/tavily"), Some(("tavily", "/")));
    }

    #[test]
    fn a_pathless_request_has_no_upstream() {
        assert_eq!(split_target("/"), None);
        assert_eq!(split_target(""), None);
    }

    #[test]
    fn the_service_half_is_recoverable_for_the_did_you_mean_hint() {
        assert_eq!(service_of("tavily:personal"), "tavily");
        assert_eq!(service_of("tavily"), "tavily");
    }
}
