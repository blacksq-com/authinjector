//! The forwarder: one outbound HTTPS request, response returned unchanged.
//!
//! The broker is a proxy, not a client library. It parses no payloads, retries
//! nothing, and interprets no status codes. Whatever the upstream says is what
//! the caller gets.
//!
//! 🔴 THE SECRET'S LIFETIME IS ONE STATEMENT. `inject::apply` is called inside
//! the request-building expression and its output is consumed immediately.
//! Nothing holding key material is bound to a variable that outlives this
//! function.

use std::time::Duration;

use crate::config::{Auth, Upstream};
use crate::gtoken::Tokens;
use crate::inject::{self, Header};
use crate::secret::Secret;

/// What came back. Headers are returned verbatim for passthrough.
pub struct UpstreamResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub enum ProxyError {
    Build(String),
    Send(String),
    /// A `google_sa` upstream whose access token could not be minted. Separate
    /// from Send because the failure is ours, not the upstream's, and the
    /// caller should be told which.
    Token(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // 🔴 The message never includes the request headers or the URL, so
            // a transport error cannot surface a credential in a log line.
            // That matters more now that query-mode services exist: for those
            // the credential IS part of the URL, and reqwest's own error
            // Display would happily print it.
            ProxyError::Build(m) => write!(f, "could not build upstream request: {m}"),
            ProxyError::Send(m) => write!(f, "upstream unreachable: {m}"),
            ProxyError::Token(m) => write!(f, "{m}"),
        }
    }
}

pub struct Forwarder {
    client: reqwest::Client,
    /// Access tokens minted for `google_sa` upstreams, cached ~55 minutes.
    /// Empty and untouched for every other upstream.
    tokens: Tokens,
}

impl Forwarder {
    pub fn new() -> Result<Self, ProxyError> {
        let client = reqwest::Client::builder()
            // rustls, no OpenSSL: no system TLS library to keep patched and
            // nothing standing between us and a static binary.
            .use_rustls_tls()
            // Ten minutes, not one. A high-quality image edit or a whole video's narration
            // (ElevenLabs voices ~26k characters in ONE call) runs well past 60 s, and a
            // timeout here does not cancel the upstream: the work is done and billed, and
            // the caller just never receives it. Connect stays at 10 s: a dead host is
            // still reported fast.
            .timeout(Duration::from_secs(600))
            .connect_timeout(Duration::from_secs(10))
            // A proxy that followed redirects could be steered to send the
            // credential to a host the policy never allowed.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ProxyError::Build(e.to_string()))?;
        Ok(Self { client, tokens: Tokens::new() })
    }

    pub async fn forward(
        &self,
        upstream: &Upstream,
        method: &str,
        path_and_query: &str,
        headers: &[Header],
        body: Vec<u8>,
        secret: &Secret,
    ) -> Result<UpstreamResponse, ProxyError> {
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| ProxyError::Build(e.to_string()))?;

        // 🔴 A google_sa UPSTREAM IS HANDED A TOKEN, NOT ITS KEY. The stored
        // credential is a service-account JSON; it is exchanged for a
        // short-lived access token here, and only that token is passed to the
        // injector. The private key never reaches `inject::apply` and so can
        // never reach a header. Cached, so a thousand calls cost one exchange.
        let minted;
        let credential: &Secret = match &upstream.auth {
            Auth::GoogleServiceAccount { scope } => {
                minted = self
                    .tokens
                    .access_token(&self.client, &upstream.id, secret, scope)
                    .await
                    .map_err(|e| ProxyError::Token(e.to_string()))?;
                &minted
            }
            _ => secret,
        };

        // Strip-then-inject. For a query-mode service this is also what puts
        // the credential into the URL, which is why the request is built from
        // `injected.path_and_query` and never from the caller's own.
        let injected = inject::apply(headers, path_and_query, upstream, credential);
        let mut req = self
            .client
            .request(m, format!("{}{}", upstream.base_url, injected.path_and_query));
        for (name, value) in injected.headers {
            req = req.header(name, value);
        }

        let resp = req
            .body(body)
            .send()
            .await
            // 🔴 `reqwest::Error`'s Display includes the URL it was talking to.
            // For a query-mode service that URL carries the key, so the error
            // is reduced to its kind rather than rendered.
            .map_err(|e| ProxyError::Send(describe(&e)))?;

        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), s.to_string())))
            .collect();
        let body = resp.bytes().await.map_err(|e| ProxyError::Send(describe(&e)))?.to_vec();

        Ok(UpstreamResponse { status, headers, body })
    }
}

/// A transport failure described by its KIND, never by its URL.
fn describe(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "could not connect"
    } else if e.is_body() || e.is_decode() {
        "malformed response"
    } else if e.is_request() {
        "request rejected before sending"
    } else {
        "transport failure"
    };
    match e.status() {
        Some(s) => format!("{kind} (status {s})"),
        None => kind.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forwarder_builds() {
        assert!(Forwarder::new().is_ok());
    }

    #[test]
    fn transport_errors_never_render_headers() {
        let e = ProxyError::Send("could not connect".into());
        let s = e.to_string();
        assert!(s.contains("unreachable"));
        assert!(!s.to_lowercase().contains("authorization"));
    }

    /// Diagnostic, not a conformance check. Run deliberately:
    ///
    ///   cargo test --bin authinjector -- --ignored --nocapture network_diag
    ///
    /// Prints the FULL error chain for a bare request to each host, with no
    /// credential involved at all. `describe()` deliberately reduces an error
    /// to its kind, which is right for the journal and useless for diagnosis.
    #[tokio::test]
    #[ignore]
    async fn network_diag() {
        let hosts = [
            ("pexels      ", "https://api.pexels.com/v1/search?query=x"),
            ("tavily      ", "https://api.tavily.com/search"),
            ("elevenlabs  ", "https://api.elevenlabs.io/v1/user"),
            ("googleapis  ", "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=https://example.com"),
            ("maps-google ", "https://maps.googleapis.com/maps/api/geocode/json?address=Toronto"),
            ("places-goog ", "https://places.googleapis.com/v1/places:searchText"),
            ("gbp-google  ", "https://mybusinessbusinessinformation.googleapis.com/v1/accounts"),
            ("stripe      ", "https://api.stripe.com/v1/balance"),
        ];
        let client = Forwarder::new().expect("client");
        for (name, url) in hosts {
            match client.client.get(url).send().await {
                Ok(r) => println!("  {name} OK   status {}", r.status()),
                Err(e) => {
                    println!("  {name} ERR  {e}");
                    println!("           kinds: timeout={} connect={} request={} body={} builder={}",
                             e.is_timeout(), e.is_connect(), e.is_request(), e.is_body(), e.is_builder());
                    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
                    let mut depth = 0;
                    while let Some(c) = src {
                        println!("           caused by [{depth}]: {c}");
                        src = std::error::Error::source(c);
                        depth += 1;
                        if depth > 5 { break; }
                    }
                }
            }
        }
    }

    /// Which element of a forwarded request breaks an upstream. Diagnostic:
    ///
    ///   cargo test --bin authinjector -- --ignored --nocapture stage_diag
    ///
    /// No real credential anywhere. Each stage adds one thing `forward()` does
    /// on top of the bare request that is already known to work.
    #[tokio::test]
    #[ignore]
    async fn stage_diag() {
        let f = Forwarder::new().expect("client");
        for (label, url) in [
            ("stripe ", "https://api.stripe.com/v1/balance"),
            ("maps   ", "https://maps.googleapis.com/maps/api/geocode/json?address=Toronto"),
            ("11labs ", "https://api.elevenlabs.io/v1/user"),
        ] {
            println!("\n  === {label} ===");
            let show = |n: &str, r: Result<reqwest::Response, reqwest::Error>| match r {
                Ok(x) => println!("    {n:<34} {}", x.status()),
                Err(e) => println!("    {n:<34} ERR {} (connect={} request={})",
                                   describe(&e), e.is_connect(), e.is_request()),
            };

            show("1 bare", f.client.get(url).send().await);
            show("2 + auth header",
                 f.client.get(url).header("Authorization", "Bearer fake").send().await);
            show("3 + accept/user-agent",
                 f.client.get(url).header("Authorization", "Bearer fake")
                  .header("accept", "*/*").header("user-agent", "curl/8.14.1").send().await);
            show("4 + host: localhost",
                 f.client.get(url).header("Authorization", "Bearer fake")
                  .header("accept", "*/*").header("user-agent", "curl/8.14.1")
                  .header("host", "localhost").send().await);
            show("5 + empty body (no host)",
                 f.client.get(url).header("Authorization", "Bearer fake")
                  .header("accept", "*/*").body(Vec::<u8>::new()).send().await);
            show("6 host only",
                 f.client.get(url).header("host", "localhost").send().await);
        }
        println!();
    }

    #[tokio::test]
    async fn a_send_error_never_renders_the_url_that_carried_the_key() {
        // A query-mode credential lives in the URL, and reqwest's own Display
        // prints the URL. `describe` is what keeps it out of the journal.
        let c = reqwest::Client::builder().use_rustls_tls().build().unwrap();
        let err = c
            .get("https://no-such-host.invalid/maps/api/geocode/json?key=AIza-SHOULD-NOT-APPEAR")
            .send()
            .await
            .expect_err("an invalid TLD must not resolve");
        assert!(
            err.to_string().contains("no-such-host.invalid"),
            "precondition: reqwest does print the URL, which is the problem being solved"
        );
        let ours = describe(&err);
        assert!(!ours.contains("AIza-SHOULD-NOT-APPEAR"), "the key must not reach the log");
        assert!(!ours.contains("no-such-host"));
    }
}
