//! Credential injection: stripping what the caller sent, then setting ours.
//!
//! 🔴 THIS IS ONE OF THE FOUR FILES TO READ, and the most important one. It is
//! deliberately free of hyper, reqwest and every other framework type: the
//! whole credential path is plain strings, so it can be read without knowing
//! the HTTP stack and tested without a socket.
//!
//! Two rules, in this order, and the order is the point:
//!
//!   1. STRIP every field the caller must not control, matching
//!      case-insensitively for headers and after percent-decoding for query
//!      parameters.
//!   2. THEN set the credential from the resolved Secret.
//!
//! Strip-then-set, never set-alone. Both transports allow repetition. HTTP
//! permits repeated header names, so a caller sending `authorization:` while
//! the broker sets `Authorization:` would, under a naive "set", produce a
//! request carrying BOTH -- the caller's value and ours. A query string
//! permits `?key=a&key=b` for the same reason. Which one an upstream honours
//! is upstream-specific and not something to bet a credential on.
//!
//! The Secret arrives as an explicit argument rather than hiding inside the
//! upstream struct, so it is visible in the signature of the one function that
//! reads it. `grep -rn expose_for_injection src/` should list exactly one call.

use crate::config::{Auth, Upstream};
use crate::secret::Secret;

/// A header as it travels: name as written, value as written.
pub type Header = (String, String);

/// What the forwarder should actually send. Both halves come back together
/// because a query-mode service changes the URL rather than the headers, and
/// a caller of this function must not be able to use one without the other.
pub struct Injected {
    pub headers: Vec<Header>,
    pub path_and_query: String,
}

/// Remove every header this caller is not permitted to set.
pub fn strip(headers: &[Header], upstream: &Upstream) -> Vec<Header> {
    let strip_set = upstream.strip_set();
    headers
        .iter()
        .filter(|(name, _)| !strip_set.contains(&name.to_ascii_lowercase()))
        .cloned()
        .collect()
}

/// Strip, then inject. The only function in the program that reads a Secret.
///
/// Header mode: `auth_prefix` comes from the catalogue (`"Bearer "`, or empty
/// for a raw key header) and is concatenated verbatim -- no trimming, no
/// normalising -- because a service wanting `Bearer ` and one wanting nothing
/// are both correct, and the catalogue says which.
///
/// Query mode: the parameter is removed if the caller sent it and appended
/// last, percent-encoded. The value is never prefixed; a query parameter
/// carries the bare credential.
pub fn apply(
    headers: &[Header],
    path_and_query: &str,
    upstream: &Upstream,
    secret: &Secret,
) -> Injected {
    let mut out = strip(headers, upstream);
    match &upstream.auth {
        Auth::Header { name, prefix } => {
            out.push((name.clone(), format!("{}{}", prefix, secret.expose_for_injection())));
            Injected { headers: out, path_and_query: path_and_query.to_string() }
        }
        Auth::Query { param } => Injected {
            headers: out,
            path_and_query: set_query_param(path_and_query, param, secret.expose_for_injection()),
        },
        // 🔴 `secret` HERE IS THE MINTED ACCESS TOKEN, NOT THE SERVICE-ACCOUNT
        // KEY. The proxy exchanges the key for a token before calling this, so
        // the private key never reaches the injector and never reaches a
        // header. See proxy::forward and src/gtoken.rs.
        Auth::GoogleServiceAccount { .. } => {
            out.push(("Authorization".to_string(),
                      format!("Bearer {}", secret.expose_for_injection())));
            Injected { headers: out, path_and_query: path_and_query.to_string() }
        }
    }
}

/// Replace `param` in a query string, dropping any the caller supplied.
///
/// 🔴 THE CALLER'S COPY IS REMOVED BEFORE OURS IS APPENDED, and the comparison
/// is made on the percent-DECODED name. `?k%65y=theirs` decodes to `key` and
/// would otherwise sail past a raw string comparison, leaving two parameters
/// with the upstream free to honour either.
fn set_query_param(path_and_query: &str, param: &str, value: &str) -> String {
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_and_query, ""),
    };

    let mut kept: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let name = pair.split_once('=').map(|(n, _)| n).unwrap_or(pair);
        if percent_decode(name) == param {
            continue;
        }
        kept.push(pair);
    }

    let mut out = String::with_capacity(path_and_query.len() + value.len() + param.len() + 8);
    out.push_str(path);
    out.push('?');
    for pair in kept {
        out.push_str(pair);
        out.push('&');
    }
    out.push_str(param);
    out.push('=');
    out.push_str(&percent_encode(value));
    out
}

/// Remove the injected credential from response headers on its way back.
///
/// 🔴 THIS CLOSES A REAL LEAK, FOUND IN PRODUCTION.
///
/// A query-mode upstream that answers with a redirect echoes the request URL
/// in `Location` -- query string and all. Since the broker returns upstream
/// response headers to the caller verbatim, that hands the caller the exact
/// credential the broker exists to keep from it:
///
///   location: http://api.example.com/svc/?phone=555&token=<the real key>
///
/// The caller never sees the URL we build, so `Location` was the one channel
/// that exposed it. Worse, that particular upstream redirected to **http**, so
/// a caller following it would also have put the credential on the wire in
/// clear. The forwarder does not follow redirects (`Policy::none`), which kept
/// US from doing that -- but nothing stopped us handing the caller the means.
///
/// Scrubbing is by PARAMETER NAME, not by value: it never needs the secret,
/// and it therefore also removes a stale copy the caller itself supplied.
pub fn scrub_response_headers(headers: Vec<Header>, upstream: &Upstream) -> Vec<Header> {
    let Auth::Query { param } = &upstream.auth else {
        return headers;
    };
    let needle = format!("{param}=");
    headers
        .into_iter()
        .map(|(name, value)| {
            if value.contains(&needle) {
                (name, remove_query_param(&value, param))
            } else {
                (name, value)
            }
        })
        .collect()
}

/// Drop `param` from any query string inside `value`, leaving the rest intact.
fn remove_query_param(value: &str, param: &str) -> String {
    let Some((head, query)) = value.split_once('?') else {
        return value.to_string();
    };
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            if pair.is_empty() {
                return false;
            }
            let name = pair.split_once('=').map(|(n, _)| n).unwrap_or(pair);
            percent_decode(name) != param
        })
        .collect();
    if kept.is_empty() {
        head.to_string()
    } else {
        format!("{head}?{}", kept.join("&"))
    }
}

/// Percent-encode everything outside RFC 3986's unreserved set.
///
/// Deliberately conservative: a key containing `&`, `=`, `+`, `#` or a space
/// must not be able to terminate the parameter and start another one. Encoding
/// more than strictly necessary is always safe; encoding less is a URL
/// injection.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::Catalogue;
    use crate::config::{merge, Policy, Settings};
    use std::collections::HashMap;

    const CAT: &str = r#"
[services.tavily]
base_url = "https://api.tavily.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]

[services.provision]
base_url = "https://provision.blacksq.com"
auth_header = "x-provision-token"
auth_prefix = ""
endpoints = [{ methods = ["POST"], path_prefix = "/api" }]

[services.geocoding]
base_url = "https://maps.googleapis.com"
auth_in = "query"
auth_param = "key"
endpoints = [{ methods = ["GET"], path_prefix = "/maps/api/geocode/json" }]
"#;

    fn build(cfg: &str) -> (Policy, HashMap<String, Secret>) {
        let cat = Catalogue::parse(CAT).expect("catalogue");
        let set = Settings::parse(cfg).expect("settings");
        merge(&cat, set).expect("merge")
    }

    fn bearer() -> (Policy, HashMap<String, Secret>) {
        build("[services.tavily.default]\nkey=\"tvly-REAL\"\ncallers=[\"alice\"]\n")
    }

    fn geo() -> (Policy, HashMap<String, Secret>) {
        build("[services.geocoding.default]\nkey=\"AIza-REAL\"\ncallers=[\"alice\"]\n")
    }

    fn names(h: &[Header]) -> Vec<String> {
        h.iter().map(|(n, _)| n.to_ascii_lowercase()).collect()
    }

    // ── header mode ─────────────────────────────────────────────────────────

    #[test]
    fn caller_supplied_auth_header_is_removed_whatever_its_casing() {
        let (p, _) = bearer();
        let u = p.get("tavily").unwrap();
        let sent = vec![
            ("authorization".into(), "Bearer CALLER-SUPPLIED".to_string()),
            ("AUTHORIZATION".into(), "Bearer ALSO-CALLER".to_string()),
            ("Content-Type".into(), "application/json".to_string()),
        ];
        assert_eq!(names(&strip(&sent, u)), vec!["content-type"]);
    }

    #[test]
    fn the_callers_host_never_reaches_the_upstream() {
        // The upstream's host comes from the catalogue's base_url. The
        // caller's Host describes the hop it made to the broker's socket --
        // literally "localhost" -- and forwarding it broke every HTTP/2
        // upstream and every nginx front end.
        let (p, keys) = bearer();
        let u = p.get("tavily").unwrap();
        let out = apply(
            &[
                ("Host".into(), "localhost".into()),
                ("Content-Length".into(), "999".into()),
                ("Connection".into(), "keep-alive".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            "/search",
            u,
            keys.get("tavily").unwrap(),
        );
        let got = names(&out.headers);
        assert!(!got.contains(&"host".to_string()), "Host must be dropped");
        assert!(!got.contains(&"content-length".to_string()), "a stale Content-Length must be dropped");
        assert!(!got.contains(&"connection".to_string()), "hop-by-hop must be dropped");
        assert!(got.contains(&"content-type".to_string()), "Content-Type is end-to-end and must survive");
    }

    #[test]
    fn cookie_and_proxy_auth_are_always_stripped() {
        let (p, _) = bearer();
        let u = p.get("tavily").unwrap();
        let sent = vec![
            ("Cookie".into(), "session=abc".to_string()),
            ("Proxy-Authorization".into(), "Basic xyz".to_string()),
            ("Accept".into(), "*/*".to_string()),
        ];
        assert_eq!(names(&strip(&sent, u)), vec!["accept"]);
    }

    #[test]
    fn injects_exactly_one_auth_header_with_the_catalogue_prefix() {
        let (p, keys) = bearer();
        let u = p.get("tavily").unwrap();
        let out = apply(
            &[("Content-Type".into(), "application/json".into())],
            "/search",
            u,
            keys.get("tavily").unwrap(),
        );
        let auth: Vec<&Header> = out.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).collect();
        assert_eq!(auth.len(), 1, "exactly one credential header, never two");
        assert_eq!(auth[0].1, "Bearer tvly-REAL");
        assert_eq!(out.path_and_query, "/search", "header mode leaves the URL alone");
    }

    #[test]
    fn a_caller_cannot_smuggle_its_own_credential_alongside_ours() {
        let (p, keys) = bearer();
        let u = p.get("tavily").unwrap();
        let out = apply(
            &[("authorization".into(), "Bearer CALLER-SUPPLIED".into())],
            "/search",
            u,
            keys.get("tavily").unwrap(),
        );
        let auth: Vec<&Header> = out.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).collect();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].1, "Bearer tvly-REAL");
        assert!(!out.headers.iter().any(|(_, v)| v.contains("CALLER-SUPPLIED")));
    }

    #[test]
    fn an_empty_prefix_sends_the_raw_value() {
        let (p, keys) = build("[services.provision.default]\nkey=\"prov-123\"\ncallers=[\"svc\"]\n");
        let u = p.get("provision").unwrap();
        let out = apply(&[], "/api", u, keys.get("provision").unwrap());
        assert_eq!(out.headers.len(), 1);
        assert_eq!(out.headers[0].0, "x-provision-token");
        assert_eq!(out.headers[0].1, "prov-123", "no prefix means no prefix, not a trimmed one");
    }

    #[test]
    fn the_secret_appears_only_in_the_injected_header() {
        let (p, keys) = bearer();
        let u = p.get("tavily").unwrap();
        let out = apply(
            &[("Accept".into(), "*/*".into()), ("X-Thing".into(), "value".into())],
            "/search",
            u,
            keys.get("tavily").unwrap(),
        );
        let carrying: Vec<&Header> = out.headers.iter().filter(|(_, v)| v.contains("tvly-REAL")).collect();
        assert_eq!(carrying.len(), 1);
        assert!(carrying[0].0.eq_ignore_ascii_case("authorization"));
        assert!(!out.path_and_query.contains("tvly-REAL"), "never in the URL for a header service");
    }

    // ── query mode ──────────────────────────────────────────────────────────

    #[test]
    fn query_mode_appends_the_parameter_and_touches_no_header() {
        let (p, keys) = geo();
        let u = p.get("geocoding").unwrap();
        let out = apply(&[("Accept".into(), "*/*".into())], "/maps/api/geocode/json?address=Toronto", u, keys.get("geocoding").unwrap());
        assert_eq!(out.path_and_query, "/maps/api/geocode/json?address=Toronto&key=AIza-REAL");
        assert_eq!(names(&out.headers), vec!["accept"], "no credential header is added");
    }

    #[test]
    fn query_mode_works_when_the_caller_sent_no_query_at_all() {
        let (p, keys) = geo();
        let u = p.get("geocoding").unwrap();
        let out = apply(&[], "/maps/api/geocode/json", u, keys.get("geocoding").unwrap());
        assert_eq!(out.path_and_query, "/maps/api/geocode/json?key=AIza-REAL");
    }

    #[test]
    fn a_caller_supplied_parameter_of_the_same_name_is_dropped() {
        let (p, keys) = geo();
        let u = p.get("geocoding").unwrap();
        let out = apply(&[], "/maps/api/geocode/json?key=CALLER&address=x", u, keys.get("geocoding").unwrap());
        assert_eq!(out.path_and_query, "/maps/api/geocode/json?address=x&key=AIza-REAL");
        assert!(!out.path_and_query.contains("CALLER"), "exactly one key parameter, and it is ours");
    }

    #[test]
    fn a_percent_encoded_duplicate_does_not_slip_past_the_strip() {
        // `k%65y` decodes to `key`. A raw string comparison would keep it and
        // the request would carry two credentials.
        let (p, keys) = geo();
        let u = p.get("geocoding").unwrap();
        let out = apply(&[], "/maps/api/geocode/json?k%65y=CALLER", u, keys.get("geocoding").unwrap());
        assert!(!out.path_and_query.contains("CALLER"));
        assert_eq!(out.path_and_query, "/maps/api/geocode/json?key=AIza-REAL");
    }

    #[test]
    fn a_key_containing_url_metacharacters_cannot_inject_a_parameter() {
        let (p, keys) = build("[services.geocoding.default]\nkey=\"a&admin=1 b+c#d\"\ncallers=[\"alice\"]\n");
        let u = p.get("geocoding").unwrap();
        let out = apply(&[], "/maps/api/geocode/json", u, keys.get("geocoding").unwrap());
        assert_eq!(out.path_and_query, "/maps/api/geocode/json?key=a%26admin%3D1%20b%2Bc%23d");
        assert!(!out.path_and_query.contains("&admin=1"), "the key must not become a second parameter");
    }

    #[test]
    fn a_redirect_never_hands_the_credential_back_to_the_caller() {
        // The exact response that exposed this: RealValidation answered 301
        // with the full request URL, credential included, in Location.
        let (p, _) = geo();
        let u = p.get("geocoding").unwrap();
        let out = scrub_response_headers(
            vec![
                ("location".into(), "http://api.example.com/svc/?phone=555&key=AIza-REAL".into()),
                ("content-type".into(), "text/html".into()),
            ],
            u,
        );
        let loc = &out.iter().find(|(n, _)| n == "location").unwrap().1;
        assert!(!loc.contains("AIza-REAL"), "the credential must not travel back: {loc}");
        assert_eq!(loc, "http://api.example.com/svc/?phone=555", "the rest of the redirect survives");
        assert_eq!(out.iter().find(|(n, _)| n == "content-type").unwrap().1, "text/html");
    }

    #[test]
    fn scrubbing_leaves_a_header_mode_service_untouched() {
        let (p, _) = bearer();
        let u = p.get("tavily").unwrap();
        let out = scrub_response_headers(vec![("location".into(), "https://x/y?key=abc".into())], u);
        assert_eq!(out[0].1, "https://x/y?key=abc", "not our parameter, not our business");
    }

    #[test]
    fn scrubbing_handles_the_credential_being_the_only_parameter() {
        let (p, _) = geo();
        let u = p.get("geocoding").unwrap();
        let out = scrub_response_headers(vec![("location".into(), "https://x/y?key=AIza-REAL".into())], u);
        assert_eq!(out[0].1, "https://x/y", "no dangling '?'");
    }

    #[test]
    fn encoding_leaves_the_unreserved_set_alone() {
        assert_eq!(percent_encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(percent_encode("a/b"), "a%2Fb");
    }

    #[test]
    fn decoding_handles_plus_and_a_trailing_stray_percent() {
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("k%65y"), "key");
        assert_eq!(percent_decode("100%"), "100%", "a stray % is literal, not a panic");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
