//! Delivering a key to where it is *used*, without anyone reading it.
//!
//! `POST /_broker/push {"source": "resend:blacksq",
//!                      "dest": "cf-worker:blacksq-example/RESEND_API_KEY"}`
//!
//! The broker already holds the key and already holds the credential for the
//! destination's API. So it can put one into the other and answer "done",
//! and the value never enters the caller's process — the same guarantee
//! `/tavily/search` makes, applied to provisioning instead of a query.
//!
//! 🔴 WHY THE ALLOWLIST BELONGS TO THE KEY, NOT THE CALLER.
//!
//! "Send secret X to destination Y" is, unconstrained, an exfiltration
//! primitive: a Worker's code can read its own secrets, and whoever can deploy
//! a Worker can therefore read anything pushed to it. An agent allowed to push
//! `stripe:live` to a worker it controls has simply read the Stripe key, and
//! every audit line would look ordinary.
//!
//! So the destination is not the caller's to choose. Each key declares, in the
//! private config, the exact places it may ever land and the exact NAME it
//! lands under:
//!
//! ```toml
//! [services.resend.blacksq]
//! key = "…"
//! callers = ["alice"]
//! push_to = ["cf-worker:blacksq-*/RESEND_API_KEY"]
//! ```
//!
//! A key with no `push_to` can never be pushed. `*` matches within one
//! path-ish segment and never spans `/`, so `blacksq-*` cannot become
//! `blacksq-x/../y`. The secret NAME is matched exactly — a Resend key can
//! only ever be delivered as `RESEND_API_KEY`, never as, say, a variable some
//! other code path prints.
//!
//! The requirement: send a specific secret to a GitHub repository or a
//! Cloudflare Worker as a secret, without ever displaying it.
use std::fmt;

use crate::config::{Policy, Upstream};
use crate::proxy::Forwarder;
use crate::secret::Secret;

/// Where a key may be delivered. One variant per provider; GitLab is the
/// expected third.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// `cf-worker:{script}/{SECRET_NAME}` — a Cloudflare Worker's secret.
    CfWorker { script: String, name: String },
    /// `gh-repo:{owner}/{repo}/{SECRET_NAME}` — a GitHub Actions repo secret.
    GhRepo { owner: String, repo: String, name: String },
    /// `gh-env:{owner}/{repo}/{environment}/{SECRET_NAME}` — an environment
    /// secret, which is what a deploy credential should be: reachable only
    /// from a job that names that environment.
    GhEnv { owner: String, repo: String, env: String, name: String },
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A secret's NAME, at every provider we speak to: A–Z, 0–9, `_`, not leading
/// with a digit. Deliberately the strictest of the set, so one spelling is
/// valid everywhere and a name can never carry a path separator.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// One segment of a destination: a worker name, an owner, a repo, an
/// environment. `allow_star` is true only when parsing a config PATTERN.
fn valid_segment(s: &str, allow_star: bool) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || (allow_star && c == '*')
        })
}

/// What a destination string is being read as. The three differ only in how
/// much they may say, and the differences are the security model.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A request. Names one real place and one real secret. No wildcards.
    Request,
    /// A rule that PERMITS. Wildcards inside a segment, but never a bare `*`
    /// first segment — that reads "any account", "any organisation".
    Allow,
    /// A rule that FORBIDS. Any wildcard, including a bare `*` first segment:
    /// "this key goes to no GitHub repository, wherever it is" is a sentence
    /// worth being able to write, and a deny can only ever narrow.
    Deny,
}

impl Destination {
    /// Parse a CONCRETE destination — what a request names. No wildcards.
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        Self::parse_inner(s, Mode::Request)
    }

    /// Parse a PERMITTING rule — `[push] default`, `push_to`, `push_allow`.
    pub fn parse_pattern(s: &str) -> Result<Self, ParseError> {
        Self::parse_inner(s, Mode::Allow)
    }

    /// Parse a FORBIDDING rule — `push_deny`.
    pub fn parse_deny(s: &str) -> Result<Self, ParseError> {
        Self::parse_inner(s, Mode::Deny)
    }

    fn parse_inner(s: &str, mode: Mode) -> Result<Self, ParseError> {
        let star = mode != Mode::Request;
        let err = |m: &str| Err(ParseError(m.to_string()));
        let Some((kind, rest)) = s.split_once(':') else {
            return err("expected <kind>:<location>/<SECRET_NAME>");
        };
        let parts: Vec<&str> = rest.split('/').collect();
        let bad_seg = |p: &[&str]| p.iter().any(|seg| !valid_segment(seg, star));

        let dest = match (kind, parts.as_slice()) {
            ("cf-worker", [script, name]) => {
                if bad_seg(&[script]) {
                    return err("worker name is not a valid segment");
                }
                Destination::CfWorker { script: (*script).into(), name: (*name).into() }
            }
            ("gh-repo", [owner, repo, name]) => {
                if bad_seg(&[owner, repo]) {
                    return err("owner/repo is not a valid segment");
                }
                Destination::GhRepo {
                    owner: (*owner).into(),
                    repo: (*repo).into(),
                    name: (*name).into(),
                }
            }
            ("gh-env", [owner, repo, env, name]) => {
                if bad_seg(&[owner, repo, env]) {
                    return err("owner/repo/environment is not a valid segment");
                }
                Destination::GhEnv {
                    owner: (*owner).into(),
                    repo: (*repo).into(),
                    env: (*env).into(),
                    name: (*name).into(),
                }
            }
            ("cf-worker" | "gh-repo" | "gh-env", _) => {
                return err("wrong number of '/' segments for this kind")
            }
            _ => return err("unknown kind — expected cf-worker, gh-repo or gh-env"),
        };
        // A PATTERN may wildcard the name — `[push] default` cannot know what
        // each key is called. A REQUEST never may: it names one real secret.
        let name = dest.secret_name();
        if !(valid_name(name) || (star && name == "*")) {
            return err("secret name must be A-Z, 0-9 and _, not starting with a digit");
        }
        // 🔴 A BARE `*` IN THE FIRST SEGMENT IS REFUSED, in a pattern too. It
        // would read "any Cloudflare account" or "any GitHub org" — the one
        // shape that turns delivery into exfiltration. `blacksq-*` and
        // `Black-Squid` are the point; `*` alone is never what anyone meant.
        if mode == Mode::Allow && dest.first_segment() == "*" {
            return err("the first segment may not be a bare '*' — name the account or organisation");
        }
        Ok(dest)
    }

    /// The account/org-scoping segment — a worker's name, a repo owner.
    pub fn first_segment(&self) -> &str {
        match self {
            Destination::CfWorker { script, .. } => script,
            Destination::GhRepo { owner, .. } | Destination::GhEnv { owner, .. } => owner,
        }
    }

    pub fn secret_name(&self) -> &str {
        match self {
            Destination::CfWorker { name, .. }
            | Destination::GhRepo { name, .. }
            | Destination::GhEnv { name, .. } => name,
        }
    }

    /// The upstream whose credential delivers this — and which therefore has
    /// to be configured, with this caller allowed to use it, before any push
    /// can happen. Reusing the ordinary upstreams means a delivery is bounded
    /// by exactly the same permissions as a call.
    pub fn via_upstream(&self) -> &'static str {
        match self {
            Destination::CfWorker { .. } => "cloudflare-rw",
            Destination::GhRepo { .. } | Destination::GhEnv { .. } => "github-rw",
        }
    }

    /// For the audit line and the answer. Never contains the value.
    pub fn describe(&self) -> String {
        match self {
            Destination::CfWorker { script, name } => format!("cf-worker:{script}/{name}"),
            Destination::GhRepo { owner, repo, name } => format!("gh-repo:{owner}/{repo}/{name}"),
            Destination::GhEnv { owner, repo, env, name } => {
                format!("gh-env:{owner}/{repo}/{env}/{name}")
            }
        }
    }

    /// Does this concrete destination satisfy a declared pattern? Every
    /// location segment must match (with `*` inside a segment), and the secret
    /// name must be equal — never wildcarded.
    pub fn matches(&self, pattern: &Destination) -> bool {
        let seg = |a: &str, p: &str| glob_segment(p, a);
        match (self, pattern) {
            (
                Destination::CfWorker { script: a, name: an },
                Destination::CfWorker { script: p, name: pn },
            ) => seg(a, p) && seg(an, pn),
            (
                Destination::GhRepo { owner: ao, repo: ar, name: an },
                Destination::GhRepo { owner: po, repo: pr, name: pn },
            ) => seg(ao, po) && seg(ar, pr) && seg(an, pn),
            (
                Destination::GhEnv { owner: ao, repo: ar, env: ae, name: an },
                Destination::GhEnv { owner: po, repo: pr, env: pe, name: pn },
            ) => seg(ao, po) && seg(ar, pr) && seg(ae, pe) && seg(an, pn),
            _ => false,
        }
    }

    /// Permitted by at least one of the key's declared destinations.
    pub fn permitted_by(&self, patterns: &[String]) -> bool {
        patterns
            .iter()
            .filter_map(|p| Destination::parse_pattern(p).ok())
            .any(|p| self.matches(&p))
    }

    /// 🔴 DENY WINS. A destination is reachable only if something permits it
    /// AND nothing forbids it — the ordinary precedence, and the only one that
    /// is safe to get wrong in the tired direction: a broadened allow-list
    /// cannot quietly re-open what a deny closed.
    pub fn forbidden_by(&self, patterns: &[String]) -> bool {
        patterns
            .iter()
            .filter_map(|p| Destination::parse_deny(p).ok())
            .any(|p| self.matches(&p))
    }
}

/// `*` matches any run of characters WITHIN one segment. The caller has
/// already rejected `/` in a segment, so this cannot cross a boundary.
fn glob_segment(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((head, tail)) => {
            value.len() >= head.len() + tail.len()
                && value.starts_with(head)
                && value.ends_with(tail)
                && !tail.contains('*') // one star per segment is plenty
        }
    }
}


// ── Delivery ─────────────────────────────────────────────────────────────────
//
// Every call goes out through the ordinary `Forwarder` with the ordinary
// `Upstream`, so the destination's credential is injected by the same code that
// injects one for a proxied request, and an error is scrubbed by the same code
// that keeps a key out of `reqwest`'s Display. The push path invents no second
// way to talk to the network.

/// GitHub asks to be told explicitly which version of its API you mean.
const GH_ACCEPT: &str = "application/vnd.github+json";
const CF_ACCEPT: &str = "application/json";

#[derive(Debug)]
pub struct PushError(pub String);

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Everything delivery needs, resolved by the caller (the server) so this
/// module never reaches into the Broker.
pub struct Via<'a> {
    pub forwarder: &'a Forwarder,
    pub upstream: &'a Upstream,
    pub credential: &'a Secret,
}

async fn call(
    via: &Via<'_>,
    method: &str,
    path: &str,
    accept: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, PushError> {
    let (bytes, headers) = match &body {
        Some(v) => (
            serde_json::to_vec(v).map_err(|e| PushError(e.to_string()))?,
            vec![("content-type".to_string(), "application/json".to_string())],
        ),
        None => (Vec::new(), Vec::new()),
    };
    // GitHub refuses a request with no User-Agent; Cloudflare does not mind one.
    let mut headers = headers;
    headers.push(("user-agent".to_string(), "authinjector".to_string()));
    headers.push(("accept".to_string(), accept.to_string()));

    let resp = via
        .forwarder
        .forward(via.upstream, method, path, &headers, bytes, via.credential)
        .await
        .map_err(|e| PushError(e.to_string()))?;

    if resp.status >= 400 {
        // The upstream's own message, never our request. A 404 from GitHub on a
        // repo that does not exist is worth reading; the body cannot contain the
        // key we sent, because we sent it encrypted or in a field they echo back
        // as null — but it is truncated regardless.
        let text = String::from_utf8_lossy(&resp.body);
        return Err(PushError(format!(
            "{} {} -> HTTP {}: {}",
            method,
            path.split('?').next().unwrap_or(path),
            resp.status,
            text.chars().take(300).collect::<String>()
        )));
    }
    Ok(serde_json::from_slice(&resp.body).unwrap_or(serde_json::Value::Null))
}

/// The one account this token can see. Resolved per push rather than cached:
/// a push is a provisioning event, not a hot path, and a stale account id
/// would be a very confusing failure.
async fn cf_account(via: &Via<'_>) -> Result<String, PushError> {
    let body = call(via, "GET", "/client/v4/accounts?per_page=5", CF_ACCEPT, None).await?;
    let list = body["result"].as_array().cloned().unwrap_or_default();
    match list.len() {
        1 => Ok(list[0]["id"].as_str().unwrap_or_default().to_string()),
        n => Err(PushError(format!(
            "expected exactly one Cloudflare account, this token sees {n}"
        ))),
    }
}

/// Put the value into a Worker's secrets. Cloudflare takes it in the clear over
/// TLS; there is no envelope to build.
async fn deliver_cf_worker(
    via: &Via<'_>,
    script: &str,
    name: &str,
    value: &Secret,
) -> Result<(), PushError> {
    let account = cf_account(via).await?;
    call(
        via,
        "PUT",
        &format!("/client/v4/accounts/{account}/workers/scripts/{script}/secrets"),
        CF_ACCEPT,
        Some(serde_json::json!({
            "name": name,
            "text": value.expose_for_injection(),
            "type": "secret_text",
        })),
    )
    .await
    .map(|_| ())
}

/// 🔴 GITHUB TAKES THE VALUE SEALED, NOT IN THE CLEAR. An Actions secret is
/// encrypted client-side with the repository's (or environment's) own public
/// key — libsodium's sealed box: an ephemeral keypair per message, so the
/// ciphertext is anonymous and only GitHub's private key opens it. `dryoc` is
/// the pure-Rust implementation; a C libsodium binding would break the static
/// musl build this ships as.
fn seal_for_github(public_key_b64: &str, value: &Secret) -> Result<String, PushError> {
    use base64::Engine as _;
    use dryoc::dryocbox::{DryocBox, PublicKey};

    let b64 = base64::engine::general_purpose::STANDARD;
    let raw = b64
        .decode(public_key_b64)
        .map_err(|_| PushError("the public key GitHub returned is not base64".into()))?;
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| PushError("the public key GitHub returned is not 32 bytes".into()))?;

    let sealed = DryocBox::seal_to_vecbox(value.expose_for_injection().as_bytes(), &PublicKey::from(key))
        .map_err(|e| PushError(format!("sealing failed: {e}")))?;
    Ok(b64.encode(sealed.to_vec()))
}

async fn deliver_github(
    via: &Via<'_>,
    base: &str,
    name: &str,
    value: &Secret,
) -> Result<(), PushError> {
    let pk = call(via, "GET", &format!("{base}/secrets/public-key"), GH_ACCEPT, None).await?;
    let (key, key_id) = (
        pk["key"].as_str().unwrap_or_default(),
        pk["key_id"].as_str().unwrap_or_default().to_string(),
    );
    if key.is_empty() || key_id.is_empty() {
        return Err(PushError("GitHub returned no public key for this target".into()));
    }
    let encrypted = seal_for_github(key, value)?;
    call(
        via,
        "PUT",
        &format!("{base}/secrets/{name}"),
        GH_ACCEPT,
        Some(serde_json::json!({ "encrypted_value": encrypted, "key_id": key_id })),
    )
    .await
    .map(|_| ())
}

/// Deliver `value` to `dest`. Returns nothing on success: there is nothing to
/// report but the fact, and the fact is in the audit line.
pub async fn deliver(via: &Via<'_>, dest: &Destination, value: &Secret) -> Result<(), PushError> {
    match dest {
        Destination::CfWorker { script, name } => deliver_cf_worker(via, script, name, value).await,
        Destination::GhRepo { owner, repo, name } => {
            deliver_github(via, &format!("/repos/{owner}/{repo}/actions"), name, value).await
        }
        Destination::GhEnv { owner, repo, env, name } => {
            deliver_github(
                via,
                &format!("/repos/{owner}/{repo}/environments/{env}"),
                name,
                value,
            )
            .await
        }
    }
}

/// What a request body names. The destination is a STRING the caller chooses,
/// and `Destination::permitted_by` is what decides whether it may have it.
#[derive(Debug, serde::Deserialize)]
pub struct PushRequest {
    pub source: String,
    pub dest: String,
}

/// Resolve a push: who may do it, and to where. Separated from `deliver` so the
/// whole decision is testable without a network.
pub fn authorize<'p>(
    policy: &'p Policy,
    caller: &str,
    req: &PushRequest,
) -> Result<(&'p Upstream, &'p Upstream, Destination), (u16, String)> {
    let source = policy
        .get(&req.source)
        .ok_or((404, format!("no key configured as {:?}", req.source)))?;
    if !source.permits_caller(caller) {
        return Err((403, format!("{caller} may not use {}", source.id)));
    }
    let dest = Destination::parse(&req.dest).map_err(|e| (400, e.0))?;

    if source.push_to.is_empty() {
        return Err((
            403,
            format!(
                "{} declares no push_to, so it can never be delivered anywhere. \
                 Add the destinations it is allowed to reach to its config block.",
                source.id
            ),
        ));
    }
    if dest.forbidden_by(&source.push_deny) {
        return Err((
            403,
            format!("{} is explicitly denied to {}", dest.describe(), source.id),
        ));
    }
    if !dest.permitted_by(&source.push_to) {
        return Err((
            403,
            format!("{} is not a destination {} is allowed to reach", dest.describe(), source.id),
        ));
    }

    // The credential that DELIVERS is an ordinary upstream, and the caller must
    // be permitted to use that too: pushing through it is at least as
    // consequential as calling it.
    let via_id = dest.via_upstream();
    let via = policy.get(via_id).ok_or((
        501,
        format!("{via_id} is not configured on this box, so {} cannot be reached", dest.describe()),
    ))?;
    if !via.permits_caller(caller) {
        return Err((403, format!("{caller} may not use {via_id}")));
    }
    Ok((source, via, dest))
}

// ── Turnstile widget secrets ────────────────────────────────────────────────
//
// `POST /_broker/push {"source": "cf-turnstile:{sitekey}",
//                      "dest": "cf-worker:blacksq-x/TURNSTILE_SECRET_KEY"}`
//
// A provisioning tool can create and manage Turnstile widgets with no manual
// step. Cloudflare MINTS a widget's secret and returns it in every
// widget response, so it is not a key anyone configured here — it is fetched
// on the way through. `redact` strips it from what callers see; this is the
// only way it ever leaves Cloudflare: straight into the Worker that verifies.
//
// 🔴 THE ALLOWLIST IS STILL THE KEY'S. The minted secret inherits the push
// rules of the credential that can read it (`cloudflare-rw`), and may land only
// under the one name the verifier reads. A Turnstile secret can do nothing but
// verify tokens, but the rule that a caller does not choose where a secret goes
// holds for it as for every other.

pub const TURNSTILE_SOURCE: &str = "cf-turnstile:";
pub const TURNSTILE_SECRET_NAME: &str = "TURNSTILE_SECRET_KEY";

/// Resolve a Turnstile push: the sitekey, the upstream that reads and delivers
/// it, and the destination. Network-free, like `authorize`.
pub fn authorize_turnstile<'p>(
    policy: &'p Policy,
    caller: &str,
    req: &PushRequest,
) -> Result<(String, &'p Upstream, Destination), (u16, String)> {
    let sitekey = req
        .source
        .strip_prefix(TURNSTILE_SOURCE)
        .ok_or((400, "not a cf-turnstile: source".to_string()))?;
    if sitekey.is_empty()
        || sitekey.len() > 64
        || !sitekey.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err((400, format!("{:?} is not a Turnstile sitekey", sitekey)));
    }
    let dest = Destination::parse(&req.dest).map_err(|e| (400, e.0))?;
    let Destination::CfWorker { name, .. } = &dest else {
        return Err((403, "a Turnstile secret goes only to a Cloudflare Worker".to_string()));
    };
    if name != TURNSTILE_SECRET_NAME {
        return Err((403, format!("a Turnstile secret lands only as {TURNSTILE_SECRET_NAME}")));
    }
    let via = policy
        .get("cloudflare-rw")
        .ok_or((501, "cloudflare-rw is not configured on this box".to_string()))?;
    if !via.permits_caller(caller) {
        return Err((403, format!("{caller} may not use cloudflare-rw")));
    }
    if dest.forbidden_by(&via.push_deny) || !dest.permitted_by(&via.push_to) {
        return Err((
            403,
            format!("{} is not a destination cloudflare-rw may deliver to", dest.describe()),
        ));
    }
    Ok((sitekey.to_string(), via, dest))
}

/// Read the widget's secret from Cloudflare and put it into the Worker. The
/// value lives in this function and nowhere else.
pub async fn deliver_turnstile(
    via: &Via<'_>,
    sitekey: &str,
    dest: &Destination,
) -> Result<(), PushError> {
    let Destination::CfWorker { script, name } = dest else {
        return Err(PushError("a Turnstile secret goes only to a Cloudflare Worker".into()));
    };
    let account = cf_account(via).await?;
    let body = call(
        via,
        "GET",
        &format!("/client/v4/accounts/{account}/challenges/widgets/{sitekey}"),
        CF_ACCEPT,
        None,
    )
    .await?;
    let secret = match body["result"]["secret"].as_str() {
        Some(s) if !s.is_empty() => Secret::new(s.to_string()),
        _ => return Err(PushError(format!("widget {sitekey} returned no secret"))),
    };
    drop(body);
    deliver_cf_worker(via, script, name, &secret).await
}

/// Cloudflare answers every Turnstile widget call — create, list, read,
/// update, rotate — with the widget's `secret` in it. Replace each with a
/// marker before the caller sees the response. Anything that is not a JSON
/// widget response passes through untouched.
pub fn redact_turnstile(base_url: &str, path: &str, body: Vec<u8>) -> (Vec<u8>, bool) {
    if !base_url.contains("api.cloudflare.com") || !path.contains("/challenges/widgets") {
        return (body, false);
    }
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (body, false);
    };
    fn walk(v: &mut serde_json::Value, hit: &mut bool) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m.iter_mut() {
                    if k == "secret" && x.is_string() {
                        *x = serde_json::Value::String("<held by broker: push cf-turnstile:{sitekey}>".into());
                        *hit = true;
                    } else {
                        walk(x, hit);
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter_mut().for_each(|x| walk(x, hit)),
            _ => {}
        }
    }
    let mut hit = false;
    walk(&mut v, &mut hit);
    if !hit {
        return (body, false);
    }
    (serde_json::to_vec(&v).unwrap_or_default(), true)
}

#[cfg(test)]
mod turnstile_tests {
    use super::*;

    #[test]
    fn every_widget_secret_is_redacted() {
        let body = br#"{"success":true,"result":[{"sitekey":"0x4A","secret":"0x4AAA-REAL","domains":["a.ca"]},{"sitekey":"0x4B","secret":"0x4BBB-REAL"}]}"#.to_vec();
        let (out, hit) = redact_turnstile("https://api.cloudflare.com", "/client/v4/accounts/x/challenges/widgets", body);
        let s = String::from_utf8(out).unwrap();
        assert!(hit);
        assert!(!s.contains("REAL"));
        assert!(s.contains("0x4A") && s.contains("a.ca"));
    }

    #[test]
    fn other_responses_pass_untouched() {
        let body = br#"{"result":{"secret":"keep"}}"#.to_vec();
        let (out, hit) = redact_turnstile("https://api.cloudflare.com", "/client/v4/accounts/x/workers/scripts", body.clone());
        assert!(!hit);
        assert_eq!(out, body);
        let (out, hit) = redact_turnstile("https://api.example.com", "/challenges/widgets", body.clone());
        assert!(!hit);
        assert_eq!(out, body);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::Catalogue;
    use crate::config::{merge, Settings};

    const CAT: &str = r#"
[services.resend]
base_url = "https://api.resend.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["POST"], path_prefix = "/emails" }]

[services.cloudflare-rw]
base_url = "https://api.cloudflare.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["GET", "PUT"], path_prefix = "/client/v4/" }]

[services.github-rw]
base_url = "https://api.github.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["GET", "PUT"], path_prefix = "/repos/Black-Squid/" }]
"#;

    fn policy(cfg: &str) -> Policy {
        merge(&Catalogue::parse(CAT).expect("catalogue"), Settings::parse(cfg).expect("settings"))
            .map(|(p, _)| p)
            .unwrap_or_else(|e| panic!("merge: {e}"))
    }

    /// A key allowed to reach blacksq-* workers, and a delivery credential.
    fn ok_config() -> Policy {
        policy(
            "[services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_to=[\"cf-worker:blacksq-*/RESEND_API_KEY\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n",
        )
    }

    fn req(source: &str, dest: &str) -> PushRequest {
        PushRequest { source: source.into(), dest: dest.into() }
    }

    #[test]
    fn a_declared_destination_is_authorized() {
        let p = ok_config();
        let (src, via, dest) = authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-example/RESEND_API_KEY"),
        )
        .expect("this is exactly what push_to declares");
        assert_eq!(src.id, "resend:blacksq");
        assert_eq!(via.id, "cloudflare-rw");
        assert_eq!(dest.describe(), "cf-worker:blacksq-example/RESEND_API_KEY");
    }

    #[test]
    fn a_key_that_declares_nothing_is_refused_and_told_why() {
        let p = policy(
            "[services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n",
        );
        let (status, msg) =
            authorize(&p, "alice", &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"))
                .map(|_| ())
                .expect_err("default deny");
        assert_eq!(status, 403);
        assert!(msg.contains("push_to"), "{msg}");
    }

    #[test]
    fn a_worker_outside_the_pattern_is_refused() {
        let p = ok_config();
        let (status, _) = authorize(
            &p,
            "alice",
            // someone else's worker, or one we do not own
            &req("resend:blacksq", "cf-worker:not-ours/RESEND_API_KEY"),
        )
        .map(|_| ())
        .expect_err("outside the declared pattern");
        assert_eq!(status, 403);
    }

    #[test]
    fn the_secret_may_not_land_under_another_name() {
        let p = ok_config();
        assert!(authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-grow/STRIPE_SECRET_KEY")
        )
        .map(|_| ())
        .is_err());
    }

    #[test]
    fn a_caller_who_may_not_use_the_key_may_not_push_it() {
        let p = ok_config();
        let (status, _) = authorize(
            &p,
            "nobody",
            &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"),
        )
        .map(|_| ())
        .expect_err("not this caller's key");
        assert_eq!(status, 403);
    }

    /// 🔴 The delivery credential is a second permission, not a free ride: a
    /// caller who may use the Resend key but not the Cloudflare one cannot
    /// borrow Cloudflare by asking for a push.
    #[test]
    fn the_delivering_credential_is_permissioned_separately() {
        let p = policy(
            "[services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_to=[\"cf-worker:blacksq-*/RESEND_API_KEY\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"someone-else\"]\n",
        );
        let (status, msg) = authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"),
        )
        .map(|_| ())
        .expect_err("alice may not use cloudflare-rw");
        assert_eq!(status, 403);
        assert!(msg.contains("cloudflare-rw"), "{msg}");
    }

    #[test]
    fn a_box_with_no_delivery_credential_says_so() {
        let p = policy(
            "[services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_to=[\"cf-worker:blacksq-*/RESEND_API_KEY\"]\n",
        );
        let (status, _) = authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"),
        )
        .map(|_| ())
        .expect_err("cloudflare-rw is not configured here");
        assert_eq!(status, 501);
    }

    #[test]
    fn an_unknown_source_is_a_404_not_a_403() {
        let p = ok_config();
        let (status, _) =
            authorize(&p, "alice", &req("stripe:live", "cf-worker:blacksq-grow/RESEND_API_KEY"))
                .map(|_| ())
                .expect_err("no such key");
        assert_eq!(status, 404);
    }

    /// A key that says nothing inherits the fleet default…
    #[test]
    fn a_key_with_no_rule_of_its_own_inherits_the_default() {
        let p = policy(
            "[push]\ndefault=[\"cf-worker:blacksq-*/*\"]\n\
             [services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n",
        );
        assert!(authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-example/RESEND_API_KEY")
        )
        .is_ok());
        // …and the default still scopes: someone else's worker is refused.
        assert!(authorize(&p, "alice", &req("resend:blacksq", "cf-worker:not-ours/RESEND_API_KEY"))
            .map(|_| ())
            .is_err());
    }

    /// …but an EMPTY list is a decision, not a gap: this key goes nowhere,
    /// whatever the default says. That is how a live Stripe key is pinned down.
    #[test]
    fn an_empty_push_to_overrides_the_default_and_means_nowhere() {
        let p = policy(
            "[push]\ndefault=[\"cf-worker:blacksq-*/*\"]\n\
             [services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\npush_to=[]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n",
        );
        let (status, msg) =
            authorize(&p, "alice", &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"))
                .map(|_| ())
                .expect_err("pinned down");
        assert_eq!(status, 403);
        assert!(msg.contains("push_to"), "{msg}");
    }

    #[test]
    fn a_key_may_narrow_the_default() {
        let p = policy(
            "[push]\ndefault=[\"cf-worker:blacksq-*/*\"]\n\
             [services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_to=[\"cf-worker:blacksq-example/RESEND_API_KEY\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n",
        );
        assert!(authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-example/RESEND_API_KEY")
        )
        .is_ok());
        // the default would have allowed this; the key's own rule does not
        assert!(authorize(&p, "alice", &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"))
            .map(|_| ())
            .is_err());
    }

    #[test]
    fn a_default_that_cannot_be_parsed_refuses_to_start() {
        let cat = Catalogue::parse(CAT).unwrap();
        let set = Settings::parse(
            "[push]\ndefault=[\"cf-worker:*/K\"]\n\
             [services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n",
        )
        .unwrap();
        let err = match merge(&cat, set) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("'any account' must not reach the serving path"),
        };
        assert!(err.contains("[push] default"), "{err}");
    }

    /// The niche case: everywhere the fleet allows, except one
    /// provider this particular key must never reach.
    #[test]
    fn a_key_may_be_forbidden_one_destination_and_keep_the_rest() {
        let p = policy(
            "[push]\ndefault=[\"cf-worker:blacksq-*/*\",\"gh-repo:Black-Squid/*/*\"]\n\
             [services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_deny=[\"gh-repo:*/*/*\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n\
             [services.github-rw.default]\nkey=\"g\"\ncallers=[\"alice\"]\n",
        );
        // the worker is still fine
        assert!(authorize(
            &p,
            "alice",
            &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY")
        )
        .is_ok());
        // GitHub is not, though the default permits it
        let (status, msg) = authorize(
            &p,
            "alice",
            &req("resend:blacksq", "gh-repo:Black-Squid/blacksq-start/RESEND_API_KEY"),
        )
        .map(|_| ())
        .expect_err("denied");
        assert_eq!(status, 403);
        assert!(msg.contains("denied"), "{msg}");
    }

    /// A deny may say "any organisation" — it can only ever narrow. An allow
    /// may not: that is the shape that turns delivery into theft.
    #[test]
    fn a_bare_star_is_refused_in_an_allow_and_accepted_in_a_deny() {
        assert!(Destination::parse_pattern("gh-repo:*/*/*").is_err());
        assert!(Destination::parse_deny("gh-repo:*/*/*").is_ok());
    }

    /// Deny beats allow, including a key's own explicit push_to.
    #[test]
    fn deny_wins_over_the_keys_own_allow() {
        let p = policy(
            "[services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_to=[\"cf-worker:blacksq-*/*\"]\npush_deny=[\"cf-worker:blacksq-grow/*\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n",
        );
        assert!(authorize(&p, "alice", &req("resend:blacksq", "cf-worker:blacksq-demos/RESEND_API_KEY")).is_ok());
        assert!(authorize(&p, "alice", &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY"))
            .map(|_| ())
            .is_err());
    }

    /// push_allow adds to the fleet default rather than replacing it.
    #[test]
    fn push_allow_extends_the_default() {
        let p = policy(
            "[push]\ndefault=[\"cf-worker:blacksq-*/*\"]\n\
             [services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_allow=[\"gh-repo:Black-Squid/*/*\"]\n\
             [services.cloudflare-rw.default]\nkey=\"c\"\ncallers=[\"alice\"]\n\
             [services.github-rw.default]\nkey=\"g\"\ncallers=[\"alice\"]\n",
        );
        assert!(authorize(&p, "alice", &req("resend:blacksq", "cf-worker:blacksq-grow/RESEND_API_KEY")).is_ok());
        assert!(authorize(
            &p,
            "alice",
            &req("resend:blacksq", "gh-repo:Black-Squid/blacksq-start/RESEND_API_KEY")
        )
        .is_ok());
    }

    #[test]
    fn a_push_to_typo_refuses_to_start_rather_than_surprising_a_provision() {
        let cat = Catalogue::parse(CAT).unwrap();
        let set = Settings::parse(
            "[services.resend.blacksq]\nkey=\"k\"\ncallers=[\"alice\"]\n\
             push_to=[\"cf-wroker:blacksq-grow/RESEND_API_KEY\"]\n",
        )
        .unwrap();
        let err = match merge(&cat, set) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a destination nobody can parse must not reach the serving path"),
        };
        assert!(err.contains("push_to"), "{err}");
    }

    #[test]
    fn a_concrete_destination_parses() {
        assert_eq!(
            Destination::parse("cf-worker:blacksq-example/RESEND_API_KEY").unwrap(),
            Destination::CfWorker {
                script: "blacksq-example".into(),
                name: "RESEND_API_KEY".into()
            }
        );
        assert_eq!(
            Destination::parse("gh-env:Black-Squid/blacksq-start/production/CLOUDFLARE_API_TOKEN")
                .unwrap(),
            Destination::GhEnv {
                owner: "Black-Squid".into(),
                repo: "blacksq-start".into(),
                env: "production".into(),
                name: "CLOUDFLARE_API_TOKEN".into()
            }
        );
    }

    #[test]
    fn a_request_may_not_carry_a_wildcard() {
        assert!(Destination::parse("cf-worker:blacksq-*/RESEND_API_KEY").is_err());
        assert!(Destination::parse_pattern("cf-worker:blacksq-*/RESEND_API_KEY").is_ok());
    }

    #[test]
    fn a_key_with_no_destinations_goes_nowhere() {
        let d = Destination::parse("cf-worker:blacksq-grow/RESEND_API_KEY").unwrap();
        assert!(!d.permitted_by(&[]));
    }

    /// A REQUEST always names one real secret. A PATTERN may wildcard the name,
    /// because `[push] default` cannot know what each key is called.
    #[test]
    fn only_a_pattern_may_wildcard_the_name() {
        assert!(Destination::parse("cf-worker:blacksq-grow/*").is_err());
        assert!(Destination::parse_pattern("cf-worker:blacksq-*/*").is_ok());

        let d = Destination::parse("cf-worker:blacksq-grow/STRIPE_SECRET_KEY").unwrap();
        assert!(!d.permitted_by(&["cf-worker:blacksq-*/RESEND_API_KEY".into()]));
        assert!(d.permitted_by(&["cf-worker:blacksq-*/STRIPE_SECRET_KEY".into()]));
        // a name-wildcarded default covers it, which is the point of a default
        assert!(d.permitted_by(&["cf-worker:blacksq-*/*".into()]));
    }

    /// 🔴 The one shape that turns delivery into exfiltration: "any account",
    /// "any organisation". Refused even in a pattern.
    #[test]
    fn a_bare_star_may_not_be_the_first_segment() {
        assert!(Destination::parse_pattern("cf-worker:*/RESEND_API_KEY").is_err());
        assert!(Destination::parse_pattern("gh-repo:*/blacksq-start/K").is_err());
        assert!(Destination::parse_pattern("gh-env:*/r/e/K").is_err());
        // scoped is fine — that is what a fleet default is for
        assert!(Destination::parse_pattern("cf-worker:blacksq-*/*").is_ok());
        assert!(Destination::parse_pattern("gh-repo:Black-Squid/*/*").is_ok());
    }

    #[test]
    fn a_star_cannot_escape_its_segment() {
        let pat = ["gh-repo:Black-Squid/*/DEPLOY_KEY".to_string()];
        assert!(Destination::parse("gh-repo:Black-Squid/blacksq-start/DEPLOY_KEY")
            .unwrap()
            .permitted_by(&pat));
        // another owner is not ours, however the repo is spelled
        assert!(!Destination::parse("gh-repo:Someone-Else/blacksq-start/DEPLOY_KEY")
            .unwrap()
            .permitted_by(&pat));
        // and a traversal attempt is not a valid segment at all
        assert!(Destination::parse("gh-repo:Black-Squid/../DEPLOY_KEY").is_err());
    }

    #[test]
    fn kinds_do_not_cross() {
        let d = Destination::parse("cf-worker:blacksq-grow/RESEND_API_KEY").unwrap();
        assert!(!d.permitted_by(&["gh-repo:Black-Squid/blacksq-grow/RESEND_API_KEY".into()]));
    }

    #[test]
    fn each_kind_names_the_credential_that_delivers_it() {
        assert_eq!(
            Destination::parse("cf-worker:w/K").unwrap().via_upstream(),
            "cloudflare-rw"
        );
        assert_eq!(
            Destination::parse("gh-repo:o/r/K").unwrap().via_upstream(),
            "github-rw"
        );
    }

    #[test]
    fn a_malformed_destination_is_refused_not_guessed() {
        for bad in [
            "cf-worker:blacksq-grow",                    // no name
            "cf-worker:blacksq-grow/lower_case",         // names are upper
            "cf-worker:blacksq-grow/9LIVES",             // leading digit
            "s3:bucket/KEY",                             // unknown kind
            "gh-repo:owner/REPO_KEY",                    // too few segments
            "cf-worker:/KEY",                            // empty segment
        ] {
            assert!(Destination::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
