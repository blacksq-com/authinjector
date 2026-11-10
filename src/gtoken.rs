//! Minting Google OAuth2 access tokens from a held service-account key.
//!
//! 🔴 WHY THIS EXISTS. Every other upstream here takes a static credential: the
//! broker strips whatever the caller sent and injects the key, verbatim, into a
//! header or a query parameter. Google's APIs take neither. They want a
//! short-lived OAuth2 access token, minted by signing a JWT assertion with the
//! service account's private key and exchanging it at Google's token endpoint.
//!
//! The catalogue has said so for months, in the Business Profile entry:
//!
//!     "A static credential cannot satisfy them, so a catalogue entry here
//!      would promise something that can never work. If GBP is needed, the
//!      broker would have to learn to mint tokens from a refresh token, which
//!      is a feature, not an entry."
//!
//! This is that feature. Without it every Google API that needs OAuth --
//! Search Console, Business Profile, Indexing, Drive -- is reachable only by a
//! caller holding the private key itself, which is the thing this whole service
//! exists to prevent.
//!
//! 🔴 THE KEY IS READ, SIGNED WITH, AND DROPPED. The service-account JSON lives
//! in the config like any other credential and arrives here as a `Secret`. It
//! is parsed inside one function, the signing key is built from it, and both go
//! out of scope at the end of the mint. What is cached is the ACCESS TOKEN,
//! which is the thing designed to be held for an hour and is useless after it.
//!
//! 🔴 ONE MINT AN HOUR, NOT ONE A REQUEST. Google issues these for 3600s and
//! rate-limits the token endpoint. Tokens are cached per upstream id and reused
//! until they are within `SKEW` of expiry, so a thousand Search Console calls
//! cost one token exchange.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::secret::Secret;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Treat a token as spent this long before it actually expires, so a request
/// in flight cannot arrive after it has died.
const SKEW: Duration = Duration::from_secs(300);
/// What we ask for. Google caps it at 3600 regardless.
const LIFETIME_SECS: u64 = 3600;

#[derive(Debug)]
pub enum TokenError {
    /// The stored credential is not a service-account JSON.
    Credential(String),
    /// Signing failed.
    Sign(String),
    /// The token endpoint refused or was unreachable. NEVER carries the
    /// response body: a token response contains a token.
    Exchange(String),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Credential(m) => write!(f, "service-account credential: {m}"),
            TokenError::Sign(m) => write!(f, "assertion signing: {m}"),
            TokenError::Exchange(m) => write!(f, "token exchange: {m}"),
        }
    }
}

/// The fields of a Google service-account JSON that matter here.
#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default)]
    token_uri: String,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
    /// Domain-wide delegation. Absent for an ordinary service account.
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<&'a str>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

struct Cached {
    token: String,
    /// When this stops being usable, already reduced by SKEW.
    good_until: Instant,
}

/// Per-upstream access-token cache.
pub struct Tokens {
    cache: Mutex<HashMap<String, Cached>>,
}

impl Default for Tokens {
    fn default() -> Self {
        Self::new()
    }
}

impl Tokens {
    pub fn new() -> Self {
        Self { cache: Mutex::new(HashMap::new()) }
    }

    /// A usable access token for `upstream_id`, minted if the cache has none.
    ///
    /// Returns a `Secret` so the token takes the same path as every other
    /// credential: wiped on drop, never Debug-printed, and injected by the one
    /// function that is allowed to see a credential.
    pub async fn access_token(
        &self,
        client: &reqwest::Client,
        upstream_id: &str,
        key_json: &Secret,
        scope: &str,
    ) -> Result<Secret, TokenError> {
        if let Some(t) = self.cached(upstream_id) {
            return Ok(t);
        }
        // 🔴 The assertion is built and signed inside this call. Neither the
        // parsed key nor the PEM outlives it.
        let (assertion, token_uri) = sign_assertion(key_json, scope)?;
        let resp = client
            .post(if token_uri.is_empty() { TOKEN_URL } else { token_uri.as_str() })
            .form(&[("grant_type", GRANT), ("assertion", assertion.expose_for_injection())])
            .send()
            .await
            // 🔴 reqwest's Display can carry the URL; the body can carry a
            // token. Neither is rendered -- only the kind of failure.
            .map_err(|e| TokenError::Exchange(describe(&e)))?;

        let status = resp.status();
        let body = resp.bytes().await.map_err(|e| TokenError::Exchange(describe(&e)))?;
        if !status.is_success() {
            // Google's error bodies are short and carry no secret, but we do
            // not trust that: the status is enough to act on.
            return Err(TokenError::Exchange(format!("token endpoint returned {}", status.as_u16())));
        }
        let parsed: TokenResponse = serde_json::from_slice(&body)
            .map_err(|_| TokenError::Exchange("token endpoint returned unparseable JSON".into()))?;
        if parsed.access_token.is_empty() {
            return Err(TokenError::Exchange("token endpoint returned no access_token".into()));
        }

        let life = Duration::from_secs(if parsed.expires_in == 0 { LIFETIME_SECS } else { parsed.expires_in });
        let good_until = Instant::now() + life.saturating_sub(SKEW);
        if let Ok(mut c) = self.cache.lock() {
            c.insert(upstream_id.to_string(), Cached { token: parsed.access_token.clone(), good_until });
        }
        Ok(Secret::new(parsed.access_token))
    }

    fn cached(&self, upstream_id: &str) -> Option<Secret> {
        let c = self.cache.lock().ok()?;
        let hit = c.get(upstream_id)?;
        if Instant::now() < hit.good_until {
            Some(Secret::new(hit.token.clone()))
        } else {
            None
        }
    }

    /// Drop a cached token — used when an upstream answers 401, so one stale
    /// token does not poison an hour of calls.
    pub fn forget(&self, upstream_id: &str) {
        if let Ok(mut c) = self.cache.lock() {
            c.remove(upstream_id);
        }
    }
}

/// Build and RS256-sign the JWT assertion. Returns it with the token URI the
/// key itself names, so a key issued for a non-default endpoint still works.
fn sign_assertion(key_json: &Secret, scope: &str) -> Result<(Secret, String), TokenError> {
    let sa: ServiceAccount = serde_json::from_str(key_json.expose_for_injection())
        .map_err(|_| TokenError::Credential(
            "not a service-account JSON (expected client_email and private_key)".into()))?;
    if sa.client_email.is_empty() || sa.private_key.is_empty() {
        return Err(TokenError::Credential("client_email or private_key is empty".into()));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| TokenError::Sign("system clock is before the epoch".into()))?
        .as_secs();
    let aud = if sa.token_uri.is_empty() { TOKEN_URL } else { sa.token_uri.as_str() };
    let claims = Claims {
        iss: &sa.client_email,
        scope,
        aud,
        exp: now + LIFETIME_SECS,
        iat: now,
        sub: None,
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        // The error KIND only. jsonwebtoken's Display can quote the input it
        // failed on, and the input here is a private key.
        .map_err(|e| TokenError::Sign(format!("private_key is not an RSA PEM ({:?})", e.kind())))?;
    let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    let jwt = jsonwebtoken::encode(&header, &claims, &key)
        .map_err(|e| TokenError::Sign(format!("{:?}", e.kind())))?;
    Ok((Secret::new(jwt), aud.to_string()))
}

/// A reqwest error reduced to its kind. Same rule as proxy::describe: the
/// Display impl can include the URL, and this one talks to a token endpoint.
fn describe(e: &reqwest::Error) -> String {
    if e.is_timeout() { "timed out".into() }
    else if e.is_connect() { "connection failed".into() }
    else if e.is_body() { "body error".into() }
    else if e.is_decode() { "decode error".into() }
    else { "request failed".into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_json_credential_is_rejected_by_name() {
        let err = sign_assertion(&Secret::new("sk-not-a-service-account".into()), "x").unwrap_err();
        assert!(matches!(err, TokenError::Credential(_)), "{err}");
    }

    #[test]
    fn json_without_a_private_key_is_rejected() {
        let err = sign_assertion(
            &Secret::new(r#"{"client_email":"a@b.iam.gserviceaccount.com","private_key":""}"#.into()),
            "x").unwrap_err();
        assert!(matches!(err, TokenError::Credential(_)), "{err}");
    }

    #[test]
    fn a_garbage_pem_fails_at_signing_not_at_parse() {
        let err = sign_assertion(
            &Secret::new(r#"{"client_email":"a@b.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n"}"#.into()), // gitleaks:allow (fixture: the body is the word "nope")
            "x").unwrap_err();
        assert!(matches!(err, TokenError::Sign(_)), "{err}");
    }

    #[test]
    fn an_expired_cache_entry_is_not_returned() {
        let t = Tokens::new();
        t.cache.lock().unwrap().insert(
            "gsc".into(),
            Cached { token: "stale".into(), good_until: Instant::now() - Duration::from_secs(1) });
        assert!(t.cached("gsc").is_none());
    }

    #[test]
    fn a_live_cache_entry_is_returned_and_forget_clears_it() {
        let t = Tokens::new();
        t.cache.lock().unwrap().insert(
            "gsc".into(),
            Cached { token: "fresh".into(), good_until: Instant::now() + Duration::from_secs(60) });
        assert_eq!(t.cached("gsc").unwrap().expose_for_injection(), "fresh");
        t.forget("gsc");
        assert!(t.cached("gsc").is_none());
    }
}
