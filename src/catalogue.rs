//! The service catalogue: what each upstream IS.
//!
//! 🔴 PUBLIC, SHIPPED, AND THE SAME FOR EVERYONE. This file holds no secret
//! and no permission. It is the mechanical knowledge of how to talk to a
//! service -- where it lives, which field it wants its key in, what its
//! endpoints are -- which is identical for every user of that service.
//!
//! It is separate from the private config on purpose:
//!
//!   catalogue    what a service IS            public, shipped, updatable
//!   config       who may use it, and the keys private, 0640, yours
//!
//! Adding support for a new service is then a catalogue update, not a change
//! anyone has to make to their own configuration. Note the asymmetry: a
//! catalogue entry is per SERVICE, while a config may hold SEVERAL labelled
//! keys for that one service. "How to talk to Tavily" is one fact however
//! many Tavily accounts you hold.
//!
//! 🔴 THE CATALOGUE DECIDES WHERE CREDENTIALS GO. `base_url` together with
//! `auth_header` or `auth_param` determines which host receives a key and in
//! which field. A catalogue swapped by an attacker would silently redirect
//! every credential while the audit log recorded a perfectly ordinary
//! forward. So:
//!
//!   - a fetched catalogue must be signature-verified before it is written
//!   - `catalogue update` shows a diff for any service already configured and
//!     waits for a human, rather than applying silently
//!
//! Neither is implemented yet; both belong before the fetch command exists,
//! not after.

use std::collections::HashMap;

use serde::Deserialize;

/// Where the credential goes on the wire.
///
/// 🔴 QUERY IS THE WEAKER OF THE TWO AND IS NEVER THE DEFAULT. A credential in
/// a URL reaches the upstream's access logs, any intermediary, and a `Referer`
/// header if the response ever renders in a browser. We strip it from OUR
/// audit log (`audit::path_only`), but we cannot strip it from theirs.
///
/// It exists because several services accept nothing else -- voip.ms and
/// Google's geocoding endpoint among them -- and the alternative to brokering
/// those keys is the caller holding them, which is worse.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthIn {
    #[default]
    Header,
    Query,
    /// 🔴 NOT A STORED STRING. The held credential is a Google service-account
    /// JSON; the broker signs an assertion with it and injects the short-lived
    /// access token Google returns. `auth_scope` says what the token is for.
    /// See src/gtoken.rs for why this had to be a feature rather than an entry.
    #[serde(rename = "google_sa")]
    GoogleSa,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Endpoint {
    pub methods: Vec<String>,
    pub path_prefix: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServiceDef {
    /// Human name, for the portal and for `authinjector list`.
    #[serde(default)]
    pub name: String,
    pub base_url: String,
    /// Header or query. Defaults to header, so an entry that says nothing gets
    /// the safer of the two.
    #[serde(default)]
    pub auth_in: AuthIn,
    /// The header this service wants its credential in. Header mode only.
    #[serde(default)]
    pub auth_header: String,
    /// Literal prefix: `"Bearer "` for most, `""` for a raw key header.
    /// Header mode only -- a query parameter carries the bare value.
    #[serde(default)]
    pub auth_prefix: String,
    /// The query parameter this service wants its credential in. Query mode
    /// only.
    #[serde(default)]
    pub auth_param: String,
    /// OAuth scope the minted token carries. `google_sa` mode only, and
    /// required there -- a token with no scope is refused by Google, and
    /// guessing one on the user's behalf would widen access silently.
    #[serde(default)]
    pub auth_scope: String,
    /// Everything this service offers. A user's config may narrow this, never
    /// widen it.
    pub endpoints: Vec<Endpoint>,
    /// Where the user gets a key. Shown by `authinjector list`, never fetched.
    #[serde(default)]
    pub signup_url: String,
    /// Indicative cost, overridable per install.
    #[serde(default)]
    pub cost_per_call_cad: f64,
}

#[derive(Debug, Deserialize, Default)]
pub struct Catalogue {
    #[serde(default)]
    pub services: HashMap<String, ServiceDef>,
}

#[derive(Debug)]
pub enum CatalogueError {
    Read(String),
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for CatalogueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CatalogueError::Read(m) => write!(f, "cannot read catalogue: {m}"),
            CatalogueError::Parse(m) => write!(f, "cannot parse catalogue: {m}"),
            CatalogueError::Invalid(m) => write!(f, "invalid catalogue: {m}"),
        }
    }
}

impl Catalogue {
    pub fn parse(text: &str) -> Result<Self, CatalogueError> {
        let c: Catalogue = toml::from_str(text).map_err(|e| CatalogueError::Parse(e.to_string()))?;
        for (id, s) in &c.services {
            // 🔴 https only. A catalogue entry with http:// would put the
            // injected credential on the wire in clear, and a malicious
            // catalogue is exactly how that would arrive.
            if !s.base_url.starts_with("https://") {
                return Err(CatalogueError::Invalid(format!("{id}: base_url must be https://")));
            }

            // 🔴 EXACTLY ONE AUTH FIELD IS POPULATED, and it is the one
            // `auth_in` names. An entry carrying both would leave the
            // credential's destination depending on which branch of `inject`
            // happened to run -- the kind of ambiguity that survives review
            // precisely because both fields look intentional.
            // google_sa carries neither: it mints its own header, and declaring
            // one here would suggest a stored string goes into it.
            if s.auth_in != AuthIn::GoogleSa && !s.auth_scope.is_empty() {
                return Err(CatalogueError::Invalid(format!(
                    "{id}: auth_scope is only meaningful when auth_in is \"google_sa\""
                )));
            }
            match s.auth_in {
                AuthIn::GoogleSa => {
                    if s.auth_scope.trim().is_empty() {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: auth_in is \"google_sa\" so auth_scope must name the OAuth scope"
                        )));
                    }
                    if !s.auth_header.is_empty() || !s.auth_param.is_empty() {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: google_sa injects its own Authorization header — \
                             auth_header and auth_param must be empty"
                        )));
                    }
                    // A scope is sent to Google verbatim inside a signed
                    // assertion. Keep it to the shape Google actually uses, so
                    // a mistyped entry fails here rather than as an opaque 400.
                    if !s.auth_scope.split_whitespace().all(|u| u.starts_with("https://www.googleapis.com/auth/")) {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: auth_scope must be one or more https://www.googleapis.com/auth/… URLs"
                        )));
                    }
                }
                AuthIn::Header => {
                    if s.auth_header.trim().is_empty() {
                        return Err(CatalogueError::Invalid(format!("{id}: auth_header must not be empty")));
                    }
                    if !s.auth_param.is_empty() {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: auth_param is set but auth_in is \"header\" — one or the other, never both"
                        )));
                    }
                }
                AuthIn::Query => {
                    if s.auth_param.trim().is_empty() {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: auth_in is \"query\" so auth_param must name the parameter"
                        )));
                    }
                    // A parameter name is spliced into a URL. Anything outside
                    // this set could smuggle a second parameter, or terminate
                    // the query and rewrite the path.
                    if !s.auth_param.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: auth_param may contain only letters, digits, '_', '-' and '.'"
                        )));
                    }
                    if !s.auth_header.is_empty() || !s.auth_prefix.is_empty() {
                        return Err(CatalogueError::Invalid(format!(
                            "{id}: auth_header/auth_prefix are set but auth_in is \"query\""
                        )));
                    }
                }
            }

            if s.endpoints.is_empty() {
                return Err(CatalogueError::Invalid(format!("{id}: no endpoints declared")));
            }
            for e in &s.endpoints {
                if !e.path_prefix.starts_with('/') {
                    return Err(CatalogueError::Invalid(format!("{id}: path_prefix must begin with '/'")));
                }
                if e.methods.is_empty() {
                    return Err(CatalogueError::Invalid(format!("{id}: an endpoint declares no methods")));
                }
            }
        }
        Ok(c)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, CatalogueError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CatalogueError::Read(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn get(&self, id: &str) -> Option<&ServiceDef> {
        self.services.get(id)
    }

    pub fn ids(&self) -> Vec<&String> {
        let mut v: Vec<&String> = self.services.keys().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape a google_sa entry must have, with one field overridable so
    /// each rule can be tested by breaking exactly one thing.
    fn google_sa(extra: &str) -> String {
        format!(r#"
[services.gsc]
name = "Google Search Console"
base_url = "https://searchconsole.googleapis.com"
auth_in = "google_sa"
auth_scope = "https://www.googleapis.com/auth/webmasters.readonly"
{extra}
endpoints = [ {{ methods = ["POST"], path_prefix = "/webmasters/v3/sites/" }} ]
"#)
    }

    #[test]
    fn a_google_sa_entry_is_accepted_and_keeps_its_scope() {
        let c = Catalogue::parse(&google_sa("")).expect("valid");
        let g = &c.services["gsc"];
        assert_eq!(g.auth_in, AuthIn::GoogleSa);
        assert_eq!(g.auth_scope, "https://www.googleapis.com/auth/webmasters.readonly");
    }

    #[test]
    fn google_sa_without_a_scope_is_refused() {
        let t = google_sa("").replace(
            "auth_scope = \"https://www.googleapis.com/auth/webmasters.readonly\"", "");
        let e = Catalogue::parse(&t).unwrap_err();
        assert!(format!("{e:?}").contains("auth_scope"), "{e:?}");
    }

    #[test]
    fn google_sa_declaring_a_header_is_refused() {
        // It mints its own Authorization; naming one would suggest a stored
        // string goes into it.
        let e = Catalogue::parse(&google_sa("auth_header = \"Authorization\"")).unwrap_err();
        assert!(format!("{e:?}").contains("auth_header"), "{e:?}");
    }

    #[test]
    fn a_scope_that_is_not_a_google_scope_url_is_refused() {
        let t = google_sa("").replace(
            "https://www.googleapis.com/auth/webmasters.readonly", "webmasters.readonly");
        let e = Catalogue::parse(&t).unwrap_err();
        assert!(format!("{e:?}").contains("auth_scope"), "{e:?}");
    }

    #[test]
    fn a_scope_on_a_static_key_service_is_refused() {
        let e = Catalogue::parse(r#"
[services.pexels]
base_url = "https://api.pexels.com"
auth_header = "Authorization"
auth_scope = "https://www.googleapis.com/auth/webmasters.readonly"
endpoints = [ { methods = ["GET"], path_prefix = "/v1/search" } ]
"#).unwrap_err();
        assert!(format!("{e:?}").contains("auth_scope"), "{e:?}");
    }


    const CAT: &str = r#"
[services.pexels]
name = "Pexels"
base_url = "https://api.pexels.com"
auth_header = "Authorization"
auth_prefix = ""
signup_url = "https://www.pexels.com/api/"
endpoints = [
  { methods = ["GET"], path_prefix = "/v1/search" },
  { methods = ["GET"], path_prefix = "/v1/curated" },
]

[services.tavily]
name = "Tavily"
base_url = "https://api.tavily.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
cost_per_call_cad = 0.008
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]

[services.geocoding]
name = "Google Geocoding"
base_url = "https://maps.googleapis.com"
auth_in = "query"
auth_param = "key"
endpoints = [{ methods = ["GET"], path_prefix = "/maps/api/geocode/json" }]
"#;

    #[test]
    fn parses_services_and_their_auth_style() {
        let c = Catalogue::parse(CAT).expect("valid catalogue");
        assert_eq!(c.ids().len(), 3);
        let p = c.get("pexels").unwrap();
        assert_eq!(p.auth_prefix, "", "pexels takes a raw key, not Bearer");
        let t = c.get("tavily").unwrap();
        assert_eq!(t.auth_prefix, "Bearer ");
        assert_eq!(t.cost_per_call_cad, 0.008);
    }

    #[test]
    fn auth_in_defaults_to_the_safer_of_the_two() {
        let c = Catalogue::parse(CAT).unwrap();
        assert_eq!(c.get("pexels").unwrap().auth_in, AuthIn::Header);
        assert_eq!(c.get("geocoding").unwrap().auth_in, AuthIn::Query);
        assert_eq!(c.get("geocoding").unwrap().auth_param, "key");
    }

    #[test]
    fn rejects_a_plaintext_base_url() {
        let bad = CAT.replace("https://api.pexels.com", "http://api.pexels.com");
        assert!(matches!(Catalogue::parse(&bad), Err(CatalogueError::Invalid(_))));
    }

    #[test]
    fn rejects_a_service_with_no_endpoints() {
        let bad = r#"
[services.x]
base_url = "https://x.example.com"
auth_header = "Authorization"
endpoints = []
"#;
        assert!(matches!(Catalogue::parse(bad), Err(CatalogueError::Invalid(_))));
    }

    #[test]
    fn query_mode_without_a_parameter_name_is_refused() {
        let bad = r#"
[services.x]
base_url = "https://x.example.com"
auth_in = "query"
endpoints = [{ methods = ["GET"], path_prefix = "/" }]
"#;
        assert!(matches!(Catalogue::parse(bad), Err(CatalogueError::Invalid(_))));
    }

    #[test]
    fn an_entry_may_not_declare_both_a_header_and_a_parameter() {
        // Ambiguity about where a credential goes is the one thing this file
        // exists to remove.
        let bad = r#"
[services.x]
base_url = "https://x.example.com"
auth_header = "X-Key"
auth_param = "key"
endpoints = [{ methods = ["GET"], path_prefix = "/" }]
"#;
        assert!(matches!(Catalogue::parse(bad), Err(CatalogueError::Invalid(_))));
    }

    #[test]
    fn a_parameter_name_that_could_rewrite_the_url_is_refused() {
        for evil in ["key&admin", "key=1", "key#", "a/b", "a?b"] {
            let bad = format!(
                "[services.x]\nbase_url = \"https://x.example.com\"\nauth_in = \"query\"\n\
                 auth_param = \"{evil}\"\nendpoints = [{{ methods = [\"GET\"], path_prefix = \"/\" }}]\n"
            );
            assert!(
                matches!(Catalogue::parse(&bad), Err(CatalogueError::Invalid(_))),
                "auth_param {evil:?} must be refused"
            );
        }
    }

    #[test]
    fn comments_are_fine_and_a_missing_prefix_defaults_to_empty() {
        let c = Catalogue::parse(
            "# a comment\n\
             [services.x]\n\
             base_url = \"https://x.example.com\"\n\
             auth_header = \"X-Key\"\n\
             endpoints = [{ methods = [\"GET\"], path_prefix = \"/\" }]\n",
        )
        .expect("valid");
        assert_eq!(c.get("x").unwrap().auth_prefix, "");
    }

    #[test]
    fn the_shipped_catalogue_is_valid() {
        // The file that actually gets installed, not a fixture. A typo in it
        // is a startup failure on every box, so it is checked here.
        let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/catalogue.toml"))
            .expect("catalogue.toml is part of the repo");
        let c = Catalogue::parse(&text).expect("the shipped catalogue must parse and validate");

        // Every declared section became a service. A magic number here would
        // only have to be edited every time a service is added; this instead
        // catches the failure that actually matters -- two sections sharing a
        // name, where the second silently replaces the first and a key would
        // be sent to the wrong host.
        let declared = text.lines().filter(|l| l.starts_with("[services.")).count();
        assert_eq!(c.ids().len(), declared, "a service section was silently overwritten");
        assert!(declared > 0, "the shipped catalogue is empty");
    }
}
