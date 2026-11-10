//! The private config, and the merge that turns catalogue + config into policy.
//!
//! 🔴 TWO FILES, TWO PURPOSES:
//!
//!   catalogue.toml   what a service IS    public, shipped, updatable
//!   config.toml      who may use it, and  private, 0640 root:authinjector
//!                    the keys themselves
//!
//! Your keys sit beside the rules that govern them, in one short file you can
//! read. Everything mechanical -- base URLs, which field a service wants its
//! key in, what its endpoints are called -- comes from the catalogue, so
//! adding support for a new service never requires anyone to edit their own
//! config.
//!
//! 🔴 EVERY KEY LIVES UNDER A LABEL.
//!
//!     [services.tavily.blacksq]
//!     key = "..."
//!     callers = ["alice"]
//!
//!     [services.tavily.personal]
//!     key = "..."
//!     callers = ["alice"]
//!
//! One service, several accounts, each with its OWN callers and its own rate
//! limit -- which is the point. "alice may use the Black Squid Tavily account
//! but not the personal one" is a sentence the old service-keyed shape could
//! not express at all.
//!
//! The label is the address. `label = "default"` is reached as `/tavily/...`
//! and every other label as `/tavily:blacksq/...`, so the first path segment
//! of a request is LITERALLY the map key here -- see `instance_key`. There is
//! no resolution step, and so no place for one to disagree with another.
//!
//! 🔴 TWO OF THE FOUR FILES TO READ ARE HERE: config loading and the allowlist.
//! Both are pure. Every refusal is unit-testable without a socket or a key.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::catalogue::{AuthIn, Catalogue, Endpoint};
use crate::secret::Secret;

/// Headers a caller may never supply, whatever the catalogue says.
///
/// Two groups, for two different reasons.
///
/// CREDENTIAL SLOTS -- `authorization`, `cookie`, `proxy-authorization`. A
/// caller must not be able to put its own credential beside ours.
///
/// 🔴 CONNECTION-SCOPED HEADERS -- everything else in this list. These
/// describe the hop the caller made TO US, and are meaningless or actively
/// wrong on the separate connection we make to the upstream. RFC 9110 requires
/// a proxy to drop them rather than forward them.
///
/// `host` is the one that mattered. Forwarding the caller's `Host: localhost`
/// to a real API produced two different failures that looked like completely
/// unrelated outages:
///
///   - nginx front ends (Stripe, Meta, Outscraper) answered 400 or 502 with
///     their own HTML error page, never reaching the API behind them, so the
///     response looked nothing like an auth error
///   - HTTP/2 hosts (every googleapis.com endpoint, ElevenLabs) rejected it
///     CLIENT-SIDE while deriving the `:authority` pseudo-header, so the
///     request never left this machine and surfaced as "upstream unreachable"
///
/// Both read as "that service is down" or "that key is bad". Neither was.
/// `content-length` belongs here for the same structural reason: the outbound
/// client computes its own from the body it is given, and a stale one from the
/// caller contradicts it.
pub const ALWAYS_STRIP: &[&str] = &[
    // credential slots
    "authorization",
    "cookie",
    "proxy-authorization",
    // connection-scoped: ours to set, never the caller's to carry over
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "proxy-authenticate",
    "proxy-connection",
];

/// The label reached by the bare `/{service}/...` form.
pub const DEFAULT_LABEL: &str = "default";

/// Fields that belong to one key. Seeing any of them where a label should be
/// means the file predates labels -- see `ServiceEntry`'s Deserialize.
const KEY_LEVEL_FIELDS: [&str; 6] =
    ["key", "callers", "rate_per_minute", "cost_per_call_cad", "endpoints", "version"];

#[derive(Debug)]
pub enum ConfigError {
    Read(String),
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read(m) => write!(f, "cannot read config: {m}"),
            ConfigError::Parse(m) => write!(f, "cannot parse config: {m}"),
            ConfigError::Invalid(m) => write!(f, "invalid config: {m}"),
        }
    }
}
impl std::error::Error for ConfigError {}

/// The address of one key: `tavily` for the default label, `tavily:blacksq`
/// otherwise.
///
/// 🔴 THIS IS THE SINGLE DEFINITION OF HOW A KEY IS ADDRESSED. The policy map,
/// the secrets map, the rate-limiter bucket, the audit line and the first
/// segment of a request path are all this same string. Nothing anywhere else
/// parses or reassembles it, so none of them can drift apart.
pub fn instance_key(service: &str, label: &str) -> String {
    if label == DEFAULT_LABEL {
        service.to_string()
    } else {
        format!("{service}:{label}")
    }
}

/// A label is part of a URL path segment and part of a map key, so it is kept
/// to an unambiguous set rather than trusted.
pub fn valid_label(label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err("a label must not be empty".into());
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')) {
        return Err(format!(
            "label {label:?} may contain only letters, digits, '-' and '_' \
             (it becomes part of the request path, as /service:{label}/...)"
        ));
    }
    Ok(())
}

// ── The private file ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ServiceSettings {
    /// 🔴 Deserialised straight into a zeroizing Secret -- never through an
    /// intermediate String that would be freed without being wiped.
    pub key: Secret,
    /// Mandatory. The difference between "this box may call it" and "this
    /// process may call it".
    pub callers: Vec<String>,
    #[serde(default = "default_per_minute")]
    pub rate_per_minute: u32,
    /// Overrides the catalogue's indicative cost when set.
    #[serde(default)]
    pub cost_per_call_cad: Option<f64>,
    /// Optional NARROWING of the catalogue's endpoints. Never a widening --
    /// see `merge`.
    #[serde(default)]
    pub endpoints: Option<Vec<Endpoint>>,
    /// Where this key may be DELIVERED, overriding `[push] default`.
    ///
    /// 🔴 ABSENT AND EMPTY MEAN DIFFERENT THINGS. No `push_to` at all = use the
    /// fleet default. `push_to = []` = nowhere, ever, whatever the default says
    /// — which is how a key too consequential to install automatically (a live
    /// Stripe key, the account master) is pinned down.
    #[serde(default)]
    pub push_to: Option<Vec<String>>,
    /// Destinations this key may reach IN ADDITION to whatever applies — the
    /// common override, because it leaves the fleet rule doing its job.
    #[serde(default)]
    pub push_allow: Vec<String>,
    /// Destinations this key may never reach, whatever else says otherwise.
    /// Deny wins. A bare `*` first segment is allowed HERE and nowhere else:
    /// "never to any GitHub repository" is a sentence worth writing.
    #[serde(default)]
    pub push_deny: Vec<String>,
    #[serde(default = "default_version")]
    pub version: u32,
}

fn default_per_minute() -> u32 {
    60
}
fn default_version() -> u32 {
    1
}

/// Every labelled key for one service.
#[derive(Debug, Default)]
pub struct ServiceEntry {
    pub instances: BTreeMap<String, ServiceSettings>,
}

/// 🔴 HAND-WRITTEN, AND NOT `#[serde(untagged)]`.
///
/// Accepting both the old flat shape and the new labelled one would need an
/// untagged enum, and untagged buffers the whole table into serde's internal
/// `Content` type first -- which holds the key in an ordinary String that is
/// dropped without being wiped. That would quietly undo the single guarantee
/// `Secret` exists to make, and it would not show up in any test.
///
/// So there is one shape, and a file written before labels existed gets a
/// specific error naming the fix rather than a type mismatch three levels
/// deep. The error is raised on the FIELD NAME, before the value is read, so
/// an old key still never passes through a plain String.
impl<'de> Deserialize<'de> for ServiceEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct EntryVisitor;

        impl<'de> Visitor<'de> for EntryVisitor {
            type Value = ServiceEntry;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a table of labelled keys, e.g. [services.tavily.default]")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ServiceEntry, A::Error> {
                let mut instances = BTreeMap::new();
                while let Some(label) = map.next_key::<String>()? {
                    if KEY_LEVEL_FIELDS.contains(&label.as_str()) {
                        return Err(de::Error::custom(format!(
                            "found `{label}` where a label was expected. This config predates \
                             labelled keys; every key now lives under one, so that a service can \
                             hold more than one account:\n\
                             \n    [services.<service>.default]\n    key = \"...\"\n    callers = [\"alice\"]\n\
                             \nRun `authinjector migrate` — it moves each existing entry under \
                             `default`, keeping your keys and your comments exactly as they are."
                        )));
                    }
                    valid_label(&label).map_err(de::Error::custom)?;
                    let settings: ServiceSettings = map.next_value()?;
                    if instances.insert(label.clone(), settings).is_some() {
                        return Err(de::Error::custom(format!("label {label:?} appears twice")));
                    }
                }
                Ok(ServiceEntry { instances })
            }
        }

        d.deserialize_map(EntryVisitor)
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub services: BTreeMap<String, ServiceEntry>,
    /// Fleet-wide delivery rules — see `PushDefaults`.
    #[serde(default)]
    pub push: PushDefaults,
}

/// `[push] default = [...]` — where any key may be delivered unless it says
/// otherwise.
///
/// 🔴 ONE SECTION, NOT TWENTY-FIVE LINES: a default destination list, with an
/// optional per-key override, so allowing a destination is one line. Every key
/// on this box is ours and every destination is ours; stating that once is the
/// honest shape, and a rule nobody has to repeat is a rule that stays true.
#[derive(Debug, Default, Deserialize)]
pub struct PushDefaults {
    #[serde(default)]
    pub default: Vec<String>,
}

impl Settings {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Every configured key, as `(service, label)`, sorted. For `show`.
    pub fn instances(&self) -> Vec<(&String, &String, &ServiceSettings)> {
        let mut v = Vec::new();
        for (service, entry) in &self.services {
            for (label, s) in &entry.instances {
                v.push((service, label, s));
            }
        }
        v
    }
}

// ── The merged runtime policy ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AllowRule {
    pub methods: Vec<String>,
    pub path_prefix: String,
}

impl AllowRule {
    fn matches(&self, method: &str, path: &str) -> bool {
        self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) && path.starts_with(&self.path_prefix)
    }
}

/// Where this upstream's credential goes. Resolved once, at startup, from the
/// catalogue -- so `inject` has no decision left to make beyond which arm.
#[derive(Debug, Clone)]
pub enum Auth {
    Header { name: String, prefix: String },
    Query { param: String },
    /// The held credential is a Google service-account JSON, not a token. The
    /// proxy mints a short-lived access token from it and injects that; see
    /// src/gtoken.rs.
    GoogleServiceAccount { scope: String },
}

#[derive(Debug)]
pub struct Upstream {
    /// `tavily` or `tavily:blacksq` — the first path segment, verbatim.
    pub id: String,
    pub service: String,
    pub label: String,
    pub base_url: String,
    pub auth: Auth,
    pub allow: Vec<AllowRule>,
    pub callers: HashSet<String>,
    pub per_minute: u32,
    pub cost_per_call_cad: f64,
    /// Delivery destinations this key may reach — the fleet default or this
    /// key's own, plus `push_allow`. See `ServiceSettings::push_to`.
    pub push_to: Vec<String>,
    /// …minus anything matching these, which win. See `push_deny`.
    pub push_deny: Vec<String>,
    pub version: u32,
}

impl Upstream {
    /// `{id}@{n}` — an audit line is attributable to the exact rule in force,
    /// and to the exact key, since the id carries the label.
    pub fn policy_id(&self) -> String {
        format!("{}@{}", self.id, self.version)
    }

    pub fn permits_caller(&self, caller: &str) -> bool {
        self.callers.contains(caller)
    }

    pub fn permits(&self, method: &str, path: &str) -> bool {
        self.allow.iter().any(|r| r.matches(method, path))
    }

    /// Path matches but the verb does not — lets the server answer 405, not 403.
    pub fn path_known_method_wrong(&self, path: &str) -> bool {
        self.allow.iter().any(|r| path.starts_with(&r.path_prefix))
    }

    /// 🔴 STRIP, DO NOT OVERWRITE. A caller must not influence the credential
    /// slot, including via a differently-cased duplicate a naive "set" leaves
    /// beside ours.
    ///
    /// A query-mode service adds nothing here: its credential field is in the
    /// URL, and `inject::set_query_param` removes the caller's copy there.
    pub fn strip_set(&self) -> HashSet<String> {
        let mut s: HashSet<String> = ALWAYS_STRIP.iter().map(|h| h.to_string()).collect();
        match &self.auth {
            Auth::Header { name, .. } => { s.insert(name.to_ascii_lowercase()); }
            // google_sa injects Authorization with a token it minted, so the
            // caller's own Authorization must go the same way a header-mode
            // caller's does. Leaving it would send two, and which one the
            // upstream honours is not ours to decide.
            Auth::GoogleServiceAccount { .. } => { s.insert("authorization".to_string()); }
            Auth::Query { .. } => {}
        }
        s
    }
}

pub struct Policy {
    pub upstreams: HashMap<String, Upstream>,
}

impl Policy {
    pub fn get(&self, id: &str) -> Option<&Upstream> {
        self.upstreams.get(id)
    }

    /// Which labels exist for a service. Used to turn "unknown upstream" into
    /// an answer rather than a dead end when a caller asks for `/tavily` and
    /// every Tavily key happens to be labelled.
    pub fn labels_for(&self, service: &str) -> Vec<&str> {
        let mut v: Vec<&str> = self
            .upstreams
            .values()
            .filter(|u| u.service == service)
            .map(|u| u.id.as_str())
            .collect();
        v.sort_unstable();
        v
    }

    /// What a caller may be told about its own permissions (PROTOCOL.md §7).
    /// Never a key, never another caller's rules.
    pub fn visible_to(&self, caller: &str) -> Vec<serde_json::Value> {
        let mut v: Vec<&Upstream> = self.upstreams.values().filter(|u| u.permits_caller(caller)).collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        v.into_iter()
            .map(|u| {
                serde_json::json!({
                    "id": u.id,
                    "service": u.service,
                    "label": u.label,
                    "allow": u.allow.iter().map(|r| serde_json::json!({
                        "methods": r.methods, "path_prefix": r.path_prefix,
                    })).collect::<Vec<_>>(),
                    "rate_per_minute": u.per_minute,
                })
            })
            .collect()
    }
}

/// Build the runtime policy from the public catalogue and the private config.
///
/// Returns the policy plus the keys, kept in a separate map so a `Secret`
/// arrives at `inject::apply` as an explicit argument rather than hiding
/// inside a struct — it should be visible in the signature of the one function
/// that reads it. Both maps are keyed by `instance_key`.
pub fn merge(
    cat: &Catalogue,
    settings: Settings,
) -> Result<(Policy, HashMap<String, Secret>), ConfigError> {
    let mut upstreams = HashMap::new();
    let mut secrets = HashMap::new();

    // The fleet default, validated once. A key that names nothing of its own
    // inherits this; a key with `push_to = []` inherits nothing.
    let push_default = settings.push.default;
    for pat in &push_default {
        if let Err(e) = crate::push::Destination::parse_pattern(pat) {
            return Err(ConfigError::Invalid(format!("[push] default {pat:?}: {e}")));
        }
    }

    for (service, entry) in settings.services {
        // 🔴 A configured service the catalogue does not know is a STARTUP
        // error, not a warning. Usually a typo or a catalogue that needs
        // updating, and either way the operator should hear about it now.
        let Some(def) = cat.get(&service) else {
            return Err(ConfigError::Invalid(format!(
                "service {service:?} is configured but not in the catalogue — check the spelling, or run `authinjector catalogue update`"
            )));
        };
        if entry.instances.is_empty() {
            return Err(ConfigError::Invalid(format!(
                "service {service:?} has no keys — a service section needs at least one label, e.g. [services.{service}.default]"
            )));
        }

        for (label, s) in entry.instances {
            let id = instance_key(&service, &label);
            let where_ = format!("{service}.{label}");

            if s.callers.is_empty() {
                return Err(ConfigError::Invalid(format!("{where_}: callers is required and must not be empty")));
            }
            if s.key.is_blank() {
                return Err(ConfigError::Invalid(format!("{where_}: key is empty")));
            }
            // Applies to BOTH transports: as a header the padding makes an
            // upstream edge reject the request before the API sees it, and as
            // a query parameter it is encoded to %20 and sent as part of the
            // credential. Neither failure looks like "your key has a space on
            // the end".
            if s.key.has_surrounding_whitespace() {
                return Err(ConfigError::Invalid(format!(
                    "{where_}: this key begins or ends with whitespace, which no API key does — \
                     it was picked up when the value was pasted. Re-copy it and run \
                     `authinjector add {} -c {} -f`.",
                    instance_key(&service, &label),
                    s.callers.join(","),
                )));
            }

            // 🔴 A config may NARROW the catalogue's endpoints, never widen
            // them. Otherwise a catalogue update adding an endpoint would
            // silently grant access nobody asked for. Narrowing is per LABEL,
            // so a restricted key can be genuinely more restricted than its
            // sibling rather than only nominally so.
            let allow: Vec<AllowRule> = match &s.endpoints {
                None => def.endpoints.iter().map(to_rule).collect(),
                Some(narrowed) => {
                    for n in narrowed {
                        let covered = def.endpoints.iter().any(|d| {
                            n.path_prefix.starts_with(&d.path_prefix)
                                && n.methods.iter().all(|m| d.methods.iter().any(|dm| dm.eq_ignore_ascii_case(m)))
                        });
                        if !covered {
                            return Err(ConfigError::Invalid(format!(
                                "{where_}: endpoint {} {} is not offered by the catalogue — a config may narrow access, never widen it",
                                n.methods.join("/"), n.path_prefix
                            )));
                        }
                    }
                    narrowed.iter().map(to_rule).collect()
                }
            };

            let auth = match def.auth_in {
                AuthIn::Header => {
                    // 🔴 A KEY THAT CANNOT BE SENT IS A STARTUP ERROR, not a
                    // 502 per request. Without this the broker accepts a key
                    // it can never transmit, and every call fails as "upstream
                    // unreachable" -- which points at the network, at the
                    // upstream, at TLS, at anything except the one line of
                    // config actually responsible. §6: fail loudly, once, at
                    // the moment someone can still act on it.
                    //
                    // Query mode needs no such check: those values are
                    // percent-encoded, so any byte is transmissible.
                    if let Some(fault) = s.key.header_value_fault() {
                        return Err(ConfigError::Invalid(format!(
                            "{where_}: this key cannot be sent as an HTTP header — it contains {fault}. \
                             That is almost always an invisible character pasted in from a document, \
                             or a line ending that came along with the value. Re-copy it from the \
                             provider and run `authinjector add {} -c {} -f`.",
                            instance_key(&service, &label),
                            s.callers.join(","),
                        )));
                    }
                    Auth::Header {
                        name: def.auth_header.clone(),
                        prefix: def.auth_prefix.clone(),
                    }
                }
                AuthIn::Query => Auth::Query { param: def.auth_param.clone() },
                AuthIn::GoogleSa => Auth::GoogleServiceAccount { scope: def.auth_scope.clone() },
            };

            // A destination pattern is parsed at STARTUP, not at push time: a
            // typo in a delivery rule must be a refusal to serve, not a
            // surprise the first time someone provisions a client.
            let push_to = match &s.push_to {
                Some(own) => {
                    for pat in own {
                        if let Err(e) = crate::push::Destination::parse_pattern(pat) {
                            return Err(ConfigError::Invalid(format!("{where_}: push_to {pat:?}: {e}")));
                        }
                    }
                    own.clone()
                }
                None => push_default.clone(),
            };
            let mut push_to = push_to;
            for pat in &s.push_allow {
                if let Err(e) = crate::push::Destination::parse_pattern(pat) {
                    return Err(ConfigError::Invalid(format!("{where_}: push_allow {pat:?}: {e}")));
                }
            }
            push_to.extend(s.push_allow.iter().cloned());
            for pat in &s.push_deny {
                if let Err(e) = crate::push::Destination::parse_deny(pat) {
                    return Err(ConfigError::Invalid(format!("{where_}: push_deny {pat:?}: {e}")));
                }
            }

            secrets.insert(id.clone(), s.key);
            upstreams.insert(
                id.clone(),
                Upstream {
                    id,
                    service: service.clone(),
                    label,
                    base_url: def.base_url.trim_end_matches('/').to_string(),
                    auth,
                    allow,
                    callers: s.callers.into_iter().collect(),
                    per_minute: s.rate_per_minute,
                    cost_per_call_cad: s.cost_per_call_cad.unwrap_or(def.cost_per_call_cad),
                    push_to,
                    push_deny: s.push_deny,
                    version: s.version,
                },
            );
        }
    }

    if upstreams.is_empty() {
        return Err(ConfigError::Invalid("no services configured".into()));
    }
    Ok((Policy { upstreams }, secrets))
}

fn to_rule(e: &Endpoint) -> AllowRule {
    AllowRule { methods: e.methods.clone(), path_prefix: e.path_prefix.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAT: &str = r#"
[services.pexels]
base_url = "https://api.pexels.com"
auth_header = "Authorization"
auth_prefix = ""
endpoints = [
  { methods = ["GET"], path_prefix = "/v1/search" },
  { methods = ["GET"], path_prefix = "/v1/curated" },
]

[services.tavily]
base_url = "https://api.tavily.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]

[services.geocoding]
base_url = "https://maps.googleapis.com"
auth_in = "query"
auth_param = "key"
endpoints = [{ methods = ["GET"], path_prefix = "/maps/api/geocode/json" }]
"#;

    const CFG: &str = r#"
# Keys for Pexels
[services.pexels.default]
key = "test-key-value"
callers = ["alice"]
rate_per_minute = 20
"#;

    fn built() -> (Policy, HashMap<String, Secret>) {
        let cat = Catalogue::parse(CAT).expect("catalogue");
        let set = Settings::parse(CFG).expect("settings");
        merge(&cat, set).expect("merge")
    }

    fn build(cfg: &str) -> (Policy, HashMap<String, Secret>) {
        let cat = Catalogue::parse(CAT).expect("catalogue");
        let set = Settings::parse(cfg).expect("settings");
        merge(&cat, set).expect("merge")
    }

    #[test]
    fn config_comments_and_blank_lines_are_fine() {
        let (p, _) = built();
        assert!(p.get("pexels").is_some());
    }

    #[test]
    fn the_catalogue_supplies_the_mechanics_and_the_config_the_permissions() {
        let (p, keys) = built();
        let u = p.get("pexels").unwrap();
        assert_eq!(u.base_url, "https://api.pexels.com", "from the catalogue");
        assert!(matches!(&u.auth, Auth::Header { name, prefix } if name == "Authorization" && prefix.is_empty()));
        assert!(u.permits_caller("alice"), "from the config");
        assert_eq!(u.per_minute, 20, "from the config");
        assert_eq!(keys.get("pexels").unwrap().expose_for_injection(), "test-key-value");
    }

    #[test]
    fn default_deny_on_method_path_and_caller() {
        let (p, _) = built();
        let u = p.get("pexels").unwrap();
        assert!(u.permits("GET", "/v1/search"));
        assert!(!u.permits("POST", "/v1/search"), "method off the list");
        assert!(!u.permits("GET", "/v1/videos"), "path off the list");
        assert!(!u.permits_caller("nobody"), "caller off the list");
    }

    // ── labels ──────────────────────────────────────────────────────────────

    #[test]
    fn one_service_may_hold_several_labelled_keys() {
        let (p, keys) = build(
            "[services.tavily.default]\nkey=\"tvly-A\"\ncallers=[\"alice\"]\n\
             [services.tavily.personal]\nkey=\"tvly-B\"\ncallers=[\"alice\"]\n",
        );
        assert_eq!(keys.get("tavily").unwrap().expose_for_injection(), "tvly-A");
        assert_eq!(keys.get("tavily:personal").unwrap().expose_for_injection(), "tvly-B");
        assert_eq!(p.get("tavily").unwrap().label, "default");
        assert_eq!(p.get("tavily:personal").unwrap().label, "personal");
        assert_eq!(p.get("tavily:personal").unwrap().service, "tavily");
    }

    #[test]
    fn the_default_label_is_addressed_bare_and_others_by_name() {
        assert_eq!(instance_key("tavily", "default"), "tavily");
        assert_eq!(instance_key("tavily", "blacksq"), "tavily:blacksq");
    }

    #[test]
    fn a_service_need_not_have_a_default_at_all() {
        let (p, keys) = build(
            "[services.tavily.work]\nkey=\"tvly-A\"\ncallers=[\"alice\"]\n\
             [services.tavily.home]\nkey=\"tvly-B\"\ncallers=[\"alice\"]\n",
        );
        assert!(p.get("tavily").is_none(), "the bare form is not invented");
        assert_eq!(keys.len(), 2);
        assert_eq!(p.labels_for("tavily"), vec!["tavily:home", "tavily:work"]);
    }

    #[test]
    fn callers_are_per_label_so_one_key_can_be_withheld() {
        // The whole reason labels exist: "alice may use the work account, the
        // build service may not".
        let (p, _) = build(
            "[services.tavily.work]\nkey=\"a\"\ncallers=[\"alice\",\"svc\"]\n\
             [services.tavily.personal]\nkey=\"b\"\ncallers=[\"alice\"]\n",
        );
        assert!(p.get("tavily:work").unwrap().permits_caller("svc"));
        assert!(!p.get("tavily:personal").unwrap().permits_caller("svc"));
    }

    #[test]
    fn rate_limits_are_per_label_too() {
        let (p, _) = build(
            "[services.tavily.work]\nkey=\"a\"\ncallers=[\"alice\"]\nrate_per_minute=5\n\
             [services.tavily.personal]\nkey=\"b\"\ncallers=[\"alice\"]\nrate_per_minute=99\n",
        );
        assert_eq!(p.get("tavily:work").unwrap().per_minute, 5);
        assert_eq!(p.get("tavily:personal").unwrap().per_minute, 99);
    }

    #[test]
    fn each_label_narrows_independently() {
        let (p, _) = build(
            "[services.pexels.full]\nkey=\"a\"\ncallers=[\"alice\"]\n\
             [services.pexels.limited]\nkey=\"b\"\ncallers=[\"alice\"]\n\
             endpoints=[{methods=[\"GET\"],path_prefix=\"/v1/search\"}]\n",
        );
        assert!(p.get("pexels:full").unwrap().permits("GET", "/v1/curated"));
        assert!(!p.get("pexels:limited").unwrap().permits("GET", "/v1/curated"));
    }

    #[test]
    fn the_policy_id_names_the_label_so_audit_says_which_key_was_used() {
        let (p, _) = build("[services.tavily.personal]\nkey=\"a\"\ncallers=[\"alice\"]\nversion=3\n");
        assert_eq!(p.get("tavily:personal").unwrap().policy_id(), "tavily:personal@3");
    }

    #[test]
    fn the_old_unlabelled_shape_names_the_fix_instead_of_a_type_error() {
        let err = Settings::parse("[services.pexels]\nkey=\"k\"\ncallers=[\"alice\"]\n")
            .expect_err("a pre-label config must not load silently");
        let msg = err.to_string();
        assert!(msg.contains("authinjector migrate"), "the error must say how to fix it: {msg}");
        assert!(!msg.contains("\"k\""), "an error must never quote the key back");
    }

    #[test]
    fn a_label_that_could_confuse_a_path_is_refused() {
        for bad in ["a:b", "a/b", "a b", ""] {
            let cfg = format!("[services.tavily.\"{bad}\"]\nkey=\"k\"\ncallers=[\"alice\"]\n");
            assert!(Settings::parse(&cfg).is_err(), "label {bad:?} must be refused");
        }
    }

    // ── query-mode services ─────────────────────────────────────────────────

    #[test]
    fn a_key_that_could_never_be_sent_as_a_header_is_refused_at_startup() {
        let cat = Catalogue::parse(CAT).unwrap();
        let set = Settings::parse("[services.pexels.default]\nkey=\"abc\\u201Cdef\"\ncallers=[\"alice\"]\n").unwrap();
        // `expect_err` would require Policy: Debug, and Policy deliberately has
        // no Debug -- it owns the upstream table, and a derived Debug on it is
        // one refactor away from rendering something that holds key material.
        let err = match merge(&cat, set) {
            Err(e) => e,
            Ok(_) => panic!("an unsendable key must not reach the serving path"),
        };
        let msg = err.to_string();
        assert!(msg.contains("cannot be sent as an HTTP header"), "{msg}");
        assert!(!msg.contains("abc"), "the error must not quote the key: {msg}");
    }

    #[test]
    fn a_query_mode_key_may_contain_anything_because_it_is_encoded() {
        let (p, _) = build("[services.geocoding.default]\nkey=\"a\\u201Cb\"\ncallers=[\"alice\"]\n");
        assert!(p.get("geocoding").is_some(), "query mode encodes, so nothing is unsendable");
    }

    #[test]
    fn a_query_mode_service_resolves_to_a_parameter_and_strips_no_extra_header() {
        let (p, _) = build("[services.geocoding.default]\nkey=\"k\"\ncallers=[\"alice\"]\n");
        let u = p.get("geocoding").unwrap();
        assert!(matches!(&u.auth, Auth::Query { param } if param == "key"));
        let s = u.strip_set();
        assert_eq!(s.len(), ALWAYS_STRIP.len(), "nothing beyond the always-stripped headers");
        assert!(s.contains("authorization"));
    }

    // ── the rules that predate labels, still holding ────────────────────────

    #[test]
    fn a_config_may_narrow_the_catalogue() {
        let (p, _) = build(
            "[services.pexels.default]\nkey=\"k\"\ncallers=[\"alice\"]\nendpoints=[{methods=[\"GET\"],path_prefix=\"/v1/search\"}]\n",
        );
        let u = p.get("pexels").unwrap();
        assert!(u.permits("GET", "/v1/search"));
        assert!(!u.permits("GET", "/v1/curated"), "narrowed away");
    }

    #[test]
    fn a_config_may_not_widen_the_catalogue() {
        let cat = Catalogue::parse(CAT).unwrap();
        let set = Settings::parse(
            "[services.pexels.default]\nkey=\"k\"\ncallers=[\"alice\"]\nendpoints=[{methods=[\"DELETE\"],path_prefix=\"/v1/everything\"}]\n",
        )
        .unwrap();
        assert!(matches!(merge(&cat, set), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn a_service_absent_from_the_catalogue_is_a_startup_error() {
        let cat = Catalogue::parse(CAT).unwrap();
        let set = Settings::parse("[services.nosuch.default]\nkey=\"k\"\ncallers=[\"alice\"]\n").unwrap();
        assert!(matches!(merge(&cat, set), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn empty_callers_or_key_is_refused() {
        let cat = Catalogue::parse(CAT).unwrap();
        let no_callers = Settings::parse("[services.pexels.default]\nkey=\"k\"\ncallers=[]\n").unwrap();
        assert!(matches!(merge(&cat, no_callers), Err(ConfigError::Invalid(_))));
        let cat2 = Catalogue::parse(CAT).unwrap();
        let no_key = Settings::parse("[services.pexels.default]\nkey=\"\"\ncallers=[\"alice\"]\n").unwrap();
        assert!(matches!(merge(&cat2, no_key), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn a_service_section_with_no_labels_is_refused() {
        let cat = Catalogue::parse(CAT).unwrap();
        let set = Settings::parse("[services.pexels]\n").unwrap();
        assert!(matches!(merge(&cat, set), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn visible_to_never_leaks_a_key() {
        let (p, _) = built();
        let rendered = serde_json::to_string(&p.visible_to("alice")).unwrap();
        assert!(rendered.contains("pexels"));
        assert!(!rendered.contains("test-key-value"));
    }

    #[test]
    fn strip_set_covers_the_injected_header_case_insensitively() {
        let (p, _) = built();
        let s = p.get("pexels").unwrap().strip_set();
        assert!(s.contains("authorization"));
        assert!(s.contains("cookie"));
        assert!(s.contains("proxy-authorization"));
    }

    #[test]
    fn connection_scoped_headers_are_stripped_even_for_a_query_mode_service() {
        // 🔴 THE REGRESSION. Forwarding the caller's `Host` made nginx front
        // ends return their own 400/502 page and made every HTTP/2 upstream
        // reject the request before it left the machine. Both looked like the
        // upstream was down or the key was bad.
        let (p, _) = build("[services.geocoding.default]\nkey=\"k\"\ncallers=[\"alice\"]\n");
        let s = p.get("geocoding").unwrap().strip_set();
        for h in ["host", "content-length", "connection", "transfer-encoding", "keep-alive", "te", "upgrade"] {
            assert!(s.contains(h), "{h} must never reach the upstream");
        }
    }
}
