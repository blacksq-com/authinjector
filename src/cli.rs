//! Agent-facing commands: `help`, `status`, `call`, `catalogue update` and the
//! one documentation generator, `gen-docs`.
//!
//! 🔴 ONE SOURCE OF TRUTH: THE CATALOGUE. `help <service>`, the Claude skill,
//! the Cursor rule, AGENTS.md, the Copilot instructions, docs/services.md and
//! docs/help.json (which the help MCP at mcp.authinjector.com serves) are all
//! rendered here from the same `Catalogue`, so none of them can describe a
//! service differently from the broker that serves it. CI regenerates them and
//! fails on any diff.
//!
//! `call` and `status` speak plain HTTP/1.1 over the Unix socket with a
//! blocking std stream. They never carry a credential: the broker adds it, and
//! a caller-supplied credential header is refused before anything is sent.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::catalogue::{AuthIn, Catalogue, ServiceDef};

pub const DEFAULT_SOCKET: &str = "/run/authinjector/authinjector.sock";
pub const REPO: &str = "https://github.com/blacksq-com/authinjector";
pub const SITE: &str = "https://authinjector.com";
pub const HELP_MCP: &str = "https://mcp.authinjector.com/mcp";
pub const CATALOGUE_URL: &str = "https://raw.githubusercontent.com/blacksq-com/authinjector/main/catalogue.toml";

// ── HTTP/1.1 over the Unix socket ────────────────────────────────────────────

/// Headers a caller may never send: the credential slots (the broker refuses
/// them too, but refusing here means they never leave this process), and the
/// connection-scoped ones this client writes itself.
const REFUSED_HEADERS: &[&str] = &["authorization", "cookie", "proxy-authorization"];
const OWN_HEADERS: &[&str] = &["host", "content-length", "connection", "transfer-encoding"];

#[derive(Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Validate one `-H 'Name: value'`. A credential header is refused with the
/// reason, because the whole point is that the caller never holds one.
pub fn check_header(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("header {raw:?} is not 'Name: value'"))?;
    let name = name.trim();
    let lower = name.to_ascii_lowercase();
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(format!("header name {name:?} is not valid"));
    }
    if REFUSED_HEADERS.contains(&lower.as_str()) {
        return Err(format!(
            "refusing to send {name}: credentials are never sent by the caller. The broker adds \
             the key itself; if this service needs one, ask the user to configure it with \
             `sudo authinjector add <service> -c <you>`."
        ));
    }
    if OWN_HEADERS.contains(&lower.as_str()) {
        return Err(format!("{name} is set by authinjector itself"));
    }
    let value = value.trim();
    if value.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(format!("header {name} contains a line break"));
    }
    Ok((name.to_string(), value.to_string()))
}

pub fn build_request(method: &str, target: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Parse a complete HTTP/1.1 response (the connection is closed by then).
/// Handles Content-Length, chunked and read-to-close bodies.
pub fn parse_response(raw: &[u8]) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the broker closed the connection before sending a full response")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "response headers are not UTF-8")?;
    let rest = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let proto = parts.next().unwrap_or_default();
    if !proto.starts_with("HTTP/1.") {
        return Err(format!("not an HTTP/1.x response: {status_line:?}"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line {status_line:?}"))?;
    let reason = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let get = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.as_str());
    let body = if get("transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false) {
        dechunk(rest)?
    } else if let Some(n) = get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if rest.len() < n {
            return Err(format!("body truncated: expected {n} bytes, got {}", rest.len()));
        }
        rest[..n].to_vec()
    } else {
        rest.to_vec()
    };
    Ok(Response { status, reason, headers, body })
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n").ok_or("malformed chunked body")?;
        let size_txt = std::str::from_utf8(&data[..eol]).map_err(|_| "malformed chunk size")?;
        let size_txt = size_txt.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_txt, 16).map_err(|_| format!("bad chunk size {size_txt:?}"))?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 {
            return Err("chunked body truncated".into());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// What to tell the user when the socket cannot be reached. Never "give me
/// the key": every failure here is a setup step the user takes.
pub fn connect_hint(socket: &Path, e: &std::io::Error) -> String {
    let base = match e.kind() {
        std::io::ErrorKind::NotFound => format!("no broker socket at {}: the broker is not installed or not running.", socket.display()),
        std::io::ErrorKind::PermissionDenied => format!("permission denied on {}: you are not in the authinjector-clients group.", socket.display()),
        std::io::ErrorKind::ConnectionRefused => format!("connection refused on {}: the broker is not running, or you are not in the authinjector-clients group.", socket.display()),
        _ => format!("cannot reach the broker at {}: {e}", socket.display()),
    };
    format!(
        "{base}\n\
         Ask the user to check:\n  \
         systemctl status authinjector.socket\n  \
         sudo usermod -aG authinjector-clients \"$USER\"   (then log out and back in,\n  \
         or run one command with: sg authinjector-clients -c '...')"
    )
}

/// The hint printed under a refusal, by status code.
pub fn status_hint(status: u16, service: &str) -> Option<String> {
    let svc = service.split(':').next().unwrap_or(service);
    Some(match status {
        403 => format!(
            "403: this caller is not allowed to use {service} for that method and path.\n\
             Ask the user to allow it: `sudo authinjector add {svc} -c <your-user>` (or add your\n\
             user to that key's callers / widen its endpoints in /etc/authinjector/config.toml),\n\
             then `sudo systemctl restart authinjector`. Do not ask for the key itself."
        ),
        404 => format!(
            "404: unknown service or label {service:?}. Run `authinjector status` to see what this\n\
             caller may use; a labelled key is addressed as {svc}:<label>."
        ),
        405 => "405: that method is not allowed on this path. `authinjector help <service>` lists the allowed methods.".into(),
        429 => "429: rate limited for this caller and key. Wait a minute and retry; do not loop.".into(),
        502 => "502: the upstream service could not be reached (network, DNS or the service itself).".into(),
        _ => return None,
    })
}

pub fn request(socket: &Path, raw: &[u8]) -> Result<Response, String> {
    let mut s = UnixStream::connect(socket).map_err(|e| connect_hint(socket, &e))?;
    s.write_all(raw).map_err(|e| format!("writing to the broker: {e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| format!("reading from the broker: {e}"))?;
    parse_response(&buf)
}

// ── catalogue diff ───────────────────────────────────────────────────────────

#[derive(Debug, Default, PartialEq)]
pub struct Change {
    pub id: String,
    pub fields: Vec<&'static str>,
    /// base_url or where the key goes changed: the change that could send a
    /// configured credential somewhere new.
    pub redirects_key: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct Diff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<Change>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
    /// Changes that must be confirmed by a person at a terminal, even with
    /// --yes: the key would be sent to a new place.
    pub fn needs_human(&self, configured: &HashSet<String>) -> Vec<&Change> {
        self.changed.iter().filter(|c| c.redirects_key && configured.contains(&c.id)).collect()
    }
}

fn endpoints_of(s: &ServiceDef) -> Vec<(Vec<String>, String)> {
    let mut v: Vec<(Vec<String>, String)> = s
        .endpoints
        .iter()
        .map(|e| {
            let mut m = e.methods.clone();
            m.sort();
            (m, e.path_prefix.clone())
        })
        .collect();
    v.sort();
    v
}

pub fn diff(old: &Catalogue, new: &Catalogue) -> Diff {
    let mut d = Diff::default();
    for id in new.ids() {
        match old.get(id) {
            None => d.added.push(id.clone()),
            Some(o) => {
                let n = new.get(id).unwrap();
                let mut fields = Vec::new();
                let mut redirects = false;
                if o.base_url != n.base_url {
                    fields.push("base_url");
                    redirects = true;
                }
                if o.auth_in != n.auth_in {
                    fields.push("auth_in");
                    redirects = true;
                }
                if o.auth_header != n.auth_header {
                    fields.push("auth_header");
                    redirects = true;
                }
                if o.auth_param != n.auth_param {
                    fields.push("auth_param");
                    redirects = true;
                }
                if o.auth_prefix != n.auth_prefix {
                    fields.push("auth_prefix");
                }
                if endpoints_of(o) != endpoints_of(n) {
                    fields.push("endpoints");
                }
                if !fields.is_empty() {
                    d.changed.push(Change { id: id.clone(), fields, redirects_key: redirects });
                }
            }
        }
    }
    for id in old.ids() {
        if new.get(id).is_none() {
            d.removed.push(id.clone());
        }
    }
    d
}

// ── generated documentation ─────────────────────────────────────────────────

pub fn auth_text(s: &ServiceDef) -> String {
    match s.auth_in {
        AuthIn::Header => format!("header {}: {}<key>", s.auth_header, s.auth_prefix),
        AuthIn::Query => format!("query ?{}=<key>", s.auth_param),
        AuthIn::GoogleSa => format!("header Authorization: Bearer <minted Google access token> (service account, scope {})", s.auth_scope),
    }
}

/// One representative call for a service: the first GET endpoint if there is
/// one, else the first endpoint. Paths ending in a parameter keep the prefix.
fn example(id: &str, s: &ServiceDef) -> (String, String) {
    let ep = s
        .endpoints
        .iter()
        .find(|e| e.methods.iter().any(|m| m == "GET"))
        .or_else(|| s.endpoints.first());
    match ep {
        Some(e) => {
            let method = if e.methods.iter().any(|m| m == "GET") { "GET".to_string() } else { e.methods.first().cloned().unwrap_or_else(|| "GET".into()) };
            let path = e.path_prefix.clone();
            let _ = id;
            (method, path)
        }
        None => ("GET".into(), "/".into()),
    }
}

fn example_call(id: &str, s: &ServiceDef) -> String {
    let (m, p) = example(id, s);
    if m == "GET" || m == "DELETE" {
        format!("authinjector call {id} {m} {p}")
    } else {
        format!("authinjector call {id} {m} {p} --data '{{}}'")
    }
}

fn example_curl(id: &str, s: &ServiceDef) -> String {
    let (m, p) = example(id, s);
    if m == "GET" {
        format!("curl --unix-socket {DEFAULT_SOCKET} 'http://localhost/{id}{p}'")
    } else {
        format!("curl --unix-socket {DEFAULT_SOCKET} -X {m} 'http://localhost/{id}{p}' -H 'content-type: application/json' -d '{{}}'")
    }
}

fn display_name<'a>(id: &'a str, s: &'a ServiceDef) -> &'a str {
    if s.name.is_empty() { id } else { s.name.as_str() }
}

pub fn service_help(id: &str, s: &ServiceDef) -> String {
    let mut out = String::new();
    out.push_str(&format!("### {} (`{id}`)\n\n", display_name(id, s)));
    out.push_str(&format!("- Base URL: {}\n", s.base_url));
    out.push_str(&format!("- Key injected as: {}\n", auth_text(s)));
    if !s.signup_url.is_empty() {
        out.push_str(&format!("- Get a key: {}\n", s.signup_url));
    }
    out.push_str("- Allowed:\n");
    for e in &s.endpoints {
        out.push_str(&format!("  - {} {}\n", e.methods.join(", "), e.path_prefix));
    }
    out.push_str(&format!(
        "\nCall it (the broker adds the key):\n\n```bash\n{}\n{}\n```\n\n\
         A second key for the same service is addressed as `{id}:<label>`, e.g. `authinjector call {id}:work ...`.\n",
        example_call(id, s),
        example_curl(id, s)
    ));
    out
}

const OVERVIEW: &str = "AuthInjector is a local broker that holds API keys so AI agents and scripts never do. \
A caller sends plain HTTP to a Unix socket with no credential; the broker reads the caller's identity \
from the kernel (SO_PEERCRED), checks that caller's allowlist and rate limit for that key, injects \
the key, forwards the call and returns the upstream response unchanged. One audit line per call.\n\n\
Platform: Linux only (SO_PEERCRED). Windows: run in WSL2. macOS: not supported yet.";

fn sect_install() -> String {
    format!(
        "Install the latest release (Linux, x86_64 or arm64):\n\n```bash\n\
curl -fsSL {SITE}/dl/$(uname -m) | tar xz\n\
cd authinjector-$(uname -m)-unknown-linux-musl\n\
sudo ./install.sh --caller \"$USER\"\n```\n\n\
Each release lists `SHA256SUMS.txt` ({REPO}/releases/latest); verify with `sha256sum -c SHA256SUMS.txt --ignore-missing`.\n\n\
Build from source (static musl, needs Docker for `cross`):\n\n```bash\n\
git clone {REPO} && cd authinjector\ncargo install cross\n\
cross build --release --target x86_64-unknown-linux-musl\nsudo ./install.sh --caller \"$USER\"\n```\n"
    )
}

const SETUP: &str = "Keys are added by the user, never by an agent, and never as an argument:\n\n```bash\n\
sudo authinjector add <service> -c <user> -r 20      # prompts for the key, echo off\n\
sudo authinjector add <service> -c <user> -l work    # a second key for the same service\n\
sudo systemctl restart authinjector\n\
authinjector status                                 # what this user may call\n\
authinjector help <service>                         # how to call one service\n```\n\n\
Update the service catalogue from the repo with `sudo authinjector catalogue update` (shows a diff; a \
change that would send a configured key to a new host or slot must be confirmed at a terminal).";

fn sect_clients() -> String {
    format!(
        "Help-only MCP server (no keys, no API calls, no user data): Streamable HTTP at {HELP_MCP}.\n\n\
- Claude Code: `claude mcp add --transport http authinjector-help {HELP_MCP}`\n\
- Claude.ai / Claude Desktop: Settings > Connectors > Add custom connector, URL `{HELP_MCP}`\n\
- Cursor: `~/.cursor/mcp.json`: `{{\"mcpServers\":{{\"authinjector-help\":{{\"url\":\"{HELP_MCP}\"}}}}}}`\n\n\
Agent instructions, generated from the catalogue:\n\n\
- Claude skill: copy `skills/authinjector/` into `~/.claude/skills/` (or a project's `.claude/skills/`) — {REPO}/blob/main/skills/authinjector/SKILL.md\n\
- Cursor rule: copy `.cursor/rules/authinjector.mdc` into your project — {REPO}/blob/main/.cursor/rules/authinjector.mdc\n\
- Codex, Cursor and others: add the AuthInjector section of AGENTS.md — {REPO}/blob/main/AGENTS.md\n\
- GitHub Copilot: `.github/copilot-instructions.md` — {REPO}/blob/main/.github/copilot-instructions.md\n"
    )
}

const TROUBLESHOOTING: &str = "- `no broker socket` / `connection refused`: the broker is not running, or the user is not in \
`authinjector-clients`. Tell the user: `systemctl status authinjector.socket`; `sudo usermod -aG authinjector-clients \"$USER\"` \
then log out and back in (or `sg authinjector-clients -c '...'`).\n\
- 403: the caller is not allowlisted for that key, method or path. Tell the user: `sudo authinjector add <service> -c <your-user>` \
(or add you to that key's callers / widen its endpoints in /etc/authinjector/config.toml), then `sudo systemctl restart authinjector`.\n\
- 404: unknown service or label. `authinjector status` lists what this caller may use; labelled keys are `<service>:<label>`.\n\
- 405: method not allowed on that path; `authinjector help <service>` lists the allowed ones.\n\
- 429: rate limited per caller and key. Wait, do not retry in a loop.\n\
- 502: the upstream could not be reached.";

const AGENT_RULES: &str = "1. Never ask the user for an API key, token or password, and never accept one pasted into the chat.\n\
2. Never read, print, grep or open `.env`, `.dev.vars` or any file holding a credential; never put a key in code, logs, commits or command arguments.\n\
3. Check what is available first: `authinjector status`.\n\
4. Make every call through the broker: `authinjector call <service> <METHOD> <path> [--data ...]` (or curl over the socket). The broker adds the key; the response comes back unchanged.\n\
5. On an error, tell the user the exact command from the troubleshooting list instead of asking for a key.\n\
6. More help: `authinjector help`, `authinjector help <service>`, the help MCP at https://mcp.authinjector.com/mcp, and https://github.com/blacksq-com/authinjector.";

pub fn overview_text() -> String {
    format!(
        "{OVERVIEW}\n\n\
Commands for agents:\n  \
authinjector status                       what this caller may use\n  \
authinjector help <service>               how to call one service\n  \
authinjector call <service> <METHOD> <path> [--data JSON|@file|-] [-H 'Name: value']\n  \
authinjector list                         the whole catalogue\n\n\
Socket: {DEFAULT_SOCKET}\n\
More help: {HELP_MCP} (help-only MCP), {REPO}\n"
    )
}

fn agent_body(cat: &Catalogue) -> String {
    let mut s = String::new();
    s.push_str("AuthInjector holds API keys so you never do. You call services through it; it adds the key.\n\n");
    s.push_str("## Rules\n\n");
    s.push_str(AGENT_RULES);
    s.push_str("\n\n## Check setup\n\n```bash\nauthinjector status   # caller, and every service + method + path you may use\n```\n\n");
    s.push_str("## Make calls\n\n`authinjector call <service[:label]> <METHOD> <path> [--data JSON|@file|-] [-H 'Name: value']` prints the upstream body unchanged. One example per service:\n\n```bash\n");
    for id in cat.ids() {
        s.push_str(&example_call(id, cat.get(id).unwrap()));
        s.push('\n');
    }
    s.push_str("```\n\n`authinjector help <service>` shows every allowed method and path for one service.\n\n");
    s.push_str("## Errors: what to tell the user\n\n");
    s.push_str(TROUBLESHOOTING);
    s.push_str(&format!("\n\n## More help\n\n- `authinjector help`\n- Help MCP (no keys): {HELP_MCP}\n- {REPO}\n"));
    s
}

fn skill_description(cat: &Catalogue) -> String {
    let names: Vec<String> = cat.ids().into_iter().map(|id| display_name(id, cat.get(id).unwrap()).to_string()).collect();
    let mut uniq: Vec<String> = Vec::new();
    for n in names {
        if !uniq.contains(&n) {
            uniq.push(n);
        }
    }
    format!(
        "Use whenever a task involves API keys, secrets, tokens, credentials, .env files, or calling an external API through \
AuthInjector, including {}. Never ask for or read a key; call the service through the local AuthInjector broker instead.",
        uniq.join(", ")
    )
}

fn yaml_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn help_json(cat: &Catalogue) -> serde_json::Value {
    let services: Vec<serde_json::Value> = cat
        .ids()
        .into_iter()
        .map(|id| {
            let s = cat.get(id).unwrap();
            serde_json::json!({
                "id": id,
                "name": display_name(id, s),
                "base_url": s.base_url,
                "auth": auth_text(s),
                "endpoints": s.endpoints.iter().map(|e| serde_json::json!({"methods": e.methods, "path_prefix": e.path_prefix})).collect::<Vec<_>>(),
                "signup_url": s.signup_url,
                "help": service_help(id, s),
            })
        })
        .collect();
    serde_json::json!({
        "name": "AuthInjector",
        "version": env!("CARGO_PKG_VERSION"),
        "repo": REPO,
        "site": SITE,
        "sections": {
            "overview": OVERVIEW,
            "install": sect_install(),
            "setup": SETUP,
            "clients": sect_clients(),
            "troubleshooting": TROUBLESHOOTING,
            "agent_rules": AGENT_RULES,
        },
        "services": services,
    })
}

const GENERATED: &str = "<!-- Generated by `authinjector gen-docs` from catalogue.toml. Do not edit by hand. -->";

/// Every generated file, path relative to the repo root, in a fixed order.
pub fn render_all(cat: &Catalogue) -> BTreeMap<&'static str, String> {
    let body = agent_body(cat);
    let desc = skill_description(cat);
    let mut m = BTreeMap::new();
    m.insert(
        "skills/authinjector/SKILL.md",
        format!("---\nname: authinjector\ndescription: {}\n---\n\n{GENERATED}\n\n# AuthInjector\n\n{body}", yaml_quote(&desc)),
    );
    m.insert(
        ".cursor/rules/authinjector.mdc",
        format!("---\ndescription: {}\nglobs:\nalwaysApply: false\n---\n\n{GENERATED}\n\n# AuthInjector\n\n{body}", yaml_quote(&desc)),
    );
    let section = format!("## AuthInjector\n\n{GENERATED}\n\n{}", body.replace("\n## ", "\n### "));
    m.insert("AGENTS.md", format!("# Agent instructions\n\n{section}"));
    m.insert(".github/copilot-instructions.md", format!("# Copilot instructions\n\n{section}"));
    let mut svc = format!("# Services\n\n{GENERATED}\n\nEvery service in the public catalogue, how its key is injected, and how to call it.\n\n");
    for id in cat.ids() {
        svc.push_str(&service_help(id, cat.get(id).unwrap()));
        svc.push('\n');
    }
    m.insert("docs/services.md", svc);
    let mut j = serde_json::to_string_pretty(&help_json(cat)).expect("serialisable");
    j.push('\n');
    m.insert("docs/help.json", j);
    m
}

pub fn write_all(cat: &Catalogue, out: &Path) -> Result<Vec<String>, String> {
    let mut written = Vec::new();
    for (rel, content) in render_all(cat) {
        let p = out.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        std::fs::write(&p, content).map_err(|e| format!("{}: {e}", p.display()))?;
        written.push(rel.to_string());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAT: &str = r#"
[services.tavily]
name = "Tavily"
base_url = "https://api.tavily.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]

[services.pexels]
name = "Pexels"
base_url = "https://api.pexels.com"
auth_header = "Authorization"
endpoints = [{ methods = ["GET"], path_prefix = "/v1/search" }]
"#;

    fn cat(s: &str) -> Catalogue {
        Catalogue::parse(s).expect("valid catalogue")
    }

    #[test]
    fn a_content_length_response_parses() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}extra").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.reason, "OK");
        assert_eq!(r.body, b"{}");
    }

    #[test]
    fn a_chunked_response_is_reassembled() {
        let r = parse_response(b"HTTP/1.1 403 Forbidden\r\ntransfer-encoding: chunked\r\n\r\n4\r\nnot \r\n7\r\nallowed\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.status, 403);
        assert_eq!(r.body, b"not allowed");
    }

    #[test]
    fn a_read_to_close_body_and_a_truncated_one() {
        assert_eq!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap().body, b"");
        assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc").is_err());
        assert!(parse_response(b"garbage").is_err());
    }

    #[test]
    fn credential_headers_are_refused_before_anything_is_sent() {
        for h in ["Authorization: Bearer x", "authorization: x", "Cookie: a=b", "Proxy-Authorization: x"] {
            let e = check_header(h).unwrap_err();
            assert!(e.contains("never sent by the caller"), "{h}: {e}");
        }
        assert!(check_header("Host: evil").is_err());
        assert!(check_header("X-Thing: a\r\nAuthorization: b").is_err());
        assert_eq!(check_header("Accept: application/json").unwrap(), ("Accept".into(), "application/json".into()));
    }

    #[test]
    fn a_request_carries_no_credential_and_closes() {
        let r = String::from_utf8(build_request("POST", "/tavily/search", &[], b"{}")).unwrap();
        assert!(r.starts_with("POST /tavily/search HTTP/1.1\r\n"));
        assert!(r.contains("Connection: close\r\n") && r.contains("Content-Length: 2\r\n"));
        assert!(!r.to_ascii_lowercase().contains("authorization"));
    }

    #[test]
    fn the_diff_names_added_removed_and_changed() {
        let old = cat(CAT);
        let new = cat(&CAT.replace("api.pexels.com", "api.pexels.example").replace("[services.tavily]", "[services.resend]\nbase_url = \"https://api.resend.com\"\nauth_header = \"Authorization\"\nendpoints = [{ methods = [\"POST\"], path_prefix = \"/emails\" }]\n\n[services.tavily2]"));
        let d = diff(&old, &new);
        assert_eq!(d.added, vec!["resend".to_string(), "tavily2".to_string()]);
        assert_eq!(d.removed, vec!["tavily".to_string()]);
        assert_eq!(d.changed, vec![Change { id: "pexels".into(), fields: vec!["base_url"], redirects_key: true }]);
        assert!(diff(&old, &cat(CAT)).is_empty());
    }

    #[test]
    fn a_key_redirect_on_a_configured_service_needs_a_human() {
        let old = cat(CAT);
        let moved = cat(&CAT.replace("api.pexels.com", "api.pexels.example"));
        let d = diff(&old, &moved);
        let configured: HashSet<String> = ["pexels".to_string()].into();
        assert_eq!(d.needs_human(&configured).len(), 1);
        assert!(d.needs_human(&HashSet::new()).is_empty(), "unconfigured service: --yes may apply it");
        let widened = cat(&CAT.replace("\"/v1/search\"", "\"/v1/\""));
        let d2 = diff(&old, &widened);
        assert_eq!(d2.changed[0].fields, vec!["endpoints"]);
        assert!(d2.needs_human(&configured).is_empty(), "an endpoint change never moves the key");
    }

    #[test]
    fn gen_docs_is_deterministic_and_complete() {
        let c = cat(CAT);
        let a = render_all(&c);
        assert_eq!(a, render_all(&c));
        let skill = &a["skills/authinjector/SKILL.md"];
        assert!(skill.starts_with("---\nname: authinjector\ndescription: \""));
        assert!(skill.contains("Tavily") && skill.contains("authinjector call pexels GET /v1/search"));
        let j: serde_json::Value = serde_json::from_str(&a["docs/help.json"]).unwrap();
        assert_eq!(j["services"][0]["id"], "pexels");
        assert_eq!(j["services"][1]["auth"], "header Authorization: Bearer <key>");
        for k in ["overview", "install", "setup", "clients", "troubleshooting", "agent_rules"] {
            assert!(j["sections"][k].as_str().map(|s| !s.is_empty()).unwrap_or(false), "{k}");
        }
    }
}
