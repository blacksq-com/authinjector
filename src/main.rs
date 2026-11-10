//! AuthInjector — a broker that holds API credentials so the processes calling
//! them never do.
//!
//! `PROTOCOL.md` is authoritative. This binary implements it.
//!
//! Two files:
//!   catalogue.toml   what a service IS      public, shipped, updatable
//!   config.toml      who may use it + keys  private, 0640 root:authinjector
//!
//! 🔴 A KEY NEVER ARRIVES AS AN ARGUMENT. Only stdin (a prompt, or a pipe) or
//! a file passed to `import`. There is no `--key VALUE` flag and there will not
//! be one: argv is readable at /proc/PID/cmdline by every user on the box while
//! the command runs, and lands in shell history besides.
//!
//! 🔴 A SERVICE MAY HOLD SEVERAL KEYS, each under a label. `add tavily` writes
//! the `default` label; `add tavily -l personal` writes another beside it. They
//! are addressed as `/tavily/...` and `/tavily:personal/...` respectively, and
//! each carries its OWN callers and rate limit.

mod audit;
mod catalogue;
mod config;
mod gtoken;
mod importer;
mod inject;
mod peer;
mod proxy;
mod push;
mod ratelimit;
mod secret;
mod server;

use std::io::{BufRead, Read, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use crate::config::{instance_key, valid_label, DEFAULT_LABEL};
use crate::secret::Secret;

const DEFAULT_CATALOGUE: &str = "/usr/share/authinjector/catalogue.toml";
const DEFAULT_CONFIG: &str = "/etc/authinjector/config.toml";
const DEFAULT_AUDIT: &str = "/var/log/authinjector/audit.jsonl";

fn usage() -> String {
    format!(
        "authinjector <command> [options]\n\
         \n\
         list                       services in the catalogue, and which are configured\n\
         show                       configured keys (never the keys themselves)\n\
         add <service> -c <who>[,<who>] [-l <label>] [-r <n>] [-f]\n\
         \u{20}                            prompts for the key on stdin\n\
         import <file> [-f]         batch: service[/label]:key:callers[:rate] per line\n\
         del <service>[:<label>]    remove one key\n\
         push-to --default <dest>...          where ANY key may be delivered\n\
         push-to <service>[:<label>] <dest>...  replace that for one key\n\
         \u{20}       [--allow|--deny] <dest>...  extend it, or forbid one destination\n\
         \u{20}                            naming none clears that list\n\
         migrate                    move pre-label entries under `default`\n\
         serve                      run the broker (default)\n\
         \n\
         --catalogue <path>         default: {DEFAULT_CATALOGUE}\n\
         --config <path>            default: {DEFAULT_CONFIG}\n\
         --audit <path>             default: {DEFAULT_AUDIT}\n\
         --socket <path>            bind here when not socket-activated\n\
         --check                    validate and exit without serving\n\
         -f, --force                replace a key that is already configured\n\
         \n\
         EXISTING KEYS ARE NEVER REPLACED BY ACCIDENT. `add` refuses if that\n\
         label is already configured, and `import` skips those lines and says so,\n\
         so re-running the same file is safe and does nothing. -f replaces them.\n\
         \n\
         LABELS. A service may hold several keys. Without -l a key is stored as\n\
         `default` and called as /<service>/...; with -l it is stored under that\n\
         label and called as /<service>:<label>/... . Each label has its own\n\
         callers and its own rate limit.\n\
         \n\
         A key is read from stdin or from an import file. Never from an argument.\n"
    )
}

struct Opts {
    catalogue: PathBuf,
    config: PathBuf,
    audit: PathBuf,
    socket: Option<PathBuf>,
    check_only: bool,
    callers: Vec<String>,
    rate: Option<u32>,
    label: Option<String>,
    force: bool,
    positional: Vec<String>,
    push_default: bool,
    push_mode: &'static str,
}

fn parse_args() -> Result<(String, Opts), String> {
    let mut o = Opts {
        catalogue: PathBuf::from(DEFAULT_CATALOGUE),
        config: PathBuf::from(DEFAULT_CONFIG),
        audit: PathBuf::from(DEFAULT_AUDIT),
        socket: None,
        check_only: false,
        callers: Vec::new(),
        rate: None,
        label: None,
        force: false,
        positional: Vec::new(),
        push_default: false,
        push_mode: "to",
    };
    let mut it = std::env::args().skip(1);
    let mut cmd = String::new();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--catalogue" => o.catalogue = PathBuf::from(it.next().ok_or("--catalogue needs a path")?),
            "--config" => o.config = PathBuf::from(it.next().ok_or("--config needs a path")?),
            "--audit" => o.audit = PathBuf::from(it.next().ok_or("--audit needs a path")?),
            "--socket" => o.socket = Some(PathBuf::from(it.next().ok_or("--socket needs a path")?)),
            "--check" => o.check_only = true,
            "-c" | "--callers" => {
                let v = it.next().ok_or("-c needs a caller (comma separated for several)")?;
                o.callers = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            "-r" | "--rate" => {
                o.rate = Some(it.next().ok_or("-r needs a number")?.parse().map_err(|_| "-r must be a number")?);
            }
            "-l" | "--label" => {
                o.label = Some(it.next().ok_or("-l needs a label, e.g. -l personal")?);
            }
            "-f" | "--force" => o.force = true,
            "-k" | "--key" => {
                return Err("keys are never passed as arguments — they land in shell history and in \
                            /proc/PID/cmdline where any user can read them.\n\
                            Use `authinjector add <service> -c <who>` and type it at the prompt, \
                            or `authinjector import <file>`."
                    .into())
            }
            "-h" | "--help" => return Err(usage()),
            "--default" => o.push_default = true,
            "--allow" => o.push_mode = "allow",
            "--deny" => o.push_mode = "deny",
            other if other.starts_with('-') => return Err(format!("unknown option {other:?}\n\n{}", usage())),
            other if cmd.is_empty() => cmd = other.to_string(),
            other => o.positional.push(other.to_string()),
        }
    }
    if cmd.is_empty() {
        cmd = "serve".into();
    }
    Ok((cmd, o))
}

/// Resolve `service[:label]` plus an optional `-l`, which wins.
///
/// Both spellings are accepted because `service:label` is how a key is
/// addressed everywhere else -- in a request path, in `show`, in the audit log
/// -- and having to retype it a different way to delete it would be its own
/// small trap.
fn target_of(arg: &str, flag: &Option<String>) -> Result<(String, String), String> {
    let (service, label) = match arg.split_once(':') {
        Some((s, l)) => (s.to_string(), l.to_string()),
        None => (arg.to_string(), DEFAULT_LABEL.to_string()),
    };
    let label = flag.clone().unwrap_or(label);
    valid_label(&label)?;
    if service.is_empty() {
        return Err("no service given".into());
    }
    Ok((service, label))
}

// ── reading a key without it touching argv ──────────────────────────────────

/// Read a key from stdin. Echo is disabled when stdin is a terminal.
///
/// 🔴 A CREDENTIAL IS NOT ALWAYS ONE LINE (2026-10-05). This read exactly one
/// line, which is right for every API key here and wrong for the one kind of
/// credential that is a document: a Google service-account JSON. Pasting one at
/// the prompt stored its first line -- `{` -- and the broker then reported, from
/// gtoken.rs and correctly, "not a service-account JSON". The error was right;
/// the reader was not.
///
/// Piped stdin is now read to EOF, so the documented way to load a multi-line
/// credential works:
///
///     sudo authinjector add gsc -c alice < key.json
///
/// A terminal still reads one line, because a human typing at a hidden prompt
/// needs Enter to mean "done" rather than "newline" -- and the keys a human
/// types are single-line by nature.
///
/// 🔴 The value goes straight into a zeroizing Secret. The intermediate String
/// is the one unavoidable allocation; it is overwritten before being dropped.
fn read_key_from_stdin(prompt: &str) -> std::io::Result<Secret> {
    let stdin = std::io::stdin();
    let interactive = stdin.is_terminal();
    if interactive {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
    }
    let restore = if interactive { Some(set_echo(false)?) } else { None };
    let mut buf = String::new();
    if interactive {
        stdin.lock().read_line(&mut buf)?;
    } else {
        stdin.lock().read_to_string(&mut buf)?;
    }
    if let Some(saved) = restore {
        let _ = set_echo_raw(saved);
        eprintln!();
    }
    let trimmed = buf.trim_matches(['\n', '\r', ' ', '\t']).to_string();
    // Wipe the buffer we read into before it is dropped.
    unsafe { std::ptr::write_bytes(buf.as_mut_ptr(), 0, buf.len()) };
    Ok(Secret::new(trimmed))
}

fn set_echo(on: bool) -> std::io::Result<libc::termios> {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let saved = t;
    if on {
        t.c_lflag |= libc::ECHO;
    } else {
        t.c_lflag &= !libc::ECHO;
    }
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(saved)
}

fn set_echo_raw(t: libc::termios) -> std::io::Result<()> {
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ── writing config.toml, comments preserved ─────────────────────────────────

fn load_doc(path: &Path) -> Result<toml_edit::DocumentMut, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => t.parse::<toml_edit::DocumentMut>().map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml_edit::DocumentMut::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Write the config atomically via a temp file + rename, PRESERVING the
/// original's owner, group and mode.
///
/// 🔴 THE CHOWN IS NOT OPTIONAL, AND OMITTING IT BREAKS THE SERVICE.
///
/// The config is `0640 root:authinjector` so the broker's own user can read it
/// and no caller can. A rename replaces the inode, so the file written here
/// starts life owned by whoever ran the command with their default group --
/// root:root, not root:authinjector. The content is perfect and the broker
/// then cannot read its own config, failing at startup with a permission
/// error that looks nothing like "the tool you just ran did this".
///
/// That is exactly what happened the first time, so: stat the original,
/// restore its ownership and mode onto the replacement BEFORE the rename, and
/// treat a failure to do so as a hard error rather than a warning. A config
/// the broker cannot read is not a partial success.
fn save_doc(path: &Path, doc: &toml_edit::DocumentMut) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // Inherit from the file being replaced; fall back to 0640 for a new one.
    let previous = std::fs::metadata(path).ok();
    let mode = previous.as_ref().map(|m| m.mode() & 0o7777).unwrap_or(0o640);

    let tmp = path.with_extension("toml.tmp");
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        // 🔴 `.mode()` IS A REQUEST, AND THE CALLER'S UMASK CAN REFUSE IT. The
        // mode passed to open(2) is masked by the process umask, so under
        // `umask 077` the 0640 asked for above arrives as 0600 — and the file
        // stays root:authinjector, which now reads as "the group may not". The
        // broker runs as that group, cannot read its own config, and exits 78
        // on the next restart with the socket unit taken down behind it. A
        // script that wrapped `authinjector import` in `umask 077` to protect
        // its OWN temp file did exactly this on 2026-09-19. The file was
        // written to carry the mode of the one it replaces, so set it, rather
        // than ask for it and hope.
        f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(doc.to_string().as_bytes()).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }

    if let Some(md) = previous {
        let c = std::ffi::CString::new(tmp.as_os_str().as_encoded_bytes())
            .map_err(|e| e.to_string())?;
        if unsafe { libc::chown(c.as_ptr(), md.uid(), md.gid()) } != 0 {
            let err = std::io::Error::last_os_error();
            let _ = std::fs::remove_file(&tmp);
            return Err(format!(
                "could not preserve ownership on {} ({err}) — refusing to write a config \
                 the broker would not be able to read",
                path.display()
            ));
        }
    }

    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

/// Insert or replace one labelled key, leaving its siblings and every comment
/// in the file untouched.
fn upsert_instance(
    doc: &mut toml_edit::DocumentMut,
    service: &str,
    label: &str,
    key: &Secret,
    callers: &[String],
    rate: Option<u32>,
) {
    fn implicit_table() -> toml_edit::Item {
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        toml_edit::Item::Table(t)
    }

    let Some(services) = doc.entry("services").or_insert(implicit_table()).as_table_mut() else {
        return;
    };
    // 🔴 Implicit only when WE create it. Flipping an existing `[services]`
    // header to implicit would drop the header line and the comment block
    // install.sh writes above it.
    let Some(svc) = services.entry(service).or_insert(implicit_table()).as_table_mut() else {
        return;
    };

    let mut t = toml_edit::Table::new();
    t["key"] = toml_edit::value(key.expose_for_injection());
    let mut arr = toml_edit::Array::new();
    for c in callers {
        arr.push(c.as_str());
    }
    t["callers"] = toml_edit::value(arr);
    if let Some(r) = rate {
        t["rate_per_minute"] = toml_edit::value(r as i64);
    }
    svc.insert(label, toml_edit::Item::Table(t));
}

/// Is this label already configured?
///
/// 🔴 THE REASON REPLACEMENT IS OPT-IN. Writing a key is destructive and
/// silent: the value it overwrites is gone, and `show` reports only a length,
/// so a rotation you did not mean to perform looks exactly like one you did.
/// Re-running an import file must therefore be a no-op, not a rewrite --
/// otherwise a template still holding placeholders replaces working keys, and
/// the first sign of it is an upstream returning 401.
fn instance_exists(doc: &toml_edit::DocumentMut, service: &str, label: &str) -> bool {
    doc.get("services")
        .and_then(|s| s.as_table())
        .and_then(|t| t.get(service))
        .and_then(|s| s.as_table())
        .map(|t| t.contains_key(label))
        .unwrap_or(false)
}

// ── commands ────────────────────────────────────────────────────────────────

fn cmd_list(o: &Opts) -> ExitCode {
    let cat = match catalogue::Catalogue::load(&o.catalogue) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };

    let mut note = None;
    let settings = match config::Settings::load(&o.config) {
        Ok(s) => s,
        Err(e) => {
            // A config that will not load must not make `list` useless — the
            // catalogue is still worth showing, and the reason is worth saying.
            note = Some(e.to_string());
            config::Settings::default()
        }
    };

    println!("{:<16} {:<34} {}", "SERVICE", "NAME", "CONFIGURED");
    for id in cat.ids() {
        let def = cat.get(id).unwrap();
        let name = if def.name.is_empty() { "-" } else { def.name.as_str() };
        let configured = match settings.services.get(id) {
            None => String::new(),
            Some(entry) => entry
                .instances
                .keys()
                .map(|l| instance_key(id, l))
                .collect::<Vec<_>>()
                .join(", "),
        };
        println!("{id:<16} {name:<34} {configured}");
    }
    if let Some(n) = note {
        println!("\n  NOTE: {n}");
    }
    println!("\n  authinjector add <service> -c <who>              configure one");
    println!("  authinjector add <service> -c <who> -l <label>   a second key for the same service");
    ExitCode::SUCCESS
}

fn cmd_show(o: &Opts) -> ExitCode {
    let settings = match config::Settings::load(&o.config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let instances = settings.instances();
    if instances.is_empty() {
        println!("no services configured");
        return ExitCode::SUCCESS;
    }
    println!("{:<24} {:<26} {:<6} {}", "CALLED AS", "CALLERS", "RATE", "KEY");
    for (service, label, s) in instances {
        // 🔴 Length only, never the value. Enough to spot a key that absorbed
        // a trailing comment; useless to anyone reading over your shoulder.
        println!(
            "{:<24} {:<26} {:<6} {} chars",
            instance_key(service, label),
            s.callers.join(","),
            s.rate_per_minute,
            s.key.len()
        );
    }
    ExitCode::SUCCESS
}

fn cmd_add(o: &Opts) -> ExitCode {
    let Some(arg) = o.positional.first() else {
        eprintln!("authinjector: add needs a service name\n\n{}", usage());
        return ExitCode::from(2);
    };
    let (service, label) = match target_of(arg, &o.label) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(2);
        }
    };
    let cat = match catalogue::Catalogue::load(&o.catalogue) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let Some(def) = cat.get(&service) else {
        eprintln!("authinjector: {service:?} is not in the catalogue — `authinjector list` shows what is available");
        return ExitCode::from(2);
    };
    if o.callers.is_empty() {
        eprintln!("authinjector: -c is required — who may use this key?\n  e.g. -c alice  or  -c alice,svc-blacksq");
        return ExitCode::from(2);
    }
    let id = instance_key(&service, &label);

    // 🔴 Load and check BEFORE prompting. Refusing after someone has typed a
    // key wastes the one action that must happen at a terminal, and invites
    // them to reach for shell history the second time.
    let mut doc = match load_doc(&o.config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let replacing = instance_exists(&doc, &service, &label);
    if replacing && !o.force {
        eprintln!("authinjector: {id} is already configured — nothing changed");
        eprintln!("  authinjector show                    what is there now");
        eprintln!("  authinjector add {id} -c {} -f   replace it", o.callers.join(","));
        eprintln!("  authinjector add {service} -c {} -l <label>   add another key instead", o.callers.join(","));
        return ExitCode::from(2);
    }

    if !def.signup_url.is_empty() {
        eprintln!("{} — keys from {}", def.name, def.signup_url);
    }
    let key = match read_key_from_stdin(&format!("key for {id}: ")) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("authinjector: could not read the key: {e}");
            return ExitCode::from(74);
        }
    };
    if key.is_blank() {
        eprintln!("authinjector: no key given, nothing changed");
        return ExitCode::from(2);
    }

    upsert_instance(&mut doc, &service, &label, &key, &o.callers, o.rate);
    if let Err(e) = save_doc(&o.config, &doc) {
        eprintln!("authinjector: {e}");
        return ExitCode::from(73);
    }
    println!(
        "{} {id} ({} chars) for {}",
        if replacing { "replaced" } else { "added" },
        key.len(),
        o.callers.join(",")
    );
    println!("  called as /{id}/...");
    println!("  systemctl restart authinjector   to pick it up");
    ExitCode::SUCCESS
}

/// `authinjector push-to <service>[:<label>] <dest>...` — declare where a key
/// may be delivered by `/_broker/push`.
///
/// 🔴 THIS EXISTS SO NOBODY OPENS config.toml IN AN EDITOR. That file holds
/// every key on the box; a sudo-edit to add one line risks all of them, and a
/// botched save is how the broker lost its own config once already. The
/// destinations are validated here and written through the same comment- and
/// permission-preserving path `add` uses.
///
/// Naming no destination CLEARS the list, which is the same as never having
/// set one: that key can then be delivered nowhere.
fn cmd_push_to(o: &Opts) -> ExitCode {
    // `--default` sets the fleet-wide section instead of one key's override.
    if o.push_default {
        let dests: Vec<String> = o.positional.clone();
        for d in &dests {
            if let Err(e) = push::Destination::parse_pattern(d) {
                eprintln!("authinjector: {d:?}: {e}");
                return ExitCode::from(2);
            }
        }
        let mut doc = match load_doc(&o.config) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("authinjector: {e}");
                return ExitCode::from(78);
            }
        };
        if dests.is_empty() {
            doc.remove("push");
        } else {
            let mut arr = toml_edit::Array::new();
            for d in &dests {
                arr.push(d.as_str());
            }
            let mut t = toml_edit::Table::new();
            t["default"] = toml_edit::value(arr);
            doc.insert("push", toml_edit::Item::Table(t));
        }
        if let Err(e) = save_doc(&o.config, &doc) {
            eprintln!("authinjector: {e}");
            return ExitCode::from(74);
        }
        if dests.is_empty() {
            println!("No fleet default: only keys with their own push_to may be delivered.");
        } else {
            println!("Any key without its own rule may be delivered to:");
            for d in &dests {
                println!("  {d}");
            }
        }
        println!("\nRestart to pick it up:  sudo systemctl restart authinjector.socket");
        return ExitCode::SUCCESS;
    }

    let Some(arg) = o.positional.first() else {
        eprintln!("usage: authinjector push-to --default <dest>...      the fleet-wide rule\n\
                   \u{20}      authinjector push-to <service>[:<label>] <dest>...\n\
                   \n  e.g. authinjector push-to resend:blacksq cf-worker:blacksq-*/RESEND_API_KEY\n\
                   \n  Destinations: cf-worker:{{script}}/{{NAME}}\n\
                   \u{20}               gh-repo:{{owner}}/{{repo}}/{{NAME}}\n\
                   \u{20}               gh-env:{{owner}}/{{repo}}/{{env}}/{{NAME}}\n\
                   \n  `*` matches inside one segment, and may not be a first segment on its own.\n\
                   \u{20} A request always names one real secret; only a rule may wildcard the name.");
        return ExitCode::from(2);
    };
    let (service, label) = match target_of(arg, &o.label) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(2);
        }
    };
    let id = config::instance_key(&service, &label);
    let dests: Vec<String> = o.positional[1..].to_vec();

    // Validated BEFORE anything is written: a destination the broker would
    // refuse to load must never reach the file, because the next restart is
    // what would discover it.
    // A deny may say "any organisation"; an allow may not. See push.rs.
    for d in &dests {
        let parsed = if o.push_mode == "deny" {
            push::Destination::parse_deny(d)
        } else {
            push::Destination::parse_pattern(d)
        };
        if let Err(e) = parsed {
            eprintln!("authinjector: {d:?}: {e}");
            return ExitCode::from(2);
        }
    }

    let mut doc = match load_doc(&o.config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    if !instance_exists(&doc, &service, &label) {
        eprintln!("authinjector: {id} is not configured — `authinjector show` lists what is");
        return ExitCode::from(2);
    }

    let Some(table) = doc
        .get_mut("services")
        .and_then(|s| s.as_table_mut())
        .and_then(|t| t.get_mut(&service))
        .and_then(|s| s.as_table_mut())
        .and_then(|t| t.get_mut(&label))
        .and_then(|i| i.as_table_mut())
    else {
        eprintln!("authinjector: {id} is not a table in the config");
        return ExitCode::from(78);
    };

    let field = match o.push_mode {
        "allow" => "push_allow",
        "deny" => "push_deny",
        _ => "push_to",
    };
    if dests.is_empty() {
        table.remove(field);
    } else {
        let mut arr = toml_edit::Array::new();
        for d in &dests {
            arr.push(d.as_str());
        }
        table[field] = toml_edit::value(arr);
    }

    if let Err(e) = save_doc(&o.config, &doc) {
        eprintln!("authinjector: {e}");
        return ExitCode::from(74);
    }
    match (o.push_mode, dests.is_empty()) {
        ("deny", true) => println!("{id} forbids no destination."),
        ("deny", false) => {
            println!("{id} may NEVER be delivered to:");
            for d in &dests {
                println!("  {d}");
            }
        }
        ("allow", true) => println!("{id} adds nothing to whatever rule applies."),
        ("allow", false) => {
            println!("{id} may also be delivered to:");
            for d in &dests {
                println!("  {d}");
            }
        }
        (_, true) => println!("{id} may no longer be delivered anywhere."),
        (_, false) => {
            println!("{id} may be delivered to:");
            for d in &dests {
                println!("  {d}");
            }
        }
    }
    println!("\nRestart to pick it up:  sudo systemctl restart authinjector.socket");
    ExitCode::SUCCESS
}

fn cmd_del(o: &Opts) -> ExitCode {
    let Some(arg) = o.positional.first() else {
        eprintln!("authinjector: del needs a service, e.g. `del tavily` or `del tavily:personal`");
        return ExitCode::from(2);
    };
    let (service, label) = match target_of(arg, &o.label) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(2);
        }
    };
    let id = instance_key(&service, &label);

    let mut doc = match load_doc(&o.config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };

    let Some(services) = doc.get_mut("services").and_then(|s| s.as_table_mut()) else {
        eprintln!("authinjector: nothing is configured, nothing changed");
        return ExitCode::from(2);
    };
    let Some(svc) = services.get_mut(&service).and_then(|s| s.as_table_mut()) else {
        eprintln!("authinjector: {id:?} is not configured, nothing changed");
        return ExitCode::from(2);
    };
    if svc.remove(&label).is_none() {
        let siblings: Vec<String> = svc.iter().map(|(l, _)| instance_key(&service, l)).collect();
        eprintln!("authinjector: {id:?} is not configured, nothing changed");
        if !siblings.is_empty() {
            eprintln!("  {service} is configured as: {}", siblings.join(", "));
        }
        return ExitCode::from(2);
    }
    // Removing the last label removes the service section with it, rather than
    // leaving an empty one that `merge` would then refuse to start on.
    let now_empty = svc.is_empty();
    if now_empty {
        services.remove(&service);
    }

    if let Err(e) = save_doc(&o.config, &doc) {
        eprintln!("authinjector: {e}");
        return ExitCode::from(73);
    }
    println!("removed {id} and its key");
    println!("  systemctl restart authinjector   to pick it up");
    ExitCode::SUCCESS
}

fn cmd_import(o: &Opts) -> ExitCode {
    let Some(file) = o.positional.first() else {
        eprintln!("authinjector: import needs a file\n  service[/label]:key:callers[:rate] per line");
        return ExitCode::from(2);
    };
    let path = Path::new(file);

    // 🔴 The import file holds every key in plaintext. Say so if anyone else
    // on the box can read it.
    if let Ok(md) = std::fs::metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode() & 0o077;
        if mode != 0 {
            eprintln!("warning: {} is readable by others (mode {:o}) — chmod 600 it", path.display(), md.permissions().mode() & 0o777);
        }
    }

    let cat = match catalogue::Catalogue::load(&o.catalogue) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("authinjector: {}: {e}", path.display());
            return ExitCode::from(66);
        }
    };
    // All-or-nothing: a partial import leaves you not knowing which half landed.
    let entries = match importer::parse(&text, &cat) {
        Ok(e) => e,
        Err(errs) => {
            eprintln!("authinjector: {} problem(s), nothing imported:", errs.len());
            for e in errs {
                eprintln!("  {e}");
            }
            return ExitCode::from(65);
        }
    };

    let mut doc = match load_doc(&o.config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    // Existing keys are skipped unless -f, so re-running a file is a no-op
    // rather than a silent mass rotation.
    let mut plan: Vec<(&importer::ImportEntry, bool)> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for e in &entries {
        let exists = instance_exists(&doc, &e.service, &e.label);
        if exists && !o.force {
            skipped.push(e.id());
        } else {
            plan.push((e, exists));
        }
    }

    if plan.is_empty() {
        // Nothing is written and the file is not touched: an unchanged config
        // must not look like a change, or the restart prompt trains people to
        // restart for nothing.
        println!("nothing to do — all {} key(s) in this file are already configured", entries.len());
        println!("  authinjector show          what is configured now");
        println!("  import -f {}   replace them with the values in this file", path.display());
        return ExitCode::SUCCESS;
    }

    for (e, _) in &plan {
        upsert_instance(&mut doc, &e.service, &e.label, &e.key, &e.callers, e.rate_per_minute);
    }
    if let Err(e) = save_doc(&o.config, &doc) {
        eprintln!("authinjector: {e}");
        return ExitCode::from(73);
    }

    let replaced = plan.iter().filter(|(_, existed)| *existed).count();
    println!(
        "imported {} key(s){}:",
        plan.len(),
        if replaced > 0 { format!(", {replaced} of them replacing an existing key") } else { String::new() }
    );
    for (e, existed) in &plan {
        println!(
            "  {:<24} {} chars, callers {}{}",
            e.id(),
            e.key.len(),
            e.callers.join(","),
            if *existed { "   REPLACED" } else { "" }
        );
    }
    if !skipped.is_empty() {
        println!("\nskipped {} already configured, -f replaces them:", skipped.len());
        println!("  {}", skipped.join(", "));
    }
    println!("\n  shred -u {}   once you are done with it", path.display());
    println!("  systemctl restart authinjector   to pick it up");
    ExitCode::SUCCESS
}

/// Move pre-label entries under `default`.
///
/// 🔴 THE KEY IS MOVED AS A toml_edit ITEM AND NEVER READ. It is not parsed
/// into a String, not held in a variable of ours, and not logged -- the whole
/// operation is a reparenting of nodes in the document tree, so the credential
/// goes from one line of the file to another without this process ever
/// inspecting it. Comments attached to each line move with it.
fn cmd_migrate(o: &Opts) -> ExitCode {
    let mut doc = match load_doc(&o.config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let Some(services) = doc.get_mut("services").and_then(|s| s.as_table_mut()) else {
        println!("nothing to migrate");
        return ExitCode::SUCCESS;
    };

    let names: Vec<String> = services.iter().map(|(k, _)| k.to_string()).collect();
    let mut moved: Vec<String> = Vec::new();
    for name in names {
        let Some(svc) = services.get_mut(&name).and_then(|s| s.as_table_mut()) else {
            continue;
        };
        if !svc.contains_key("key") {
            continue; // already labelled
        }
        let mut inner = toml_edit::Table::new();
        let fields: Vec<String> = svc.iter().map(|(k, _)| k.to_string()).collect();
        for f in fields {
            if let Some(item) = svc.remove(&f) {
                inner.insert(&f, item);
            }
        }
        svc.set_implicit(true);
        svc.insert(DEFAULT_LABEL, toml_edit::Item::Table(inner));
        moved.push(name);
    }

    if moved.is_empty() {
        println!("nothing to migrate — every key is already under a label");
        return ExitCode::SUCCESS;
    }
    if let Err(e) = save_doc(&o.config, &doc) {
        eprintln!("authinjector: {e}");
        return ExitCode::from(73);
    }
    println!("migrated {} service(s) to labelled keys:", moved.len());
    for m in &moved {
        println!("  [services.{m}] -> [services.{m}.default]   still called as /{m}/...");
    }
    println!("\n  authinjector show                confirm");
    println!("  systemctl restart authinjector   to pick it up");
    ExitCode::SUCCESS
}

// ── serve ───────────────────────────────────────────────────────────────────

async fn cmd_serve(o: &Opts) -> ExitCode {
    let cat = match catalogue::Catalogue::load(&o.catalogue) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let settings = match config::Settings::load(&o.config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };
    let (policy, secrets) = match config::merge(&cat, settings) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(78);
        }
    };

    let mut ids: Vec<&String> = policy.upstreams.keys().collect();
    ids.sort();
    eprintln!(
        "authinjector: {} key(s) [{}] ready",
        ids.len(),
        ids.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
    );

    if o.check_only {
        eprintln!("authinjector: --check passed, not serving");
        return ExitCode::SUCCESS;
    }

    let audit = match audit::Audit::to_file(&o.audit) {
        Ok(a) => a,
        Err(e) => {
            // No audit means no record of what was forwarded. Refuse rather
            // than proxy credentials silently.
            eprintln!("authinjector: cannot open audit log {}: {e}", o.audit.display());
            return ExitCode::from(73);
        }
    };
    let forwarder = match proxy::Forwarder::new() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("authinjector: {e}");
            return ExitCode::from(70);
        }
    };

    let broker = Arc::new(server::Broker {
        policy,
        secrets,
        audit,
        limiter: ratelimit::RateLimiter::new(),
        forwarder,
    });
    if let Err(e) = server::serve(broker, o.socket.as_deref()).await {
        eprintln!("authinjector: {e}");
        return ExitCode::from(74);
    }
    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> ExitCode {
    let (cmd, opts) = match parse_args() {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };
    match cmd.as_str() {
        "list" => cmd_list(&opts),
        "show" => cmd_show(&opts),
        "add" => cmd_add(&opts),
        "del" | "delete" | "rm" => cmd_del(&opts),
        "push-to" => cmd_push_to(&opts),
        "import" => cmd_import(&opts),
        "migrate" => cmd_migrate(&opts),
        "serve" => cmd_serve(&opts).await,
        other => {
            eprintln!("unknown command {other:?}\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 🔴 THE 2026-09-19 OUTAGE. A caller's umask must not decide who can read
    /// the broker's config. `umask 077` around `authinjector import` wrote it
    /// 0600 root:authinjector; the broker, running as that group, could no
    /// longer read it and exited 78 at the next restart.
    #[test]
    fn a_restrictive_umask_does_not_narrow_the_config() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("authinjector-umask-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "[services]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let doc: toml_edit::DocumentMut = "[services]\n".parse().unwrap();
        let old = unsafe { libc::umask(0o077) };
        let result = save_doc(&path, &doc);
        unsafe { libc::umask(old) };
        result.unwrap();

        let mode = std::fs::metadata(&path).unwrap().mode() & 0o7777;
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(mode, 0o640, "save_doc must carry the replaced file's mode, whatever the umask");
    }

    #[test]
    fn a_bare_service_targets_the_default_label() {
        assert_eq!(target_of("tavily", &None).unwrap(), ("tavily".into(), "default".into()));
    }

    #[test]
    fn the_colon_form_is_accepted_so_del_takes_what_show_printed() {
        assert_eq!(
            target_of("tavily:personal", &None).unwrap(),
            ("tavily".into(), "personal".into())
        );
    }

    #[test]
    fn the_flag_wins_over_the_colon_form() {
        assert_eq!(
            target_of("tavily:personal", &Some("work".into())).unwrap(),
            ("tavily".into(), "work".into())
        );
    }

    #[test]
    fn a_label_that_could_confuse_a_path_is_refused() {
        assert!(target_of("tavily", &Some("bad label".into())).is_err());
        assert!(target_of("tavily", &Some("a/b".into())).is_err());
    }

    // ── the config writer ───────────────────────────────────────────────────

    fn doc_after(ops: &[(&str, &str, &str)], start: &str) -> String {
        let mut doc = start.parse::<toml_edit::DocumentMut>().unwrap();
        for (service, label, key) in ops {
            upsert_instance(
                &mut doc,
                service,
                label,
                &Secret::new((*key).to_string()),
                &["alice".to_string()],
                Some(20),
            );
        }
        doc.to_string()
    }

    #[test]
    fn two_labels_for_one_service_become_two_tables() {
        let out = doc_after(&[("tavily", "default", "A"), ("tavily", "personal", "B")], "");
        assert!(out.contains("[services.tavily.default]"), "{out}");
        assert!(out.contains("[services.tavily.personal]"), "{out}");
        assert!(!out.contains("\n[services.tavily]\n"), "the parent header is implicit: {out}");
    }

    #[test]
    fn adding_a_label_leaves_its_sibling_and_the_comments_alone() {
        let start = "# Keys for Tavily\n[services.tavily.default]\nkey = \"KEEP-ME\"\ncallers = [\"alice\"]\n";
        let out = doc_after(&[("tavily", "personal", "B")], start);
        assert!(out.contains("# Keys for Tavily"), "comments survive: {out}");
        assert!(out.contains("KEEP-ME"), "the sibling key survives: {out}");
        assert!(out.contains("[services.tavily.personal]"));
    }

    #[test]
    fn an_existing_services_header_and_its_comment_block_survive() {
        // install.sh seeds the file with a comment block above `[services]`.
        // Flipping that table to implicit would delete both.
        let start = "# Managed with the CLI\n[services]\n";
        let out = doc_after(&[("pexels", "default", "A")], start);
        assert!(out.contains("# Managed with the CLI"), "{out}");
        assert!(out.contains("[services]"), "{out}");
        assert!(out.contains("[services.pexels.default]"), "{out}");
    }

    #[test]
    fn an_existing_label_is_detected_and_its_siblings_are_not_confused_with_it() {
        let doc = "[services.tavily.default]\nkey=\"A\"\ncallers=[\"alice\"]\n"
            .parse::<toml_edit::DocumentMut>()
            .unwrap();
        assert!(instance_exists(&doc, "tavily", "default"));
        assert!(!instance_exists(&doc, "tavily", "personal"), "a different label is not configured");
        assert!(!instance_exists(&doc, "pexels", "default"), "a different service is not configured");
        assert!(!instance_exists(&toml_edit::DocumentMut::new(), "tavily", "default"));
    }

    #[test]
    fn re_adding_the_same_label_replaces_it_rather_than_duplicating() {
        let out = doc_after(&[("tavily", "default", "OLD"), ("tavily", "default", "NEW")], "");
        assert!(out.contains("NEW"));
        assert!(!out.contains("OLD"));
        assert_eq!(out.matches("[services.tavily.default]").count(), 1);
    }
}
