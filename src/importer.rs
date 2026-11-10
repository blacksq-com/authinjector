//! Batch import: `service[/label]:key:callers[:rate]`, one per line.
//!
//! ```text
//! # comments and blank lines are ignored
//! tavily:tvly-xxxxxx:alice:20
//! pexels:xaxaxa:alice:20
//! openai:sk-yyy:alice,svc-blacksq:10
//! resend:re-zzz:svc-blacksq            # rate omitted, defaults applied
//!
//! # several keys for one service, each labelled:
//! tavily/blacksq:tvly-aaa:alice:20
//! tavily/personal:tvly-bbb:alice:5
//! ```
//!
//! 🔴 WHY THE LABEL IS SEPARATED BY `/` AND NOT `:`, when a request path uses
//! `/tavily:blacksq/...`. Each separator is forced by its own context and
//! neither can be the other:
//!
//!   - a path cannot use `/`, which already separates the upstream from the
//!     request path
//!   - a line here cannot use `:`, because a KEY MAY CONTAIN COLONS and
//!     `tavily:a:b:alice:20` would be genuinely ambiguous — is `a` a label or
//!     the first half of the key?
//!
//! A service id and a label both exclude `/` by construction, so the first
//! field parses without ambiguity.
//!
//! 🔴 WHY A FILE AT ALL. It keeps keys out of argv and out of shell history.
//! A key passed as `-k xxxx` is visible at /proc/PID/cmdline to every user on
//! the box for as long as the command runs, and is written to ~/.bash_history
//! unless the line began with a space. A file avoids both.
//!
//! 🔴 THE FILE IS ITSELF A CREDENTIAL FILE. It holds every key in plaintext,
//! so `import` checks its permissions, warns if it is group- or world-readable,
//! and offers to shred it afterwards. Importing and leaving it lying in
//! ~/Downloads would defeat the exercise.
//!
//! 🔴 VALIDATE EVERYTHING, THEN WRITE. A partial import is worse than none: it
//! leaves you not knowing which half landed. Every line is parsed and checked
//! against the catalogue before a single byte reaches the config.

use crate::catalogue::Catalogue;
use crate::config::{instance_key, valid_label, DEFAULT_LABEL};
use crate::secret::Secret;

#[derive(Debug)]
pub struct ImportEntry {
    pub service: String,
    pub label: String,
    pub key: Secret,
    pub callers: Vec<String>,
    pub rate_per_minute: Option<u32>,
}

impl ImportEntry {
    /// How this key will be addressed once written.
    pub fn id(&self) -> String {
        instance_key(&self.service, &self.label)
    }
}

#[derive(Debug)]
pub struct ImportError {
    pub line_no: usize,
    pub message: String,
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 🔴 The line's CONTENT is never quoted back -- it contains a key.
        write!(f, "line {}: {}", self.line_no, self.message)
    }
}

struct ParsedLine {
    service: String,
    label: String,
    key: String,
    callers: Vec<String>,
    rate: Option<u32>,
}

/// Parse one line into its fields.
///
/// 🔴 A KEY MAY CONTAIN COLONS, so the fields are taken from the OUTSIDE IN,
/// never by splitting on every colon. Basic-auth style credentials (`id:secret`)
/// and several vendors' prefixed tokens contain them, and a naive `split(':')`
/// would truncate such a key into something that fails authentication in a way
/// that looks exactly like a revoked credential.
///
///   target   = everything before the FIRST colon, itself `service[/label]`
///   rate     = after the LAST colon, only when it is entirely digits
///   callers  = after the last colon of what remains
///   key      = whatever is left in the middle, colons and all
fn parse_line(line: &str) -> Result<ParsedLine, String> {
    let (target, rest) = line.split_once(':').ok_or("expected service[/label]:key:callers[:rate]")?;

    let (service, label) = match target.split_once('/') {
        Some((s, l)) => (s.trim(), l.trim()),
        None => (target.trim(), DEFAULT_LABEL),
    };
    if service.is_empty() {
        return Err("empty service name".into());
    }
    valid_label(label)?;

    // Is the final field a rate, or is it the callers list?
    let (body, rate) = match rest.rsplit_once(':') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
            let r: u32 = tail.parse().map_err(|_| "rate is not a number".to_string())?;
            if r == 0 {
                return Err("rate must be greater than zero".into());
            }
            (head, Some(r))
        }
        _ => (rest, None),
    };

    let (key, callers_field) = body.rsplit_once(':').ok_or("expected service[/label]:key:callers[:rate]")?;
    if key.trim().is_empty() {
        return Err("empty key".into());
    }

    let callers: Vec<String> = callers_field
        .split(',')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    if callers.is_empty() {
        return Err("no callers listed".into());
    }

    Ok(ParsedLine {
        service: service.to_string(),
        label: label.to_string(),
        key: key.to_string(),
        callers,
        rate,
    })
}

/// Parse and validate the whole file. All-or-nothing.
pub fn parse(text: &str, cat: &Catalogue) -> Result<Vec<ImportEntry>, Vec<ImportError>> {
    let mut out: Vec<ImportEntry> = Vec::new();
    let mut errors = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw).trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        match parse_line(line) {
            Err(message) => errors.push(ImportError { line_no, message }),
            Ok(p) => {
                let id = instance_key(&p.service, &p.label);
                if cat.get(&p.service).is_none() {
                    errors.push(ImportError {
                        line_no,
                        message: format!(
                            "service {:?} is not in the catalogue — `authinjector list` shows what is available",
                            p.service
                        ),
                    });
                } else if seen.contains(&id) {
                    // 🔴 By INSTANCE, not by service. Two labelled keys for one
                    // service are the point; two entries for the same label are
                    // a mistake, and silently keeping the last would leave the
                    // operator with a key they did not choose.
                    errors.push(ImportError { line_no, message: format!("{id:?} appears twice") });
                } else {
                    seen.push(id);
                    out.push(ImportEntry {
                        service: p.service,
                        label: p.label,
                        key: Secret::new(p.key),
                        callers: p.callers,
                        rate_per_minute: p.rate,
                    });
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    if out.is_empty() {
        return Err(vec![ImportError { line_no: 0, message: "no entries found".into() }]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAT: &str = r#"
[services.tavily]
base_url = "https://api.tavily.com"
auth_header = "Authorization"
auth_prefix = "Bearer "
endpoints = [{ methods = ["POST"], path_prefix = "/search" }]

[services.pexels]
base_url = "https://api.pexels.com"
auth_header = "Authorization"
endpoints = [{ methods = ["GET"], path_prefix = "/v1/search" }]
"#;

    fn cat() -> Catalogue {
        Catalogue::parse(CAT).expect("catalogue")
    }

    #[test]
    fn parses_the_documented_form() {
        let e = parse("tavily:xxxxxx:alice:20\npexels:xaxaxa:alice:20\n", &cat()).expect("valid");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].service, "tavily");
        assert_eq!(e[0].label, "default", "an unlabelled line is the default key");
        assert_eq!(e[0].id(), "tavily");
        assert_eq!(e[0].key.expose_for_injection(), "xxxxxx");
        assert_eq!(e[0].callers, vec!["alice"]);
        assert_eq!(e[0].rate_per_minute, Some(20));
    }

    #[test]
    fn a_label_is_given_with_a_slash() {
        let e = parse("tavily/blacksq:tvly-aaa:alice:20\n", &cat()).expect("valid");
        assert_eq!(e[0].service, "tavily");
        assert_eq!(e[0].label, "blacksq");
        assert_eq!(e[0].id(), "tavily:blacksq");
        assert_eq!(e[0].key.expose_for_injection(), "tvly-aaa");
    }

    #[test]
    fn several_labelled_keys_for_one_service_are_the_point() {
        let e = parse(
            "tavily/blacksq:tvly-aaa:alice:20\ntavily/personal:tvly-bbb:alice:5\ntavily:tvly-ccc:alice\n",
            &cat(),
        )
        .expect("valid");
        assert_eq!(e.len(), 3);
        let ids: Vec<String> = e.iter().map(|x| x.id()).collect();
        assert_eq!(ids, vec!["tavily:blacksq", "tavily:personal", "tavily"]);
    }

    #[test]
    fn a_key_containing_colons_survives_intact_even_with_a_label() {
        // The failure this prevents: a truncated key authenticates as nothing
        // and looks exactly like a revoked credential.
        let e = parse("tavily/work:user:pass:word:alice:20\n", &cat()).expect("valid");
        assert_eq!(e[0].label, "work");
        assert_eq!(e[0].key.expose_for_injection(), "user:pass:word");
        assert_eq!(e[0].callers, vec!["alice"]);
        assert_eq!(e[0].rate_per_minute, Some(20));
    }

    #[test]
    fn rate_may_be_omitted() {
        let e = parse("pexels:abc123:alice\n", &cat()).expect("valid");
        assert_eq!(e[0].rate_per_minute, None);
        assert_eq!(e[0].key.expose_for_injection(), "abc123");
    }

    #[test]
    fn several_callers_are_comma_separated() {
        let e = parse("tavily:k:alice,svc-blacksq:10\n", &cat()).expect("valid");
        assert_eq!(e[0].callers, vec!["alice", "svc-blacksq"]);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let e = parse("# a note\n\n  ; another\ntavily:k:alice:5\n", &cat()).expect("valid");
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn an_unknown_service_fails_the_whole_import() {
        let errs = parse("tavily:k:alice:5\nnosuch:k:alice:5\n", &cat()).expect_err("must fail");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].line_no, 2);
        assert!(errs[0].message.contains("not in the catalogue"));
    }

    #[test]
    fn the_same_label_twice_is_refused_but_two_labels_are_not() {
        let errs = parse("tavily/work:a:alice:5\ntavily/work:b:alice:5\n", &cat()).expect_err("must fail");
        assert!(errs[0].message.contains("twice"));
        parse("tavily/work:a:alice:5\ntavily/home:b:alice:5\n", &cat()).expect("two labels are fine");
    }

    #[test]
    fn the_bare_form_and_an_explicit_default_label_collide() {
        // Both mean `tavily`. Accepting them would write one key and discard
        // the other without saying so.
        let errs = parse("tavily:a:alice:5\ntavily/default:b:alice:5\n", &cat()).expect_err("must fail");
        assert!(errs[0].message.contains("twice"));
    }

    #[test]
    fn an_invalid_label_is_reported_without_echoing_the_key() {
        let errs = parse("tavily/bad label:secret-key:alice:5\n", &cat()).expect_err("must fail");
        assert!(errs[0].message.contains("label"));
        assert!(!errs[0].to_string().contains("secret-key"));
    }

    #[test]
    fn malformed_lines_are_reported_by_number_without_echoing_the_key() {
        let errs = parse("tavily:onlytwo\n", &cat()).expect_err("must fail");
        assert_eq!(errs[0].line_no, 1);
        let rendered = errs[0].to_string();
        assert!(!rendered.contains("onlytwo"), "an error must never quote the line back");
    }

    #[test]
    fn an_empty_file_is_an_error_not_a_silent_success() {
        assert!(parse("# nothing here\n", &cat()).is_err());
    }
}
