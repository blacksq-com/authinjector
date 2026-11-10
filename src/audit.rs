//! The audit line: one per call, append-only JSON (PROTOCOL.md §5).
//!
//! This is also the site check's cost line, which is why the schema lives in
//! the protocol spec and is not duplicated in that repo.
//!
//! 🔴 THE SIGNATURE IS THE CONTROL, NOT A RULE.
//!
//! `Line` holds primitives only. There is no field a header map, a request or
//! a response body could be put in, so "never log headers or bodies" cannot be
//! violated by someone who forgets, by a field added in haste, or by a debug
//! line that seemed harmless at the time. A rule you can break by accident
//! eventually gets broken; a struct with nowhere to put the thing cannot.
//!
//! This matters because the alternative was already tried here. The guard this
//! whole project replaces was a blocklist of ways to print an environment, and
//! a leak went straight through it. "Log every header except the one we add"
//! is the same mistake one layer down: a caller putting a token in `X-Debug`
//! would have it written to disk.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Forwarded,
    UnknownUpstream,
    CallerNotPermitted,
    PathNotAllowed,
    MethodNotAllowed,
    RateLimited,
    UpstreamError,
}

#[derive(Debug, Serialize)]
pub struct Line {
    pub ts: String,
    pub caller: String,
    pub uid: u32,
    pub upstream: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub duration_ms: u64,
    pub cost_cad: f64,
    pub policy_id: String,
    pub outcome: Outcome,
}

/// Drop any query string before recording.
///
/// 🔴 NOT COSMETIC. `?key=`, `?api_key=` and `?access_token=` are all live
/// conventions -- a Google API key travels exactly that way. Recording the
/// caller's raw path would write credentials into the one file whose promise
/// is that it holds none.
pub fn path_only(path: &str) -> &str {
    match path.split_once('?') {
        Some((p, _)) => p,
        None => path,
    }
}

fn now_iso() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Civil-from-days, so no chrono dependency for one timestamp.
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };
    format!("{year:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub struct Audit {
    sink: Mutex<Box<dyn Write + Send>>,
}

impl Audit {
    /// Append-only, `0600`, line-buffered.
    ///
    /// The log carries no secret by construction, but it is a complete map of
    /// what this machine talks to and how often, which is not public either.
    /// Flushed per line: a crash must not lose the record of a call that has
    /// already reached an upstream, because an unrecorded call is
    /// indistinguishable from one that never happened.
    pub fn to_file(path: &Path) -> std::io::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let f = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
        Ok(Self { sink: Mutex::new(Box::new(f)) })
    }

    #[cfg(test)]
    pub fn to_writer(w: Box<dyn Write + Send>) -> Self {
        Self { sink: Mutex::new(w) }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        caller: &str,
        uid: u32,
        upstream: &str,
        method: &str,
        path: &str,
        status: u16,
        bytes_in: usize,
        bytes_out: usize,
        duration_ms: u64,
        cost_cad: f64,
        policy_id: &str,
        outcome: Outcome,
    ) -> Line {
        let line = Line {
            ts: now_iso(),
            caller: caller.to_string(),
            uid,
            upstream: upstream.to_string(),
            method: method.to_ascii_uppercase(),
            path: path_only(path).to_string(),
            status,
            bytes_in,
            bytes_out,
            duration_ms,
            cost_cad: (cost_cad * 1e6).round() / 1e6,
            policy_id: policy_id.to_string(),
            outcome,
        };
        if let Ok(json) = serde_json::to_string(&line) {
            if let Ok(mut s) = self.sink.lock() {
                let _ = writeln!(s, "{json}");
                let _ = s.flush();
            }
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings_are_never_recorded() {
        assert_eq!(path_only("/v5/runPagespeed?url=x&key=SECRET-VALUE"), "/v5/runPagespeed");
        assert_eq!(path_only("/search"), "/search");
    }

    #[test]
    fn a_recorded_line_contains_no_query_string_even_when_the_caller_sent_one() {
        let a = Audit::to_writer(Box::new(Vec::new()));
        let line = a.record(
            "alice", 1000, "psi", "get",
            "/pagespeedonline/v5/runPagespeed?url=https://x&key=AIza-SHOULD-NOT-APPEAR",
            200, 0, 1234, 812, 0.0, "psi@1", Outcome::Forwarded,
        );
        let json = serde_json::to_string(&line).unwrap();
        assert!(!json.contains("AIza-SHOULD-NOT-APPEAR"), "a key in the query must never be logged");
        assert!(!json.contains('?'));
        assert!(json.contains("\"method\":\"GET\""));
    }

    #[test]
    fn timestamp_is_iso_8601_utc() {
        let ts = now_iso();
        assert_eq!(ts.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(ts.ends_with('Z'));
        assert!(ts.starts_with("20"));
    }

    #[test]
    fn outcomes_serialise_as_stable_snake_case() {
        let j = serde_json::to_string(&Outcome::CallerNotPermitted).unwrap();
        assert_eq!(j, "\"caller_not_permitted\"");
    }
}
