//! Key material, and the only type allowed to hold it.
//!
//! 🔴 THIS IS ONE OF THE FOUR FILES TO READ. It is deliberately tiny.
//!
//! Three properties, each enforced by the type rather than by a rule someone
//! has to remember:
//!
//!   1. It wipes itself. `ZeroizeOnDrop` overwrites the heap buffer when the
//!      value is dropped, and the compiler is not permitted to optimise that
//!      write away. Stage 5 test 3 gcores the running process and greps the
//!      dump for the key; this is what makes it pass.
//!   2. It cannot be printed by accident. `Debug` is implemented to render
//!      `Secret(<redacted>)`. There is no `Display`, no `Serialize`, and no
//!      `ToString`. A `{:?}` in a log line or a panic message cannot leak it.
//!   3. Reading it is deliberate and greppable. The accessor is called
//!      `expose_for_injection`, not `as_str`, so `grep -rn expose_for_injection
//!      src/` lists every place in the program where a key becomes visible.
//!      That list should stay one entry long.

use std::fmt;

use serde::{Deserialize, Deserializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret {
    value: String,
}

impl Secret {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    /// The ONE way to read key material.
    ///
    /// Named to be conspicuous in review and in `grep`. Call it as late as
    /// possible and never bind the result to a longer-lived variable: the
    /// borrow should end inside the statement that writes the header.
    pub fn expose_for_injection(&self) -> &str {
        &self.value
    }

    /// Whitespace-only counts as unset. Checked at startup so a half-filled
    /// config fails once, loudly, rather than per request.
    pub fn is_blank(&self) -> bool {
        self.value.trim().is_empty()
    }

    /// Length only — safe to print, and the one diagnostic that tells you a
    /// trailing comment got absorbed into the value.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// True when the value begins or ends with whitespace.
    ///
    /// 🔴 NO API KEY IS WHITESPACE-PADDED, so this is always an accident of
    /// pasting or editing -- and it is the accident hardest to see, because
    /// the value looks perfect in a text editor and `show` reports a length
    /// that is only one or two characters off.
    ///
    /// It matters in BOTH transports and breaks them differently. As a header
    /// the padding is legal to construct but upstream edges reject the request
    /// at the protocol layer, returning their own error page rather than the
    /// API's JSON -- which reads as an outage, not a bad key. As a query
    /// parameter it is percent-encoded to %20 and sent as part of the
    /// credential, which simply fails to authenticate.
    pub fn has_surrounding_whitespace(&self) -> bool {
        self.value.len() != self.value.trim().len()
    }

    /// Why this value could not be sent as an HTTP header, if it could not.
    ///
    /// 🔴 THE CHECK LIVES INSIDE THE TYPE so that validating a key does not
    /// require exposing it. `grep -rn expose_for_injection src/` must keep
    /// listing exactly one call, and a caller doing this check elsewhere would
    /// have made it two.
    ///
    /// The returned description names the KIND of byte and its position, never
    /// the byte itself: "a non-ASCII byte at position 12" is enough to find a
    /// smart quote pasted in from a document, and reveals nothing.
    ///
    /// An HTTP header value may carry visible ASCII plus space and tab. A key
    /// holding anything else can never be sent, so the broker must say so at
    /// startup rather than failing per request.
    pub fn header_value_fault(&self) -> Option<String> {
        for (i, b) in self.value.bytes().enumerate() {
            if b == b'\t' || (0x20..=0x7e).contains(&b) {
                continue;
            }
            let what = match b {
                b'\n' => "a newline",
                b'\r' => "a carriage return",
                0x00..=0x1f | 0x7f => "a control character",
                _ => "a non-ASCII byte",
            };
            return Some(format!("{what} at position {i} of {}", self.value.len()));
        }
        None
    }
}

/// 🔴 A KEY IS DESERIALISED STRAIGHT INTO A ZEROIZING TYPE.
///
/// Without this impl the config would land the credential in an ordinary
/// `String` first, and that intermediate allocation would be freed without
/// being overwritten -- leaving a copy in the heap that `gcore` would find,
/// which is exactly what Stage 5 test 3 looks for. Going directly to `Secret`
/// means there is one allocation and it wipes on drop.
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret::new)
    }
}

/// 🔴 Redacted, always. A panic inside a request handler prints its payload;
/// without this, a `{:?}` on anything holding a Secret would put the key in
/// the journal.
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_the_value() {
        let s = Secret::new("tvly-dev-SHOULD-NOT-APPEAR".to_string());
        let rendered = format!("{:?}", s);
        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains("tvly"));
    }

    #[test]
    fn a_sendable_key_reports_no_fault() {
        assert_eq!(Secret::new("sk-Abc123_-.~+/=".to_string()).header_value_fault(), None);
        assert_eq!(Secret::new("with a space".to_string()).header_value_fault(), None);
    }

    #[test]
    fn an_unsendable_key_is_described_without_revealing_it() {
        // Everything a paste from a document or a stray line ending produces.
        for (bad, expect) in [
            ("abc\ndef", "a newline"),
            ("abc\rdef", "a carriage return"),
            ("abc\u{0}def", "a control character"),
            ("abc\u{201c}def", "a non-ASCII byte"),
            ("abc\u{200b}def", "a non-ASCII byte"),
        ] {
            let f = Secret::new(bad.to_string()).header_value_fault().expect("must be refused");
            assert!(f.contains(expect), "{bad:?} -> {f}");
            assert!(!f.contains("abc") && !f.contains("def"), "the fault must not quote the key: {f}");
        }
    }

    #[test]
    fn surrounding_whitespace_is_detected_in_either_direction() {
        assert!(Secret::new(" sk-abc".to_string()).has_surrounding_whitespace());
        assert!(Secret::new("sk-abc ".to_string()).has_surrounding_whitespace());
        assert!(Secret::new("sk-abc\t".to_string()).has_surrounding_whitespace());
        assert!(!Secret::new("sk-abc".to_string()).has_surrounding_whitespace());
        assert!(!Secret::new("sk ab".to_string()).has_surrounding_whitespace(), "interior space is not padding");
    }

    #[test]
    fn exposes_exactly_what_was_stored() {
        let s = Secret::new("abc123".to_string());
        assert_eq!(s.expose_for_injection(), "abc123");
    }

}
