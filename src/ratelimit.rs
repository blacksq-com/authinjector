//! Per-caller, per-upstream rate limiting (PROTOCOL.md §4, `rate.per_minute`).
//!
//! 🔴 THE KEY IS (CALLER, UPSTREAM), NOT UPSTREAM ALONE.
//!
//! A limit shared across callers lets one caller exhaust another's budget,
//! which turns a rate limit into a denial-of-service lever between processes
//! on the same box. It also makes the audit log lie: spend attributed to an
//! upstream with no way to attribute it to who spent it.
//!
//! Same reasoning as `callers[]` in the policy. The threat model is not only
//! an outsider; it is a caller on this machine behaving badly, very much
//! including an agent looping on a retry it should not be making.
//!
//! Sliding window over real instants rather than a fixed per-minute bucket: a
//! fixed bucket permits 2x the limit across a boundary (the last moment of one
//! minute plus the first of the next), and a retry loop finds that boundary
//! reliably.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct RateLimiter {
    hits: Mutex<HashMap<(String, String), VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when this call is within budget, recording it. False when it is not.
    ///
    /// 🔴 A REFUSED CALL IS NOT RECORDED. Being over the limit must not extend
    /// the period you stay over it; otherwise a caller that keeps retrying can
    /// never recover, which is indistinguishable from a broken broker.
    pub fn check(&self, caller: &str, upstream: &str, per_minute: u32) -> bool {
        if per_minute == 0 {
            return false;
        }
        let now = Instant::now();
        let mut map = match self.hits.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(), // a poisoned lock must not disable limiting
        };
        let q = map.entry((caller.to_string(), upstream.to_string())).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) >= WINDOW) {
            q.pop_front();
        }
        if q.len() as u32 >= per_minute {
            return false;
        }
        q.push_back(now);
        true
    }

    /// Whole seconds until the oldest hit leaves the window, for `Retry-After`.
    pub fn retry_after(&self, caller: &str, upstream: &str) -> u64 {
        let now = Instant::now();
        let map = match self.hits.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        match map.get(&(caller.to_string(), upstream.to_string())).and_then(|q| q.front()) {
            Some(oldest) => {
                let elapsed = now.duration_since(*oldest);
                WINDOW.saturating_sub(elapsed).as_secs().max(1)
            }
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let r = RateLimiter::new();
        for i in 0..5 {
            assert!(r.check("alice", "tavily", 5), "call {i} should be allowed");
        }
        assert!(!r.check("alice", "tavily", 5), "the sixth call must be refused");
    }

    #[test]
    fn one_caller_cannot_exhaust_anothers_budget() {
        let r = RateLimiter::new();
        for _ in 0..5 {
            assert!(r.check("greedy", "tavily", 5));
        }
        assert!(!r.check("greedy", "tavily", 5));
        assert!(r.check("quiet", "tavily", 5), "a different caller has its own budget");
    }

    #[test]
    fn budgets_are_per_upstream_too() {
        let r = RateLimiter::new();
        for _ in 0..2 {
            assert!(r.check("alice", "tavily", 2));
        }
        assert!(!r.check("alice", "tavily", 2));
        assert!(r.check("alice", "psi", 2), "a different upstream has its own budget");
    }

    #[test]
    fn refused_calls_do_not_extend_the_lockout() {
        let r = RateLimiter::new();
        assert!(r.check("alice", "tavily", 1));
        for _ in 0..50 {
            assert!(!r.check("alice", "tavily", 1));
        }
        // One hit in the window, not fifty-one: a retry storm must not push
        // recovery further away.
        assert!(r.retry_after("alice", "tavily") <= 60);
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        let r = RateLimiter::new();
        assert!(!r.check("alice", "tavily", 0));
    }

    #[test]
    fn retry_after_is_zero_when_nothing_has_been_used() {
        let r = RateLimiter::new();
        assert_eq!(r.retry_after("alice", "tavily"), 0);
    }
}
