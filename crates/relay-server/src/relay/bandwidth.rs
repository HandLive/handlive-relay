//! Per-pair bandwidth limit (`RELAY_RATE_LIMIT`: 2 MiB/s per pair, CONN-03
//! API 6 logic 2). Over the limit the relay delays reading the sender's
//! socket instead of dropping frames.
//!
//! A token bucket that may go into debt: a frame always passes, and the
//! debt it leaves is the time the connection waits before reading again.

use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    /// A full bucket: `rate` bytes per second, bursts of one second.
    pub fn new(rate_bytes_per_sec: u64, now: Instant) -> Self {
        let rate = rate_bytes_per_sec.max(1) as f64;
        Self {
            rate,
            capacity: rate,
            tokens: rate,
            updated: now,
        }
    }

    /// Take `cost` bytes; returns how long to wait before the next read.
    pub fn take(&mut self, cost: usize, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.updated = now;
        self.tokens -= cost as f64;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}
