use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Six digits is a million values: wrong guesses earn an escalating cooldown.
pub const PIN_FAILURES_BEFORE_LOCKOUT: u32 = 5;
const PIN_BASE_COOLDOWN: Duration = Duration::from_secs(15);
const PIN_MAX_COOLDOWN: Duration = Duration::from_secs(300);

/// DPAPI-protected on disk: another process cannot lower the count or shorten the cooldown.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersistedPinThrottle {
    pub failures: u32,
    pub locked_until_unix_ms: Option<u64>,
}

#[derive(Default)]
pub struct PinAttemptGuard {
    state: PersistedPinThrottle,
}

impl PinAttemptGuard {
    pub fn from_persisted(state: PersistedPinThrottle) -> Self {
        Self { state }
    }

    pub fn persisted(&self) -> PersistedPinThrottle {
        self.state.clone()
    }

    /// Error carries whole seconds remaining, for a specific wait message.
    pub fn check(&self) -> Result<(), u64> {
        self.check_at(unix_time_ms())
    }

    pub fn check_at(&self, now_ms: u64) -> Result<(), u64> {
        match self.state.locked_until_unix_ms {
            Some(until) if until > now_ms => Err((until - now_ms).div_ceil(1_000)),
            _ => Ok(()),
        }
    }

    pub fn record_failure(&mut self) {
        self.record_failure_at(unix_time_ms())
    }

    pub fn record_failure_at(&mut self, now_ms: u64) {
        self.state.failures = self.state.failures.saturating_add(1);
        if self.state.failures >= PIN_FAILURES_BEFORE_LOCKOUT {
            let cooldown_ms = self.cooldown().as_millis().try_into().unwrap_or(u64::MAX);
            self.state.locked_until_unix_ms = Some(now_ms.saturating_add(cooldown_ms));
        }
    }

    pub fn record_success(&mut self) {
        self.state = PersistedPinThrottle::default();
    }

    fn cooldown(&self) -> Duration {
        let over_threshold = self.state.failures - PIN_FAILURES_BEFORE_LOCKOUT;
        let factor = 1_u32 << over_threshold.min(5);
        (PIN_BASE_COOLDOWN * factor).min(PIN_MAX_COOLDOWN)
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
