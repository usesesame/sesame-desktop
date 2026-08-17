//! The Sesame Sync coordinator: one transfer at a time, bounded retry with jitter, terminal halt states.
//! A conflict is never resolved here: a person chooses the winner.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    Revoked,
    NotEntitled,
    Incompatible,
    Conflict { server_revision: i64 },
    Locked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Working,
    Retrying { attempt: u32 },
    Halted(Halt),
}

/// Secret-free and path-free: this crosses the IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub pending: bool,
    pub last_success_revision: Option<i64>,
    pub consecutive_failures: u32,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            pending: false,
            last_success_revision: None,
            consecutive_failures: 0,
        }
    }
}

/// Recorded, not branched on: every trigger means the same thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    VaultSaved,
    Unlocked,
    Reconnected,
    Resumed,
    Started,
    Periodic,
    Requested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Uploaded { revision: i64 },
    Downloaded { revision: i64 },
    AlreadyCurrent,
    Transient,
    Halt(Halt),
}

/// Gives up rather than hiding a failing device behind a spinner.
pub const MAX_ATTEMPTS: u32 = 6;

pub const BASE_BACKOFF: Duration = Duration::from_secs(2);
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// One save per keystroke must become one upload, not forty.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Coordinator {
    inner: Arc<Mutex<State>>,
}

struct State {
    status: Status,
    running: bool,
    /// One flag, not a queue: one agreement covers every request that arrived while running.
    follow_up: bool,
    last_request: Option<Instant>,
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                status: Status::default(),
                running: false,
                follow_up: false,
                last_request: None,
            })),
        }
    }

    pub fn status(&self) -> Status {
        match self.inner.lock() {
            Ok(state) => state.status.clone(),
            // A poisoned lock is reported as a halt, not a lie about idling.
            Err(_) => Status {
                phase: Phase::Halted(Halt::Locked),
                ..Status::default()
            },
        }
    }

    pub fn request(&self, trigger: Trigger, now: Instant) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if let Phase::Halted(_) = state.status.phase {
            // A halt is final until something clears it.
            return false;
        }
        state.status.pending = true;
        state.last_request = Some(now);
        if state.running {
            state.follow_up = true;
            return false;
        }
        // A vault save coalesces; everything else runs immediately.
        if trigger == Trigger::VaultSaved {
            return false;
        }
        state.running = true;
        state.status.phase = Phase::Working;
        true
    }

    pub fn coalesce_elapsed(&self, now: Instant) -> bool {
        let Ok(state) = self.inner.lock() else {
            return false;
        };
        if state.running || !state.status.pending {
            return false;
        }
        matches!(state.last_request, Some(at) if now.duration_since(at) >= COALESCE_WINDOW)
    }

    pub fn begin(&self) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if state.running || matches!(state.status.phase, Phase::Halted(_)) {
            return false;
        }
        state.running = true;
        state.status.phase = Phase::Working;
        true
    }

    pub fn finish(&self, outcome: Outcome) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.running = false;
        match outcome {
            Outcome::Uploaded { revision } | Outcome::Downloaded { revision } => {
                state.status.last_success_revision = Some(revision);
                state.status.consecutive_failures = 0;
                state.status.phase = Phase::Idle;
                state.status.pending = state.follow_up;
                let again = state.follow_up;
                state.follow_up = false;
                again
            }
            Outcome::AlreadyCurrent => {
                state.status.consecutive_failures = 0;
                state.status.phase = Phase::Idle;
                state.status.pending = state.follow_up;
                let again = state.follow_up;
                state.follow_up = false;
                again
            }
            Outcome::Halt(halt) => {
                // Terminal: retrying a final answer hammers the service.
                state.status.phase = Phase::Halted(halt);
                state.status.pending = false;
                state.follow_up = false;
                false
            }
            Outcome::Transient => {
                state.status.consecutive_failures += 1;
                if state.status.consecutive_failures >= MAX_ATTEMPTS {
                    state.status.phase = Phase::Idle;
                    state.status.pending = false;
                    state.follow_up = false;
                    return false;
                }
                state.status.phase = Phase::Retrying {
                    attempt: state.status.consecutive_failures,
                };
                state.status.pending = true;
                true
            }
        }
    }

    pub fn resume(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.status = Status {
                last_success_revision: state.status.last_success_revision,
                ..Status::default()
            };
            state.running = false;
            state.follow_up = false;
        }
    }
}

/// Capped and jittered so reconnected devices do not retry in lockstep.
pub fn backoff(attempt: u32) -> Duration {
    let exponent = attempt.min(8);
    let base = BASE_BACKOFF.saturating_mul(1_u32 << exponent);
    let base = base.min(MAX_BACKOFF);
    let mut jitter = [0_u8; 2];
    crate::vault::util::fill_random(&mut jitter);
    let spread = u16::from_be_bytes(jitter) as u64 % (base.as_millis() as u64 / 2 + 1);
    base + Duration::from_millis(spread)
}
