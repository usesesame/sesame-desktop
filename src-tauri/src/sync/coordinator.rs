use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    Revoked,
    NotEntitled,
    Incompatible,
    Fork,
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

#[derive(Clone)]
pub struct Coordinator {
    inner: Arc<Mutex<State>>,
}

struct State {
    status: Status,
    running: bool,
    /// One flag, not a queue: one agreement covers every request that arrived while running.
    follow_up: bool,
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
            Outcome::Halt(Halt::Locked) => {
                state.status.phase = Phase::Idle;
                state.status.pending = false;
                state.follow_up = false;
                false
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locked_vault_pauses_one_run_and_does_not_stop_sync_for_good() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Locked));
        assert_eq!(coordinator.status().phase, Phase::Idle);
        assert!(coordinator.begin());
    }

    #[test]
    fn a_revoked_device_stays_halted_until_something_clears_it() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Revoked));
        assert_eq!(coordinator.status().phase, Phase::Halted(Halt::Revoked));
        assert!(!coordinator.begin());
    }

    #[test]
    fn a_transient_failure_retries_and_gives_up_after_the_attempt_limit() {
        let coordinator = Coordinator::new();
        for attempt in 1..MAX_ATTEMPTS {
            assert!(coordinator.begin());
            assert!(coordinator.finish(Outcome::Transient));
            assert_eq!(coordinator.status().phase, Phase::Retrying { attempt });
        }
        assert!(coordinator.begin());
        assert!(!coordinator.finish(Outcome::Transient));
        assert_eq!(coordinator.status().phase, Phase::Idle);
    }
}
