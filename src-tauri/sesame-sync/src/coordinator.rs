use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    Revoked,
    NotEntitled,
    Incompatible,
    FloorDamaged,
    Fork,
    Conflict { server_revision: i64 },
    NeedsNewKey,
    Locked,
    TooLarge { vault_bytes: u64, limit_bytes: u64 },
    LinkEnded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Working,
    Retrying { attempt: u32 },
    Waiting { retry_after_secs: u64 },
    GaveUp,
    Paused,
    Halted(Halt),
}

/// Secret-free and path-free: this crosses the IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    pub pending: bool,
    pub last_success_revision: Option<i64>,
    pub consecutive_failures: u32,
    pub downloads_applied: u32,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            pending: false,
            last_success_revision: None,
            consecutive_failures: 0,
            downloads_applied: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Uploaded { revision: i64 },
    Downloaded { revision: i64 },
    AlreadyCurrent,
    Transient,
    Busy { retry_after_secs: u64 },
    Halt(Halt),
}

/// Gives up rather than hiding a failing device behind a spinner.
pub const MAX_ATTEMPTS: u32 = 6;

pub struct ManualRun {
    inner: Arc<Mutex<State>>,
}

impl Drop for ManualRun {
    fn drop(&mut self) {
        if let Ok(mut state) = self.inner.lock() {
            state.running = false;
        }
    }
}

#[derive(Clone)]
pub struct Coordinator {
    inner: Arc<Mutex<State>>,
}

struct State {
    status: Status,
    running: bool,
    wait_until: Option<Instant>,
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
                wait_until: None,
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
        self.begin_at(Instant::now())
    }

    pub fn begin_at(&self, now: Instant) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        if state.running || matches!(state.status.phase, Phase::Halted(_)) {
            return false;
        }
        if state.wait_until.is_some_and(|until| now < until) {
            return false;
        }
        state.wait_until = None;
        state.running = true;
        state.status.phase = Phase::Working;
        true
    }

    /// A push, pull or conflict resolution a person asked for. It holds the same lock as a
    /// scheduled run, so the two never overlap, and it leaves the phase alone.
    pub fn begin_manual(&self) -> Option<ManualRun> {
        let mut state = self.inner.lock().ok()?;
        if state.running {
            return None;
        }
        state.running = true;
        Some(ManualRun {
            inner: Arc::clone(&self.inner),
        })
    }

    /// A person has fixed what stopped Sync, such as resolving a conflict or turning Sync off.
    pub fn resume(&self) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        if matches!(state.status.phase, Phase::Halted(_)) {
            state.status.phase = Phase::Idle;
            state.status.consecutive_failures = 0;
            state.status.pending = false;
        }
    }

    /// Taking the new vault key is the only thing that ends a wait for it, and it ends no other stop.
    pub fn key_taken(&self) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        if state.status.phase == Phase::Halted(Halt::NeedsNewKey) {
            state.status.phase = Phase::Idle;
            state.status.consecutive_failures = 0;
            state.status.pending = false;
        }
    }

    /// A person pressed Sync now, which is enough to try again after a stop they can fix elsewhere.
    pub fn retry_after_user_action(&self) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        if matches!(
            state.status.phase,
            Phase::Halted(Halt::NotEntitled)
                | Phase::Halted(Halt::Incompatible)
                | Phase::Halted(Halt::FloorDamaged)
                | Phase::Halted(Halt::LinkEnded)
        ) {
            state.status.phase = Phase::Idle;
            state.status.pending = false;
        }
        state.wait_until = None;
    }

    pub fn halted_size(&self) -> Option<u64> {
        let state = self.inner.lock().ok()?;
        match state.status.phase {
            Phase::Halted(Halt::TooLarge { vault_bytes, .. }) => Some(vault_bytes),
            _ => None,
        }
    }

    pub fn vault_resized(&self, vault_bytes: u64) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        if matches!(
            state.status.phase,
            Phase::Halted(Halt::TooLarge { vault_bytes: halted, .. }) if halted != vault_bytes
        ) {
            state.status.phase = Phase::Idle;
            state.status.pending = false;
        }
    }

    pub fn finish(&self, outcome: Outcome) -> bool {
        self.finish_at(outcome, Instant::now())
    }

    pub fn finish_at(&self, outcome: Outcome, now: Instant) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        state.running = false;
        state.wait_until = None;
        if matches!(outcome, Outcome::Downloaded { .. }) {
            state.status.downloads_applied = state.status.downloads_applied.saturating_add(1);
        }
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
                state.status.phase = Phase::Paused;
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
            Outcome::Busy { retry_after_secs } => {
                state.wait_until = now.checked_add(Duration::from_secs(retry_after_secs));
                state.status.phase = Phase::Waiting { retry_after_secs };
                state.status.pending = true;
                state.follow_up = false;
                false
            }
            Outcome::Transient => {
                state.status.consecutive_failures += 1;
                if state.status.consecutive_failures >= MAX_ATTEMPTS {
                    state.status.phase = Phase::GaveUp;
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
    fn only_a_download_counts_as_a_change_applied_to_this_vault() {
        let coordinator = Coordinator::new();
        for outcome in [
            Outcome::Uploaded { revision: 2 },
            Outcome::AlreadyCurrent,
            Outcome::Transient,
            Outcome::Halt(Halt::Conflict { server_revision: 3 }),
        ] {
            coordinator.resume();
            assert!(coordinator.begin());
            coordinator.finish(outcome);
            assert_eq!(coordinator.status().downloads_applied, 0);
        }
        coordinator.resume();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Downloaded { revision: 4 });
        assert_eq!(coordinator.status().downloads_applied, 1);
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Downloaded { revision: 5 });
        assert_eq!(coordinator.status().downloads_applied, 2);
    }

    #[test]
    fn taking_the_new_key_ends_the_wait_for_it_and_no_other_stop() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::NeedsNewKey));
        assert_eq!(coordinator.status().phase, Phase::Halted(Halt::NeedsNewKey));
        assert!(!coordinator.begin());
        coordinator.key_taken();
        assert_eq!(coordinator.status().phase, Phase::Idle);
        assert!(coordinator.begin());

        coordinator.finish(Outcome::Halt(Halt::Revoked));
        coordinator.key_taken();
        assert_eq!(coordinator.status().phase, Phase::Halted(Halt::Revoked));
        coordinator.resume();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Conflict { server_revision: 4 }));
        coordinator.key_taken();
        assert_eq!(
            coordinator.status().phase,
            Phase::Halted(Halt::Conflict { server_revision: 4 })
        );
    }

    #[test]
    fn a_locked_vault_pauses_one_run_and_does_not_stop_sync_for_good() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Locked));
        assert_eq!(coordinator.status().phase, Phase::Paused);
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
        assert_eq!(coordinator.status().phase, Phase::GaveUp);
        assert_eq!(coordinator.status().consecutive_failures, MAX_ATTEMPTS);
    }

    #[test]
    fn giving_up_still_lets_the_next_scheduled_run_try_again_and_a_success_clears_it() {
        let coordinator = Coordinator::new();
        for _ in 0..MAX_ATTEMPTS {
            assert!(coordinator.begin());
            coordinator.finish(Outcome::Transient);
        }
        assert_eq!(coordinator.status().phase, Phase::GaveUp);

        assert!(coordinator.begin());
        coordinator.finish(Outcome::Uploaded { revision: 4 });

        let status = coordinator.status();
        assert_eq!(status.phase, Phase::Idle);
        assert_eq!(status.consecutive_failures, 0);
        assert_eq!(status.last_success_revision, Some(4));
    }

    #[test]
    fn a_locked_pause_does_not_reset_the_failure_count() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Transient);
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Locked));
        assert_eq!(coordinator.status().consecutive_failures, 1);
    }

    #[test]
    fn resuming_clears_any_halt_and_does_nothing_otherwise() {
        for halt in [
            Halt::Revoked,
            Halt::NotEntitled,
            Halt::Incompatible,
            Halt::FloorDamaged,
            Halt::Fork,
            Halt::Conflict { server_revision: 3 },
        ] {
            let coordinator = Coordinator::new();
            assert!(coordinator.begin());
            coordinator.finish(Outcome::Halt(halt));
            coordinator.resume();
            assert_eq!(coordinator.status().phase, Phase::Idle);
            assert!(coordinator.begin());
        }

        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Transient);
        coordinator.resume();
        assert_eq!(coordinator.status().phase, Phase::Retrying { attempt: 1 });
    }

    #[test]
    fn pressing_sync_now_retries_only_the_stops_a_person_can_fix_elsewhere() {
        for (halt, retried) in [
            (Halt::NotEntitled, true),
            (Halt::Incompatible, true),
            (Halt::FloorDamaged, true),
            (Halt::Revoked, false),
            (Halt::Fork, false),
            (Halt::Conflict { server_revision: 3 }, false),
        ] {
            let coordinator = Coordinator::new();
            assert!(coordinator.begin());
            coordinator.finish(Outcome::Halt(halt));
            coordinator.retry_after_user_action();
            assert_eq!(coordinator.begin(), retried);
        }
    }

    #[test]
    fn a_busy_server_never_counts_toward_giving_up() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Transient);
        let mut now = Instant::now();
        for _ in 0..(MAX_ATTEMPTS * 3) {
            assert!(coordinator.begin_at(now));
            coordinator.finish_at(
                Outcome::Busy {
                    retry_after_secs: 5,
                },
                now,
            );
            now += Duration::from_secs(5);
            let status = coordinator.status();
            assert_eq!(
                status.phase,
                Phase::Waiting {
                    retry_after_secs: 5
                }
            );
            assert_eq!(status.consecutive_failures, 1);
            assert!(status.pending);
        }
        assert!(coordinator.begin_at(now));
        coordinator.finish(Outcome::AlreadyCurrent);
        assert_eq!(coordinator.status().phase, Phase::Idle);
        assert_eq!(coordinator.status().consecutive_failures, 0);
    }

    #[test]
    fn a_busy_wait_holds_from_the_answer_until_it_ends_for_every_scheduled_run() {
        let coordinator = Coordinator::new();
        let started = Instant::now();
        let answered = started + Duration::from_secs(20);
        assert!(coordinator.begin_at(started));
        coordinator.finish_at(
            Outcome::Busy {
                retry_after_secs: 30,
            },
            answered,
        );

        assert!(!coordinator.begin_at(started + Duration::from_secs(31)));
        assert!(!coordinator.begin_at(answered + Duration::from_secs(29)));
        assert!(coordinator.begin_at(answered + Duration::from_secs(30)));
        coordinator.finish(Outcome::AlreadyCurrent);
        assert!(coordinator.begin());
    }

    #[test]
    fn pressing_sync_now_ends_a_busy_wait() {
        let coordinator = Coordinator::new();
        let now = Instant::now();
        assert!(coordinator.begin_at(now));
        coordinator.finish_at(
            Outcome::Busy {
                retry_after_secs: 60,
            },
            now,
        );
        assert!(!coordinator.begin_at(now + Duration::from_secs(1)));

        coordinator.retry_after_user_action();

        assert!(coordinator.begin_at(now + Duration::from_secs(1)));
    }

    #[test]
    fn a_vault_too_large_to_sync_stops_until_its_size_changes() {
        let coordinator = Coordinator::new();
        let halt = Halt::TooLarge {
            vault_bytes: 12_000_000,
            limit_bytes: 10_485_760,
        };
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(halt.clone()));
        assert_eq!(coordinator.halted_size(), Some(12_000_000));
        assert!(!coordinator.begin());

        coordinator.retry_after_user_action();
        coordinator.vault_resized(12_000_000);
        assert_eq!(coordinator.status().phase, Phase::Halted(halt));
        assert!(!coordinator.begin());

        coordinator.vault_resized(9_000_000);
        assert_eq!(coordinator.status().phase, Phase::Idle);
        assert_eq!(coordinator.halted_size(), None);
        assert!(coordinator.begin());
    }

    #[test]
    fn a_new_size_only_ends_a_size_stop() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Fork));
        coordinator.vault_resized(1);
        assert_eq!(coordinator.status().phase, Phase::Halted(Halt::Fork));
        assert_eq!(coordinator.halted_size(), None);
    }

    #[test]
    fn an_ended_desktop_link_stops_sync_until_a_person_tries_again() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::LinkEnded));
        assert!(!coordinator.begin());
        coordinator.retry_after_user_action();
        assert!(coordinator.begin());
    }

    #[test]
    fn a_manual_run_and_a_scheduled_run_never_overlap() {
        let coordinator = Coordinator::new();
        let manual = coordinator.begin_manual().expect("idle coordinator");
        assert!(!coordinator.begin());
        assert!(coordinator.begin_manual().is_none());
        drop(manual);
        assert!(coordinator.begin());
        assert!(coordinator.begin_manual().is_none());
    }

    #[test]
    fn a_manual_run_leaves_the_phase_alone_and_runs_even_while_halted() {
        let coordinator = Coordinator::new();
        assert!(coordinator.begin());
        coordinator.finish(Outcome::Halt(Halt::Fork));
        let manual = coordinator
            .begin_manual()
            .expect("a halt does not block a manual run");
        assert_eq!(coordinator.status().phase, Phase::Halted(Halt::Fork));
        drop(manual);
        assert_eq!(coordinator.status().phase, Phase::Halted(Halt::Fork));
        assert!(coordinator.begin_manual().is_some());
    }

    #[test]
    fn a_manual_run_that_is_dropped_by_an_error_releases_the_lock() {
        let coordinator = Coordinator::new();
        let attempt = || -> Result<(), ()> {
            let _run = coordinator.begin_manual().ok_or(())?;
            Err(())
        };
        assert!(attempt().is_err());
        assert!(coordinator.begin_manual().is_some());
    }
}
