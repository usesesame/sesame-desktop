const APPROVAL_FOCUS_DELAY: Duration = Duration::from_millis(750);
const APPROVAL_TOO_SOON: &str = "approvalTooSoon";
const APPROVAL_TOO_SOON_MESSAGE: &str =
    "Wait a moment after Sesame comes forward, then approve again.";

trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

struct FocusDelay {
    clock: Arc<dyn Clock>,
    focused_since: Option<Instant>,
    shown_at: Option<Instant>,
}

impl Default for FocusDelay {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl FocusDelay {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            focused_since: None,
            shown_at: None,
        }
    }

    fn window_focus_changed(&mut self, focused: bool) {
        if !focused {
            self.focused_since = None;
        } else if self.focused_since.is_none() {
            self.focused_since = Some(self.clock.now());
        }
    }

    fn approval_shown(&mut self) {
        self.shown_at = Some(self.clock.now());
    }

    fn remaining(&self) -> Duration {
        let Some(focused_since) = self.focused_since else {
            return APPROVAL_FOCUS_DELAY;
        };
        let counted_from = self
            .shown_at
            .map_or(focused_since, |shown_at| shown_at.max(focused_since));
        APPROVAL_FOCUS_DELAY
            .saturating_sub(self.clock.now().saturating_duration_since(counted_from))
    }

    fn is_ready(&self) -> bool {
        self.remaining().is_zero()
    }
}

#[cfg(test)]
mod focus_delay_tests {
    use super::*;
    use std::sync::Mutex;

    pub(super) struct FakeClock {
        now: Mutex<Instant>,
    }

    impl FakeClock {
        pub(super) fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
            })
        }

        pub(super) fn advance(&self, by: Duration) {
            *self.now.lock().expect("clock") += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("clock")
        }
    }

    pub(super) fn state_with_clock() -> (BrowserFillState, Arc<FakeClock>) {
        let clock = FakeClock::new();
        (BrowserFillState::with_clock(clock.clone()), clock)
    }

    pub(super) fn let_delay_pass(state: &BrowserFillState, clock: &FakeClock) {
        state.window_focus_changed(true);
        clock.advance(APPROVAL_FOCUS_DELAY);
    }

    fn delay_with_clock() -> (FocusDelay, Arc<FakeClock>) {
        let clock = FakeClock::new();
        (FocusDelay::new(clock.clone()), clock)
    }

    const JUST_UNDER: Duration = Duration::from_millis(749);

    #[test]
    fn an_unfocused_window_is_never_ready() {
        let (mut delay, clock) = delay_with_clock();
        delay.approval_shown();
        clock.advance(Duration::from_secs(60));

        assert!(!delay.is_ready());
        assert_eq!(delay.remaining(), APPROVAL_FOCUS_DELAY);
    }

    #[test]
    fn the_delay_is_not_over_until_the_full_time_has_passed_in_focus() {
        let (mut delay, clock) = delay_with_clock();
        delay.window_focus_changed(true);
        delay.approval_shown();

        clock.advance(JUST_UNDER);
        assert!(!delay.is_ready());
        clock.advance(Duration::from_millis(1));
        assert!(delay.is_ready());
    }

    #[test]
    fn losing_focus_restarts_the_delay_from_zero() {
        let (mut delay, clock) = delay_with_clock();
        delay.window_focus_changed(true);
        delay.approval_shown();
        clock.advance(JUST_UNDER);

        delay.window_focus_changed(false);
        clock.advance(Duration::from_secs(10));
        delay.window_focus_changed(true);
        clock.advance(JUST_UNDER);
        assert!(!delay.is_ready());
        clock.advance(Duration::from_millis(1));
        assert!(delay.is_ready());
    }

    #[test]
    fn time_spent_unfocused_does_not_count() {
        let (mut delay, clock) = delay_with_clock();
        delay.approval_shown();
        clock.advance(Duration::from_secs(5));
        delay.window_focus_changed(true);
        clock.advance(Duration::from_millis(200));

        assert_eq!(delay.remaining(), Duration::from_millis(550));
    }

    #[test]
    fn a_repeated_focus_event_does_not_restart_the_delay() {
        let (mut delay, clock) = delay_with_clock();
        delay.window_focus_changed(true);
        delay.approval_shown();
        clock.advance(Duration::from_millis(500));
        delay.window_focus_changed(true);
        clock.advance(Duration::from_millis(250));

        assert!(delay.is_ready());
    }

    #[test]
    fn a_new_approval_in_a_focused_window_starts_its_own_delay() {
        let (mut delay, clock) = delay_with_clock();
        delay.window_focus_changed(true);
        clock.advance(Duration::from_secs(30));
        delay.approval_shown();

        assert!(!delay.is_ready());
        clock.advance(APPROVAL_FOCUS_DELAY);
        assert!(delay.is_ready());
    }
}

#[cfg(test)]
mod approval_delay_tests {
    use super::focus_delay_tests::{let_delay_pass, state_with_clock, FakeClock};
    use super::*;

    const JUST_UNDER: Duration = Duration::from_millis(749);

    fn begin_fill(state: &BrowserFillState, request_id: &str) -> (String, Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                NormalizedOrigin::from_request("https://example.test").expect("origin"),
                7,
                ApprovalRequest::Fill {
                    candidate_ids: HashSet::from(["login-a".to_string()]),
                },
            )
            .expect("begin");
        (approval_id, receiver)
    }

    fn select(login_id: &str) -> ApprovalDecision {
        ApprovalDecision::Selected(login_id.to_string())
    }

    fn focused_state() -> (BrowserFillState, Arc<FakeClock>) {
        let (state, clock) = state_with_clock();
        state.window_focus_changed(true);
        (state, clock)
    }

    #[test]
    fn an_approval_right_after_focus_is_rejected_and_the_prompt_stays_open() {
        let (state, clock) = focused_state();
        let (approval_id, receiver) = begin_fill(&state, "request-1");
        clock.advance(JUST_UNDER);

        assert_eq!(
            state.decide(&approval_id, select("login-a")),
            Err(APPROVAL_TOO_SOON)
        );
        assert!(receiver.try_recv().is_err());

        clock.advance(Duration::from_millis(1));
        assert!(state.decide(&approval_id, select("login-a")).is_ok());
        assert!(matches!(
            receiver.try_recv(),
            Ok(ApprovalDecision::Selected(login_id)) if login_id == "login-a"
        ));
    }

    #[test]
    fn a_focus_loss_restarts_the_delay_for_a_pending_approval() {
        let (state, clock) = focused_state();
        let (approval_id, _receiver) = begin_fill(&state, "request-1");
        clock.advance(JUST_UNDER);

        state.window_focus_changed(false);
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            state.decide(&approval_id, select("login-a")),
            Err(APPROVAL_TOO_SOON)
        );

        state.window_focus_changed(true);
        clock.advance(JUST_UNDER);
        assert_eq!(
            state.decide(&approval_id, select("login-a")),
            Err(APPROVAL_TOO_SOON)
        );
        clock.advance(Duration::from_millis(1));
        assert!(state.decide(&approval_id, select("login-a")).is_ok());
    }

    #[test]
    fn an_approval_while_the_window_is_unfocused_is_rejected() {
        let (state, clock) = state_with_clock();
        let (approval_id, _receiver) = begin_fill(&state, "request-1");
        clock.advance(Duration::from_secs(20));

        assert_eq!(
            state.decide(&approval_id, select("login-a")),
            Err(APPROVAL_TOO_SOON)
        );
    }

    #[test]
    fn a_stale_approval_id_is_reported_as_expired_not_as_too_soon() {
        let (state, _clock) = focused_state();
        let (approval_id, receiver) = begin_fill(&state, "request-1");

        assert_eq!(
            state.decide("not-the-approval", select("login-a")),
            Err("approvalExpired")
        );
        assert_eq!(
            state.require_ready("not-the-approval"),
            Ok(())
        );
        assert!(receiver.try_recv().is_err());
        assert!(state.decide(&approval_id, ApprovalDecision::Denied).is_ok());
    }

    #[test]
    fn a_repeated_approval_is_rejected_after_the_first_one_is_used() {
        let (state, clock) = state_with_clock();
        let (approval_id, receiver) = begin_fill(&state, "request-1");
        let_delay_pass(&state, &clock);

        assert!(state.decide(&approval_id, select("login-a")).is_ok());
        assert!(receiver.try_recv().is_ok());
        assert_eq!(
            state.decide(&approval_id, select("login-a")),
            Err("approvalExpired")
        );
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn declining_is_allowed_at_any_time() {
        let (state, _clock) = state_with_clock();
        let (approval_id, receiver) = begin_fill(&state, "request-1");

        assert!(state.decide(&approval_id, ApprovalDecision::Denied).is_ok());
        assert!(matches!(receiver.try_recv(), Ok(ApprovalDecision::Denied)));
    }

    #[test]
    fn a_selection_that_is_not_offered_does_not_end_the_prompt_before_the_delay() {
        let (state, clock) = focused_state();
        let (approval_id, receiver) = begin_fill(&state, "request-1");
        clock.advance(JUST_UNDER);

        assert_eq!(
            state.decide(&approval_id, select("login-b")),
            Err(APPROVAL_TOO_SOON)
        );
        assert!(receiver.try_recv().is_err());
        assert_eq!(state.require_ready(&approval_id), Err(APPROVAL_TOO_SOON));
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            state.decide(&approval_id, select("login-b")),
            Err("selectionNotOffered")
        );
    }

    #[test]
    fn a_save_approval_is_checked_before_the_vault_is_written() {
        let (state, clock) = focused_state();
        let (approval_id, _receiver) = begin_fill(&state, "request-1");
        clock.advance(JUST_UNDER);

        assert_eq!(state.require_ready(&approval_id), Err(APPROVAL_TOO_SOON));
        clock.advance(Duration::from_millis(1));
        assert_eq!(state.require_ready(&approval_id), Ok(()));
        assert!(state.decide(&approval_id, ApprovalDecision::Saved).is_ok());
    }

    #[test]
    fn a_save_commit_is_not_undone_by_a_focus_loss_after_the_check() {
        let (state, clock) = focused_state();
        let (approval_id, receiver) = begin_fill(&state, "request-1");
        clock.advance(APPROVAL_FOCUS_DELAY);
        assert_eq!(state.require_ready(&approval_id), Ok(()));

        state.window_focus_changed(false);
        assert!(state.decide(&approval_id, ApprovalDecision::Saved).is_ok());
        assert!(matches!(receiver.try_recv(), Ok(ApprovalDecision::Saved)));
    }

    #[test]
    fn the_next_approval_gets_its_own_delay() {
        let (state, clock) = focused_state();
        let (first, _receiver) = begin_fill(&state, "request-1");
        clock.advance(APPROVAL_FOCUS_DELAY);
        assert!(state.decide(&first, select("login-a")).is_ok());

        let (second, _receiver) = begin_fill(&state, "request-2");
        assert_eq!(
            state.decide(&second, select("login-a")),
            Err(APPROVAL_TOO_SOON)
        );
        assert!(state.approval_wait() > Duration::ZERO);
    }

    #[test]
    fn the_reported_wait_shrinks_with_time_in_focus() {
        let (state, clock) = focused_state();
        let (_approval_id, _receiver) = begin_fill(&state, "request-1");
        clock.advance(Duration::from_millis(250));

        assert_eq!(state.approval_wait(), Duration::from_millis(500));
    }
}
