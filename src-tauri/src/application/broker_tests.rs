use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::browser_fill::{
    ApprovalDecision, BrowserFillRequestEvent, NormalizedOrigin, SaveKind, APPROVAL_TOO_SOON,
};
use super::browser_fill_broker::{
    ApprovalEvent, ApprovalRequest, BrowserFillState, Clock, FocusDelay, ACTIVATE_MIN_INTERVAL,
    APPROVAL_FOCUS_DELAY, APPROVAL_TIMEOUT,
};
use super::logins::reveal_login_secret_in_state;
use crate::commands::test_support::TestVault;
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};

pub(crate) use focus_delay_tests::{let_delay_pass, state_with_clock, FakeClock};

#[cfg(test)]
mod approval_tests {
    use super::*;

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("origin")
    }

    fn ids(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn begin_fill(
        state: &BrowserFillState,
        request_id: &str,
        epoch: u64,
    ) -> (String, std::sync::mpsc::Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
                epoch,
                ApprovalRequest::Fill {
                    candidate_ids: ids(&["login-a"]),
                },
            )
            .expect("begin");
        (approval_id, receiver)
    }

    fn begin_card(
        state: &BrowserFillState,
        request_id: &str,
    ) -> (String, std::sync::mpsc::Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://checkout.example.test"),
                7,
                ApprovalRequest::Card {
                    candidate_ids: ids(&["card-a"]),
                },
            )
            .expect("begin card");
        (approval_id, receiver)
    }

    #[test]
    fn a_card_approval_is_consumed_and_cannot_be_replayed() {
        let (state, clock) = state_with_clock();
        let (approval_id, receiver) = begin_card(&state, "card-request-1");
        let_delay_pass(&state, &clock);

        state
            .decide(
                &approval_id,
                ApprovalDecision::Selected("card-a".to_string()),
            )
            .expect("approve card");
        assert!(
            matches!(receiver.recv(), Ok(ApprovalDecision::Selected(card_id)) if card_id == "card-a")
        );
        assert!(state.pending_card_request().is_none());
        assert!(matches!(
            state.begin(
                "card-request-1",
                origin("https://checkout.example.test"),
                7,
                ApprovalRequest::Card {
                    candidate_ids: ids(&["card-a"]),
                },
            ),
            Err("staleRequest")
        ));
    }

    #[test]
    fn a_card_not_offered_for_approval_is_never_released() {
        let (state, clock) = state_with_clock();
        let (approval_id, receiver) = begin_card(&state, "card-request-2");
        let_delay_pass(&state, &clock);

        assert_eq!(
            state.decide(
                &approval_id,
                ApprovalDecision::Selected("card-b".to_string()),
            ),
            Err("selectionNotOffered")
        );
        assert!(matches!(
            receiver.recv(),
            Ok(ApprovalDecision::InvalidSelection)
        ));
        assert!(state.pending_card_request().is_none());
    }

    #[test]
    fn a_second_prompt_is_refused_while_one_waits() {
        let state = BrowserFillState::default();
        let (_approval_id, _receiver) = begin_fill(&state, "req-1", 7);

        assert!(matches!(
            state.begin(
                "req-2",
                origin("https://example.test"),
                7,
                ApprovalRequest::Save {
                    kind: SaveKind::New,
                    title: "Fictional".to_string(),
                    username: String::new(),
                    password: zeroize::Zeroizing::new(String::new()),
                    candidates: Vec::new(),
                },
            ),
            Err("approvalUnavailable")
        ));
        assert!(matches!(
            state.begin(
                "req-1",
                origin("https://example.test"),
                7,
                ApprovalRequest::Card {
                    candidate_ids: ids(&["card-a"]),
                },
            ),
            Err("staleRequest")
        ));
    }

    #[test]
    fn a_stale_or_replayed_decision_is_refused() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);

        assert_eq!(
            state.decide("not-the-approval", ApprovalDecision::Denied),
            Err("approvalExpired")
        );
        assert!(state.decide(&approval_id, ApprovalDecision::Denied).is_ok());
        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied),
            Err("approvalExpired")
        );
    }

    #[test]
    fn a_decision_for_a_different_approval_id_is_refused_and_leaves_the_binding() {
        let (state, clock) = state_with_clock();
        let (approval_id, receiver) = begin_fill(&state, "req-1", 7);
        let_delay_pass(&state, &clock);

        assert_eq!(
            state.decide(
                "different-approval",
                ApprovalDecision::Selected("login-a".to_string()),
            ),
            Err("approvalExpired")
        );
        assert!(state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 7));
        assert!(receiver.try_recv().is_err());

        assert!(state.decide(&approval_id, ApprovalDecision::Denied).is_ok());
        assert!(matches!(receiver.try_recv(), Ok(ApprovalDecision::Denied)));
    }

    #[test]
    fn an_expired_approval_refuses_every_step() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);
        state.expire_pending();

        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Denied),
            Err("approvalExpired")
        );
        assert!(state.save_payload_if_bound(&approval_id).is_none());
        assert!(state.pending_fill_request().is_none());
    }

    #[test]
    fn an_expired_save_approval_returns_no_payload() {
        let state = BrowserFillState::default();
        let (approval_id, _, _receiver) = state
            .begin(
                "save-1",
                origin("https://example.test"),
                7,
                ApprovalRequest::Save {
                    kind: SaveKind::New,
                    title: "Fictional".to_string(),
                    username: "casey".to_string(),
                    password: Zeroizing::new("fictional-secret".to_string()),
                    candidates: Vec::new(),
                },
            )
            .expect("begin save");
        state.expire_pending();

        assert!(state.save_payload_if_bound(&approval_id).is_none());
        assert!(state.pending_save_request().is_none());
        assert_eq!(
            state.decide(&approval_id, ApprovalDecision::Saved),
            Err("approvalExpired")
        );
    }

    #[test]
    fn cancelling_wakes_the_waiter_and_clears_the_binding() {
        let state = BrowserFillState::default();
        let (approval_id, receiver) = begin_fill(&state, "req-1", 7);

        state.cancel_pending();

        assert!(matches!(receiver.recv(), Ok(ApprovalDecision::Denied)));
        assert!(!state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 7));
    }

    #[test]
    fn a_binding_requires_the_same_request_origin_and_epoch() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);

        assert!(state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 7));
        assert!(!state.is_bound(&approval_id, "req-2", &origin("https://example.test"), 7));
        assert!(!state.is_bound(&approval_id, "req-1", &origin("https://other.test"), 7));
        assert!(!state.is_bound(&approval_id, "req-1", &origin("https://example.test"), 8));
    }

    #[test]
    fn a_save_payload_is_only_returned_for_its_own_pending_save() {
        let state = BrowserFillState::default();
        let (approval_id, _, _receiver) = state
            .begin(
                "save-1",
                origin("https://example.test"),
                7,
                ApprovalRequest::Save {
                    kind: SaveKind::Update,
                    title: "Fictional".to_string(),
                    username: "casey".to_string(),
                    password: zeroize::Zeroizing::new("fictional-secret".to_string()),
                    candidates: Vec::new(),
                },
            )
            .expect("begin save");

        let payload = state.save_payload_if_bound(&approval_id).expect("payload");
        assert_eq!(payload.password.as_str(), "fictional-secret");
        assert_eq!(payload.kind, SaveKind::Update);
        assert!(state.save_payload_if_bound("not-the-approval").is_none());

        state
            .decide(&approval_id, ApprovalDecision::Saved)
            .expect("decide");
        assert!(state.save_payload_if_bound(&approval_id).is_none());
    }

    #[test]
    fn a_published_prompt_is_readable_until_it_is_decided() {
        let state = BrowserFillState::default();
        let (approval_id, _receiver) = begin_fill(&state, "req-1", 7);
        assert!(state.pending_fill_request().is_none());

        let event = BrowserFillRequestEvent {
            approval_id: approval_id.clone(),
            origin: "https://example.test".to_string(),
            hostname: "example.test".to_string(),
            candidates: Vec::new(),
            expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
            expires_at_unix_ms: 0,
        };
        state
            .publish(&approval_id, ApprovalEvent::Fill(event))
            .expect("publish");
        assert!(state.pending_fill_request().is_some());
        assert!(state.pending_save_request().is_none());

        state
            .decide(&approval_id, ApprovalDecision::Denied)
            .expect("decide");
        assert!(state.pending_fill_request().is_none());
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;

    #[test]
    fn activation_raises_are_rate_limited_to_one_per_interval() {
        let state = BrowserFillState::default();
        let now = Instant::now();

        assert!(state.note_activation(now));
        assert!(!state.note_activation(now));
        assert!(!state.note_activation(now + ACTIVATE_MIN_INTERVAL - Duration::from_millis(1)));
        assert!(state.note_activation(now + ACTIVATE_MIN_INTERVAL));
    }
}

#[cfg(test)]
mod focus_delay_tests {
    use super::*;

    pub(crate) struct FakeClock {
        now: Mutex<Instant>,
    }

    impl FakeClock {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
            })
        }

        pub(crate) fn advance(&self, by: Duration) {
            *self.now.lock().expect("clock") += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("clock")
        }
    }

    pub(crate) fn state_with_clock() -> (BrowserFillState, Arc<FakeClock>) {
        let clock = FakeClock::new();
        (BrowserFillState::with_clock(clock.clone()), clock)
    }

    pub(crate) fn let_delay_pass(state: &BrowserFillState, clock: &FakeClock) {
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
    use super::*;

    const JUST_UNDER: Duration = Duration::from_millis(749);

    fn origin(value: &str) -> NormalizedOrigin {
        NormalizedOrigin::from_request(value).expect("origin")
    }

    fn begin_fill(
        state: &BrowserFillState,
        request_id: &str,
    ) -> (String, std::sync::mpsc::Receiver<ApprovalDecision>) {
        let (approval_id, _, receiver) = state
            .begin(
                request_id,
                origin("https://example.test"),
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
    fn an_approval_that_comes_too_soon_is_refused_and_keeps_its_binding() {
        let (state, clock) = focused_state();
        let (approval_id, receiver) = begin_fill(&state, "request-1");
        clock.advance(JUST_UNDER);

        assert_eq!(
            state.decide(&approval_id, select("login-a")),
            Err(APPROVAL_TOO_SOON)
        );
        assert!(state.is_bound(
            &approval_id,
            "request-1",
            &origin("https://example.test"),
            7
        ));
        assert!(receiver.try_recv().is_err());

        clock.advance(Duration::from_millis(1));
        assert!(state.decide(&approval_id, select("login-a")).is_ok());
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
        assert_eq!(state.require_ready("not-the-approval"), Ok(()));
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

#[test]
fn revealing_a_login_secret_still_needs_presence() {
    let vault = TestVault::with_login("login-a", "https://northwind.example");
    let presence = ReleasePresence::default();

    assert_eq!(
        reveal_login_secret_in_state(&vault.state, &presence, "login-a"),
        Err(PRESENCE_REQUIRED.to_string())
    );
}
