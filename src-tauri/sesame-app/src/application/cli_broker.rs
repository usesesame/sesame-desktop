use std::{
    collections::VecDeque,
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use super::approval_slot::{ApprovalSlot, SlotClaim};
use super::browser_fill::APPROVAL_TOO_SOON;
use super::browser_fill_broker::{Clock, FocusDelay};
use super::terminal_allowances::{SystemClock, UnverifiedProgram};
use crate::cli_protocol::CliErrorCode;
use crate::vault::random_id;

pub const CLI_APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
pub const CLI_UNLOCK_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_CLEAR_AFTER_SECONDS: u64 = 30;
pub const CLEAR_AFTER_CHOICES: [u64; 3] = [10, 30, 60];
pub const COOLING_FIRST: Duration = Duration::from_secs(15);
pub const COOLING_LONGEST: Duration = Duration::from_secs(5 * 60);
pub const COOLING_MESSAGE: &str = "Sesame is turning away terminal requests for a short while because the last one was denied or not answered. Try again shortly.";
const REPLAY_CACHE_SIZE: usize = 128;
const APPROVAL_EXPIRED: &str = "approvalExpired";
const SELECTION_NOT_OFFERED: &str = "selectionNotOffered";

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum CliCommandKind {
    List,
    Get,
    Totp,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct CliCandidate {
    pub id: String,
    pub kind: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_name: Option<String>,
    pub field_hidden: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct CliApprovalRequestEvent {
    pub approval_id: String,
    pub command: CliCommandKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub field_hidden: bool,
    pub copy: bool,
    pub candidates: Vec<CliCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_found: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<UnverifiedProgram>,
    pub remote: bool,
    pub can_allow_terminal: bool,
    pub needs_presence: bool,
    pub allowed: bool,
    pub expires_in_ms: u64,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CliApprovalCancelledEvent {
    pub approval_id: String,
    pub reason: String,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct CliUnlockRequestEvent {
    pub command: CliCommandKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<UnverifiedProgram>,
    pub remote: bool,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CliUnlockEndedEvent {
    pub reason: String,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub enum CliDecisionKind {
    Allow,
    Deny,
    Dismiss,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CliDecisionInput {
    pub approval_id: String,
    pub decision: CliDecisionKind,
    #[serde(default)]
    pub item_id: Option<String>,
    #[serde(default)]
    pub allow_terminal: Option<bool>,
    #[serde(default)]
    pub clear_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliDecision {
    Allow {
        item_id: Option<String>,
        terminal_grant: Option<u64>,
    },
    Deny,
    Dismiss,
    InvalidSelection,
    Withdrawn,
    Preempted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartRefusal {
    Code(CliErrorCode),
    CoolingOff,
}

struct CliPending {
    approval_id: String,
    request_id: String,
    epoch: u64,
    offered: Vec<String>,
    not_found: bool,
    terminal_allowed: bool,
    event: CliApprovalRequestEvent,
    deadline: Instant,
    sender: SyncSender<CliDecision>,
    _slot: SlotClaim,
}

struct CliInner {
    in_flight: bool,
    pending: Option<CliPending>,
    recent_request_ids: VecDeque<String>,
    focus: FocusDelay,
    clock: Arc<dyn Clock>,
    unanswered: u32,
    cooling_until: Option<Instant>,
    clear_after_seconds: u64,
    approval_timeout: Duration,
}

impl CliInner {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            in_flight: false,
            pending: None,
            recent_request_ids: VecDeque::new(),
            focus: FocusDelay::new(Arc::clone(&clock)),
            clock,
            unanswered: 0,
            cooling_until: None,
            clear_after_seconds: DEFAULT_CLEAR_AFTER_SECONDS,
            approval_timeout: CLI_APPROVAL_TIMEOUT,
        }
    }

    fn cooling(&self) -> bool {
        self.cooling_until
            .is_some_and(|until| self.clock.now() < until)
    }
}

fn cooling_period(unanswered: u32) -> Duration {
    let doublings = unanswered.saturating_sub(1).min(16);
    COOLING_FIRST
        .saturating_mul(1 << doublings)
        .min(COOLING_LONGEST)
}

pub struct CliApprovalState {
    inner: Arc<Mutex<CliInner>>,
    slot: ApprovalSlot,
}

impl Default for CliApprovalState {
    fn default() -> Self {
        Self::sharing(ApprovalSlot::default())
    }
}

pub struct InFlight {
    inner: Arc<Mutex<CliInner>>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.in_flight = false;
    }
}

pub struct ApprovalOffer {
    pub approval_id: String,
    pub deadline: Instant,
    pub receiver: Receiver<CliDecision>,
    pub event: CliApprovalRequestEvent,
}

pub struct ApprovalSubject {
    pub request_id: String,
    pub epoch: u64,
    pub offered: Vec<String>,
    pub not_found: bool,
    pub terminal_allowed: bool,
    pub event: CliApprovalRequestEvent,
}

impl CliApprovalState {
    pub fn sharing(slot: ApprovalSlot) -> Self {
        Self::with_clock(slot, Arc::new(SystemClock))
    }

    pub fn with_clock(slot: ApprovalSlot, clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CliInner::new(clock))),
            slot,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CliInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn start(&self, request_id: &str) -> Result<InFlight, StartRefusal> {
        let mut inner = self.lock();
        if inner
            .recent_request_ids
            .iter()
            .any(|recent| recent == request_id)
        {
            return Err(StartRefusal::Code(CliErrorCode::Stale));
        }
        inner.recent_request_ids.push_back(request_id.to_string());
        while inner.recent_request_ids.len() > REPLAY_CACHE_SIZE {
            inner.recent_request_ids.pop_front();
        }
        if inner.in_flight {
            return Err(StartRefusal::Code(CliErrorCode::Busy));
        }
        if inner.cooling() {
            return Err(StartRefusal::CoolingOff);
        }
        inner.in_flight = true;
        Ok(InFlight {
            inner: Arc::clone(&self.inner),
        })
    }

    pub fn begin(&self, subject: ApprovalSubject) -> Result<ApprovalOffer, CliErrorCode> {
        let mut inner = self.lock();
        if inner.pending.is_some() {
            return Err(CliErrorCode::Busy);
        }
        let approval_id = random_id();
        let preempted = Arc::downgrade(&self.inner);
        let preempted_id = approval_id.clone();
        let claim = self
            .slot
            .claim_for_terminal(move || {
                let Some(inner) = preempted.upgrade() else {
                    return;
                };
                let mut inner = inner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if inner
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.approval_id == preempted_id)
                {
                    if let Some(pending) = inner.pending.take() {
                        let _ = pending.sender.send(CliDecision::Preempted);
                    }
                }
            })
            .ok_or(CliErrorCode::Busy)?;
        inner.focus.approval_shown();
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + inner.approval_timeout;
        let mut event = subject.event;
        event.approval_id = approval_id.clone();
        event.expires_in_ms = inner.approval_timeout.as_millis() as u64;
        inner.pending = Some(CliPending {
            approval_id: approval_id.clone(),
            request_id: subject.request_id,
            epoch: subject.epoch,
            offered: subject.offered,
            not_found: subject.not_found,
            terminal_allowed: subject.terminal_allowed,
            event: event.clone(),
            deadline,
            sender,
            _slot: claim,
        });
        Ok(ApprovalOffer {
            approval_id,
            deadline,
            receiver,
            event,
        })
    }

    pub fn pending_request(&self) -> Option<CliApprovalRequestEvent> {
        let inner = self.lock();
        let pending = inner.pending.as_ref()?;
        let now = Instant::now();
        if pending.deadline <= now {
            return None;
        }
        let mut event = pending.event.clone();
        event.expires_in_ms = pending
            .deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        Some(event)
    }

    pub fn window_focus_changed(&self, focused: bool) {
        self.lock().focus.window_focus_changed(focused);
    }

    pub fn approval_wait(&self) -> Duration {
        self.lock().focus.remaining()
    }

    pub fn clear_after_seconds(&self) -> u64 {
        self.lock().clear_after_seconds
    }

    pub fn set_clear_after_seconds(&self, seconds: u64) -> bool {
        if !CLEAR_AFTER_CHOICES.contains(&seconds) {
            return false;
        }
        self.lock().clear_after_seconds = seconds;
        true
    }

    pub fn decide(
        &self,
        input: CliDecisionInput,
        allowance_revision: u64,
    ) -> Result<(), &'static str> {
        let mut inner = self.lock();
        let (offered, not_found, terminal_allowed) = {
            let pending = inner.pending.as_ref().ok_or(APPROVAL_EXPIRED)?;
            if pending.approval_id != input.approval_id || pending.deadline <= Instant::now() {
                return Err(APPROVAL_EXPIRED);
            }
            (
                pending.offered.clone(),
                pending.not_found,
                pending.terminal_allowed,
            )
        };
        let decision = match input.decision {
            CliDecisionKind::Deny => CliDecision::Deny,
            CliDecisionKind::Dismiss | CliDecisionKind::Allow if not_found => CliDecision::Dismiss,
            CliDecisionKind::Dismiss => CliDecision::Deny,
            CliDecisionKind::Allow => {
                if !inner.focus.is_ready() {
                    return Err(APPROVAL_TOO_SOON);
                }
                let item_id = match (&input.item_id, offered.as_slice()) {
                    (Some(id), offered) if offered.contains(id) => Some(id.clone()),
                    (Some(_), _) => {
                        if let Some(pending) = inner.pending.take() {
                            let _ = pending.sender.send(CliDecision::InvalidSelection);
                        }
                        return Err(SELECTION_NOT_OFFERED);
                    }
                    (None, [only]) => Some(only.clone()),
                    (None, []) => None,
                    (None, _) => return Err(SELECTION_NOT_OFFERED),
                };
                CliDecision::Allow {
                    item_id,
                    terminal_grant: (terminal_allowed && input.allow_terminal.unwrap_or(false))
                        .then_some(allowance_revision),
                }
            }
        };
        if let Some(seconds) = input.clear_after_seconds {
            if CLEAR_AFTER_CHOICES.contains(&seconds) {
                inner.clear_after_seconds = seconds;
            }
        }
        let pending = inner.pending.take().ok_or(APPROVAL_EXPIRED)?;
        let sent = pending
            ._slot
            .while_held(|| pending.sender.send(decision).is_ok());
        match sent {
            Some(true) => Ok(()),
            Some(false) => Err(APPROVAL_EXPIRED),
            None => {
                let _ = pending.sender.send(CliDecision::Preempted);
                Err(APPROVAL_EXPIRED)
            }
        }
    }

    pub fn note_unanswered(&self) {
        let mut inner = self.lock();
        inner.unanswered = inner.unanswered.saturating_add(1);
        let until = inner.clock.now() + cooling_period(inner.unanswered);
        inner.cooling_until = Some(until);
    }

    pub fn note_approved(&self) {
        let mut inner = self.lock();
        inner.unanswered = 0;
        inner.cooling_until = None;
    }

    pub fn revoke(&self, approval_id: &str) {
        let mut inner = self.lock();
        if inner
            .pending
            .as_ref()
            .is_some_and(|pending| pending.approval_id == approval_id)
        {
            inner.pending = None;
        }
    }

    pub fn cancel_pending(&self) {
        let mut inner = self.lock();
        if let Some(pending) = inner.pending.take() {
            let _ = pending.sender.send(CliDecision::Withdrawn);
        }
    }

    pub fn is_bound(&self, approval_id: &str, request_id: &str, epoch: u64) -> bool {
        self.lock().pending.as_ref().is_some_and(|pending| {
            pending.approval_id == approval_id
                && pending.request_id == request_id
                && pending.epoch == epoch
        })
    }

    #[cfg(test)]
    pub fn shorten_approval_timeout(&self, timeout: Duration) {
        self.lock().approval_timeout = timeout;
    }
}
