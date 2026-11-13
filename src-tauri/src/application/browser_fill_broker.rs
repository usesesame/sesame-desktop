use std::{
    collections::{HashSet, VecDeque},
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use zeroize::Zeroize;

use crate::vault::random_id;

use super::browser_fill::{
    ApprovalDecision, BrowserCardRequestEvent, BrowserFillCandidate, BrowserFillRequestEvent,
    BrowserIdentityRequestEvent, BrowserSaveRequestEvent, BrowserTotpRequestEvent,
    NormalizedOrigin, SaveKind, SavePayload, APPROVAL_TOO_SOON,
};

pub(crate) const APPROVAL_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const APPROVAL_FOCUS_DELAY: Duration = Duration::from_millis(750);
pub(super) const ACTIVATE_MIN_INTERVAL: Duration = Duration::from_secs(5);
const REPLAY_CACHE_SIZE: usize = 128;

pub(crate) trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub(super) struct FocusDelay {
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
    pub(super) fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            focused_since: None,
            shown_at: None,
        }
    }

    pub(super) fn window_focus_changed(&mut self, focused: bool) {
        if !focused {
            self.focused_since = None;
        } else if self.focused_since.is_none() {
            self.focused_since = Some(self.clock.now());
        }
    }

    pub(super) fn approval_shown(&mut self) {
        self.shown_at = Some(self.clock.now());
    }

    pub(super) fn remaining(&self) -> Duration {
        let Some(focused_since) = self.focused_since else {
            return APPROVAL_FOCUS_DELAY;
        };
        let counted_from = self
            .shown_at
            .map_or(focused_since, |shown_at| shown_at.max(focused_since));
        APPROVAL_FOCUS_DELAY
            .saturating_sub(self.clock.now().saturating_duration_since(counted_from))
    }

    pub(super) fn is_ready(&self) -> bool {
        self.remaining().is_zero()
    }
}

pub(crate) enum ApprovalRequest {
    Fill {
        candidate_ids: HashSet<String>,
    },
    Save {
        kind: SaveKind,
        title: String,
        username: String,
        password: zeroize::Zeroizing<String>,
        candidates: Vec<BrowserFillCandidate>,
    },
    Identity {
        candidate_ids: HashSet<String>,
    },
    Card {
        candidate_ids: HashSet<String>,
    },
    Totp {
        candidate_ids: HashSet<String>,
    },
}

impl ApprovalRequest {
    fn offers(&self, id: &str) -> bool {
        match self {
            Self::Fill { candidate_ids }
            | Self::Identity { candidate_ids }
            | Self::Card { candidate_ids }
            | Self::Totp { candidate_ids } => candidate_ids.contains(id),
            Self::Save { .. } => false,
        }
    }
}

pub(crate) enum ApprovalEvent {
    Fill(BrowserFillRequestEvent),
    Save(BrowserSaveRequestEvent),
    Identity(BrowserIdentityRequestEvent),
    Card(BrowserCardRequestEvent),
    Totp(BrowserTotpRequestEvent),
}

struct PendingApproval {
    approval_id: String,
    request_id: String,
    origin: NormalizedOrigin,
    session_epoch: u64,
    request: ApprovalRequest,
    request_event: Option<ApprovalEvent>,
    deadline: Instant,
    sender: SyncSender<ApprovalDecision>,
}

impl Drop for PendingApproval {
    fn drop(&mut self) {
        if let ApprovalRequest::Save {
            title,
            username,
            password,
            ..
        } = &mut self.request
        {
            title.zeroize();
            username.zeroize();
            password.zeroize();
        }
    }
}

#[derive(Default)]
struct FillInner {
    pending: Option<PendingApproval>,
    recent_request_ids: VecDeque<String>,
    last_activation: Option<Instant>,
    focus: FocusDelay,
}

#[derive(Default)]
pub struct BrowserFillState {
    inner: Mutex<FillInner>,
}

impl BrowserFillState {
    #[cfg(test)]
    pub(crate) fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(FillInner {
                focus: FocusDelay::new(clock),
                ..FillInner::default()
            }),
        }
    }

    pub fn window_focus_changed(&self, focused: bool) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.focus.window_focus_changed(focused);
        }
    }

    pub fn approval_wait(&self) -> Duration {
        self.inner
            .lock()
            .map_or(APPROVAL_FOCUS_DELAY, |inner| inner.focus.remaining())
    }

    pub(crate) fn require_ready(&self, approval_id: &str) -> Result<(), &'static str> {
        let inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let bound = inner
            .pending
            .as_ref()
            .is_some_and(|pending| pending.approval_id == approval_id);
        if bound && !inner.focus.is_ready() {
            return Err(APPROVAL_TOO_SOON);
        }
        Ok(())
    }

    pub(crate) fn cancel_pending(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(pending) = inner.pending.take() {
                let _ = pending.sender.send(ApprovalDecision::Denied);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn expire_pending(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(pending) = inner.pending.as_mut() {
                pending.deadline = Instant::now() - Duration::from_secs(1);
            }
        }
    }

    pub(crate) fn note_activation(&self, now: Instant) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        if inner
            .last_activation
            .is_some_and(|last| now.duration_since(last) < ACTIVATE_MIN_INTERVAL)
        {
            return false;
        }
        inner.last_activation = Some(now);
        true
    }

    fn note_request_id(inner: &mut FillInner, request_id: &str) -> Result<(), &'static str> {
        if inner
            .recent_request_ids
            .iter()
            .any(|recent| recent == request_id)
        {
            return Err("staleRequest");
        }
        inner.recent_request_ids.push_back(request_id.to_string());
        while inner.recent_request_ids.len() > REPLAY_CACHE_SIZE {
            inner.recent_request_ids.pop_front();
        }
        Ok(())
    }

    pub(crate) fn begin(
        &self,
        request_id: &str,
        origin: NormalizedOrigin,
        session_epoch: u64,
        request: ApprovalRequest,
    ) -> Result<(String, Instant, Receiver<ApprovalDecision>), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        Self::note_request_id(&mut inner, request_id)?;
        if inner.pending.is_some() {
            return Err("approvalUnavailable");
        }
        let approval_id = random_id();
        inner.focus.approval_shown();
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + APPROVAL_TIMEOUT;
        inner.pending = Some(PendingApproval {
            approval_id: approval_id.clone(),
            request_id: request_id.to_string(),
            origin,
            session_epoch,
            request,
            request_event: None,
            deadline,
            sender,
        });
        Ok((approval_id, deadline, receiver))
    }

    fn pending_event<T>(&self, pick: impl FnOnce(&ApprovalEvent) -> Option<T>) -> Option<T> {
        let inner = self.inner.lock().ok()?;
        let pending = inner.pending.as_ref()?;
        if pending.deadline <= Instant::now() {
            return None;
        }
        pick(pending.request_event.as_ref()?)
    }

    pub(crate) fn pending_fill_request(&self) -> Option<BrowserFillRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Fill(event) => Some(event.clone()),
            _ => None,
        })
    }

    pub(crate) fn pending_save_request(&self) -> Option<BrowserSaveRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Save(event) => Some(event.clone()),
            _ => None,
        })
    }

    pub(crate) fn pending_identity_request(&self) -> Option<BrowserIdentityRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Identity(event) => Some(event.clone()),
            _ => None,
        })
    }

    pub(crate) fn pending_card_request(&self) -> Option<BrowserCardRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Card(event) => Some(event.clone()),
            _ => None,
        })
    }

    pub(crate) fn pending_totp_request(&self) -> Option<BrowserTotpRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Totp(event) => Some(event.clone()),
            _ => None,
        })
    }

    /// Credential only while bound; `decide` still releases the broker.
    pub(crate) fn save_payload_if_bound(&self, approval_id: &str) -> Option<SavePayload> {
        let inner = self.inner.lock().ok()?;
        let pending = inner.pending.as_ref()?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return None;
        }
        let ApprovalRequest::Save {
            kind,
            title,
            username,
            password,
            candidates,
        } = &pending.request
        else {
            return None;
        };
        Some(SavePayload {
            kind: *kind,
            title: title.clone(),
            username: username.clone(),
            password: password.clone(),
            origin: pending.origin.canonical(),
            epoch: pending.session_epoch,
            candidates: candidates.clone(),
        })
    }

    pub(crate) fn publish(
        &self,
        approval_id: &str,
        request_event: ApprovalEvent,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending.as_mut().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        pending.request_event = Some(request_event);
        Ok(())
    }

    pub(crate) fn decide(
        &self,
        approval_id: &str,
        decision: ApprovalDecision,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending.as_ref().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        if let ApprovalDecision::Selected(id) = &decision {
            if !inner.focus.is_ready() {
                return Err(APPROVAL_TOO_SOON);
            }
            if !pending.request.offers(id) {
                pending
                    .sender
                    .send(ApprovalDecision::InvalidSelection)
                    .map_err(|_| "approvalExpired")?;
                inner.pending = None;
                return Err("selectionNotOffered");
            }
        }
        pending
            .sender
            .send(decision)
            .map_err(|_| "approvalExpired")?;
        inner.pending = None;
        Ok(())
    }

    pub(crate) fn revoke(&self, approval_id: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            if inner
                .pending
                .as_ref()
                .is_some_and(|pending| pending.approval_id == approval_id)
            {
                inner.pending = None;
            }
        }
    }

    pub(crate) fn is_bound(
        &self,
        approval_id: &str,
        request_id: &str,
        origin: &NormalizedOrigin,
        session_epoch: u64,
    ) -> bool {
        self.inner
            .lock()
            .ok()
            .and_then(|inner| {
                inner.pending.as_ref().map(|pending| {
                    pending.approval_id == approval_id
                        && pending.request_id == request_id
                        && pending.origin == *origin
                        && pending.session_epoch == session_epoch
                })
            })
            .unwrap_or(false)
    }
}
