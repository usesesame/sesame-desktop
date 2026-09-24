enum ApprovalRequest {
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
}

impl ApprovalRequest {
    fn offers(&self, id: &str) -> bool {
        match self {
            Self::Fill { candidate_ids }
            | Self::Identity { candidate_ids }
            | Self::Card { candidate_ids } => candidate_ids.contains(id),
            Self::Save { .. } => false,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalKind {
    Fill,
    Save,
    Identity,
    Card,
}

impl ApprovalKind {
    fn cancelled_event(self) -> &'static str {
        match self {
            Self::Fill => "browser-fill-cancelled",
            Self::Save => "browser-save-cancelled",
            Self::Identity => "browser-identity-cancelled",
            Self::Card => "browser-card-cancelled",
        }
    }

    fn timeout_code(self) -> &'static str {
        match self {
            Self::Fill => "fill_timeout",
            Self::Save => "save_timeout",
            Self::Identity => "identity_timeout",
            Self::Card => "card_timeout",
        }
    }

    fn connection_closed_code(self) -> &'static str {
        match self {
            Self::Fill => "fill_connection_closed",
            Self::Save => "save_connection_closed",
            Self::Identity => "identity_connection_closed",
            Self::Card => "card_connection_closed",
        }
    }

    fn vault_changed_code(self) -> &'static str {
        match self {
            Self::Fill => "fill_vault_changed",
            Self::Save => "save_vault_changed",
            Self::Identity => "identity_vault_changed",
            Self::Card => "card_vault_changed",
        }
    }
}

enum ApprovalDecision {
    Denied,
    InvalidSelection,
    Selected(String),
    Saved,
}

enum ApprovalEvent {
    Fill(BrowserFillRequestEvent),
    Save(BrowserSaveRequestEvent),
    Identity(BrowserIdentityRequestEvent),
    Card(BrowserCardRequestEvent),
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

/// Held credential, returned to the command layer only while the approval is still bound.
pub struct SavePayload {
    pub kind: SaveKind,
    pub title: String,
    pub username: String,
    pub password: String,
    pub origin: String,
    pub epoch: u64,
    pub candidates: Vec<BrowserFillCandidate>,
}

#[derive(Default)]
struct FillInner {
    pending: Option<PendingApproval>,
    recent_request_ids: VecDeque<String>,
    grants: Vec<FillGrant>,
}

/// One approval the user chose to extend to a single origin and login for a short window.
/// Bound to the session epoch, so locking or changing the vault discards it.
struct FillGrant {
    origin: String,
    login_id: String,
    session_epoch: u64,
    expires: Instant,
}

#[derive(Default)]
pub struct BrowserFillState {
    inner: Mutex<FillInner>,
}

impl BrowserFillState {
    fn cancel_pending(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(pending) = inner.pending.take() {
                let _ = pending.sender.send(ApprovalDecision::Denied);
            }
            inner.grants.clear();
        }
    }

    /// An unexpired grant for this exact origin and epoch whose login is still offered.
    fn granted_login(
        &self,
        origin: &NormalizedOrigin,
        session_epoch: u64,
        candidate_ids: &HashSet<String>,
    ) -> Option<String> {
        let mut inner = self.inner.lock().ok()?;
        let now = Instant::now();
        inner
            .grants
            .retain(|grant| grant.expires > now && grant.session_epoch == session_epoch);
        let canonical = origin.canonical();
        inner
            .grants
            .iter()
            .find(|grant| grant.origin == canonical && candidate_ids.contains(&grant.login_id))
            .map(|grant| grant.login_id.clone())
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

    fn begin(
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

    fn pending_fill_request(&self) -> Option<BrowserFillRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Fill(event) => Some(event.clone()),
            _ => None,
        })
    }

    fn pending_save_request(&self) -> Option<BrowserSaveRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Save(event) => Some(event.clone()),
            _ => None,
        })
    }

    fn pending_identity_request(&self) -> Option<BrowserIdentityRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Identity(event) => Some(event.clone()),
            _ => None,
        })
    }

    fn pending_card_request(&self) -> Option<BrowserCardRequestEvent> {
        self.pending_event(|event| match event {
            ApprovalEvent::Card(event) => Some(event.clone()),
            _ => None,
        })
    }

    /// Credential only while bound; `decide` still releases the broker.
    fn save_payload_if_bound(&self, approval_id: &str) -> Option<SavePayload> {
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
            password: password.as_str().to_string(),
            origin: pending.origin.canonical(),
            epoch: pending.session_epoch,
            candidates: candidates.clone(),
        })
    }

    fn publish(&self, approval_id: &str, request_event: ApprovalEvent) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending.as_mut().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        pending.request_event = Some(request_event);
        Ok(())
    }

    fn decide(
        &self,
        approval_id: &str,
        decision: ApprovalDecision,
        remember: bool,
    ) -> Result<(), &'static str> {
        let mut inner = self.inner.lock().map_err(|_| "approvalUnavailable")?;
        let pending = inner.pending.as_ref().ok_or("approvalExpired")?;
        if pending.approval_id != approval_id || pending.deadline <= Instant::now() {
            return Err("approvalExpired");
        }
        if let ApprovalDecision::Selected(id) = &decision {
            if !pending.request.offers(id) {
                pending
                    .sender
                    .send(ApprovalDecision::InvalidSelection)
                    .map_err(|_| "approvalExpired")?;
                inner.pending = None;
                return Err("selectionNotOffered");
            }
        }
        let grant = match (&decision, remember, &pending.request) {
            (ApprovalDecision::Selected(login_id), true, ApprovalRequest::Fill { .. }) => {
                Some(FillGrant {
                    origin: pending.origin.canonical(),
                    login_id: login_id.clone(),
                    session_epoch: pending.session_epoch,
                    expires: Instant::now() + FILL_GRANT_DURATION,
                })
            }
            _ => None,
        };
        pending
            .sender
            .send(decision)
            .map_err(|_| "approvalExpired")?;
        inner.pending = None;
        if let Some(grant) = grant {
            inner
                .grants
                .retain(|held| held.origin != grant.origin || held.login_id != grant.login_id);
            inner.grants.push(grant);
        }
        Ok(())
    }

    fn revoke(&self, approval_id: &str) {
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

    fn is_bound(
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

pub fn cancel_pending_approvals(app: &tauri::AppHandle) {
    app.state::<BrowserFillState>().cancel_pending();
}

#[allow(clippy::too_many_arguments)]
fn wait_for_decision(
    app: &AppHandle,
    fill_state: &BrowserFillState,
    vault: &VaultState,
    approval_id: &str,
    request_id: &str,
    origin: &NormalizedOrigin,
    epoch: u64,
    deadline: Instant,
    receiver: Receiver<ApprovalDecision>,
    peer: &PipePeer,
    kind: ApprovalKind,
) -> Result<ApprovalDecision, &'static str> {
    loop {
        match receiver.try_recv() {
            Ok(decision) => return Ok(decision),
            Err(TryRecvError::Disconnected) => return Err("approvalUnavailable"),
            Err(TryRecvError::Empty) => {}
        }
        if !peer.is_connected() {
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "connectionClosed");
            diagnostics::record_browser_host_registration(app, kind.connection_closed_code());
            return Err("staleRequest");
        }
        if Instant::now() >= deadline {
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "expired");
            diagnostics::record_browser_host_registration(app, kind.timeout_code());
            return Err("approvalTimeout");
        }
        if !fill_state.is_bound(approval_id, request_id, origin, epoch) {
            if let Ok(decision) = receiver.try_recv() {
                return Ok(decision);
            }
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "expired");
            return Err("approvalUnavailable");
        }
        if vault.session_epoch() != epoch {
            fill_state.revoke(approval_id);
            emit_approval_cancelled(app, kind, approval_id, "vaultChanged");
            diagnostics::record_browser_host_registration(app, kind.vault_changed_code());
            return Err("staleRequest");
        }
        thread::sleep(APPROVAL_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

include!("browser_fill_matching.rs");

fn emit_approval_cancelled(
    app: &AppHandle,
    kind: ApprovalKind,
    approval_id: &str,
    reason: &'static str,
) {
    let _ = app.emit(
        kind.cancelled_event(),
        BrowserApprovalCancelledEvent {
            approval_id: approval_id.to_string(),
            reason,
        },
    );
}
