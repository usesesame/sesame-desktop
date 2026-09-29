fn totp_response(app: &AppHandle, request: &BrowserRequest, peer: &PipePeer) -> BrowserResponse {
    diagnostics::record_browser_host_registration(app, "totp_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    let vault = app.state::<VaultState>();
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::totp_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let Some(session) = session.as_ref() else {
            diagnostics::record_browser_host_registration(app, "totp_locked");
            return BrowserResponse::totp_unavailable(&request.request_id, "noMatch");
        };
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::totp_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        (
            vault.session_epoch(),
            matching_totp_entries(&payload.entries, &origin),
        )
    };
    if candidates.is_empty() {
        diagnostics::record_browser_host_registration(app, "totp_no_match");
        return BrowserResponse::totp_unavailable(&request.request_id, "noMatch");
    }

    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let fill_state = app.state::<BrowserFillState>();
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Totp { candidate_ids },
    ) {
        Ok(value) => value,
        Err(reason) => return BrowserResponse::totp_unavailable(&request.request_id, reason),
    };
    let event = BrowserTotpRequestEvent {
        approval_id: approval_id.clone(),
        origin: origin.canonical(),
        hostname: origin.hostname.clone(),
        candidates,
        expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
        expires_at_unix_ms: approval_expires_at_unix_ms(),
    };
    if fill_state
        .publish(&approval_id, ApprovalEvent::Totp(event.clone()))
        .is_err()
    {
        fill_state.revoke(&approval_id);
        return BrowserResponse::totp_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-totp-request", event);

    let decision = match wait_for_decision(
        app,
        &fill_state,
        &vault,
        &approval_id,
        &request.request_id,
        &origin,
        epoch,
        deadline,
        receiver,
        peer,
        ApprovalKind::Totp,
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::totp_unavailable(&request.request_id, reason),
    };
    let login_id = match decision {
        ApprovalDecision::Selected(login_id) => login_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::totp_unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::totp_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "connectionClosed");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    }

    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::totp_unavailable(&request.request_id, "approvalUnavailable")
        }
    };
    if vault.session_epoch() != epoch {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&login_id) else {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Login(entry) = &*item else {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    let Some(saved_origin) = NormalizedOrigin::from_saved_url(&entry.url) else {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    if origin_match_kind(&saved_origin, &origin).is_none() {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    }
    let Some(response) = entry
        .totp
        .as_deref()
        .and_then(|secret| totp_response_for_secret(request, secret))
    else {
        emit_approval_cancelled(app, ApprovalKind::Totp, &approval_id, "vaultChanged");
        return BrowserResponse::totp_unavailable(&request.request_id, "staleRequest");
    };
    response
}

fn totp_response_for_secret(request: &BrowserRequest, secret: &str) -> Option<BrowserResponse> {
    let (code, remaining, _period) = current_totp(secret)?;
    let response = BrowserResponse::totp_for(request, code, remaining);
    response.validate_for(request).then_some(response)
}
