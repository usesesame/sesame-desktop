/// Every identity is a candidate: identities are not site-scoped, but the prompt still names the page.
fn identity_response(
    app: &AppHandle,
    request: &BrowserRequest,
    peer: &PipePeer,
) -> BrowserResponse {
    diagnostics::record_browser_host_registration(app, "identity_requested");
    let Some(origin) = request
        .origin
        .as_deref()
        .and_then(NormalizedOrigin::from_request)
    else {
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    };
    let Some(requested_fields) = request.fields.as_deref().and_then(parse_identity_fields) else {
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    };

    let vault = app.state::<VaultState>();
    let (epoch, candidates) = {
        let session = match vault.session.lock() {
            Ok(session) => session,
            Err(_) => {
                return BrowserResponse::identity_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let Some(session) = session.as_ref() else {
            diagnostics::record_browser_host_registration(app, "identity_locked");
            return BrowserResponse::identity_unavailable(&request.request_id, "locked");
        };
        let candidates: Vec<IdentityFillCandidate> = session
            .payload
            .identities
            .iter()
            .take(MAX_MATCHING_CANDIDATES)
            .map(|identity| IdentityFillCandidate {
                id: identity.id.clone(),
                label: bounded_display(&identity.label, 128),
            })
            .collect();
        (vault.session_epoch(), candidates)
    };
    if candidates.is_empty() {
        diagnostics::record_browser_host_registration(app, "identity_no_match");
        return BrowserResponse::identity_unavailable(&request.request_id, "noMatch");
    }

    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id.clone())
        .collect();
    let fill_state = app.state::<BrowserFillState>();
    let (approval_id, deadline, receiver) = match fill_state.begin_identity(
        &request.request_id,
        origin.clone(),
        epoch,
        candidate_ids,
    ) {
        Ok(value) => value,
        Err(reason) => return BrowserResponse::identity_unavailable(&request.request_id, reason),
    };

    let event = BrowserIdentityRequestEvent {
        approval_id: approval_id.clone(),
        origin: origin.canonical(),
        hostname: origin.hostname.clone(),
        requested_fields: requested_fields.clone(),
        candidates,
        expires_in_seconds: APPROVAL_TIMEOUT.as_secs(),
        expires_at_unix_ms: approval_expires_at_unix_ms(),
    };
    if fill_state
        .publish_identity(&approval_id, event.clone())
        .is_err()
    {
        fill_state.revoke_identity(&approval_id);
        return BrowserResponse::identity_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-identity-request", event);

    let decision = match wait_for_identity_decision(
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
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::identity_unavailable(&request.request_id, reason),
    };
    let identity_id = match decision {
        IdentityDecision::Identity(identity_id) => identity_id,
        IdentityDecision::Denied => {
            return BrowserResponse::identity_unavailable(&request.request_id, "approvalDeclined")
        }
        IdentityDecision::InvalidSelection => {
            return BrowserResponse::identity_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_identity_cancelled(app, &approval_id, "connectionClosed");
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    }

    // Recheck under the current vault lock. No identity value is read before this point.
    let session = match vault.session.lock() {
        Ok(session) => session,
        Err(_) => {
            return BrowserResponse::identity_unavailable(
                &request.request_id,
                "approvalUnavailable",
            )
        }
    };
    if vault.session_epoch() != epoch {
        emit_identity_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_identity_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::identity_unavailable(&request.request_id, "locked");
    };
    let Some(identity) = session
        .payload
        .identities
        .iter()
        .find(|identity| identity.id == identity_id)
    else {
        emit_identity_cancelled(app, &approval_id, "vaultChanged");
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    };
    BrowserResponse::identity_for(
        request,
        selected_identity_fields(identity, &requested_fields),
    )
}

/// Released key set matches the requested set exactly: unrequested keys stay `None`.
fn selected_identity_fields(identity: &Identity, requested: &[String]) -> IdentityFillFields {
    let mut fields = IdentityFillFields::default();
    for key in requested {
        match key.as_str() {
            "fullName" => fields.full_name = Some(bounded_display(&identity.full_name, 256)),
            "email" => fields.email = Some(bounded_display(&identity.email, 320)),
            "phone" => fields.phone = Some(bounded_display(&identity.phone, 64)),
            "addressLine1" => {
                fields.address_line1 = Some(bounded_display(&identity.address_line1, 256))
            }
            "addressLine2" => {
                fields.address_line2 = Some(bounded_display(&identity.address_line2, 256))
            }
            "city" => fields.city = Some(bounded_display(&identity.city, 128)),
            "region" => fields.region = Some(bounded_display(&identity.region, 128)),
            "postalCode" => fields.postal_code = Some(bounded_display(&identity.postal_code, 32)),
            "country" => fields.country = Some(bounded_display(&identity.country, 128)),
            _ => {}
        }
    }
    fields
}

#[allow(clippy::too_many_arguments)]
fn wait_for_identity_decision(
    app: &AppHandle,
    fill_state: &BrowserFillState,
    vault: &VaultState,
    approval_id: &str,
    request_id: &str,
    origin: &NormalizedOrigin,
    epoch: u64,
    deadline: Instant,
    receiver: Receiver<IdentityDecision>,
    peer: &PipePeer,
) -> Result<IdentityDecision, &'static str> {
    loop {
        match receiver.try_recv() {
            Ok(decision) => return Ok(decision),
            Err(TryRecvError::Disconnected) => return Err("approvalUnavailable"),
            Err(TryRecvError::Empty) => {}
        }
        if !peer.is_connected() {
            fill_state.revoke_identity(approval_id);
            emit_identity_cancelled(app, approval_id, "connectionClosed");
            diagnostics::record_browser_host_registration(app, "identity_connection_closed");
            return Err("staleRequest");
        }
        if Instant::now() >= deadline {
            fill_state.revoke_identity(approval_id);
            emit_identity_cancelled(app, approval_id, "expired");
            diagnostics::record_browser_host_registration(app, "identity_timeout");
            return Err("approvalTimeout");
        }
        if !fill_state.is_identity_bound(approval_id, request_id, origin, epoch) {
            if let Ok(decision) = receiver.try_recv() {
                return Ok(decision);
            }
            fill_state.revoke_identity(approval_id);
            emit_identity_cancelled(app, approval_id, "expired");
            return Err("approvalUnavailable");
        }
        if vault.session_epoch() != epoch {
            fill_state.revoke_identity(approval_id);
            emit_identity_cancelled(app, approval_id, "vaultChanged");
            diagnostics::record_browser_host_registration(app, "identity_vault_changed");
            return Err("staleRequest");
        }
        thread::sleep(APPROVAL_POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

fn emit_identity_cancelled(app: &AppHandle, approval_id: &str, reason: &'static str) {
    let _ = app.emit(
        "browser-identity-cancelled",
        BrowserIdentityCancelledEvent {
            approval_id: approval_id.to_string(),
            reason,
        },
    );
}
