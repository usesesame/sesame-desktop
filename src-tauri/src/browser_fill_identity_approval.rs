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
        let payload = match session.open_payload() {
            Ok(payload) => payload,
            Err(_) => {
                return BrowserResponse::identity_unavailable(
                    &request.request_id,
                    "approvalUnavailable",
                )
            }
        };
        let candidates: Vec<IdentityFillCandidate> = payload
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
    let (approval_id, deadline, receiver) = match fill_state.begin(
        &request.request_id,
        origin.clone(),
        epoch,
        ApprovalRequest::Identity { candidate_ids },
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
        .publish(&approval_id, ApprovalEvent::Identity(event.clone()))
        .is_err()
    {
        fill_state.revoke(&approval_id);
        return BrowserResponse::identity_unavailable(&request.request_id, "approvalUnavailable");
    }
    bring_to_foreground(app);
    let _ = app.emit("browser-identity-request", event);

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
        ApprovalKind::Identity,
    ) {
        Ok(decision) => decision,
        Err(reason) => return BrowserResponse::identity_unavailable(&request.request_id, reason),
    };
    let identity_id = match decision {
        ApprovalDecision::Selected(identity_id) => identity_id,
        ApprovalDecision::Denied => {
            return BrowserResponse::identity_unavailable(&request.request_id, "approvalDeclined")
        }
        ApprovalDecision::InvalidSelection | ApprovalDecision::Saved => {
            return BrowserResponse::identity_unavailable(&request.request_id, "invalidSelection")
        }
    };
    if !peer.is_connected() {
        emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "connectionClosed");
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
        emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "vaultChanged");
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    }
    let Some(session) = session.as_ref() else {
        emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "vaultChanged");
        return BrowserResponse::identity_unavailable(&request.request_id, "locked");
    };
    let Ok(item) = session.open_item(&identity_id) else {
        emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "vaultChanged");
        return BrowserResponse::identity_unavailable(&request.request_id, "staleRequest");
    };
    let TaggedItem::Identity(identity) = &*item else {
        emit_approval_cancelled(app, ApprovalKind::Identity, &approval_id, "vaultChanged");
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
