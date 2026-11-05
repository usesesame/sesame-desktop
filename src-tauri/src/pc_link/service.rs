use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{
    HeaderValue, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE,
    ORIGIN, REFERER, TRANSFER_ENCODING, UPGRADE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{de::DeserializeOwned, Serialize};
use tauri::{AppHandle, Manager};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::authority::validate_phone_public_key;
use super::discovery::Discovery;
use super::enrollment::PairingWindow;
use super::protocol::*;
use super::{ApprovedPeer, PcLinkState, PendingCommit, PendingPairing, SnapshotLease};
use crate::release::{ReleasePresence, PRESENCE_REQUIRED};
use crate::vault::{unix_timestamp, VaultResult, VaultState};

const PAIRING_GRACE_SECONDS: u64 = 5;

pub(crate) trait PcLinkHost: Send + Sync {
    fn data_dir(&self) -> &Path;

    fn selected_vault(&self) -> VaultResult<(String, String, u64)>;

    fn require_presence(&self, epoch: u64) -> VaultResult<()>;

    fn begin_pairing(
        &self,
        state: &PcLinkState,
        phone_public_key: &[u8],
        label: &str,
        request_id: String,
        now: u64,
    ) -> VaultResult<PendingPairing>;

    fn confirm_pairing(
        &self,
        state: &PcLinkState,
        request_id: &str,
        now: u64,
    ) -> VaultResult<PendingCommit>;

    fn commit_pairing(
        &self,
        state: &PcLinkState,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<ApprovedPeer>;

    fn capture_snapshot(
        &self,
        state: &PcLinkState,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<SnapshotLease>;

    fn lease_next_chunk(&self, lease: &mut SnapshotLease) -> VaultResult<Option<Vec<u8>>>;

    fn bind_listeners(&self, preferred: u16) -> VaultResult<(u16, Vec<StdTcpListener>)> {
        bind_listeners(preferred)
    }

    fn on_authority_changed(&self) {}

    fn allow_loopback(&self) -> bool {
        false
    }

    fn enable_discovery(&self) -> bool {
        true
    }
}

pub(crate) struct AppHandleHost {
    app: AppHandle,
    data_dir: PathBuf,
}

impl AppHandleHost {
    pub(crate) fn new(app: &AppHandle) -> VaultResult<Self> {
        let data_dir = app
            .path()
            .app_local_data_dir()
            .map_err(|_| "Sesame could not locate its local data folder.".to_string())?;
        Ok(Self {
            app: app.clone(),
            data_dir,
        })
    }

    pub(crate) fn shared(app: &AppHandle) -> VaultResult<Arc<dyn PcLinkHost>> {
        Ok(Arc::new(Self::new(app)?))
    }
}

impl PcLinkHost for AppHandleHost {
    fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    fn selected_vault(&self) -> VaultResult<(String, String, u64)> {
        PcLinkState::selected_vault(&self.app.state::<VaultState>())
    }

    fn require_presence(&self, epoch: u64) -> VaultResult<()> {
        self.app.state::<ReleasePresence>().require(epoch)
    }

    fn begin_pairing(
        &self,
        state: &PcLinkState,
        phone_public_key: &[u8],
        label: &str,
        request_id: String,
        now: u64,
    ) -> VaultResult<PendingPairing> {
        state.begin_pairing_with_id_at(
            &self.app.state::<VaultState>(),
            phone_public_key,
            label,
            request_id,
            now,
        )
    }

    fn confirm_pairing(
        &self,
        state: &PcLinkState,
        request_id: &str,
        now: u64,
    ) -> VaultResult<PendingCommit> {
        state.confirm_pairing_at(
            &self.app.state::<VaultState>(),
            &self.app.state::<ReleasePresence>(),
            request_id,
            now,
        )
    }

    fn commit_pairing(
        &self,
        state: &PcLinkState,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<ApprovedPeer> {
        state.commit_pairing_at(
            &self.app.state::<VaultState>(),
            &self.app.state::<ReleasePresence>(),
            link_id,
            leaf_certificate_der,
            now,
        )
    }

    fn capture_snapshot(
        &self,
        state: &PcLinkState,
        link_id: &str,
        leaf_certificate_der: &[u8],
        now: u64,
    ) -> VaultResult<SnapshotLease> {
        state.capture_snapshot_at(
            &self.app.state::<VaultState>(),
            link_id,
            leaf_certificate_der,
            now,
        )
    }

    fn lease_next_chunk(&self, lease: &mut SnapshotLease) -> VaultResult<Option<Vec<u8>>> {
        lease.next_chunk(&self.app.state::<VaultState>())
    }

    fn on_authority_changed(&self) {
        if let Some(service) = self.app.try_state::<PcLinkService>() {
            service.on_authority_changed();
        }
    }
}

#[derive(Clone, Default)]
pub struct PcLinkService {
    inner: Arc<Mutex<Option<ServiceInner>>>,
}

struct ServiceInner {
    state: Arc<PcLinkState>,
    retrieval_port: Option<u16>,
    retrieval_tls: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    pairing_tls: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    retrieval: Option<ListenerSet>,
    pairing: Option<PairingRuntime>,
    discovery: Option<Discovery>,
    discovery_error: Option<String>,
    pairing_generation: u64,
}

struct PairingRuntime {
    generation: u64,
    port: u16,
    expires_at: u64,
    deadline: Instant,
    window: Arc<Mutex<Option<PairingWindow>>>,
    tls: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    listener: ListenerSet,
}

#[derive(Clone)]
struct ListenerSpec {
    host: Arc<dyn PcLinkHost>,
    state: Arc<PcLinkState>,
    retrieval_port: u16,
    retrieval_tls: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    pairing_tls: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    mode: ListenerMode,
    window: Option<Arc<Mutex<Option<PairingWindow>>>>,
    allow_loopback: bool,
}

struct ListenerSet {
    tasks: Vec<tauri::async_runtime::JoinHandle<()>>,
}

impl ListenerSet {
    fn start(spec: ListenerSpec, listeners: Vec<StdTcpListener>) -> Self {
        let tasks = listeners
            .into_iter()
            .map(|listener| spawn_accept_loop(spec.clone(), listener))
            .collect();
        Self { tasks }
    }

    fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for ListenerSet {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy)]
enum ListenerMode {
    Retrieval,
    Pairing,
}

#[derive(Clone)]
struct HttpContext {
    host: Arc<dyn PcLinkHost>,
    state: Arc<PcLinkState>,
    retrieval_port: u16,
    retrieval_tls: Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    pairing_tls: Option<Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>>,
    pairing_window: Option<Arc<Mutex<Option<PairingWindow>>>>,
    mode: ListenerMode,
}

enum ServiceBody {
    Full(Full<Bytes>),
    Lease(Box<LeaseBody>),
}

struct LeaseBody {
    host: Arc<dyn PcLinkHost>,
    lease: SnapshotLease,
}

impl Unpin for LeaseBody {}

impl Body for LeaseBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.host.lease_next_chunk(&mut this.lease) {
            Ok(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(Bytes::from(bytes))))),
            Ok(None) => Poll::Ready(None),
            Err(error) => Poll::Ready(Some(Err(std::io::Error::other(error)))),
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.lease.remaining_bytes() as u64)
    }

    fn is_end_stream(&self) -> bool {
        false
    }
}

impl Body for ServiceBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Full(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|frame| frame.map(|result| result.map_err(|never| match never {}))),
            Self::Lease(body) => Pin::new(body.as_mut()).poll_frame(cx),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Full(body) => body.size_hint(),
            Self::Lease(body) => body.as_ref().size_hint(),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(body) => body.is_end_stream(),
            Self::Lease(body) => body.as_ref().is_end_stream(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PcLinkStatus {
    pub desktop_fingerprint: Option<String>,
    pub retrieval_port: Option<u16>,
    pub discovery_available: bool,
    pub discovery_hostname: Option<String>,
    pub discovery_error: Option<String>,
    pub links: Vec<LinkedPhone>,
    pub pairing: Option<PairingWindowView>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedPhone {
    pub link_id: String,
    pub label: String,
    pub phone_public_key_fingerprint: String,
    pub approved_at: u64,
    pub not_after: i64,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PairingWindowView {
    pub code: String,
    pub port: u16,
    pub expires_at: u64,
    pub enrollments: Vec<PairingEnrollmentView>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PairingEnrollmentView {
    pub enrollment_id: String,
    pub label: String,
    pub phone_public_key_fingerprint: String,
    pub state: PairingState,
}

impl ServiceInner {
    fn new(state: Arc<PcLinkState>) -> Self {
        Self {
            state,
            retrieval_port: None,
            retrieval_tls: Arc::new(RwLock::new(None)),
            pairing_tls: Arc::new(RwLock::new(None)),
            retrieval: None,
            pairing: None,
            discovery: None,
            discovery_error: None,
            pairing_generation: 0,
        }
    }
}

impl PcLinkService {
    pub fn status(&self, host: &Arc<dyn PcLinkHost>) -> VaultResult<PcLinkStatus> {
        if !self.ensure_open(host, false)? {
            return Ok(cold_status());
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
        let Some(inner) = guard.as_mut() else {
            return Ok(cold_status());
        };
        if inner
            .pairing
            .as_ref()
            .is_some_and(|pairing| pairing.deadline <= Instant::now())
        {
            stop_pairing_locked(inner);
        }
        let active = !inner.state.all_active_link_authorities()?.is_empty();
        if active && inner.retrieval.is_none() {
            start_serving(host, inner)?;
        }
        if !active && inner.pairing.is_none() {
            stop_serving(inner);
            inner
                .state
                .remove_authority_if_no_active(unix_timestamp())?;
        }
        let links = match host.selected_vault() {
            Ok((vault_id, _, _)) => inner
                .state
                .approved_peers(&vault_id)?
                .into_iter()
                .map(|peer| LinkedPhone {
                    link_id: peer.link_id().to_string(),
                    label: peer.label().to_string(),
                    phone_public_key_fingerprint: peer.phone_public_key_fingerprint().to_hex(),
                    approved_at: peer.approved_at(),
                    not_after: peer.not_after_unix(),
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        Ok(PcLinkStatus {
            desktop_fingerprint: Some(inner.state.desktop_certificate().fingerprint_hex()),
            retrieval_port: inner.retrieval_port,
            discovery_available: inner.discovery.is_some(),
            discovery_hostname: inner
                .discovery
                .as_ref()
                .map(|discovery| discovery.hostname().to_string()),
            discovery_error: inner.discovery_error.clone(),
            links,
            pairing: pairing_view(inner),
        })
    }

    pub fn start_pairing(&self, host: &Arc<dyn PcLinkHost>) -> VaultResult<PcLinkStatus> {
        let window = PairingWindow::new(unix_timestamp())?;
        self.start_pairing_with_window(host, window)
    }

    #[cfg(test)]
    pub(crate) fn start_pairing_with_code(
        &self,
        host: &Arc<dyn PcLinkHost>,
        code: &str,
    ) -> VaultResult<PcLinkStatus> {
        let window = PairingWindow::new_with_code(unix_timestamp(), code.to_string())?;
        self.start_pairing_with_window(host, window)
    }

    fn start_pairing_with_window(
        &self,
        host: &Arc<dyn PcLinkHost>,
        window: PairingWindow,
    ) -> VaultResult<PcLinkStatus> {
        if !self.ensure_open(host, true)? {
            return Err("Sesame could not start the PC link service.".to_string());
        }
        let (_, _, session_epoch) = host.selected_vault()?;
        host.require_presence(session_epoch)?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
        let inner = guard
            .as_mut()
            .ok_or_else(|| "Sesame could not start the PC link service.".to_string())?;
        if inner.pairing.is_some() {
            stop_pairing_locked(inner);
        }
        if inner.retrieval.is_none() {
            start_serving(host, inner)?;
        }
        let expires_at = window.expires_at;
        let deadline = window.deadline();
        let (port, listeners) = host.bind_listeners(0)?;
        let window = Arc::new(Mutex::new(Some(window)));
        let tls = Arc::clone(&inner.pairing_tls);
        refresh_pairing_tls(&inner.state, &tls)?;
        let listener = ListenerSet::start(
            ListenerSpec {
                host: Arc::clone(host),
                state: Arc::clone(&inner.state),
                retrieval_port: inner
                    .retrieval_port
                    .ok_or_else(|| "Sesame could not start the PC link service.".to_string())?,
                retrieval_tls: Arc::clone(&inner.retrieval_tls),
                pairing_tls: Arc::clone(&tls),
                mode: ListenerMode::Pairing,
                window: Some(Arc::clone(&window)),
                allow_loopback: host.allow_loopback(),
            },
            listeners,
        );
        inner.pairing_generation = inner.pairing_generation.saturating_add(1);
        let generation = inner.pairing_generation;
        inner.pairing = Some(PairingRuntime {
            generation,
            port,
            expires_at,
            deadline,
            window,
            tls,
            listener,
        });
        if let Some(discovery) = &inner.discovery {
            let _ = discovery.set_pairing_port(Some(port));
        }
        spawn_pairing_watchdog(Arc::clone(&self.inner), generation, deadline);
        drop(guard);
        self.status(host)
    }

    pub fn cancel_pairing(&self, host: &Arc<dyn PcLinkHost>) -> VaultResult<PcLinkStatus> {
        if self.ensure_open(host, false)? {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
            if let Some(inner) = guard.as_mut() {
                stop_pairing_locked(inner);
            }
        }
        self.status(host)
    }

    pub fn confirm_pairing(
        &self,
        host: &Arc<dyn PcLinkHost>,
        enrollment_id: &str,
    ) -> VaultResult<PcLinkStatus> {
        if !self.ensure_open(host, false)? {
            return Err("Open the pairing window before confirming a phone.".to_string());
        }
        let (state, window, tls) = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
            let inner = guard
                .as_ref()
                .ok_or_else(|| "Sesame could not start the PC link service.".to_string())?;
            let pairing = inner
                .pairing
                .as_ref()
                .ok_or_else(|| "Open the pairing window before confirming a phone.".to_string())?;
            if pairing.deadline <= Instant::now() {
                return Err("This pairing window has expired. Start pairing again.".to_string());
            }
            (
                Arc::clone(&inner.state),
                Arc::clone(&pairing.window),
                Arc::clone(&pairing.tls),
            )
        };
        let commit = host.confirm_pairing(&state, enrollment_id, unix_timestamp())?;
        {
            let mut window = window
                .lock()
                .map_err(|_| "Sesame could not read the pairing window.".to_string())?;
            let window = window
                .as_mut()
                .ok_or_else(|| "This pairing window has closed.".to_string())?;
            let enrollment = window
                .enrollment_mut(enrollment_id)
                .ok_or_else(|| "This pairing request is no longer available.".to_string())?;
            enrollment.state = PairingState::Confirmed;
            enrollment.link_id = Some(commit.link_id().to_string());
        }
        refresh_pairing_tls(&state, &tls)?;
        self.status(host)
    }

    pub fn reject_pairing(
        &self,
        host: &Arc<dyn PcLinkHost>,
        enrollment_id: &str,
    ) -> VaultResult<PcLinkStatus> {
        if !self.ensure_open(host, false)? {
            return Err("This pairing window has closed.".to_string());
        }
        let (state, window, tls) = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
            let inner = guard
                .as_ref()
                .ok_or_else(|| "Sesame could not start the PC link service.".to_string())?;
            let pairing = inner
                .pairing
                .as_ref()
                .ok_or_else(|| "This pairing window has closed.".to_string())?;
            (
                Arc::clone(&inner.state),
                Arc::clone(&pairing.window),
                Arc::clone(&pairing.tls),
            )
        };
        state.cancel_pairing(enrollment_id);
        if let Ok(mut window) = window.lock() {
            if let Some(window) = window.as_mut() {
                if let Some(enrollment) = window.enrollment_mut(enrollment_id) {
                    enrollment.state = PairingState::Rejected;
                }
            }
        }
        refresh_pairing_tls(&state, &tls)?;
        self.status(host)
    }

    pub fn revoke_link(
        &self,
        host: &Arc<dyn PcLinkHost>,
        link_id: &str,
    ) -> VaultResult<PcLinkStatus> {
        if !self.ensure_open(host, false)? {
            return Ok(cold_status());
        }
        let (state, retrieval_tls, pairing_tls) = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
            let inner = guard
                .as_ref()
                .ok_or_else(|| "Sesame could not start the PC link service.".to_string())?;
            (
                Arc::clone(&inner.state),
                Arc::clone(&inner.retrieval_tls),
                inner
                    .pairing
                    .as_ref()
                    .map(|pairing| Arc::clone(&pairing.tls)),
            )
        };
        let (vault_id, _, _) = host.selected_vault()?;
        state.revoke_peer(&vault_id, link_id)?;
        refresh_tls_configs(&state, &retrieval_tls, pairing_tls.as_ref())?;
        state.remove_authority_if_no_active(unix_timestamp())?;
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
            if let Some(inner) = guard.as_mut() {
                if inner.pairing.is_none() && inner.state.all_active_link_authorities()?.is_empty()
                {
                    stop_serving(inner);
                }
            }
        }
        self.status(host)
    }

    pub fn on_vault_locked(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(inner) = guard.as_mut() {
                stop_pairing_locked(inner);
                inner.state.discard_pending_pairings();
            }
        }
    }

    fn on_authority_changed(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            if let Some(inner) = guard.as_mut() {
                if inner.pairing.is_none()
                    && inner
                        .state
                        .all_active_link_authorities()
                        .map(|authorities| authorities.is_empty())
                        .unwrap_or(false)
                {
                    stop_serving(inner);
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn rebind_retrieval_for_test(
        &self,
        host: &Arc<dyn PcLinkHost>,
    ) -> VaultResult<PcLinkStatus> {
        if !self.ensure_open(host, false)? {
            return Ok(cold_status());
        }
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
            let inner = guard
                .as_mut()
                .ok_or_else(|| "Sesame could not start the PC link service.".to_string())?;
            if inner.state.all_active_link_authorities()?.is_empty() {
                return Err("No active PC link can change its retrieval endpoint.".to_string());
            }
            stop_serving(inner);
            start_serving(host, inner)?;
        }
        self.status(host)
    }

    #[cfg(test)]
    pub(crate) fn inject_state_for_test(&self, state: Arc<PcLinkState>) -> VaultResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
        if guard.is_none() {
            *guard = Some(ServiceInner::new(state));
        }
        Ok(())
    }

    fn ensure_open(&self, host: &Arc<dyn PcLinkHost>, allow_create: bool) -> VaultResult<bool> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Sesame could not read the PC link service.".to_string())?;
        if guard.is_some() {
            return Ok(true);
        }
        if !allow_create && !super::has_authority_file(host.data_dir()) {
            return Ok(false);
        }
        let state = Arc::new(PcLinkState::open(host.data_dir())?);
        let now = unix_timestamp();
        let active = !state.all_active_link_authorities()?.is_empty();
        let mut inner = ServiceInner::new(state);
        if !active {
            inner.state.remove_authority_if_no_active(now)?;
        }
        if active {
            start_serving(host, &mut inner)?;
        }
        *guard = Some(inner);
        Ok(true)
    }
}

fn cold_status() -> PcLinkStatus {
    PcLinkStatus {
        desktop_fingerprint: None,
        retrieval_port: None,
        discovery_available: false,
        discovery_hostname: None,
        discovery_error: None,
        links: Vec::new(),
        pairing: None,
    }
}

fn start_serving(host: &Arc<dyn PcLinkHost>, inner: &mut ServiceInner) -> VaultResult<()> {
    if inner.retrieval.is_some() {
        return Ok(());
    }
    let (port, listeners) = host.bind_listeners(0)?;
    refresh_retrieval_tls(&inner.state, &inner.retrieval_tls)?;
    let listener = ListenerSet::start(
        ListenerSpec {
            host: Arc::clone(host),
            state: Arc::clone(&inner.state),
            retrieval_port: port,
            retrieval_tls: Arc::clone(&inner.retrieval_tls),
            pairing_tls: Arc::clone(&inner.pairing_tls),
            mode: ListenerMode::Retrieval,
            window: None,
            allow_loopback: host.allow_loopback(),
        },
        listeners,
    );
    let fingerprint = inner.state.desktop_certificate().fingerprint_hex();
    let (discovery, discovery_error) = if host.enable_discovery() {
        match Discovery::start(port, fingerprint) {
            Ok(discovery) => (Some(discovery), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    inner.retrieval = Some(listener);
    inner.retrieval_port = Some(port);
    inner.discovery = discovery;
    inner.discovery_error = discovery_error;
    Ok(())
}

fn stop_serving(inner: &mut ServiceInner) {
    inner.retrieval.take();
    inner.retrieval_port = None;
    inner.discovery.take();
    inner.discovery_error = None;
}

fn pairing_view(inner: &ServiceInner) -> Option<PairingWindowView> {
    let pairing = inner.pairing.as_ref()?;
    let window = pairing.window.lock().ok()?;
    let window = window.as_ref()?;
    Some(PairingWindowView {
        code: window.code.to_string(),
        port: pairing.port,
        expires_at: pairing.expires_at,
        enrollments: window
            .enrollments
            .values()
            .map(|enrollment| PairingEnrollmentView {
                enrollment_id: enrollment.enrollment_id.clone(),
                label: enrollment.label.clone(),
                phone_public_key_fingerprint: enrollment.phone_public_key_fingerprint.to_hex(),
                state: enrollment.state,
            })
            .collect(),
    })
}

fn stop_pairing_locked(inner: &mut ServiceInner) {
    if let Some(mut pairing) = inner.pairing.take() {
        if let Ok(mut window) = pairing.window.lock() {
            if let Some(window) = window.as_mut() {
                window.expire_all();
            }
            *window = None;
        }
        pairing.listener.stop();
        if let Some(discovery) = &inner.discovery {
            let _ = discovery.set_pairing_port(None);
        }
    }
    inner.state.discard_pending_pairings();
    let active = inner
        .state
        .all_active_link_authorities()
        .map(|authorities| !authorities.is_empty())
        .unwrap_or(true);
    if !active {
        stop_serving(inner);
        let _ = inner.state.remove_authority_if_no_active(unix_timestamp());
    }
}

fn spawn_pairing_watchdog(
    inner: Arc<Mutex<Option<ServiceInner>>>,
    generation: u64,
    deadline: Instant,
) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline + Duration::from_secs(PAIRING_GRACE_SECONDS),
        ))
        .await;
        if let Ok(mut guard) = inner.lock() {
            if let Some(inner) = guard.as_mut() {
                if inner
                    .pairing
                    .as_ref()
                    .is_some_and(|pairing| pairing.generation == generation)
                {
                    stop_pairing_locked(inner);
                }
            }
        }
    });
}

fn bind_listeners(preferred: u16) -> VaultResult<(u16, Vec<StdTcpListener>)> {
    let mut listeners = Vec::new();
    let mut port = preferred;
    if let Ok(listener) = StdTcpListener::bind((Ipv6Addr::UNSPECIFIED, preferred)) {
        port = listener
            .local_addr()
            .map_err(|_| "Sesame could not start the PC link service.".to_string())?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|_| "Sesame could not start the PC link service.".to_string())?;
        listeners.push(listener);
    }
    if let Ok(listener) = StdTcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
        listener
            .set_nonblocking(true)
            .map_err(|_| "Sesame could not start the PC link service.".to_string())?;
        listeners.push(listener);
    }
    if listeners.is_empty() {
        return Err("Sesame could not start the PC link service.".to_string());
    }
    let port = listeners[0]
        .local_addr()
        .map_err(|_| "Sesame could not start the PC link service.".to_string())?
        .port();
    Ok((port, listeners))
}

fn spawn_accept_loop(
    spec: ListenerSpec,
    listener: StdTcpListener,
) -> tauri::async_runtime::JoinHandle<()> {
    let ListenerSpec {
        host,
        state,
        retrieval_port,
        retrieval_tls,
        pairing_tls,
        mode,
        window,
        allow_loopback,
    } = spec;
    tauri::async_runtime::spawn(async move {
        let listener = match TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(_) => return,
        };
        let semaphore = Arc::new(Semaphore::new(CONCURRENT_CONNECTIONS));
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => break,
            };
            if !is_allowed_peer(peer.ip(), allow_loopback) {
                continue;
            }
            let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                continue;
            };
            let listener_tls = if matches!(mode, ListenerMode::Pairing) {
                &pairing_tls
            } else {
                &retrieval_tls
            };
            let current = listener_tls.read().ok().and_then(|config| config.clone());
            let Some(config) = current else {
                continue;
            };
            let context = HttpContext {
                host: Arc::clone(&host),
                state: Arc::clone(&state),
                retrieval_port,
                retrieval_tls: Arc::clone(&retrieval_tls),
                pairing_tls: Some(Arc::clone(&pairing_tls)),
                pairing_window: window.clone(),
                mode,
            };
            tauri::async_runtime::spawn(async move {
                let _permit = permit;
                let acceptor = TlsAcceptor::from(config);
                let tls_stream =
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => stream,
                        _ => return,
                    };
                let leaf = tls_stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|certificates| certificates.first())
                    .map(|certificate| certificate.to_vec());
                let service = service_fn(move |request| {
                    handle_request(request, context.clone(), leaf.clone())
                });
                let mut builder = http1::Builder::new();
                builder
                    .keep_alive(false)
                    .max_headers(MAX_HEADERS)
                    .max_buf_size(MAX_HEADER_BYTES + 1024)
                    .header_read_timeout(HEADER_TIMEOUT)
                    .timer(TokioTimer::new());
                let connection = builder.serve_connection(TokioIo::new(tls_stream), service);
                let _ = tokio::time::timeout(SNAPSHOT_TIMEOUT, connection).await;
            });
        }
    })
}

async fn handle_request(
    request: Request<Incoming>,
    context: HttpContext,
    leaf: Option<Vec<u8>>,
) -> Result<Response<ServiceBody>, std::convert::Infallible> {
    let response = match validate_common(&request) {
        Err((status, error)) => error_response(status, error),
        Ok(()) => match context.mode {
            ListenerMode::Pairing => handle_pairing(request, &context, leaf.as_deref()).await,
            ListenerMode::Retrieval => handle_retrieval(request, &context, leaf.as_deref()).await,
        },
    };
    Ok(response)
}

fn validate_common<B>(request: &Request<B>) -> Result<(), (StatusCode, &'static str)> {
    if request.method() != Method::POST {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    }
    if request.uri().query().is_some()
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    }
    if request.headers().contains_key(ORIGIN) || request.headers().contains_key(REFERER) {
        return Err((StatusCode::FORBIDDEN, ERROR_FORBIDDEN));
    }
    if request.headers().contains_key(CONTENT_ENCODING)
        || request.headers().contains_key(TRANSFER_ENCODING)
        || request.headers().contains_key(COOKIE)
        || request.headers().contains_key(UPGRADE)
    {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    }
    let header_bytes = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len().saturating_add(value.as_bytes().len()))
        .sum::<usize>();
    if header_bytes > MAX_HEADER_BYTES {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    }
    Ok(())
}

async fn handle_pairing(
    request: Request<Incoming>,
    context: &HttpContext,
    leaf: Option<&[u8]>,
) -> Response<ServiceBody> {
    let path = request.uri().path();
    match path {
        ENROLL_PATH => handle_enroll(request, context).await,
        STATUS_PATH => handle_status(request, context).await,
        ACTIVATE_PATH => handle_activate(request, context, leaf).await,
        COMMIT_PATH => handle_commit(request, context, leaf).await,
        _ => error_response(StatusCode::NOT_FOUND, ERROR_INVALID),
    }
}

async fn handle_retrieval(
    request: Request<Incoming>,
    context: &HttpContext,
    leaf: Option<&[u8]>,
) -> Response<ServiceBody> {
    let Some((link_id, operation)) = link_route(request.uri().path()) else {
        return error_response(StatusCode::NOT_FOUND, ERROR_INVALID);
    };
    let Some(leaf) = leaf else {
        return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
    };
    match operation {
        "snapshot" => handle_snapshot(request, context, &link_id, leaf).await,
        "revoke" => handle_revoke(request, context, &link_id, leaf).await,
        _ => error_response(StatusCode::NOT_FOUND, ERROR_INVALID),
    }
}

fn link_route(path: &str) -> Option<(String, &str)> {
    let mut parts = path.split('/');
    if parts.next() != Some("") || parts.next() != Some("v1") || parts.next() != Some("links") {
        return None;
    }
    let link_id = parts.next()?;
    let operation = parts.next()?;
    if parts.next().is_some() || !is_identifier(link_id) {
        return None;
    }
    Some((link_id.to_string(), operation))
}

async fn handle_enroll(request: Request<Incoming>, context: &HttpContext) -> Response<ServiceBody> {
    let body: EnrollRequest = match json_body(request).await {
        Ok(body) => body,
        Err((status, error)) => return error_response(status, error),
    };
    if body.v != WIRE_VERSION || !is_identifier(&body.enrollment_id) || !is_pairing_code(&body.code)
    {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let phone_public_key = match URL_SAFE_NO_PAD.decode(body.phone_public_key.as_bytes()) {
        Ok(key) => key,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID),
    };
    if validate_phone_public_key(&phone_public_key).is_err() {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let Some(window) = &context.pairing_window else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    let mut window = match window.lock() {
        Ok(window) => window,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE),
    };
    let Some(pairing) = window.as_mut() else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    if pairing.is_expired() {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    }
    if !pairing.verify_code(&body.code) {
        let status = if pairing.failed_attempts >= 5 {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::FORBIDDEN
        };
        return error_response(
            status,
            if status == StatusCode::TOO_MANY_REQUESTS {
                ERROR_RATE_LIMITED
            } else {
                ERROR_FORBIDDEN
            },
        );
    }
    if pairing.enrollment(&body.enrollment_id).is_some() {
        return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
    }
    if let Err(error) = context.host.begin_pairing(
        &context.state,
        &phone_public_key,
        &body.label,
        body.enrollment_id.clone(),
        unix_timestamp(),
    ) {
        return core_error_response(&error);
    }
    if pairing
        .enroll(body.enrollment_id.clone(), body.label, phone_public_key)
        .is_err()
    {
        context.state.cancel_pairing(&body.enrollment_id);
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    json_response(
        StatusCode::OK,
        &EnrollResponse {
            v: WIRE_VERSION,
            enrollment_id: body.enrollment_id,
            state: PairingState::PendingConfirmation,
            expires_at: pairing.expires_at,
        },
    )
}

async fn handle_status(request: Request<Incoming>, context: &HttpContext) -> Response<ServiceBody> {
    let body: StatusRequest = match json_body(request).await {
        Ok(body) => body,
        Err((status, error)) => return error_response(status, error),
    };
    if body.v != WIRE_VERSION || !is_identifier(&body.enrollment_id) || !is_pairing_code(&body.code)
    {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let Some(window) = &context.pairing_window else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    let mut window = match window.lock() {
        Ok(window) => window,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE),
    };
    let Some(pairing) = window.as_mut() else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    if pairing.is_expired() {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    }
    if !pairing.verify_code(&body.code) {
        let status = if pairing.failed_attempts >= 5 {
            StatusCode::TOO_MANY_REQUESTS
        } else {
            StatusCode::FORBIDDEN
        };
        return error_response(
            status,
            if status == StatusCode::TOO_MANY_REQUESTS {
                ERROR_RATE_LIMITED
            } else {
                ERROR_FORBIDDEN
            },
        );
    }
    let Some(enrollment) = pairing.enrollment(&body.enrollment_id) else {
        return error_response(StatusCode::NOT_FOUND, ERROR_UNKNOWN_LINK);
    };
    let state = enrollment.state;
    let mut response = StatusResponse {
        v: WIRE_VERSION,
        state,
        client_certificate: None,
        client_ca: None,
        retrieval_port: None,
    };
    if state == PairingState::Confirmed {
        let Some(commit) = context
            .state
            .pending_commit_for_request(&body.enrollment_id)
        else {
            return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
        };
        response.client_certificate = Some(URL_SAFE_NO_PAD.encode(commit.leaf_certificate_der()));
        response.client_ca = Some(URL_SAFE_NO_PAD.encode(commit.certificate_authority_der()));
        response.retrieval_port = Some(context.retrieval_port);
    }
    json_response(StatusCode::OK, &response)
}

async fn handle_activate(
    request: Request<Incoming>,
    context: &HttpContext,
    leaf: Option<&[u8]>,
) -> Response<ServiceBody> {
    let Some(leaf) = leaf else {
        return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
    };
    let body: ActivateRequest = match json_body(request).await {
        Ok(body) => body,
        Err((status, error)) => return error_response(status, error),
    };
    if body.v != WIRE_VERSION || !is_identifier(&body.enrollment_id) {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let Some(window) = &context.pairing_window else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    let mut window = match window.lock() {
        Ok(window) => window,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE),
    };
    let Some(pairing) = window.as_mut() else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    if pairing.is_expired() {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    }
    let Some(enrollment) = pairing.enrollment_mut(&body.enrollment_id) else {
        return error_response(StatusCode::NOT_FOUND, ERROR_UNKNOWN_LINK);
    };
    if enrollment.state == PairingState::PendingCommit || enrollment.state == PairingState::Active {
        let Some(link_id) = enrollment.link_id.clone() else {
            return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
        };
        let state = enrollment.state;
        let (vault_id, vault_name, _) = match context.host.selected_vault() {
            Ok(vault) => vault,
            Err(_) => return error_response(StatusCode::LOCKED, ERROR_LOCKED),
        };
        let expected_leaf = context
            .state
            .pending_commit(&link_id)
            .map(|commit| commit.leaf_certificate_der().to_vec())
            .or_else(|| {
                context
                    .state
                    .approved_peers(&vault_id)
                    .ok()
                    .and_then(|peers| {
                        peers
                            .into_iter()
                            .find(|peer| peer.link_id() == link_id)
                            .map(|peer| peer.leaf_certificate_der().to_vec())
                    })
            });
        if expected_leaf.as_deref() != Some(leaf) {
            return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
        }
        return json_response(
            StatusCode::OK,
            &ActivateResponse {
                v: WIRE_VERSION,
                link_id,
                vault_id,
                vault_name,
                state,
            },
        );
    }
    if enrollment.state != PairingState::Confirmed {
        return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
    }
    let Some(commit) = context
        .state
        .pending_commit_for_request(&body.enrollment_id)
    else {
        return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
    };
    if commit.leaf_certificate_der() != leaf {
        return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
    }
    let (vault_id, vault_name, _) = match context.host.selected_vault() {
        Ok(vault) => vault,
        Err(_) => return error_response(StatusCode::LOCKED, ERROR_LOCKED),
    };
    if vault_id != commit.vault_id() {
        return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
    }
    enrollment.state = PairingState::PendingCommit;
    enrollment.link_id = Some(commit.link_id().to_string());
    json_response(
        StatusCode::OK,
        &ActivateResponse {
            v: WIRE_VERSION,
            link_id: commit.link_id().to_string(),
            vault_id,
            vault_name,
            state: PairingState::PendingCommit,
        },
    )
}

async fn handle_commit(
    request: Request<Incoming>,
    context: &HttpContext,
    leaf: Option<&[u8]>,
) -> Response<ServiceBody> {
    let Some(leaf) = leaf else {
        return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
    };
    let body: CommitRequest = match json_body(request).await {
        Ok(body) => body,
        Err((status, error)) => return error_response(status, error),
    };
    if body.v != WIRE_VERSION || !is_identifier(&body.link_id) {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let Some(window) = &context.pairing_window else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    let mut window = match window.lock() {
        Ok(window) => window,
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE),
    };
    let Some(pairing) = window.as_mut() else {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    };
    if pairing.is_expired() {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    }
    let Some(enrollment) = pairing
        .enrollments
        .values_mut()
        .find(|enrollment| enrollment.link_id.as_deref() == Some(body.link_id.as_str()))
    else {
        return error_response(StatusCode::NOT_FOUND, ERROR_UNKNOWN_LINK);
    };
    if enrollment.state != PairingState::PendingCommit && enrollment.state != PairingState::Active {
        return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
    }
    match context
        .host
        .commit_pairing(&context.state, &body.link_id, leaf, unix_timestamp())
    {
        Ok(_) => {
            enrollment.state = PairingState::Active;
            if refresh_tls_configs(
                &context.state,
                &context.retrieval_tls,
                context.pairing_tls.as_ref(),
            )
            .is_err()
            {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE);
            }
            json_response(
                StatusCode::OK,
                &CommitResponse {
                    v: WIRE_VERSION,
                    state: PairingState::Active,
                },
            )
        }
        Err(error) => core_error_response(&error),
    }
}

async fn handle_snapshot(
    request: Request<Incoming>,
    context: &HttpContext,
    link_id: &str,
    leaf: &[u8],
) -> Response<ServiceBody> {
    if !empty_request(&request) {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let (vault_id, _, _) = match context.host.selected_vault() {
        Ok(vault) => vault,
        Err(_) => return error_response(StatusCode::LOCKED, ERROR_LOCKED),
    };
    if let Some(response) = grant_status(context, &vault_id, link_id, leaf) {
        return response;
    }
    match context
        .host
        .capture_snapshot(&context.state, link_id, leaf, unix_timestamp())
    {
        Ok(lease) => snapshot_response(lease, Arc::clone(&context.host)),
        Err(error) => core_error_response(&error),
    }
}

async fn handle_revoke(
    request: Request<Incoming>,
    context: &HttpContext,
    link_id: &str,
    leaf: &[u8],
) -> Response<ServiceBody> {
    let body: RevokeRequest = match json_body(request).await {
        Ok(body) => body,
        Err((status, error)) => return error_response(status, error),
    };
    if body.v != WIRE_VERSION || body.link_id != link_id {
        return error_response(StatusCode::BAD_REQUEST, ERROR_INVALID);
    }
    let (vault_id, _, _) = match context.host.selected_vault() {
        Ok(vault) => vault,
        Err(_) => return error_response(StatusCode::LOCKED, ERROR_LOCKED),
    };
    if let Some(response) = grant_status(context, &vault_id, link_id, leaf) {
        return response;
    }
    match context.state.revoke_peer(&vault_id, link_id) {
        Ok(true) => {
            context
                .state
                .remove_authority_if_no_active(unix_timestamp())
                .ok();
            refresh_tls_configs(
                &context.state,
                &context.retrieval_tls,
                context.pairing_tls.as_ref(),
            )
            .ok();
            context.host.on_authority_changed();
            json_response(
                StatusCode::OK,
                &RevokeResponse {
                    v: WIRE_VERSION,
                    state: "revoked",
                },
            )
        }
        Ok(false) => error_response(StatusCode::NOT_FOUND, ERROR_UNKNOWN_LINK),
        Err(error) => core_error_response(&error),
    }
}

fn grant_status(
    context: &HttpContext,
    vault_id: &str,
    link_id: &str,
    leaf: &[u8],
) -> Option<Response<ServiceBody>> {
    let peers = match context.state.approved_peers(vault_id) {
        Ok(peers) => peers,
        Err(_) => {
            return Some(error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                ERROR_UNAVAILABLE,
            ))
        }
    };
    let Some(peer) = peers.iter().find(|peer| peer.link_id() == link_id) else {
        return Some(error_response(StatusCode::NOT_FOUND, ERROR_UNKNOWN_LINK));
    };
    if peer.is_expired(unix_timestamp()) {
        return Some(error_response(StatusCode::GONE, ERROR_EXPIRED));
    }
    if peer.leaf_certificate_der() != leaf {
        return Some(error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN));
    }
    None
}

async fn json_body<T: DeserializeOwned>(
    request: Request<Incoming>,
) -> Result<T, (StatusCode, &'static str)> {
    let length = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    let Some(length) = length else {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    };
    if length == 0 || length > MAX_JSON_REQUEST_BYTES {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    }
    let body = request.into_body();
    let collected = match tokio::time::timeout(
        BODY_TIMEOUT,
        Limited::new(body, MAX_JSON_REQUEST_BYTES).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected,
        _ => return Err((StatusCode::BAD_REQUEST, ERROR_INVALID)),
    };
    let bytes = collected.to_bytes();
    if bytes.len() != length {
        return Err((StatusCode::BAD_REQUEST, ERROR_INVALID));
    }
    serde_json::from_slice(&bytes).map_err(|_| (StatusCode::BAD_REQUEST, ERROR_INVALID))
}

fn empty_request<B>(request: &Request<B>) -> bool {
    match request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
    {
        None | Some(0) => true,
        Some(_) => false,
    }
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<ServiceBody> {
    let body = match serde_json::to_vec(value) {
        Ok(body) if body.len() <= MAX_JSON_RESPONSE_BYTES => body,
        _ => return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE),
    };
    let length = body.len();
    let mut response = Response::new(ServiceBody::Full(Full::new(Bytes::from(body))));
    *response.status_mut() = status;
    set_header(&mut response, CONTENT_TYPE, JSON_MEDIA_TYPE);
    set_header(&mut response, CACHE_CONTROL, "no-store");
    set_header(&mut response, CONNECTION, "close");
    set_content_length(&mut response, length);
    response
}

fn error_response(status: StatusCode, error: &'static str) -> Response<ServiceBody> {
    let body = serde_json::to_vec(&ErrorResponse {
        v: WIRE_VERSION,
        error,
    })
    .unwrap_or_else(|_| b"{\"v\":1,\"error\":\"unavailable\"}".to_vec());
    let length = body.len();
    let mut response = Response::new(ServiceBody::Full(Full::new(Bytes::from(body))));
    *response.status_mut() = status;
    set_header(&mut response, CONTENT_TYPE, JSON_MEDIA_TYPE);
    set_header(&mut response, CACHE_CONTROL, "no-store");
    set_header(&mut response, CONNECTION, "close");
    set_content_length(&mut response, length);
    response
}

fn snapshot_response(lease: SnapshotLease, host: Arc<dyn PcLinkHost>) -> Response<ServiceBody> {
    let length = lease.content_length();
    if length == 0 || length > MAX_SNAPSHOT_BYTES {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE);
    }
    let mut response = Response::new(ServiceBody::Lease(Box::new(LeaseBody { host, lease })));
    *response.status_mut() = StatusCode::OK;
    set_header(&mut response, CONTENT_TYPE, SNAPSHOT_MEDIA_TYPE);
    set_header(&mut response, CACHE_CONTROL, "no-store");
    set_header(&mut response, CONNECTION, "close");
    set_content_length(&mut response, length);
    response
}

fn set_content_length(response: &mut Response<ServiceBody>, length: usize) {
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
}

fn set_header(
    response: &mut Response<ServiceBody>,
    name: hyper::header::HeaderName,
    value: &'static str,
) {
    response
        .headers_mut()
        .insert(name, HeaderValue::from_static(value));
}

fn core_error_response(error: &str) -> Response<ServiceBody> {
    if error == PRESENCE_REQUIRED {
        return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
    }
    if error.contains("Unlock") || error.contains("locked") {
        return error_response(StatusCode::LOCKED, ERROR_LOCKED);
    }
    if error.contains("expired") || error.contains("Expired") {
        return error_response(StatusCode::GONE, ERROR_EXPIRED);
    }
    if error.contains("session changed")
        || error.contains("selected vault")
        || error.contains("authority changed")
        || error.contains("already exists")
    {
        return error_response(StatusCode::CONFLICT, ERROR_WRONG_VAULT);
    }
    if error.contains("too quickly") || error.contains("Too many pairing") {
        return error_response(StatusCode::TOO_MANY_REQUESTS, ERROR_RATE_LIMITED);
    }
    if error.contains("not approved")
        || error.contains("not valid")
        || error.contains("certificate")
    {
        return error_response(StatusCode::FORBIDDEN, ERROR_FORBIDDEN);
    }
    error_response(StatusCode::SERVICE_UNAVAILABLE, ERROR_UNAVAILABLE)
}

fn refresh_tls_configs(
    state: &PcLinkState,
    retrieval_tls: &Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
    pairing_tls: Option<&Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>>,
) -> VaultResult<()> {
    refresh_retrieval_tls(state, retrieval_tls)?;
    if let Some(pairing_tls) = pairing_tls {
        refresh_pairing_tls(state, pairing_tls)?;
    }
    Ok(())
}

fn refresh_retrieval_tls(
    state: &PcLinkState,
    tls: &Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
) -> VaultResult<()> {
    let authorities = state.all_active_link_authorities()?;
    let config = if authorities.is_empty() {
        None
    } else {
        Some(build_server_config(state, &authorities, true)?)
    };
    *tls.write()
        .map_err(|_| "Sesame could not prepare PC link TLS.".to_string())? = config;
    Ok(())
}

fn refresh_pairing_tls(
    state: &PcLinkState,
    tls: &Arc<RwLock<Option<Arc<rustls::ServerConfig>>>>,
) -> VaultResult<()> {
    let authorities = state.pairing_trust_authorities()?;
    let config = build_server_config(state, &authorities, false)?;
    *tls.write()
        .map_err(|_| "Sesame could not prepare PC link TLS.".to_string())? = Some(config);
    Ok(())
}

fn build_server_config(
    state: &PcLinkState,
    authorities: &[Vec<u8>],
    mandatory: bool,
) -> VaultResult<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for authority in authorities {
        roots
            .add(CertificateDer::from(authority.clone()))
            .map_err(|_| "Sesame could not prepare PC link TLS.".to_string())?;
    }
    if mandatory && roots.is_empty() {
        return Err("Sesame could not prepare PC link TLS.".to_string());
    }
    let verifier = if roots.is_empty() {
        WebPkiClientVerifier::no_client_auth()
    } else {
        let builder = WebPkiClientVerifier::builder(Arc::new(roots));
        if mandatory {
            builder
                .build()
                .map_err(|_| "Sesame could not prepare PC link TLS.".to_string())?
        } else {
            builder
                .allow_unauthenticated()
                .build()
                .map_err(|_| "Sesame could not prepare PC link TLS.".to_string())?
        }
    };
    let certificate = CertificateDer::from(state.desktop_certificate().certificate_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(state.private_key_der().to_vec()));
    let mut config =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![certificate], key)
            .map_err(|_| "Sesame could not prepare PC link TLS.".to_string())?;
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

fn is_allowed_peer(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_link_local() || (allow_loopback && ip.is_loopback())
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return ip.is_private()
                    || ip.is_link_local()
                    || (allow_loopback && ip.is_loopback());
            }
            if allow_loopback && ip.is_loopback() {
                return true;
            }
            let first = ip.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::TestVault;
    use crate::pc_link::envelope::TestProtection;
    use crate::pc_link::PendingCommit;
    use crate::vault::{commit_payload_change, UnlockedVault};
    use rcgen::PublicKeyData;
    use rustls::pki_types::ServerName;
    use sesame_core::api;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;
    use tokio_rustls::TlsConnector;

    struct InjectedHost {
        data_dir: std::path::PathBuf,
        vault: Arc<VaultState>,
        presence: Arc<ReleasePresence>,
        served_bytes: AtomicU64,
        snapshots: AtomicU64,
        committed: AtomicBool,
        bound_ports: Mutex<Vec<u16>>,
    }

    impl InjectedHost {
        fn new(
            data_dir: std::path::PathBuf,
            vault: Arc<VaultState>,
            presence: Arc<ReleasePresence>,
        ) -> Self {
            Self {
                data_dir,
                vault,
                presence,
                served_bytes: AtomicU64::new(0),
                snapshots: AtomicU64::new(0),
                committed: AtomicBool::new(false),
                bound_ports: Mutex::new(Vec::new()),
            }
        }

        fn served_bytes(&self) -> u64 {
            self.served_bytes.load(Ordering::SeqCst)
        }

        fn committed(&self) -> bool {
            self.committed.load(Ordering::SeqCst)
        }

        fn snapshots(&self) -> u64 {
            self.snapshots.load(Ordering::SeqCst)
        }
    }

    impl PcLinkHost for InjectedHost {
        fn data_dir(&self) -> &Path {
            &self.data_dir
        }

        fn selected_vault(&self) -> VaultResult<(String, String, u64)> {
            PcLinkState::selected_vault(&self.vault)
        }

        fn require_presence(&self, epoch: u64) -> VaultResult<()> {
            self.presence.require(epoch)
        }

        fn begin_pairing(
            &self,
            state: &PcLinkState,
            phone_public_key: &[u8],
            label: &str,
            request_id: String,
            now: u64,
        ) -> VaultResult<PendingPairing> {
            state.begin_pairing_with_id_at(&self.vault, phone_public_key, label, request_id, now)
        }

        fn confirm_pairing(
            &self,
            state: &PcLinkState,
            request_id: &str,
            now: u64,
        ) -> VaultResult<PendingCommit> {
            state.confirm_pairing_at(&self.vault, &self.presence, request_id, now)
        }

        fn commit_pairing(
            &self,
            state: &PcLinkState,
            link_id: &str,
            leaf_certificate_der: &[u8],
            now: u64,
        ) -> VaultResult<ApprovedPeer> {
            let result = state.commit_pairing_at(
                &self.vault,
                &self.presence,
                link_id,
                leaf_certificate_der,
                now,
            );
            if result.is_ok() {
                self.committed.store(true, Ordering::SeqCst);
            }
            result
        }

        fn capture_snapshot(
            &self,
            state: &PcLinkState,
            link_id: &str,
            leaf_certificate_der: &[u8],
            now: u64,
        ) -> VaultResult<SnapshotLease> {
            self.snapshots.fetch_add(1, Ordering::SeqCst);
            state.capture_snapshot_at(&self.vault, link_id, leaf_certificate_der, now)
        }

        fn lease_next_chunk(&self, lease: &mut SnapshotLease) -> VaultResult<Option<Vec<u8>>> {
            let chunk = lease.next_chunk(&self.vault);
            if let Ok(Some(bytes)) = &chunk {
                self.served_bytes
                    .fetch_add(bytes.len() as u64, Ordering::SeqCst);
            }
            chunk
        }

        fn bind_listeners(&self, preferred: u16) -> VaultResult<(u16, Vec<StdTcpListener>)> {
            for _ in 0..8 {
                let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, preferred))
                    .map_err(|_| "Sesame could not start the PC link service.".to_string())?;
                listener
                    .set_nonblocking(true)
                    .map_err(|_| "Sesame could not start the PC link service.".to_string())?;
                let port = listener
                    .local_addr()
                    .map_err(|_| "Sesame could not start the PC link service.".to_string())?
                    .port();
                let mut ports = self
                    .bound_ports
                    .lock()
                    .map_err(|_| "Sesame could not start the PC link service.".to_string())?;
                if preferred != 0 || !ports.contains(&port) {
                    ports.push(port);
                    return Ok((port, vec![listener]));
                }
            }
            Err("Sesame could not start the PC link service.".to_string())
        }

        fn allow_loopback(&self) -> bool {
            true
        }

        fn enable_discovery(&self) -> bool {
            false
        }
    }

    fn arc_vault(name: &str) -> (Arc<VaultState>, std::path::PathBuf, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("sesame-pc-link-vault-{name}-{}", unix_timestamp()));
        std::fs::create_dir_all(&root).expect("vault root");
        let vault_path = root.join("vault.sesame");
        let (opened, _) =
            api::create_vault("fictional master password", "Fictional vault").expect("vault");
        let mut session = UnlockedVault::from_opened(vault_path.clone(), &opened).expect("session");
        session.setup_complete = true;
        let mut payload = session.open_payload().expect("payload").clone();
        payload.vault_name = "Fictional vault".to_string();
        commit_payload_change(&mut session, payload).expect("saved vault");
        let state = Arc::new(VaultState::default());
        *state.session.lock().expect("session") = Some(session);
        (state, vault_path, root)
    }

    #[test]
    fn cold_status_is_inert_without_authority() {
        let root = std::env::temp_dir().join(format!("sesame-pc-link-cold-{}", unix_timestamp()));
        std::fs::create_dir_all(&root).expect("root");
        let host: Arc<dyn PcLinkHost> = Arc::new(InjectedHost::new(
            root.clone(),
            Arc::new(VaultState::default()),
            Arc::new(ReleasePresence::default()),
        ));
        let service = PcLinkService::default();
        let status = service.status(&host).expect("cold status");
        assert!(status.desktop_fingerprint.is_none());
        assert!(status.retrieval_port.is_none());
        assert!(status.links.is_empty());
        assert!(status.pairing.is_none());
        assert!(!status.discovery_available);
        assert!(!crate::pc_link::has_authority_file(&root));
        assert!(!root.join("pc-link").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn active_grant_serves_and_last_revoke_stops_listeners_and_discovery() {
        let (vault, _vault_path, vault_root) = arc_vault("lifecycle");
        let pc_root =
            std::env::temp_dir().join(format!("sesame-pc-link-lifecycle-{}", unix_timestamp()));
        let presence = Arc::new(ReleasePresence::default());
        presence.grant_until(
            vault.session_epoch(),
            Instant::now() + Duration::from_secs(600),
        );
        let host: Arc<dyn PcLinkHost> = Arc::new(InjectedHost::new(
            pc_root.clone(),
            Arc::clone(&vault),
            Arc::clone(&presence),
        ));
        let state =
            PcLinkState::open_with_protection(&pc_root, Box::new(TestProtection { fail: false }))
                .expect("state");
        let phone_key = rcgen::KeyPair::generate().expect("phone key");
        let pending = state
            .begin_pairing_at(&vault, phone_key.der_bytes(), "Fictional phone", 1_000)
            .expect("pending");
        let commit = state
            .confirm_pairing_at(&vault, &presence, pending.request_id(), 1_000)
            .expect("confirmed");
        let active = state
            .commit_pairing_at(
                &vault,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .expect("committed");
        drop(state);

        let reopened = Arc::new(
            PcLinkState::open_with_protection(&pc_root, Box::new(TestProtection { fail: false }))
                .expect("reopened"),
        );
        assert_eq!(
            reopened
                .approved_peers(active.vault_id())
                .expect("peers")
                .len(),
            1
        );
        let service = PcLinkService::default();
        service
            .inject_state_for_test(reopened)
            .expect("injected state");
        let status = service.status(&host).expect("status");
        assert!(status.desktop_fingerprint.is_some());
        assert!(status.retrieval_port.is_some());
        assert_eq!(status.links.len(), 1);
        assert!(!status.discovery_available);

        let rebound = service
            .rebind_retrieval_for_test(&host)
            .expect("rebind retrieval");
        assert_eq!(rebound.desktop_fingerprint, status.desktop_fingerprint);
        assert_eq!(rebound.links.len(), 1);
        assert!(rebound.retrieval_port.is_some());
        assert_ne!(rebound.retrieval_port, status.retrieval_port);

        let pairing = service.start_pairing(&host).expect("pairing");
        assert!(pairing.pairing.is_some());
        service.cancel_pairing(&host).expect("cancel pairing");
        let after_cancel = service.status(&host).expect("after cancel");
        assert!(after_cancel.retrieval_port.is_some());
        assert!(after_cancel.pairing.is_none());

        let revoked = service
            .revoke_link(&host, active.link_id())
            .expect("revoked");
        assert!(revoked.links.is_empty());
        assert!(revoked.retrieval_port.is_none());
        assert!(!revoked.discovery_available);
        assert!(!crate::pc_link::has_authority_file(&pc_root));

        let cold_service = PcLinkService::default();
        let cold = cold_service.status(&host).expect("cold status");
        assert!(cold.desktop_fingerprint.is_none());
        assert!(cold.retrieval_port.is_none());
        let _ = std::fs::remove_dir_all(&pc_root);
        let _ = std::fs::remove_dir_all(&vault_root);
    }

    const FIXTURE_PAIRING_CODE: &str = "ABCDEFGHJK";

    struct FixtureCleanup(std::path::PathBuf);

    impl Drop for FixtureCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_password() -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(
            std::env::var("SESAME_PC_LINK_E2E_PASSWORD")
                .unwrap_or_else(|_| "fictional-otter-meadow-42".to_string()),
        )
    }

    fn write_fixture_ready(
        ready_dir: &Path,
        fingerprint: &str,
        pairing_port: u16,
        retrieval_port: u16,
    ) -> std::path::PathBuf {
        crate::vault::create_private_dir(ready_dir).expect("ready dir");
        let ready = serde_json::json!({
            "desktop_fingerprint": fingerprint,
            "pairing_port": pairing_port,
            "retrieval_port": retrieval_port,
        });
        let ready_path = ready_dir.join("ready.json");
        crate::vault::atomic_replace(
            &ready_path,
            &serde_json::to_vec(&ready).expect("ready json"),
        )
        .expect("write ready");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&ready_path)
                    .expect("ready metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        ready_path
    }

    #[test]
    #[ignore = "run with the Android dedicated PC-link test package"]
    fn android_http_transfer_fixture() {
        let artifact = std::env::var_os("SESAME_PC_LINK_E2E_ARTIFACT")
            .map(std::path::PathBuf::from)
            .expect("SESAME_PC_LINK_E2E_ARTIFACT must point to the current desktop artifact");
        let ready_dir = std::env::var_os("SESAME_PC_LINK_E2E_READY_DIR")
            .map(std::path::PathBuf::from)
            .expect("SESAME_PC_LINK_E2E_READY_DIR must point to the private e2e output directory");
        let stop_file = std::env::var_os("SESAME_PC_LINK_E2E_STOP_FILE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| ready_dir.join("stop"));
        let rebind_file = std::env::var_os("SESAME_PC_LINK_E2E_REBIND_FILE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| ready_dir.join("rebind"));
        let timeout = std::env::var("SESAME_PC_LINK_E2E_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(600)
            .clamp(1, 600);
        let data_root = std::env::var_os("SESAME_PC_LINK_E2E_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!("sesame-pc-link-e2e-{}", std::process::id()))
            });
        let _cleanup = FixtureCleanup(data_root.clone());
        crate::vault::create_private_dir(&data_root).expect("fixture data dir");
        let vault_path = data_root.join("vault.sesame");
        crate::vault::copy_private_file(&artifact, &vault_path).expect("copy artifact");
        let source_before = std::fs::read(&vault_path).expect("source bytes");
        assert!(!source_before.is_empty());

        let password = fixture_password();
        let file = sesame_core::loader::VaultLoader::read(&vault_path).expect("artifact envelope");
        let opened = api::open_vault_with_password(&file, &password).expect("artifact password");
        let session = UnlockedVault::from_opened(vault_path.clone(), &opened).expect("session");
        assert!(session.setup_complete);
        let snapshot = session.snapshot();
        assert_eq!(snapshot.vault_id.as_deref(), Some("629onBLQlMmpPc4H"));
        assert_eq!(snapshot.revision, 3);
        let vault_state = Arc::new(VaultState::default());
        *vault_state.session.lock().expect("session") = Some(session);
        let presence = Arc::new(ReleasePresence::default());
        presence.grant_until(
            vault_state.session_epoch(),
            Instant::now() + Duration::from_secs(120),
        );
        let host_impl = Arc::new(InjectedHost::new(
            data_root.clone(),
            Arc::clone(&vault_state),
            Arc::clone(&presence),
        ));
        let host: Arc<dyn PcLinkHost> = Arc::clone(&host_impl) as Arc<dyn PcLinkHost>;
        let state = Arc::new(
            PcLinkState::open_with_protection(&data_root, Box::new(TestProtection { fail: false }))
                .expect("pc link state"),
        );
        let service = PcLinkService::default();
        service
            .inject_state_for_test(state)
            .expect("injected state");
        let status = service
            .start_pairing_with_code(&host, FIXTURE_PAIRING_CODE)
            .expect("pairing window");
        let pairing = status.pairing.as_ref().expect("pairing view");
        let fingerprint = status
            .desktop_fingerprint
            .as_deref()
            .expect("desktop fingerprint");
        let mut retrieval_port = status.retrieval_port.expect("retrieval port");
        let pairing_port = pairing.port;
        let ready_path = write_fixture_ready(&ready_dir, fingerprint, pairing_port, retrieval_port);
        println!("fixture_ready={}", ready_path.display());

        let started = Instant::now();
        let mut confirmed = false;
        let mut observed_commit = false;
        let mut observed_revoke = false;
        while started.elapsed() < Duration::from_secs(timeout) {
            if stop_file.exists() {
                break;
            }
            if rebind_file.exists() {
                let _ = std::fs::remove_file(&rebind_file);
                let rebound = service
                    .rebind_retrieval_for_test(&host)
                    .expect("rebind retrieval");
                retrieval_port = rebound.retrieval_port.expect("rebound retrieval port");
                let _ = write_fixture_ready(&ready_dir, fingerprint, pairing_port, retrieval_port);
            }
            let current = service.status(&host).expect("fixture status");
            if !confirmed {
                let pending = current
                    .pairing
                    .as_ref()
                    .map(|pairing| {
                        pairing
                            .enrollments
                            .iter()
                            .filter(|enrollment| {
                                enrollment.state == PairingState::PendingConfirmation
                                    && enrollment.label == "Sesame test phone"
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if pending.len() > 1 {
                    panic!("more than one enrollment appeared in the fixture window");
                }
                if let Some(enrollment) = pending.first() {
                    service
                        .confirm_pairing(&host, &enrollment.enrollment_id)
                        .expect("fixture confirmation");
                    confirmed = true;
                }
            }
            if host_impl.committed() {
                observed_commit = true;
            }
            if observed_commit && host_impl.snapshots() >= 2 && current.links.is_empty() {
                observed_revoke = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let final_status = service.status(&host).expect("final status");
        assert!(confirmed, "no Android test enrollment reached confirmation");
        assert!(
            host_impl.committed(),
            "the Android test phone did not commit a link"
        );
        assert!(observed_commit, "fixture did not observe a committed link");
        assert!(
            host_impl.snapshots() >= 2,
            "the Android test phone did not download the snapshot before and after reopen"
        );
        assert!(
            host_impl.served_bytes() >= source_before.len() as u64 * 2,
            "the Android test phone did not receive both committed snapshots"
        );
        assert!(
            observed_revoke,
            "the Android test phone did not revoke the link"
        );
        assert!(
            final_status.links.is_empty(),
            "fixture did not observe revocation"
        );
        assert!(
            !crate::pc_link::has_authority_file(&data_root),
            "the last revoke left authority behind"
        );
        assert_eq!(
            std::fs::read(&vault_path).expect("source after"),
            source_before,
            "snapshotting changed the committed source"
        );
        println!("fixture_passed");
    }

    fn state_with_active_link(name: &str) -> (PcLinkState, TestVault, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "sesame-pc-link-service-{name}-{}",
            unix_timestamp()
        ));
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let state =
            PcLinkState::open_with_protection(&root, Box::new(TestProtection { fail: false }))
                .expect("state");
        let presence = ReleasePresence::default();
        presence.grant_until(
            vault.state.session_epoch(),
            Instant::now() + Duration::from_secs(600),
        );
        let key = rcgen::KeyPair::generate().expect("phone key");
        let phone_public_key = key.der_bytes().to_vec();
        let pending = state
            .begin_pairing_at(&vault.state, &phone_public_key, "Fictional phone", 1_000)
            .expect("pending");
        let commit = state
            .confirm_pairing_at(&vault.state, &presence, pending.request_id(), 1_000)
            .expect("confirmed");
        state
            .commit_pairing_at(
                &vault.state,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .expect("committed");
        (state, vault, root)
    }

    #[test]
    fn only_private_and_link_local_peers_are_served() {
        assert!(is_allowed_peer(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            false
        ));
        assert!(is_allowed_peer(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            false
        ));
        assert!(is_allowed_peer(
            IpAddr::V4(Ipv4Addr::new(169, 254, 4, 4)),
            false
        ));
        assert!(!is_allowed_peer(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            false
        ));
        assert!(!is_allowed_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), false));
        assert!(is_allowed_peer(IpAddr::V4(Ipv4Addr::LOCALHOST), true));
        assert!(is_allowed_peer("fd00::1".parse().expect("ula"), false));
        assert!(is_allowed_peer(
            "fe80::1".parse().expect("link local"),
            false
        ));
        assert!(!is_allowed_peer(
            "2001:db8::1".parse().expect("public"),
            false
        ));
        assert!(!is_allowed_peer("::".parse().expect("unspecified"), false));
    }

    #[test]
    fn listeners_bind_a_local_port() {
        let (port, listeners) = bind_listeners(0).expect("listeners");
        assert!(port > 0);
        assert!(!listeners.is_empty());
    }

    #[test]
    fn request_validation_rejects_forbidden_headers_and_methods() {
        let request = Request::builder()
            .method(Method::POST)
            .uri(ENROLL_PATH)
            .body(())
            .expect("request");
        assert!(validate_common(&request).is_ok());

        let request = Request::builder()
            .method(Method::GET)
            .uri(ENROLL_PATH)
            .body(())
            .expect("request");
        assert_eq!(
            validate_common(&request).err(),
            Some((StatusCode::BAD_REQUEST, ERROR_INVALID))
        );

        for (name, value) in [
            (ORIGIN, "https://example.test"),
            (REFERER, "https://example.test/"),
            (COOKIE, "fictional=1"),
            (CONTENT_ENCODING, "gzip"),
            (TRANSFER_ENCODING, "chunked"),
        ] {
            let request = Request::builder()
                .method(Method::POST)
                .uri(ENROLL_PATH)
                .header(name, value)
                .body(())
                .expect("request");
            assert!(validate_common(&request).is_err());
        }

        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/pair/enroll?fictional=1")
            .body(())
            .expect("request");
        assert!(validate_common(&request).is_err());
    }

    #[test]
    fn absolute_request_targets_are_refused() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://example.test/v1/pair/enroll")
            .body(())
            .expect("request");
        assert_eq!(
            validate_common(&request).err(),
            Some((StatusCode::BAD_REQUEST, ERROR_INVALID))
        );
    }

    #[test]
    fn empty_snapshot_requests_accept_only_zero_length_bodies() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/links/ABCDEFGHIJKLMNOPQRSTUV/snapshot")
            .body(())
            .expect("request");
        assert!(empty_request(&request));
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/links/ABCDEFGHIJKLMNOPQRSTUV/snapshot")
            .header(CONTENT_LENGTH, "0")
            .body(())
            .expect("request");
        assert!(empty_request(&request));
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/links/ABCDEFGHIJKLMNOPQRSTUV/snapshot")
            .header(CONTENT_LENGTH, "1")
            .body(())
            .expect("request");
        assert!(!empty_request(&request));
    }

    #[test]
    fn routes_are_exact_and_have_no_query_or_extra_segments() {
        assert_eq!(
            link_route("/v1/links/ABCDEFGHIJKLMNOPQRSTUV/snapshot"),
            Some(("ABCDEFGHIJKLMNOPQRSTUV".to_string(), "snapshot"))
        );
        assert_eq!(
            link_route("/v1/links/ABCDEFGHIJKLMNOPQRSTUV/snapshot/"),
            None
        );
        assert_eq!(link_route("/v1/links/short/snapshot"), None);
        assert_eq!(
            link_route("/v1/links/ABCDEFGHIJKLMNOPQRSTUV/other"),
            Some(("ABCDEFGHIJKLMNOPQRSTUV".to_string(), "other"))
        );
    }

    #[test]
    fn pairing_and_retrieval_error_statuses_are_stable() {
        assert_eq!(
            core_error_response("Unlock your vault first.").status(),
            StatusCode::LOCKED
        );
        assert_eq!(
            core_error_response(PRESENCE_REQUIRED).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            core_error_response("This pairing request has expired. Start pairing again.").status(),
            StatusCode::GONE
        );
        assert_eq!(
            core_error_response("The desktop has not approved this phone for this vault.").status(),
            StatusCode::FORBIDDEN
        );
    }

    fn state_with_phone_key(
        name: &str,
    ) -> (
        PcLinkState,
        TestVault,
        std::path::PathBuf,
        rcgen::KeyPair,
        PendingCommit,
    ) {
        let root = std::env::temp_dir().join(format!(
            "sesame-pc-link-handshake-{name}-{}",
            unix_timestamp()
        ));
        let vault = TestVault::with_login("fictional-login", "https://example.test");
        let state =
            PcLinkState::open_with_protection(&root, Box::new(TestProtection { fail: false }))
                .expect("state");
        let presence = ReleasePresence::default();
        presence.grant_until(
            vault.state.session_epoch(),
            Instant::now() + Duration::from_secs(600),
        );
        let phone_key = rcgen::KeyPair::generate().expect("phone key");
        let pending = state
            .begin_pairing_at(
                &vault.state,
                phone_key.der_bytes(),
                "Fictional phone",
                1_000,
            )
            .expect("pending");
        let commit = state
            .confirm_pairing_at(&vault.state, &presence, pending.request_id(), 1_000)
            .expect("confirmed");
        state
            .commit_pairing_at(
                &vault.state,
                &presence,
                commit.link_id(),
                commit.leaf_certificate_der(),
                1_000,
            )
            .expect("committed");
        (state, vault, root, phone_key, commit)
    }

    #[test]
    fn issued_client_leaf_completes_a_tls13_handshake() {
        let (state, _vault, root, phone_key, commit) = state_with_phone_key("success");
        let authorities = state.all_active_link_authorities().expect("authorities");
        let server_config = build_server_config(&state, &authorities, true).expect("server");
        let desktop_certificate = state.desktop_certificate().certificate_der().to_vec();
        tauri::async_runtime::block_on(async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
            let port = listener.local_addr().expect("address").port();
            let acceptor = TlsAcceptor::from(server_config);
            let server = tauri::async_runtime::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accepted");
                acceptor.accept(stream).await.map(|_| ())
            });
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(desktop_certificate))
                .expect("desktop root");
            let client_config =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(roots)
                    .with_client_auth_cert(
                        vec![
                            CertificateDer::from(commit.leaf_certificate_der().to_vec()),
                            CertificateDer::from(commit.certificate_authority_der().to_vec()),
                        ],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(phone_key.serialize_der())),
                    )
                    .expect("client config");
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            let result = tokio::time::timeout(
                Duration::from_secs(10),
                TlsConnector::from(Arc::new(client_config)).connect(
                    ServerName::try_from("sesame-pc.local").expect("server name"),
                    stream,
                ),
            )
            .await
            .expect("handshake timeout");
            assert!(result.is_ok());
            assert!(matches!(server.await, Ok(Ok(()))));
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mandatory_retrieval_tls_rejects_no_client_certificate() {
        let (state, _vault, root, _phone_key, _commit) = state_with_phone_key("no-cert");
        let authorities = state.all_active_link_authorities().expect("authorities");
        let server_config = build_server_config(&state, &authorities, true).expect("server");
        let desktop_certificate = state.desktop_certificate().certificate_der().to_vec();
        tauri::async_runtime::block_on(async {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("listener");
            let port = listener.local_addr().expect("address").port();
            let acceptor = TlsAcceptor::from(server_config);
            let server = tauri::async_runtime::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accepted");
                acceptor.accept(stream).await.map(|_| ())
            });
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(desktop_certificate))
                .expect("desktop root");
            let client_config =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                TlsConnector::from(Arc::new(client_config)).connect(
                    ServerName::try_from("sesame-pc.local").expect("server name"),
                    stream,
                ),
            )
            .await;
            assert!(!matches!(server.await, Ok(Ok(()))));
        });
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tls_configs_disable_resumption_and_require_client_auth_when_active() {
        let (state, _vault, root) = state_with_active_link("tls");
        let authorities = state.all_active_link_authorities().expect("authorities");
        assert!(!authorities.is_empty());
        let config = build_server_config(&state, &authorities, true).expect("mandatory config");
        assert_eq!(config.send_tls13_tickets, 0);
        assert_eq!(config.max_early_data_size, 0);
        assert!(build_server_config(&state, &[], true).is_err());
        let pairing = build_server_config(&state, &[], false).expect("optional config");
        assert_eq!(pairing.send_tls13_tickets, 0);
        assert_eq!(pairing.max_early_data_size, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn json_responses_are_bounded_and_non_cacheable() {
        let response = json_response(
            StatusCode::OK,
            &CommitResponse {
                v: WIRE_VERSION,
                state: PairingState::Active,
            },
        );
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert!(response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length <= MAX_JSON_RESPONSE_BYTES));
    }
}
