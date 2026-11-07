use crate::application::updater::{
    download_failure_message as describe_download_failure, require_available_update, update_status,
    updater_trust, verify_artifact_digest, verify_update_manifest, DownloadFailureKind,
    ReceiptArtifact, SizeRefusal, UpdateRelease,
};
use crate::vault::VaultResult;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::Poll;
use tauri::{process::restart, AppHandle, Emitter, Manager};
#[derive(Clone, serde::Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
pub struct DesktopUpdateStatus {
    pub available: bool,
    pub version: Option<String>,
    pub body: Option<String>,
    pub freshness: Option<crate::adapters::network::update_freshness::UpdateFreshness>,
}

#[derive(Clone, serde::Serialize, ts_rs::TS)]
#[ts(export, optional_fields)]
#[serde(rename_all = "camelCase")]
struct DesktopUpdateProgress {
    downloaded_bytes: u64,
    total_bytes: Option<u64>,
}

struct VerifiedDesktopUpdate {
    update: tauri_plugin_updater::Update,
    artifact: ReceiptArtifact,
}

#[derive(Debug)]
enum DownloadFailure {
    Refused(SizeRefusal),
    Failed(tauri_plugin_updater::Error),
}

struct SignedSizeGuard {
    signed_size: u64,
    received: AtomicU64,
    refusal: OnceLock<SizeRefusal>,
}

impl SignedSizeGuard {
    fn new(signed_size: u64) -> Self {
        Self {
            signed_size,
            received: AtomicU64::new(0),
            refusal: OnceLock::new(),
        }
    }

    fn refuse(&self, refusal: SizeRefusal) {
        let _ = self.refusal.set(refusal);
    }

    fn observe(&self, chunk_len: usize, announced_length: Option<u64>) -> u64 {
        if announced_length.is_some_and(|length| length != self.signed_size) {
            self.refuse(SizeRefusal::AnnouncedLength);
        }
        let received = self
            .received
            .fetch_add(chunk_len as u64, Ordering::Relaxed)
            .saturating_add(chunk_len as u64);
        if received > self.signed_size {
            self.refuse(SizeRefusal::ExceededSignedSize);
        }
        received
    }

    fn refusal(&self) -> Option<SizeRefusal> {
        self.refusal.get().copied()
    }
}

async fn download_within_signed_size<Fut>(
    signed_size: u64,
    start: impl FnOnce(Arc<SignedSizeGuard>) -> Fut,
) -> Result<Vec<u8>, DownloadFailure>
where
    Fut: Future<Output = Result<Vec<u8>, tauri_plugin_updater::Error>>,
{
    let guard = Arc::new(SignedSizeGuard::new(signed_size));
    let mut download = std::pin::pin!(start(Arc::clone(&guard)));
    std::future::poll_fn(|context| {
        let polled = download.as_mut().poll(context);
        if let Some(refusal) = guard.refusal() {
            return Poll::Ready(Err(DownloadFailure::Refused(refusal)));
        }
        polled.map(|outcome| match outcome {
            Ok(bytes) if bytes.len() as u64 != signed_size => {
                Err(DownloadFailure::Refused(SizeRefusal::ReceivedLength))
            }
            Ok(bytes) => Ok(bytes),
            Err(error) => Err(DownloadFailure::Failed(error)),
        })
    })
    .await
}

fn download_failure_message(failure: &DownloadFailure) -> String {
    let kind = match failure {
        DownloadFailure::Refused(refusal) => DownloadFailureKind::Refused(*refusal),
        DownloadFailure::Failed(tauri_plugin_updater::Error::Reqwest(error))
            if error.is_timeout() =>
        {
            DownloadFailureKind::TimedOut
        }
        DownloadFailure::Failed(_) => DownloadFailureKind::Failed,
    };
    describe_download_failure(kind)
}

async fn download_verified_artifact(
    verified: &VerifiedDesktopUpdate,
    mut on_progress: impl FnMut(u64, Option<u64>) + Send,
) -> VaultResult<Vec<u8>> {
    let bytes = download_within_signed_size(verified.artifact.bytes, |guard| {
        verified.update.download(
            move |chunk_bytes, announced_length| {
                on_progress(
                    guard.observe(chunk_bytes, announced_length),
                    announced_length,
                );
            },
            || {},
        )
    })
    .await
    .map_err(|failure| download_failure_message(&failure))?;
    let digest = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    verify_artifact_digest(&digest, &verified.artifact)?;
    Ok(bytes)
}

async fn check(app: &AppHandle) -> VaultResult<Option<VerifiedDesktopUpdate>> {
    let trust = updater_trust()?;
    let update = crate::adapters::network::public_updates::check(app).await?;
    update
        .map(|update| {
            let artifact = verify_update_manifest(
                &trust,
                &update.raw_json,
                &update.version,
                &update.signature,
            )?;
            Ok(VerifiedDesktopUpdate { update, artifact })
        })
        .transpose()
}

#[tauri::command]
pub async fn check_desktop_update(app: AppHandle) -> VaultResult<DesktopUpdateStatus> {
    let status = update_status(check(&app).await?.map(|update| UpdateRelease {
        version: update.update.version,
        body: update.update.body,
    }));
    let freshness =
        crate::adapters::network::update_freshness::current(&app, status.version.as_deref()).await;
    Ok(DesktopUpdateStatus {
        available: status.available,
        version: status.version,
        body: status.body,
        freshness,
    })
}

#[tauri::command]
pub async fn download_and_install_desktop_update(app: AppHandle) -> VaultResult<()> {
    let verified = require_available_update(check(&app).await?)?;
    let progress_app = app.clone();
    let bytes = download_verified_artifact(&verified, move |downloaded_bytes, total_bytes| {
        let _ = progress_app.emit(
            "desktop-update-progress",
            DesktopUpdateProgress {
                downloaded_bytes,
                total_bytes,
            },
        );
    })
    .await?;
    // Nothing decrypted may stay alive while the updater replaces the executable.
    crate::desktop_shell::lock_vault_if_unlocked(&app);
    crate::browser_fill::cancel_pending_approvals(&app);
    verified
        .update
        .install(&bytes)
        .map_err(|_| "Sesame could not install the verified update.".to_string())?;
    restart(&app.env());
}

#[cfg(test)]
mod download_tests {
    use super::{
        download_verified_artifact, download_within_signed_size, DownloadFailure, SignedSizeGuard,
        VerifiedDesktopUpdate,
    };
    use crate::adapters::network::public_updates::{check_endpoint, TransferLimits};
    use crate::application::updater::{ReceiptArtifact, SizeRefusal};
    use std::future::Future;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::task::{Context, Poll};
    use std::thread;
    use std::time::{Duration, Instant};
    use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};

    const FIXTURE_UPDATER_PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IENERDcyNDRFOEEzOUNFQzQKUldURXpqbUtUaVRYemEvVUlKalpjSzZqMzNvbVZ6cFg4amlhUFdwU1A0S0VpaytCaG1jeURESTIK";
    const FIXTURE_ARTIFACT: &[u8] =
        b"sesame fictional installer body, 64 bytes of text for signing.....";
    const FIXTURE_SIGNATURE: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVURXpqbUtUaVRYemE3RlpuUXlXV2JNeTlPaGlDRHJqcDZVdDE0RnJpTkxuYzltaXpsZ2k5VDBpMmtJRVVPakpXU0kveGc5d3dPOUpCZkpjVEwyRGgrZWZGL3JmWkZzWmdFPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzkxMjE4NTYxCWZpbGU6Ym9keS5iaW4KenpKTVNRUWlrUGJreFlaZFpUbVhMMkhKRGxldDhoRDRwK2N6VFk2aTh1NjFXNGhud21EQUsxM2QvSVdBL3FZZ2d0RnZuU1p4ZTZWTVRJUW9xUFpvQ3c9PQo=";

    fn signed_size() -> u64 {
        FIXTURE_ARTIFACT.len() as u64
    }

    fn quick_limits() -> TransferLimits {
        TransferLimits {
            connect: Duration::from_secs(2),
            read: Duration::from_millis(400),
            manifest_total: Duration::from_secs(5),
            download_total: Duration::from_secs(2),
        }
    }

    struct TestServer {
        host: &'static str,
        port: u16,
        connections: Arc<AtomicUsize>,
    }

    impl TestServer {
        fn url(&self, path: &str) -> String {
            format!("http://{}:{}{path}", self.host, self.port)
        }
    }

    fn request_path(stream: &mut TcpStream) -> Option<String> {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).ok()?;
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).ok()?;
        head.split_whitespace().nth(1).map(str::to_owned)
    }

    fn start(
        listener: TcpListener,
        host: &'static str,
        route: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
    ) -> TestServer {
        let port = listener.local_addr().expect("address").port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let route = Arc::new(route);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                let route = Arc::clone(&route);
                thread::spawn(move || {
                    if let Some(path) = request_path(&mut stream) {
                        route(&path, &mut stream);
                    }
                });
            }
        });
        TestServer {
            host,
            port,
            connections,
        }
    }

    fn serve(
        host: &'static str,
        route: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
    ) -> TestServer {
        start(TcpListener::bind((host, 0)).expect("bind"), host, route)
    }

    fn manifest(version: &str, artifact_url: &str) -> String {
        let target = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        serde_json::json!({
            "version": version,
            "notes": "fictional release",
            "platforms": { target: { "url": artifact_url, "signature": FIXTURE_SIGNATURE } },
        })
        .to_string()
    }

    fn respond(stream: &mut TcpStream, status: &str, headers: &[String], body: &[u8]) {
        let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
        for header in headers {
            head.push_str(header);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }

    fn respond_with_length(stream: &mut TcpStream, declared: u64, body: &[u8]) {
        respond(
            stream,
            "200 OK",
            &[format!("Content-Length: {declared}")],
            body,
        );
    }

    fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> bool {
        stream
            .write_all(format!("{:x}\r\n", data.len()).as_bytes())
            .and_then(|()| stream.write_all(data))
            .and_then(|()| stream.write_all(b"\r\n"))
            .is_ok()
    }

    fn serve_release(
        version: &'static str,
        artifact: impl Fn(&mut TcpStream) + Send + Sync + 'static,
    ) -> TestServer {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("address").port();
        let manifest_body = manifest(version, &format!("http://127.0.0.1:{port}/Sesame.exe"));
        start(listener, "127.0.0.1", move |path, stream| {
            if path == "/latest.json" {
                respond(
                    stream,
                    "200 OK",
                    &[
                        "Content-Type: application/json".to_owned(),
                        format!("Content-Length: {}", manifest_body.len()),
                    ],
                    manifest_body.as_bytes(),
                );
            } else {
                artifact(stream);
            }
        })
    }

    fn updater_app() -> tauri::App<MockRuntime> {
        let mut context = mock_context(noop_assets());
        context.config_mut().plugins.0.insert(
            "updater".to_owned(),
            serde_json::json!({ "pubkey": FIXTURE_UPDATER_PUBLIC_KEY }),
        );
        mock_builder()
            .plugin(tauri_plugin_updater::Builder::new().build())
            .build(context)
            .expect("mock app")
    }

    fn endpoint(server: &TestServer) -> url::Url {
        url::Url::parse(&server.url("/latest.json")).expect("endpoint")
    }

    fn fetch(server: &TestServer, limits: TransferLimits) -> Result<Vec<u8>, DownloadFailure> {
        let app = updater_app();
        tauri::async_runtime::block_on(async {
            let update = check_endpoint(app.handle(), endpoint(server), limits)
                .await
                .expect("check")
                .expect("update available");
            download_within_signed_size(signed_size(), |guard| {
                update.download(
                    move |chunk_bytes, announced_length| {
                        guard.observe(chunk_bytes, announced_length);
                    },
                    || {},
                )
            })
            .await
        })
    }

    fn verified_update(
        server: &TestServer,
        sha256: &str,
        bytes: u64,
    ) -> (tauri::App<MockRuntime>, VerifiedDesktopUpdate) {
        let app = updater_app();
        let update = tauri::async_runtime::block_on(check_endpoint(
            app.handle(),
            endpoint(server),
            quick_limits(),
        ))
        .expect("check")
        .expect("update available");
        let artifact = ReceiptArtifact {
            sha256: sha256.to_owned(),
            bytes,
        };
        (app, VerifiedDesktopUpdate { update, artifact })
    }

    fn fixture_sha256() -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(FIXTURE_ARTIFACT)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn the_install_path_gets_the_artifact_only_when_size_signature_and_digest_agree() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let (_app, verified) = verified_update(&server, &fixture_sha256(), signed_size());
        let progress = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&progress);
        let bytes = tauri::async_runtime::block_on(download_verified_artifact(
            &verified,
            move |downloaded, total| recorded.lock().expect("progress").push((downloaded, total)),
        ))
        .expect("verified artifact");
        assert_eq!(bytes, FIXTURE_ARTIFACT);
        let progress = progress.lock().expect("progress");
        assert_eq!(progress.last(), Some(&(signed_size(), Some(signed_size()))));
    }

    #[test]
    fn the_install_path_refuses_a_signed_body_whose_digest_is_not_in_the_receipt() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let (_app, verified) = verified_update(&server, &"0".repeat(64), signed_size());
        let message =
            tauri::async_runtime::block_on(download_verified_artifact(&verified, |_, _| {}))
                .expect_err("digest mismatch");
        assert!(message.contains("did not match its signed release receipt"));
    }

    #[test]
    fn the_install_path_refuses_a_body_that_differs_from_the_receipt_size() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        for receipt_size in [signed_size() - 1, signed_size() + 1] {
            let (_app, verified) = verified_update(&server, &fixture_sha256(), receipt_size);
            let message =
                tauri::async_runtime::block_on(download_verified_artifact(&verified, |_, _| {}))
                    .expect_err("size mismatch");
            assert!(message.contains("signed size"), "{message}");
        }
    }

    #[test]
    fn the_install_path_refuses_a_body_larger_than_the_signed_size_before_installing() {
        let server = serve_release("1.2.3", |stream| {
            let oversized = vec![0_u8; (signed_size() * 2) as usize];
            respond_with_length(stream, oversized.len() as u64, &oversized);
        });
        let (_app, verified) = verified_update(&server, &fixture_sha256(), signed_size());
        let message =
            tauri::async_runtime::block_on(download_verified_artifact(&verified, |_, _| {}))
                .expect_err("oversized body");
        assert!(message.contains("signed size"), "{message}");
    }

    fn is_timeout(failure: &DownloadFailure) -> bool {
        matches!(
            failure,
            DownloadFailure::Failed(tauri_plugin_updater::Error::Reqwest(error)) if error.is_timeout()
        )
    }

    #[test]
    fn downloads_and_verifies_a_body_of_the_signed_size() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let bytes = fetch(&server, quick_limits()).expect("download");
        assert_eq!(bytes, FIXTURE_ARTIFACT);
    }

    #[test]
    fn the_download_carries_the_total_time_limit() {
        let server = serve_release("1.2.3", |_| {});
        let app = updater_app();
        let update = tauri::async_runtime::block_on(check_endpoint(
            app.handle(),
            endpoint(&server),
            quick_limits(),
        ))
        .expect("check")
        .expect("update available");
        assert_eq!(update.timeout, Some(quick_limits().download_total));
    }

    #[test]
    fn keeps_the_plugin_signature_check_for_a_body_of_the_signed_size() {
        let server = serve_release("1.2.3", |stream| {
            let forged = vec![b'x'; FIXTURE_ARTIFACT.len()];
            respond_with_length(stream, signed_size(), &forged);
        });
        let failure = fetch(&server, quick_limits()).expect_err("forged body");
        assert!(matches!(
            failure,
            DownloadFailure::Failed(tauri_plugin_updater::Error::Minisign(_))
        ));
    }

    #[test]
    fn stops_an_endless_body_at_the_signed_size() {
        let (finished, written) = mpsc::channel();
        let server = serve_release("1.2.3", move |stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            let block = vec![0_u8; 8192];
            let mut total = 0_u64;
            while total < 256 * 1024 * 1024 && write_chunk(stream, &block) {
                total += block.len() as u64;
            }
            let _ = finished.send(total);
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("endless body");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::ExceededSignedSize)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        let total = written
            .recv_timeout(Duration::from_secs(10))
            .expect("server stopped writing");
        assert!(total < 256 * 1024 * 1024);
    }

    #[test]
    fn refuses_a_larger_body_with_an_honest_length_header() {
        let server = serve_release("1.2.3", |stream| {
            let oversized = vec![0_u8; 1024 * 1024];
            respond_with_length(stream, oversized.len() as u64, &oversized);
        });
        let failure = fetch(&server, quick_limits()).expect_err("oversized body");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
    }

    #[test]
    fn refuses_a_smaller_body_with_an_honest_length_header() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, 20, &FIXTURE_ARTIFACT[..20]);
        });
        let failure = fetch(&server, quick_limits()).expect_err("short body");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
    }

    #[test]
    fn refuses_a_length_header_that_understates_the_body() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, 10, FIXTURE_ARTIFACT);
        });
        let failure = fetch(&server, quick_limits()).expect_err("understated length");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
    }

    #[test]
    fn refuses_a_length_header_that_overstates_the_body() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, 5_000_000_000, FIXTURE_ARTIFACT);
            thread::sleep(Duration::from_secs(1));
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("overstated length");
        assert!(matches!(
            failure,
            DownloadFailure::Refused(SizeRefusal::AnnouncedLength)
        ));
        assert!(started.elapsed() < Duration::from_millis(900));
    }

    #[test]
    fn refuses_a_body_that_ends_before_its_declared_length() {
        let server = serve_release("1.2.3", |stream| {
            respond_with_length(stream, signed_size(), &FIXTURE_ARTIFACT[..20]);
        });
        let failure = fetch(&server, quick_limits()).expect_err("cut body");
        assert!(matches!(failure, DownloadFailure::Failed(_)));
    }

    #[test]
    fn refuses_a_chunked_body_that_ends_early() {
        let server = serve_release("1.2.3", |stream| {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            write_chunk(stream, &FIXTURE_ARTIFACT[..20]);
            let _ = stream.write_all(b"0\r\n\r\n");
        });
        let failure = fetch(&server, quick_limits()).expect_err("early end");
        assert!(matches!(
            failure,
            DownloadFailure::Failed(tauri_plugin_updater::Error::Minisign(_))
        ));
    }

    #[test]
    fn stops_a_body_that_stalls_after_the_headers() {
        let server = serve_release("1.2.3", |stream| {
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    signed_size()
                )
                .as_bytes(),
            );
            let _ = stream.write_all(&FIXTURE_ARTIFACT[..10]);
            let _ = stream.flush();
            thread::sleep(Duration::from_secs(4));
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("stalled body");
        assert!(is_timeout(&failure), "{failure:?}");
        assert!(started.elapsed() < Duration::from_millis(1500));
    }

    #[test]
    fn stops_a_body_that_trickles_past_the_total_limit() {
        let server = serve_release("1.2.3", |stream| {
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                    signed_size()
                )
                .as_bytes(),
            );
            for byte in FIXTURE_ARTIFACT {
                if stream
                    .write_all(&[*byte])
                    .and_then(|()| stream.flush())
                    .is_err()
                {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("trickling body");
        assert!(is_timeout(&failure), "{failure:?}");
        assert!(started.elapsed() < Duration::from_millis(3500));
    }

    #[test]
    fn stops_a_server_that_never_sends_a_response() {
        let server = serve_release("1.2.3", |_| {
            thread::sleep(Duration::from_secs(5));
        });
        let started = Instant::now();
        let failure = fetch(&server, quick_limits()).expect_err("silent server");
        assert!(is_timeout(&failure), "{failure:?}");
        assert!(started.elapsed() < Duration::from_millis(3500));
    }

    #[test]
    fn does_not_follow_a_download_redirect_to_another_host() {
        let other = serve("127.0.0.2", |_, stream| {
            respond_with_length(stream, signed_size(), FIXTURE_ARTIFACT);
        });
        let target = other.url("/Sesame.exe");
        let server = serve_release("1.2.3", move |stream| {
            respond(stream, "302 Found", &[format!("Location: {target}")], b"");
        });
        let failure = fetch(&server, quick_limits()).expect_err("redirected download");
        assert!(matches!(failure, DownloadFailure::Failed(_)));
        assert_eq!(other.connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn does_not_follow_a_download_redirect_to_the_same_host_over_http() {
        let server = serve_release("1.2.3", |stream| {
            respond(
                stream,
                "302 Found",
                &["Location: /elsewhere.exe".to_owned()],
                b"",
            );
        });
        let failure = fetch(&server, quick_limits()).expect_err("redirected download");
        assert!(matches!(failure, DownloadFailure::Failed(_)));
    }

    #[test]
    fn does_not_follow_a_manifest_redirect_to_another_host() {
        let other = serve("127.0.0.2", |_, stream| {
            let body = manifest("1.2.3", "http://127.0.0.2/Sesame.exe");
            respond(
                stream,
                "200 OK",
                &[format!("Content-Length: {}", body.len())],
                body.as_bytes(),
            );
        });
        let target = other.url("/latest.json");
        let server = serve("127.0.0.1", move |_, stream| {
            respond(stream, "302 Found", &[format!("Location: {target}")], b"");
        });
        let app = updater_app();
        let result = tauri::async_runtime::block_on(check_endpoint(
            app.handle(),
            endpoint(&server),
            quick_limits(),
        ));
        assert!(result.is_err());
        assert_eq!(other.connections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ignores_a_replayed_manifest_for_the_installed_or_an_older_version() {
        for replayed in ["0.1.0", "0.0.9"] {
            let server = serve_release(replayed, |_| {});
            let app = updater_app();
            let update = tauri::async_runtime::block_on(check_endpoint(
                app.handle(),
                endpoint(&server),
                quick_limits(),
            ))
            .expect("check");
            assert!(update.is_none(), "{replayed} must not offer an update");
        }
    }

    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    async fn scripted_download(
        guard: Arc<SignedSizeGuard>,
        chunks: Vec<usize>,
        announced_length: Option<u64>,
        delivered: Arc<AtomicUsize>,
    ) -> Result<Vec<u8>, tauri_plugin_updater::Error> {
        let mut body = Vec::new();
        for chunk in chunks {
            YieldOnce(false).await;
            delivered.fetch_add(1, Ordering::SeqCst);
            guard.observe(chunk, announced_length);
            body.extend(std::iter::repeat_n(0_u8, chunk));
        }
        Ok(body)
    }

    fn run_scripted(
        signed: u64,
        chunks: Vec<usize>,
        announced_length: Option<u64>,
    ) -> (Result<Vec<u8>, DownloadFailure>, usize) {
        let delivered = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&delivered);
        let outcome =
            tauri::async_runtime::block_on(download_within_signed_size(signed, move |guard| {
                scripted_download(guard, chunks, announced_length, counter)
            }));
        (outcome, delivered.load(Ordering::SeqCst))
    }

    #[test]
    fn a_body_of_exactly_the_signed_size_passes() {
        let (outcome, _) = run_scripted(100, vec![40, 60], Some(100));
        assert_eq!(outcome.expect("download").len(), 100);
        let (outcome, _) = run_scripted(100, vec![40, 60], None);
        assert_eq!(outcome.expect("download").len(), 100);
    }

    #[test]
    fn a_body_past_the_signed_size_is_dropped_at_the_first_excess_chunk() {
        let (outcome, delivered) = run_scripted(100, vec![60; 1000], None);
        assert!(matches!(
            outcome,
            Err(DownloadFailure::Refused(SizeRefusal::ExceededSignedSize))
        ));
        assert_eq!(delivered, 2);
    }

    #[test]
    fn a_body_short_of_the_signed_size_is_refused() {
        let (outcome, _) = run_scripted(100, vec![40, 59], None);
        assert!(matches!(
            outcome,
            Err(DownloadFailure::Refused(SizeRefusal::ReceivedLength))
        ));
        let (outcome, _) = run_scripted(100, Vec::new(), None);
        assert!(matches!(
            outcome,
            Err(DownloadFailure::Refused(SizeRefusal::ReceivedLength))
        ));
    }

    #[test]
    fn an_announced_length_that_differs_from_the_signed_size_is_refused_at_once() {
        for announced in [99, 101, u64::MAX] {
            let (outcome, delivered) = run_scripted(100, vec![10; 1000], Some(announced));
            assert!(matches!(
                outcome,
                Err(DownloadFailure::Refused(SizeRefusal::AnnouncedLength))
            ));
            assert_eq!(delivered, 1);
        }
    }
}
