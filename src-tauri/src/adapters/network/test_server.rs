use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};

use super::server_address::fingerprint_of_public_key;

#[derive(Clone, Debug)]
pub(crate) struct Recorded {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }

    pub fn bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_date(self, unix_seconds: u64) -> Self {
        let moment = chrono::DateTime::from_timestamp(unix_seconds as i64, 0).unwrap();
        self.with_header("Date", &moment.to_rfc2822())
    }
}

pub(crate) struct TestServer {
    address: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
}

impl TestServer {
    pub fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let thread = {
            let requests = requests.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let requests = requests.clone();
                    let handler = handler.clone();
                    std::thread::spawn(move || serve(stream, &requests, &*handler));
                }
            })
        };
        Self {
            address,
            requests,
            stop,
            listener: Some(thread),
        }
    }

    pub fn base(&self) -> String {
        self.address.clone()
    }

    pub fn with_prefix(&self, prefix: &str) -> String {
        format!("{}{prefix}", self.address)
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    pub fn paths(&self) -> Vec<String> {
        self.requests()
            .into_iter()
            .map(|request| request.path)
            .collect()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address.trim_start_matches("http://"));
        if let Some(thread) = self.listener.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) fn closed_port_base() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    address
}

fn serve(
    mut stream: TcpStream,
    requests: &Mutex<Vec<Recorded>>,
    handler: &(dyn Fn(&Recorded) -> Reply + Send + Sync),
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut body = buffer[header_end + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => body.extend_from_slice(&chunk[..read]),
        }
    }
    let recorded = Recorded {
        method,
        path,
        headers,
        body,
    };
    requests.lock().unwrap().push(recorded.clone());
    let reply = handler(&recorded);
    let mut response = format!(
        "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (name, value) in &reply.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
    if recorded.method != "HEAD" {
        let _ = stream.write_all(&reply.body);
    }
    let _ = stream.flush();
}

#[derive(Clone)]
pub(crate) struct FakeSesame {
    pub signing_key: SigningKey,
    pub key_id: String,
    pub api_version: u64,
    pub minimum_client_version: String,
    pub maximum_client_version: Option<String>,
    pub name: String,
    pub desktop_linking: bool,
    pub capability_expires_at: String,
    pub date: Option<u64>,
}

impl FakeSesame {
    pub fn new(seed: u8) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[seed; 32]),
            key_id: format!("key-{seed}"),
            api_version: 1,
            minimum_client_version: "0.1.0".into(),
            maximum_client_version: None,
            name: "Home server".into(),
            desktop_linking: true,
            capability_expires_at: "2099-01-01T00:00:00Z".into(),
            date: None,
        }
    }

    pub fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_of_public_key(self.signing_key.verifying_key().as_bytes())
    }

    pub fn instance(&self) -> serde_json::Value {
        let mut document = serde_json::json!({
            "instanceId": "instance-1",
            "name": self.name,
            "version": "1.0.0",
            "commit": "abc",
            "apiVersion": self.api_version,
            "minimumClientVersion": self.minimum_client_version,
            "profile": "selfhost",
            "modules": [],
            "capabilityKeyId": self.key_id,
            "capabilityPublicKey": self.public_key(),
            "fingerprint": self.fingerprint(),
            "setupRequired": false,
        });
        if let Some(maximum) = &self.maximum_client_version {
            document["maximumClientVersion"] = serde_json::json!(maximum);
        }
        document
    }

    pub fn capability_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "minimumDesktopVersion": "0.1.0",
            "latestDesktopVersion": "9.9.9",
            "features": { "desktopLinking": self.desktop_linking, "sync": false },
            "serviceStatus": {},
            "expiresAt": self.capability_expires_at,
        })
    }

    pub fn capabilities(&self) -> serde_json::Value {
        self.signed(&self.capability_payload())
    }

    pub fn signed(&self, document: &serde_json::Value) -> serde_json::Value {
        let payload = serde_json::to_vec(document).unwrap();
        let signature = self.signing_key.sign(&payload);
        serde_json::json!({
            "payload": URL_SAFE_NO_PAD.encode(&payload),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            "keyId": self.key_id,
        })
    }

    pub fn handler(&self) -> impl Fn(&Recorded) -> Reply + Send + Sync + 'static {
        let fake = self.clone();
        move |request: &Recorded| {
            let reply = fake.answer(request);
            match fake.date {
                Some(date) => reply.with_date(date),
                None => reply,
            }
        }
    }

    fn answer(&self, request: &Recorded) -> Reply {
        let fake = self;
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/v1/instance") => Reply::json(200, &fake.instance()),
            ("GET", "/v1/capabilities") => Reply::json(200, &fake.capabilities()),
            ("DELETE", "/v1/desktop/connection") => Reply::bytes(204, Vec::new()),
            ("POST", "/v1/desktop/link") => Reply::json(
                201,
                &serde_json::json!({
                    "accessToken": "fictional-device-token",
                    "device": { "deviceId": "device-1", "deviceName": "Linux desktop" },
                    "expiresAt": "2099-01-01T00:00:00Z",
                    "syncAvailable": false,
                }),
            ),
            _ => Reply::json(
                404,
                &serde_json::json!({ "error": { "code": "not_found" } }),
            ),
        }
    }
}
