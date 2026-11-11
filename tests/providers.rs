//! The fingerprint library is built from loadable providers.
//!
//! Every test registers a provider under an id of its own and unregisters
//! before it returns so a later test sees the embedded library alone. The
//! registry is process-wide and `refresh_providers()` reloads *every*
//! provider, so tests that touch it run one at a time behind `exclusive()`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rust_curl_impersonate::fingerprint::provider::{
    register_provider, register_provider_with_priority, unregister_provider, BuiltinProvider,
    DirProvider, FnProvider, JsonProvider, RemoteProvider, PRIORITY_BUILTIN, PRIORITY_USER,
};
use rust_curl_impersonate::fingerprint::{self, Fingerprint};
use rust_curl_impersonate::profile::H3Setting;
use rust_curl_impersonate::{Client, FormBoundary, Profile};

/// Serializes tests that mutate the process-wide provider registry.
static REGISTRY: Mutex<()> = Mutex::new(());

fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn record(name: &str, family: &str) -> Fingerprint {
    Fingerprint {
        name: name.to_string(),
        family: family.to_string(),
        tls: fingerprint::TlsFingerprint {
            ciphers: Some("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384".to_string()),
            alpn: Some(vec!["http/1.1".to_string()]),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn document(name: &str, family: &str) -> String {
    serde_json::to_string(&record(name, family)).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rust-curl-impersonate-provider-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_embedded_library_is_the_default_provider() {
    let _registry = exclusive();
    let providers = fingerprint::providers();
    let builtin = providers
        .first()
        .expect("the embedded provider is registered");
    assert_eq!(builtin.id, BuiltinProvider::ID);
    assert_eq!(builtin.priority, PRIORITY_BUILTIN);
    assert_eq!(builtin.records, fingerprint::builtin().len());
    assert!(builtin.overrides.is_empty());

    // Other tests in this binary may have added providers, so only the lower
    // bound is fixed.
    assert!(fingerprint::records().len() >= fingerprint::builtin().len());
    assert!(fingerprint::find("go1.26").is_some());
    assert!(unregister_provider(BuiltinProvider::ID).is_err());
}

#[test]
fn a_json_provider_makes_its_records_resolvable() {
    let _registry = exclusive();
    register_provider(JsonProvider::new(
        "prov-json",
        document("prov_json_client", "go"),
    ))
    .unwrap();

    let record = fingerprint::find("prov_json_client").expect("the provider's record");
    assert_eq!(record.family, "go");
    assert!(fingerprint::names().contains(&"prov_json_client"));

    let profile = Profile::find("prov_json_client").expect("a provider record is a profile");
    assert_eq!(profile.family(), "go");
    assert!(profile.http1_only());
    assert!(profile.emulation().tls_options.is_some());
    assert_eq!(
        fingerprint::provider_of("prov_json_client").unwrap().id,
        "prov-json"
    );

    unregister_provider("prov-json").unwrap();
    assert!(fingerprint::find("prov_json_client").is_none());
    assert!(Profile::find("prov_json_client").is_none());
}

#[test]
fn a_higher_priority_provider_shadows_a_lower_one() {
    let _registry = exclusive();
    let mut patched = record("go1.26", "patched");
    patched.tls.ciphers = Some("TLS_AES_128_GCM_SHA256".to_string());
    register_provider_with_priority(
        JsonProvider::new("prov-shadow", serde_json::to_string(&patched).unwrap()),
        PRIORITY_USER,
    )
    .unwrap();

    assert_eq!(fingerprint::find("go1.26").unwrap().family, "patched");
    let info = fingerprint::providers()
        .into_iter()
        .find(|info| info.id == "prov-shadow")
        .unwrap();
    assert!(info.overrides.contains(&"go1.26".to_string()));
    // The listing keeps the built-in record's position: the shadowed name is
    // still listed exactly once.
    assert_eq!(
        fingerprint::names()
            .iter()
            .filter(|name| **name == "go1.26")
            .count(),
        1
    );

    unregister_provider("prov-shadow").unwrap();
    assert_ne!(fingerprint::find("go1.26").unwrap().family, "patched");
}

#[test]
fn equal_priority_goes_to_the_later_provider() {
    let _registry = exclusive();
    register_provider(JsonProvider::new(
        "prov-first",
        document("prov_tie", "first"),
    ))
    .unwrap();
    register_provider(JsonProvider::new(
        "prov-second",
        document("prov_tie", "second"),
    ))
    .unwrap();
    assert_eq!(fingerprint::find("prov_tie").unwrap().family, "second");
    assert_eq!(
        fingerprint::provider_of("prov_tie").unwrap().id,
        "prov-second"
    );

    unregister_provider("prov-second").unwrap();
    assert_eq!(fingerprint::find("prov_tie").unwrap().family, "first");
    unregister_provider("prov-first").unwrap();
    assert!(fingerprint::find("prov_tie").is_none());
}

#[test]
fn a_provider_is_validated_before_it_is_registered() {
    let _registry = exclusive();
    // Two records with one name are ambiguous, so the whole provider is
    // rejected and nothing is added.
    let twice = format!(
        "[{},{}]",
        serde_json::to_string(&record("prov_dup", "one")).unwrap(),
        serde_json::to_string(&record("prov_dup", "two")).unwrap()
    );
    let error = register_provider(JsonProvider::new("prov-dup", twice)).unwrap_err();
    assert!(error.contains("prov_dup"), "{error}");
    assert!(!fingerprint::providers()
        .iter()
        .any(|info| info.id == "prov-dup"));

    // A record with no name is rejected.
    let anonymous = r#"[{"name":""}]"#;
    assert!(register_provider(JsonProvider::new("prov-anon", anonymous)).is_err());

    // A reserved id cannot be reused.
    assert!(register_provider(JsonProvider::new(BuiltinProvider::ID, "[]")).is_err());

    // Two providers cannot share an id.
    register_provider(JsonProvider::new("prov-unique", "[]")).unwrap();
    assert!(register_provider(JsonProvider::new("prov-unique", "[]")).is_err());
    unregister_provider("prov-unique").unwrap();

    // A document that is not JSON is reported as an error.
    assert!(register_provider(JsonProvider::new("prov-bad", "{")).is_err());
    assert!(register_provider(JsonProvider::from_path(
        "prov-missing",
        "/nonexistent/fingerprints.json"
    ))
    .is_err());
}

#[test]
fn a_record_may_extend_a_builtin_or_another_record() {
    let _registry = exclusive();
    // Extending a built-in record keeps the built-in wire settings.
    let mut alias = record("prov_alias", "chrome");
    alias.tls = Default::default();
    alias.extends = Some("go1.26".to_string());
    register_provider(JsonProvider::new(
        "prov-alias",
        serde_json::to_string(&alias).unwrap(),
    ))
    .unwrap();
    let profile = Profile::find("prov_alias").unwrap();
    assert_eq!(profile.target(), "go1.26");
    assert_eq!(profile.family(), "chrome");
    unregister_provider("prov-alias").unwrap();

    // An unknown base fails the whole registration and leaves no record.
    let mut orphan = record("prov_orphan", "go");
    orphan.extends = Some("no-such-profile".to_string());
    let error = register_provider(JsonProvider::new(
        "prov-orphan",
        serde_json::to_string(&orphan).unwrap(),
    ))
    .unwrap_err();
    assert!(error.contains("no-such-profile"), "{error}");
    assert!(fingerprint::find("prov_orphan").is_none());
    assert!(!fingerprint::providers()
        .iter()
        .any(|info| info.id == "prov-orphan"));

    // A record cannot extend itself; that would loop `Profile::find` forever.
    let mut selfie = record("prov_self", "go");
    selfie.extends = Some("prov_self".to_string());
    let error = register_provider(JsonProvider::new(
        "prov-self",
        serde_json::to_string(&selfie).unwrap(),
    ))
    .unwrap_err();
    assert!(error.contains("cannot extend itself"), "{error}");
    assert!(fingerprint::find("prov_self").is_none());
}

#[test]
fn a_directory_provider_reads_every_document() {
    let _registry = exclusive();
    let dir = scratch("dir");
    std::fs::write(dir.join("b.json"), document("prov_dir_b", "go")).unwrap();
    std::fs::write(dir.join("a.json"), document("prov_dir_a", "python")).unwrap();
    std::fs::write(dir.join("notes.txt"), "not a fingerprint").unwrap();

    register_provider(DirProvider::new("prov-dir", &dir)).unwrap();
    assert_eq!(fingerprint::find("prov_dir_a").unwrap().family, "python");
    assert_eq!(fingerprint::find("prov_dir_b").unwrap().family, "go");
    assert_eq!(
        fingerprint::providers()
            .into_iter()
            .find(|info| info.id == "prov-dir")
            .unwrap()
            .records,
        2
    );
    unregister_provider("prov-dir").unwrap();
    assert!(fingerprint::find("prov_dir_a").is_none());
    assert!(fingerprint::find("prov_dir_b").is_none());

    // A directory without documents is a configuration error, not an empty
    // provider.
    let empty = scratch("empty");
    assert!(register_provider(DirProvider::new("prov-empty", Path::new(&empty))).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&empty).unwrap();
}

#[test]
fn refresh_reloads_a_closure_provider() {
    let _registry = exclusive();
    let version = Arc::new(AtomicUsize::new(0));
    let source = Arc::clone(&version);
    let provider = FnProvider::new("prov-fn", move || {
        Ok(vec![record(
            "prov_fn_client",
            if source.load(Ordering::SeqCst) == 0 {
                "first"
            } else {
                "second"
            },
        )])
    })
    .with_description("a closure that fetches records");
    register_provider(provider).unwrap();
    assert_eq!(fingerprint::find("prov_fn_client").unwrap().family, "first");
    let info = fingerprint::providers()
        .into_iter()
        .find(|info| info.id == "prov-fn")
        .unwrap();
    assert_eq!(info.description, "a closure that fetches records");

    version.store(1, Ordering::SeqCst);
    // Another test in this binary may register a provider whose own reload
    // fails; the error is reported after the ones that loaded are applied, so
    // only this provider's record is checked here.
    let refreshed = fingerprint::refresh_providers();
    assert!(
        refreshed.is_ok() || !refreshed.unwrap_err().contains("prov-fn"),
        "the closure provider reloads"
    );
    assert_eq!(
        fingerprint::find("prov_fn_client").unwrap().family,
        "second"
    );

    // A refresh leaves the embedded library untouched.
    assert!(fingerprint::find("go1.26").is_some());
    unregister_provider("prov-fn").unwrap();
    assert!(fingerprint::find("prov_fn_client").is_none());
}

#[test]
fn a_failing_refresh_keeps_the_loaded_records() {
    let _registry = exclusive();
    let healthy = Arc::new(AtomicUsize::new(0));
    let source = Arc::clone(&healthy);
    let provider = FnProvider::new("prov-refresh", move || {
        if source.load(Ordering::SeqCst) == 0 {
            Ok(vec![record("prov_refresh_client", "go")])
        } else {
            Err("service unavailable".to_string())
        }
    });
    register_provider(provider).unwrap();
    healthy.store(1, Ordering::SeqCst);
    let error = fingerprint::refresh_providers().unwrap_err();
    assert!(error.contains("service unavailable"), "{error}");
    assert!(fingerprint::find("prov_refresh_client").is_some());
    unregister_provider("prov-refresh").unwrap();
}

#[test]
fn provider_ids_are_reported_with_their_record_count() {
    let _registry = exclusive();
    register_provider(JsonProvider::new("prov-info", "[]")).unwrap();
    let info = fingerprint::providers()
        .into_iter()
        .find(|info| info.id == "prov-info")
        .unwrap();
    assert_eq!(info.records, 0);
    assert_eq!(info.priority, PRIORITY_USER);
    assert!(info.description.is_empty());
    assert!(unregister_provider("prov-none").is_err());
    unregister_provider("prov-info").unwrap();
}

/// A tiny HTTP server speaking just enough of the protocol for the remote
/// provider: serves `body` with an ETag, answers `If-None-Match` with 304, and
/// optionally demands a bearer token. Every request is counted and logged.
struct CloudServer {
    address: SocketAddr,
    total: Arc<AtomicUsize>,
    conditional: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl CloudServer {
    fn start(body: &str, etag: &str, bearer: Option<&str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let body = body.to_string();
        let etag = etag.to_string();
        let bearer = bearer.map(str::to_string);
        let total = Arc::new(AtomicUsize::new(0));
        let conditional = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = {
            let total = Arc::clone(&total);
            let conditional = Arc::clone(&conditional);
            let seen = Arc::clone(&seen);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                while !shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            total.fetch_add(1, Ordering::SeqCst);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                            let mut buf = Vec::new();
                            let mut chunk = [0u8; 1024];
                            'read: loop {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        buf.extend_from_slice(&chunk[..n]);
                                        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                                            break 'read;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                            let head = String::from_utf8_lossy(&buf).to_string();
                            let mut lines = head.lines();
                            let request_line = lines.next().unwrap_or_default().to_string();
                            let mut if_none_match = None;
                            let mut authorization = None;
                            let mut x_client = None;
                            for line in lines {
                                let lower = line.to_ascii_lowercase();
                                if lower.starts_with("if-none-match:") {
                                    if_none_match =
                                        Some(line["if-none-match:".len()..].trim().to_string());
                                } else if lower.starts_with("authorization:") {
                                    authorization =
                                        Some(line["authorization:".len()..].trim().to_string());
                                } else if lower.starts_with("x-client:") {
                                    x_client = Some(line["x-client:".len()..].trim().to_string());
                                }
                            }
                            seen.lock().unwrap().push(format!(
                                "{request_line} if-none-match={if_none_match:?} \
                                 authorization={authorization:?} x-client={x_client:?}"
                            ));
                            let mut status = "200 OK";
                            let mut payload = body.as_bytes();
                            if let Some(required) = &bearer {
                                if authorization.as_deref() != Some(&format!("Bearer {required}")) {
                                    status = "401 Unauthorized";
                                    payload = b"";
                                }
                            }
                            if payload == body.as_bytes()
                                && if_none_match.as_deref() == Some(etag.as_str())
                            {
                                conditional.fetch_add(1, Ordering::SeqCst);
                                status = "304 Not Modified";
                                payload = b"";
                            }
                            let header = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                                 ETag: {etag}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                payload.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(payload);
                            let _ = stream.flush();
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            address,
            total,
            conditional,
            seen,
            shutdown,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }
}

impl Drop for CloudServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[test]
fn a_remote_provider_fetches_and_revalidates() {
    let _registry = exclusive();
    let server = CloudServer::start(&document("prov_cloud_client", "cloud"), "\"v1\"", None);
    // Impersonating a target while downloading exercises the client rebuild.
    let provider =
        RemoteProvider::new("prov-remote", server.url("/library")).with_profile("chrome131");
    register_provider(provider).unwrap();

    let record = fingerprint::find("prov_cloud_client").expect("the cloud record");
    assert_eq!(record.family, "cloud");
    assert_eq!(
        fingerprint::provider_of("prov_cloud_client").unwrap().id,
        "prov-remote"
    );
    let profile = Profile::find("prov_cloud_client").expect("a cloud record is a profile");
    assert_eq!(profile.family(), "cloud");
    assert!(server.total.load(Ordering::SeqCst) >= 1);

    // A refresh round-trips with If-None-Match and keeps the records on 304.
    // Another test may register a provider whose own reload fails, so only this
    // provider's health is checked.
    let refreshed = fingerprint::refresh_providers();
    assert!(
        refreshed.is_ok() || !refreshed.unwrap_err().contains("prov-remote"),
        "the remote provider revalidates"
    );
    assert!(
        server.conditional.load(Ordering::SeqCst) >= 1,
        "{:?}",
        server.seen
    );
    assert_eq!(
        fingerprint::find("prov_cloud_client").unwrap().family,
        "cloud"
    );

    unregister_provider("prov-remote").unwrap();
    assert!(fingerprint::find("prov_cloud_client").is_none());
}

#[test]
fn a_remote_provider_sends_a_bearer_token_and_custom_headers() {
    let _registry = exclusive();
    let server = CloudServer::start(
        &document("prov_cloud_auth", "cloud"),
        "\"v1\"",
        Some("secret"),
    );

    // The right token loads and the custom header is visible to the server.
    let provider = RemoteProvider::new("prov-auth-ok", server.url("/private"))
        .with_bearer_token("secret")
        .with_header("X-Client", "rust-curl-impersonate");
    register_provider(provider).unwrap();
    assert_eq!(
        fingerprint::find("prov_cloud_auth").unwrap().family,
        "cloud"
    );
    let logged = server.seen.lock().unwrap().clone();
    assert!(
        logged
            .iter()
            .any(|line| line.contains("x-client=Some(\"rust-curl-impersonate\")")),
        "{logged:?}"
    );
    unregister_provider("prov-auth-ok").unwrap();

    // A wrong token fails registration and leaves nothing behind.
    let error = register_provider(
        RemoteProvider::new("prov-auth-bad", server.url("/private")).with_bearer_token("wrong"),
    )
    .unwrap_err();
    assert!(error.contains("401"), "{error}");
    assert!(fingerprint::find("prov_cloud_auth").is_none());
    assert!(!fingerprint::providers()
        .iter()
        .any(|info| info.id == "prov-auth-bad"));
}

#[test]
fn loading_or_refreshing_a_provider_does_not_block_lookups() {
    let _registry = exclusive();
    // A gate that blocks every load until the test releases it, proving that
    // registration and refresh run `load` without holding the registry lock.
    use std::sync::mpsc::Sender;
    #[derive(Default)]
    struct Gate {
        block: bool,
        // (reports that a load started, releases that load) per blocking load
        active: Vec<(Sender<()>, Sender<()>)>,
    }
    let gate = Arc::new(Mutex::new(Gate::default()));
    let load = {
        let gate = Arc::clone(&gate);
        move || {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (go_tx, go_rx) = std::sync::mpsc::channel();
            {
                let mut gate = gate.lock().unwrap();
                if !gate.block {
                    return Ok(vec![record("prov_blocked", "go")]);
                }
                gate.active.push((started_tx, go_tx));
            }
            let _ = started_rx.recv_timeout(Duration::from_secs(10));
            let _ = go_rx.recv_timeout(Duration::from_secs(10));
            Ok(vec![record("prov_blocked", "go")])
        }
    };

    // Wait for one blocking load and take over its release channels.
    fn wait_for_load(gate: &Arc<Mutex<Gate>>) -> (Sender<()>, Sender<()>) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let mut gate = gate.lock().unwrap();
            if let Some(pair) = gate.active.pop() {
                return pair;
            }
            if std::time::Instant::now() > deadline {
                panic!("provider load never started");
            }
            drop(gate);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // Registration's load blocks; lookups must stay responsive.
    let register =
        std::thread::spawn(move || register_provider(FnProvider::new("prov-block", load)));
    {
        gate.lock().unwrap().block = true;
    }
    let (started, go) = wait_for_load(&gate);
    started.send(()).unwrap();
    let t = std::time::Instant::now();
    assert!(fingerprint::find("go1.26").is_some());
    assert!(fingerprint::providers()
        .iter()
        .any(|info| info.id == "builtin"));
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "lookups waited on a provider load"
    );
    go.send(()).unwrap();
    register
        .join()
        .unwrap()
        .expect("the blocked provider registers");
    assert_eq!(fingerprint::find("prov_blocked").unwrap().family, "go");

    // The same holds for a refresh whose reload blocks.
    let refresh = std::thread::spawn(move || fingerprint::refresh_providers());
    let (started, go) = wait_for_load(&gate);
    started.send(()).unwrap();
    let t = std::time::Instant::now();
    assert!(fingerprint::find("go1.26").is_some());
    assert!(fingerprint::providers()
        .iter()
        .any(|info| info.id == "builtin"));
    assert!(
        t.elapsed() < Duration::from_secs(3),
        "lookups waited on a refresh load"
    );
    go.send(()).unwrap();
    refresh
        .join()
        .unwrap()
        .expect("refresh applies once released");
    assert_eq!(fingerprint::find("prov_blocked").unwrap().family, "go");
    unregister_provider("prov-block").unwrap();

    // A malformed non-alias record is rejected at registration, before any name
    // appears in the merged view: an HTTP/3 profile whose cipher list can
    // neither come from the `http3` block nor fall back to the TLS list.
    let mut broken = record("prov_broken", "go");
    broken.tls = Default::default();
    broken.http3 = Some(fingerprint::Http3Fingerprint {
        settings: Some("1:1".to_string()),
        ..Default::default()
    });
    let error = register_provider(JsonProvider::new(
        "prov-broken",
        serde_json::to_string(&broken).unwrap(),
    ))
    .unwrap_err();
    assert!(error.contains("cipher"), "{error}");
    assert!(fingerprint::find("prov_broken").is_none());
}

#[test]
fn a_provider_record_can_express_a_complete_browser_profile() {
    let _registry = exclusive();
    // TLS and HTTP/2 come from the usual fields; HTTP/3, the multipart boundary
    // and cookie splitting are now record fields too, so a provider no longer
    // has to name a built-in preset to carry them.
    let mut full = record("prov_full_chrome", "chrome");
    // BoringSSL needs at least one TLS 1.2 suite, so the list is not TLS 1.3
    // only.
    full.tls.ciphers =
        Some("TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string());
    full.tls.alpn = Some(vec!["h2".to_string(), "http/1.1".to_string()]);
    full.form_boundary = Some("firefox".to_string());
    full.split_cookies = Some(true);
    full.http3 = Some(fingerprint::Http3Fingerprint {
        settings: Some("1:1;6:1;GREASE".to_string()),
        initial_packet_number: Some(1),
        pseudo_order: Some("m,a,s,p".to_string()),
        curves: Some("X25519".to_string()),
        grease: Some(true),
        ..Default::default()
    });
    register_provider(JsonProvider::new(
        "prov-full",
        serde_json::to_string(&full).unwrap(),
    ))
    .unwrap();

    let profile = Profile::find("prov_full_chrome").expect("the provider record");
    assert_eq!(profile.form_boundary(), Some(FormBoundary::Firefox));
    assert!(profile.split_cookies());

    let client = Client::new(profile).unwrap();
    let prepared = client.prepared();
    let http3 = prepared.http3().expect("the record carries HTTP/3");
    // The HTTP/3 cipher list falls back to the record's TLS ciphers.
    assert_eq!(http3.ciphers, full.tls.ciphers.as_deref().unwrap());
    assert!(http3
        .settings
        .iter()
        .any(|setting| matches!(setting, H3Setting::Grease)));
    assert_eq!(http3.initial_packet_number, Some(1));
    assert_eq!(prepared.http3_pseudo_order(), Some("m,a,s,p"));
    assert_eq!(prepared.form_boundary(), Some(FormBoundary::Firefox));
    assert!(prepared.splits_cookies());

    unregister_provider("prov-full").unwrap();
    assert!(Profile::find("prov_full_chrome").is_none());
}

#[test]
fn a_provider_record_can_override_a_builtin_preset() {
    let _registry = exclusive();
    // The 48 curl-impersonate presets are not a one-way street: a provider
    // record that reuses a preset name replaces the preset's wire settings,
    // HTTP/3 inputs and request behavior, without editing the generated table.
    let before = Profile::find("chrome150").unwrap();
    assert!(before
        .emulation()
        .tls_options
        .unwrap()
        .permute_extensions
        .unwrap());

    let mut patched = record("chrome150", "chrome");
    patched.tls.alpn = Some(vec!["h2".to_string(), "http/1.1".to_string()]);
    patched.tls.ciphers =
        Some("TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string());
    patched.form_boundary = Some("firefox".to_string());
    register_provider(JsonProvider::new(
        "prov-preset",
        serde_json::to_string(&patched).unwrap(),
    ))
    .unwrap();

    // The preset name now resolves to the provider record's wire settings.
    let after = Profile::find("chrome150").unwrap();
    assert_eq!(
        after
            .emulation()
            .tls_options
            .unwrap()
            .cipher_list
            .as_deref(),
        Some("TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    );
    let client = Client::new(after).unwrap();
    assert_eq!(
        client.prepared().form_boundary(),
        Some(FormBoundary::Firefox)
    );

    unregister_provider("prov-preset").unwrap();
    let restored = Profile::find("chrome150").unwrap();
    assert!(restored
        .emulation()
        .tls_options
        .unwrap()
        .permute_extensions
        .unwrap());
}
