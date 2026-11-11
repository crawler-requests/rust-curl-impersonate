//! Shipped-client checks for the curl-impersonate 2.4.0 options.
//!
//! Each assertion reads the emulation, QUIC configuration, or header list the
//! handshake and send path use.

use std::time::Duration;

use rust_curl_impersonate::profile::{self, H3Setting, TARGETS};
use rust_curl_impersonate::{Client, CookieProtocol, Profile, ProfileSpec};
use wreq::http2::PseudoId;
use wreq::tls::compress::CertificateCompressionAlgorithm;
use wreq::tls::ExtensionType;

fn client(target: &str) -> Client {
    Client::new(Profile::find(target).expect(target)).unwrap()
}

fn algorithms(client: &Client) -> Vec<CertificateCompressionAlgorithm> {
    client
        .prepared()
        .emulation()
        .tls_options
        .as_ref()
        .unwrap()
        .certificate_compressors
        .as_ref()
        .unwrap()
        .iter()
        .map(|compressor| compressor.algorithm())
        .collect()
}

fn anchor_ids(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut ids = Vec::new();
    let mut index = 0;
    while index < wire.len() {
        let len = wire[index] as usize;
        index += 1;
        assert!(index + len <= wire.len(), "truncated trust anchor");
        ids.push(wire[index..index + len].to_vec());
        index += len;
    }
    ids
}

#[tokio::test]
async fn presets_keep_their_tls_inputs_on_tcp_and_quic() {
    let chrome = client("chrome150");
    let tls = chrome.prepared().emulation().tls_options.as_ref().unwrap();
    assert!(tls.alps_protocols.is_some());
    assert!(tls.alps_use_new_codepoint);
    assert!(tls.session_ticket);
    assert_eq!(tls.permute_extensions, Some(true));
    assert_eq!(tls.grease_enabled, Some(true));
    assert!(tls.enable_signed_cert_timestamps);
    assert!(tls.enable_ocsp_stapling);
    assert!(tls.extension_permutation.is_none());
    assert!(tls.record_size_limit.is_none());
    assert!(tls.key_shares.is_none());
    assert!(tls.trust_anchors.is_none());
    assert!(tls.enforce_rsa_key_usage.is_none());
    assert_eq!(
        algorithms(&chrome),
        vec![CertificateCompressionAlgorithm::BROTLI]
    );
    for name in ["mldsa44", "mldsa65", "mldsa87"] {
        assert!(chrome.prepared().deviation().unwrap().contains(name));
        assert!(!tls.sigalgs_list.as_deref().unwrap().contains(name));
    }

    let endpoint = chrome.http3_endpoint().unwrap();
    let quic = endpoint.quic_tls();
    assert!(quic.alps && quic.new_alps);
    assert!(quic.session_ticket);
    assert!(quic.grease);
    assert!(quic.signed_cert_timestamps);
    assert!(quic.status_request);
    assert!(quic.record_size_limit.is_none());
    assert!(quic.trust_anchors.is_none());
    assert!(quic.enforce_rsa_key_usage.is_none());
    for name in ["mldsa44", "mldsa65", "mldsa87"] {
        assert!(!quic.sigalgs.contains(name));
    }
    assert_eq!(quic.cert_compression, vec!["brotli".to_string()]);

    let chrome151 = client("chrome151");
    assert_eq!(
        chrome151
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .record_size_limit,
        Some(0)
    );

    let firefox = client("firefox133");
    let tls = firefox.prepared().emulation().tls_options.as_ref().unwrap();
    assert_eq!(tls.record_size_limit, Some(16385));
    assert!(tls.delegated_credentials.is_some());
    assert!(tls.extension_permutation.is_some());
    assert_eq!(tls.key_shares.as_ref().unwrap().len(), 3);
    assert_eq!(
        algorithms(&firefox),
        vec![
            CertificateCompressionAlgorithm::ZLIB,
            CertificateCompressionAlgorithm::BROTLI,
            CertificateCompressionAlgorithm::ZSTD,
        ]
    );
    assert!(firefox.prepared().pseudo_order().is_some());

    let quic147 = client("firefox147").http3_endpoint().unwrap();
    let quic = quic147.quic_tls();
    assert_eq!(quic.record_size_limit, Some(16385));
    assert_eq!(quic.key_shares.len(), 3);
    assert_eq!(quic.cert_compression.len(), 3);
    assert!(quic.delegated_credentials.is_some());
    assert!(!quic.extension_permutation.is_empty());
    assert!(
        client("safari270")
            .http3_endpoint()
            .unwrap()
            .quic_tls()
            .session_ticket
            == false
    );

    let chrome152 = client("chrome152").http3_endpoint().unwrap();
    assert_eq!(chrome152.quic_tls().record_size_limit, Some(0));
}

#[tokio::test]
async fn caller_overrides_reach_the_tcp_and_quic_handshakes() {
    let profile = Profile::find("chrome150").unwrap();
    let cipher = profile
        .emulation()
        .tls_options
        .unwrap()
        .cipher_list
        .unwrap();
    let client = Client::builder(profile)
        .sigalgs("mldsa44:mldsa65:mldsa87:ecdsa_secp256r1_sha256")
        .enable_alps(false)
        .cert_compression("zlib,zstd")
        .session_ticket(false)
        .permute_extensions(false)
        .grease(false)
        .extension_order("0-5-10")
        .key_usage_no_check(true)
        .signed_cert_timestamps(false)
        .status_request(false)
        .delegated_credentials("ecdsa_secp256r1_sha256")
        .trust_anchors("1.2,1.3")
        .record_size_limit(0)
        .build()
        .unwrap();

    let tls = client.prepared().emulation().tls_options.as_ref().unwrap();
    assert_eq!(tls.cipher_list.as_deref(), Some(cipher.as_ref()));
    assert_eq!(tls.sigalgs_list.as_deref(), Some("ecdsa_secp256r1_sha256"));
    assert!(tls.alps_protocols.is_none());
    assert!(!tls.alps_use_new_codepoint);
    assert!(!tls.session_ticket);
    assert_eq!(tls.permute_extensions, Some(false));
    assert_eq!(tls.grease_enabled, Some(false));
    assert!(!tls.enable_signed_cert_timestamps);
    assert!(!tls.enable_ocsp_stapling);
    assert_eq!(
        tls.delegated_credentials.as_deref(),
        Some("ecdsa_secp256r1_sha256")
    );
    assert_eq!(tls.record_size_limit, Some(0));
    assert_eq!(tls.enforce_rsa_key_usage, Some(false));
    let ids = anchor_ids(tls.trust_anchors.as_deref().unwrap());
    assert_eq!(
        ids.iter()
            .map(|id| id.as_slice())
            .collect::<std::collections::BTreeSet<_>>(),
        [
            &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x01, 0x02][..],
            &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x01, 0x03][..],
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        tls.extension_permutation.as_ref().unwrap().as_ref(),
        &[
            ExtensionType::from(0u16),
            ExtensionType::from(5u16),
            ExtensionType::from(10u16),
        ]
    );
    assert_eq!(
        algorithms(&client),
        vec![
            CertificateCompressionAlgorithm::ZLIB,
            CertificateCompressionAlgorithm::ZSTD,
        ]
    );

    let quic = client.http3_endpoint().unwrap().quic_tls().clone();
    assert_eq!(quic.sigalgs, "ecdsa_secp256r1_sha256");
    assert!(!quic.alps);
    assert!(!quic.session_ticket);
    assert_eq!(quic.record_size_limit, Some(0));
    assert_eq!(quic.enforce_rsa_key_usage, Some(false));
    assert_eq!(
        quic.cert_compression,
        vec!["zlib".to_string(), "zstd".to_string()]
    );
    let quic_ids = anchor_ids(quic.trust_anchors.as_deref().unwrap());
    assert_eq!(quic_ids.len(), 2);
    assert!(quic_ids
        .iter()
        .any(|id| id.as_slice() == [0x2b, 0x06, 0x01, 0x04, 0x01, 0x01, 0x02]));

    let empty = Client::builder(profile).trust_anchors("").build().unwrap();
    assert_eq!(
        empty
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .trust_anchors
            .as_deref(),
        Some(&[][..])
    );
    assert_eq!(
        empty
            .http3_endpoint()
            .unwrap()
            .quic_tls()
            .trust_anchors
            .as_deref(),
        Some(&[][..])
    );

    let limited = Client::builder(Profile::find("firefox133").unwrap())
        .key_shares_limit(1)
        .build()
        .unwrap();
    assert_eq!(
        limited
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .key_shares
            .as_ref()
            .unwrap()
            .len(),
        1
    );
    let quic_limited = Client::builder(Profile::find("firefox147").unwrap())
        .key_shares_limit(1)
        .build()
        .unwrap();
    assert_eq!(
        quic_limited
            .http3_endpoint()
            .unwrap()
            .quic_tls()
            .key_shares
            .len(),
        1
    );
}

#[tokio::test]
async fn http3_tls_overrides_stay_on_the_quic_path() {
    let profile = Profile::find("chrome150").unwrap();
    let tcp_curves = profile
        .emulation()
        .tls_options
        .unwrap()
        .curves_list
        .unwrap();
    let client = Client::builder(profile)
        .sigalgs("ecdsa_secp256r1_sha256")
        .http3_curves("X25519")
        .http3_sigalgs("mldsa44:rsa_pss_rsae_sha256")
        .http3_extension_order("0-5-10")
        .http3_settings("1:9;GREASE")
        .http3_pseudo_order("mpas")
        .quic_cid("firefox")
        .quic_transport_parameters("1:30000")
        .build()
        .unwrap();
    assert_eq!(
        client
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .curves_list
            .as_deref(),
        Some(tcp_curves.as_ref())
    );
    assert_eq!(
        client
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .sigalgs_list
            .as_deref(),
        Some("ecdsa_secp256r1_sha256")
    );
    assert!(client
        .prepared()
        .emulation()
        .tls_options
        .as_ref()
        .unwrap()
        .extension_permutation
        .is_none());

    let endpoint = client.http3_endpoint().unwrap();
    let quic = endpoint.quic_tls();
    assert_eq!(quic.curves, "X25519");
    assert_eq!(quic.sigalgs, "rsa_pss_rsae_sha256");
    assert!(!quic.sigalgs.contains("mldsa"));
    assert_eq!(
        quic.extension_permutation,
        vec![
            ExtensionType::from(0u16),
            ExtensionType::from(5u16),
            ExtensionType::from(10u16),
        ]
    );
    assert_eq!(
        endpoint.settings_for_send(),
        &[H3Setting::Value(1, 9), H3Setting::Grease]
    );
    assert_eq!(endpoint.transport_parameters(), "1:30000");
    assert!(!endpoint.transport_parameter_bytes().is_empty());
    assert_eq!(endpoint.connection_id_lengths().1, 3);
    assert!((8..=20).contains(&endpoint.connection_id_lengths().0));
    let headers = endpoint.assemble_headers("example.com", "/", None);
    let pseudos: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.starts_with(':'))
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(pseudos, [":method", ":path", ":authority", ":scheme"]);
}

#[test]
fn http2_overrides_keep_unset_fields() {
    let profile = Profile::find("chrome150").unwrap();
    let client = Client::builder(profile)
        .http2_settings("1:4096;4:1000")
        .http2_window_update(999)
        .http2_streams(7)
        .http2_no_priority(true)
        .http2_pseudo_order("mpas")
        .stream_exclusive(0)
        .build()
        .unwrap();
    let http2 = client
        .prepared()
        .emulation()
        .http2_options
        .as_ref()
        .unwrap();
    assert_eq!(http2.header_table_size, Some(4096));
    assert_eq!(http2.initial_window_size, 1000);
    assert_eq!(http2.initial_conn_window_size, 999);
    assert_eq!(http2.max_concurrent_streams, Some(7));
    assert_eq!(http2.no_rfc7540_priorities, Some(true));
    assert_eq!(http2.max_header_list_size, Some(262144));
    assert_eq!(
        client.prepared().pseudo_order().unwrap(),
        vec![
            PseudoId::Method,
            PseudoId::Path,
            PseudoId::Authority,
            PseudoId::Scheme,
            PseudoId::Protocol,
            PseudoId::Status,
        ]
    );
    let dependency = http2.headers_stream_dependency.unwrap();
    let mut encoded = Vec::new();
    dependency.encode(&mut encoded);
    assert_eq!(encoded[0] & 0x80, 0);
    assert_eq!(encoded[4], 255);

    assert!(Client::builder(profile)
        .build()
        .unwrap()
        .prepared()
        .pseudo_order()
        .is_none());
    assert!(
        expect_builder_error(Client::builder(profile).http2_pseudo_order("mpasd").build())
            .is_builder()
    );
    assert!(
        expect_builder_error(Client::builder(profile).stream_exclusive(2).build()).is_builder()
    );
    assert!(
        expect_builder_error(Client::builder(profile).initial_packet_number(-2).build())
            .is_builder()
    );
    assert!(expect_builder_error(
        Client::builder(profile)
            .initial_packet_number(2_147_483_648)
            .build()
    )
    .is_builder());
}

fn store_cookies(client: &Client, version: wreq::Version) -> Vec<String> {
    use wreq::cookie::{CookieStore, Cookies};
    use wreq::header::HeaderValue;

    let uri = wreq::Uri::from_static("https://example.com/");
    let first = HeaderValue::from_static("a=1");
    let second = HeaderValue::from_static("b=2");
    let values = [&first, &second];
    let store = client.cookie_store();
    CookieStore::set_cookies(store, &mut values.into_iter(), &uri);
    match CookieStore::cookies(store, &uri, version) {
        Cookies::Compressed(value) => vec![value.to_str().unwrap().to_string()],
        Cookies::Uncompressed(values) => values
            .iter()
            .map(|value| value.to_str().unwrap().to_string())
            .collect(),
        Cookies::Empty => Vec::new(),
        _ => panic!("unexpected cookie serialization"),
    }
}

fn expect_builder_error(
    result: Result<Client, rust_curl_impersonate::Error>,
) -> rust_curl_impersonate::Error {
    match result {
        Err(err) => err,
        Ok(_) => panic!("expected a builder error"),
    }
}

#[tokio::test]
async fn headers_cookies_boundaries_and_http3_selection() {
    let profile = Profile::find("chrome150").unwrap();
    let client = Client::builder(profile)
        .header("user-agent", "Lab")
        .header("accept", "")
        .header("x-added", "1")
        .header_order("x-added,user-agent")
        .form_boundary("firefox")
        .split_cookies(false)
        .build()
        .unwrap();
    let names: Vec<_> = client
        .prepared()
        .regular_headers()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(names[0], "x-added");
    assert_eq!(names[1], "user-agent");
    assert_eq!(client.prepared().extra_header("user-agent"), Some("Lab"));
    assert!(client.prepared().extra_header("accept").is_none());
    assert!(client.prepared().extra_header("sec-ch-ua").is_some());
    let boundary = client.multipart().unwrap().boundary().to_string();
    assert!(boundary.starts_with("------geckoformboundary"));

    let h1 = client
        .request_cookies_for(
            wreq::Method::GET,
            "https://example.com",
            "a=1; b=2",
            CookieProtocol::Http1,
        )
        .build()
        .unwrap();
    let h1_cookies: Vec<_> = h1
        .headers()
        .get_all(wreq::header::COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    assert_eq!(h1_cookies, ["a=1; b=2"]);

    let split = Client::new(profile).unwrap();
    let h2 = split
        .request_cookies(wreq::Method::GET, "https://example.com", "a=1; b=2")
        .build()
        .unwrap();
    let h2_cookies: Vec<_> = h2
        .headers()
        .get_all(wreq::header::COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    assert_eq!(h2_cookies, ["a=1", "b=2"]);
    assert_eq!(
        store_cookies(&split, wreq::Version::HTTP_2),
        vec!["a=1".to_string(), "b=2".to_string()]
    );
    let merged = Client::builder(profile)
        .split_cookies(false)
        .build()
        .unwrap();
    assert_eq!(
        store_cookies(&merged, wreq::Version::HTTP_2),
        vec!["a=1; b=2".to_string()]
    );
    let endpoint = split.http3_endpoint().unwrap();
    let h3: Vec<_> = endpoint
        .assemble_headers("example.com", "/", Some("a=1; b=2"))
        .into_iter()
        .filter(|(name, _)| name == "cookie")
        .map(|(_, value)| value)
        .collect();
    assert_eq!(h3, ["a=1".to_string(), "b=2".to_string()]);

    let chrome152 = client_named("chrome152");
    let negotiated = chrome152.headers_after_negotiation(true).unwrap();
    assert!(negotiated
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("sec-fetch-mode") && value == "cors"));
    let fallback = chrome152.headers_after_negotiation(false).unwrap();
    assert!(fallback
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("sec-fetch-mode") && value == "navigate"));
    assert!(chrome152
        .prepared()
        .regular_headers()
        .iter()
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("sec-fetch-mode") && value == "navigate"
        }));
    let ios = client_named("safari270_ios");
    let ios_fallback = ios.headers_after_negotiation(false).unwrap();
    assert!(ios_fallback.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("sec-fetch-mode") && value == "navigate"
    }));
    assert!(ios_fallback
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("priority") && value == "u=0, i"));
    let ios_http3 = ios.headers_after_negotiation(true).unwrap();
    assert!(ios_http3
        .iter()
        .all(|(name, _)| !name.eq_ignore_ascii_case("sec-fetch-mode")));
    assert!(ios_http3
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("priority") && value == "u=3"));
    assert!(chrome152
        .http3_endpoint()
        .unwrap()
        .assemble_headers("example.com", "/", None)
        .iter()
        .any(|(name, value)| name == "sec-fetch-mode" && value == "cors"));

    let firefox = client_named("firefox153");
    assert!(firefox.prepared().http3().is_none());
    assert!(firefox.http3_endpoint().is_err());
    assert!(firefox.headers_after_negotiation(true).is_err());
    assert!(firefox
        .headers_after_negotiation(false)
        .unwrap()
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("user-agent")));
    assert!(profile::http3("firefox154").is_none());
    assert!(profile::http3("firefox155").is_none());

    let replaced = Client::builder(Profile::find("chrome152").unwrap())
        .http3_header("x-h3", "1")
        .http3_header_order("x-h3")
        .build()
        .unwrap();
    let fields = replaced.headers_after_negotiation(true).unwrap();
    assert_eq!(fields, vec![("x-h3".to_string(), "1".to_string())]);
    assert_eq!(
        replaced
            .http3_endpoint()
            .unwrap()
            .assemble_headers("example.com", "/", None)
            .into_iter()
            .find(|(name, _)| !name.starts_with(':'))
            .unwrap(),
        ("x-h3".to_string(), "1".to_string())
    );
}

fn client_named(target: &str) -> Client {
    client(target)
}

#[test]
fn impersonate_register_and_websocket_overrides() {
    let with_headers = Client::impersonate("chrome150:yes").unwrap();
    assert!(with_headers.prepared().extra_header("user-agent").is_some());
    let without = Client::impersonate("chrome150:no").unwrap();
    assert!(without.prepared().extra_header("user-agent").is_none());
    let explicit = Client::impersonate_choice(Some("chrome150"), Some("firefox133:no")).unwrap();
    assert_eq!(explicit.profile().target(), "chrome150");
    assert!(explicit.prepared().extra_header("user-agent").is_some());
    let from_env = Client::impersonate_choice(None, Some("firefox133:no")).unwrap();
    assert_eq!(from_env.profile().target(), "firefox133");
    assert!(from_env.prepared().regular_headers().is_empty());

    let registered =
        Profile::register("lab-browser-240", Profile::find("chrome150").unwrap()).unwrap();
    assert_eq!(registered.target(), "chrome150");
    assert_eq!(registered.name(), "lab-browser-240");
    assert_eq!(TARGETS.len(), 48);
    assert!(Profile::find("okhttp4_android").is_some());
    let client = Client::new(Profile::find("lab-browser-240").unwrap()).unwrap();
    assert_eq!(client.prepared().name(), "lab-browser-240");
    assert_eq!(client.profile().target(), "chrome150");
    assert!(client
        .prepared()
        .cipher_list()
        .unwrap()
        .contains("TLS_AES_128_GCM_SHA256"));

    let profile = Profile::find("chrome150").unwrap();
    let ws = Client::builder(profile)
        .ws_header("x-ws", "1")
        .ws_header_order("x-ws")
        .ws_disable_ticket(true)
        .ws_cert_compression("zlib")
        .build()
        .unwrap();
    assert!(
        ws.prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .session_ticket
    );
    let ws_tls = ws
        .prepared()
        .websocket_emulation()
        .unwrap()
        .tls_options
        .as_ref()
        .unwrap();
    assert!(!ws_tls.session_ticket);
    assert_eq!(
        ws_tls
            .certificate_compressors
            .as_ref()
            .unwrap()
            .iter()
            .map(|compressor| compressor.algorithm())
            .collect::<Vec<_>>(),
        vec![CertificateCompressionAlgorithm::ZLIB]
    );
    let names: Vec<_> = ws
        .prepared()
        .websocket_emulation()
        .unwrap()
        .headers
        .keys()
        .map(|name| name.as_str().to_string())
        .collect();
    assert_eq!(names, ["x-ws"]);
    let upgrade = ws.websocket_deflate("wss://example.com");
    assert_eq!(
        upgrade.extensions(),
        "permessage-deflate; client_max_window_bits"
    );
    assert_eq!(upgrade.headers(), [("x-ws".to_string(), "1".to_string())]);

    let mut codec = upgrade.accepted_codec();
    let text = codec.encode(0x1, b"hello impersonate", false).unwrap();
    assert!(text.rsv1);
    assert_ne!(text.payload.as_slice(), b"hello impersonate");
    assert_eq!(codec.decode(&text).unwrap(), b"hello impersonate");
    let binary = codec.encode(0x2, b"abc", false).unwrap();
    assert!(binary.rsv1);
    assert_eq!(codec.decode(&binary).unwrap(), b"abc");
    let ping = codec.encode(0x9, b"ping", false).unwrap();
    assert!(!ping.rsv1);
    assert_eq!(ping.payload, b"ping");
    match codec.encode(0x1, b"x", true) {
        Err(err) => assert!(err.is_argument()),
        Ok(_) => panic!("raw mode with deflate must be rejected"),
    }
    match ws.try_websocket_deflate("wss://example.com", false) {
        Err(err) => assert!(err.is_not_built()),
        Ok(_) => panic!("missing zlib must be a not-built error"),
    }
}

#[test]
fn delegated_dns_and_credential_isolation() {
    let profile = Profile::find("chrome150").unwrap();
    for scheme in ["http", "https", "socks4a", "socks5h"] {
        let delegated = Client::builder(profile)
            .proxy_url(&format!("{scheme}://127.0.0.1:9"))
            .unwrap()
            .build()
            .unwrap();
        let addrs = delegated.lookup_origin("localhost");
        assert!(addrs.is_empty(), "{scheme} resolved the origin: {addrs:?}");
        assert!(
            !delegated
                .direct_queries()
                .iter()
                .any(|name| name == "localhost"),
            "{scheme} still asked the system resolver: {:?}",
            delegated.direct_queries()
        );
    }

    let local = Client::builder(profile)
        .proxy_url("socks5://127.0.0.1:9")
        .unwrap()
        .build()
        .unwrap();
    let addrs = local.lookup_origin("localhost");
    assert!(
        addrs.iter().any(|addr| addr.ip().is_loopback()),
        "local SOCKS did not resolve localhost: {addrs:?}"
    );
    assert!(local
        .direct_queries()
        .iter()
        .any(|name| name == "localhost"));

    let isolated = Client::builder(profile)
        .proxy_credential_no_reuse(true)
        .build()
        .unwrap();
    isolated.proxy_credentials("ann", "one");
    let generation = isolated.session_generation();
    assert!(isolated.session_accepts(generation));
    isolated.proxy_credentials("ann", "two");
    assert!(!isolated.session_accepts(generation));
    assert!(isolated.session_accepts(isolated.session_generation()));
}

#[tokio::test]
async fn delegated_proxy_hostname_is_resolved_and_the_origin_is_not() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await;
            });
        }
    });

    let profile = Profile::find("chrome150").unwrap();
    let client = Client::builder(profile)
        .proxy_url(&format!("http://localhost:{port}"))
        .unwrap()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let response = client
        .get("http://example.com/")
        .send()
        .await
        .expect("proxy connection");
    assert!(response.status().is_success());
    let queries = client.direct_queries();
    assert!(
        queries
            .iter()
            .any(|name| name.eq_ignore_ascii_case("localhost")),
        "proxy host was not resolved: {queries:?}"
    );
    assert!(
        !queries
            .iter()
            .any(|name| name.eq_ignore_ascii_case("example.com")),
        "origin was resolved while connecting: {queries:?}"
    );
    let origin = client.lookup_origin("example.com");
    assert!(
        origin.is_empty(),
        "delegated origin lookup returned {origin:?}"
    );
    assert!(
        !client
            .direct_queries()
            .iter()
            .any(|name| name.eq_ignore_ascii_case("example.com")),
        "origin lookup called the system resolver: {:?}",
        client.direct_queries()
    );
}

#[tokio::test]
async fn redirects_and_cookie_changes_use_the_installed_policy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let body = if text.contains("GET /go ") {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://10.1.2.3/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                } else if text.contains("GET /set ") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: id=1; Path=/\r\nSet-Cookie: gone=; Max-Age=0; Path=/\r\nConnection: close\r\n\r\nOK"
                        .to_string()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                        .to_string()
                };
                let _ = socket.write_all(body.as_bytes()).await;
            });
        }
    });

    let profile = Profile::find("chrome150").unwrap();
    let safe = Client::builder(profile)
        .follow_safe(true)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let initial = safe.get(format!("http://127.0.0.1:{port}/ok")).send().await;
    assert!(initial.unwrap().status().is_success());
    let blocked = safe.get(format!("http://127.0.0.1:{port}/go")).send().await;
    assert!(blocked.is_err());
    let history = safe.redirect_history();
    assert!(
        history
            .iter()
            .any(|line| line.starts_with("302\t") && line.contains("/go")),
        "{history:?}"
    );

    let cookies = Client::builder(profile)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    cookies
        .get(format!("http://127.0.0.1:{port}/set"))
        .send()
        .await
        .unwrap();
    let changes = cookies.cookie_changes();
    assert!(
        changes
            .iter()
            .any(|line| line.starts_with("SET\t") && line.contains("id\t1")),
        "{changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|line| line.starts_with("DELETE\t") && line.contains("gone")),
        "{changes:?}"
    );
}

/// A name that is not in the generated table reaches the handshake as data.
#[tokio::test]
async fn caller_supplied_chrome_reaches_the_handshake() {
    let builtins = ["chrome150", "chrome151", "chrome152", "chrome152_macos"];
    let before: Vec<_> = builtins.iter().map(|name| wire_snapshot(name)).collect();

    let chrome150 = Client::new(Profile::find("chrome150").unwrap()).unwrap();
    let exposed = Profile::find("chrome150").unwrap().emulation();
    let exposed_tls = exposed.tls_options.as_ref().unwrap();
    let exposed_http2 = exposed.http2_options.as_ref().unwrap();
    let chrome150_cipher = chrome150.prepared().cipher_list().unwrap().to_string();
    assert_eq!(
        chrome150_cipher.as_str(),
        exposed_tls.cipher_list.as_deref().unwrap()
    );
    let chrome150_table = exposed_http2.header_table_size;
    assert_eq!(
        chrome150
            .prepared()
            .emulation()
            .http2_options
            .as_ref()
            .unwrap()
            .header_table_size,
        chrome150_table
    );
    let chrome150_ua = exposed
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        chrome150.prepared().extra_header("user-agent"),
        Some(chrome150_ua.as_str())
    );
    assert!(
        chrome150
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .enable_ocsp_stapling
    );
    let chrome150_h3 = chrome150.http3_endpoint().unwrap();
    assert!(
        chrome150_h3.quic_tls().status_request,
        "chrome150 QUIC leaves OCSP stapling on"
    );
    assert_eq!(
        chrome150_h3.quic_tls().curves,
        chrome150.prepared().http3().unwrap().curves
    );
    assert_eq!(
        chrome150_h3.profile().settings,
        chrome150.prepared().http3().unwrap().settings
    );

    // The captured list already omits the three ML-DSA names. Putting them back
    // around every algorithm that preset still exposes must install that same
    // list and nothing else.
    let preset_sigalgs = exposed_tls.sigalgs_list.as_deref().unwrap().to_string();
    let with_mldsa = format!("mldsa44:{preset_sigalgs}:mldsa65:mldsa87");
    let resigned = Client::builder(Profile::find("chrome150").unwrap())
        .sigalgs(&with_mldsa)
        .build()
        .unwrap();
    let installed = resigned
        .prepared()
        .emulation()
        .tls_options
        .as_ref()
        .unwrap()
        .sigalgs_list
        .as_deref()
        .unwrap();
    assert_eq!(installed, preset_sigalgs);
    for name in ["mldsa44", "mldsa65", "mldsa87"] {
        assert!(
            !installed.split(':').any(|part| part == name),
            "{name} was installed"
        );
    }
    assert_eq!(
        resigned.prepared().cipher_list(),
        Some(chrome150_cipher.as_str())
    );

    let h3_sigalgs = chrome150_h3.quic_tls().sigalgs.clone();
    let h3_with = format!("mldsa44:{h3_sigalgs}:mldsa65:mldsa87");
    let h3_resigned = Client::builder(Profile::find("chrome150").unwrap())
        .http3_sigalgs(&h3_with)
        .build()
        .unwrap();
    let h3_endpoint = h3_resigned.http3_endpoint().unwrap();
    assert_eq!(h3_endpoint.quic_tls().sigalgs, h3_sigalgs);
    for name in ["mldsa44", "mldsa65", "mldsa87"] {
        assert!(
            !h3_endpoint
                .quic_tls()
                .sigalgs
                .split(':')
                .any(|part| part == name),
            "{name} was installed on QUIC"
        );
    }
    assert!(h3_endpoint.quic_tls().status_request);
    assert_eq!(
        h3_resigned.prepared().cipher_list(),
        Some(chrome150_cipher.as_str())
    );

    let chrome150_headers = before[0].1.clone();
    assert!(
        chrome150_cipher.contains(':'),
        "chrome150 cipher list is a captured preset, not a single suite"
    );
    assert!(
        chrome150_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("user-agent") && value == &chrome150_ua
        }),
        "chrome150 header table is the captured preset"
    );

    let supplied_cipher = "TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256";
    let supplied_sigalgs = "mldsa44:ecdsa_secp256r1_sha256:mldsa65:rsa_pss_rsae_sha256:mldsa87";
    let installed_sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256";
    let profile = ProfileSpec::new("lab-chrome-next")
        .cipher_list(supplied_cipher)
        .sigalgs(supplied_sigalgs)
        .http2_settings("1:8192")
        .header("x-lab-future", "next")
        .install()
        .unwrap();
    assert_eq!(profile.name(), "lab-chrome-next");
    assert_eq!(profile.target(), "lab-chrome-next");
    assert!(!TARGETS.contains(&"lab-chrome-next"));
    assert!(profile::http3("lab-chrome-next").is_none());
    assert_eq!(TARGETS.len(), 48);

    let client = Client::new(Profile::find("lab-chrome-next").unwrap()).unwrap();
    let tls = client.prepared().emulation().tls_options.as_ref().unwrap();
    let http2 = client
        .prepared()
        .emulation()
        .http2_options
        .as_ref()
        .unwrap();
    assert_eq!(tls.cipher_list.as_deref(), Some(supplied_cipher));
    assert_ne!(tls.cipher_list.as_deref(), Some(chrome150_cipher.as_str()));
    assert_ne!(http2.header_table_size, chrome150_table);
    assert_eq!(tls.sigalgs_list.as_deref(), Some(installed_sigalgs));
    for name in ["mldsa44", "mldsa65", "mldsa87"] {
        assert!(
            !tls.sigalgs_list
                .as_deref()
                .unwrap()
                .split(':')
                .any(|part| part == name),
            "{name} was installed"
        );
    }
    assert!(tls.curves_list.is_none());
    assert!(tls.grease_enabled.is_none());
    assert!(tls.permute_extensions.is_none());
    assert!(!tls.enable_ech_grease);
    assert!(tls.alps_protocols.is_none());
    assert!(tls.extension_permutation.is_none());
    assert!(tls.certificate_compressors.is_none());
    assert!(tls.record_size_limit.is_none());
    assert!(tls.key_shares.is_none());
    assert!(!tls.enable_ocsp_stapling);
    assert_eq!(http2.header_table_size, Some(8192));
    assert!(http2.headers_pseudo_order.is_none());
    assert!(client.prepared().pseudo_order().is_none());
    assert!(http2.headers_stream_dependency.is_none());
    assert_ne!(http2.initial_window_size, 6_291_456);
    assert_eq!(
        client.prepared().regular_headers(),
        [("x-lab-future".to_string(), "next".to_string())]
    );
    assert!(chrome150_headers
        .iter()
        .all(|(name, value)| { !(name.eq_ignore_ascii_case("x-lab-future") && value == "next") }));
    assert!(client.prepared().http3().is_none());
    assert!(client.http3_endpoint().is_err());

    let again = Client::new(Profile::find("lab-chrome-next").unwrap()).unwrap();
    assert_eq!(again.prepared().cipher_list(), Some(supplied_cipher));
    assert_eq!(
        again
            .prepared()
            .emulation()
            .http2_options
            .as_ref()
            .unwrap()
            .header_table_size,
        Some(8192)
    );
    assert_eq!(again.prepared().extra_header("x-lab-future"), Some("next"));

    let overridden = Client::builder(Profile::find("lab-chrome-next").unwrap())
        .http2_settings("1:2048")
        .build()
        .unwrap();
    assert_eq!(
        overridden
            .prepared()
            .emulation()
            .http2_options
            .as_ref()
            .unwrap()
            .header_table_size,
        Some(2048)
    );
    assert_eq!(overridden.prepared().cipher_list(), Some(supplied_cipher));
    assert_eq!(
        overridden
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .sigalgs_list
            .as_deref(),
        Some(installed_sigalgs)
    );
    assert_eq!(
        overridden.prepared().extra_header("x-lab-future"),
        Some("next")
    );
    assert!(overridden.prepared().pseudo_order().is_none());
    assert!(overridden.prepared().http3().is_none());

    let h3_profile = ProfileSpec::new("lab-chrome-next-h3")
        .cipher_list(supplied_cipher)
        .http3_curves("X25519")
        .http3_settings("1:111;6:222")
        .initial_packet_number(17)
        .install()
        .unwrap();
    assert!(profile::http3("lab-chrome-next-h3").is_none());
    let h3 = Client::new(Profile::find(h3_profile.name()).unwrap()).unwrap();
    let endpoint = h3.http3_endpoint().unwrap();
    assert_eq!(endpoint.quic_tls().curves, "X25519");
    assert_eq!(endpoint.quic_tls().ciphers, supplied_cipher);
    assert_ne!(endpoint.quic_tls().ciphers, chrome150_cipher);
    assert!(endpoint.quic_tls().sigalgs.is_empty());
    assert_eq!(
        endpoint.settings_for_send(),
        &[H3Setting::Value(1, 111), H3Setting::Value(6, 222)]
    );
    assert_eq!(endpoint.initial_packet_number(), Some(17));
    assert_eq!(endpoint.profile().transport_parameters, "");
    assert_eq!(endpoint.profile().pseudo_order, "");
    assert!(endpoint.profile().headers.is_empty());
    let fields = endpoint.assemble_headers("example.com", "/", None);
    assert!(
        fields.is_empty(),
        "unset pseudo-order and headers stay unset: {fields:?}"
    );
    let pairs: Vec<(&str, &str)> = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let frame = rust_curl_impersonate::quic::h3::headers_frame(&pairs);
    assert!(!frame.is_empty(), "HEADERS frame");
    assert!(
        frame.len() < 6,
        "empty header block is shorter than 6 bytes, got {}",
        frame.len()
    );
    assert!(endpoint.profile().cid_profile.is_none());
    assert!(endpoint.profile().extension_permutation.is_empty());
    assert!(
        !endpoint.quic_tls().status_request,
        "unset OCSP must stay off on the QUIC handshake"
    );

    let ocsp_off = ProfileSpec::new("lab-chrome-next-h3-ocsp")
        .cipher_list(supplied_cipher)
        .ocsp_stapling(false)
        .http3_curves("X25519")
        .http3_settings("1:111;6:222")
        .initial_packet_number(17)
        .install()
        .unwrap();
    let ocsp_client = Client::new(Profile::find(ocsp_off.name()).unwrap()).unwrap();
    let ocsp_endpoint = ocsp_client.http3_endpoint().unwrap();
    assert!(!ocsp_endpoint.quic_tls().status_request);
    assert!(
        !ocsp_client
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .enable_ocsp_stapling
    );
    assert_eq!(ocsp_endpoint.quic_tls().curves, "X25519");
    assert_eq!(
        ocsp_endpoint.settings_for_send(),
        endpoint.settings_for_send()
    );
    assert_eq!(ocsp_endpoint.initial_packet_number(), Some(17));

    assert!(chrome150_h3.quic_tls().status_request);

    let after: Vec<_> = builtins.iter().map(|name| wire_snapshot(name)).collect();
    assert_eq!(before, after);
}

fn wire_snapshot(name: &str) -> (String, Vec<(String, String)>) {
    let profile = Profile::find(name).unwrap_or_else(|| panic!("{name} resolves"));
    assert_eq!(profile.target(), name);
    assert_eq!(profile.name(), name);
    let client = Client::new(profile).unwrap();
    assert_eq!(client.profile().target(), name);
    (
        client.prepared().cipher_list().unwrap().to_string(),
        client.prepared().regular_headers().to_vec(),
    )
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
