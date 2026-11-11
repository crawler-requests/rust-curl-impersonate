//! The built-in and caller-supplied fingerprint library.
//!
//! The records are captured from real clients with `tools/capture`, then
//! reduced by `tools/gen_fingerprints.py` to the fields BoringSSL can send.
//! These tests check the data and the path from a record to wire options; the
//! live handshake is compared separately with `examples/echo`.

use rust_curl_impersonate::fingerprint::{self, Fidelity};
use rust_curl_impersonate::{Client, FormBoundary, Profile};
use wreq::tls::{AlpnProtocol, AlpsProtocol};

fn ids(value: &str) -> Vec<&str> {
    value.split(':').collect()
}

#[test]
fn embedded_library_has_the_expected_clients() {
    let names = fingerprint::names();
    assert_eq!(names.len(), fingerprint::builtin().len());
    for expected in [
        "go1.26",
        "python3.12_requests",
        "python3.12_urllib",
        "python3.12_aiohttp",
        "curl8.5_h2",
        "curl8.5_http1",
        "java21_httpclient",
        "java21_urlconn",
        "node22_https",
        "node22_http2",
        "golang",
        "python",
        "curl",
        "java",
        "node",
        "chrome_android",
        "safari_ios",
        "okhttp_android",
        "node22_fetch",
        "go1.26_http1",
        "python3.12_httpx",
        "python3.12_httpclient",
        "bun1.3.14",
        "php8.3_curl",
        "php8.3_streams",
        "wget1.21.4",
        "perl5_lwp",
        "openssl3_sclient",
        "rust_reqwest_rustls",
        "chromium156",
        "chromium157",
        "chrome158",
        "chrome159",
        "firefox158",
        "firefox159",
        "firefox160",
        "firefox161",
        "firefox162",
        "bun",
        "php",
        "wget",
        "perl",
        "rust",
        "httpx",
        "chrome",
        "firefox",
        "openssl",
        "android_confirmed",
        "android_confirmed2",
        "android_mesh",
        "android_mesh1",
        "android_okhttp7",
        "android_okhttp8",
        "android_okhttp9",
        "android_okhttp10",
        "android_okhttp11",
        "android_okhttp12",
        "android_okhttp13",
        "android_nike",
        "android_zalando",
        "ios_confirmed",
        "ios_safari18_5",
        "ios_safari26",
        "opera91",
        "android",
        "android7",
        "android8",
        "android9",
        "ios",
        "opera",
        "tlsclient_chrome103",
        "tlsclient_chrome133",
        "tlsclient_chrome152",
        "tlsclient_firefox102",
        "tlsclient_firefox148",
        "tlsclient_safari15_6_1",
        "tlsclient_ios_safari18",
        "tlsclient_ios_mms",
        "tlsclient_opera89",
        "tlsclient_brave146",
        "tlsclient_cloudflare",
        "utls_chrome58",
        "utls_chrome106shuffle",
        "utls_chrome115pq",
        "utls_chrome133",
        "utls_firefox55",
        "utls_firefox120",
        "utls_safari16",
        "utls_ios11",
        "utls_android11okhttp",
        "utls_edge85",
        "utls_360_7_5",
        "utls_qq11_1",
        "go1.21",
        "go1.24",
        "node24_https",
        "node24_http2",
        "curl7.88.1_h2",
        "curl8.10.1_h2",
        "python3.9_urllib",
        "python3.11_urllib",
        "java8_urlconn",
        "java11_httpclient",
        "java17_urlconn",
        "openssl1.1_sclient",
        "openssl3.3_sclient",
        "wget1.21_bookworm",
        "php8.1_streams",
    ] {
        assert!(names.contains(&expected), "{expected} is in the library");
        assert!(Profile::find(expected).is_some(), "{expected} resolves");
    }
    for family in [
        "go",
        "python",
        "curl",
        "java",
        "node",
        "chrome",
        "safari",
        "okhttp",
        "firefox",
        "bun",
        "php",
        "wget",
        "perl",
        "rust",
        "openssl",
        "android",
        "ios",
        "opera",
        "brave",
        "cloudflare",
        "edge",
        "360",
        "qq",
    ] {
        assert!(
            fingerprint::families().contains(&family),
            "family {family} is present"
        );
    }
    // Eight captures (3.8/3.9/3.11/3.12/3.13 across requests/urllib/httpx/...)
    // plus the `python` and `httpx` aliases.
    assert_eq!(fingerprint::by_family("python").count(), 10);
}

#[test]
fn every_embedded_record_validates() {
    let mut seen = Vec::new();
    for record in fingerprint::builtin() {
        assert!(!record.name.is_empty());
        assert!(record.validate().is_ok(), "{} validates", record.name);
        assert!(!seen.contains(&record.name), "{} is unique", record.name);
        seen.push(record.name.clone());

        // Aliases point at a base record and inherit its wire settings.
        if let Some(base) = &record.extends {
            assert!(Profile::find(base).is_some(), "{} base exists", record.name);
            let alias = Profile::find(&record.name).unwrap();
            assert_eq!(alias.target(), base);
            assert_eq!(alias.name(), record.name);
        }
    }
}

#[test]
fn go_fingerprint_matches_its_capture() {
    let record = fingerprint::find("go1.26").unwrap();
    assert_eq!(record.family, "go");
    assert_eq!(record.platform, "linux");
    assert_eq!(record.fidelity, Some(Fidelity::Close));
    assert_eq!(
        ids(record.tls.ciphers.as_deref().unwrap())[0],
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    );
    assert_eq!(
        record.tls.curves.as_deref(),
        Some("X25519MLKEM768:X25519:P-256:P-384:P-521")
    );
    assert_eq!(
        record.tls.extension_order.as_deref(),
        Some("0-11-65281-23-18-5-10-13-16-43-51")
    );
    assert_eq!(
        record.alpn().unwrap(),
        &["h2".to_string(), "http/1.1".to_string()][..]
    );
    assert!(!record.http1_only());

    let http2 = record.http2.as_ref().unwrap();
    assert_eq!(
        http2.settings.as_deref(),
        Some("2:0;4:4194304;5:16384;6:10485760")
    );
    assert_eq!(http2.window_update, Some(1_073_741_824));
    assert_eq!(http2.pseudo_order.as_deref(), Some("amps"));
    assert_eq!(http2.initial_window_size, Some(4_194_304));
    assert!(record
        .headers
        .iter()
        .any(|(name, value)| name == "user-agent" && value == "Go-http-client/2.0"));
    assert!(record
        .headers
        .iter()
        .any(|(name, value)| name == "accept-encoding" && value == "gzip"));

    // The transport cannot send the captured TLS 1.3 position or these fields;
    // the record says so instead of hiding it.
    let note = record.deviation().unwrap();
    assert!(note.contains("TLS 1.3 cipher suites"));
    assert!(note.contains("signature_algorithms_cert"));
    assert!(note.contains("4587"));

    let emulation = Profile::find("go1.26").unwrap().emulation();
    let tls = emulation.tls_options.unwrap();
    assert_eq!(
        tls.alpn_protocols.as_deref(),
        Some(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1][..])
    );
    assert_eq!(
        tls.curves_list.as_deref(),
        Some("X25519MLKEM768:X25519:P-256:P-384:P-521")
    );
    let http2 = emulation.http2_options.unwrap();
    // The transport reports the connection window target; the wire increment
    // is target - 65535, which is what the capture shows.
    assert_eq!(http2.initial_conn_window_size, 1_073_741_824 + 65_535);
    assert_eq!(http2.initial_window_size, 4_194_304);
}

#[test]
fn browser_captures_keep_grease_alps_ech_and_compression() {
    let chrome = fingerprint::find("chromium156").unwrap();
    assert_eq!(chrome.fidelity, Some(Fidelity::Close));
    assert!(chrome.tls.grease, "Chromium greases every list");
    assert!(chrome.tls.alps, "Chromium advertises ALPS");
    assert!(chrome.tls.new_alps_codepoint);
    assert!(chrome.tls.ech_grease);
    assert_eq!(chrome.tls.cert_compression.as_deref(), Some("brotli"));
    assert!(
        chrome.tls.permute_extensions,
        "Chrome shuffles the extension list on every connection"
    );
    // The captured order is the set to permute, not a fixed wire order.
    let mut got: Vec<u32> = chrome
        .tls
        .extension_order
        .as_deref()
        .unwrap()
        .split('-')
        .map(|id| id.parse().unwrap())
        .collect();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17_613, 65_037, 65_281]
    );
    assert!(chrome
        .tls
        .extension_order
        .as_deref()
        .unwrap()
        .split('-')
        .all(|id| id != "51764"));
    let http2 = chrome.http2.as_ref().unwrap();
    assert_eq!(
        http2.settings.as_deref(),
        Some("1:65536;2:0;4:6291456;6:262144")
    );
    assert_eq!(http2.pseudo_order.as_deref(), Some("masp"));
    assert_eq!(http2.window_update, Some(15_663_105));
    let note = chrome.deviation().unwrap();
    assert!(note.contains("mldsa44"));
    assert!(note.contains("51764"));

    let tls = Profile::find("chromium156")
        .unwrap()
        .emulation()
        .tls_options
        .unwrap();
    assert_eq!(tls.grease_enabled, Some(true));
    assert_eq!(tls.permute_extensions, Some(true));
    // A fixed extension order would pin the listed extensions; Chrome
    // reshuffles them on every connection, so none is installed.
    assert!(tls.extension_permutation.is_none());
    assert_eq!(
        tls.alps_protocols.as_deref(),
        Some(&[AlpsProtocol::HTTP2][..])
    );
    assert!(tls.alps_use_new_codepoint);
    assert!(tls.enable_ech_grease);
    assert_eq!(tls.certificate_compressors.unwrap().len(), 1);

    let firefox = fingerprint::find("firefox158").unwrap();
    assert_eq!(firefox.fidelity, Some(Fidelity::Exact));
    assert_eq!(firefox.tls.record_size_limit, Some(16_385));
    assert_eq!(
        firefox.tls.cert_compression.as_deref(),
        Some("zlib:brotli:zstd")
    );
    assert_eq!(
        firefox.tls.delegated_credentials.as_deref(),
        Some(
            "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:\
             ecdsa_secp521r1_sha512:ecdsa_sha1"
        )
    );
    assert!(firefox.tls.ech_grease);
    assert_eq!(
        firefox.tls.extension_order.as_deref(),
        Some("0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037")
    );
    let http2 = firefox.http2.as_ref().unwrap();
    assert_eq!(
        http2.settings.as_deref(),
        Some("1:65536;2:0;4:131072;5:16384")
    );
    assert_eq!(http2.pseudo_order.as_deref(), Some("mpas"));
    let tls = Profile::find("firefox158")
        .unwrap()
        .emulation()
        .tls_options
        .unwrap();
    assert_eq!(tls.record_size_limit, Some(16_385));
    assert_eq!(tls.certificate_compressors.unwrap().len(), 3);
    assert_eq!(
        tls.delegated_credentials.as_deref(),
        Some(
            "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:\
             ecdsa_secp521r1_sha512:ecdsa_sha1"
        )
    );

    assert_eq!(
        Profile::find("chrome").unwrap().fidelity(),
        Some(Fidelity::Close)
    );
    assert_eq!(
        Profile::find("firefox").unwrap().fidelity(),
        Some(Fidelity::Exact)
    );
}

#[test]
fn modern_runtimes_are_embedded() {
    // Bun is a BoringSSL client: every captured field is inside the transport.
    let bun = fingerprint::find("bun1.3.14").unwrap();
    assert_eq!(bun.fidelity, Some(Fidelity::Exact));
    assert_eq!(bun.alpn(), Some(&["http/1.1".to_string()][..]));
    assert!(bun.http1_only());
    assert!(!bun.tls.grease);

    // rustls sends a small, BoringSSL-sendable ClientHello apart from the
    // renegotiation SCSV.
    let rust = fingerprint::find("rust_reqwest_rustls").unwrap();
    assert_eq!(rust.fidelity, Some(Fidelity::Close));
    assert!(rust
        .deviation()
        .unwrap()
        .contains("TLS_EMPTY_RENEGOTIATION_INFO"));
    assert_eq!(
        rust.http2.as_ref().unwrap().pseudo_order.as_deref(),
        Some("msap")
    );
    assert!(Profile::find("rust").is_some());

    // OpenSSL-family HTTP/1.1 tools and the OpenSSL-backed HTTP/2 clients.
    for name in ["php8.3_curl", "python3.12_httpx", "node22_fetch"] {
        assert_eq!(
            fingerprint::find(name).unwrap().fidelity,
            Some(Fidelity::Partial),
            "{name}"
        );
    }
    assert!(fingerprint::find("node22_fetch").unwrap().http1_only());
    assert!(!fingerprint::find("php8.3_curl").unwrap().http1_only());
}

#[test]
fn mobile_and_opera_records_cover_android_and_ios() {
    // A TLS 1.2-only Android app: no supported_versions, no TLS 1.3 suite.
    let android = fingerprint::find("android_confirmed").unwrap();
    assert_eq!(android.family, "android");
    assert_eq!(android.platform, "android");
    assert_eq!(android.fidelity, Some(Fidelity::Exact));
    assert_eq!(android.tls.min_version.as_deref(), Some("1.2"));
    assert_eq!(android.tls.max_version.as_deref(), Some("1.2"));
    assert!(!android.tls.grease);
    assert_eq!(
        android.http2.as_ref().unwrap().settings.as_deref(),
        Some("4:16777216")
    );

    // OkHttp 4 on Android 13 speaks TLS 1.3 and HTTP/2.
    let okhttp = fingerprint::find("android_okhttp13").unwrap();
    assert_eq!(okhttp.family, "okhttp");
    assert_eq!(okhttp.fidelity, Some(Fidelity::Exact));
    assert_eq!(ids(okhttp.tls.ciphers.as_deref().unwrap()).len(), 15);
    assert_eq!(okhttp.tls.max_version.as_deref(), Some("1.3"));
    assert_eq!(
        okhttp.http2.as_ref().unwrap().pseudo_order.as_deref(),
        Some("mpas")
    );
    assert_eq!(
        Profile::find("android").unwrap().target(),
        "android_okhttp13"
    );

    // Older OkHttp releases negotiate TLS 1.2 only. OkHttp 7 asks for the
    // NIST curves rather than X25519, and its two SHA-224 signature algorithms
    // cannot be sent by BoringSSL, so its fidelity is `close`.
    for name in ["android_okhttp7", "android_okhttp8", "android_okhttp9"] {
        let record = fingerprint::find(name).unwrap();
        assert_eq!(record.family, "okhttp", "{name}");
        assert_eq!(record.platform, "android", "{name}");
        assert_eq!(record.tls.min_version.as_deref(), Some("1.2"), "{name}");
        assert_eq!(record.tls.max_version.as_deref(), Some("1.2"), "{name}");
    }
    let okhttp7 = fingerprint::find("android_okhttp7").unwrap();
    assert_eq!(okhttp7.fidelity, Some(Fidelity::Close));
    assert_eq!(okhttp7.tls.curves.as_deref(), Some("P-256:P-384:P-521"));
    assert_eq!(
        okhttp7.tls.extension_order.as_deref(),
        Some("65281-0-23-35-13-16-11-10")
    );
    for name in ["android_okhttp8", "android_okhttp9"] {
        assert_eq!(
            fingerprint::find(name).unwrap().fidelity,
            Some(Fidelity::Exact),
            "{name}"
        );
    }
    for alias in ["android7", "android8", "android9"] {
        assert!(fingerprint::find(alias).unwrap().is_alias(), "{alias}");
    }
    assert_eq!(
        Profile::find("android7").unwrap().target(),
        "android_okhttp7"
    );
    assert_eq!(
        Profile::find("android8").unwrap().target(),
        "android_okhttp8"
    );
    assert_eq!(
        Profile::find("android9").unwrap().target(),
        "android_okhttp9"
    );

    // Mesh (Android app) splits into an HTTP/2 TLS 1.3 profile and an
    // HTTP/1.1 TLS 1.2 profile with the same TLS 1.2 cipher list.
    let mesh = fingerprint::find("android_mesh").unwrap();
    assert_eq!(mesh.family, "android");
    assert_eq!(mesh.fidelity, Some(Fidelity::Exact));
    assert!(!mesh.http1_only());
    assert_eq!(ids(mesh.tls.ciphers.as_deref().unwrap()).len(), 15);
    assert_eq!(mesh.tls.max_version.as_deref(), Some("1.3"));
    let mesh1 = fingerprint::find("android_mesh1").unwrap();
    assert_eq!(mesh1.family, "android");
    assert_eq!(mesh1.fidelity, Some(Fidelity::Exact));
    assert!(mesh1.http1_only());
    assert!(mesh1.http2.is_none());
    assert_eq!(mesh1.alpn(), Some(&["http/1.1".to_string()][..]));
    assert_eq!(mesh1.tls.max_version.as_deref(), Some("1.2"));

    // App-specific Android shapes share OkHttp's TLS 1.3 list but differ on
    // HTTP/2: Nike sends OkHttp's SETTINGS, Zalando adds a signed certificate
    // timestamp extension. Nike greases only its key share, which BoringSSL's
    // single GREASE switch cannot reproduce, so it is `close`.
    let nike = fingerprint::find("android_nike").unwrap();
    assert_eq!(nike.family, "android");
    assert_eq!(nike.fidelity, Some(Fidelity::Close));
    assert_eq!(
        nike.http2.as_ref().unwrap().settings.as_deref(),
        Some("1:4096;3:4294967295;4:16777216;5:16384;6:4294967295")
    );
    assert!(nike
        .deviations
        .iter()
        .any(|note| note.contains("greases only the key share")));
    let zalando = fingerprint::find("android_zalando").unwrap();
    assert_eq!(zalando.family, "android");
    assert_eq!(zalando.fidelity, Some(Fidelity::Exact));
    assert!(zalando.tls.signed_cert_timestamps);
    assert_eq!(
        zalando.http2.as_ref().unwrap().settings.as_deref(),
        Some("1:4096;3:4294967295;4:16777216;5:16384;6:4294967295")
    );

    // ConfirmedAndroid2 is a TLS 1.2 shape indistinguishable from the first
    // capture except for the padding extension, which is length-dependent.
    let confirmed2 = fingerprint::find("android_confirmed2").unwrap();
    assert_eq!(confirmed2.fidelity, Some(Fidelity::Exact));
    assert_eq!(
        confirmed2.tls.ciphers.as_deref(),
        fingerprint::find("android_confirmed")
            .unwrap()
            .tls
            .ciphers
            .as_deref()
    );
    assert_eq!(
        confirmed2.tls.extension_order.as_deref(),
        fingerprint::find("android_confirmed")
            .unwrap()
            .tls
            .extension_order
            .as_deref()
    );

    // iOS app profile: GREASE, zlib certificate compression, six SETTINGS.
    let ios = fingerprint::find("ios_confirmed").unwrap();
    assert_eq!(ios.family, "ios");
    assert_eq!(ios.platform, "ios");
    assert_eq!(ios.fidelity, Some(Fidelity::Exact));
    assert!(ios.tls.grease);
    assert_eq!(ios.tls.cert_compression.as_deref(), Some("zlib"));
    assert_eq!(
        ios.http2.as_ref().unwrap().settings.as_deref(),
        Some("1:4096;2:1;3:100;4:2097152;5:16384;6:4294967295")
    );

    // iOS 18.5 still offers TLS 1.0 and the 3DES suites.
    let old_ios = fingerprint::find("ios_safari18_5").unwrap();
    assert_eq!(old_ios.tls.min_version.as_deref(), Some("1.0"));
    assert!(ids(old_ios.tls.ciphers.as_deref().unwrap()).len() >= 20);
    assert_eq!(old_ios.fidelity, Some(Fidelity::Exact));

    let new_ios = fingerprint::find("ios_safari26").unwrap();
    assert_eq!(
        new_ios.tls.curves.as_deref(),
        Some("X25519MLKEM768:X25519:P-256:P-384:P-521")
    );
    assert_eq!(new_ios.fidelity, Some(Fidelity::Exact));
    assert_eq!(Profile::find("ios").unwrap().target(), "ios_safari26");

    // Opera keeps the older ALPS code point.
    let opera = fingerprint::find("opera91").unwrap();
    assert_eq!(opera.family, "opera");
    assert!(opera.tls.alps);
    assert!(!opera.tls.new_alps_codepoint);
    assert_eq!(opera.tls.cert_compression.as_deref(), Some("brotli"));
    assert_eq!(
        opera.http2.as_ref().unwrap().pseudo_order.as_deref(),
        Some("masp")
    );
    assert_eq!(Profile::find("opera").unwrap().target(), "opera91");
}

#[test]
fn tls_client_browser_and_ios_records_cover_more_versions() {
    // Chrome 103-152 and Firefox 102-148 from tls-client's own ClientHello
    // definitions. The wire shape changes between major versions, so each one
    // keeps its own record rather than aliasing an older capture.
    let chrome = fingerprint::find("tlsclient_chrome103").unwrap();
    assert_eq!(chrome.family, "chrome");
    assert_eq!(chrome.fidelity, Some(Fidelity::Exact));
    assert_eq!(chrome.tls.max_version.as_deref(), Some("1.3"));
    assert_eq!(
        fingerprint::by_family("chrome")
            .filter(|record| record.name.starts_with("tlsclient_"))
            .count(),
        19
    );
    assert_eq!(
        fingerprint::by_family("firefox")
            .filter(|record| record.name.starts_with("tlsclient_"))
            .count(),
        14
    );

    // Chrome 133 offers h3 in ALPN; BoringSSL can advertise all three.
    let chrome133 = fingerprint::find("tlsclient_chrome133").unwrap();
    assert_eq!(
        chrome133.alpn(),
        Some(&["h3".to_string(), "h2".to_string(), "http/1.1".to_string()][..])
    );
    assert!(chrome133.validate().is_ok());

    // Chrome 152 asks for ML-DSA signature algorithms BoringSSL cannot send.
    let chrome152 = fingerprint::find("tlsclient_chrome152").unwrap();
    assert_eq!(chrome152.fidelity, Some(Fidelity::Close));
    assert!(chrome152
        .deviations
        .iter()
        .any(|note| note.contains("mldsa44")));

    // Firefox 102-123 send six RFC 7540 PRIORITY frames before the headers;
    // the transport sends none, so those records are `close`.
    let firefox = fingerprint::find("tlsclient_firefox102").unwrap();
    assert_eq!(firefox.fidelity, Some(Fidelity::Close));
    assert!(firefox
        .deviations
        .iter()
        .any(|note| note.contains("PRIORITY frames")));
    assert_eq!(
        fingerprint::find("tlsclient_firefox148").unwrap().fidelity,
        Some(Fidelity::Exact)
    );

    // Safari 15.6.1 still offers TLS 1.0 and the 3DES suites.
    let safari = fingerprint::find("tlsclient_safari15_6_1").unwrap();
    assert_eq!(safari.tls.min_version.as_deref(), Some("1.0"));

    // Cloudflare's custom profile and the first two MMS profiles negotiate
    // HTTP/1.1 only; MMS 3 is the HTTP/2 variant.
    for name in [
        "tlsclient_cloudflare",
        "tlsclient_ios_mms",
        "tlsclient_ios_mms2",
    ] {
        let record = fingerprint::find(name).unwrap();
        assert!(record.http1_only(), "{name}");
        assert!(record.http2.is_none(), "{name}");
        assert!(Profile::find(name).unwrap().http1_only(), "{name}");
    }
    assert!(!fingerprint::find("tlsclient_ios_mms3")
        .unwrap()
        .http1_only());
}

#[test]
fn utls_records_cover_legacy_browsers_and_http1_chrome() {
    // uTLS only shapes the TLS handshake, so every record is HTTP/1.1 and
    // describes the ClientHello alone.
    let utls: Vec<_> = fingerprint::builtin()
        .iter()
        .filter(|record| record.name.starts_with("utls_"))
        .collect();
    assert_eq!(utls.len(), 34);
    for record in &utls {
        assert!(record.http1_only(), "{} is HTTP/1.1 only", record.name);
        assert!(record.http2.is_none(), "{} has no HTTP/2 pair", record.name);
        assert_eq!(
            record.alpn(),
            Some(&["http/1.1".to_string()][..]),
            "{} keeps the narrowed ALPN",
            record.name
        );
        assert_eq!(
            record
                .deviations
                .iter()
                .filter(|note| note.contains("capture ran over HTTP/1.1"))
                .count(),
            1,
            "{} explains the missing h2 ALPN",
            record.name
        );
    }

    // Chrome 58-72 still send BoringSSL's ChannelID extension, which the
    // transport has no way to enable, so those records are `close`.
    let chrome58 = fingerprint::find("utls_chrome58").unwrap();
    assert_eq!(chrome58.family, "chrome");
    assert_eq!(chrome58.fidelity, Some(Fidelity::Close));
    assert_eq!(chrome58.tls.max_version.as_deref(), Some("1.2"));
    assert_eq!(
        chrome58.tls.extension_order.as_deref(),
        Some("65281-0-23-35-13-5-18-16-11-10")
    );
    assert!(chrome58
        .deviations
        .iter()
        .any(|note| note.contains("30032")));

    // Chrome 106 with shuffled extensions keeps the captured set and asks the
    // transport to reorder it on every connection.
    let shuffle = fingerprint::find("utls_chrome106shuffle").unwrap();
    assert_eq!(shuffle.fidelity, Some(Fidelity::Exact));
    assert!(shuffle.tls.permute_extensions);

    // Chrome 115/120 PQ key shares use the X25519Kyber768 draft group, which
    // BoringSSL still accepts by name, so both records are byte-exact.
    for name in ["utls_chrome115pq", "utls_chrome120pq"] {
        let record = fingerprint::find(name).unwrap();
        assert_eq!(record.fidelity, Some(Fidelity::Exact), "{name}");
        assert_eq!(
            record.tls.curves.as_deref(),
            Some("X25519Kyber768Draft00:X25519:P-256:P-384"),
            "{name}"
        );
        assert_eq!(
            record.tls.key_shares.as_deref(),
            Some("X25519Kyber768Draft00:X25519"),
            "{name}"
        );
    }

    // Firefox 55 is TLS 1.2 only; Firefox 120 adds TLS 1.3, delegated
    // credentials and ECH.
    let firefox55 = fingerprint::find("utls_firefox55").unwrap();
    assert_eq!(firefox55.fidelity, Some(Fidelity::Exact));
    assert_eq!(firefox55.tls.max_version.as_deref(), Some("1.2"));
    let firefox120 = fingerprint::find("utls_firefox120").unwrap();
    assert_eq!(firefox120.tls.max_version.as_deref(), Some("1.3"));
    assert_eq!(
        firefox120.tls.delegated_credentials.as_deref(),
        Some("ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1")
    );

    // Safari 16, iOS 11 and OkHttp on Android 11 are TLS 1.2/1.3 captures;
    // iOS 11 sends no supported_versions, so its version bounds come from the
    // record version.
    let safari = fingerprint::find("utls_safari16").unwrap();
    assert_eq!(safari.family, "safari");
    assert_eq!(safari.tls.min_version.as_deref(), Some("1.0"));
    let ios11 = fingerprint::find("utls_ios11").unwrap();
    assert_eq!(ios11.platform, "ios");
    assert_eq!(ios11.tls.max_version.as_deref(), Some("1.2"));
    let okhttp = fingerprint::find("utls_android11okhttp").unwrap();
    assert_eq!(okhttp.family, "okhttp");
    assert_eq!(
        okhttp.tls.extension_order.as_deref(),
        Some("0-23-65281-10-11-5-13-16")
    );

    // Edge, 360 and QQ are new families. 360 7.5 sends RC4 suites, DSA
    // signature algorithms, NPN and the old ChannelID, and omits
    // extended_master_secret that BoringSSL always adds.
    assert_eq!(fingerprint::find("utls_edge85").unwrap().family, "edge");
    let qq = fingerprint::find("utls_qq11_1").unwrap();
    assert_eq!(qq.family, "qq");
    assert!(qq.tls.alps);
    let browser360 = fingerprint::find("utls_360_7_5").unwrap();
    assert_eq!(browser360.family, "360");
    assert_eq!(browser360.fidelity, Some(Fidelity::Partial));
    assert!(browser360
        .deviations
        .iter()
        .any(|note| note.contains("extended_master_secret")));
    assert!(browser360
        .deviations
        .iter()
        .any(|note| note.contains("30031")));
}

#[test]
fn docker_sourced_runtime_versions_are_embedded() {
    // Go's TLS stack changes the ClientHello every release: 1.21-1.26 have
    // distinct JA4s, and 1.23+ adds signature_algorithms_cert.
    let go21 = fingerprint::find("go1.21").unwrap();
    assert_eq!(go21.family, "go");
    assert_eq!(go21.fidelity, Some(Fidelity::Close));
    assert_eq!(go21.tls.max_version.as_deref(), Some("1.3"));
    assert!(go21
        .deviations
        .iter()
        .any(|note| note.contains("TLS 1.3 cipher suites")));
    assert_eq!(
        fingerprint::find("go1.23").unwrap().tls.curves.as_deref(),
        Some("X25519Kyber768Draft00:X25519:P-256:P-384:P-521")
    );

    // Node 24 links OpenSSL 3.5: X25519MLKEM768 first, ML-DSA and brainpool
    // signature algorithms, and a much longer cipher list than Node 18/20.
    let node = fingerprint::find("node24_https").unwrap();
    assert_eq!(node.family, "node");
    assert_eq!(
        node.tls.curves.as_deref(),
        Some("X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072")
    );
    assert!(node.http1_only());
    assert_eq!(node.fidelity, Some(Fidelity::Partial));
    let node_h2 = fingerprint::find("node24_http2").unwrap();
    assert!(!node_h2.http1_only());

    // curl carries whatever OpenSSL the image links: 7.88.1 is OpenSSL 1.1.1
    // (no ffdhe4096+), 8.10.1 is OpenSSL 3.x with the full FFDHE list.
    for name in ["curl7.88.1_h2", "curl8.10.1_h2"] {
        let record = fingerprint::find(name).unwrap();
        assert_eq!(record.family, "curl", "{name}");
        assert!(!record.http1_only(), "{name}");
    }
    assert_eq!(
        fingerprint::find("curl8.10.1_h2")
            .unwrap()
            .tls
            .curves
            .as_deref()
            .unwrap()
            .contains("ffdhe2048"),
        true
    );

    // Java 8 URLConnection (TLS 1.2 with DHE-DSS ciphers) and Java 11/17
    // HttpClient differ; Java 17 and 21 share a fingerprint.
    let java8 = fingerprint::find("java8_urlconn").unwrap();
    assert_eq!(java8.platform, "linux");
    assert!(java8
        .deviations
        .iter()
        .any(|note| note.contains("signature_algorithms_cert")));

    // OpenSSL s_client and PHP streams vary with the bundled OpenSSL; GnuTLS
    // wget from Debian has a much smaller cipher list than the local one.
    assert_eq!(
        fingerprint::find("openssl1.1_sclient")
            .unwrap()
            .tls
            .max_version
            .as_deref(),
        Some("1.3")
    );
    let php = fingerprint::find("php8.1_streams").unwrap();
    assert_eq!(php.family, "php");
    assert!(php.http1_only());
    assert_eq!(
        fingerprint::find("wget1.21_bookworm").unwrap().family,
        "wget"
    );
}

#[test]
fn other_runtime_stacks_are_embedded() {
    // Go 1.20 predates the go1.21 extension set: no signature_algorithms_cert,
    // and the TLS 1.3 suites still come last.
    let go20 = fingerprint::find("go1.20").unwrap();
    assert_eq!(go20.family, "go");
    assert_eq!(go20.fidelity, Some(Fidelity::Close));
    assert_eq!(
        go20.tls.extension_order.as_deref(),
        Some("0-5-10-11-13-65281-16-18-43-51")
    );
    assert!(!go20.http1_only());

    // Python 3.8 links OpenSSL 1.1.1, so it offers X448, ffdhe4096+ and the
    // padding extension that 3.9 and later do not.
    let python38 = fingerprint::find("python3.8_urllib").unwrap();
    assert_eq!(python38.family, "python");
    assert!(python38.http1_only());
    assert_eq!(python38.fidelity, Some(Fidelity::Partial));
    assert!(python38.deviations.iter().any(|note| note.contains("X448")));

    // Ruby, Dart and Erlang are HTTP/1.1-only stacks. Dart's dart:io HTTPS is
    // BoringSSL-based, so its ClientHello is reproduced exactly.
    let ruby = fingerprint::find("ruby3.3_nethttp").unwrap();
    assert_eq!(ruby.family, "ruby");
    assert!(ruby.http1_only());
    assert!(ruby
        .tls
        .curves
        .as_deref()
        .unwrap()
        .starts_with("X25519MLKEM768"));
    let dart = fingerprint::find("dart_httpclient").unwrap();
    assert_eq!(dart.family, "dart");
    assert!(dart.http1_only());
    assert_eq!(dart.fidelity, Some(Fidelity::Exact));
    assert_eq!(
        dart.tls.extension_order.as_deref(),
        Some("0-23-65281-10-11-35-13-51-45-43")
    );
    let erlang = fingerprint::find("erlang_ssl").unwrap();
    assert_eq!(erlang.family, "erlang");
    assert!(erlang.http1_only());
    assert_eq!(
        erlang.tls.curves.as_deref(),
        Some("X25519:P-521:P-384:P-256")
    );

    // Deno's fetch goes through rustls and keeps HTTP/2.
    let deno = fingerprint::find("deno_fetch").unwrap();
    assert_eq!(deno.family, "deno");
    assert!(!deno.http1_only());
    assert_eq!(
        deno.tls.curves.as_deref(),
        Some("X25519:P-256:P-384:X25519MLKEM768")
    );

    // .NET's SocketsHttpHandler negotiates HTTP/2 when asked to and falls back
    // to HTTP/1.1 by default; both records share one ClientHello.
    let dotnet1 = fingerprint::find("dotnet8_http1").unwrap();
    let dotnet2 = fingerprint::find("dotnet8_http2").unwrap();
    assert_eq!(dotnet1.family, "dotnet");
    assert!(dotnet1.http1_only());
    assert!(!dotnet2.http1_only());
    assert_eq!(dotnet1.tls.ciphers, dotnet2.tls.ciphers);

    // Each new stack has a short alias that resolves to its capture.
    for (alias, base) in [
        ("ruby", "ruby3.3_nethttp"),
        ("deno", "deno_fetch"),
        ("dart", "dart_httpclient"),
        ("erlang", "erlang_ssl"),
        ("dotnet", "dotnet8_http2"),
    ] {
        let record = fingerprint::find(alias).unwrap();
        assert!(record.is_alias(), "{alias}");
        assert_eq!(record.extends.as_deref(), Some(base), "{alias}");
        assert_eq!(Profile::find(alias).unwrap().target(), base);
    }
}

#[test]
fn http1_only_clients_keep_http11_and_their_alpn() {
    for name in [
        "python3.12_requests",
        "python3.12_urllib",
        "python3.12_aiohttp",
        "python3.12_httpclient",
        "curl8.5_http1",
        "java21_urlconn",
        "node22_https",
        "node22_fetch",
        "go1.26_http1",
        "bun1.3.14",
        "php8.3_streams",
        "wget1.21.4",
        "perl5_lwp",
        "openssl3_sclient",
        "android_mesh1",
        "tlsclient_cloudflare",
        "tlsclient_ios_mms",
        "tlsclient_ios_mms2",
        "utls_chrome58",
        "utls_chrome133",
        "utls_qq11_1",
    ] {
        let record = fingerprint::find(name).unwrap();
        assert!(record.http1_only(), "{name} is HTTP/1.1 only");
        assert!(Profile::find(name).unwrap().http1_only(), "{name}");
        assert!(record.http2.is_none(), "{name} has no HTTP/2 settings");
        let prepared = Client::new(Profile::find(name).unwrap()).unwrap();
        assert!(
            prepared.prepared().http1_only(),
            "{name} keeps HTTP/1.1 in the client"
        );
    }
    for name in [
        "go1.26",
        "curl8.5_h2",
        "java21_httpclient",
        "node22_http2",
        "python3.12_httpx",
        "php8.3_curl",
        "rust_reqwest_rustls",
        "chromium156",
        "firefox158",
        "android_confirmed",
        "android_confirmed2",
        "android_mesh",
        "android_okhttp7",
        "android_okhttp8",
        "android_okhttp9",
        "android_okhttp10",
        "android_okhttp11",
        "android_okhttp12",
        "android_okhttp13",
        "android_nike",
        "android_zalando",
        "tlsclient_chrome103",
        "tlsclient_chrome133",
        "tlsclient_firefox102",
        "tlsclient_ios_safari18",
        "tlsclient_safari15_6_1",
        "tlsclient_brave146",
        "ios_confirmed",
        "ios_safari18_5",
        "ios_safari26",
        "opera91",
    ] {
        assert!(
            !Profile::find(name).unwrap().http1_only(),
            "{name} may negotiate HTTP/2"
        );
    }
    // The alias inherits the base profile's HTTP/1.1-only mode.
    assert!(Profile::find("python").unwrap().http1_only());
    assert!(!Profile::find("java").unwrap().http1_only());
}

#[test]
fn clients_without_alpn_send_no_alpn() {
    // The JDK's HttpsURLConnection and Node's https module were captured with
    // no ALPN extension. An empty list keeps it absent instead of letting the
    // HTTP/1.1 preference add one.
    for name in [
        "java21_urlconn",
        "node22_https",
        "go1.26_http1",
        "php8.3_streams",
        "wget1.21.4",
        "perl5_lwp",
    ] {
        let record = fingerprint::find(name).unwrap();
        assert_eq!(record.alpn(), Some(&[][..]), "{name} captured no ALPN");
        let tls = Profile::find(name)
            .unwrap()
            .emulation()
            .tls_options
            .unwrap();
        assert_eq!(
            tls.alpn_protocols.as_deref(),
            Some(&[][..]),
            "{name} keeps ALPN empty"
        );
    }
    assert_eq!(
        fingerprint::find("python3.12_requests").unwrap().alpn(),
        Some(&["http/1.1".to_string()][..])
    );
}

#[test]
fn aliases_resolve_to_their_base() {
    for (alias, base) in [
        ("golang", "go1.26"),
        ("python", "python3.12_requests"),
        ("curl", "curl8.5_h2"),
        ("java", "java21_httpclient"),
        ("node", "node22_http2"),
        ("chrome_android", "chrome131_android"),
        ("safari_ios", "safari270_ios"),
        ("okhttp_android", "okhttp4_android"),
        ("bun", "bun1.3.14"),
        ("php", "php8.3_curl"),
        ("wget", "wget1.21.4"),
        ("perl", "perl5_lwp"),
        ("rust", "rust_reqwest_rustls"),
        ("httpx", "python3.12_httpx"),
        ("chrome", "chromium156"),
        ("firefox", "firefox158"),
        ("openssl", "openssl3_sclient"),
        ("android10", "android_okhttp10"),
        ("android11", "android_okhttp11"),
        ("android12", "android_okhttp12"),
        ("nike", "android_nike"),
        ("zalando", "android_zalando"),
    ] {
        let profile = Profile::find(alias).unwrap();
        assert_eq!(profile.target(), base, "{alias}");
        assert_eq!(profile.name(), alias, "{alias}");
        assert!(fingerprint::find(alias).unwrap().is_alias());
        assert_eq!(
            profile.emulation().tls_options.unwrap().cipher_list,
            Profile::find(base)
                .unwrap()
                .emulation()
                .tls_options
                .unwrap()
                .cipher_list,
            "{alias} sends the base cipher list"
        );
    }
    assert_eq!(Profile::find("golang").unwrap().family(), "go");
    assert_eq!(
        Profile::find("golang").unwrap().fidelity(),
        Some(Fidelity::Close),
        "an alias reports the base capture's fidelity"
    );
    // Aliasing a preset outside the library has no capture to rate.
    assert_eq!(Profile::find("chrome_android").unwrap().fidelity(), None);
    assert_eq!(Profile::find("chrome_android").unwrap().family(), "chrome");
    assert_eq!(
        Profile::find("chrome_android").unwrap().platform(),
        "android"
    );
    assert_eq!(Profile::find("safari_ios").unwrap().platform(), "ios");
    assert_eq!(
        Profile::find("okhttp_android").unwrap().platform(),
        "android"
    );
}

#[test]
fn prepared_reports_family_fidelity_and_deviation() {
    let go = Client::new(Profile::find("go1.26").unwrap()).unwrap();
    assert_eq!(go.prepared().family(), "go");
    assert_eq!(go.prepared().platform(), "linux");
    assert_eq!(go.prepared().fidelity(), Some(Fidelity::Close));
    assert!(go.prepared().deviation().unwrap().contains("TLS 1.3"));

    let python = Client::new(Profile::find("python3.12_requests").unwrap()).unwrap();
    assert_eq!(python.prepared().family(), "python");
    assert_eq!(python.prepared().fidelity(), Some(Fidelity::Partial));
    assert!(python.prepared().deviation().unwrap().contains("cipher"));

    // An alias reports the base record's gaps.
    let alias = Client::new(Profile::find("golang").unwrap()).unwrap();
    assert_eq!(alias.prepared().family(), "go");
    assert!(alias.prepared().deviation().unwrap().contains("BoringSSL"));

    // Browser presets are not part of the embedded library.
    let chrome = Client::new(Profile::find("chrome150").unwrap()).unwrap();
    assert_eq!(chrome.prepared().family(), "chrome");
    assert_eq!(chrome.prepared().fidelity(), None);
}

#[test]
fn external_json_installs_and_resolves() {
    let document = r#"
    {
      "fingerprints": [
        {
          "name": "test_client_min",
          "family": "test",
          "client": "Minimal test client",
          "version": "1.0",
          "platform": "linux",
          "fidelity": "exact",
          "tls": {
            "ciphers": "TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "curves": "X25519:P-256",
            "extension_order": "0-10-16-43-51",
            "alpn": ["h2", "http/1.1"]
          },
          "http2": {
            "settings": "2:0;4:4194304",
            "pseudo_order": "a,m,p,s",
            "window_update": 1048576
          },
          "headers": [["user-agent", "minimal/1.0"], ["accept", "*/*"]]
        }
      ]
    }
    "#;
    let profiles = fingerprint::load_json(document).unwrap();
    assert_eq!(profiles.len(), 1);

    let profile = Profile::find("test_client_min").expect("installed record resolves");
    assert_eq!(profile.name(), "test_client_min");
    assert_eq!(profile.target(), "test_client_min");
    assert_eq!(profile.family(), "test");
    assert_eq!(profile.fidelity(), Some(Fidelity::Exact));

    let emulation = profile.emulation();
    let tls = emulation.tls_options.unwrap();
    assert_eq!(
        tls.alpn_protocols.as_deref(),
        Some(&[AlpnProtocol::HTTP2, AlpnProtocol::HTTP1][..])
    );
    let http2 = emulation.http2_options.unwrap();
    assert_eq!(http2.initial_conn_window_size, 1_048_576 + 65_535);
    assert_eq!(http2.initial_window_size, 4_194_304);

    let client = Client::new(profile).unwrap();
    assert!(!client.prepared().http1_only());
    assert_eq!(
        client
            .prepared()
            .emulation()
            .headers
            .get("user-agent")
            .unwrap()
            .to_str()
            .unwrap(),
        "minimal/1.0"
    );

    // The name is now taken.
    assert!(fingerprint::load_json(document).is_err());
}

#[test]
fn a_document_can_carry_http3_multipart_and_cookie_behavior() {
    // One record describes a whole browser profile: TLS, HTTP/2, HTTP/3, the
    // multipart boundary and cookie splitting. No built-in preset is needed.
    let document = r#"
    {
      "name": "test_full_browser",
      "family": "chrome",
      "client": "Full browser record",
      "version": "999",
      "platform": "macos",
      "fidelity": "close",
      "tls": {
        "ciphers": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "curves": "X25519:P-256",
        "extension_order": "0-10-16-43-51",
        "alpn": ["h2", "http/1.1"],
        "grease": true
      },
      "http2": {
        "settings": "2:0;4:4194304",
        "pseudo_order": "m,a,s,p",
        "window_update": 1048576
      },
      "headers": [["user-agent", "test/999"]],
      "form_boundary": "firefox",
      "split_cookies": true,
      "http3": {
        "settings": "1:1;6:1;7:1;GREASE",
        "initial_packet_number": 1,
        "transport_parameters": "0x01:1200;0x0f:AUTO",
        "pseudo_order": "m,a,s,p",
        "curves": "X25519",
        "grease": true
      }
    }
    "#;
    let profiles = fingerprint::load_json(document).unwrap();
    assert_eq!(profiles.len(), 1);

    let profile = Profile::find("test_full_browser").expect("the installed record");
    assert_eq!(profile.form_boundary(), Some(FormBoundary::Firefox));
    assert!(profile.split_cookies());

    let client = Client::new(profile).unwrap();
    let prepared = client.prepared();
    let http3 = prepared.http3().expect("the record carries HTTP/3");
    assert_eq!(http3.initial_packet_number, Some(1));
    assert_eq!(
        http3.ciphers,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    );
    assert!(http3
        .settings
        .iter()
        .any(|setting| matches!(setting, rust_curl_impersonate::profile::H3Setting::Grease)));
    assert_eq!(prepared.http3_pseudo_order(), Some("m,a,s,p"));
    assert_eq!(http3.transport_parameters, "0x01:1200;0x0f:AUTO");
    assert_eq!(prepared.form_boundary(), Some(FormBoundary::Firefox));
    assert!(prepared.splits_cookies());
    assert_eq!(prepared.initial_packet_number(), Some(1));

    // A preset with no record keeps its behavior table entry.
    let preset = Client::new(Profile::find("chrome150").unwrap()).unwrap();
    assert_eq!(
        preset.prepared().form_boundary(),
        Some(FormBoundary::WebKit)
    );
    assert!(preset.prepared().splits_cookies());
    assert_eq!(
        Client::new(Profile::find("okhttp4_android").unwrap())
            .unwrap()
            .prepared()
            .form_boundary(),
        None
    );
}

#[test]
fn invalid_documents_are_rejected_before_installing_anything() {
    assert!(fingerprint::parse_json("not json").is_err());
    assert!(fingerprint::load_json("[]").is_err());
    assert!(fingerprint::load_json(
        r#"[{"name":"test_dup","tls":{"ciphers":"TLS_AES_128_GCM_SHA256"}},
            {"name":"test_dup","tls":{"ciphers":"TLS_AES_128_GCM_SHA256"}}]"#
    )
    .is_err());

    // A record cannot reuse an embedded or curl-impersonate name.
    assert!(fingerprint::parse_json(
        r#"{"name":"go1.26","tls":{"ciphers":"TLS_AES_128_GCM_SHA256"}}"#
    )
    .unwrap()[0]
        .clone()
        .install()
        .is_err());
    assert!(fingerprint::parse_json(
        r#"{"name":"chrome150","tls":{"ciphers":"TLS_AES_128_GCM_SHA256"}}"#
    )
    .unwrap()[0]
        .clone()
        .install()
        .is_err());

    // Empty names and unknown bases fail validation.
    let empty = fingerprint::parse_json(r#"{"name":""}"#).unwrap().remove(0);
    assert!(empty.validate().is_err());
    let orphan = fingerprint::parse_json(r#"{"name":"test_orphan","extends":"does-not-exist"}"#)
        .unwrap()
        .remove(0);
    assert!(orphan.validate().is_err());
    assert!(orphan.emulation().is_err());
}

#[test]
fn json_round_trip_preserves_the_library() {
    let json = fingerprint::to_json(fingerprint::builtin()).unwrap();
    let parsed = fingerprint::parse_json(&json).unwrap();
    assert_eq!(parsed.len(), fingerprint::builtin().len());
    for (before, after) in fingerprint::builtin().iter().zip(&parsed) {
        assert_eq!(before.name, after.name);
        assert_eq!(before.family, after.family);
        assert_eq!(before.extends, after.extends);
        assert_eq!(before.fidelity, after.fidelity);
        assert_eq!(before.deviations, after.deviations);
        assert_eq!(before.http1_only, after.http1_only);
        assert_eq!(before.tls.ciphers, after.tls.ciphers);
        assert_eq!(before.tls.curves, after.tls.curves);
        assert_eq!(before.tls.sigalgs, after.tls.sigalgs);
        assert_eq!(before.tls.extension_order, after.tls.extension_order);
        assert_eq!(before.tls.key_shares, after.tls.key_shares);
        assert_eq!(before.tls.alpn, after.tls.alpn);
        assert_eq!(before.headers, after.headers);
        assert_eq!(
            before.http2.as_ref().map(|h| &h.settings),
            after.http2.as_ref().map(|h| &h.settings)
        );
        assert_eq!(
            before.http2.as_ref().and_then(|h| h.window_update),
            after.http2.as_ref().and_then(|h| h.window_update)
        );
        assert_eq!(before.deviation_text, after.deviation_text);
    }
}

#[test]
fn preset_family_and_platform_are_inferred() {
    assert_eq!(fingerprint::preset_family("chrome150"), "chrome");
    assert_eq!(fingerprint::preset_family("edge101"), "chrome");
    assert_eq!(fingerprint::preset_family("firefox133"), "firefox");
    assert_eq!(fingerprint::preset_family("safari270"), "safari");
    assert_eq!(fingerprint::preset_family("okhttp4_android"), "okhttp");
    assert_eq!(fingerprint::preset_family("tor145"), "tor");
    assert_eq!(fingerprint::preset_platform("chrome131_android"), "android");
    assert_eq!(fingerprint::preset_platform("safari270_ios"), "ios");
    assert_eq!(fingerprint::preset_platform("chrome151_macos"), "macos");
    assert_eq!(fingerprint::preset_platform("chrome150"), "");

    // Built-in targets keep resolving, and their fingerprint accessors are
    // empty instead of inventing data.
    let chrome = Profile::find("chrome150").unwrap();
    assert!(chrome.fingerprint().is_none());
    assert_eq!(chrome.fidelity(), None);
    assert_eq!(chrome.deviation_note(), None);
    assert!(!chrome.http1_only());
}
