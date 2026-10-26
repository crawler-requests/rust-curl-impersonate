//! Browser impersonation profiles.
//!
//! A profile names a browser target and resolves to a [`wreq::Emulation`], which
//! carries the TLS, HTTP/2 and header settings actually used on the wire.
//!
//! Targets that [`wreq_util::Profile`] already ships delegate to it. Targets it
//! does not ship are built here from curl-impersonate's preset data; `chrome150`
//! is the first of those.

use wreq::header::{HeaderMap, HeaderValue};
use wreq::http2::{
    Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
};
use wreq::tls::{AlpsProtocol, TlsOptions, TlsVersion};
use wreq::{Emulation, IntoEmulation, header};

/// A browser target this crate can impersonate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Chrome 149, the newest Chrome target shipped by wreq-util 3.0.0-rc.14.
    Chrome149,
    /// Chrome 150. wreq-util stops at 149; the TLS and HTTP/2 settings come from
    /// curl-impersonate's `chrome150` entry in `lib/impersonate.c`.
    Chrome150,
}

impl Profile {
    pub fn target(self) -> &'static str {
        match self {
            Profile::Chrome149 => "chrome149",
            Profile::Chrome150 => "chrome150",
        }
    }

    pub fn find(target: &str) -> Option<Profile> {
        match target {
            "chrome149" => Some(Profile::Chrome149),
            "chrome150" => Some(Profile::Chrome150),
            _ => None,
        }
    }

    /// The emulation settings sent on the wire for this profile.
    pub fn emulation(self) -> Emulation {
        match self {
            Profile::Chrome149 => wreq_util::Profile::Chrome149.into_emulation(),
            Profile::Chrome150 => chrome150(),
        }
    }
}

/// Chrome's cipher list as curl-impersonate records it for `chrome150`.
const CHROME_CIPHERS: &str = "TLS_AES_128_GCM_SHA256:\
TLS_AES_256_GCM_SHA384:\
TLS_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:\
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:\
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:\
TLS_RSA_WITH_AES_128_GCM_SHA256:\
TLS_RSA_WITH_AES_256_GCM_SHA384:\
TLS_RSA_WITH_AES_128_CBC_SHA:\
TLS_RSA_WITH_AES_256_CBC_SHA";

/// `sig_hash_algs` from curl-impersonate's `chrome150` preset, minus the three
/// leading ML-DSA entries. That preset reads `mldsa44:mldsa65:mldsa87:...`, but
/// the BoringSSL build linked by wreq rejects those names with
/// `INVALID_SIGNATURE_ALGORITHM` and aborts the handshake. They are recorded in
/// [`CHROME150_UNSUPPORTED_SIGALGS`] until the TLS backend learns them.
const CHROME150_SIGALGS: &str = "ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512";

/// Signature algorithms curl-impersonate advertises for `chrome150` that the
/// current TLS backend cannot express.
pub const CHROME150_UNSUPPORTED_SIGALGS: &[&str] = &["mldsa44", "mldsa65", "mldsa87"];

fn chrome150() -> Emulation {
    let tls = TlsOptions::builder()
        .grease_enabled(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .sigalgs_list(CHROME150_SIGALGS)
        .cipher_list(CHROME_CIPHERS)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .permute_extensions(true)
        .pre_shared_key(true)
        .enable_ech_grease(true)
        .alps_protocols([AlpsProtocol::HTTP2])
        .alps_use_new_codepoint(true)
        .aes_hw_override(true)
        .build();

    // curl-impersonate: http2_settings = "1:65536;2:0;4:6291456;6:262144",
    // http2_window_update = 15663105, stream weight 256 exclusive on stream 0.
    let http2 = Http2Options::builder()
        .header_table_size(65536)
        .enable_push(false)
        .initial_window_size(6291456)
        .max_header_list_size(262144)
        .initial_connection_window_size(15663105)
        .headers_stream_dependency(StreamDependency::new(StreamId::zero(), 255, true))
        .headers_pseudo_order(
            PseudoOrder::builder()
                .extend([
                    PseudoId::Method,
                    PseudoId::Authority,
                    PseudoId::Scheme,
                    PseudoId::Path,
                ])
                .build(),
        )
        .settings_order(
            SettingsOrder::builder()
                .extend([
                    SettingId::HeaderTableSize,
                    SettingId::EnablePush,
                    SettingId::InitialWindowSize,
                    SettingId::MaxHeaderListSize,
                ])
                .build(),
        )
        .build();

    // `http_headers` from curl-impersonate's chrome150 preset, macOS platform.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::HeaderName::from_static("sec-ch-ua"),
        HeaderValue::from_static(
            "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("sec-ch-ua-mobile"),
        HeaderValue::from_static("?0"),
    );
    headers.insert(
        header::HeaderName::from_static("sec-ch-ua-platform"),
        HeaderValue::from_static("\"macOS\""),
    );
    headers.insert(
        header::UPGRADE_INSECURE_REQUESTS,
        HeaderValue::from_static("1"),
    );
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        ),
    );
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        ),
    );
    headers.insert(
        header::HeaderName::from_static("sec-fetch-site"),
        HeaderValue::from_static("none"),
    );
    headers.insert(
        header::HeaderName::from_static("sec-fetch-mode"),
        HeaderValue::from_static("navigate"),
    );
    headers.insert(
        header::HeaderName::from_static("sec-fetch-user"),
        HeaderValue::from_static("?1"),
    );
    headers.insert(
        header::HeaderName::from_static("sec-fetch-dest"),
        HeaderValue::from_static("document"),
    );
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br, zstd"),
    );
    headers.insert(
        header::ACCEPT_LANGUAGE,
        HeaderValue::from_static("en-US,en;q=0.9"),
    );
    headers.insert(
        header::HeaderName::from_static("priority"),
        HeaderValue::from_static("u=0, i"),
    );

    Emulation::builder()
        .tls_options(tls)
        .http2_options(http2)
        .headers(headers)
        .build(wreq::Group::new("chrome_150"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_resolve_to_emulation_settings() {
        assert_eq!(Profile::find("chrome150"), Some(Profile::Chrome150));
        assert!(Profile::find("nope").is_none());

        let chrome150 = Profile::Chrome150.emulation();
        let tls = chrome150.tls_options.expect("chrome150 sets tls options");
        assert_eq!(
            tls.curves_list.as_deref(),
            Some("X25519MLKEM768:X25519:P-256:P-384")
        );
        assert_eq!(tls.sigalgs_list.as_deref(), Some(CHROME150_SIGALGS));
        assert_eq!(tls.permute_extensions, Some(true));
        assert!(tls.enable_ech_grease);
        assert!(tls.alps_use_new_codepoint);

        let http2 = chrome150.http2_options.expect("chrome150 sets http2 options");
        assert_eq!(http2.initial_conn_window_size, 15663105);
        assert_eq!(http2.header_table_size, Some(65536));
        assert_eq!(http2.initial_window_size, 6291456);
        assert_eq!(http2.max_header_list_size, Some(262144));

        // Chrome 149 stays delegated to wreq-util rather than re-declared here.
        assert!(Profile::Chrome149.emulation().tls_options.is_some());
    }
}
