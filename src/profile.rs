//! Browser impersonation profiles.
//!
//! A profile is data, not behaviour: it records every knob curl-impersonate
//! stores in `struct impersonate_opts` (`lib/impersonate.h`). Applying a profile
//! to a real TLS handshake is a separate layer and is not implemented yet.
//!
//! Field values are transcribed from lexiforest/curl-impersonate
//! `patches/curl.patch` against curl 8.23.0. `None` means the upstream preset
//! leaves the field unset, so the TLS stack's own default applies.

/// `struct impersonate_opts`, one entry per supported browser target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Canonical target name, e.g. `chrome150`.
    pub target: &'static str,
    pub alias: &'static str,
    /// curl `CURL_HTTP_VERSION_*`. `2` is HTTP/2.
    pub http_version: u8,
    pub ciphers: &'static [&'static str],
    /// TLS extension 10, `CURLOPT_SSL_EC_CURVES`.
    pub curves: Option<&'static [&'static str]>,
    /// TLS extension 13. `None` keeps the TLS stack default.
    pub sig_hash_algs: Option<&'static [&'static str]>,
    /// QUIC uses a different verify list: BoringSSL's default keeps `rsa_pkcs1_sha1`,
    /// which Chrome strips for TCP.
    pub http3_sig_hash_algs: Option<&'static [&'static str]>,
    pub alpn: bool,
    pub alps: bool,
    /// `true` once the preset randomises ClientHello extension order per connection.
    pub tls_permute_extensions: bool,
    pub tls_session_ticket: bool,
    /// TLS extension 27, e.g. `brotli`.
    pub cert_compression: Option<&'static str>,
    /// Header lines sent verbatim, in order, when default headers are enabled.
    pub headers: &'static [&'static str],
    /// `id:value` pairs separated by `;`, e.g. `1:65536;2:0;4:6291456;6:262144`.
    pub http2_settings: Option<&'static str>,
    pub http2_window_update: Option<u32>,
    pub http2_stream_weight: Option<u16>,
    pub http2_stream_exclusive: bool,
    pub http3_settings: Option<&'static str>,
    /// Pseudo header order: `m` method, `a` authority, `s` scheme, `p` path.
    pub http3_pseudo_headers_order: Option<&'static str>,
    pub quic_cid_length: Option<&'static str>,
    /// `1` matches Chrome's QUIC initial packet number.
    pub quic_initial_packet_number: Option<i64>,
    pub quic_transport_parameters: Option<&'static str>,
    /// Extension type numbers in the order they appear in the HTTP/3 ClientHello.
    pub http3_tls_extension_order: Option<&'static str>,
    /// Encrypted ClientHello. The string `true` enables GREASE ECH.
    pub ech: Option<&'static str>,
    pub tls_use_new_alps_codepoint: bool,
    pub tls_signed_cert_timestamps: bool,
    pub tls_grease: bool,
    /// One `Cookie` header per pair instead of joining them.
    pub split_cookies: bool,
    /// `multipart/form-data` boundary style, `webkit` or `firefox`.
    pub form_boundary: Option<&'static str>,
}

impl Profile {
    pub fn find(target: &str) -> Option<&'static Profile> {
        PROFILES.iter().find(|profile| profile.target == target)
    }
}

const CHROME_MODERN_CIPHERS: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA",
    "AES256-SHA",
];

/// Chrome 150, transcribed from `impersonations[]` in `lib/impersonate.c`.
pub const CHROME_150: Profile = Profile {
    target: "chrome150",
    alias: "chrome150",
    http_version: 2,
    ciphers: CHROME_MODERN_CIPHERS,
    curves: Some(&["X25519MLKEM768", "X25519", "P-256", "P-384"]),
    sig_hash_algs: Some(&[
        "mldsa44",
        "mldsa65",
        "mldsa87",
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
    ]),
    http3_sig_hash_algs: Some(&[
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pss_rsae_sha384",
        "rsa_pkcs1_sha384",
        "rsa_pss_rsae_sha512",
        "rsa_pkcs1_sha512",
        "rsa_pkcs1_sha1",
    ]),
    alpn: true,
    alps: true,
    tls_permute_extensions: true,
    tls_session_ticket: true,
    cert_compression: Some("brotli"),
    headers: &[
        "sec-ch-ua: \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", \"Google Chrome\";v=\"150\"",
        "sec-ch-ua-mobile: ?0",
        "sec-ch-ua-platform: \"macOS\"",
        "Upgrade-Insecure-Requests: 1",
        "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-User: ?1",
        "Sec-Fetch-Dest: document",
        "Accept-Encoding: gzip, deflate, br, zstd",
        "Accept-Language: en-US,en;q=0.9",
        "Priority: u=0, i",
    ],
    http2_settings: Some("1:65536;2:0;4:6291456;6:262144"),
    http2_window_update: Some(15_663_105),
    http2_stream_weight: Some(256),
    http2_stream_exclusive: true,
    http3_settings: Some("1:65536;6:262144;7:100;51:1;GREASE"),
    http3_pseudo_headers_order: Some("masp"),
    quic_cid_length: Some("webkit"),
    quic_initial_packet_number: Some(1),
    quic_transport_parameters: Some(
        "1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;8:100;9:103;15:;17:1@1,GREASE;32:65536;12584:0x4f524947;GREASE",
    ),
    http3_tls_extension_order: Some("0-10-13-16-27-43-45-51-57-17613-65037"),
    ech: Some("true"),
    tls_use_new_alps_codepoint: true,
    tls_signed_cert_timestamps: true,
    tls_grease: true,
    split_cookies: true,
    form_boundary: Some("webkit"),
};

pub static PROFILES: &[Profile] = &[CHROME_150];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome150_matches_upstream_preset() {
        let profile = Profile::find("chrome150").unwrap();
        assert!(profile.tls_grease);
        assert!(profile.tls_permute_extensions);
        assert_eq!(profile.curves.unwrap()[0], "X25519MLKEM768");
        assert_eq!(profile.http2_window_update, Some(15_663_105));
        assert_eq!(profile.http3_pseudo_headers_order, Some("masp"));
        assert_eq!(profile.quic_initial_packet_number, Some(1));
        assert_eq!(profile.headers.len(), 13);
        assert!(profile.headers[0].contains("Chromium\";v=\"150\""));
    }
}
