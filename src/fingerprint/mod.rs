//! Fingerprints for non-browser HTTP clients, from loadable providers.
//!
//! curl-impersonate's 48 presets cover browsers, Tor and Android's OkHttp. This
//! module adds a data-driven library for the clients and browser builds those
//! presets do not describe: Go's `net/http`, Python (`requests`/`urllib`/
//! `aiohttp`/`httpx`/`http.client`), libcurl with OpenSSL, the JDK's HTTP
//! client, Node.js (`https`/`http2`/`fetch`), Bun, PHP, Wget, Perl LWP, OpenSSL
//! `s_client`, reqwest with rustls, and browser/app profiles captured from
//! Chromium, Firefox, Android and iOS. A record
//! holds the TLS ClientHello, HTTP/2 settings, request headers and, for
//! HTTP/1.1-only clients, the protocol mode. Chrome shuffles its extension
//! list on every connection; that record sets `permute_extensions` and its
//! `extension_order` is the captured set, not a fixed wire order.
//!
//! # Providers
//!
//! The records are not compiled in as one blob. Every record comes from a
//! [`provider::FingerprintProvider`]: the embedded library is
//! [`provider::BuiltinProvider`], and [`provider::register_provider`]
//! adds records from another source — a JSON document, a directory of
//! documents, or a closure that fetches from a record service. `Profile::find`
//! resolves every name across all registered providers without a separate
//! install step. A provider with a higher
//! [`priority`](provider::FingerprintProvider::priority) wins a clash with a
//! lower one, so an application can patch an embedded record at runtime.
//! [`provider::providers`] lists what is registered and what each shadows.
//! [`load_json`] remains for callers that want to register records as installed
//! profiles rather than library records.
//!
//! Some captured bytes cannot be sent by the BoringSSL transport. A record's
//! `deviations` list says which ones: a cipher suite BoringSSL does not
//! implement, an extension it never emits, or a group it does not know. The
//! library keeps the captured value in the record so the gap is visible instead
//! of silently changing the profile.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use wreq::header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap};
use wreq::http2::Http2Options;
use wreq::tls::{AlpnProtocol, AlpsProtocol, ExtensionType, KeyShare, TlsOptions, TlsVersion};
use wreq::Emulation;

use crate::form::FormBoundary;
use crate::policy;
use crate::profile::{H3Setting, Http3Profile, Profile};

pub mod provider;

pub use provider::{
    provider_of, providers, refresh_providers, register_provider, register_provider_with_priority,
    unregister_provider, BuiltinProvider, DirProvider, FingerprintProvider, FnProvider,
    JsonProvider, ProviderInfo, RemoteProvider, PRIORITY_BUILTIN, PRIORITY_CLOUD, PRIORITY_USER,
};

/// The embedded library. Regenerate with `tools/gen_fingerprints.py`.
const BUILTIN_JSON: &str = include_str!("builtin.json");

/// How closely the transport can reproduce the captured bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fidelity {
    /// Every captured field is sent unchanged.
    Exact,
    /// A few fields are dropped by the transport; the rest match.
    #[default]
    Close,
    /// Several cipher suites or extensions are missing.
    Partial,
}

/// One non-browser client fingerprint.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Fingerprint {
    /// Name used with `Profile::find`.
    pub name: String,
    /// Coarse family: `go`, `python`, `curl`, `java`, `node`, `chrome`, ...
    #[serde(default)]
    pub family: String,
    /// Human-readable client name.
    #[serde(default)]
    pub client: String,
    /// Client version the capture came from.
    #[serde(default)]
    pub version: String,
    /// `linux`, `windows`, `macos`, `android`, `ios`, or empty when unknown.
    #[serde(default)]
    pub platform: String,
    /// How the record was captured.
    #[serde(default)]
    pub source: String,
    /// How closely the transport reproduces the capture. `None` for a record
    /// that only renames a preset outside the library.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fidelity: Option<Fidelity>,
    /// Captured fields the transport cannot send, one sentence each.
    #[serde(default)]
    pub deviations: Vec<String>,
    /// Reuse another profile's wire settings, changing only the metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    /// TLS ClientHello inputs.
    #[serde(default)]
    pub tls: TlsFingerprint,
    /// HTTP/2 settings. `None` for an HTTP/1.1-only client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http2: Option<Http2Fingerprint>,
    /// Default request headers, in send order.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Header order when it differs from `headers`. `Host` is never listed:
    /// the transport writes it for each connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_order: Option<String>,
    /// Force HTTP/1.1 even when the ALPN list contains `h2`.
    #[serde(default)]
    pub http1_only: bool,
    /// Multipart boundary style: `webkit`, `firefox`, or unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_boundary: Option<String>,
    /// Whether HTTP/2 splits cookies into one `Cookie` header each. Unset falls
    /// back to the 48 built-in targets' table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_cookies: Option<bool>,
    /// HTTP/3 inputs, mirroring the `http3_*` builders of [`crate::ProfileSpec`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http3: Option<Http3Fingerprint>,
    /// The joined `deviations`, filled after the library is parsed.
    #[serde(skip)]
    pub deviation_text: Option<String>,
}

/// TLS ClientHello inputs in the names the transport uses.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsFingerprint {
    /// OpenSSL/BoringSSL cipher names in ClientHello order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<String>,
    /// Key-exchange group names in ClientHello order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curves: Option<String>,
    /// Signature algorithm names in ClientHello order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigalgs: Option<String>,
    /// Extension ids joined with `-`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_order: Option<String>,
    /// Groups a key share is generated for, in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_shares: Option<String>,
    /// ALPN protocols in order, `["h2", "http/1.1"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    /// Lowest TLS version, `1.2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    /// Highest TLS version, `1.3`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,
    /// GREASE values in the ClientHello.
    #[serde(default)]
    pub grease: bool,
    /// Shuffle the extension list on every connection, as Chrome does. The
    /// recorded `extension_order` is then the captured set, not the wire order.
    #[serde(default)]
    pub permute_extensions: bool,
    /// Send the `session_ticket` extension.
    #[serde(default)]
    pub session_ticket: bool,
    /// Send `status_request`.
    #[serde(default)]
    pub ocsp_stapling: bool,
    /// Send `signed_certificate_timestamp`.
    #[serde(default)]
    pub signed_cert_timestamps: bool,
    /// Send a GREASE ECH extension.
    #[serde(default)]
    pub ech_grease: bool,
    /// Advertise ALPS for HTTP/2.
    #[serde(default)]
    pub alps: bool,
    /// Use the newer ALPS code point.
    #[serde(default)]
    pub new_alps_codepoint: bool,
    /// Send `renegotiation_info`.
    #[serde(default = "yes")]
    pub renegotiation: bool,
    /// Offer `psk_dhe_ke` in `psk_key_exchange_modes`.
    #[serde(default = "yes")]
    pub psk_dhe_ke: bool,
    /// Keep the supplied TLS 1.3 cipher order.
    #[serde(default = "yes")]
    pub preserve_tls13_cipher_list: bool,
    /// `zlib`, `brotli`, or `zstd`, separated by commas or colons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_compression: Option<String>,
    /// `record_size_limit` value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_size_limit: Option<u16>,
    /// Delegated credential signature algorithms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_credentials: Option<String>,
}

fn yes() -> bool {
    true
}

impl Default for TlsFingerprint {
    fn default() -> Self {
        Self {
            ciphers: None,
            curves: None,
            sigalgs: None,
            extension_order: None,
            key_shares: None,
            alpn: None,
            min_version: None,
            max_version: None,
            grease: false,
            permute_extensions: false,
            session_ticket: false,
            ocsp_stapling: false,
            signed_cert_timestamps: false,
            ech_grease: false,
            alps: false,
            new_alps_codepoint: false,
            renegotiation: true,
            psk_dhe_ke: true,
            preserve_tls13_cipher_list: true,
            cert_compression: None,
            record_size_limit: None,
            delegated_credentials: None,
        }
    }
}

/// HTTP/2 SETTINGS and connection window.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Http2Fingerprint {
    /// `1:v;2:v` settings in frame order. An empty string sends an empty frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<String>,
    /// Pseudo-header letters `m`, `a`, `s`, `p`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudo_order: Option<String>,
    /// The `WINDOW_UPDATE` increment on the connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_update: Option<u32>,
    /// Initial stream window, when it differs from the transport default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_window_size: Option<u32>,
    /// `NO_RFC7540_PRIORITIES`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_priority: Option<bool>,
}

/// HTTP/3 (QUIC) inputs for a record, in the same names [`ProfileSpec`] uses.
///
/// Every field is optional: an unset field stays unset rather than being copied
/// from a preset. A record that sets none of them has no HTTP/3 profile. The
/// cipher list falls back to the record's TLS ciphers unless
/// [`Self::ciphers`] supplies one.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Http3Fingerprint {
    /// QUIC key-exchange groups, in ClientHello order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curves: Option<String>,
    /// HTTP/3 SETTINGS, `1:v;6:v` or `GREASE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<String>,
    /// QUIC initial packet number. `-1` is the Neqo range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_packet_number: Option<i64>,
    /// Signature algorithms for the QUIC ClientHello.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sigalgs: Option<String>,
    /// QUIC cipher list. When both this and [`crate::Fingerprint::tls`] ciphers
    /// are unset, the HTTP/3 profile cannot be built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<String>,
    /// QUIC transport parameters in curl-impersonate's `id:value` syntax.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_parameters: Option<String>,
    /// HTTP/3 pseudo-header order, letters `m`, `a`, `s`, `p`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pseudo_order: Option<String>,
    /// ClientHello extension ids for the QUIC handshake, `0-5-10`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_order: Option<String>,
    /// GREASE values in the QUIC ClientHello.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grease: Option<bool>,
    /// TLS session ticket extension on the QUIC handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ticket: Option<bool>,
    /// BoringSSL's permuted-extension behavior for QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permute_extensions: Option<bool>,
    /// Send a GREASE ECH extension on the QUIC handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech_grease: Option<bool>,
    /// Send `signed_certificate_timestamp` on the QUIC handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_cert_timestamps: Option<bool>,
    /// Use the newer ALPS code point on the QUIC handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_alps: Option<bool>,
    /// Query OCSP for the origin's certificate over QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_stapling: Option<bool>,
    /// Delegated credential signature algorithms for QUIC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_credentials: Option<String>,
    /// `record_size_limit` value. `Some(0)` means the extension is not sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_size_limit: Option<u16>,
    /// `zlib`, `brotli`, or `zstd`, separated by commas or colons.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_compression: Option<String>,
    /// HTTP/3 header order. Unset keeps the record's regular header order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_order: Option<String>,
    /// HTTP/3 request headers, in send order.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

impl Http3Fingerprint {
    /// Whether any HTTP/3 field is set.
    pub fn wants_http3(&self) -> bool {
        self.curves.is_some()
            || self.settings.is_some()
            || self.initial_packet_number.is_some()
            || self.sigalgs.is_some()
            || self.ciphers.is_some()
            || self.transport_parameters.is_some()
            || self.pseudo_order.is_some()
            || self.extension_order.is_some()
            || self.grease.is_some()
            || self.session_ticket.is_some()
            || self.permute_extensions.is_some()
            || self.ech_grease.is_some()
            || self.signed_cert_timestamps.is_some()
            || self.new_alps.is_some()
            || self.ocsp_stapling.is_some()
            || self.delegated_credentials.is_some()
            || self.record_size_limit.is_some()
            || self.cert_compression.is_some()
            || self.header_order.is_some()
            || !self.headers.is_empty()
    }
}

impl Fingerprint {
    /// The name this record is selected by.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The preset whose wire bytes are sent. Equal to [`Self::name`] unless the
    /// record extends another one.
    pub fn wire(&self) -> &str {
        self.extends.as_deref().unwrap_or(&self.name)
    }

    /// Whether this record only renames another profile.
    pub fn is_alias(&self) -> bool {
        self.extends.is_some()
    }

    /// Captured fields the transport cannot send, joined with `; `.
    pub fn deviation(&self) -> Option<&str> {
        self.deviation_text.as_deref()
    }

    /// Build the wire options for this record.
    ///
    /// An alias delegates to the base profile. The result is not cached, so a
    /// caller can modify its copy without changing the library.
    pub fn emulation(&self) -> Result<Emulation, String> {
        if let Some(base) = &self.extends {
            let profile = Profile::find(base)
                .ok_or_else(|| format!("{} extends unknown profile {base}", self.name))?;
            return Ok(profile.emulation());
        }
        let tls = self.tls_options()?;
        let http2 = self
            .http2
            .as_ref()
            .map(Http2Fingerprint::options)
            .transpose()?;
        let (headers, order) = self.header_map()?;
        let mut builder = Emulation::builder().tls_options(tls);
        if let Some(http2) = http2 {
            builder = builder.http2_options(http2);
        }
        if !headers.is_empty() {
            builder = builder.headers(headers).orig_headers(order);
        }
        Ok(builder.build(wreq::Group::new(self.name.clone())))
    }

    /// Register this record under its name.
    ///
    /// The built-in library and the 48 curl-impersonate targets keep their
    /// names. [`Profile::find`] returns the new profile afterwards.
    pub fn install(self) -> Result<Profile, String> {
        if self.name.is_empty() {
            return Err("fingerprint name is empty".to_string());
        }
        if crate::profile::TARGETS.contains(&self.name.as_str()) {
            return Err(format!("{} is already a built-in target", self.name));
        }
        if find(&self.name).is_some() {
            return Err(format!(
                "{} is already in the fingerprint library",
                self.name
            ));
        }
        if let Some(base) = &self.extends {
            let profile = Profile::find(base)
                .ok_or_else(|| format!("{} extends unknown profile {base}", self.name))?;
            let meta = crate::profile::StoredMeta {
                family: leak(&self.family),
                platform: leak(&self.platform),
                fidelity: self.fidelity,
                deviation: profile.deviation_note(),
                http1_only: profile.http1_only() || self.http1_only(),
                form_boundary: profile.form_boundary(),
                split_cookies: Some(profile.split_cookies()),
            };
            return crate::profile::insert_spec(
                &self.name,
                profile.emulation(),
                profile.http3_profile(),
                profile.http3_status_request(),
                meta,
            );
        }
        let emulation = self.emulation()?;
        let http3 = self.http3_profile()?;
        let http3_status_request = http3.as_ref().map(|_| {
            self.http3
                .as_ref()
                .and_then(|http3| http3.ocsp_stapling)
                .unwrap_or(false)
        });
        let meta = crate::profile::StoredMeta {
            family: leak(&self.family),
            platform: leak(&self.platform),
            fidelity: self.fidelity,
            deviation: self.deviation().map(leak),
            http1_only: self.http1_only(),
            form_boundary: self.form_boundary(),
            split_cookies: self.split_cookies,
        };
        crate::profile::insert_spec(&self.name, emulation, http3, http3_status_request, meta)
    }

    /// The ALPN list, or `None` to keep the transport default.
    pub fn alpn(&self) -> Option<&[String]> {
        self.tls.alpn.as_deref()
    }

    /// Whether the client must not negotiate HTTP/2.
    pub fn http1_only(&self) -> bool {
        self.http1_only
            || self
                .tls
                .alpn
                .as_deref()
                .is_some_and(|alpn| alpn == ["http/1.1"])
    }

    /// The multipart boundary style the record names, when it names one.
    pub fn form_boundary(&self) -> Option<FormBoundary> {
        match self.form_boundary.as_deref() {
            Some("webkit") => Some(FormBoundary::WebKit),
            Some("firefox") => Some(FormBoundary::Firefox),
            _ => None,
        }
    }

    /// Whether HTTP/2 should split cookies, when the record says so.
    pub fn split_cookies(&self) -> Option<bool> {
        self.split_cookies
    }

    /// HTTP/3 profile for this record, or `None` when it carries none.
    ///
    /// An alias delegates to the base profile. The result is not cached, so a
    /// caller can modify its copy without changing the library.
    pub fn http3_profile(&self) -> Result<Option<Http3Profile>, String> {
        if let Some(base) = &self.extends {
            let profile = Profile::find(base)
                .ok_or_else(|| format!("{} extends unknown profile {base}", self.name))?;
            return Ok(profile.http3_profile());
        }
        let Some(http3) = &self.http3 else {
            return Ok(None);
        };
        if !http3.wants_http3() {
            return Ok(None);
        }
        if let Some(value) = http3.initial_packet_number {
            policy::check_initial_packet_number(value)?;
        }
        let ciphers = http3
            .ciphers
            .clone()
            .or_else(|| self.tls.ciphers.clone())
            .ok_or_else(|| "HTTP/3 needs the cipher list the record supplied".to_string())?;
        let sigalgs = match http3.sigalgs.as_deref() {
            Some(list) => policy::install_sigalgs(list),
            None => String::new(),
        };
        let settings: &'static [H3Setting] = match http3.settings.as_deref() {
            Some(spec) => Box::leak(policy::http3_settings(spec)?.into_boxed_slice()),
            None => &[],
        };
        let extension_permutation: &'static [ExtensionType] = match http3.extension_order.as_deref()
        {
            Some(spec) => Box::leak(extension_types(spec)?.into_boxed_slice()),
            None => &[],
        };
        let cert_compression: &'static [&'static str] = match http3.cert_compression.as_deref() {
            Some(spec) => {
                let names = policy::cert_compression_names(spec)?;
                let leaked: Vec<&'static str> = names.iter().map(|name| leak(name)).collect();
                Box::leak(leaked.into_boxed_slice())
            }
            None => &[],
        };
        let pseudo_order = match http3.pseudo_order.as_deref() {
            Some(order) => {
                policy::pseudo_letters(order)?;
                leak(order)
            }
            None => "",
        };
        let header_order = http3.header_order.as_deref().map(leak);
        let headers: &'static [(&'static str, &'static str)] = if http3.headers.is_empty() {
            &[]
        } else {
            Box::leak(
                http3
                    .headers
                    .iter()
                    .map(|(name, value)| (leak(name), leak(value)))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            )
        };
        Ok(Some(Http3Profile {
            grease: http3.grease.unwrap_or(false),
            signed_cert_timestamps: http3.signed_cert_timestamps.unwrap_or(false),
            session_ticket: http3.session_ticket.unwrap_or(false),
            curves: leak(http3.curves.as_deref().unwrap_or("")),
            sigalgs: leak(&sigalgs),
            ciphers: leak(&ciphers),
            permute_extensions: http3.permute_extensions.unwrap_or(false),
            ech_grease: http3.ech_grease.unwrap_or(false),
            new_alps: http3.new_alps.unwrap_or(false),
            delegated_credentials: http3.delegated_credentials.as_deref().map(leak),
            record_size_limit: http3.record_size_limit,
            extension_permutation,
            key_shares: &[],
            cert_compression,
            settings,
            transport_parameters: match http3.transport_parameters.as_deref() {
                Some(spec) => leak(spec),
                None => "",
            },
            cid_profile: None,
            initial_packet_number: http3.initial_packet_number,
            pseudo_order,
            header_order,
            headers,
        }))
    }

    fn tls_options(&self) -> Result<TlsOptions, String> {
        let tls = &self.tls;
        let mut builder = TlsOptions::builder()
            .grease_enabled(tls.grease)
            .permute_extensions(tls.permute_extensions)
            .session_ticket(tls.session_ticket)
            .enable_ocsp_stapling(tls.ocsp_stapling)
            .enable_signed_cert_timestamps(tls.signed_cert_timestamps)
            .enable_ech_grease(tls.ech_grease)
            .alps_use_new_codepoint(tls.new_alps_codepoint)
            .renegotiation(tls.renegotiation)
            .psk_dhe_ke(tls.psk_dhe_ke)
            .preserve_tls13_cipher_list(tls.preserve_tls13_cipher_list);
        if tls.alps {
            builder = builder.alps_protocols([AlpsProtocol::HTTP2]);
        }
        if let Some(list) = &tls.ciphers {
            builder = builder.cipher_list(list.clone());
        }
        if let Some(list) = &tls.curves {
            builder = builder.curves_list(list.clone());
        }
        if let Some(list) = &tls.sigalgs {
            builder = builder.sigalgs_list(policy::install_sigalgs(list));
        }
        // BoringSSL's fixed extension order keeps the listed extensions in
        // place and only shuffles the rest, so it cannot model a client that
        // reshuffles the whole list. When the record sets `permute_extensions`,
        // leave the order to BoringSSL and treat `extension_order` as the
        // captured set.
        if !tls.permute_extensions {
            if let Some(spec) = &tls.extension_order {
                let types = policy::extension_ids(spec)?
                    .into_iter()
                    .map(ExtensionType::from)
                    .collect::<Vec<_>>();
                builder = builder.extension_permutation(types);
            }
        }
        if let Some(spec) = &tls.key_shares {
            builder = builder.key_shares(key_shares(spec)?);
        }
        if let Some(limit) = tls.record_size_limit {
            builder = builder.record_size_limit(limit);
        }
        if let Some(spec) = &tls.cert_compression {
            builder = builder.certificate_compressors(compressors(spec)?);
        }
        if let Some(list) = &tls.delegated_credentials {
            builder = builder.delegated_credentials(list.clone());
        }
        if let Some(version) = tls.min_version.as_deref() {
            builder = builder.min_tls_version(parse_version(version)?);
        }
        if let Some(version) = tls.max_version.as_deref() {
            builder = builder.max_tls_version(parse_version(version)?);
        }
        if let Some(protocols) = &tls.alpn {
            builder = builder.alpn_protocols(
                protocols
                    .iter()
                    .map(|name| alpn(name))
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok(builder.build())
    }

    fn header_map(&self) -> Result<(HeaderMap, OrigHeaderMap), String> {
        let pairs = match self.header_order.as_deref() {
            Some(order) => policy::order_headers(&self.headers, order),
            None => self.headers.clone(),
        };
        let mut headers = HeaderMap::new();
        let mut order = OrigHeaderMap::new();
        for (name, value) in &pairs {
            let header_name =
                HeaderName::try_from(name.as_str()).map_err(|error| error.to_string())?;
            let header_value =
                HeaderValue::try_from(value.as_str()).map_err(|error| error.to_string())?;
            headers.append(header_name, header_value);
            order.insert(name.clone());
        }
        Ok((headers, order))
    }

    /// Check the parts that do not depend on a network connection.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("fingerprint name is empty".to_string());
        }
        if let Some(base) = &self.extends {
            if Profile::find(base).is_none() {
                return Err(format!("{} extends unknown profile {base}", self.name));
            }
            return Ok(());
        }
        self.emulation().map(|_| ())
    }
}

impl Http2Fingerprint {
    fn options(&self) -> Result<Http2Options, String> {
        let mut http2 = Http2Options::builder().build();
        match self.settings.as_deref() {
            Some("") => {
                // The transport always writes SETTINGS_INITIAL_WINDOW_SIZE.
                // The protocol default is the least visible value.
                http2.initial_window_size = 65_535;
            }
            Some(spec) => crate::prepare::apply_http2_settings(&mut http2, spec)?,
            None => {}
        }
        if let Some(order) = self.pseudo_order.as_deref() {
            http2.headers_pseudo_order = Some(crate::prepare::pseudo_order(order)?);
        }
        if let Some(increment) = self.window_update {
            // The transport emits `target - 65535` as the increment.
            http2.initial_conn_window_size = increment.saturating_add(65_535);
        } else {
            // 65535 is the initial connection window, so no WINDOW_UPDATE is
            // written, matching a capture that has none.
            http2.initial_conn_window_size = 65_535;
        }
        if let Some(size) = self.initial_window_size {
            http2.initial_window_size = size;
        }
        if let Some(disabled) = self.no_priority {
            http2.no_rfc7540_priorities = Some(disabled);
        }
        Ok(http2)
    }
}

fn leak(value: &str) -> &'static str {
    Box::leak(value.to_string().into_boxed_str())
}

fn alpn(name: &str) -> Result<AlpnProtocol, String> {
    match name {
        "h2" => Ok(AlpnProtocol::HTTP2),
        "http/1.1" => Ok(AlpnProtocol::HTTP1),
        "h3" => Ok(AlpnProtocol::HTTP3),
        other => Err(format!("unsupported ALPN protocol {other}")),
    }
}

fn parse_version(version: &str) -> Result<TlsVersion, String> {
    match version {
        "1.0" => Ok(TlsVersion::TLS_1_0),
        "1.1" => Ok(TlsVersion::TLS_1_1),
        "1.2" => Ok(TlsVersion::TLS_1_2),
        "1.3" => Ok(TlsVersion::TLS_1_3),
        other => Err(format!("unsupported TLS version {other}")),
    }
}

fn extension_types(spec: &str) -> Result<Vec<ExtensionType>, String> {
    Ok(policy::extension_ids(spec)?
        .into_iter()
        .map(ExtensionType::from)
        .collect())
}

fn key_shares(spec: &str) -> Result<Vec<KeyShare>, String> {
    let mut shares = Vec::new();
    for name in spec.split(':') {
        if name.is_empty() {
            continue;
        }
        let share = match name {
            "P-256" | "P256" => KeyShare::P256,
            "P-384" | "P384" => KeyShare::P384,
            "P-521" | "P521" => KeyShare::P521,
            "X25519" => KeyShare::X25519,
            "X25519MLKEM768" => KeyShare::X25519_MLKEM768,
            "X25519Kyber768Draft00" => KeyShare::X25519_KYBER768_DRAFT00,
            "P256Kyber768Draft00" => KeyShare::P256_KYBER768_DRAFT00,
            "MLKEM1024" => KeyShare::MLKEM1024,
            "ffdhe2048" | "dhe2048" => KeyShare::FFDHE2048,
            "ffdhe3072" | "dhe3072" => KeyShare::FFDHE3072,
            other => return Err(format!("unsupported key share group {other}")),
        };
        shares.push(share);
    }
    Ok(shares)
}

fn compressors(
    spec: &str,
) -> Result<Vec<&'static dyn wreq::tls::compress::CertificateCompressor>, String> {
    let names = policy::cert_compression_names(spec)?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let compressor = crate::profile::compress::named(&name)
            .ok_or_else(|| format!("unknown certificate compression {name}"))?;
        out.push(compressor);
    }
    Ok(out)
}

/// Every fingerprint embedded in this crate, in file order.
///
/// This is the built-in provider's records only. [`records`] adds the records
/// every other registered provider supplies.
pub fn builtin() -> &'static [Fingerprint] {
    static LIBRARY: OnceLock<&'static [Fingerprint]> = OnceLock::new();
    LIBRARY.get_or_init(|| {
        Box::leak(
            parse_builtin()
                .expect("built-in fingerprint JSON")
                .into_boxed_slice(),
        )
    })
}

/// Parse the embedded library.
pub(crate) fn parse_builtin() -> Result<Vec<Fingerprint>, String> {
    parse_json(BUILTIN_JSON)
}

/// Every record from every registered provider, in first-provider order.
///
/// When two providers supply a record with the same name, the higher-priority
/// one wins and takes the name's position. The embedded library comes first,
/// so the built-in names keep their order.
pub fn records() -> &'static [&'static Fingerprint] {
    &provider::snapshot().records
}

/// Resolve one fingerprint by name, across every registered provider.
pub fn find(name: &str) -> Option<&'static Fingerprint> {
    provider::snapshot().index.get(name).copied()
}

/// Every resolvable fingerprint's name, in [`records`] order.
pub fn names() -> Vec<&'static str> {
    records()
        .iter()
        .map(|record| record.name.as_str())
        .collect()
}

/// Every family that has at least one record, in [`records`] order.
pub fn families() -> Vec<&'static str> {
    let mut families = Vec::new();
    for record in records() {
        if !record.family.is_empty() && !families.contains(&record.family.as_str()) {
            families.push(record.family.as_str());
        }
    }
    families
}

/// Records in one family, in [`records`] order.
pub fn by_family(family: &str) -> impl Iterator<Item = &'static Fingerprint> + '_ {
    records()
        .iter()
        .copied()
        .filter(move |record| record.family == family)
}

/// Parse a JSON document containing one record or a list of records.
pub fn parse_json(text: &str) -> Result<Vec<Fingerprint>, String> {
    #[derive(Deserialize)]
    struct Document {
        fingerprints: Vec<Fingerprint>,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Input {
        List(Vec<Fingerprint>),
        One(Fingerprint),
        Named(Document),
    }

    let mut records =
        match serde_json::from_str::<Input>(text).map_err(|error| error.to_string())? {
            Input::List(records) => records,
            Input::One(record) => vec![record],
            Input::Named(document) => document.fingerprints,
        };
    for record in &mut records {
        if !record.deviations.is_empty() {
            record.deviation_text = Some(record.deviations.join("; "));
        }
    }
    Ok(records)
}

/// Parse a JSON document and register every record.
///
/// Returns the profiles in the same order as the document. A record whose name
/// already resolves is rejected before anything is changed.
pub fn load_json(text: &str) -> Result<Vec<Profile>, String> {
    let records = parse_json(text)?;
    if records.is_empty() {
        return Err("fingerprint document is empty".to_string());
    }
    let mut seen = Vec::new();
    for record in &records {
        if seen.contains(&record.name) {
            return Err(format!("{} appears twice in the document", record.name));
        }
        // Check every name and every wire input before installing anything.
        record.validate()?;
        if Profile::find(&record.name).is_some() {
            return Err(format!("{} is already registered", record.name));
        }
        seen.push(record.name.clone());
    }
    let mut profiles = Vec::with_capacity(records.len());
    for record in records {
        profiles.push(record.install()?);
    }
    Ok(profiles)
}

/// Read a JSON document from disk and register every record.
pub fn load_json_file(path: impl AsRef<std::path::Path>) -> Result<Vec<Profile>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    load_json(&text)
}

/// Serialize records back to JSON.
pub fn to_json(records: &[Fingerprint]) -> Result<String, String> {
    serde_json::to_string_pretty(records).map_err(|error| error.to_string())
}

/// Inferred family for one of the 48 curl-impersonate targets.
pub fn preset_family(name: &str) -> &'static str {
    if name.starts_with("chrome") || name.starts_with("edge") {
        "chrome"
    } else if name.starts_with("firefox") {
        "firefox"
    } else if name.starts_with("safari") {
        "safari"
    } else if name.starts_with("okhttp") {
        "okhttp"
    } else if name.starts_with("tor") {
        "tor"
    } else {
        "browser"
    }
}

/// Inferred platform for one of the 48 curl-impersonate targets.
pub fn preset_platform(name: &str) -> &'static str {
    if name.ends_with("_android") {
        "android"
    } else if name.ends_with("_ios") {
        "ios"
    } else if name.ends_with("_macos") {
        "macos"
    } else {
        ""
    }
}
