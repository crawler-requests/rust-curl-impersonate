//! One preparation path for a preset and the caller's overrides.
//!
//! The public client builds this before it opens a connection. HTTP/2
//! emulation, the HTTP/3 profile, cookie splitting, the multipart boundary,
//! the initial packet number, and the SOCKS choice all come from here, so a
//! test can read the bytes the client will send without a network.

use std::borrow::Cow;
use std::sync::Arc;

use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::http2::{PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId};
use wreq::tls::ExtensionType;
use wreq::Emulation;

use crate::cookies;
use crate::form::FormBoundary;
use crate::policy::{self, CookieProtocol};
use crate::profile::{self, Http3Profile, Profile};
use crate::quic;
use crate::quic::spec::QuicTls;
use crate::socks::{self, SocksChoice};

/// The wire options a built client will use.
pub struct Prepared {
    name: String,
    base: &'static str,
    family: &'static str,
    platform: &'static str,
    fidelity: Option<crate::fingerprint::Fidelity>,
    deviation: Option<&'static str>,
    http1_only: bool,
    emulation: Emulation,
    http3: Option<Http3Profile>,
    quic_tls: Option<Arc<QuicTls>>,
    split_cookies: bool,
    form_boundary: Option<FormBoundary>,
    initial_packet_number: Option<u32>,
    proxy_url: Option<String>,
    socks: SocksChoice,
    udp_associate_request: Option<Vec<u8>>,
    /// Offer sent on a WebSocket upgrade that negotiates permessage-deflate.
    websocket_extension: &'static str,
    regular_headers: Vec<(String, String)>,
    http3_header_override: Option<Vec<(String, String)>>,
    http3_header_order: Option<String>,
    http3_settings: Option<Vec<profile::H3Setting>>,
    http3_pseudo_order: Option<String>,
    transport_parameters: Option<String>,
    cid_profile: Option<String>,
    websocket_headers: Option<Vec<(String, String)>>,
    websocket_emulation: Option<Emulation>,
    proxy_credential_no_reuse: bool,
    follow_safe: Option<bool>,
}

/// The permessage-deflate offer curl-impersonate puts on a WebSocket handshake.
pub const WEBSOCKET_EXTENSION: &str = "permessage-deflate; client_max_window_bits";

/// Caller changes applied on top of a built-in preset.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    /// Name recorded for this client. Defaults to the preset's target.
    pub name: Option<String>,
    /// Headers merged onto the preset. An empty value removes that header.
    pub headers: Vec<(String, String)>,
    /// `false` drops the preset's base headers before the caller headers.
    pub base_headers: Option<bool>,
    /// Comma-separated normal header order.
    pub header_order: Option<String>,
    /// Replacement for the preset's HTTP/2 stream window, when set.
    pub http2_initial_window_size: Option<u32>,
    /// `1:v;2:v` HTTP/2 SETTINGS.
    pub http2_settings: Option<String>,
    /// `WINDOW_UPDATE` connection window.
    pub http2_window_update: Option<u32>,
    /// `STREAMS` max concurrent streams.
    pub http2_streams: Option<u32>,
    /// `NO_PRIORITY`.
    pub http2_no_priority: Option<bool>,
    /// Force HTTP/1.1 even when the profile would negotiate `h2`.
    pub http1_only: Option<bool>,
    /// Pseudo-header letters `m`, `a`, `s`, `p`.
    pub http2_pseudo_order: Option<String>,
    /// `STREAM_EXCLUSIVE`, `0` or `1`.
    pub stream_exclusive: Option<i64>,
    /// Proxy URL, `http://`, `https://`, or `socks5://`.
    pub proxy_url: Option<String>,
    pub sigalgs: Option<String>,
    pub enable_alps: Option<bool>,
    pub new_alps_codepoint: Option<bool>,
    pub cert_compression: Option<String>,
    pub session_ticket: Option<bool>,
    pub permute_extensions: Option<bool>,
    pub grease: Option<bool>,
    pub extension_order: Option<String>,
    pub key_usage_no_check: Option<bool>,
    pub signed_cert_timestamps: Option<bool>,
    pub status_request: Option<bool>,
    pub delegated_credentials: Option<String>,
    pub trust_anchors: Option<String>,
    pub record_size_limit: Option<u16>,
    pub key_shares_limit: Option<usize>,
    pub http3_pseudo_order: Option<String>,
    pub http3_settings: Option<String>,
    pub http3_curves: Option<String>,
    pub http3_sigalgs: Option<String>,
    pub http3_extension_order: Option<String>,
    pub http3_headers: Option<Vec<(String, String)>>,
    pub http3_header_order: Option<String>,
    pub quic_cid: Option<String>,
    pub initial_packet_number: Option<i64>,
    pub quic_transport_parameters: Option<String>,
    pub form_boundary: Option<String>,
    pub split_cookies: Option<bool>,
    pub websocket_headers: Option<Vec<(String, String)>>,
    pub websocket_header_order: Option<String>,
    pub websocket_disable_ticket: Option<bool>,
    pub websocket_cert_compression: Option<String>,
    pub proxy_credential_no_reuse: bool,
    pub follow_safe: Option<bool>,
}

impl Prepared {
    /// Apply `profile` and `overrides` to the settings that go on the wire.
    pub fn prepare(profile: Profile, overrides: &Overrides) -> Result<Self, String> {
        let base = profile.target();
        let mut emulation = profile.emulation();
        apply_http2(&mut emulation, overrides)?;
        apply_tls(emulation.tls_options.as_mut(), overrides)?;
        let regular_headers = apply_headers(&mut emulation, overrides)?;

        let http3 = profile.http3_profile();
        let status_request = profile.http3_status_request().unwrap_or(true);
        let mut quic_tls = http3.map(|h3| QuicTls::from_profile(&h3, status_request));
        if let Some(tls) = quic_tls.as_mut() {
            apply_quic_tls(tls, overrides)?;
        }
        let quic_tls = quic_tls.map(QuicTls::shared);

        let packet_source = overrides
            .initial_packet_number
            .or_else(|| http3.and_then(|profile| profile.initial_packet_number));
        let initial_packet_number = quic::resolve_initial_packet_number(packet_source)?;

        let mut form_boundary = profile.form_boundary();
        if let Some(style) = overrides.form_boundary.as_deref() {
            form_boundary = Some(parse_boundary(style)?);
        }
        let split_cookies = overrides
            .split_cookies
            .unwrap_or_else(|| profile.split_cookies());

        let http3_settings = match overrides.http3_settings.as_deref() {
            Some(spec) => Some(policy::http3_settings(spec)?),
            None => None,
        };
        if let Some(order) = overrides.http3_pseudo_order.as_deref() {
            policy::pseudo_letters(order)?;
        }
        let cid_profile = match overrides.quic_cid.as_deref() {
            Some(spec) => Some(policy::cid_profile(spec)?.to_string()),
            None => None,
        };

        let socks = socks::select(overrides.proxy_url.as_deref(), http3.is_some());
        let udp_associate_request = match socks {
            SocksChoice::UdpAssociate => Some(socks::udp_associate_request()),
            SocksChoice::Direct | SocksChoice::TcpConnect => None,
        };

        let websocket_emulation = websocket_emulation(&emulation, overrides)?;

        Ok(Self {
            name: overrides
                .name
                .clone()
                .unwrap_or_else(|| profile.name().to_string()),
            base,
            family: profile.family(),
            platform: profile.platform(),
            fidelity: profile.fidelity(),
            deviation: profile
                .deviation_note()
                .or_else(|| profile::deviation(base)),
            http1_only: overrides.http1_only.unwrap_or_else(|| profile.http1_only()),
            emulation,
            http3,
            quic_tls,
            split_cookies,
            form_boundary,
            initial_packet_number,
            proxy_url: overrides.proxy_url.clone(),
            socks,
            udp_associate_request,
            websocket_extension: WEBSOCKET_EXTENSION,
            regular_headers,
            http3_header_override: overrides.http3_headers.clone(),
            http3_header_order: overrides.http3_header_order.clone(),
            http3_settings,
            http3_pseudo_order: overrides.http3_pseudo_order.clone(),
            transport_parameters: overrides.quic_transport_parameters.clone(),
            cid_profile,
            websocket_headers: overrides.websocket_headers.clone(),
            websocket_emulation,
            proxy_credential_no_reuse: overrides.proxy_credential_no_reuse,
            follow_safe: overrides.follow_safe,
        })
    }

    /// The target name, including a caller-supplied name that is not in the preset table.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The preset this client started from.
    ///
    /// A caller-supplied profile uses the name it was installed under.
    pub fn base(&self) -> &'static str {
        self.base
    }

    /// TLS and HTTP/2 options, after overrides. This is the emulation handed to
    /// the TCP client.
    pub fn emulation(&self) -> &Emulation {
        &self.emulation
    }

    /// QUIC ClientHello inputs, when the preset has an HTTP/3 profile.
    ///
    /// The endpoint passes this same `Arc` to the BoringSSL configuration.
    pub fn quic_tls(&self) -> Option<&Arc<QuicTls>> {
        self.quic_tls.as_ref()
    }

    /// Cipher list the ClientHello will advertise.
    pub fn cipher_list(&self) -> Option<&str> {
        self.emulation
            .tls_options
            .as_ref()
            .and_then(|tls| tls.cipher_list.as_deref())
    }

    /// HTTP/2 pseudo-header order. `None` when the preset does not set one.
    pub fn pseudo_order(&self) -> Option<Vec<PseudoId>> {
        self.emulation.http2_options.as_ref().and_then(|http2| {
            http2
                .headers_pseudo_order
                .as_ref()
                .map(|order| order.into_iter().copied().collect())
        })
    }

    /// HTTP/2 initial stream window after overrides.
    pub fn http2_initial_window_size(&self) -> Option<u32> {
        self.emulation
            .http2_options
            .as_ref()
            .map(|http2| http2.initial_window_size)
    }

    /// A header added by the caller, looked up case-insensitively.
    pub fn extra_header(&self, name: &str) -> Option<&str> {
        self.emulation
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
    }

    /// Normal headers after merge, suppression and ordering.
    pub fn regular_headers(&self) -> &[(String, String)] {
        &self.regular_headers
    }

    /// Headers for a negotiated protocol. HTTP/3 uses the profile's HTTP/3
    /// defaults, or the caller's HTTP/3 list when one was set. Fallback uses
    /// the regular defaults.
    pub fn headers_for(&self, http3: bool) -> Vec<(String, String)> {
        if http3 {
            http3_fields(self)
        } else {
            self.regular_headers.clone()
        }
    }

    /// HTTP/3 profile, when the preset has one. Unset profiles stay unset.
    pub fn http3(&self) -> Option<&Http3Profile> {
        self.http3.as_ref()
    }

    /// HTTP/3 SETTINGS the send path writes. `None` keeps the profile's list.
    pub fn http3_settings(&self) -> Option<&[profile::H3Setting]> {
        self.http3_settings.as_deref()
    }

    /// HTTP/3 pseudo-header letters, when the caller replaced them.
    pub fn http3_pseudo_order(&self) -> Option<&str> {
        self.http3_pseudo_order
            .as_deref()
            .or_else(|| self.http3.map(|profile| profile.pseudo_order))
    }

    /// Transport-parameter text the QUIC handshake encodes.
    pub fn transport_parameters(&self) -> Option<&str> {
        self.transport_parameters
            .as_deref()
            .or_else(|| self.http3.map(|profile| profile.transport_parameters))
    }

    /// Connection-id profile override. `None` keeps the preset's profile.
    pub fn cid_profile_override(&self) -> Option<&str> {
        self.cid_profile.as_deref()
    }

    /// Resolved initial packet number for the HTTP/3 profile.
    pub fn initial_packet_number(&self) -> Option<u32> {
        self.initial_packet_number
    }

    /// Whether HTTP/2 and HTTP/3 split cookies into one header each.
    pub fn splits_cookies(&self) -> bool {
        self.split_cookies
    }

    /// Cookie header values for an HTTP/2 request.
    pub fn cookie_headers(&self, raw: &str) -> Vec<String> {
        self.cookie_headers_for(raw, CookieProtocol::Http2)
    }

    /// Cookie header values for one HTTP version. HTTP/1.1 stays one header.
    pub fn cookie_headers_for(&self, raw: &str, protocol: CookieProtocol) -> Vec<String> {
        cookies::cookie_headers(raw, policy::split_for(protocol, self.split_cookies))
    }

    /// Multipart boundary style, when the preset sets `form_boundary`.
    pub fn form_boundary(&self) -> Option<FormBoundary> {
        self.form_boundary
    }

    /// WebSocket extension offer.
    pub fn websocket_extension(&self) -> &'static str {
        self.websocket_extension
    }

    /// Headers that replace the normal list on a WebSocket upgrade, when set.
    pub fn websocket_headers(&self) -> Option<&[(String, String)]> {
        self.websocket_headers.as_deref()
    }

    /// TLS emulation used only for `wss` when a WebSocket TLS override is set.
    ///
    /// This is the emulation the WebSocket client is built from.
    pub fn websocket_emulation(&self) -> Option<&Emulation> {
        self.websocket_emulation.as_ref()
    }

    /// Whether an HTTP/3 request through the configured proxy uses UDP ASSOCIATE.
    pub fn uses_udp_associate(&self) -> bool {
        self.socks == SocksChoice::UdpAssociate
    }

    /// The UDP ASSOCIATE request this client sends, when that is the selected mode.
    pub fn udp_associate_request(&self) -> Option<&[u8]> {
        self.udp_associate_request.as_deref()
    }

    /// Proxy URL recorded at build time.
    pub fn proxy_url(&self) -> Option<&str> {
        self.proxy_url.as_deref()
    }

    /// `CURLOPT_PROXY_CREDENTIAL_NO_REUSE`.
    pub fn proxy_credential_no_reuse(&self) -> bool {
        self.proxy_credential_no_reuse
    }

    /// `Some(true)` is `CURLFOLLOW_SAFE`. `None` does not follow redirects.
    pub fn follow_safe(&self) -> Option<bool> {
        self.follow_safe
    }

    /// Client family this profile belongs to.
    pub fn family(&self) -> &'static str {
        self.family
    }

    /// Platform this profile was captured on, or an empty string.
    pub fn platform(&self) -> &'static str {
        self.platform
    }

    /// How closely the transport reproduces an embedded fingerprint capture.
    /// `None` for the 48 browser targets.
    pub fn fidelity(&self) -> Option<crate::fingerprint::Fidelity> {
        self.fidelity
    }

    /// Whether the client must stay on HTTP/1.1.
    pub fn http1_only(&self) -> bool {
        self.http1_only
    }

    /// Captured fields the transport cannot send.
    pub fn deviation(&self) -> Option<&'static str> {
        self.deviation
    }

    pub(crate) fn http3_header_override(&self) -> Option<&[(String, String)]> {
        self.http3_header_override.as_deref()
    }

    pub(crate) fn http3_header_order(&self) -> Option<&str> {
        self.http3_header_order.as_deref()
    }
}

fn http3_fields(prepared: &Prepared) -> Vec<(String, String)> {
    let profile_headers = prepared.http3.map(|profile| profile.headers);
    let mut headers = policy::negotiated_headers(
        true,
        prepared.http3_header_override.as_deref(),
        profile_headers,
        &prepared.regular_headers,
    );
    if let Some(order) = prepared.http3_header_order.as_deref() {
        headers = policy::order_headers(&headers, order);
    }
    headers
}

fn apply_http2(emulation: &mut Emulation, overrides: &Overrides) -> Result<(), String> {
    let Some(http2) = emulation.http2_options.as_mut() else {
        return Ok(());
    };
    if let Some(size) = overrides.http2_initial_window_size {
        http2.initial_window_size = size;
    }
    if let Some(size) = overrides.http2_window_update {
        http2.initial_conn_window_size = size;
    }
    if let Some(streams) = overrides.http2_streams {
        http2.max_concurrent_streams = Some(streams);
    }
    if let Some(disabled) = overrides.http2_no_priority {
        http2.no_rfc7540_priorities = Some(disabled);
    }
    if let Some(spec) = overrides.http2_settings.as_deref() {
        apply_http2_settings(http2, spec)?;
    }
    if let Some(order) = overrides.http2_pseudo_order.as_deref() {
        http2.headers_pseudo_order = Some(pseudo_order(order)?);
    }
    if let Some(exclusive) = overrides.stream_exclusive {
        if exclusive != 0 && exclusive != 1 {
            return Err("stream exclusive must be 0 or 1".to_string());
        }
        apply_exclusive(http2, exclusive == 1);
    }
    Ok(())
}

pub(crate) fn apply_http2_settings(
    http2: &mut wreq::http2::Http2Options,
    spec: &str,
) -> Result<(), String> {
    let pairs = policy::setting_pairs(spec)?;
    let mut order = SettingsOrder::builder();
    for pair in pairs {
        let id = match pair.id {
            1 => {
                http2.header_table_size = Some(saturate_u32(pair.value));
                SettingId::HeaderTableSize
            }
            2 => {
                http2.enable_push = Some(pair.value != 0);
                SettingId::EnablePush
            }
            3 => {
                http2.max_concurrent_streams = Some(saturate_u32(pair.value));
                SettingId::MaxConcurrentStreams
            }
            4 => {
                http2.initial_window_size = saturate_u32(pair.value);
                SettingId::InitialWindowSize
            }
            5 => {
                http2.max_frame_size = Some(saturate_u32(pair.value));
                SettingId::MaxFrameSize
            }
            6 => {
                http2.max_header_list_size = Some(saturate_u32(pair.value));
                SettingId::MaxHeaderListSize
            }
            8 => {
                http2.enable_connect_protocol = Some(pair.value != 0);
                SettingId::EnableConnectProtocol
            }
            9 => {
                http2.no_rfc7540_priorities = Some(pair.value != 0);
                SettingId::NoRfc7540Priorities
            }
            other => return Err(format!("unsupported http2 setting {other}")),
        };
        order = order.push(id);
    }
    http2.settings_order = Some(order.build());
    Ok(())
}

fn saturate_u32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

pub(crate) fn pseudo_order(spec: &str) -> Result<PseudoOrder, String> {
    let mut builder = PseudoOrder::builder();
    for letter in policy::pseudo_letters(spec)? {
        let id = match letter {
            'm' => PseudoId::Method,
            'a' => PseudoId::Authority,
            's' => PseudoId::Scheme,
            'p' => PseudoId::Path,
            _ => return Err(format!("pseudo-header order rejects {letter}")),
        };
        builder = builder.push(id);
    }
    Ok(builder.build())
}

fn apply_exclusive(http2: &mut wreq::http2::Http2Options, exclusive: bool) {
    let (id, weight) = match http2.headers_stream_dependency {
        Some(dependency) => {
            let mut encoded = Vec::new();
            dependency.encode(&mut encoded);
            let weight = encoded.get(4).copied().unwrap_or(255);
            (dependency.dependency_id(), weight)
        }
        None => (StreamId::zero(), 255),
    };
    http2.headers_stream_dependency = Some(StreamDependency::new(id, weight, exclusive));
}

fn apply_tls(tls: Option<&mut wreq::tls::TlsOptions>, overrides: &Overrides) -> Result<(), String> {
    let Some(tls) = tls else {
        return Ok(());
    };
    if let Some(list) = overrides.sigalgs.as_deref() {
        let installed = policy::install_sigalgs(list);
        tls.sigalgs_list = Some(Cow::Owned(installed));
    }
    if let Some(enabled) = overrides.enable_alps {
        tls.alps_protocols = enabled.then_some(Cow::Borrowed(&[wreq::tls::AlpsProtocol::HTTP2]));
        if !enabled {
            tls.alps_use_new_codepoint = false;
        }
    }
    if let Some(enabled) = overrides.new_alps_codepoint {
        tls.alps_use_new_codepoint = enabled;
    }
    if let Some(spec) = overrides.cert_compression.as_deref() {
        tls.certificate_compressors = Some(Cow::Owned(compressors(spec)?));
    }
    if let Some(enabled) = overrides.session_ticket {
        tls.session_ticket = enabled;
    }
    if let Some(enabled) = overrides.permute_extensions {
        tls.permute_extensions = Some(enabled);
    }
    if let Some(enabled) = overrides.grease {
        tls.grease_enabled = Some(enabled);
    }
    if let Some(spec) = overrides.extension_order.as_deref() {
        tls.extension_permutation = Some(Cow::Owned(extension_types(spec)?));
    }
    if let Some(no_check) = overrides.key_usage_no_check {
        tls.enforce_rsa_key_usage = Some(!no_check);
    }
    if let Some(enabled) = overrides.signed_cert_timestamps {
        tls.enable_signed_cert_timestamps = enabled;
    }
    if let Some(enabled) = overrides.status_request {
        tls.enable_ocsp_stapling = enabled;
    }
    if let Some(creds) = overrides.delegated_credentials.as_deref() {
        tls.delegated_credentials = Some(Cow::Owned(creds.to_string()));
    }
    if let Some(spec) = overrides.trust_anchors.as_deref() {
        let anchors = policy::trust_anchors(spec)?;
        tls.trust_anchors = Some(Cow::Owned(anchors.wire));
    }
    if let Some(limit) = overrides.record_size_limit {
        tls.record_size_limit = Some(limit);
    }
    if let Some(limit) = overrides.key_shares_limit {
        if let Some(shares) = tls.key_shares.as_mut() {
            let mut owned = shares.to_vec();
            owned.truncate(limit);
            *shares = Cow::Owned(owned);
        }
    }
    Ok(())
}

fn apply_quic_tls(tls: &mut QuicTls, overrides: &Overrides) -> Result<(), String> {
    if let Some(list) = overrides.sigalgs.as_deref() {
        tls.sigalgs = policy::install_sigalgs(list);
    }
    if let Some(enabled) = overrides.enable_alps {
        tls.alps = enabled;
        if !enabled {
            tls.new_alps = false;
        }
    }
    if let Some(enabled) = overrides.new_alps_codepoint {
        tls.new_alps = enabled;
    }
    if let Some(spec) = overrides.cert_compression.as_deref() {
        tls.cert_compression = policy::cert_compression_names(spec)?;
    }
    if let Some(enabled) = overrides.session_ticket {
        tls.session_ticket = enabled;
    }
    if let Some(enabled) = overrides.permute_extensions {
        tls.permute_extensions = enabled;
    }
    if let Some(enabled) = overrides.grease {
        tls.grease = enabled;
    }
    if let Some(spec) = overrides.extension_order.as_deref() {
        tls.extension_permutation = extension_types(spec)?;
    }
    if let Some(no_check) = overrides.key_usage_no_check {
        tls.enforce_rsa_key_usage = Some(!no_check);
    }
    if let Some(enabled) = overrides.signed_cert_timestamps {
        tls.signed_cert_timestamps = enabled;
    }
    if let Some(enabled) = overrides.status_request {
        tls.status_request = enabled;
    }
    if let Some(creds) = overrides.delegated_credentials.as_deref() {
        tls.delegated_credentials = Some(creds.to_string());
    }
    if let Some(spec) = overrides.trust_anchors.as_deref() {
        tls.trust_anchors = Some(policy::trust_anchors(spec)?.wire);
    }
    if let Some(limit) = overrides.record_size_limit {
        tls.record_size_limit = Some(limit);
    }
    if let Some(limit) = overrides.key_shares_limit {
        tls.limit_key_shares(limit);
    }
    // HTTP/3-only inputs replace the TCP values on this path.
    if let Some(curves) = overrides.http3_curves.as_deref() {
        tls.curves = curves.to_string();
    }
    if let Some(list) = overrides.http3_sigalgs.as_deref() {
        tls.sigalgs = policy::install_sigalgs(list);
    }
    if let Some(spec) = overrides.http3_extension_order.as_deref() {
        tls.extension_permutation = extension_types(spec)?;
    }
    Ok(())
}

fn extension_types(spec: &str) -> Result<Vec<ExtensionType>, String> {
    Ok(policy::extension_ids(spec)?
        .into_iter()
        .map(ExtensionType::from)
        .collect())
}

fn compressors(
    spec: &str,
) -> Result<Vec<&'static dyn wreq::tls::compress::CertificateCompressor>, String> {
    let names = policy::cert_compression_names(spec)?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let compressor = profile::compress::named(&name)
            .ok_or_else(|| format!("unknown certificate compression {name}"))?;
        out.push(compressor);
    }
    Ok(out)
}

fn apply_headers(
    emulation: &mut Emulation,
    overrides: &Overrides,
) -> Result<Vec<(String, String)>, String> {
    let mut pairs = header_pairs(&emulation.headers);
    let touched = overrides.base_headers == Some(false)
        || !overrides.headers.is_empty()
        || overrides.header_order.is_some();
    if overrides.base_headers == Some(false) {
        pairs.clear();
    }
    if !overrides.headers.is_empty() {
        pairs = policy::merge_headers(&pairs, &overrides.headers);
    }
    if let Some(order) = overrides.header_order.as_deref() {
        pairs = policy::order_headers(&pairs, order);
    }
    if touched {
        write_headers(&mut emulation.headers, &mut emulation.orig_headers, &pairs)?;
    }
    Ok(pairs)
}

fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|text| (name.as_str().to_string(), text.to_string()))
        })
        .collect()
}

fn write_headers(
    headers: &mut HeaderMap,
    order: &mut wreq::header::OrigHeaderMap,
    pairs: &[(String, String)],
) -> Result<(), String> {
    headers.clear();
    *order = wreq::header::OrigHeaderMap::new();
    for (name, value) in pairs {
        let header_name = HeaderName::try_from(name.as_str()).map_err(|error| error.to_string())?;
        let header_value =
            HeaderValue::try_from(value.as_str()).map_err(|error| error.to_string())?;
        headers.append(header_name, header_value);
        order.insert(name.clone());
    }
    Ok(())
}

fn parse_boundary(style: &str) -> Result<FormBoundary, String> {
    match style {
        "webkit" => Ok(FormBoundary::WebKit),
        "firefox" => Ok(FormBoundary::Firefox),
        other => Err(format!(
            "form boundary must be webkit or firefox, not {other}"
        )),
    }
}

fn websocket_emulation(
    base: &Emulation,
    overrides: &Overrides,
) -> Result<Option<Emulation>, String> {
    let headers_set = overrides.websocket_headers.is_some();
    let tls_set = overrides.websocket_disable_ticket.is_some()
        || overrides.websocket_cert_compression.is_some();
    if !headers_set && !tls_set && overrides.websocket_header_order.is_none() {
        return Ok(None);
    }
    let mut emulation = base.clone();
    if let Some(headers) = overrides.websocket_headers.as_deref() {
        let ordered = match overrides.websocket_header_order.as_deref() {
            Some(order) => policy::order_headers(headers, order),
            None => headers.to_vec(),
        };
        write_headers(
            &mut emulation.headers,
            &mut emulation.orig_headers,
            &ordered,
        )?;
    } else if let Some(order) = overrides.websocket_header_order.as_deref() {
        let pairs = policy::order_headers(&header_pairs(&emulation.headers), order);
        write_headers(&mut emulation.headers, &mut emulation.orig_headers, &pairs)?;
    }
    if let Some(tls) = emulation.tls_options.as_mut() {
        if overrides.websocket_disable_ticket == Some(true) {
            tls.session_ticket = false;
        }
        if let Some(spec) = overrides.websocket_cert_compression.as_deref() {
            tls.certificate_compressors = Some(Cow::Owned(compressors(spec)?));
        }
    }
    Ok(Some(emulation))
}
