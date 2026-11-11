//! A caller-supplied impersonation record.
//!
//! A Chrome version, including one this tree has never captured, is the TLS
//! ClientHello, HTTP/2 settings, headers, and optional HTTP/3 inputs the caller
//! supplies. [`ProfileSpec::install`] keeps that record under the caller's name.
//! Fields left unset stay unset. The generated preset table is not edited.
//!
//! Chrome 150, 151, and 152 stay the captured presets. A later Chrome, including
//! whatever is current on the Stable channel, is another record under a new name.
//! BoringSSL still drops `mldsa44`, `mldsa65`, and `mldsa87`, and rejects a cipher
//! list that contains no TLS 1.2 suite. This record also cannot put HTTP/3 key
//! shares, a QUIC connection-id profile, HTTP/3 headers, a TLS pre-shared-key
//! flag, TLS version bounds, or an HTTP/2 stream dependency on the handshake.
//! Those stay unset instead of being copied from a built-in preset.

use wreq::header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap};
use wreq::http2::Http2Options;
use wreq::tls::{AlpsProtocol, ExtensionType, TlsOptions};
use wreq::Emulation;

use super::{compress, H3Setting, Http3Profile, Profile, TARGETS};
use crate::policy;

/// TLS, HTTP/2, header, and optional HTTP/3 inputs for one new target.
///
/// Install it with [`Self::install`]. The same name can be selected again with
/// [`Profile::find`]. Built-in names are rejected, so Chrome 150 through 152
/// keep the settings they already have.
#[derive(Debug, Clone)]
pub struct ProfileSpec {
    name: String,
    cipher_list: Option<String>,
    curves: Option<String>,
    sigalgs: Option<String>,
    grease: Option<bool>,
    permute_extensions: Option<bool>,
    session_ticket: Option<bool>,
    ech_grease: Option<bool>,
    alps: Option<bool>,
    new_alps_codepoint: Option<bool>,
    cert_compression: Option<String>,
    extension_order: Option<String>,
    record_size_limit: Option<u16>,
    signed_cert_timestamps: Option<bool>,
    ocsp_stapling: Option<bool>,
    delegated_credentials: Option<String>,
    preserve_tls13_cipher_list: Option<bool>,
    http2_settings: Option<String>,
    http2_pseudo_order: Option<String>,
    http2_window_update: Option<u32>,
    http2_initial_window_size: Option<u32>,
    http2_streams: Option<u32>,
    http2_no_priority: Option<bool>,
    headers: Vec<(String, String)>,
    header_order: Option<String>,
    http3_curves: Option<String>,
    http3_settings: Option<String>,
    initial_packet_number: Option<i64>,
    http3_sigalgs: Option<String>,
    http3_ciphers: Option<String>,
    http3_transport_parameters: Option<String>,
    http3_pseudo_order: Option<String>,
    http3_extension_order: Option<String>,
    http3_grease: Option<bool>,
    http3_session_ticket: Option<bool>,
    http3_permute_extensions: Option<bool>,
    http3_ech_grease: Option<bool>,
    http3_signed_cert_timestamps: Option<bool>,
    http3_new_alps: Option<bool>,
    http3_delegated_credentials: Option<String>,
    http3_record_size_limit: Option<u16>,
    http3_cert_compression: Option<String>,
}

impl ProfileSpec {
    /// Start a record for `name`. `name` must not be a built-in target.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cipher_list: None,
            curves: None,
            sigalgs: None,
            grease: None,
            permute_extensions: None,
            session_ticket: None,
            ech_grease: None,
            alps: None,
            new_alps_codepoint: None,
            cert_compression: None,
            extension_order: None,
            record_size_limit: None,
            signed_cert_timestamps: None,
            ocsp_stapling: None,
            delegated_credentials: None,
            preserve_tls13_cipher_list: None,
            http2_settings: None,
            http2_pseudo_order: None,
            http2_window_update: None,
            http2_initial_window_size: None,
            http2_streams: None,
            http2_no_priority: None,
            headers: Vec::new(),
            header_order: None,
            http3_curves: None,
            http3_settings: None,
            initial_packet_number: None,
            http3_sigalgs: None,
            http3_ciphers: None,
            http3_transport_parameters: None,
            http3_pseudo_order: None,
            http3_extension_order: None,
            http3_grease: None,
            http3_session_ticket: None,
            http3_permute_extensions: None,
            http3_ech_grease: None,
            http3_signed_cert_timestamps: None,
            http3_new_alps: None,
            http3_delegated_credentials: None,
            http3_record_size_limit: None,
            http3_cert_compression: None,
        }
    }

    /// Cipher list, in the order the ClientHello should advertise.
    pub fn cipher_list(mut self, list: impl Into<String>) -> Self {
        self.cipher_list = Some(list.into());
        self
    }

    /// Key-exchange groups for the TCP ClientHello.
    pub fn curves(mut self, list: impl Into<String>) -> Self {
        self.curves = Some(list.into());
        self
    }

    /// Signature algorithms. `mldsa44`, `mldsa65`, and `mldsa87` are dropped
    /// when the list is installed. Every other name is kept.
    pub fn sigalgs(mut self, list: impl Into<String>) -> Self {
        self.sigalgs = Some(list.into());
        self
    }

    pub fn grease(mut self, enabled: bool) -> Self {
        self.grease = Some(enabled);
        self
    }

    pub fn permute_extensions(mut self, enabled: bool) -> Self {
        self.permute_extensions = Some(enabled);
        self
    }

    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.session_ticket = Some(enabled);
        self
    }

    pub fn ech_grease(mut self, enabled: bool) -> Self {
        self.ech_grease = Some(enabled);
        self
    }

    /// ALPS for HTTP/2. `false` leaves the extension unset.
    pub fn alps(mut self, enabled: bool) -> Self {
        self.alps = Some(enabled);
        self
    }

    pub fn new_alps_codepoint(mut self, enabled: bool) -> Self {
        self.new_alps_codepoint = Some(enabled);
        self
    }

    /// `zlib`, `brotli`, or `zstd`, separated by commas or colons.
    pub fn cert_compression(mut self, spec: impl Into<String>) -> Self {
        self.cert_compression = Some(spec.into());
        self
    }

    /// ClientHello extension ids, `0-5-10`.
    pub fn extension_order(mut self, spec: impl Into<String>) -> Self {
        self.extension_order = Some(spec.into());
        self
    }

    pub fn record_size_limit(mut self, limit: u16) -> Self {
        self.record_size_limit = Some(limit);
        self
    }

    pub fn signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.signed_cert_timestamps = Some(enabled);
        self
    }

    pub fn ocsp_stapling(mut self, enabled: bool) -> Self {
        self.ocsp_stapling = Some(enabled);
        self
    }

    pub fn delegated_credentials(mut self, list: impl Into<String>) -> Self {
        self.delegated_credentials = Some(list.into());
        self
    }

    /// BoringSSL keeps the supplied TLS 1.3 cipher order only when this is set.
    /// A cipher list sets it unless the caller passes `false`.
    pub fn preserve_tls13_cipher_list(mut self, enabled: bool) -> Self {
        self.preserve_tls13_cipher_list = Some(enabled);
        self
    }

    /// `1:v;2:v` HTTP/2 SETTINGS. This is the only SETTINGS frame content written.
    pub fn http2_settings(mut self, spec: impl Into<String>) -> Self {
        self.http2_settings = Some(spec.into());
        self
    }

    /// Pseudo-header letters `m`, `a`, `s`, `p`. Leave this unset to send no order.
    pub fn http2_pseudo_order(mut self, order: impl Into<String>) -> Self {
        self.http2_pseudo_order = Some(order.into());
        self
    }

    pub fn http2_window_update(mut self, size: u32) -> Self {
        self.http2_window_update = Some(size);
        self
    }

    pub fn http2_initial_window_size(mut self, size: u32) -> Self {
        self.http2_initial_window_size = Some(size);
        self
    }

    pub fn http2_streams(mut self, streams: u32) -> Self {
        self.http2_streams = Some(streams);
        self
    }

    pub fn http2_no_priority(mut self, disabled: bool) -> Self {
        self.http2_no_priority = Some(disabled);
        self
    }

    /// Append one default header. Order is the order of these calls, unless
    /// [`Self::header_order`] says otherwise.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Comma-separated header names. Unset keeps the order of [`Self::header`].
    pub fn header_order(mut self, order: impl Into<String>) -> Self {
        self.header_order = Some(order.into());
        self
    }

    /// QUIC key-exchange groups. Setting any HTTP/3 field installs an HTTP/3 profile.
    pub fn http3_curves(mut self, curves: impl Into<String>) -> Self {
        self.http3_curves = Some(curves.into());
        self
    }

    /// HTTP/3 SETTINGS, `1:v;6:v` or `GREASE`.
    pub fn http3_settings(mut self, spec: impl Into<String>) -> Self {
        self.http3_settings = Some(spec.into());
        self
    }

    /// QUIC initial packet number. `-1` is the Neqo range. Any other accepted
    /// value is that packet number.
    pub fn initial_packet_number(mut self, value: i64) -> Self {
        self.initial_packet_number = Some(value);
        self
    }

    pub fn http3_sigalgs(mut self, list: impl Into<String>) -> Self {
        self.http3_sigalgs = Some(list.into());
        self
    }

    /// QUIC cipher list. When HTTP/3 is set and this is not, the TCP cipher list
    /// is used. No other cipher list is invented.
    pub fn http3_ciphers(mut self, list: impl Into<String>) -> Self {
        self.http3_ciphers = Some(list.into());
        self
    }

    pub fn http3_transport_parameters(mut self, spec: impl Into<String>) -> Self {
        self.http3_transport_parameters = Some(spec.into());
        self
    }

    pub fn http3_pseudo_order(mut self, order: impl Into<String>) -> Self {
        self.http3_pseudo_order = Some(order.into());
        self
    }

    pub fn http3_extension_order(mut self, spec: impl Into<String>) -> Self {
        self.http3_extension_order = Some(spec.into());
        self
    }

    pub fn http3_grease(mut self, enabled: bool) -> Self {
        self.http3_grease = Some(enabled);
        self
    }

    pub fn http3_session_ticket(mut self, enabled: bool) -> Self {
        self.http3_session_ticket = Some(enabled);
        self
    }

    pub fn http3_permute_extensions(mut self, enabled: bool) -> Self {
        self.http3_permute_extensions = Some(enabled);
        self
    }

    pub fn http3_ech_grease(mut self, enabled: bool) -> Self {
        self.http3_ech_grease = Some(enabled);
        self
    }

    pub fn http3_signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.http3_signed_cert_timestamps = Some(enabled);
        self
    }

    pub fn http3_new_alps(mut self, enabled: bool) -> Self {
        self.http3_new_alps = Some(enabled);
        self
    }

    pub fn http3_delegated_credentials(mut self, list: impl Into<String>) -> Self {
        self.http3_delegated_credentials = Some(list.into());
        self
    }

    pub fn http3_record_size_limit(mut self, limit: u16) -> Self {
        self.http3_record_size_limit = Some(limit);
        self
    }

    pub fn http3_cert_compression(mut self, spec: impl Into<String>) -> Self {
        self.http3_cert_compression = Some(spec.into());
        self
    }

    /// Register this record under its name and return the profile that selects it.
    ///
    /// The generated preset table is left as it is. A later [`Profile::find`] of
    /// the same name returns this record. [`ClientBuilder`](crate::ClientBuilder)
    /// overrides then replace single fields on a copy.
    pub fn install(self) -> Result<Profile, String> {
        if self.name.is_empty() {
            return Err("registered target name is empty".to_string());
        }
        if TARGETS.iter().any(|known| *known == self.name) {
            return Err(format!("{} is already a built-in target", self.name));
        }
        let emulation = self.emulation()?;
        let http3 = self.http3_profile()?;
        let http3_status_request = http3.as_ref().map(|_| self.ocsp_stapling.unwrap_or(false));
        let meta = super::StoredMeta {
            family: crate::fingerprint::preset_family(&self.name),
            platform: crate::fingerprint::preset_platform(&self.name),
            ..super::StoredMeta::default()
        };
        super::insert_spec(&self.name, emulation, http3, http3_status_request, meta)
    }

    fn emulation(&self) -> Result<Emulation, String> {
        let tls = self.tls_options()?;
        let http2 = self.http2_options()?;
        let (headers, order) = self.headers()?;
        let mut builder = Emulation::builder().tls_options(tls);
        if let Some(http2) = http2 {
            builder = builder.http2_options(http2);
        }
        if !headers.is_empty() {
            builder = builder.headers(headers).orig_headers(order);
        }
        Ok(builder.build(wreq::Group::new(self.name.clone())))
    }

    fn tls_options(&self) -> Result<TlsOptions, String> {
        let mut tls = TlsOptions::builder();
        if let Some(list) = &self.cipher_list {
            tls = tls.cipher_list(list.clone());
        }
        // BoringSSL reorders TLS 1.3 ciphers unless this is set, so a supplied
        // cipher list would not be the list the handshake sends.
        match self.preserve_tls13_cipher_list {
            Some(enabled) => tls = tls.preserve_tls13_cipher_list(enabled),
            None if self.cipher_list.is_some() => tls = tls.preserve_tls13_cipher_list(true),
            None => {}
        }
        if let Some(list) = &self.curves {
            tls = tls.curves_list(list.clone());
        }
        if let Some(list) = &self.sigalgs {
            tls = tls.sigalgs_list(policy::install_sigalgs(list));
        }
        if let Some(enabled) = self.grease {
            tls = tls.grease_enabled(enabled);
        }
        if let Some(enabled) = self.permute_extensions {
            tls = tls.permute_extensions(enabled);
        }
        if let Some(enabled) = self.session_ticket {
            tls = tls.session_ticket(enabled);
        }
        if let Some(enabled) = self.ech_grease {
            tls = tls.enable_ech_grease(enabled);
        }
        if self.alps == Some(true) {
            tls = tls.alps_protocols([AlpsProtocol::HTTP2]);
        }
        if let Some(enabled) = self.new_alps_codepoint {
            tls = tls.alps_use_new_codepoint(enabled);
        }
        if let Some(spec) = &self.cert_compression {
            tls = tls.certificate_compressors(compressors(spec)?);
        }
        if let Some(spec) = &self.extension_order {
            let types = extension_types(spec)?;
            tls = tls.extension_permutation(types);
        }
        if let Some(limit) = self.record_size_limit {
            tls = tls.record_size_limit(limit);
        }
        if let Some(enabled) = self.signed_cert_timestamps {
            tls = tls.enable_signed_cert_timestamps(enabled);
        }
        if let Some(enabled) = self.ocsp_stapling {
            tls = tls.enable_ocsp_stapling(enabled);
        }
        if let Some(list) = &self.delegated_credentials {
            tls = tls.delegated_credentials(list.clone());
        }
        Ok(tls.build())
    }

    fn http2_options(&self) -> Result<Option<Http2Options>, String> {
        let set = self.http2_settings.is_some()
            || self.http2_pseudo_order.is_some()
            || self.http2_window_update.is_some()
            || self.http2_initial_window_size.is_some()
            || self.http2_streams.is_some()
            || self.http2_no_priority.is_some();
        if !set {
            return Ok(None);
        }
        let mut http2 = Http2Options::builder().build();
        if let Some(spec) = self.http2_settings.as_deref() {
            crate::prepare::apply_http2_settings(&mut http2, spec)?;
        }
        if let Some(order) = self.http2_pseudo_order.as_deref() {
            http2.headers_pseudo_order = Some(crate::prepare::pseudo_order(order)?);
        }
        if let Some(size) = self.http2_window_update {
            http2.initial_conn_window_size = size;
        }
        if let Some(size) = self.http2_initial_window_size {
            http2.initial_window_size = size;
        }
        if let Some(streams) = self.http2_streams {
            http2.max_concurrent_streams = Some(streams);
        }
        if let Some(disabled) = self.http2_no_priority {
            http2.no_rfc7540_priorities = Some(disabled);
        }
        Ok(Some(http2))
    }

    fn headers(&self) -> Result<(HeaderMap, OrigHeaderMap), String> {
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

    fn http3_profile(&self) -> Result<Option<Http3Profile>, String> {
        if !self.wants_http3() {
            return Ok(None);
        }
        if let Some(value) = self.initial_packet_number {
            policy::check_initial_packet_number(value)?;
        }
        let ciphers = self
            .http3_ciphers
            .clone()
            .or_else(|| self.cipher_list.clone())
            .ok_or_else(|| "HTTP/3 needs the cipher list the caller supplied".to_string())?;
        let sigalgs = match self.http3_sigalgs.as_deref() {
            Some(list) => policy::install_sigalgs(list),
            None => String::new(),
        };
        let settings: &'static [H3Setting] = match self.http3_settings.as_deref() {
            Some(spec) => Box::leak(policy::http3_settings(spec)?.into_boxed_slice()),
            None => &[],
        };
        let extension_permutation: &'static [ExtensionType] =
            match self.http3_extension_order.as_deref() {
                Some(spec) => Box::leak(extension_types(spec)?.into_boxed_slice()),
                None => &[],
            };
        let cert_compression: &'static [&'static str] = match self.http3_cert_compression.as_deref()
        {
            Some(spec) => {
                let names = policy::cert_compression_names(spec)?;
                let leaked: Vec<&'static str> = names.iter().map(|name| leak(name)).collect();
                Box::leak(leaked.into_boxed_slice())
            }
            None => &[],
        };
        let pseudo_order = match self.http3_pseudo_order.as_deref() {
            Some(order) => {
                policy::pseudo_letters(order)?;
                leak(order)
            }
            None => "",
        };
        Ok(Some(Http3Profile {
            grease: self.http3_grease.unwrap_or(false),
            signed_cert_timestamps: self.http3_signed_cert_timestamps.unwrap_or(false),
            session_ticket: self.http3_session_ticket.unwrap_or(false),
            curves: leak(self.http3_curves.as_deref().unwrap_or("")),
            sigalgs: leak(&sigalgs),
            ciphers: leak(&ciphers),
            permute_extensions: self.http3_permute_extensions.unwrap_or(false),
            ech_grease: self.http3_ech_grease.unwrap_or(false),
            new_alps: self.http3_new_alps.unwrap_or(false),
            delegated_credentials: self.http3_delegated_credentials.as_deref().map(leak),
            record_size_limit: self.http3_record_size_limit,
            extension_permutation,
            key_shares: &[],
            cert_compression,
            settings,
            transport_parameters: match self.http3_transport_parameters.as_deref() {
                Some(spec) => leak(spec),
                None => "",
            },
            cid_profile: None,
            initial_packet_number: self.initial_packet_number,
            pseudo_order,
            header_order: None,
            headers: &[],
        }))
    }

    fn wants_http3(&self) -> bool {
        self.http3_curves.is_some()
            || self.http3_settings.is_some()
            || self.initial_packet_number.is_some()
            || self.http3_sigalgs.is_some()
            || self.http3_ciphers.is_some()
            || self.http3_transport_parameters.is_some()
            || self.http3_pseudo_order.is_some()
            || self.http3_extension_order.is_some()
            || self.http3_grease.is_some()
            || self.http3_session_ticket.is_some()
            || self.http3_permute_extensions.is_some()
            || self.http3_ech_grease.is_some()
            || self.http3_signed_cert_timestamps.is_some()
            || self.http3_new_alps.is_some()
            || self.http3_delegated_credentials.is_some()
            || self.http3_record_size_limit.is_some()
            || self.http3_cert_compression.is_some()
    }
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_string().into_boxed_str())
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
        let compressor = compress::named(&name)
            .ok_or_else(|| format!("unknown certificate compression {name}"))?;
        out.push(compressor);
    }
    Ok(out)
}
