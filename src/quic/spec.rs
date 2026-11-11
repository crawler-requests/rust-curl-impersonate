//! TLS inputs the QUIC handshake installs.
//!
//! [`super::crypto`] reads this value and nothing else when it configures
//! BoringSSL. A preset starts here; caller overrides replace fields on the
//! same value before the endpoint is bound.

use std::sync::Arc;

use wreq::tls::{ExtensionType, KeyShare};

use crate::policy;
use crate::profile::Http3Profile;

/// The ClientHello inputs `BoringClientConfig` writes into BoringSSL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTls {
    pub ciphers: String,
    pub curves: String,
    pub sigalgs: String,
    pub grease: bool,
    pub permute_extensions: bool,
    pub signed_cert_timestamps: bool,
    pub session_ticket: bool,
    /// OCSP stapling / status request.
    ///
    /// Generated Chrome presets pass `true`. A caller-supplied record passes
    /// the flag it stored, which is `false` when the caller left OCSP unset.
    pub status_request: bool,
    pub extension_permutation: Vec<ExtensionType>,
    pub delegated_credentials: Option<String>,
    /// `Some(0)` is sent. `None` means the preset did not set a limit.
    pub record_size_limit: Option<u16>,
    pub cert_compression: Vec<String>,
    pub key_shares: Vec<KeyShare>,
    pub ech_grease: bool,
    pub alps: bool,
    pub new_alps: bool,
    /// `None` leaves the extension unset. `Some` empty advertises it.
    pub trust_anchors: Option<Vec<u8>>,
    /// `Some(false)` is key-usage-no-check. `None` leaves the BoringSSL default.
    pub enforce_rsa_key_usage: Option<bool>,
}

impl QuicTls {
    /// Copy the fields the QUIC handshake already reads off a profile.
    ///
    /// `status_request` is the OCSP flag installed into BoringSSL. Generated
    /// Chrome presets pass `true`. Caller records pass their stored flag.
    pub fn from_profile(profile: &Http3Profile, status_request: bool) -> Self {
        Self {
            ciphers: profile.ciphers.to_string(),
            curves: profile.curves.to_string(),
            sigalgs: policy::install_sigalgs(profile.sigalgs),
            grease: profile.grease,
            permute_extensions: profile.permute_extensions,
            signed_cert_timestamps: profile.signed_cert_timestamps,
            session_ticket: profile.session_ticket,
            status_request,
            extension_permutation: profile.extension_permutation.to_vec(),
            delegated_credentials: profile.delegated_credentials.map(str::to_string),
            record_size_limit: profile.record_size_limit,
            cert_compression: profile
                .cert_compression
                .iter()
                .map(|name| (*name).to_string())
                .collect(),
            key_shares: profile.key_shares.to_vec(),
            ech_grease: profile.ech_grease,
            alps: profile.new_alps,
            new_alps: profile.new_alps,
            trust_anchors: None,
            enforce_rsa_key_usage: None,
        }
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Keep at most `limit` key shares. The handshake sends this list.
    pub fn limit_key_shares(&mut self, limit: usize) {
        if self.key_shares.len() > limit {
            self.key_shares.truncate(limit);
        }
    }
}
