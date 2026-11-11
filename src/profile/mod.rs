//! Browser impersonation profiles.
//!
//! [`Profile::find`] resolves a curl-impersonate target name to the TLS, HTTP/2
//! and header settings sent on the wire. All 48 targets in `lib/impersonate.c`
//! resolve. [`generated::deviation`] records the fields a target's preset asks
//! for that the current BoringSSL transport cannot send.

pub mod behavior;
pub(crate) mod compress;
mod generated;
mod spec;

use std::sync::Mutex;

use wreq::Emulation;

use crate::fingerprint::{self, Fidelity, Fingerprint, Http3Fingerprint};
use crate::form::FormBoundary;

pub use generated::{deviation, http3, H3Setting, Http3Profile, TARGETS};
pub use spec::ProfileSpec;

/// Alias names. The wire settings still come from a built-in target.
/// The generated table is not edited.
static REGISTRY: Mutex<Vec<(&'static str, &'static str)>> = Mutex::new(Vec::new());

/// An `extends` chain longer than this is treated as a cycle.
const MAX_EXTENDS_DEPTH: usize = 32;

/// Caller-supplied records. Selected by the name the caller gave them.
struct StoredSpec {
    name: &'static str,
    emulation: Emulation,
    http3: Option<Http3Profile>,
    /// QUIC OCSP for this record. `None` when it has no HTTP/3 profile.
    /// `Some(false)` when the caller left OCSP unset.
    http3_status_request: Option<bool>,
    meta: StoredMeta,
}

/// The parts of a caller-supplied record that describe the client rather than
/// the bytes. Kept next to the emulation so an installed record reports the
/// same family, fidelity and HTTP/1.1-only mode as the embedded metadata it
/// came from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StoredMeta {
    pub(crate) family: &'static str,
    pub(crate) platform: &'static str,
    pub(crate) fidelity: Option<Fidelity>,
    pub(crate) deviation: Option<&'static str>,
    pub(crate) http1_only: bool,
    pub(crate) form_boundary: Option<FormBoundary>,
    pub(crate) split_cookies: Option<bool>,
}

impl Default for StoredMeta {
    fn default() -> Self {
        Self {
            family: "",
            platform: "",
            fidelity: None,
            deviation: None,
            http1_only: false,
            form_boundary: None,
            split_cookies: None,
        }
    }
}

static SPECS: Mutex<Vec<StoredSpec>> = Mutex::new(Vec::new());

/// A browser target this crate can impersonate.
///
/// `wire` is the preset whose bytes are sent: a built-in name, or the name of
/// a record installed with [`ProfileSpec`]. `name` is the name the caller asked
/// for. An alias from [`Profile::register`] keeps `wire` as the base preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    wire: &'static str,
    name: &'static str,
}

impl Profile {
    /// The preset whose TLS and HTTP settings are sent.
    ///
    /// A built-in profile and an alias of one return the built-in name.
    /// A profile installed from [`ProfileSpec`] returns the name the caller gave it.
    pub fn target(self) -> &'static str {
        self.wire
    }

    /// The name this profile was resolved as.
    pub fn name(self) -> &'static str {
        self.name
    }

    /// Resolve a built-in target, one of the embedded non-browser
    /// fingerprints, a [`ProfileSpec`], or a name from [`Self::register`].
    ///
    /// Returns `None` when the name is not one of the 48 targets in [`TARGETS`],
    /// not in [`fingerprint::builtin`], and has not been registered.
    pub fn find(name: &str) -> Option<Profile> {
        Self::find_with_depth(name, 0)
    }

    /// [`Self::find`] bounded so an `extends` cycle between provider records
    /// cannot recurse forever.
    fn find_with_depth(name: &str, depth: usize) -> Option<Profile> {
        if depth > MAX_EXTENDS_DEPTH {
            return None;
        }
        if let Some(known) = TARGETS.iter().copied().find(|known| *known == name) {
            return Some(Profile {
                wire: known,
                name: known,
            });
        }
        if let Some(record) = fingerprint::find(name) {
            return match record.extends.as_deref() {
                Some(base) => {
                    let profile = Self::find_with_depth(base, depth + 1)?;
                    Some(Profile {
                        wire: profile.wire,
                        name: record.name.as_str(),
                    })
                }
                None => Some(Profile {
                    wire: record.name.as_str(),
                    name: record.name.as_str(),
                }),
            };
        }
        let specs = SPECS.lock().ok()?;
        if let Some(spec) = specs.iter().find(|spec| spec.name == name) {
            return Some(Profile {
                wire: spec.name,
                name: spec.name,
            });
        }
        drop(specs);
        let registry = REGISTRY.lock().ok()?;
        registry
            .iter()
            .find(|(registered, _)| *registered == name)
            .map(|(registered, wire)| Profile {
                wire,
                name: registered,
            })
    }

    /// Register `name` as another way to select `base`.
    ///
    /// The generated preset table is left as it is. `name` must not already be
    /// a built-in target. [`Self::target`] on the result is still `base`'s
    /// wire name, so the 48 built-in targets stay selectable.
    pub fn register(name: &str, base: Profile) -> Result<Profile, String> {
        if name.is_empty() {
            return Err("registered target name is empty".to_string());
        }
        if TARGETS.iter().any(|known| *known == name) {
            return Err(format!("{name} is already a built-in target"));
        }
        if fingerprint::find(name).is_some() {
            return Err(format!("{name} is already a built-in fingerprint"));
        }
        let specs = SPECS.lock().map_err(|_| "target registry".to_string())?;
        let mut registry = REGISTRY.lock().map_err(|_| "target registry".to_string())?;
        if registry.iter().any(|(registered, _)| *registered == name)
            || specs.iter().any(|spec| spec.name == name)
        {
            return Err(format!("{name} is already registered"));
        }
        let name = Box::leak(name.to_string().into_boxed_str());
        registry.push((name, base.wire));
        Ok(Profile {
            wire: base.wire,
            name,
        })
    }

    /// The emulation settings sent on the wire for this profile.
    pub fn emulation(self) -> Emulation {
        if let Some((emulation, _, _)) = stored(self.name).or_else(|| stored(self.wire)) {
            return emulation;
        }
        if let Some(record) = self.fingerprint() {
            return record.emulation().expect("built-in fingerprint builds");
        }
        generated::emulation(self.wire).expect("profile target is a known target")
    }

    /// The embedded fingerprint this profile resolves to, when it has one.
    ///
    /// An alias returns the alias record; its wire settings are still the base
    /// profile's.
    pub fn fingerprint(self) -> Option<&'static Fingerprint> {
        fingerprint::find(self.name).or_else(|| fingerprint::find(self.wire))
    }

    /// Coarse client family: `chrome`, `go`, `python`, `curl`, `java`, or `node`.
    pub fn family(self) -> &'static str {
        if let Some(meta) = self.stored_meta() {
            return meta.family;
        }
        match self.fingerprint() {
            Some(record) => record.family.as_str(),
            None => fingerprint::preset_family(self.wire),
        }
    }

    /// Platform recorded for this profile, or an empty string.
    pub fn platform(self) -> &'static str {
        if let Some(meta) = self.stored_meta() {
            return meta.platform;
        }
        match self.fingerprint() {
            Some(record) => record.platform.as_str(),
            None => fingerprint::preset_platform(self.wire),
        }
    }

    /// How closely the transport reproduces the capture, for embedded
    /// fingerprints. Built-in browser targets have no such note.
    pub fn fidelity(self) -> Option<Fidelity> {
        if let Some(meta) = self.stored_meta() {
            return meta.fidelity;
        }
        self.fingerprint().and_then(|record| record.fidelity)
    }

    /// Captured fields the transport cannot send.
    ///
    /// An alias reports the base record's gaps.
    pub fn deviation_note(self) -> Option<&'static str> {
        if let Some(meta) = self.stored_meta() {
            if meta.deviation.is_some() {
                return meta.deviation;
            }
        }
        let record = self.fingerprint()?;
        match record.deviation() {
            Some(note) => Some(note),
            None => self
                .extends()
                .and_then(fingerprint::find)
                .and_then(Fingerprint::deviation),
        }
    }

    /// Whether this client must not negotiate HTTP/2.
    pub fn http1_only(self) -> bool {
        if let Some(meta) = self.stored_meta() {
            return meta.http1_only;
        }
        let Some(record) = self.fingerprint() else {
            return false;
        };
        if record.http1_only() {
            return true;
        }
        self.extends()
            .and_then(fingerprint::find)
            .is_some_and(Fingerprint::http1_only)
    }

    /// The multipart boundary style the profile names, when it names one.
    ///
    /// An installed record keeps the boundary it was created with; a fingerprint
    /// record uses the boundary the record supplies; a preset uses the
    /// 48-target table in [`behavior`]. `okhttp4_android` and an unnamed
    /// caller-supplied record stay unset.
    pub fn form_boundary(self) -> Option<FormBoundary> {
        if let Some(boundary) = self.stored_meta().and_then(|meta| meta.form_boundary) {
            return Some(boundary);
        }
        if let Some(record) = self.fingerprint() {
            if let Some(boundary) = record.form_boundary() {
                return Some(boundary);
            }
        }
        behavior::form_boundary(self.wire)
    }

    /// Whether HTTP/2 sends one `Cookie` header per cookie.
    ///
    /// An installed record keeps its recorded setting, a fingerprint record
    /// resolves from the record, and a preset falls back to the 48-target table
    /// in [`behavior`].
    pub fn split_cookies(self) -> bool {
        if let Some(meta) = self.stored_meta() {
            if let Some(split) = meta.split_cookies {
                return split;
            }
        }
        if let Some(record) = self.fingerprint() {
            if let Some(split) = record.split_cookies() {
                return split;
            }
        }
        behavior::split_cookies(self.wire)
    }

    fn stored_meta(self) -> Option<StoredMeta> {
        stored_meta(self.name).or_else(|| stored_meta(self.wire))
    }

    fn extends(self) -> Option<&'static str> {
        self.fingerprint()
            .and_then(|record| record.extends.as_deref())
    }

    /// HTTP/3 record for this profile.
    ///
    /// A caller-supplied profile returns only the HTTP/3 fields it set; a
    /// fingerprint record builds one from its `http3` block; a built-in profile
    /// uses the generated table. An unknown name stays unset.
    pub(crate) fn http3_profile(self) -> Option<Http3Profile> {
        if let Some((_, http3, _)) = stored(self.name).or_else(|| stored(self.wire)) {
            return http3;
        }
        if let Some(record) = self.fingerprint() {
            if let Some(profile) = record.http3_profile().ok().flatten() {
                return Some(profile);
            }
        }
        generated::http3(self.wire)
    }

    /// OCSP flag stored on a caller-supplied HTTP/3 record.
    ///
    /// `Some(false)` when the caller left OCSP unset. `None` for a generated
    /// preset, which keeps OCSP on.
    pub(crate) fn http3_status_request(self) -> Option<bool> {
        if let Some((_, _, flag)) = stored(self.name).or_else(|| stored(self.wire)) {
            return flag;
        }
        if let Some(record) = self.fingerprint() {
            if record
                .http3
                .as_ref()
                .is_some_and(Http3Fingerprint::wants_http3)
            {
                return Some(
                    record
                        .http3
                        .as_ref()
                        .and_then(|http3| http3.ocsp_stapling)
                        .unwrap_or(false),
                );
            }
        }
        None
    }
}

fn stored(name: &str) -> Option<(Emulation, Option<Http3Profile>, Option<bool>)> {
    let specs = SPECS.lock().ok()?;
    let spec = specs.iter().find(|spec| spec.name == name)?;
    Some((
        spec.emulation.clone(),
        spec.http3,
        spec.http3_status_request,
    ))
}

fn stored_meta(name: &str) -> Option<StoredMeta> {
    let specs = SPECS.lock().ok()?;
    specs
        .iter()
        .find(|spec| spec.name == name)
        .map(|spec| spec.meta)
}

pub(crate) fn insert_spec(
    name: &str,
    emulation: Emulation,
    http3: Option<Http3Profile>,
    http3_status_request: Option<bool>,
    meta: StoredMeta,
) -> Result<Profile, String> {
    if fingerprint::find(name).is_some() {
        return Err(format!("{name} is already in the fingerprint library"));
    }
    let mut specs = SPECS.lock().map_err(|_| "target registry".to_string())?;
    let registry = REGISTRY.lock().map_err(|_| "target registry".to_string())?;
    if specs.iter().any(|spec| spec.name == name)
        || registry.iter().any(|(registered, _)| *registered == name)
    {
        return Err(format!("{name} is already registered"));
    }
    let name = Box::leak(name.to_string().into_boxed_str());
    specs.push(StoredSpec {
        name,
        emulation,
        http3,
        http3_status_request,
        meta,
    });
    Ok(Profile { wire: name, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_target_resolves_to_wire_settings() {
        assert_eq!(TARGETS.len(), 48);
        for target in TARGETS {
            let profile = Profile::find(target).expect(target);
            assert_eq!(profile.target(), *target);
            let emulation = profile.emulation();
            let tls = emulation
                .tls_options
                .expect("every preset sets tls options");
            assert!(tls.cipher_list.is_some(), "{target} sets a cipher list");
            assert!(
                emulation.http2_options.is_some(),
                "{target} sets http2 options"
            );
        }
        assert!(Profile::find("nope").is_none());
    }

    #[test]
    fn chrome150_matches_curl_impersonate() {
        let tls = Profile::find("chrome150")
            .unwrap()
            .emulation()
            .tls_options
            .unwrap();
        assert_eq!(
            tls.curves_list.as_deref(),
            Some("X25519MLKEM768:X25519:P-256:P-384")
        );
        assert_eq!(tls.permute_extensions, Some(true));
        assert!(tls.enable_ech_grease);
        assert!(tls.alps_use_new_codepoint);
        // curl-impersonate leads the signature list with ML-DSA. BoringSSL
        // rejects those names, so they are dropped and the deviation says so.
        assert!(!tls.sigalgs_list.as_deref().unwrap().contains("mldsa"));
        assert!(deviation("chrome150").unwrap().contains("mldsa44"));

        let http2 = Profile::find("chrome150")
            .unwrap()
            .emulation()
            .http2_options
            .unwrap();
        assert_eq!(http2.initial_conn_window_size, 15663105);
        assert_eq!(http2.header_table_size, Some(65536));
        assert_eq!(http2.initial_window_size, 6291456);
        assert_eq!(http2.max_header_list_size, Some(262144));
    }

    #[test]
    fn deviations_cover_every_unrepresentable_field() {
        // HTTP/3 presets are sent over the QUIC transport, so they no longer
        // deviate. ML-DSA is the only remaining gap for these targets.
        for target in [
            "chrome145",
            "chrome146",
            "firefox147",
            "safari270",
            "safari270_ios",
        ] {
            assert!(http3(target).is_some(), "{target}");
            assert!(
                deviation(target).is_none_or(|note| !note.contains("HTTP/3")),
                "{target}"
            );
        }
        let chrome145 = http3("chrome145").unwrap();
        assert_eq!(chrome145.cid_profile, Some("webkit"));
        assert_eq!(chrome145.initial_packet_number, Some(1));
        assert!(chrome145.settings.contains(&H3Setting::Grease));
        assert_eq!(http3("firefox147").unwrap().cid_profile, Some("firefox"));
        assert_eq!(http3("firefox133"), None);
        // A record size limit of zero means "send no extension", and BoringSSL
        // implements it that way, so chrome151 no longer deviates on it.
        let chrome151 = Profile::find("chrome151").unwrap().emulation();
        assert_eq!(chrome151.tls_options.unwrap().record_size_limit, Some(0));
        assert!(!deviation("chrome151")
            .unwrap()
            .contains("record_size_limit"));
        // Firefox's extension order and delegated credentials are representable.
        assert!(deviation("firefox133").is_none());
        assert!(deviation("tor145").is_none());
    }
}
