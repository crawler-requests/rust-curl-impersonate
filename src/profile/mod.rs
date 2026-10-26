//! Browser impersonation profiles.
//!
//! [`Profile::find`] resolves a curl-impersonate target name to the TLS, HTTP/2
//! and header settings sent on the wire. All 48 targets in `lib/impersonate.c`
//! resolve. [`generated::deviation`] records the fields a target's preset asks
//! for that the current BoringSSL transport cannot send.

mod compress;
mod generated;

use wreq::Emulation;

pub use generated::{deviation, TARGETS};

/// A browser target this crate can impersonate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    target: &'static str,
}

impl Profile {
    /// The curl-impersonate target name, for example `chrome150`.
    pub fn target(self) -> &'static str {
        self.target
    }

    /// Resolve a curl-impersonate target name.
    ///
    /// Returns `None` when the name is not one of the 48 targets in
    /// [`TARGETS`].
    pub fn find(target: &str) -> Option<Profile> {
        generated::emulation(target).map(|_| Profile {
            target: TARGETS.iter().find(|known| **known == target).unwrap(),
        })
    }

    /// The emulation settings sent on the wire for this profile.
    pub fn emulation(self) -> Emulation {
        generated::emulation(self.target).expect("profile target is a known target")
    }
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
        // HTTP/3 has no transport, so every preset that carries it deviates.
        for target in [
            "chrome145",
            "chrome146",
            "firefox147",
            "safari270",
            "safari270_ios",
        ] {
            assert!(deviation(target).unwrap().contains("HTTP/3"), "{target}");
        }
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
