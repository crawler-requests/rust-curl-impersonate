//! Preset fields that change request bytes but are not part of the TLS or
//! HTTP/2 emulation struct.
//!
//! `tools/gen_profiles.py` parses `split_cookies` and `form_boundary` from
//! curl-impersonate's `impersonations[]`. The values below are those fields for
//! the 48 targets in [`super::TARGETS`]. `okhttp4_android` sets no
//! `form_boundary`; every other target sets `webkit` or `firefox`. Every one of
//! the 48 sets `split_cookies` to true. A name outside that list is left unset.
//!
//! A fingerprint record can carry the same two fields itself — a provider
//! record, or one installed from JSON. [`super::Profile::form_boundary`] and
//! [`super::Profile::split_cookies`] prefer those and fall back to this table
//! for a preset name no record describes.

use super::TARGETS;
use crate::form::FormBoundary;

/// Whether the preset sends one `Cookie` header per cookie on HTTP/2.
pub fn split_cookies(target: &str) -> bool {
    TARGETS.contains(&target)
}

/// The multipart boundary style the preset names, when it names one.
pub fn form_boundary(target: &str) -> Option<FormBoundary> {
    if !TARGETS.contains(&target) {
        return None;
    }
    match target {
        "okhttp4_android" => None,
        "firefox133" | "firefox135" | "firefox144" | "firefox147" | "firefox153" | "firefox154"
        | "firefox155" | "tor145" => Some(FormBoundary::Firefox),
        _ => Some(FormBoundary::WebKit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn okhttp_sets_no_boundary_and_unknown_names_stay_unset() {
        assert!(split_cookies("okhttp4_android"));
        assert_eq!(form_boundary("okhttp4_android"), None);
        assert!(!split_cookies("not-a-preset"));
        assert_eq!(form_boundary("not-a-preset"), None);
        assert_eq!(form_boundary("firefox133"), Some(FormBoundary::Firefox));
        assert_eq!(form_boundary("chrome150"), Some(FormBoundary::WebKit));
    }
}
