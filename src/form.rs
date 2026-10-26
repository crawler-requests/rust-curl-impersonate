//! Multipart form boundaries shaped like a browser's.
//!
//! curl-impersonate's presets set `form_boundary` to `webkit` or `firefox`, and
//! `lib/mime.c` turns that into a boundary with a fixed prefix and a fixed
//! amount of randomness:
//!
//! * `webkit` is `------WebKitFormBoundary` plus 16 alphanumeric characters.
//! * `firefox` is `------geckoformboundary` plus 32 hexadecimal characters.
//!
//! wreq's [`wreq::multipart::Form`] accepts a caller-supplied boundary, so a
//! form built here is indistinguishable from one those presets would send.

use wreq::multipart::Form;

/// Which browser's multipart boundary a form should carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormBoundary {
    /// Chrome, Edge, Safari and OkHttp presets (`form_boundary = "webkit"`).
    WebKit,
    /// Firefox and Tor presets (`form_boundary = "firefox"`).
    Firefox,
}

impl FormBoundary {
    /// The boundary string curl-impersonate would generate for this style.
    pub fn generate(self) -> String {
        match self {
            FormBoundary::WebKit => format!("------WebKitFormBoundary{}", random_alnum(16)),
            FormBoundary::Firefox => format!("------geckoformboundary{}", random_hex(32)),
        }
    }

    /// A multipart form whose boundary matches this style.
    pub fn form(self) -> Form {
        Form::with_boundary(self.generate())
    }
}

/// Alphanumeric characters, matching curl's `Curl_rand_alnum` alphabet.
fn random_alnum(len: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    random(len, ALPHABET)
}

fn random_hex(len: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    random(len, ALPHABET)
}

fn random(len: usize, alphabet: &[u8]) -> String {
    use std::io::Read;
    let mut bytes = vec![0u8; len];
    std::fs::File::open("/dev/urandom")
        .expect("urandom")
        .read_exact(&mut bytes)
        .expect("urandom");
    bytes
        .into_iter()
        .map(|byte| alphabet[(byte as usize) % alphabet.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_match_curl_impersonate() {
        let webkit = FormBoundary::WebKit.generate();
        assert!(webkit.starts_with("------WebKitFormBoundary"));
        assert_eq!(webkit.len(), "------WebKitFormBoundary".len() + 16);
        assert!(webkit
            .chars()
            .skip("------WebKitFormBoundary".len())
            .all(|c| c.is_ascii_alphanumeric()));

        let firefox = FormBoundary::Firefox.generate();
        assert!(firefox.starts_with("------geckoformboundary"));
        assert_eq!(firefox.len(), "------geckoformboundary".len() + 32);
        assert!(firefox
            .chars()
            .skip("------geckoformboundary".len())
            .all(|c| c.is_ascii_hexdigit()));

        // Two generations must not collide: the tail is random.
        assert_ne!(
            FormBoundary::WebKit.generate(),
            FormBoundary::WebKit.generate()
        );
    }
}
