//! A fully custom provider: pull records from your own server over your own
//! protocol.
//!
//! This example implements [`FingerprintProvider`] by hand instead of using one
//! of the built-in providers ([`JsonProvider`], [`RemoteProvider`], ...). It
//! teaches the whole contract: `id`, a stable identifier; `priority`, where the
//! records sit against the built-in library; and `load`, called once at
//! registration and again on every refresh, which returns the records in the
//! library schema. Whether the records come from a file, a gRPC client, a
//! database or a remote server is entirely up to the implementation — this one
//! pretends to ask a server over the wire.
//!
//! The server side of the contract is tiny. A real endpoint can be anything
//! you already run; the only requirements are that it answers a request and
//! that `load` turns the answer into `Vec<Fingerprint>`.
//!
//! ```sh
//! cargo run --example custom_provider
//! ```

use std::time::Duration;

use rust_curl_impersonate::fingerprint::provider::{
    register_provider, FingerprintProvider, PRIORITY_USER,
};
use rust_curl_impersonate::fingerprint::Fingerprint;

/// A provider that fetches records from a service speaking a private protocol.
///
/// Real implementations would open a socket, call an API, or read a file; this
/// one fakes the round-trip to show the shape. Because `load` is called again
/// by `refresh_providers`, the same code path serves both the initial load and
/// later refreshes.
#[derive(Debug)]
struct CustomProvider {
    // A fully custom source can carry any configuration it needs.
    name: String,
    latency: Duration,
}

impl FingerprintProvider for CustomProvider {
    fn id(&self) -> &str {
        &self.name
    }

    fn priority(&self) -> i32 {
        PRIORITY_USER
    }

    /// The records this source supplies, in the library schema.
    ///
    /// `self` is shared and `&self`, so a stateless provider is easiest: each
    /// call fetches a fresh copy. The registry calls `load` at registration and
    /// on every refresh; nothing else calls it.
    fn load(&self) -> Result<Vec<Fingerprint>, String> {
        // Pretend to be a slow remote service. Real code would do its actual
        // I/O here; a slow provider does not block `Profile::find` on other
        // threads because `load` runs without the registry lock held.
        std::thread::sleep(self.latency);

        // Records can be built directly (serde) or parsed from any format by
        // building `Fingerprint` values.
        let record = Fingerprint {
            name: "custom_hello".to_string(),
            family: "custom".to_string(),
            client: "Custom protocol client".to_string(),
            version: "1.0".to_string(),
            tls: rust_curl_impersonate::fingerprint::TlsFingerprint {
                ciphers: Some("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384".to_string()),
                curves: Some("X25519:P-256".to_string()),
                alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
                ..Default::default()
            },
            ..Default::default()
        };
        // A second record that extends the first one, showing aliases.
        Ok(vec![
            record,
            Fingerprint {
                name: "custom_hello_compact".to_string(),
                family: "custom".to_string(),
                extends: Some("custom_hello".to_string()),
                ..Default::default()
            },
        ])
    }
}

fn main() -> Result<(), String> {
    // Register the custom provider exactly like any built-in one.
    register_provider(CustomProvider {
        name: "custom-server".to_string(),
        latency: Duration::from_millis(1),
    })?;

    // The names it supplied resolve through the normal path.
    let profile = rust_curl_impersonate::Profile::find("custom_hello")
        .expect("a custom provider's record resolves");
    println!(
        "custom_hello -> target {}, family {}, tls ciphers {:?}",
        profile.target(),
        profile.family(),
        profile
            .emulation()
            .tls_options
            .unwrap()
            .cipher_list
            .as_deref()
    );

    // The alias resolves to the same wire settings.
    let compact = rust_curl_impersonate::Profile::find("custom_hello_compact")
        .expect("the alias record resolves");
    assert_eq!(compact.target(), "custom_hello");

    // Refresh calls `load` again; the same provider object is reused.
    rust_curl_impersonate::fingerprint::refresh_providers()?;
    assert!(
        rust_curl_impersonate::Profile::find("custom_hello").is_some(),
        "records survive a refresh"
    );

    println!(
        "provider registered: {}",
        rust_curl_impersonate::fingerprint::providers()
            .iter()
            .any(|info| info.id == "custom-server")
    );
    Ok(())
}
