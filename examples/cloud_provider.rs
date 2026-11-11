//! Attach a cloud fingerprint provider and resolve its records.
//!
//! The provider fetches a JSON library at registration, caches the ETag, and
//! revalidates with `If-None-Match` on refresh. Run it against the in-repo mock
//! service:
//!
//! ```sh
//! python3 tools/cloud_api.py goal-evidence/cloud-library.json \
//!     --port 8747 --bearer-token demo-token
//! # in another shell:
//! FINGERPRINT_CLOUD_URL=http://127.0.0.1:8747/fingerprints.json \
//! FINGERPRINT_CLOUD_TOKEN=demo-token \
//!     cargo run --example cloud_provider
//! ```
//!
//! The mock's log shows the first fetch (`200`) and the refresh round-trip
//! (`If-None-Match` answered with `304`).

use std::time::Duration;

use rust_curl_impersonate::fingerprint::provider::{RemoteProvider, PRIORITY_CLOUD};
use rust_curl_impersonate::fingerprint::{self, refresh_providers, register_provider};
use rust_curl_impersonate::{Client, Profile};

fn main() -> Result<(), String> {
    let url = std::env::var("FINGERPRINT_CLOUD_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8747/fingerprints.json".to_string());
    let token = std::env::var("FINGERPRINT_CLOUD_TOKEN").ok();

    let mut provider = RemoteProvider::new("cloud-acme", &url)
        .with_description("premium records from the acme fingerprint service")
        .with_priority(PRIORITY_CLOUD)
        .with_timeout(Duration::from_secs(10));
    if let Some(token) = token.filter(|token| !token.is_empty()) {
        provider = provider.with_bearer_token(token);
    }
    register_provider(provider)?;

    // A record the cloud provider alone supplies resolves like any other.
    let premium = Profile::find("cloud_premium").expect("the cloud premium record");
    println!(
        "cloud_premium -> target {}, family {}",
        premium.target(),
        premium.family()
    );

    // A record can describe the whole profile — TLS, HTTP/2, HTTP/3, multipart
    // boundary and cookie splitting — without naming a built-in preset.
    let full = Profile::find("cloud_chrome_full").expect("the cloud full-profile record");
    let client = Client::new(full).map_err(|error| error.to_string())?;
    let prepared = client.prepared();
    let http3 = prepared
        .http3()
        .expect("the record carries its own HTTP/3 inputs");
    println!(
        "cloud_chrome_full -> http3 settings {:?}, initial packet {:?}, boundary {:?}, splits cookies {}",
        http3.settings.len(),
        prepared.initial_packet_number(),
        prepared.form_boundary(),
        prepared.splits_cookies(),
    );

    // The cloud provider shadows the embedded go1.26 while it is registered.
    let cloud_go = Profile::find("go1.26").expect("go1.26 still resolves");
    println!(
        "go1.26 -> family {} (provider {})",
        cloud_go.family(),
        fingerprint::provider_of("go1.26")
            .expect("go1.26 has a provider")
            .id
    );

    for info in fingerprint::providers() {
        let overrides = if info.overrides.is_empty() {
            String::new()
        } else {
            format!(", overrides {}", info.overrides.join(", "))
        };
        println!(
            "provider {} (priority {}, {} records, {}){overrides}",
            info.id,
            info.priority,
            info.records,
            if info.description.is_empty() {
                "no description"
            } else {
                &info.description
            },
        );
    }

    // A refresh re-fetches with If-None-Match; the mock answers 304 and the
    // cached records stay.
    refresh_providers()?;
    println!(
        "after refresh, cloud_premium resolves: {}",
        Profile::find("cloud_premium").is_some()
    );

    fingerprint::unregister_provider("cloud-acme")?;
    println!(
        "after unregister, cloud_premium resolves: {}",
        Profile::find("cloud_premium").is_some()
    );
    Ok(())
}
