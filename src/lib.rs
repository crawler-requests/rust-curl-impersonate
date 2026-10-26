//! Rust rewrite of [curl-impersonate](https://github.com/lexiforest/curl-impersonate).
//!
//! curl-impersonate is a patched curl plus a patched BoringSSL. This crate keeps
//! the BoringSSL half — it is the part that can actually build a browser's
//! ClientHello — and reimplements the curl half on top of [`wreq`]: choosing a
//! browser profile, applying its TLS, HTTP/2 and header settings, and sending the
//! request.
//!
//! ```no_run
//! use rust_curl_impersonate::{Client, Profile};
//!
//! # async fn example() -> rust_curl_impersonate::Result<()> {
//! let client = Client::new(Profile::Chrome150)?;
//! let response = client.get("https://example.com").send().await?;
//! println!("{}", response.status());
//! # Ok(())
//! # }
//! ```
//!
//! # What is covered
//!
//! - **Browser profiles.** [`Profile::Chrome149`] delegates to wreq-util, which
//!   ships Chrome, Edge, Firefox, Safari, Opera and OkHttp targets.
//!   [`Profile::Chrome150`] is built in this crate from curl-impersonate's preset,
//!   because wreq-util stops at Chrome 149. It sets the ML-DSA signature
//!   algorithms, the `X25519MLKEM768` key share, GREASE, ECH grease, permuted
//!   extensions and the HTTP/2 window update that preset records.
//! - **TLS fingerprint.** Cipher order, curves, signature algorithms, extension
//!   permutation, GREASE, ALPS and certificate compression are set through
//!   BoringSSL, not rustls. rustls cannot express them.
//! - **HTTP/2 fingerprint.** SETTINGS values and order, pseudo-header order,
//!   connection window and stream priority.
//! - **WebSocket.** [`Client::websocket`] upgrades over the same TLS fingerprint.
//! - **SOCKS5.** [`ClientBuilder::proxy`] accepts `socks5://` URLs for TCP
//!   connections.
//!
//! # What is not covered
//!
//! - **HTTP/3.** Neither wreq nor its BoringSSL build exposes a QUIC stack, so
//!   curl-impersonate's HTTP/3 settings, QUIC transport parameters and SOCKS5 UDP
//!   associate have no transport to be applied to.
//! - **Per-request JA3 strings.** A profile fixes the fingerprint for the whole
//!   client. Arbitrary JA3 overrides are not parsed.

mod client;
pub mod profile;

pub use client::{Client, ClientBuilder};
pub use profile::Profile;
pub use wreq::{Method, Proxy, StatusCode};

/// Error returned by the client or the transport.
pub type Error = wreq::Error;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
