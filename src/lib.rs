//! Rust rewrite of [curl-impersonate](https://github.com/lexiforest/curl-impersonate).
//!
//! curl-impersonate is a patched curl plus a patched BoringSSL. This crate keeps
//! the BoringSSL half, which is what can actually build a browser's ClientHello,
//! and reimplements the curl half on top of [`wreq`]: choosing one of the 48
//! browser targets, applying its TLS, HTTP/2 and header settings, and sending the
//! request.
//!
//! ```no_run
//! use rust_curl_impersonate::{Client, Profile};
//!
//! # async fn example() -> rust_curl_impersonate::Result<()> {
//! let profile = Profile::find("chrome150").expect("chrome150 is a known target");
//! let client = Client::new(profile)?;
//! let response = client.get("https://example.com").send().await?;
//! println!("{}", response.status());
//! # Ok(())
//! # }
//! ```
//!
//! # What is covered
//!
//! - **All 48 browser targets** from curl-impersonate's `lib/impersonate.c`,
//!   including the Chrome 150-152, Firefox 153-155, Safari 260/270, OkHttp and Tor
//!   targets that post-date the presets shipped by other Rust clients. Resolve one
//!   with [`Profile::find`]; the full list is [`profile::TARGETS`].
//! - **TLS fingerprint.** Cipher order (including the TLS 1.3 order), curves,
//!   signature algorithms, extension order, GREASE, ECH grease, ALPS, delegated
//!   credentials, key share selection, record size limit and certificate
//!   compression are set through BoringSSL. rustls cannot express them.
//! - **HTTP/2 fingerprint.** SETTINGS values and order, pseudo-header order,
//!   connection window and stream priority.
//! - **WebSocket.** [`Client::websocket`] upgrades over the same TLS fingerprint.
//!   [`Client::websocket_deflate`] offers the `permessage-deflate` extension that
//!   curl-impersonate negotiates as `permessage-deflate; client_max_window_bits`.
//! - **Multipart boundaries.** [`FormBoundary`] reproduces the `webkit` and `firefox`
//!   boundaries curl-impersonate's presets select.
//! - **SOCKS5.** [`ClientBuilder::proxy`] accepts `socks5://` URLs for TCP
//!   connections.
//!
//! # What the transport cannot send
//!
//! [`profile::deviation`] names, per target, the preset fields that are recorded
//! but not sent:
//!
//! - **ML-DSA signature algorithms.** curl-impersonate's Chrome 150 and later
//!   presets lead `sig_hash_algs` with `mldsa44:mldsa65:mldsa87`. BoringSSL
//!   implements ML-DSA but has no TLS signature-algorithm code point for it, so
//!   the names are rejected and those presets drop them.
//! - **HTTP/3.** No Rust QUIC stack can build a BoringSSL ClientHello: `quinn`
//!   speaks only rustls, and wreq does not expose BoringSSL's QUIC API. The HTTP/3
//!   SETTINGS, QUIC transport parameters and SOCKS5 UDP associate therefore have
//!   nothing to be applied to.

mod client;
mod form;
pub mod profile;

pub use client::{Client, ClientBuilder};
pub use form::FormBoundary;
pub use profile::Profile;
pub use wreq::{Method, Proxy, StatusCode};

/// Error returned by the client or the transport.
pub type Error = wreq::Error;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
