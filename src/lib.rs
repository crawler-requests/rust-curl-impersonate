//! Pure Rust rewrite of [curl-impersonate](https://github.com/lexiforest/curl-impersonate).
//!
//! The goal is feature parity with that fork — browser TLS fingerprints, HTTP/2
//! and HTTP/3 settings, header order, WebSocket handshake fingerprints and SOCKS5
//! UDP associate for QUIC — and then profiles of our own beyond what upstream ships.
//!
//! What exists today is the profile data layer. See `README.md` for the gap
//! between this and a working client.

pub mod profile;

pub use profile::{Profile, CHROME_150, PROFILES};
