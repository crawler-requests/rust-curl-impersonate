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
//! - **A built-in library for clients and browsers.** [`fingerprint`] embeds
//!   captured Go `net/http`, Python (`requests`/`urllib`/`aiohttp`/`httpx`/
//!   `http.client`), libcurl with OpenSSL, the JDK's HTTP client, Node.js
//!   (`https`/`http2`/`fetch`), Bun, PHP, Wget, Perl LWP, OpenSSL `s_client`,
//!   reqwest with rustls, Chromium and Firefox builds, Android app and OkHttp
//!   profiles, iOS app and Safari iOS profiles, Opera, plus aliases such as
//!   `golang`, `python`, `curl`, `java`, `node`, `bun`, `php`, `rust`, `chrome`,
//!   `firefox`, `android`, `ios`, `opera`, `chrome_android`, `safari_ios` and
//!   `okhttp_android`. Every name resolves with [`Profile::find`].
//!   [`Profile::family`], [`Profile::platform`], [`Profile::fidelity`] and
//!   [`Profile::deviation_note`] report what a record describes; each record's
//!   `deviations` list names the captured fields the transport cannot send.
//! - **Loadable fingerprint providers.** The library is not one compiled-in
//!   blob: every record comes from a
//!   [`fingerprint::FingerprintProvider`]. The embedded library is
//!   [`fingerprint::BuiltinProvider`]; [`fingerprint::register_provider`] adds
//!   records from a JSON document ([`fingerprint::JsonProvider`]), a directory
//!   of documents ([`fingerprint::DirProvider`]), or a closure
//!   ([`fingerprint::FnProvider`]) that can fetch from a record service.
//!   [`Profile::find`] resolves names across every registered provider, so a
//!   provider's records are selectable without an install step. A provider's
//!   [`priority`](fingerprint::FingerprintProvider::priority) decides clashes:
//!   `PRIORITY_BUILTIN` < `PRIORITY_CLOUD` < `PRIORITY_USER`, so an application
//!   can patch an embedded record at runtime. [`fingerprint::providers`] lists
//!   what is registered and what each shadows, and
//!   [`fingerprint::refresh_providers`] reloads them.
//!   [`fingerprint::load_json`] and [`fingerprint::load_json_file`] remain for
//!   callers that want records registered as installed profiles instead.
//! - **TLS fingerprint.** Cipher order (including the TLS 1.3 order), curves,
//!   signature algorithms, extension order, GREASE, ECH grease, ALPS, delegated
//!   credentials, key share selection, record size limit and certificate
//!   compression are set through BoringSSL. rustls cannot express them. The
//!   Chromium record also enables per-connection extension permutation, because
//!   Chrome reshuffles its extension list on each handshake.
//! - **HTTP/2 fingerprint.** SETTINGS values and order, pseudo-header order when
//!   the preset sets one, connection window and stream priority. A preset that
//!   leaves the pseudo-header order unset, including Chrome 150, does not gain
//!   an invented order.
//! - **HTTP/3.** [`Client::http3_get`] sends a preset that carries a QUIC profile,
//!   and [`Client::http3_endpoint`] is the endpoint that send path binds.
//!   HTTP/3 SETTINGS, transport parameters, HTTP/3 headers, connection-id length
//!   and the initial packet number are the values on that flight. The first
//!   Initial uses that packet number. When the preset says `15:AUTO`, transport
//!   parameter `0x0f` is the same bytes as the packet's Source Connection ID.
//!   [`Client::headers_after_negotiation`] uses the profile's HTTP/3 headers
//!   after HTTP/3 is selected, and the regular headers when HTTP/3 falls back.
//!   `http3_only` fails when the preset has no HTTP/3 fingerprint. Firefox
//!   153, 154 and 155 have none, and none is invented. [`Client::get`] stays
//!   on HTTP/2.
//! - **WebSocket deflate.** [`Client::websocket_deflate`] offers
//!   `permessage-deflate; client_max_window_bits`. After the peer accepts,
//!   [`WebSocketUpgrade::accepted_codec`] compresses text and binary payloads
//!   and inflates them back to the original bytes. Control frames stay
//!   uncompressed. Deflate combined with raw mode is an argument error.
//!   [`Client::try_websocket_deflate`] returns [`WsError::NotBuilt`] when zlib
//!   is not linked, and does not offer the extension.
//! - **Multipart boundaries.** [`Client::multipart`] uses the preset's
//!   `form_boundary`. [`FormBoundary::WebKit`] is `------WebKitFormBoundary` plus
//!   16 alphanumeric characters. [`FormBoundary::Firefox`] is
//!   `------geckoformboundary` plus 32 hex characters. `okhttp4_android` sets no
//!   boundary. [`ClientBuilder::form_boundary`] switches the style.
//! - **Cookies and transfer info.** [`Client::request_cookies`] and
//!   [`Client::request_cookies_for`] apply `split_cookies`: one `Cookie` header
//!   on HTTP/1.1, and one header per cookie on HTTP/2 and HTTP/3.
//!   [`Client::cookie_changes`] records `SET` or `DELETE`, a tab, then a
//!   Netscape cookie line. [`Client::redirect_history`] records the status, a
//!   tab, then the request URL that returned it. [`ClientBuilder::follow_safe`]
//!   follows redirects and rejects a redirected connection whose address is
//!   loopback, private, or link-local. The initial URL is not filtered.
//! - **Proxy and DNS.** [`ClientBuilder::proxy_url`] accepts `http://`,
//!   `https://` and `socks5://`. An HTTP/3 request through `socks5://` or
//!   `socks5h://` uses UDP ASSOCIATE (command `0x03`). When origin DNS is
//!   delegated to an HTTP proxy or to SOCKS4a/SOCKS5h, the client does not emit
//!   a direct HTTPS DNS-record lookup. [`ClientBuilder::proxy_credential_no_reuse`]
//!   stops a later request with different proxy credentials from reusing the
//!   earlier proxy connection or TLS session.
//! - **Overrides and new targets.** [`ClientBuilder`] can replace any preset
//!   field the tests cover — TLS inputs on the TCP and QUIC handshakes, HTTP/2
//!   and HTTP/3 settings, header order and suppression, QUIC packet number and
//!   transport parameters — without editing the generated preset source. An
//!   unset preset field stays unset. [`Client::impersonate`] accepts
//!   `name[:yes|no]`. [`Client::impersonate_choice`] lets an explicit target
//!   win over `CURL_IMPERSONATE`. [`Profile::register`] adds a named target
//!   that keeps another preset's wire settings. [`ProfileSpec::install`] adds
//!   a target from the TLS ClientHello, HTTP/2 settings, header list, and
//!   optional HTTP/3 values the caller supplies. A field left unset stays
//!   unset, so a later Chrome is another record under a new name. All 48
//!   built-in targets stay selectable.
//!
//! # What the transport cannot send
//!
//! [`profile::deviation`] names, per target, the preset fields that are recorded
//! but not sent. Embedded fingerprint records carry their own `deviations` list,
//! because BoringSSL drops different fields for each captured client (cipher
//! suites it does not implement, X448/ffdhe groups, `signature_algorithms_cert`,
//! `status_request_v2`, and the automatic padding extension). The browser
//! presets have one remaining gap, ML-DSA:
//!
//! - **ML-DSA signature algorithms.** curl-impersonate's Chrome 150 and later
//!   presets lead `sig_hash_algs` with `mldsa44`, `mldsa65` and `mldsa87`.
//!   BoringSSL rejects those three names, so the installed signature list omits
//!   them. No other signature algorithm is dropped. The code points are still
//!   draft and are not hardcoded.

mod client;
mod cookies;
mod dns;
pub mod fingerprint;
mod form;
mod policy;
mod prepare;
pub mod profile;
pub mod quic;
mod session;
mod socks;
mod ws;

pub use client::{Client, ClientBuilder};
pub use form::FormBoundary;
pub use policy::CookieProtocol;
pub use prepare::Prepared;
pub use profile::{Profile, ProfileSpec};
pub use wreq::{Method, Proxy, StatusCode};
pub use ws::{WebSocketUpgrade, WsError, WsFrame};

/// Error returned by the client or the transport.
pub type Error = wreq::Error;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
