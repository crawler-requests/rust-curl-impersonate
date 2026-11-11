//! HTTP client that sends requests with a browser's TLS and HTTP/2 fingerprint.
//!
//! The transport is [`wreq`], which links BoringSSL and exposes the ClientHello
//! fields curl-impersonate patches BoringSSL to control. [`Profile`] selects
//! which browser's settings are applied. Caller overrides are merged once, in
//! [`ClientBuilder::build`], and do not change the generated preset table.
//!
//! HTTP/3 presets are sent by [`Client::http3_get`]. That path uses the same
//! preparation step as HTTP/2.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wreq::cookie::CookieStore;
use wreq::dns::Resolve;
use wreq::multipart::Form;
use wreq::{Client as WreqClient, IntoUri, Method, Proxy, RequestBuilder};

use crate::cookies::ChangeLog;
use crate::dns::PolicyResolver;
use crate::policy::{self, CookieProtocol};
use crate::prepare::{Overrides, Prepared};
use crate::profile::Profile;
use crate::quic::endpoint::{H3Bind, H3Endpoint, H3Response};
use crate::session::IsolatingSessionCache;
use crate::socks;
use crate::ws::{self, WebSocketUpgrade, WsError};

/// A client bound to one [`Profile`].
pub struct Client {
    inner: WreqClient,
    ws_inner: Option<WreqClient>,
    profile: Profile,
    prepared: Prepared,
    resolver: Arc<PolicyResolver>,
    sessions: Option<Arc<IsolatingSessionCache>>,
    generation: Arc<AtomicU64>,
    last_credentials: Mutex<Option<String>>,
    cookies: Arc<ChangeLog>,
    redirects: Arc<Mutex<Vec<String>>>,
}

impl Client {
    /// Build a client impersonating `profile`, using the default root certificates.
    pub fn new(profile: Profile) -> crate::Result<Self> {
        Self::builder(profile).build()
    }

    /// `name[:yes|no]`. `yes` installs the preset's base headers.
    pub fn impersonate(spec: &str) -> crate::Result<Self> {
        let parsed = policy::parse_impersonate(spec).map_err(arg_error)?;
        let profile = Profile::find(&parsed.name)
            .ok_or_else(|| arg_error(format!("unknown impersonate target {}", parsed.name)))?;
        Self::builder(profile)
            .base_headers(parsed.base_headers)
            .build()
    }

    /// An explicit target wins over `CURL_IMPERSONATE`.
    pub fn impersonate_choice(
        explicit: Option<&str>,
        environment: Option<&str>,
    ) -> crate::Result<Self> {
        let spec = policy::select_impersonate(explicit, environment)
            .ok_or_else(|| arg_error("no impersonate target"))?;
        Self::impersonate(spec)
    }

    /// Start a builder for a client impersonating `profile`.
    pub fn builder(profile: Profile) -> ClientBuilder {
        ClientBuilder {
            profile,
            timeout: None,
            proxy: None,
            pool_max_idle_per_host: None,
            overrides: Overrides::default(),
        }
    }

    /// The profile this client's connections impersonate.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Wire options this client will send, including caller overrides.
    pub fn prepared(&self) -> &Prepared {
        &self.prepared
    }

    /// Start a request with the given method.
    pub fn request<U: IntoUri>(&self, method: Method, url: U) -> RequestBuilder {
        self.inner.request(method, url)
    }

    pub fn get<U: IntoUri>(&self, url: U) -> RequestBuilder {
        self.inner.get(url)
    }

    pub fn post<U: IntoUri>(&self, url: U) -> RequestBuilder {
        self.inner.post(url)
    }

    /// Start a request and apply the preset's `split_cookies` policy for HTTP/2.
    pub fn request_cookies<U: IntoUri>(
        &self,
        method: Method,
        url: U,
        cookies: &str,
    ) -> RequestBuilder {
        self.request_cookies_for(method, url, cookies, CookieProtocol::Http2)
    }

    /// Cookie headers for one HTTP version. HTTP/1.1 sends a single header.
    pub fn request_cookies_for<U: IntoUri>(
        &self,
        method: Method,
        url: U,
        cookies: &str,
        protocol: CookieProtocol,
    ) -> RequestBuilder {
        let mut builder = self.inner.request(method, url);
        for value in self.prepared.cookie_headers_for(cookies, protocol) {
            builder = builder.header(wreq::header::COOKIE, value);
        }
        builder
    }

    /// A multipart body whose boundary matches the preset's `form_boundary`.
    pub fn multipart(&self) -> Option<Form> {
        self.prepared
            .form_boundary()
            .map(|boundary| boundary.form())
    }

    /// Start a WebSocket upgrade using the TLS fingerprint for `ws` or `wss`.
    pub fn websocket<U: IntoUri>(&self, url: U) -> wreq::ws::WebSocketRequestBuilder {
        self.ws_builder(url)
    }

    /// WebSocket upgrade that offers `permessage-deflate; client_max_window_bits`.
    pub fn websocket_deflate<U: IntoUri>(&self, url: U) -> WebSocketUpgrade {
        self.try_websocket_deflate(url, ws::zlib_is_linked())
            .expect("zlib is linked")
    }

    /// Same offer as [`Self::websocket_deflate`], but `zlib_linked` false is a
    /// not-built error and does not install the extension header.
    pub fn try_websocket_deflate<U: IntoUri>(
        &self,
        url: U,
        zlib_linked: bool,
    ) -> Result<WebSocketUpgrade, WsError> {
        if !zlib_linked {
            return Err(WsError::NotBuilt(
                "permessage-deflate requires zlib and was not offered",
            ));
        }
        let extensions = ws::deflate_headers();
        let headers = self.ws_header_list();
        let inner = self.ws_builder(url).headers(extensions.clone());
        Ok(WebSocketUpgrade {
            inner,
            extensions,
            headers,
        })
    }

    /// Bind the HTTP/3 endpoint this client sends with.
    pub fn http3_endpoint(&self) -> Result<H3Endpoint, String> {
        let profile = self
            .prepared
            .http3()
            .copied()
            .ok_or_else(|| "HTTP/3 is unavailable".to_string())?;
        let tls = self
            .prepared
            .quic_tls()
            .cloned()
            .ok_or_else(|| "HTTP/3 is unavailable".to_string())?;
        H3Endpoint::bind_with(
            &profile,
            self.prepared.initial_packet_number(),
            H3Bind {
                tls,
                transport_parameters: self.prepared.transport_parameters().map(str::to_string),
                cid_profile: self.prepared.cid_profile_override().map(str::to_string),
                settings: self
                    .prepared
                    .http3_settings()
                    .map(|settings| settings.to_vec()),
                pseudo_order: self.prepared.http3_pseudo_order().map(str::to_string),
                http3_header_override: self
                    .prepared
                    .http3_header_override()
                    .map(|pairs| pairs.to_vec()),
                regular_headers: self.prepared.regular_headers().to_vec(),
                header_order: self.prepared.http3_header_order().map(str::to_string),
                split_cookies: self.prepared.splits_cookies(),
            },
        )
    }

    /// Headers after protocol selection.
    ///
    /// `negotiated_http3` is true only after HTTP/3 was selected. That uses the
    /// profile's HTTP/3 headers, or fails when the preset has no HTTP/3
    /// fingerprint. Fallback (`false`) always uses the regular defaults, even
    /// when the preset also has an HTTP/3 fingerprint.
    pub fn headers_after_negotiation(
        &self,
        negotiated_http3: bool,
    ) -> Result<Vec<(String, String)>, String> {
        if !negotiated_http3 {
            return Ok(self.prepared.headers_for(false));
        }
        if self.prepared.http3().is_none() {
            return Err("HTTP/3 is unavailable".to_string());
        }
        Ok(self.prepared.headers_for(true))
    }

    /// Send one HTTP/3 GET with this preset's QUIC profile.
    pub async fn http3_get(
        &self,
        addr: SocketAddr,
        host: &str,
        path: &str,
    ) -> Result<H3Response, String> {
        if self.prepared.http3().is_none() {
            return Err("HTTP/3 is unavailable".to_string());
        }
        if self.prepared.uses_udp_associate() {
            let proxy = self
                .prepared
                .proxy_url()
                .ok_or_else(|| "missing proxy url".to_string())?;
            let proxy_addr = socks::socket_addr(proxy)
                .ok_or_else(|| format!("SOCKS5 proxy {proxy} needs an IP host"))?;
            let relay = socks::udp_associate(proxy_addr).await?;
            let gateway = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|error| error.to_string())?;
            let gateway_addr = gateway.local_addr().map_err(|error| error.to_string())?;
            let forward =
                socks::forward_quic(gateway, relay.address, host.to_string(), addr.port());
            let endpoint = self.http3_endpoint()?;
            let result = endpoint.get(gateway_addr, host, path).await;
            forward.abort();
            drop(relay);
            return result;
        }
        let endpoint = self.http3_endpoint()?;
        endpoint.get(addr, host, path).await
    }

    /// Resolve `host` with the resolver this client installed, and return the
    /// addresses that resolver produced.
    ///
    /// A delegated proxy yields no addresses and does not call the system
    /// resolver. A local SOCKS proxy returns the system lookup.
    pub fn lookup_origin(&self, host: &str) -> Vec<SocketAddr> {
        let resolving = self.resolver.resolve(host.into());
        let drive = move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("dns runtime");
            match runtime.block_on(resolving) {
                Ok(addrs) => addrs.collect(),
                Err(_) => Vec::new(),
            }
        };
        // `getaddrinfo` runs on a tokio runtime. A caller that is already on
        // one cannot start a second runtime on the same thread.
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|scope| scope.spawn(drive).join().expect("dns thread"))
        } else {
            drive()
        }
    }

    /// Names passed to the system resolver. Written only by the lookup that
    /// calls `getaddrinfo`.
    pub fn direct_queries(&self) -> Vec<String> {
        self.resolver.direct_queries()
    }

    /// Cookie store installed on this client. wreq calls [`CookieStore::cookies`]
    /// with the request's HTTP version when it builds the `Cookie` header.
    pub fn cookie_store(&self) -> &dyn CookieStore {
        self.cookies.as_ref()
    }

    /// Remember proxy credentials. A later different pair bumps the session
    /// generation when credential reuse is disabled, so the cache the handshake
    /// consults will not return the earlier session.
    pub fn proxy_credentials(&self, user: &str, password: &str) {
        if !self.prepared.proxy_credential_no_reuse() {
            return;
        }
        let key = format!("{user}:{password}");
        let mut last = self.last_credentials.lock().expect("proxy credentials");
        if last.as_ref() == Some(&key) {
            return;
        }
        if last.is_some() {
            self.generation.fetch_add(1, Ordering::Relaxed);
        }
        *last = Some(key);
    }

    /// Generation the installed session cache compares against.
    pub fn session_generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Whether a session stored at `stored` can be resumed for the current
    /// credential generation. This is the predicate the installed session
    /// cache uses in `pop`.
    pub fn session_accepts(&self, stored: u64) -> bool {
        self.sessions
            .as_ref()
            .map(|cache| cache.accepts(stored))
            .unwrap_or(true)
    }

    /// `CURLINFO_COOKIECHANGES` lines recorded by the installed cookie store.
    pub fn cookie_changes(&self) -> Vec<String> {
        self.cookies.lines()
    }

    /// `CURLINFO_REDIRECT_HISTORY` lines recorded by the installed redirect policy.
    pub fn redirect_history(&self) -> Vec<String> {
        self.redirects.lock().expect("redirect history").clone()
    }

    fn ws_builder<U: IntoUri>(&self, url: U) -> wreq::ws::WebSocketRequestBuilder {
        match &self.ws_inner {
            Some(client) => client.websocket(url),
            None => self.inner.websocket(url),
        }
    }

    fn ws_header_list(&self) -> Vec<(String, String)> {
        self.prepared
            .websocket_headers()
            .map(|headers| headers.to_vec())
            .unwrap_or_else(|| self.prepared.regular_headers().to_vec())
    }
}

/// Configuration for a [`Client`] that is fixed before the first connection.
pub struct ClientBuilder {
    profile: Profile,
    timeout: Option<Duration>,
    proxy: Option<Proxy>,
    pool_max_idle_per_host: Option<usize>,
    overrides: Overrides,
}

impl ClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn proxy_url(mut self, url: &str) -> crate::Result<Self> {
        self.proxy = Some(Proxy::all(url)?);
        self.overrides.proxy_url = Some(url.to_string());
        Ok(self)
    }

    /// Merge a request header. An empty value removes a preset header of the same name.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.overrides.headers.push((name.into(), value.into()));
        self
    }

    /// Install (`true`) or drop (`false`) the preset's base headers.
    pub fn base_headers(mut self, install: bool) -> Self {
        self.overrides.base_headers = Some(install);
        self
    }

    /// Comma-separated normal header order.
    pub fn header_order(mut self, order: impl Into<String>) -> Self {
        self.overrides.header_order = Some(order.into());
        self
    }

    pub fn http2_initial_window_size(mut self, size: u32) -> Self {
        self.overrides.http2_initial_window_size = Some(size);
        self
    }

    pub fn http2_settings(mut self, spec: impl Into<String>) -> Self {
        self.overrides.http2_settings = Some(spec.into());
        self
    }

    pub fn http2_window_update(mut self, size: u32) -> Self {
        self.overrides.http2_window_update = Some(size);
        self
    }

    pub fn http2_streams(mut self, streams: u32) -> Self {
        self.overrides.http2_streams = Some(streams);
        self
    }

    pub fn http2_no_priority(mut self, disabled: bool) -> Self {
        self.overrides.http2_no_priority = Some(disabled);
        self
    }

    pub fn http2_pseudo_order(mut self, order: impl Into<String>) -> Self {
        self.overrides.http2_pseudo_order = Some(order.into());
        self
    }

    /// `0` or `1`. Any other value fails in [`Self::build`].
    pub fn stream_exclusive(mut self, value: i64) -> Self {
        self.overrides.stream_exclusive = Some(value);
        self
    }

    pub fn target_name(mut self, name: impl Into<String>) -> Self {
        self.overrides.name = Some(name.into());
        self
    }

    pub fn sigalgs(mut self, list: impl Into<String>) -> Self {
        self.overrides.sigalgs = Some(list.into());
        self
    }

    pub fn enable_alps(mut self, enabled: bool) -> Self {
        self.overrides.enable_alps = Some(enabled);
        self
    }

    pub fn new_alps_codepoint(mut self, enabled: bool) -> Self {
        self.overrides.new_alps_codepoint = Some(enabled);
        self
    }

    pub fn cert_compression(mut self, spec: impl Into<String>) -> Self {
        self.overrides.cert_compression = Some(spec.into());
        self
    }

    pub fn session_ticket(mut self, enabled: bool) -> Self {
        self.overrides.session_ticket = Some(enabled);
        self
    }

    pub fn permute_extensions(mut self, enabled: bool) -> Self {
        self.overrides.permute_extensions = Some(enabled);
        self
    }

    pub fn grease(mut self, enabled: bool) -> Self {
        self.overrides.grease = Some(enabled);
        self
    }

    pub fn extension_order(mut self, spec: impl Into<String>) -> Self {
        self.overrides.extension_order = Some(spec.into());
        self
    }

    pub fn key_usage_no_check(mut self, enabled: bool) -> Self {
        self.overrides.key_usage_no_check = Some(enabled);
        self
    }

    pub fn signed_cert_timestamps(mut self, enabled: bool) -> Self {
        self.overrides.signed_cert_timestamps = Some(enabled);
        self
    }

    pub fn status_request(mut self, enabled: bool) -> Self {
        self.overrides.status_request = Some(enabled);
        self
    }

    pub fn delegated_credentials(mut self, spec: impl Into<String>) -> Self {
        self.overrides.delegated_credentials = Some(spec.into());
        self
    }

    /// Comma-separated relative OIDs. An empty string advertises the extension.
    pub fn trust_anchors(mut self, spec: impl Into<String>) -> Self {
        self.overrides.trust_anchors = Some(spec.into());
        self
    }

    /// `0` is passed through. It does not clear the extension.
    pub fn record_size_limit(mut self, limit: u16) -> Self {
        self.overrides.record_size_limit = Some(limit);
        self
    }

    pub fn key_shares_limit(mut self, limit: usize) -> Self {
        self.overrides.key_shares_limit = Some(limit);
        self
    }

    pub fn http3_pseudo_order(mut self, order: impl Into<String>) -> Self {
        self.overrides.http3_pseudo_order = Some(order.into());
        self
    }

    pub fn http3_settings(mut self, spec: impl Into<String>) -> Self {
        self.overrides.http3_settings = Some(spec.into());
        self
    }

    pub fn http3_curves(mut self, curves: impl Into<String>) -> Self {
        self.overrides.http3_curves = Some(curves.into());
        self
    }

    pub fn http3_sigalgs(mut self, list: impl Into<String>) -> Self {
        self.overrides.http3_sigalgs = Some(list.into());
        self
    }

    pub fn http3_extension_order(mut self, spec: impl Into<String>) -> Self {
        self.overrides.http3_extension_order = Some(spec.into());
        self
    }

    pub fn http3_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.overrides
            .http3_headers
            .get_or_insert_with(Vec::new)
            .push((name.into(), value.into()));
        self
    }

    pub fn http3_header_order(mut self, order: impl Into<String>) -> Self {
        self.overrides.http3_header_order = Some(order.into());
        self
    }

    pub fn quic_cid(mut self, profile: impl Into<String>) -> Self {
        self.overrides.quic_cid = Some(profile.into());
        self
    }

    pub fn initial_packet_number(mut self, value: i64) -> Self {
        self.overrides.initial_packet_number = Some(value);
        self
    }

    pub fn quic_transport_parameters(mut self, spec: impl Into<String>) -> Self {
        self.overrides.quic_transport_parameters = Some(spec.into());
        self
    }

    /// `webkit` or `firefox`.
    pub fn form_boundary(mut self, style: impl Into<String>) -> Self {
        self.overrides.form_boundary = Some(style.into());
        self
    }

    pub fn split_cookies(mut self, enabled: bool) -> Self {
        self.overrides.split_cookies = Some(enabled);
        self
    }

    pub fn ws_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.overrides
            .websocket_headers
            .get_or_insert_with(Vec::new)
            .push((name.into(), value.into()));
        self
    }

    pub fn ws_header_order(mut self, order: impl Into<String>) -> Self {
        self.overrides.websocket_header_order = Some(order.into());
        self
    }

    pub fn ws_disable_ticket(mut self, disabled: bool) -> Self {
        self.overrides.websocket_disable_ticket = Some(disabled);
        self
    }

    pub fn ws_cert_compression(mut self, spec: impl Into<String>) -> Self {
        self.overrides.websocket_cert_compression = Some(spec.into());
        self
    }

    pub fn proxy_credential_no_reuse(mut self, enabled: bool) -> Self {
        self.overrides.proxy_credential_no_reuse = enabled;
        self
    }

    /// Follow redirects. `true` also rejects a redirected connection whose
    /// address is loopback, private, or link-local. The initial URL is not
    /// filtered.
    pub fn follow_safe(mut self, safe: bool) -> Self {
        self.overrides.follow_safe = Some(safe);
        self
    }

    /// Force HTTP/1.1 instead of letting the profile negotiate HTTP/2.
    ///
    /// Embedded HTTP/1.1-only fingerprints (Python `requests`, Node's `https`
    /// module, the JDK's `HttpsURLConnection`) set this themselves.
    pub fn http1_only(mut self, enabled: bool) -> Self {
        self.overrides.http1_only = Some(enabled);
        self
    }

    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.pool_max_idle_per_host = Some(max);
        self
    }

    pub fn build(self) -> crate::Result<Client> {
        let prepared = Prepared::prepare(self.profile, &self.overrides).map_err(arg_error)?;
        let resolver = Arc::new(PolicyResolver::new(
            policy::delegates_origin_dns(prepared.proxy_url()),
            proxy_host(prepared.proxy_url()),
        ));
        let generation = Arc::new(AtomicU64::new(1));
        let cookies = Arc::new(ChangeLog::new(prepared.splits_cookies()));
        let redirects = Arc::new(Mutex::new(Vec::new()));

        let emulation = prepared.emulation().clone();
        // When the emulated client sends no accept-encoding, the decompression
        // layer must not add one behind its back. The emulation's headers only
        // replace the header when it is present, so disable the layer entirely.
        let advertises_encoding = emulation
            .headers
            .contains_key(wreq::header::ACCEPT_ENCODING);
        let mut builder = WreqClient::builder()
            .emulation(emulation)
            .dns_resolver(Arc::clone(&resolver))
            .cookie_provider(Arc::clone(&cookies));
        if !advertises_encoding {
            builder = builder.no_gzip().no_brotli().no_zstd().no_deflate();
        }
        if prepared.http1_only() {
            builder = builder.http1_only();
        }
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(proxy) = self.proxy {
            builder = builder.proxy(proxy);
        }
        let mut idle = self.pool_max_idle_per_host;
        let sessions = if prepared.proxy_credential_no_reuse() {
            idle = Some(0);
            let cache = Arc::new(IsolatingSessionCache::new(Arc::clone(&generation)));
            builder = builder.tls_session_cache(Arc::clone(&cache));
            Some(cache)
        } else {
            None
        };
        if let Some(max) = idle {
            builder = builder.pool_max_idle_per_host(max);
        }
        if prepared.follow_safe().is_some() {
            let log = Arc::clone(&redirects);
            let safe = prepared.follow_safe() == Some(true);
            builder = builder.redirect(wreq::redirect::Policy::custom(move |attempt| {
                if let Some(previous) = attempt.previous.last() {
                    log.lock()
                        .expect("redirect history")
                        .push(policy::redirect_history_line(
                            attempt.status.as_u16(),
                            &previous.to_string(),
                        ));
                }
                if attempt.previous.len() > 10 {
                    return attempt.error("too many redirects");
                }
                if safe && redirect_target_blocked(&attempt.uri) {
                    return attempt.error("redirect address is blocked");
                }
                attempt.follow()
            }));
        }

        let ws_inner = match prepared.websocket_emulation() {
            Some(emulation) => Some(WreqClient::builder().emulation(emulation.clone()).build()?),
            None => None,
        };

        Ok(Client {
            inner: builder.build()?,
            ws_inner,
            profile: self.profile,
            prepared,
            resolver,
            sessions,
            generation,
            last_credentials: Mutex::new(None),
            cookies,
            redirects,
        })
    }
}

/// Host the connector resolves before it can open the proxy connection.
///
/// Brackets around an IPv6 address are removed so the name matches the one
/// `HttpConnector` passes to the resolver.
fn proxy_host(url: Option<&str>) -> Option<String> {
    let uri = wreq::Uri::try_from(url?).ok()?;
    let host = uri.host()?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    Some(host.to_string())
}

fn arg_error(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> crate::Error {
    wreq::Error::builder(error)
}

fn redirect_target_blocked(uri: &wreq::Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return policy::redirect_address_blocked(ip);
    }
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        });
    match (host, port).to_socket_addrs() {
        Ok(addresses) => addresses
            .map(|address| address.ip())
            .any(policy::redirect_address_blocked),
        Err(_) => false,
    }
}

use std::net::ToSocketAddrs;
