//! HTTP client that sends requests with a browser's TLS and HTTP/2 fingerprint.
//!
//! The transport is [`wreq`], which links BoringSSL and exposes the ClientHello
//! fields curl-impersonate patches BoringSSL to control: cipher order, extension
//! order, GREASE, ECH grease, ALPS, delegated credentials and certificate
//! compression. [`Profile`]
//! selects which browser's settings are applied.

use std::time::Duration;

use wreq::{Client as WreqClient, IntoUri, Method, Proxy, RequestBuilder};

use crate::profile::Profile;

/// A client bound to one [`Profile`].
///
/// Every request it sends uses that profile's TLS, HTTP/2 and header settings.
/// Switching profile means building a new client: the fingerprint is fixed when
/// the backing connection pool is created.
pub struct Client {
    inner: WreqClient,
    profile: Profile,
}

impl Client {
    /// Build a client impersonating `profile`, using the default root certificates.
    pub fn new(profile: Profile) -> crate::Result<Self> {
        Self::builder(profile).build()
    }

    /// Start a builder for a client impersonating `profile`.
    pub fn builder(profile: Profile) -> ClientBuilder {
        ClientBuilder {
            profile,
            timeout: None,
            proxy: None,
            pool_max_idle_per_host: None,
        }
    }

    /// The profile this client's connections impersonate.
    pub fn profile(&self) -> Profile {
        self.profile
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

    /// Start a WebSocket upgrade using the same TLS fingerprint as HTTP requests.
    pub fn websocket<U: IntoUri>(&self, url: U) -> wreq::ws::WebSocketRequestBuilder {
        self.inner.websocket(url)
    }
}

/// Configuration for a [`Client`] that is fixed before the first connection.
pub struct ClientBuilder {
    profile: Profile,
    timeout: Option<Duration>,
    proxy: Option<Proxy>,
    pool_max_idle_per_host: Option<usize>,
}

impl ClientBuilder {
    /// Set the timeout applied to the whole request.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Route requests through a proxy.
    ///
    /// `wreq` accepts `http://`, `https://` and, with the `socks` feature, `socks5://`
    /// for TCP connections. SOCKS5 UDP associate exists only to carry QUIC, and the
    /// transport has no HTTP/3, so it is not available.
    pub fn proxy(mut self, proxy: Proxy) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Cap the number of idle connections kept per host.
    pub fn pool_max_idle_per_host(mut self, max: usize) -> Self {
        self.pool_max_idle_per_host = Some(max);
        self
    }

    pub fn build(self) -> crate::Result<Client> {
        let mut builder = WreqClient::builder().emulation(self.profile.emulation());
        if let Some(timeout) = self.timeout {
            builder = builder.timeout(timeout);
        }
        if let Some(proxy) = self.proxy {
            builder = builder.proxy(proxy);
        }
        if let Some(max) = self.pool_max_idle_per_host {
            builder = builder.pool_max_idle_per_host(max);
        }
        Ok(Client {
            inner: builder.build()?,
            profile: self.profile,
        })
    }
}
