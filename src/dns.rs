//! DNS for the shipped client.
//!
//! When the proxy resolves the origin (HTTP, HTTPS, SOCKS4a, SOCKS5h) this
//! resolver does not ask the system resolver for that name. The proxy's own
//! hostname is still resolved, because the connector looks that name up on
//! this same resolver before it can open the proxy connection. A local SOCKS
//! proxy resolves every name. The names in [`PolicyResolver::direct_queries`]
//! are recorded inside the resolver that calls `getaddrinfo`.

use std::sync::{Arc, Mutex};

use wreq::dns::{Addrs, GaiResolver, Name, Resolve, Resolving};

/// Resolver the client's connector calls.
pub struct PolicyResolver {
    direct: DirectResolver,
    /// When set, origin DNS is delegated and the system resolver is not called
    /// for those names.
    delegated: bool,
    /// Host the connector must resolve in order to reach the proxy.
    proxy_host: Option<String>,
}

/// System lookup. Recording happens in the same function that calls `GaiResolver`.
struct DirectResolver {
    inner: GaiResolver,
    queries: Arc<Mutex<Vec<String>>>,
}

impl DirectResolver {
    fn new() -> Self {
        Self {
            inner: GaiResolver::default(),
            queries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn queries(&self) -> Vec<String> {
        self.queries.lock().expect("dns queries").clone()
    }
}

impl Resolve for DirectResolver {
    fn resolve(&self, name: Name) -> Resolving {
        self.queries
            .lock()
            .expect("dns queries")
            .push(name.as_str().to_string());
        self.inner.resolve(name)
    }
}

impl PolicyResolver {
    pub fn new(delegated: bool, proxy_host: Option<String>) -> Self {
        Self {
            direct: DirectResolver::new(),
            delegated,
            proxy_host,
        }
    }

    /// Names the system resolver was asked to look up.
    pub fn direct_queries(&self) -> Vec<String> {
        self.direct.queries()
    }
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let proxy_host = self
            .proxy_host
            .as_deref()
            .is_some_and(|host| host.eq_ignore_ascii_case(name.as_str()));
        if self.delegated && !proxy_host {
            let addrs: Addrs = Box::new(std::iter::empty());
            return Box::pin(std::future::ready(Ok(addrs)));
        }
        self.direct.resolve(name)
    }
}
