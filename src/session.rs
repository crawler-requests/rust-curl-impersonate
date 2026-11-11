//! TLS session cache that refuses to resume across proxy credentials.
//!
//! `CURLOPT_PROXY_CREDENTIAL_NO_REUSE` bumps a generation. The cache the
//! handshake consults returns a session only when [`crate::policy::reuse_session`]
//! says the stored generation is still current.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use wreq::tls::session::{Key, TlsSession, TlsSessionCache};

use crate::policy;

/// Cache installed on the client when credential isolation is requested.
pub struct IsolatingSessionCache {
    generation: Arc<AtomicU64>,
    sessions: Mutex<HashMap<Key, Vec<(u64, TlsSession)>>>,
}

impl IsolatingSessionCache {
    pub fn new(generation: Arc<AtomicU64>) -> Self {
        Self {
            generation,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Whether a session stored at `stored` can be used for the generation the
    /// next handshake will ask for.
    pub fn accepts(&self, stored: u64) -> bool {
        policy::reuse_session(stored, self.generation.load(Ordering::Relaxed), true)
    }
}

impl TlsSessionCache for IsolatingSessionCache {
    fn put(&self, key: Key, session: TlsSession) {
        let generation = self.generation.load(Ordering::Relaxed);
        self.sessions
            .lock()
            .expect("session cache")
            .entry(key)
            .or_default()
            .push((generation, session));
    }

    fn pop(&self, key: &Key) -> Option<TlsSession> {
        let current = self.generation.load(Ordering::Relaxed);
        let mut sessions = self.sessions.lock().expect("session cache");
        let stored = sessions.get_mut(key)?;
        let position = stored
            .iter()
            .rposition(|(generation, _)| policy::reuse_session(*generation, current, true))?;
        Some(stored.remove(position).1)
    }
}
