//! HTTP/3 transport.
//!
//! curl-impersonate's HTTP/3 runs over a BoringSSL QUIC handshake. The pieces
//! that decide what a peer sees live here: the transport parameter encoding,
//! the connection id lengths and the TLS configuration taken from a preset's
//! `Http3Profile`.

mod crypto;
pub mod endpoint;
pub mod h3;
mod params;
pub mod spec;

pub use crypto::{
    initial_source_connection_id, initial_source_connection_id_from, open_client_datagram,
    open_client_initial, OpenedInitial,
};
pub use params::Rng;

/// Resolve a preset's `quic_initial_packet_number`.
///
/// `None` stays unset. `-1` is Neqo's biased range 1..=1024. Any other value is
/// that packet number. [`endpoint::H3Endpoint::bind`] records the result.
pub(crate) fn resolve_initial_packet_number(preset: Option<i64>) -> Result<Option<u32>, String> {
    let Some(value) = preset else {
        return Ok(None);
    };
    crate::policy::check_initial_packet_number(value)?;
    let mut rng = params::SystemRng;
    Ok(Some(params::initial_packet_number(value, &mut rng)))
}
