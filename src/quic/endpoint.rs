//! The QUIC endpoint that carries one preset's HTTP/3 fingerprint.
//!
//! quinn owns the packet layer and BoringSSL owns the handshake. This module
//! builds the endpoint so the two agree: the connection id lengths come from
//! the preset, the transport parameters are encoded with the source connection
//! id they embed, and the flow control values quinn enforces are copied onto
//! its transport config so the peer sees the same limits the handshake
//! advertised.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use bytes::BytesMut;
use quinn::crypto::HmacKey;
use quinn::{
    Connection, ConnectionIdGenerator, Endpoint, EndpointConfig, TokioRuntime, TransportConfig,
};
use quinn_proto::crypto::CryptoError;
use quinn_proto::ConnectionId;

use crate::cookies;
use crate::policy::{self, CookieProtocol};
use crate::profile::{H3Setting, Http3Profile};

use super::crypto::BoringClientConfig;
use super::h3::{self, Frame};
use super::params::{self, EncodedParams, Rng, SystemRng};
use super::spec::QuicTls;

/// Caller overrides that the QUIC handshake and the HTTP/3 send path read.
pub struct H3Bind {
    /// ClientHello inputs. `bind_with` passes this `Arc` to BoringSSL.
    pub tls: Arc<QuicTls>,
    /// Transport-parameter text. `None` keeps the profile's text.
    pub transport_parameters: Option<String>,
    /// Connection-id profile. `None` keeps the profile's profile.
    pub cid_profile: Option<String>,
    /// HTTP/3 SETTINGS. `None` keeps the profile's list.
    pub settings: Option<Vec<H3Setting>>,
    /// Pseudo-header letters. `None` keeps the profile's order.
    pub pseudo_order: Option<String>,
    /// `CURLOPT_HTTP3_HTTPHEADER`. Replaces merged defaults for HTTP/3 only.
    pub http3_header_override: Option<Vec<(String, String)>>,
    /// Regular headers used when HTTP/3 has no separate list.
    pub regular_headers: Vec<(String, String)>,
    /// `CURLOPT_HTTP3_HTTPHEADER_ORDER`.
    pub header_order: Option<String>,
    /// Preset `split_cookies` flag. HTTP/3 splits when this is set.
    pub split_cookies: bool,
}

/// A QUIC endpoint configured for one browser preset.
pub struct H3Endpoint {
    endpoint: Endpoint,
    profile: Http3Profile,
    /// The `Arc` inside the BoringSSL config this endpoint's handshake uses.
    tls: Arc<QuicTls>,
    /// Packet number on the first Initial.
    ///
    /// [`crate::Client`] passes the value from preparation, so a Neqo `-1`
    /// policy is not rolled a second time. `None` leaves quinn's default of 0.
    initial_packet_number: Option<u32>,
    /// Destination and source connection-id lengths taken from the preset.
    connection_id_lengths: (usize, usize),
    settings: Option<Vec<H3Setting>>,
    pseudo_order: Option<String>,
    http3_header_override: Option<Vec<(String, String)>>,
    regular_headers: Vec<(String, String)>,
    header_order: Option<String>,
    split_cookies: bool,
    /// Transport-parameter bytes passed to the BoringSSL config.
    transport_parameter_bytes: Vec<u8>,
    transport_parameters: String,
}

impl H3Endpoint {
    /// Bind a UDP socket and configure it for `profile`.
    ///
    /// The first Initial's Source Connection ID is whatever quinn's generator
    /// returns for that connection. [`super::crypto`] copies those bytes into
    /// transport parameter `0x0f` inside `start_session`, including `15:AUTO`.
    pub fn bind(profile: &Http3Profile) -> Result<Self, String> {
        let initial_packet_number =
            super::resolve_initial_packet_number(profile.initial_packet_number)?;
        let bind = H3Bind {
            tls: QuicTls::from_profile(profile, true).shared(),
            transport_parameters: None,
            cid_profile: None,
            settings: None,
            pseudo_order: None,
            http3_header_override: None,
            regular_headers: Vec::new(),
            header_order: None,
            split_cookies: true,
        };
        Self::bind_with(profile, initial_packet_number, bind)
    }

    /// Bind using a packet number the caller already resolved.
    ///
    /// [`crate::Client`] passes the value from its preparation path so a Neqo
    /// `-1` policy is not rolled a second time. `bind.tls` is the `Arc` the
    /// BoringSSL configuration stores.
    pub fn bind_with(
        profile: &Http3Profile,
        initial_packet_number: Option<u32>,
        bind: H3Bind,
    ) -> Result<Self, String> {
        let mut rng = SystemRng;
        let transport_parameters = bind
            .transport_parameters
            .clone()
            .unwrap_or_else(|| profile.transport_parameters.to_string());
        let cid_profile = bind.cid_profile.as_deref().or(profile.cid_profile);
        let (dst_len, src_len) =
            params::connection_id_lengths(cid_profile, &transport_parameters, &mut rng);

        // Seed `0x0f` with one CID of the preset's length. `start_session`
        // then overwrites that parameter with the Source Connection ID quinn
        // puts on this connection's Initial, so the two stay the same bytes.
        let mut source_bytes = vec![0u8; src_len];
        rng.fill(&mut source_bytes);
        let encoded = params::encode(&transport_parameters, &source_bytes, &mut rng)
            .map_err(|error| format!("transport parameters: {error:?}"))?;

        let crypto = BoringClientConfig::new(Arc::clone(&bind.tls), encoded.bytes.clone())?;
        let tls = crypto.tls_handle();
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(transport_config(&encoded, initial_packet_number)));
        client_config.initial_dst_cid_provider(Arc::new(move || {
            let mut bytes = vec![0u8; dst_len];
            SystemRng.fill(&mut bytes);
            ConnectionId::new(&bytes)
        }));

        // Bind to the address the caller asks for. `0.0.0.0` is wrong on a host
        // whose policy routing diverts unbound sockets onto a tunnel, so the
        // default is the interface that carries the default route.
        let bind_addr = std::env::var("H3_BIND").unwrap_or_else(|_| "0.0.0.0:0".to_string());
        let socket = UdpSocket::bind(&bind_addr).map_err(|error| error.to_string())?;
        let mut endpoint_config = EndpointConfig::new(Arc::new(BoringHmacKey::random()));
        let first_source = ConnectionId::new(&source_bytes);
        endpoint_config.cid_generator(move || {
            Box::new(PresetCidGenerator {
                len: src_len,
                first: Some(first_source),
            })
        });
        let mut endpoint = Endpoint::new(endpoint_config, None, socket, Arc::new(TokioRuntime))
            .map_err(|error| error.to_string())?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            profile: *profile,
            tls,
            initial_packet_number,
            connection_id_lengths: (dst_len, src_len),
            settings: bind.settings,
            pseudo_order: bind.pseudo_order,
            http3_header_override: bind.http3_header_override,
            regular_headers: bind.regular_headers,
            header_order: bind.header_order,
            split_cookies: bind.split_cookies,
            transport_parameter_bytes: encoded.bytes,
            transport_parameters,
        })
    }

    /// The preset this endpoint was bound with.
    pub fn profile(&self) -> &Http3Profile {
        &self.profile
    }

    /// The preset's initial packet number, after the Neqo `-1` policy is applied.
    pub fn initial_packet_number(&self) -> Option<u32> {
        self.initial_packet_number
    }

    /// Destination and source connection-id lengths for this preset.
    pub fn connection_id_lengths(&self) -> (usize, usize) {
        self.connection_id_lengths
    }

    /// ClientHello inputs the handshake configured. This is the `Arc` stored
    /// on the BoringSSL config, not a side copy.
    pub fn quic_tls(&self) -> &QuicTls {
        &self.tls
    }

    /// HTTP/3 SETTINGS the preface writes.
    pub fn settings_for_send(&self) -> &[H3Setting] {
        self.settings.as_deref().unwrap_or(self.profile.settings)
    }

    /// Transport-parameter text encoded into the handshake.
    pub fn transport_parameters(&self) -> &str {
        &self.transport_parameters
    }

    /// Encoded transport parameters passed to the BoringSSL config.
    pub fn transport_parameter_bytes(&self) -> &[u8] {
        &self.transport_parameter_bytes
    }

    /// Header fields `request` writes, including an optional cookie line.
    pub fn assemble_headers(
        &self,
        host: &str,
        path: &str,
        cookies: Option<&str>,
    ) -> Vec<(String, String)> {
        request_headers(self, host, path, cookies)
    }

    /// Open one request and read the response headers and body.
    pub async fn get(
        &self,
        addr: SocketAddr,
        host: &str,
        path: &str,
    ) -> Result<H3Response, String> {
        let connection = self
            .endpoint
            .connect(addr, host)
            .map_err(|error| error.to_string())?
            .await
            .map_err(|error| format!("connect: {error:?}"))?;
        send_preface(&connection, self.settings_for_send()).await?;
        let incoming = connection.clone();
        let control_seen = tokio::spawn(async move { drain_incoming(incoming).await });
        // The server's SETTINGS must arrive before the request. Sending first
        // makes the server reset the request stream.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), control_seen).await;
        request(self, &connection, host, path, None).await
    }
}

/// The headers and body of one HTTP/3 response.
pub struct H3Response {
    /// Response header fields, in the order they arrived.
    pub headers: Vec<(String, String)>,
    /// The concatenated DATA frame payloads.
    pub body: Vec<u8>,
}

/// Send the control stream and the two QPACK streams a client must open first.
async fn send_preface(connection: &Connection, settings: &[H3Setting]) -> Result<(), String> {
    let mut rng = SystemRng;
    let control = h3::control_preface(settings, &mut rng);
    write_uni(connection, &control).await?;
    write_uni(connection, &h3::encoder_preface()).await?;
    write_uni(connection, &h3::decoder_preface()).await?;
    Ok(())
}

/// Read the unidirectional streams the server opens so their data is
/// acknowledged. A server's control stream left unread stalls the connection.
async fn drain_incoming(connection: Connection) {
    let mut log = String::new();
    loop {
        match connection.accept_uni().await {
            Ok(mut stream) => {
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).await.unwrap_or(None).unwrap_or(0);
                log.push_str(&format!("uni {} bytes: {:02x?}\n", n, &buf[..n]));
                let _ = std::fs::write("/tmp/uni.txt", &log);
                // The control stream is type 0x00. Once it is in, the request can
                // be sent; keep draining the rest in the background.
                if n > 0 && buf[0] == 0x00 {
                    tokio::spawn(async move { drain_rest(connection).await });
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

async fn drain_rest(connection: Connection) {
    while let Ok(mut stream) = connection.accept_uni().await {
        let mut buf = [0u8; 64];
        let _ = stream.read(&mut buf).await;
    }
}

async fn write_uni(connection: &Connection, bytes: &[u8]) -> Result<(), String> {
    let mut stream = connection
        .open_uni()
        .await
        .map_err(|error| format!("open uni: {error:?}"))?;
    stream
        .write_all(bytes)
        .await
        .map_err(|error| format!("write uni: {error:?}"))?;
    stream
        .finish()
        .map_err(|error| format!("finish uni: {error:?}"))?;
    Ok(())
}

/// Send one GET and collect the response.
async fn request(
    endpoint: &H3Endpoint,
    connection: &Connection,
    host: &str,
    path: &str,
    cookies: Option<&str>,
) -> Result<H3Response, String> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| format!("open bi: {error:?}"))?;
    let owned = request_headers(endpoint, host, path, cookies);
    let headers: Vec<(&str, &str)> = owned
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let frame = h3::headers_frame(&headers);
    send.write_all(&frame)
        .await
        .map_err(|error| format!("write request: {error:?}"))?;
    send.finish()
        .map_err(|error| format!("finish request: {error:?}"))?;

    let mut buf = BytesMut::new();
    let mut headers = None;
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = recv
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read response: {error:?}"))?;
        let _ = std::fs::write("/tmp/recv.txt", format!("read {read:?}\n"));
        match read {
            Some(n) => buf.extend_from_slice(&chunk[..n]),
            None => break,
        }
        while let Some(frame) = h3::decode_frame(&mut buf) {
            match frame {
                Frame::Headers(payload) => {
                    headers =
                        Some(h3::decode_headers(&payload).map_err(|error| error.to_string())?);
                }
                Frame::Data(payload) => body.extend_from_slice(&payload),
                Frame::Other => {}
            }
        }
    }
    Ok(H3Response {
        headers: headers.ok_or_else(|| "response had no headers".to_string())?,
        body,
    })
}

/// The pseudo-headers in the preset's order, followed by the headers selected
/// for a negotiated HTTP/3 connection.
fn request_headers(
    endpoint: &H3Endpoint,
    host: &str,
    path: &str,
    cookies: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    let order = endpoint
        .pseudo_order
        .as_deref()
        .unwrap_or(endpoint.profile.pseudo_order);
    for letter in order.chars() {
        let (name, value) = match letter {
            'm' => (":method", "GET".to_string()),
            'a' => (":authority", host.to_string()),
            's' => (":scheme", "https".to_string()),
            'p' => (":path", path.to_string()),
            _ => continue,
        };
        headers.push((name.to_string(), value));
    }
    let mut fields = policy::negotiated_headers(
        true,
        endpoint.http3_header_override.as_deref(),
        Some(endpoint.profile.headers),
        &endpoint.regular_headers,
    );
    if let Some(order) = endpoint.header_order.as_deref() {
        fields = policy::order_headers(&fields, order);
    }
    // HTTP/3 field names are lowercase. curl-impersonate stores them in the
    // preset's original capitalisation and nghttp3 lowercases them on output, so
    // the same is done here. A capital letter in a name is a message error.
    headers.extend(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value)),
    );
    if let Some(raw) = cookies {
        let split = policy::split_for(CookieProtocol::Http3, endpoint.split_cookies);
        for value in cookies::cookie_headers(raw, split) {
            headers.push(("cookie".to_string(), value));
        }
    }
    headers
}

/// The transport config quinn enforces, mirroring the preset's parameters.
fn transport_config(
    encoded: &EncodedParams,
    initial_packet_number: Option<u32>,
) -> TransportConfig {
    let mut config = TransportConfig::default();
    params::apply_flow_control(encoded, &mut config);
    if let Some(number) = initial_packet_number {
        config.initial_packet_number(u64::from(number));
    }
    config
}

/// Connection ids of one length, with a pinned first value.
///
/// The first id is the Source Connection ID of the first Initial and the value
/// encoded into transport parameter `0x0f`. Later ids are random, so a second
/// connection does not collide with the first in quinn's CID map.
struct PresetCidGenerator {
    len: usize,
    first: Option<ConnectionId>,
}

impl ConnectionIdGenerator for PresetCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        if let Some(cid) = self.first.take() {
            return cid;
        }
        let mut bytes = vec![0u8; self.len];
        SystemRng.fill(&mut bytes);
        ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        self.len
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}

/// The stateless reset key, HMAC-SHA256 over BoringSSL.
struct BoringHmacKey {
    key: [u8; 32],
}

impl BoringHmacKey {
    fn random() -> Self {
        let mut key = [0u8; 32];
        SystemRng.fill(&mut key);
        Self { key }
    }
}

impl HmacKey for BoringHmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let signature = btls::hash::hmac_sha256(&self.key, data).expect("hmac-sha256");
        signature_out[..signature.len()].copy_from_slice(&signature);
    }

    fn signature_len(&self) -> usize {
        32
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut computed = [0u8; 32];
        self.sign(data, &mut computed);
        if computed == signature {
            Ok(())
        } else {
            Err(CryptoError)
        }
    }
}
