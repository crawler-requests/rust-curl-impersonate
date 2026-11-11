//! SOCKS5 UDP ASSOCIATE framing (RFC 1928).
//!
//! HTTP/3 needs UDP. A SOCKS5 proxy carries that with UDP ASSOCIATE (command
//! `0x03`), not with TCP CONNECT. quinn has no associate client, so the request
//! bytes and the choice live here and the HTTP/3 path calls them.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How a proxy URL is applied to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksChoice {
    /// No SOCKS proxy.
    Direct,
    /// SOCKS5 TCP CONNECT, used for HTTP/1.1 and HTTP/2.
    TcpConnect,
    /// SOCKS5 UDP ASSOCIATE, used when the request is HTTP/3.
    UdpAssociate,
}

/// Pick TCP CONNECT or UDP ASSOCIATE for a proxy URL.
///
/// Only `socks5://` and `socks5h://` are SOCKS. HTTP proxies stay [`SocksChoice::Direct`]
/// because `wreq` dials those itself. HTTP/3 over SOCKS5 is UDP ASSOCIATE.
pub fn select(proxy_url: Option<&str>, http3: bool) -> SocksChoice {
    let Some(url) = proxy_url else {
        return SocksChoice::Direct;
    };
    let socks = url.starts_with("socks5://") || url.starts_with("socks5h://");
    if !socks {
        return SocksChoice::Direct;
    }
    if http3 {
        SocksChoice::UdpAssociate
    } else {
        SocksChoice::TcpConnect
    }
}

/// A UDP ASSOCIATE request that asks the proxy to choose the relay address.
///
/// Layout: VER, CMD `0x03`, RSV, ATYP IPv4, `0.0.0.0`, port 0.
pub fn udp_associate_request() -> Vec<u8> {
    vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// A UDP request header plus `payload`, addressed at a domain name.
pub fn udp_datagram(host: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let host_bytes = host.as_bytes();
    let mut out = Vec::with_capacity(4 + 1 + host_bytes.len() + 2 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x03, host_bytes.len() as u8]);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The socket address of a `socks5://` or `socks5h://` URL with an IP host.
pub fn socket_addr(url: &str) -> Option<SocketAddr> {
    let rest = url
        .strip_prefix("socks5://")
        .or_else(|| url.strip_prefix("socks5h://"))?;
    let hostport = rest.split('/').next()?.rsplit('@').next()?;
    hostport.parse().ok()
}

/// A finished UDP ASSOCIATE handshake.
///
/// The TCP control connection stays open for the life of this value. RFC 1928
/// drops the association when that connection closes.
pub struct Relay {
    /// Address the client sends UDP datagrams to.
    pub address: SocketAddr,
    _control: TcpStream,
}

/// Wrap QUIC datagrams from `gateway` and deliver them to the SOCKS relay.
///
/// Packets that arrive from the local QUIC stack are prefixed with
/// [`udp_datagram`] and sent to `relay`. Packets from the relay are unwrapped
/// and written back to the QUIC stack.
pub fn forward_quic(
    gateway: tokio::net::UdpSocket,
    relay: SocketAddr,
    host: String,
    port: u16,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut peer = None;
        loop {
            let (n, src) = match gateway.recv_from(&mut buf).await {
                Ok(value) => value,
                Err(_) => return,
            };
            if src == relay {
                if let (Some(peer), Some(payload)) = (peer, strip_udp(&buf[..n])) {
                    let _ = gateway.send_to(payload, peer).await;
                }
            } else {
                peer = Some(src);
                let packet = udp_datagram(&host, port, &buf[..n]);
                let _ = gateway.send_to(&packet, relay).await;
            }
        }
    })
}

fn strip_udp(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return None;
    }
    let rest = &packet[4..];
    match packet[3] {
        0x01 => rest.get(6..),
        0x04 => rest.get(18..),
        0x03 => {
            let len = *rest.first()? as usize;
            rest.get(1 + len + 2..)
        }
        _ => None,
    }
}

/// Open a TCP connection and complete a no-auth UDP ASSOCIATE handshake.
///
/// The bytes written are the greeting `05 01 00` and [`udp_associate_request`].
pub async fn udp_associate(proxy: SocketAddr) -> Result<Relay, String> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|error| error.to_string())?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|error| error.to_string())?;
    if greeting != [0x05, 0x00] {
        return Err(format!("socks greeting {greeting:?}"));
    }
    let request = udp_associate_request();
    stream
        .write_all(&request)
        .await
        .map_err(|error| error.to_string())?;
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    if header[1] != 0x00 {
        return Err(format!("socks associate failed with status {}", header[1]));
    }
    let address = read_addr(&mut stream, header[3]).await?;
    Ok(Relay {
        address,
        _control: stream,
    })
}

async fn read_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr, String> {
    match atyp {
        0x01 => {
            let mut body = [0u8; 6];
            stream
                .read_exact(&mut body)
                .await
                .map_err(|error| error.to_string())?;
            let ip = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[4], body[5]]);
            Ok(SocketAddr::from((ip, port)))
        }
        0x04 => {
            let mut body = [0u8; 18];
            stream
                .read_exact(&mut body)
                .await
                .map_err(|error| error.to_string())?;
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&body[..16]).unwrap());
            let port = u16::from_be_bytes([body[16], body[17]]);
            Ok(SocketAddr::from((ip, port)))
        }
        other => Err(format!("unsupported socks address type {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http3_socks5_selects_udp_associate() {
        assert_eq!(
            select(Some("socks5://127.0.0.1:1080"), true),
            SocksChoice::UdpAssociate
        );
        assert_eq!(
            select(Some("socks5://127.0.0.1:1080"), false),
            SocksChoice::TcpConnect
        );
        assert_eq!(
            select(Some("http://127.0.0.1:8080"), true),
            SocksChoice::Direct
        );
    }

    #[test]
    fn associate_request_is_command_three() {
        let request = udp_associate_request();
        assert_eq!(&request[..4], &[0x05, 0x03, 0x00, 0x01]);
        assert_eq!(request.len(), 10);
    }

    #[test]
    fn datagram_carries_the_payload_after_the_header() {
        let packet = udp_datagram("example.com", 443, b"quic");
        assert_eq!(&packet[..4], &[0x00, 0x00, 0x00, 0x03]);
        assert_eq!(packet[4], b"example.com".len() as u8);
        assert!(packet.ends_with(b"quic"));
    }
}
