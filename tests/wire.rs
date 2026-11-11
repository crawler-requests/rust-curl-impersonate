//! Wire options the public client applies for a preset.
//!
//! These tests build [`Client`] and, for HTTP/3, the endpoint that
//! [`Client::http3_get`] binds. They do not reimplement the preparation path.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rust_curl_impersonate::profile::{self, http3};
use rust_curl_impersonate::quic::endpoint::H3Endpoint;
use rust_curl_impersonate::quic::{
    initial_source_connection_id_from, open_client_datagram, OpenedInitial,
};
use rust_curl_impersonate::{Client, Method, Profile};
use wreq::header;
use wreq::http2::PseudoId;

fn client(target: &str) -> Client {
    Client::new(Profile::find(target).unwrap()).unwrap()
}

#[tokio::test]
async fn chrome150_keeps_tls_and_leaves_http2_pseudo_order_unset() {
    let client = client("chrome150");
    let profile = Profile::find("chrome150").unwrap();
    let preset_ciphers = profile
        .emulation()
        .tls_options
        .unwrap()
        .cipher_list
        .unwrap();

    assert_eq!(
        client.prepared().cipher_list(),
        Some(preset_ciphers.as_ref())
    );
    assert!(client
        .prepared()
        .cipher_list()
        .unwrap()
        .contains("TLS_AES_128_GCM_SHA256"));
    assert!(client.prepared().pseudo_order().is_none());
    assert!(client.prepared().deviation().unwrap().contains("mldsa44"));
    assert!(!client
        .prepared()
        .emulation()
        .tls_options
        .as_ref()
        .unwrap()
        .sigalgs_list
        .as_deref()
        .unwrap()
        .contains("mldsa"));

    let preset = http3("chrome150").unwrap();
    assert_eq!(client.prepared().http3(), Some(&preset));
    assert_eq!(client.prepared().initial_packet_number(), Some(1));

    let endpoint = client.http3_endpoint().unwrap();
    assert_eq!(endpoint.profile(), &preset);
    assert_eq!(endpoint.initial_packet_number(), Some(1));
    assert_eq!(endpoint.connection_id_lengths(), (8, 0));
    assert_eq!(endpoint.profile().settings, preset.settings);
    assert_eq!(
        endpoint.profile().transport_parameters,
        preset.transport_parameters
    );

    let bound = H3Endpoint::bind(&preset).unwrap();
    assert_eq!(bound.initial_packet_number(), Some(1));
    assert_eq!(bound.profile().settings, preset.settings);

    let request = client
        .request_cookies(Method::GET, "https://example.com", "a=1; b=2")
        .build()
        .unwrap();
    let cookies: Vec<_> = request
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    assert_eq!(cookies, ["a=1", "b=2"]);

    let boundary = client.multipart().unwrap().boundary().to_string();
    assert!(boundary.starts_with("------WebKitFormBoundary"));
    assert_eq!(boundary.len(), "------WebKitFormBoundary".len() + 16);
    assert!(boundary
        .chars()
        .skip("------WebKitFormBoundary".len())
        .all(|c| c.is_ascii_alphanumeric()));

    assert_eq!(
        client.websocket_deflate("wss://example.com").extensions(),
        "permessage-deflate; client_max_window_bits"
    );
}

#[test]
fn firefox133_splits_cookies_and_uses_its_pseudo_order() {
    let client = client("firefox133");
    // The preset's `mpas` order is the prefix. wreq's PseudoOrder builder
    // appends the pseudo ids the preset did not name, which is how generated.rs
    // already builds the value that goes on the wire.
    assert_eq!(
        client.prepared().pseudo_order().unwrap(),
        vec![
            PseudoId::Method,
            PseudoId::Path,
            PseudoId::Authority,
            PseudoId::Scheme,
            PseudoId::Protocol,
            PseudoId::Status,
        ]
    );
    assert!(client.prepared().http3().is_none());
    assert!(client.prepared().initial_packet_number().is_none());

    let boundary = client.multipart().unwrap().boundary().to_string();
    assert!(boundary.starts_with("------geckoformboundary"));
    assert_eq!(boundary.len(), "------geckoformboundary".len() + 32);
    assert!(boundary
        .chars()
        .skip("------geckoformboundary".len())
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    let request = client
        .request_cookies(Method::GET, "https://example.com", "a=1; b=2")
        .build()
        .unwrap();
    let cookies: Vec<_> = request
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_string())
        .collect();
    assert_eq!(cookies, ["a=1", "b=2"]);
}

#[test]
fn okhttp_does_not_invent_a_form_boundary() {
    let client = client("okhttp4_android");
    assert!(client.multipart().is_none());
    assert!(client.prepared().form_boundary().is_none());
    assert_eq!(
        client.prepared().pseudo_order().unwrap(),
        vec![
            PseudoId::Method,
            PseudoId::Scheme,
            PseudoId::Path,
            PseudoId::Authority,
            PseudoId::Protocol,
            PseudoId::Status,
        ]
    );
}

#[tokio::test]
async fn firefox147_initial_packet_number_stays_inside_neqo_range() {
    let client = client("firefox147");
    let number = client.prepared().initial_packet_number().unwrap();
    assert!((1..=1024).contains(&number));
    let endpoint = client.http3_endpoint().unwrap();
    assert_eq!(endpoint.initial_packet_number(), Some(number));
    assert_eq!(endpoint.connection_id_lengths().1, 3);
    assert!((8..=20).contains(&endpoint.connection_id_lengths().0));
    assert_eq!(
        endpoint.profile().transport_parameters,
        http3("firefox147").unwrap().transport_parameters
    );
}

#[test]
fn override_keeps_the_preset_and_applies_the_caller_changes() {
    let profile = Profile::find("chrome150").unwrap();
    let cipher_list = profile
        .emulation()
        .tls_options
        .unwrap()
        .cipher_list
        .unwrap();
    let client = Client::builder(profile)
        .header("X-Lab", "1")
        .http2_initial_window_size(123_456)
        .target_name("chrome150-lab")
        .proxy_url("socks5://127.0.0.1:9")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(client.profile().target(), "chrome150");
    assert_eq!(client.prepared().name(), "chrome150-lab");
    assert_eq!(client.prepared().base(), "chrome150");
    assert_eq!(client.prepared().cipher_list(), Some(cipher_list.as_ref()));
    assert_eq!(
        client
            .prepared()
            .emulation()
            .http2_options
            .as_ref()
            .unwrap()
            .header_table_size,
        Some(65536)
    );
    assert_eq!(client.prepared().http2_initial_window_size(), Some(123_456));
    assert_eq!(client.prepared().extra_header("x-lab"), Some("1"));
    assert_eq!(client.prepared().proxy_url(), Some("socks5://127.0.0.1:9"));
    assert!(client.prepared().uses_udp_associate());
    assert_eq!(client.prepared().udp_associate_request().unwrap()[1], 0x03);
    assert!(client.prepared().deviation().unwrap().contains("mldsa44"));
    assert_eq!(
        client.prepared().http3().unwrap().settings,
        profile::http3("chrome150").unwrap().settings
    );
}

#[tokio::test]
async fn http3_socks5_uses_udp_associate() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp_port = tcp.local_addr().unwrap().port();
    let relay_addr = udp.local_addr().unwrap();

    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut sock, _) = tcp.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        tokio::io::AsyncReadExt::read_exact(&mut sock, &mut greeting)
            .await
            .unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        tokio::io::AsyncWriteExt::write_all(&mut sock, &[0x05, 0x00])
            .await
            .unwrap();
        let mut request = [0u8; 10];
        tokio::io::AsyncReadExt::read_exact(&mut sock, &mut request)
            .await
            .unwrap();
        let _ = seen_tx.send(request);
        let ip = match relay_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("relay is ipv4"),
        };
        let port = relay_addr.port().to_be_bytes();
        let reply = [
            0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1],
        ];
        tokio::io::AsyncWriteExt::write_all(&mut sock, &reply)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let profile = Profile::find("chrome150").unwrap();
    let client = Client::builder(profile)
        .proxy_url(&format!("socks5://127.0.0.1:{tcp_port}"))
        .unwrap()
        .build()
        .unwrap();
    assert!(client.prepared().uses_udp_associate());
    assert_eq!(client.prepared().udp_associate_request().unwrap()[1], 0x03);

    let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();
    let request = tokio::spawn(async move { client.http3_get(dest, "example.com", "/").await });

    let command = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx)
        .await
        .expect("socks handshake")
        .unwrap();
    assert_eq!(command[0], 0x05);
    assert_eq!(command[1], 0x03);

    let mut buf = [0u8; 2048];
    let size = tokio::time::timeout(std::time::Duration::from_secs(20), udp.recv(&mut buf))
        .await
        .expect("quic datagram on the associate relay")
        .unwrap();
    assert!(size > 10, "datagram {size} bytes");
    assert_eq!(&buf[..4], &[0x00, 0x00, 0x00, 0x03]);
    let host_len = buf[4] as usize;
    assert_eq!(&buf[5..5 + host_len], b"example.com");
    let port_at = 5 + host_len;
    assert_eq!(u16::from_be_bytes([buf[port_at], buf[port_at + 1]]), 443);

    request.abort();
}

/// First Initial from the client's real QUIC path, plus every coalesced Initial
/// needed to finish the ClientHello.
async fn capture_initial_flight(client: &Client) -> Vec<OpenedInitial> {
    let endpoint = Arc::new(
        client
            .http3_endpoint()
            .expect("preset has an http3 endpoint"),
    );
    capture_bound(endpoint).await
}

async fn capture_bound(endpoint: Arc<H3Endpoint>) -> Vec<OpenedInitial> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let sending = {
        let endpoint = Arc::clone(&endpoint);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                endpoint.get(addr, "example.com", "/"),
            )
            .await;
        })
    };

    let mut opened = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut last_error = String::from("no datagram");
    while tokio::time::Instant::now() < deadline {
        let mut buf = vec![0u8; 65535];
        let wait = deadline.saturating_duration_since(tokio::time::Instant::now());
        let size = match tokio::time::timeout(wait, socket.recv(&mut buf)).await {
            Ok(result) => result.expect("udp recv"),
            Err(_) => break,
        };
        buf.truncate(size);
        let packets = open_client_datagram(&buf).unwrap_or_else(|error| {
            let head = buf.len().min(48);
            panic!(
                "open initial: {error}; len {size}; head {:02x?}",
                &buf[..head]
            );
        });
        opened.extend(packets);
        let payloads: Vec<&[u8]> = opened
            .iter()
            .map(|packet| packet.payload.as_slice())
            .collect();
        match initial_source_connection_id_from(payloads) {
            Ok(_) => {
                sending.abort();
                return opened;
            }
            Err(error) => last_error = error,
        }
        if opened.len() > 8 {
            break;
        }
    }
    sending.abort();
    panic!(
        "client hello not in the captured initials ({last_error}); packets {}",
        opened.len()
    );
}

fn source_connection_id(packets: &[OpenedInitial]) -> Vec<u8> {
    let payloads: Vec<&[u8]> = packets
        .iter()
        .map(|packet| packet.payload.as_slice())
        .collect();
    initial_source_connection_id_from(payloads).unwrap_or_else(|error| {
        panic!(
            "transport parameter 0x0f: {error}; packet numbers {:?}",
            packets
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>()
        )
    })
}

#[tokio::test]
async fn chrome150_initial_carries_packet_number_one() {
    let client = client("chrome150");
    let expected = client.prepared().initial_packet_number().unwrap();
    assert_eq!(expected, 1);
    let packets = capture_initial_flight(&client).await;
    let first = &packets[0];
    assert!(
        first.packet_len >= 1200,
        "initial is {} bytes",
        first.packet_len
    );
    let param = source_connection_id(&packets);
    assert_eq!(first.packet_number, u64::from(expected));
    assert_eq!(first.src_cid, param);
    assert!(first.src_cid.is_empty());
    eprintln!(
        "chrome150 prepared_pn={expected} wire_pn={} scid={:02x?} param_0x0f={:02x?}",
        first.packet_number, first.src_cid, param
    );
}

#[tokio::test]
async fn firefox147_initial_scid_matches_parameter_0x0f() {
    let client = client("firefox147");
    let expected = client.prepared().initial_packet_number().unwrap();
    assert!((1..=1024).contains(&expected));
    let packets = capture_initial_flight(&client).await;
    let first = &packets[0];
    assert!(
        first.packet_len >= 1200,
        "initial is {} bytes",
        first.packet_len
    );
    assert_eq!(
        first.packet_number,
        u64::from(expected),
        "wire packet number diverges from the prepared value"
    );
    let param = source_connection_id(&packets);
    assert_eq!(first.src_cid, param);
    assert!(!first.src_cid.is_empty());
    assert_eq!(first.src_cid.len(), 3);
    assert!(packets.iter().all(|packet| packet.src_cid == param));
    eprintln!(
        "firefox147 prepared_pn={expected} wire_pn={} scid={:02x?} param_0x0f={:02x?}",
        first.packet_number, first.src_cid, param
    );
}

#[tokio::test]
async fn firefox147_second_connection_stamps_its_own_source_connection_id() {
    let client = client("firefox147");
    let endpoint = Arc::new(client.http3_endpoint().unwrap());
    let first = capture_bound(Arc::clone(&endpoint)).await;
    let second = capture_bound(endpoint).await;
    let first_id = source_connection_id(&first);
    let second_id = source_connection_id(&second);
    assert_eq!(first[0].src_cid, first_id);
    assert_eq!(second[0].src_cid, second_id);
    assert_ne!(first_id, second_id);
    assert_eq!(first_id.len(), 3);
    assert_eq!(second_id.len(), 3);
}

#[test]
fn websocket_deflate_offers_permessage_deflate() {
    let client = client("chrome150");
    let upgrade = client.websocket_deflate("wss://example.com");
    assert_eq!(
        upgrade.extensions(),
        "permessage-deflate; client_max_window_bits"
    );
}

#[test]
fn preset_form_boundary_matches_webkit_or_firefox() {
    let chrome = client("chrome150")
        .multipart()
        .unwrap()
        .boundary()
        .to_string();
    assert!(chrome.starts_with("------WebKitFormBoundary"));
    assert_eq!(chrome.len(), "------WebKitFormBoundary".len() + 16);
    assert!(chrome
        .chars()
        .skip("------WebKitFormBoundary".len())
        .all(|c| c.is_ascii_alphanumeric()));

    let firefox = client("firefox133")
        .multipart()
        .unwrap()
        .boundary()
        .to_string();
    assert!(firefox.starts_with("------geckoformboundary"));
    assert_eq!(firefox.len(), "------geckoformboundary".len() + 32);
    assert!(firefox
        .chars()
        .skip("------geckoformboundary".len())
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    assert!(client("okhttp4_android").multipart().is_none());
}

#[tokio::test]
async fn chrome150_override_packet_number_is_on_the_wire() {
    let profile = Profile::find("chrome150").unwrap();
    let client = Client::builder(profile)
        .initial_packet_number(7)
        .build()
        .unwrap();
    assert_eq!(client.prepared().initial_packet_number(), Some(7));
    let packets = capture_initial_flight(&client).await;
    assert_eq!(packets[0].packet_number, 7);
}

#[test]
fn chrome150_names_the_mldsa_deviation_and_drops_those_algorithms() {
    let client = client("chrome150");
    let note = profile::deviation("chrome150").unwrap();
    assert_eq!(client.prepared().deviation(), Some(note));
    for name in ["mldsa44", "mldsa65", "mldsa87"] {
        assert!(note.contains(name), "{note}");
        assert!(!client
            .prepared()
            .emulation()
            .tls_options
            .as_ref()
            .unwrap()
            .sigalgs_list
            .as_deref()
            .unwrap()
            .contains(name));
    }
}
