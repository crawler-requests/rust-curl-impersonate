//! Emit one Initial packet and write it to disk so it can be decrypted offline.
//!
//! A server that drops the packet gives no error back, so the bytes have to be
//! read directly. The packet is addressed at a local socket, which captures it.

use std::net::UdpSocket;

use rust_curl_impersonate::profile::http3;
use rust_curl_impersonate::quic::endpoint::H3Endpoint;

#[tokio::main]
async fn main() {
    let profile = http3("chrome145").unwrap();
    // SAFETY: this example is the only process touching the variable.
    unsafe { std::env::set_var("H3_BIND", "127.0.0.1:0") };
    let endpoint = H3Endpoint::bind(&profile).unwrap();

    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    sink.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let addr = sink.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            endpoint.get(addr, "localhost", "/"),
        )
        .await;
    });

    let mut buf = [0u8; 4096];
    let (len, _) = sink.recv_from(&mut buf).expect("no packet emitted");
    std::fs::write("/tmp/initial.bin", &buf[..len]).unwrap();
    println!("captured {len} bytes, first byte {:#04x}", buf[0]);
    handle.abort();
}

#[allow(dead_code)]
fn dump_request_frame() {
    use rust_curl_impersonate::quic::h3;
    let profile = http3("chrome145").unwrap();
    let owned: Vec<(String, String)> = {
        let mut h = Vec::new();
        for letter in profile.pseudo_order.chars() {
            let (n, v) = match letter {
                'm' => (":method", "GET"),
                'a' => (":authority", "quic.nginx.org"),
                's' => (":scheme", "https"),
                'p' => (":path", "/"),
                _ => continue,
            };
            h.push((n.to_string(), v.to_string()));
        }
        h.extend(
            profile
                .headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string())),
        );
        h
    };
    let refs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let frame = h3::headers_frame(&refs);
    println!(
        "frame {} bytes: {}",
        frame.len(),
        frame.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("decoded: {:?}", h3::decode_headers(&frame[2..]).unwrap());
}
