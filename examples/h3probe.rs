//! One live HTTP/3 request against quic.nginx.org, used to check that a preset's
//! QUIC handshake completes and the response comes back.

use std::net::ToSocketAddrs;

use rust_curl_impersonate::profile::http3;
use rust_curl_impersonate::quic::endpoint::H3Endpoint;

#[tokio::main]
async fn main() {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "chrome145".to_string());
    let profile = http3(&target).unwrap_or_else(|| panic!("{target} has no HTTP/3 profile"));
    let endpoint = H3Endpoint::bind(&profile).expect("bind");

    let addr = ("quic.nginx.org", 443)
        .to_socket_addrs()
        .expect("resolve")
        .find(|addr| addr.is_ipv4())
        .expect("ipv4");
    println!("connecting to {addr} as {target}");

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        endpoint.get(addr, "quic.nginx.org", "/"),
    )
    .await;
    match outcome {
        Err(_) => {
            eprintln!("timed out after 8s with no response");
            std::process::exit(1);
        }
        Ok(Ok(response)) => {
            println!("status headers: {}", response.headers.len());
            for (name, value) in &response.headers {
                println!("  {name}: {value}");
            }
            println!("body: {} bytes", response.body.len());
        }
        Ok(Err(error)) => {
            eprintln!("handshake failed: {error}");
            std::process::exit(1);
        }
    }
}
