//! One live HTTP/3 request, used to check that a preset's QUIC handshake
//! completes and the response comes back.
//!
//! Usage: h3probe [target] [host] [path]
//!
//! `target` is any name `Profile::find` accepts: a curl-impersonate preset or a
//! fingerprint-library record. Library records build their HTTP/3 profile from
//! the record's own `http3` block, presets from the generated table.

use std::net::ToSocketAddrs;

use rust_curl_impersonate::quic::endpoint::H3Endpoint;
use rust_curl_impersonate::{Client, Profile};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "chrome145".to_string());
    let host = args.next().unwrap_or_else(|| "quic.nginx.org".to_string());
    let path = args.next().unwrap_or_else(|| "/".to_string());
    let profile = Profile::find(&target).unwrap_or_else(|| panic!("{target} is not a known profile"));
    let client = Client::new(profile).unwrap_or_else(|error| panic!("{target}: {error}"));
    let endpoint: H3Endpoint = client
        .http3_endpoint()
        .unwrap_or_else(|error| panic!("{target} has no HTTP/3 profile: {error}"));

    let addr = (host.as_str(), 443)
        .to_socket_addrs()
        .expect("resolve")
        .find(|addr| addr.is_ipv4())
        .expect("ipv4");
    println!("connecting to {addr} as {target}");

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        endpoint.get(addr, &host, &path),
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
