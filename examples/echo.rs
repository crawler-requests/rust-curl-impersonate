//! Send one request and print the TLS echo the server saw.
//!
//! Run with `cargo run --example echo`. The endpoint reports the ClientHello it
//! received, which is the only way to tell whether the profile reached the wire.
//! Pass another curl-impersonate target as the first argument to try it instead,
//! and an optional second argument to point at a different echo endpoint
//! (e.g. a local `openssl s_server -msg` when the public service is unreachable).

use rust_curl_impersonate::{Client, Profile};

#[tokio::main]
async fn main() -> rust_curl_impersonate::Result<()> {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| "chrome150".to_string());
    let url = args
        .next()
        .unwrap_or_else(|| "https://tls.peet.ws/api/all".to_string());
    let profile =
        Profile::find(&target).unwrap_or_else(|| panic!("{target} is not a known target"));

    let client = Client::builder(profile)
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    let response = client.get(&url).send().await?;
    println!("status: {}", response.status());
    println!("{}", response.text().await?);
    Ok(())
}
