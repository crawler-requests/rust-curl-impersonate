//! Send one request and print the TLS echo the server saw.
//!
//! Run with `cargo run --example echo`. The endpoint reports the ClientHello it
//! received, which is the only way to tell whether the profile reached the wire.
//! Pass another curl-impersonate target as the first argument to try it instead.

use rust_curl_impersonate::{Client, Profile};

#[tokio::main]
async fn main() -> rust_curl_impersonate::Result<()> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "chrome150".to_string());
    let profile =
        Profile::find(&target).unwrap_or_else(|| panic!("{target} is not a known target"));

    let client = Client::builder(profile)
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    let response = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("status: {}", response.status());
    println!("{}", response.text().await?);
    Ok(())
}
