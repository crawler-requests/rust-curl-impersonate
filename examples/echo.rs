//! Send one request as Chrome 150 and print the TLS echo the server saw.
//!
//! Run with `cargo run --example echo`. The endpoint reports the ClientHello it
//! received, which is the only way to tell whether the profile reached the wire.

use rust_curl_impersonate::{Client, Profile};

#[tokio::main]
async fn main() -> rust_curl_impersonate::Result<()> {
    let client = Client::builder(Profile::Chrome150)
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    let response = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("status: {}", response.status());
    println!("{}", response.text().await?);
    Ok(())
}
