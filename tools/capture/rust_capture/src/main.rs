// Capture reqwest with its rustls backend. The TLS stack is rustls, not
// BoringSSL or OpenSSL, so the ClientHello differs from every other record.
use std::io::Write;

#[tokio::main]
async fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: rust_capture <output>");
    let client = reqwest::Client::builder()
        .build()
        .expect("build reqwest client");
    let body = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await
        .expect("send request")
        .text()
        .await
        .expect("read body");
    std::fs::File::create(out)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .expect("write capture");
    println!("rust reqwest+rustls: saved {} bytes", body.len());
}
