//! Fresh consumer of a caller-supplied Chrome record and built-in chrome150.
//!
//! Prints one TLS field, one HTTP/2 field, and one header that differ.

use rust_curl_impersonate::{Client, Profile, ProfileSpec};

fn main() {
    let profile = ProfileSpec::new("lab-chrome-next")
        .cipher_list("TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256")
        .http2_settings("1:8192")
        .header("x-lab-future", "next")
        .install()
        .expect("spec");
    let custom = Client::new(profile).expect("custom client");
    let chrome = Client::new(Profile::find("chrome150").expect("chrome150")).expect("chrome150");

    let tls = custom.prepared().cipher_list().expect("cipher");
    let tls_chrome = chrome.prepared().cipher_list().expect("chrome cipher");
    let http2 = custom
        .prepared()
        .emulation()
        .http2_options
        .as_ref()
        .expect("http2")
        .header_table_size
        .expect("header table");
    let http2_chrome = chrome
        .prepared()
        .emulation()
        .http2_options
        .as_ref()
        .expect("chrome http2")
        .header_table_size
        .expect("chrome header table");
    let header = format!(
        "x-lab-future:{}",
        custom
            .prepared()
            .extra_header("x-lab-future")
            .expect("header")
    );
    let header_chrome = format!(
        "user-agent:{}",
        chrome
            .prepared()
            .extra_header("user-agent")
            .expect("user-agent")
    );

    println!("tls_cipher={tls}");
    println!("tls_cipher_chrome150={tls_chrome}");
    println!("http2_header_table_size={http2}");
    println!("http2_header_table_size_chrome150={http2_chrome}");
    println!("header={header}");
    println!("header_chrome150={header_chrome}");

    if tls == tls_chrome || http2 == http2_chrome || header == header_chrome {
        std::process::exit(1);
    }
}
