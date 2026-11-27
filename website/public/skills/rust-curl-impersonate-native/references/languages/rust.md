# Rust

If the caller is Rust, skip the C ABI and depend on the crate itself.

```toml
[dependencies]
rust-curl-impersonate = { git = "https://github.com/crawler-requests/rust-curl-impersonate" }
```

```rust
use rust_curl_impersonate::{Client, Profile};

let profile = Profile::find("chrome150").expect("known profile");
let client = Client::new(profile)?;
let response = client.get("https://example.com").send().await?;
```

No `[patch.crates-io]` is needed: the modified `wreq` / `quinn` / `quinn-proto`
sources live inside the repository as path dependencies, so a plain path or
git dependency builds a downstream project as-is.

The C ABI (`bindings/ffi`) exists for languages that cannot take a Rust
dependency — use it only when the caller is not Rust.
