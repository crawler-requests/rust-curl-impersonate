// Detect whether the BoringSSL being linked carries
// SSL_CTX_set_server_padding_request (extension 4832).
//
// Stock BoringSSL has no such symbol; scripts/boringssl/chrome4832.patch adds
// it. The check reads the btls-sys bindings that this build produced, so it
// follows whichever BoringSSL btls-sys chose - prebuilt or source-built.
//
// The result becomes `cfg(chrome_4832)`, which gates the call so a default
// build still compiles and simply leaves the extension off.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = match env::var_os("OUT_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => return,
    };
    // target/<profile>/build/<pkg>-<hash>/out
    //   parent -> <pkg>-<hash>
    //   parent -> build
    let build_root = match out_dir.parent().and_then(|dir| dir.parent()) {
        Some(dir) => dir.to_path_buf(),
        None => return,
    };
    let target_dir = build_root;

    let mut found = false;
    if let Ok(entries) = fs::read_dir(&target_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("btls-sys-") {
                continue;
            }
            let bindings = entry.path().join("out").join("bindings.rs");
            println!("cargo:rerun-if-changed={}", bindings.display());
            if let Ok(text) = fs::read_to_string(&bindings) {
                if text.contains("SSL_CTX_set_server_padding_request") {
                    found = true;
                    break;
                }
            }
        }
    }

    if found {
        println!("cargo:rustc-cfg=chrome_4832");
    }
}
