//! Print the client fingerprint library and the providers it comes from.
//!
//! Run with `cargo run --example fingerprints`. The first block lists every
//! registered provider; then each line shows the name that selects a record,
//! the client it describes, how closely the transport can reproduce the
//! capture, and the captured fields BoringSSL cannot send.

use rust_curl_impersonate::fingerprint::{self, Fidelity};

fn fidelity(value: Option<Fidelity>) -> &'static str {
    match value {
        Some(Fidelity::Exact) => "exact",
        Some(Fidelity::Close) => "close",
        Some(Fidelity::Partial) => "partial",
        None => "-",
    }
}

fn main() {
    println!("providers:");
    for provider in fingerprint::providers() {
        let overrides = match provider.overrides.len() {
            0 => String::new(),
            count => format!(", overrides {count}"),
        };
        println!(
            "  {:<16} priority {:<4} {} records{overrides}",
            provider.id, provider.priority, provider.records
        );
        if !provider.description.is_empty() {
            println!("      {}", provider.description);
        }
    }

    println!();
    println!(
        "{} embedded fingerprints, {} resolvable",
        fingerprint::builtin().len(),
        fingerprint::records().len()
    );
    for family in fingerprint::families() {
        println!();
        println!("{family}:");
        for record in fingerprint::by_family(family) {
            let target = match &record.extends {
                Some(base) => format!(" -> {base}"),
                None => String::new(),
            };
            println!(
                "  {:<24} {:<32} {:<8}{target}",
                record.name,
                record.client,
                fidelity(record.fidelity),
            );
            for deviation in &record.deviations {
                println!("      - {deviation}");
            }
        }
    }
}
