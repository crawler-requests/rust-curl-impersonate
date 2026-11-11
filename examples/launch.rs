//! Fresh consumer of the shipped client.
//!
//! Prints the deterministic chrome150 lines a verifier compares across two runs.

use rust_curl_impersonate::{Client, Profile};

fn main() {
    let profile = Profile::find("chrome150").expect("chrome150");
    let client = Client::new(profile).expect("client");
    let packet = client
        .prepared()
        .initial_packet_number()
        .expect("packet number");
    let pseudo = if client.prepared().pseudo_order().is_none() {
        "absent"
    } else {
        "present"
    };
    let boundary = client.multipart().expect("boundary").boundary().to_string();
    let prefix = boundary_prefix(&boundary);
    println!("packet_number={packet}");
    println!("http2_pseudo_order={pseudo}");
    println!("boundary_prefix={prefix}");

    let overridden = Client::builder(profile)
        .header("x-added", "1")
        .form_boundary("firefox")
        .build()
        .expect("override");
    let added = overridden
        .prepared()
        .extra_header("x-added")
        .expect("header");
    let overridden_boundary = overridden
        .multipart()
        .expect("override boundary")
        .boundary()
        .to_string();
    println!("added_header=x-added:{added}");
    println!(
        "override_boundary_prefix={}",
        boundary_prefix(&overridden_boundary)
    );
}

fn boundary_prefix(boundary: &str) -> &str {
    if boundary.starts_with("------WebKitFormBoundary") {
        "------WebKitFormBoundary"
    } else if boundary.starts_with("------geckoformboundary") {
        "------geckoformboundary"
    } else {
        "other"
    }
}
