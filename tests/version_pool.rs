//! The enumeration and pool layer: every library is listable by name, every
//! captured version of it is reachable, and a pool can randomise over the
//! distinct shapes.

use rust_curl_impersonate::fingerprint::{self, PoolRule, VersionPool};
use rust_curl_impersonate::{Client, Profile};

#[test]
fn every_ios_library_is_enumerable() {
    let libraries = fingerprint::libraries();
    // The library distinguishes the platform stack (CFNetwork) from WebKit.
    assert!(libraries.contains(&"cfnetwork"), "{libraries:?}");
    assert!(libraries.contains(&"webkit"), "{libraries:?}");

    for library in &libraries {
        let versions = fingerprint::versions(library);
        assert!(!versions.is_empty(), "{library} has no versions");
        // Versions are sorted newest first: compare the first two numerically.
        if versions.len() >= 2 {
            let first: f64 = versions[0].parse().unwrap_or(0.0);
            let second: f64 = versions[1].parse().unwrap_or(0.0);
            assert!(first >= second, "{library}: {versions:?} is not newest-first");
        }
    }
}

#[test]
fn ios_webkit_versions_run_from_eleven_to_the_newest_capture() {
    let versions = fingerprint::versions("webkit");
    assert!(versions.contains(&"11.1"), "{versions:?}");
    assert!(versions.contains(&"26.0"), "{versions:?}");
    // 26.0 sorts ahead of 18.5, which sorts ahead of 15.5.
    let newest = fingerprint::newest("webkit").expect("webkit has records");
    assert_eq!(newest.version, "26.0", "{}", newest.name());
}

#[test]
fn distinct_shapes_collapse_versions_that_send_the_same_hello() {
    let all: Vec<&str> = fingerprint::by_library("webkit")
        .map(|record| record.name())
        .collect();
    let shapes: Vec<&str> = fingerprint::distinct_shapes("webkit")
        .iter()
        .map(|record| record.name())
        .collect();
    assert!(
        shapes.len() < all.len(),
        "expected fewer shapes than records, got {} vs {}",
        shapes.len(),
        all.len()
    );
    // Safari 15.5-18.0 share one ClientHello; the representative is the newest
    // of them, so the shape list must not name 15.5 while 18.0 exists.
    assert!(
        shapes.contains(&"tlsclient_ios_safari18"),
        "{shapes:?}"
    );
}

#[test]
fn a_pool_picks_only_its_library_and_range() {
    let pool = VersionPool::for_library("webkit")
        .with_rule(PoolRule::RandomShape)
        .at_least("15.0");
    for _ in 0..16 {
        let record = pool.pick().expect("the pool has candidates");
        assert_eq!(record.library, "webkit", "{}", record.name());
        assert!(
            record.version != "11.1" && record.version != "12.1",
            "{} is outside the range",
            record.name()
        );
        assert!(Profile::find(record.name()).is_some(), "{}", record.name());
    }
}

#[test]
fn pool_rules_have_the_documented_meaning() {
    let newest = VersionPool::for_library("webkit")
        .with_rule(PoolRule::Newest)
        .pick()
        .expect("candidates");
    assert_eq!(newest.version, "26.0");

    let version_pool = VersionPool::for_library("webkit")
        .with_rule(PoolRule::RandomVersion)
        .at_most("18.5");
    assert!(
        version_pool.candidates().len()
            >= VersionPool::for_library("webkit")
                .at_most("18.5")
                .candidates()
                .len(),
        "RandomVersion must not collapse shapes"
    );
}

#[test]
fn an_unknown_library_yields_no_pool_candidates() {
    let pool = VersionPool::for_library("does-not-exist");
    assert!(pool.candidates().is_empty());
    assert!(pool.pick().is_none());
}

#[test]
fn pool_names_can_be_installed_and_used() {
    let pool = VersionPool::for_library("cfnetwork").with_rule(PoolRule::RandomShape);
    let record = pool.pick().expect("cfnetwork has records");
    let profile = Profile::find(record.name()).expect("the record resolves");
    let client = Client::new(profile).expect("the record builds a client");
    assert!(!client.prepared().cipher_list().is_none());
}
