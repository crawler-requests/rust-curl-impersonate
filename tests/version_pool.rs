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

#[test]
fn a_version_inside_a_stable_range_resolves_to_that_shape() {
    use rust_curl_impersonate::fingerprint;
    // Safari 15.5 through 18.0 send one ClientHello; a caller asking for
    // 16.2 gets that shape and learns the captures behind it.
    let record = fingerprint::for_version("webkit", "16.2").expect("covered range");
    assert_eq!(record.library, "webkit");
    let covers = fingerprint::covering_versions("webkit", "16.2");
    assert!(covers.contains(&"15.5"), "{covers:?}");
    assert!(covers.contains(&"18.0"), "{covers:?}");
    // Every version in the range resolves to the same shape.
    for version in ["15.5", "16.0", "17.0", "18.0"] {
        let exact = fingerprint::for_version("webkit", version).expect(version);
        assert_eq!(exact.wire_shape(), record.wire_shape(), "{version}");
    }
}

#[test]
fn a_version_between_different_shapes_is_not_guessed() {
    use rust_curl_impersonate::fingerprint;
    // 18.2 sits between 18.0 and 18.5, which send different ClientHellos, so
    // no capture describes it and the lookup must not pretend one does.
    assert!(fingerprint::for_version("webkit", "18.2").is_none());
    // 12.5 likewise sits between 12.1 and 13.0, which differ.
    assert!(fingerprint::for_version("webkit", "12.5").is_none());
}

#[test]
fn a_version_above_the_newest_capture_uses_the_newest_shape() {
    use rust_curl_impersonate::fingerprint;
    // Safari 27 has no capture here; the honest answer is the newest shape,
    // and covering_versions names which capture it actually came from.
    let record = fingerprint::for_version("webkit", "27.0").expect("newest shape");
    assert_eq!(record.version, "26.0");
    assert_eq!(fingerprint::covering_versions("webkit", "27.0"), vec!["26.0"]);
}

#[test]
fn one_call_builds_a_client_from_a_pool() {
    use rust_curl_impersonate::Client;
    // The caller names a library and a rule; no record name is needed.
    let pool = VersionPool::for_library("cfnetwork").with_rule(PoolRule::Newest);
    let client = Client::from_pool(&pool).expect("a pool picks a usable record");
    assert!(client.prepared().cipher_list().is_some());
}

#[test]
fn an_empty_pool_reports_why_it_could_not_build() {
    use rust_curl_impersonate::Client;
    let pool = VersionPool::for_library("does-not-exist");
    let error = match Client::from_pool(&pool) {
        Ok(_) => panic!("an empty pool should not build a client"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("no candidates"), "{error}");
}
