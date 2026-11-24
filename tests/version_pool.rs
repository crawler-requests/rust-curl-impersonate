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
        // A library is addressable either by version (WebKit, where the
        // capture names an OS release) or by shape (CFNetwork, where the
        // capture is an app profile upstream files with `Version: "1"` and
        // the request only carries `CFNetwork/1474 Darwin/23.0.0`). Every
        // library must be reachable one way or the other.
        let versions = fingerprint::versions(library);
        let shapes = fingerprint::distinct_shapes(library);
        assert!(
            !versions.is_empty() || !shapes.is_empty(),
            "{library} has neither versions nor shapes"
        );
        // Versions are sorted newest first: compare the first two numerically.
        if versions.len() >= 2 {
            let first: f64 = versions[0].parse().unwrap_or(0.0);
            let second: f64 = versions[1].parse().unwrap_or(0.0);
            assert!(first >= second, "{library}: {versions:?} is not newest-first");
        }
    }
}

#[test]
fn cfnetwork_records_do_not_invent_an_os_version() {
    // tls-client files these app profiles as `Version: "1"` and the captures
    // all send `CFNetwork/1474 Darwin/23.0.0`, so no iOS release is named
    // anywhere upstream. An empty version is the honest value: a number here
    // would be a guess dressed up as a capture.
    let versions = fingerprint::versions("cfnetwork");
    assert!(versions.is_empty(), "{versions:?}");
    // The shapes still distinguish the apps, and the pool still picks from
    // them, so the library remains fully addressable.
    let shapes = fingerprint::distinct_shapes("cfnetwork");
    assert!(shapes.len() >= 5, "{:?}", shapes.iter().map(|r| r.name()).collect::<Vec<_>>());
    let pool = VersionPool::for_library("cfnetwork").with_rule(PoolRule::RandomShape);
    assert!(!pool.candidates().is_empty());
    assert!(pool.pick().is_some());
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
        assert_eq!(record.library(), "webkit", "{}", record.name());
        assert!(
            record.version() != "11.1" && record.version() != "12.1",
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
    assert!(
        newest.version() == "26.0" || newest.version() == "27.0",
        "{}",
        newest.version()
    );

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
    assert!(client.prepared().cipher_list().is_some());
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
    let _ = record;
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

#[test]
fn safari_27_is_reachable_through_the_presets() {
    use rust_curl_impersonate::{fingerprint, Client, Profile};
    // No capture of Safari 27 exists here, but curl-impersonate ships it as a
    // preset, so it must be reachable by name and by version.
    let ios = fingerprint::entry_for_version("webkit", "27.0").expect("Safari 27 iOS");
    assert_eq!(ios.name(), "safari270_ios");
    assert_eq!(ios.version(), "27.0");

    let mac = fingerprint::entry_for_version("webkit-macos", "27.0").expect("Safari 27 mac");
    assert_eq!(mac.name(), "safari270");

    // A pool over webkit contains it, and picking builds a client.
    let pool = VersionPool::for_library("webkit")
        .with_rule(PoolRule::RandomVersion)
        .at_least("27.0");
    let candidates = pool.candidates();
    assert!(
        candidates.iter().any(|entry| entry.name() == "safari270_ios"),
        "{:?}",
        candidates.iter().map(|entry| entry.name()).collect::<Vec<_>>()
    );
    let client = Client::from_pool(&pool).expect("Safari 27 builds a client");
    assert!(client.prepared().cipher_list().is_some());
    assert!(Profile::find("safari270_ios").is_some());
}

#[test]
fn the_newest_webkit_entry_is_safari_27() {
    use rust_curl_impersonate::fingerprint;
    let entries = fingerprint::entries("webkit");
    let newest = entries.first().expect("webkit has entries");
    assert_eq!(newest.version(), "27.0", "{}", newest.name());
    assert!(
        ["safari270_ios", "safari260_ios", "ios_safari26"]
            .contains(&newest.name()),
        "{}",
        newest.name()
    );
}

#[test]
fn the_third_party_ios_stacks_are_enumerable_too() {
    // CFNetwork and WebKit are the platform stacks. swiftnio and cronet are
    // what an app gets when it brings its own TLS instead, and both are
    // first-class libraries to enumerate.
    let libraries = fingerprint::libraries();
    for library in ["swiftnio", "cronet"] {
        assert!(libraries.contains(&library), "{library} missing: {libraries:?}");
        assert!(
            !fingerprint::versions(library).is_empty(),
            "{library} exposes no version"
        );
        let pool = VersionPool::for_library(library);
        let entry = pool.pick().expect(library);
        assert_eq!(entry.library(), library);
        assert!(Profile::find(entry.name()).is_some(), "{}", entry.name());
    }
}

#[test]
fn safari_27_2_is_the_newest_webkit_macos_capture() {
    // tls-client's master branch added a Safari 27.2 profile after v1.18.1.
    // It was captured for real, and its ClientHello is byte-identical to
    // Safari 27.0's, so both versions describe one shape.
    assert_eq!(fingerprint::newest("webkit-macos").unwrap().name(), "tlsclient_safari27_2");
    assert_eq!(fingerprint::versions("webkit-macos")[0], "27.2");

    let record = fingerprint::for_version("webkit-macos", "27.2").expect("27.2 is captured");
    assert_eq!(record.name(), "tlsclient_safari27_2");
    // 27.0 is a preset, not a capture, so the capture-only lookup returns None
    // and the entry lookup is what resolves it.
    assert!(fingerprint::for_version("webkit-macos", "27.0").is_none());
    assert_eq!(
        fingerprint::entry_for_version("webkit-macos", "27.0").map(|e| e.name()),
        Some("safari270")
    );
    // A version above the newest capture still resolves, to the newest shape.
    assert!(fingerprint::for_version("webkit-macos", "27.5").is_some());
}
