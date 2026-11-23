Android capture matrix, 2026-11-23

question
  "Are the library's Android records right on every Android release, for
  every library version a real client uses?" Until this pass that was
  answered by tls.peet.ws echoes and by tls-client profiles: shapes someone
  else's device produced, or shapes rebuilt from them. This pass ran actual
  APKs, each linking exactly one library build, on real Android runtimes
  from 8.1 to 14, and read their ClientHellos off the wire.

device
  Two kinds of device. The grid below ran on seven redroid containers;
  a physical OnePlus 9R (LE2100, Android 13, arm64-v8a, WebView 103)
  is captured separately by tools/capture/device_matrix.py, which is the
  same grid pointed at whatever phone adb shows. Both are real Android
  runtimes running the real library build - the container's value is that
  one can boot Android 8.1, 9, 10 and 14 on the same host; the phone's is
  that it is a phone.

  Seven redroid containers, one per Android release: 8.1 (SDK 27), 9 (28),
  10 (29), 11 (30), 12 (31), 13 (33), 14 (34). All x86_64, not phones: the
  runtime is the real Android framework and the library is the real library,
  which is what the hello depends on. The Android 13 container runs on the
  LAN host (192.168.1.90) and was already joined by adb; the others run
  locally. Two 64-bit builds of Android (14, 16) and the 32-bit 11 build do
  not boot under this kernel - 14 has no gralloc mapper, 16 wants an
  OpenGL ES implementation the guest cannot find - so SDK 32 and 15 are
  absent rather than guessed at.

method
  - Each library version is its own APK (tools/capture/android_phone,
    build.sh --variant <name>), linking that version and nothing else. A
    hello captured under `okhttp-4-12-0` is OkHttp 4.12.0 with no
    reflection and no class loader in the path that could substitute
    another client.
  - The APK names each stack in its SNI (`a27-okhttp-4-12-0-okhttp.<sslip>`),
    so one capture directory holds every release's result.
  - tools/capture/android_matrix.py drives the grid, tools/capture/
    phone_capture.py listens, and the listener never answers: the bytes on
    the wire are the whole point.
  - adb reverse keeps every connection on the device's own loopback, so no
    LAN address appears in a capture.
  - HTTP/2 fingerprints come from the real tls.peet.ws: the OkHttp, Cronet
    and WebView probes relay to it (CONNECT proxy for OkHttp and Cronet,
    the page's own report read back through the title for WebView, which
    cannot use a proxy). The server's ja4 and ja4_r are stored beside the
    listener's hello.

what the grid shows
  - OkHttp 3.14.4, 3.14.9, 4.9.3, 4.10.0 and 4.12.0 send the same hello on
    every release: t12d1209 on 8.1, t12d129 on 9, t13d1513 from 10 up.
    The TLS provider shapes it, not the OS version or the OkHttp major.
  - OkHttp 5.0.0 is genuinely different: it drops session_ticket, so
    t12d1207 on 8.1/9 and t13d1512 from 10 up.
  - Conscrypt 2.1.0 and 2.5.2 produce the platform stack's hello on every
    release (t13d1713h1), because they replace the JCA provider the
    platform would use.
  - Cronet 101 and 119 send what WebView 125 sends (t13d1516 with padding),
    on every release.
  - WebView 125 is on every image except Android 10; WebView 139 is the one
    that image ships, and it advertises ALPS at the newer codepoint.
  - WebView 125 appears in two shapes, padded and not, depending on where
    random-length ECH GREASE lands it relative to the 256-511 byte window.
    Only the padded shape is kept as a record: a record that suppresses
    padding for a hello this long does not survive on the wire (BoringSSL
    pads it anyway), and the unpadded hash is the padded record with
    extension 21 left out, which the wire test checks.

failures that are facts, not gaps
  - OkHttp 3.14.4 refuses to start on Android 11+ with "Expected Android
    API level 21+ but was 30" - a bug in that release, fixed by 3.14.9.
    Both versions were captured, so the range is documented rather than
    assumed.
  - Cronet needed its own dependencies (cronet-common, protobuf-javalite,
    androidx-core) and a debug-mode dex; without them it fails with
    NoClassDefFoundError before sending anything.
  - d8 cannot link ValueCallback<String>, so the WebView report comes back
    as the page title; an evaluateJavascript callback is not available.

library changes
  new  android_okhttp5           OkHttp 5.0.0, 12 extensions, server-
                                 confirmed HTTP/2 and Akamai fingerprint
  new  android_okhttp3_14_9      OkHttp 3.14.9 (the same hello OkHttp 4
                                 sends on this platform)
  new  android_cronet101         Cronet 101.0.4951.41
  new  android_cronet119         Cronet 119.0.6045.31
  new  android_webview139        WebView 139.0.7258.143, ALPS 17613
  The existing android_okhttp10..13 records were confirmed against the grid;
  none of them changed, which is the point of running it.

verification
  python3 -I tools/audit_provenance.py   -> 239 base records, 0 problems
  cargo test --workspace                 -> all suites pass; the wire tests
                                            hash each Android record's live
                                            ClientHello and compare with the
                                            capture.

what is not device-confirmed, and why
  These are recordings of specific apps, not of a library: android_confirmed,
  android_confirmed2 (a "Confirmed" app), android_mesh, android_mesh1,
  android_nike, android_zalando (the named apps) and utls_android11okhttp (a
  Go uTLS client, not an Android process). Reproducing them needs the apps
  themselves, which are not distributable, so they keep their tls.peet.ws
  captures as evidence. The audit still recomputes each stored hash from
  that capture, and android_mesh's shape is now confirmed by WebView 103 and
  by the WebView 125/139 probes.
  cronet_android100 keeps its redroid capture but is only `close`: the
  client greases fewer lists than BoringSSL's single switch can reproduce.

  Chrome for Android was attempted and could not be run: Google Play is not
  on the images, APKMirror and APKPure are unreachable from this network,
  and the official Chromium Android snapshots ship only armeabi-v7a, which
  is "for EM_ARM (40) instead of EM_386" on these x86 runs. chrome_android
  therefore stays an alias of the code-side preset chrome131_android.

the raw table
  table.txt has one line per (release, variant) with the JA4 the listener
  computed, so the grid itself is in the repository, not just in this note.

cronet versions beyond the first pair
  Five more Cronet builds were tried. The result is the boundary, not a
  list of failures:
    Cronet 76.0.3809.111   runs; t13d1615h2_46e7e9700bed_45f260be83e2,
                           no ALPS extension, a 16th cipher. Added as
                           android_cronet76. This is where Cronet's TLS
                           shape changes.
    Cronet 98.0.4758.87    runs; identical to 101/119 (t13d1516).
    Cronet 101, 119, 143   run; t13d1516.
    Cronet 105.0.5195.68   the native library aborts during
                           CronetLibraryLoader init on this Android 13
                           build - no hello is ever sent.
    Cronet 113.0.5672.61   same abort.
    Cronet 141.0.7340.3    refuses to start: NoClassDefFoundError on
                           org.chromium.base.metrics.ScopedSysTraceEvent
                           (its jar expects a newer base library than the
                           one the embedded AAR ships).
  So 66-98 share one shape, 98-143 share another, and two builds in
  between cannot run here at all. That is the honest coverage of the
  library, not a pretence that every patch level was tested.

okhttp versions beyond the first five
  3.12.0  Runs. On Android 13 it offers no ALPN and no session_ticket:
          t13d1511 (ALPN 00), against OkHttp 4's t13d1513. Added as
          android_okhttp3_12. Relayed through the CONNECT proxy it shows
          t13d1510, because the proxy strips ALPN - so the direct capture is
          the evidence, and the record leaves padding to the transport
          (the capture's padded shape is 3f5d972527c0).
  3.0.0   Will not build against the probe: its Response has no close().
          Not a shape question, an API one.
  4.0.0   Refuses to start on Android 11+: "Expected Android API level 21+
          but was 33" - the same bug as 3.14.4, fixed later in 4.x.
  4.7.2, 4.11.0  Identical to 4.12 on this platform (t13d1513).
  So OkHttp's shape changes at 3.x-versus-4.x (ALPN and session_ticket) and
  at 5 (session_ticket only); patch levels within 4.x do not move it.
