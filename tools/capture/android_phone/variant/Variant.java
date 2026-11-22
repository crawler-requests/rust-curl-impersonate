package io.capture.phone;

import java.net.Proxy;

/**
 * The library this build links. `build.sh --variant <dir>` copies one
 * `Variant.java` from `variants/<dir>/` over this file, so exactly one
 * library version is compiled into the APK. A hello captured with the
 * `okhttp-4-12-0` label therefore came from OkHttp 4.12.0 and nothing else;
 * no reflection, no second copy of a library's classes.
 */
final class Variant {
    private Variant() {
    }

    static void request(String kind, String url, Proxy proxy) throws Exception {
        throw new UnsupportedOperationException(
                "this build links no library; rebuild with --variant");
    }
}
