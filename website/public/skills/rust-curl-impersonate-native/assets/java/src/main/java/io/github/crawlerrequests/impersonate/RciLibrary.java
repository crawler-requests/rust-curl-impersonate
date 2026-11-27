package io.github.crawlerrequests.impersonate;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

/**
 * The 17 functions of the rust-curl-impersonate C ABI (version 2), declared for
 * JNA. Signatures mirror {@code rci.h} exactly; the ownership rules below are
 * the ones a JNA caller gets wrong most often.
 *
 * <pre>
 * - Every {@code char *} RESULT is owned by the library. JNA must not convert
 *   it to a String on the way out: declare the return as {@link Pointer}, read
 *   the text with {@link #stringOf}, then call {@link #rci_string_free}.
 * - {@code const char *rci_last_error()} is the exception: the caller does not
 *   free it, so a String result is safe and convenient.
 * - {@code RciClient *} is an opaque handle: a {@link Pointer} the caller frees
 *   with {@link #rci_client_free}.
 * - One handle per thread: the library's handle is not thread-safe.
 * </pre>
 *
 * Load with {@link RciNative}. This interface is only the raw ABI; use
 * {@link RustCurlImpersonate} for the typed facade.
 */
public interface RciLibrary extends Library {

    /** ABI version reported by {@link #rci_version()}. */
    int ABI_VERSION = 2;

    // -- version and library ------------------------------------------------

    int rci_version();

    Pointer rci_targets();

    Pointer rci_profiles();

    Pointer rci_profile_info(String profile);

    // -- client construction -------------------------------------------------

    Pointer rci_client_new(String profile);

    Pointer rci_client_new_with_options(String profile, String options_json);

    void rci_client_free(Pointer handle);

    Pointer rci_client_profile(Pointer handle);

    // -- requests ------------------------------------------------------------

    /**
     * @param body     a byte array or {@code null} when {@code body_len} is 0
     * @param body_len number of bytes in {@code body}
     */
    Pointer rci_request(Pointer handle, String method, String url, byte[] body, long body_len);

    Pointer rci_request_with(Pointer handle, String method, String url,
                             String headers_json, String body);

    Pointer rci_get(String profile, String url);

    Pointer rci_http3_get(String profile, String addr, String host, String path);

    // -- handle introspection -------------------------------------------------

    Pointer rci_client_last_headers(Pointer handle);

    Pointer rci_client_activity(Pointer handle);

    // -- errors and memory ----------------------------------------------------

    String rci_last_error();

    Pointer rci_load_fingerprints(String json);

    void rci_string_free(Pointer text);
}
