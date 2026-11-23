#!/usr/bin/env python3
"""Turn the raw tls.peet.ws captures into src/fingerprint/builtin.json.

Run from the repository root:

    python3 tools/gen_fingerprints.py

The capture files are produced by tools/capture/capture.sh. Only fields the
BoringSSL transport can send are written; every captured value that it cannot
send is listed in the record's ``deviations`` so the gap stays visible.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "tools", "capture", "raw")
OUT = os.path.join(ROOT, "src", "fingerprint", "builtin.json")

# BoringSSL 0.5.6 cipher table (ssl/ssl_cipher.cc, kCiphers).
SUPPORTED_CIPHERS = {
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_PSK_WITH_AES_128_CBC_SHA",
    "TLS_PSK_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
}

# BoringSSL named groups (ssl/ssl_key_share.cc, kNamedGroups).
GROUP_CODES = {
    23: "P-256",
    24: "P-384",
    25: "P-521",
    29: "X25519",
    4588: "X25519MLKEM768",
    256: "ffdhe2048",
    257: "ffdhe3072",
    # Chrome's PQ draft key share; BoringSSL still accepts the group name.
    25497: "X25519Kyber768Draft00",
}

# BoringSSL signature algorithm names (ssl/ssl_privkey.cc).
SIGALG_CODES = {
    0x0301: "rsa_pkcs1_sha224",
    0x0302: "dsa_sha224",
    0x0303: "ecdsa_sha224",
    0x0401: "rsa_pkcs1_sha256",
    0x0402: "dsa_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0502: "dsa_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0602: "dsa_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    # draft-ietf-tls-mldsa; BoringSSL rejects these names, so they stay visible
    # in the deviation note instead of being written to the cipher inputs.
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
}
SUPPORTED_SIGALGS = {
    # ML-DSA: the vendored BoringSSL passes these codepoints through
    # (scripts/boringssl/chrome4832.patch), so they reach the wire.
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "rsa_pkcs1_md5_sha1",
    "rsa_pkcs1_sha1",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha256_legacy",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ecdsa_sha1",
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "ed25519",
}

# ML-DSA codepoints: the vendored BoringSSL carries them through, so the
# generator maps them to names instead of leaving them as raw hex.
SIGALG_CODES.update({
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
})

# Extension ids in BoringSSL's kExtensions table (ssl/extensions.cc).
SUPPORTED_EXTENSIONS = {
    0, 5, 10, 11, 13, 14, 16, 18, 23, 27, 28, 34, 35, 41, 42, 43, 44, 45, 47,
    51, 57, 65037, 65281, 17513, 17613, 65445,
    # draft-ietf-tls-trust-anchors, sent when the caller supplies identifiers.
    51764,
    # Deprecated NPN, offered on request (same patch).
    13172,
    # Chromium's server padding request, added by scripts/boringssl/chrome4832.patch.
    4832,
    # Deprecated ChannelID, offered empty by Chrome 58-70 (same patch).
    30032,
}
EXTENSION_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    17: "status_request_v2",
    18: "signed_certificate_timestamp",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    27: "cert_compression",
    28: "record_size_limit",
    34: "delegated_credential",
    35: "session_ticket",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    65281: "renegotiation_info",
}

SETTING_IDS = {
    "HEADER_TABLE_SIZE": 1,
    "ENABLE_PUSH": 2,
    "MAX_CONCURRENT_STREAMS": 3,
    "INITIAL_WINDOW_SIZE": 4,
    "MAX_FRAME_SIZE": 5,
    "MAX_HEADER_LIST_SIZE": 6,
    "ENABLE_CONNECT_PROTOCOL": 8,
    "NO_RFC7540_PRIORITIES": 9,
}
PSEUDO_LETTERS = {
    ":method": "m",
    ":authority": "a",
    ":scheme": "s",
    ":path": "p",
}

PROFILES = [
    {
        "file": "go1.26.json",
        "name": "go1.26",
        "family": "go",
        "client": "Go net/http",
        "version": "go1.26.5",
        "platform": "linux",
    },
    {
        "file": "python3.12_requests.json",
        "name": "python3.12_requests",
        "family": "python",
        "client": "Python requests",
        "version": "2.32.5",
        "platform": "linux",
    },
    {
        "file": "python3.12_urllib.json",
        "name": "python3.12_urllib",
        "family": "python",
        "client": "Python urllib",
        "version": "3.12.3",
        "platform": "linux",
    },
    {
        "file": "python3.12_aiohttp.json",
        "name": "python3.12_aiohttp",
        "family": "python",
        "client": "Python aiohttp",
        "version": "3.14.0",
        "platform": "linux",
    },
    {
        "file": "curl8.5_h2.json",
        "name": "curl8.5_h2",
        "family": "curl",
        "client": "libcurl with OpenSSL, HTTP/2",
        "version": "8.5.0",
        "platform": "linux",
    },
    {
        "file": "curl8.5_http1.json",
        "name": "curl8.5_http1",
        "family": "curl",
        "client": "libcurl with OpenSSL, HTTP/1.1",
        "version": "8.5.0",
        "platform": "linux",
    },
    {
        "file": "java21_httpclient.json",
        "name": "java21_httpclient",
        "family": "java",
        "client": "Java HttpClient",
        "version": "21.0.12",
        "platform": "linux",
    },
    {
        "file": "java21_urlconn.json",
        "name": "java21_urlconn",
        "family": "java",
        "client": "Java HttpsURLConnection",
        "version": "21.0.12",
        "platform": "linux",
    },
    {
        "file": "node22_https.json",
        "name": "node22_https",
        "family": "node",
        "client": "Node.js HTTPS, HTTP/1.1",
        "version": "22.19.0",
        "platform": "linux",
    },
    {
        "file": "node22_http2.json",
        "name": "node22_http2",
        "family": "node",
        "client": "Node.js HTTP/2",
        "version": "22.19.0",
        "platform": "linux",
    },
    {
        "file": "node22_fetch.json",
        "name": "node22_fetch",
        "family": "node",
        "client": "Node.js global fetch (undici)",
        "version": "22.19.0",
        "platform": "linux",
    },
    {
        "file": "go1.26_http1.json",
        "name": "go1.26_http1",
        "family": "go",
        "client": "Go net/http, HTTP/1.1 only",
        "version": "go1.26.5",
        "platform": "linux",
    },
    {
        "file": "python3.12_httpx.json",
        "name": "python3.12_httpx",
        "family": "python",
        "client": "Python httpx",
        "version": "0.27.2",
        "platform": "linux",
    },
    {
        "file": "python3.12_httpclient.json",
        "name": "python3.12_httpclient",
        "family": "python",
        "client": "Python http.client",
        "version": "3.12.3",
        "platform": "linux",
    },
    {
        "file": "bun1.3.14.json",
        "name": "bun1.3.14",
        "family": "bun",
        "client": "Bun fetch",
        "version": "1.3.14",
        "platform": "linux",
    },
    {
        "file": "php8.3_curl.json",
        "name": "php8.3_curl",
        "family": "php",
        "client": "PHP curl extension",
        "version": "8.3.6",
        "platform": "linux",
    },
    {
        "file": "php8.3_streams.json",
        "name": "php8.3_streams",
        "family": "php",
        "client": "PHP stream wrapper",
        "version": "8.3.6",
        "platform": "linux",
    },
    {
        "file": "wget1.21.4.json",
        "name": "wget1.21.4",
        "family": "wget",
        "client": "GNU Wget with GnuTLS",
        "version": "1.21.4",
        "platform": "linux",
    },
    {
        "file": "perl5_lwp.json",
        "name": "perl5_lwp",
        "family": "perl",
        "client": "Perl LWP::UserAgent",
        "version": "LWP 6.76",
        "platform": "linux",
    },
    {
        "file": "openssl3_sclient.json",
        "name": "openssl3_sclient",
        "family": "openssl",
        "client": "OpenSSL s_client",
        "version": "3.0.13",
        "platform": "linux",
    },
    {
        "file": "rust_reqwest_rustls.json",
        "name": "rust_reqwest_rustls",
        "family": "rust",
        "client": "reqwest with rustls",
        "version": "reqwest 0.12.28 / rustls 0.23",
        "platform": "linux",
    },
    {
        "file": "chromium156.json",
        "name": "chromium156",
        "family": "chrome",
        "client": "Chromium (headless)",
        "version": "156.0.8078.47",
        "platform": "linux",
        # Two captures of the same build returned different extension orders,
        # so Chrome shuffles the extension list per connection. The recorded
        # order is the set BoringSSL should permute, not a fixed order.
        "permute_extensions": True,
    },
    {
        "file": "chromium157.json",
        "name": "chromium157",
        "family": "chrome",
        "client": "Chromium for Testing Stable (headless)",
        "version": "157.0.8103.78",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome114.json",
        "name": "chrome114",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "114.0.5696.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome116_cft.json",
        "name": "chrome116_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "116.0.5791.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome118.json",
        "name": "chrome118",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "118.0.5939.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome119_cft.json",
        "name": "chrome119_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "119.0.5997.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome121.json",
        "name": "chrome121",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "121.0.6100.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome122.json",
        "name": "chrome122",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "122.0.6168.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome123_cft.json",
        "name": "chrome123_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "123.0.6262.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome125.json",
        "name": "chrome125",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "125.0.6368.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome126.json",
        "name": "chrome126",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "126.0.6423.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome127.json",
        "name": "chrome127",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "127.0.6483.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome128.json",
        "name": "chrome128",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "128.0.6534.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome129.json",
        "name": "chrome129",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "129.0.6614.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome130.json",
        "name": "chrome130",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "130.0.6669.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome132.json",
        "name": "chrome132",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "132.0.6779.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome134.json",
        "name": "chrome134",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "134.0.6944.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome135.json",
        "name": "chrome135",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "135.0.6999.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome136_cft.json",
        "name": "chrome136_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "136.0.7051.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome137.json",
        "name": "chrome137",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "137.0.7104.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome138.json",
        "name": "chrome138",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "138.0.7152.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome139.json",
        "name": "chrome139",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "139.0.7205.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome140.json",
        "name": "chrome140",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "140.0.7259.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome141.json",
        "name": "chrome141",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "141.0.7340.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome142_cft.json",
        "name": "chrome142_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "142.0.7391.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome143.json",
        "name": "chrome143",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "143.0.7446.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome145_cft.json",
        "name": "chrome145_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "145.0.7561.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome147.json",
        "name": "chrome147",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "147.0.7681.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome148.json",
        "name": "chrome148",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "148.0.7728.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome149.json",
        "name": "chrome149",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "149.0.7779.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome151_cft.json",
        "name": "chrome151_cft",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "151.0.7872.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome153.json",
        "name": "chrome153",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "153.0.7978.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome154.json",
        "name": "chrome154",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "154.0.8011.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome155.json",
        "name": "chrome155",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "155.0.8038.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "android_webview125.json",
        "name": "android_webview125",
        "library": "webview",
        "family": "android",
        "client": "Android WebView (Chromium 125)",
        "version": "125.0.6422.113",
        "platform": "android",
        "permute_extensions": True,
        # The phone that supplied android_webview103 was updated to this
        # WebView between two capture runs, so both shapes are real: this
        # record's capture carries the padding extension; the device hello
        # did not, because random-length ECH GREASE made it longer than the
        # 256-511 byte padding window. Dropping extension 21 from this
        # record's fields gives c = 02713d6af862, exactly what the device
        # sent (t13d1516h2_8daaf6152771_02713d6af862).
        "source": (
            "tls.peet.ws capture of WebView 125.0.6422.113, confirmed on a "
            "OnePlus 9R running Android 13: the device's own WebView sends "
            "the same extension set and signature algorithms, and its JA4 "
            "differs only by the padding extension the transport adds when "
            "the hello fits the 256-511 byte window "
            "(t13d1516h2_8daaf6152771_02713d6af862 on the device); "
            "independently, the Android cloud phone (redroid Android 13, "
            "real network) loaded https://tls.peet.ws/api/all and the "
            "service itself reported t13d1517h2_8daaf6152771_b1ff8ab2d16f "
            "for that connection, the same padded shape; "
            "tools/capture/phone_capture.py, "
            "tools/capture/raw/android_webview125.json"
        ),
    },
    {
        # WebView 139 ships on the Android 10 redroid image. Its extension
        # set is WebView 125's, but it advertises ALPS at the newer
        # codepoint 17613, which moves the c hash.
        "file": "android_webview139_report.json",
        "name": "android_webview139",
        "library": "webview",
        "family": "android",
        "client": "Android WebView 139.0.7258.143",
        "version": "139.0.7258.143",
        "platform": "android",
        "permute_extensions": True,
        "source": (
            "ClientHello recorded off the wire from the system WebView "
            "139.0.7258.143 on a redroid Android 10 device (x86_64), "
            "tools/capture/android_matrix.py, "
            "tools/capture/raw/android_webview139_report.json"
        ),
    },
    {
        # Cronet 76 predates the ALPS extension and offers a 16th cipher, so
        # its a-segment is t13d1615, not the t13d1516 that 98 through 143
        # send. Captured on a redroid Android 13 device; the listener's
        # hello is the evidence, because this build's CONNECT proxy support
        # is too unreliable to reach tls.peet.ws through the relay.
        "file": "android_cronet76.json",
        "name": "android_cronet76",
        "library": "cronet",
        "family": "android",
        "client": "Cronet 76.0.3809.111 (embedded)",
        "version": "76.0.3809.111",
        "platform": "android",
        "permute_extensions": True,
        "source": (
            "ClientHello recorded off the wire from an APK that links "
            "cronet-embedded 76.0.3809.111, on a redroid Android 13 "
            "device (x86_64), tools/capture/phone_capture.py, "
            "tools/capture/raw/android_cronet76.json"
        ),
    },
    {
        # Cronet 101 and 119, linked as the only network stack in a probe
        # APK: the two Chromium versions send the same 16 ciphers and 16
        # extensions as WebView 125/139, with the padding extension.
        "file": "android_cronet101_echo.json",
        "name": "android_cronet101",
        "library": "cronet",
        "family": "android",
        "client": "Cronet 101.0.4951.41 (embedded)",
        "version": "101.0.4951.41",
        "platform": "android",
        "permute_extensions": True,
        "source": (
            "ClientHello recorded off the wire from an APK that links "
            "cronet-embedded 101.0.4951.41, on redroid Android 8.1 through "
            "14 devices (x86_64), tools/capture/android_matrix.py, "
            "tools/capture/raw/android_cronet101_echo.json"
        ),
    },
    {
        "file": "android_cronet119_echo.json",
        "name": "android_cronet119",
        # The listener saw this client padded (the hello was inside the
        # 256-511 byte window) and the echo did not (random-length ECH
        # GREASE made it longer), so the two shapes are c = b1ff8ab2d16f
        # and c = 02713d6af862 for one client. The record reproduces the
        # second, and the first needs extension 21 - see the wire test.
        "library": "cronet",
        "family": "android",
        "client": "Cronet 119.0.6045.31 (embedded)",
        "version": "119.0.6045.31",
        "platform": "android",
        "permute_extensions": True,
        "source": (
            "ClientHello recorded off the wire from an APK that links "
            "cronet-embedded 119.0.6045.31, on redroid Android 8.1 through "
            "14 devices (x86_64), tools/capture/android_matrix.py, "
            "tools/capture/raw/android_cronet119_echo.json"
        ),
    },
    {
        # Recorded off a real OnePlus 9R on Android 13: the system WebView's
        # own ClientHello, not an impersonation profile. The same device's
        # WebView matches android_mesh's JA4 exactly.
        "file": "android_webview103.json",
        "name": "android_webview103",
        "library": "webview",
        "family": "android",
        "client": "Android WebView 103.0.5060.129 (Chromium)",
        "version": "103.0.5060.129",
        "platform": "android",
        "permute_extensions": True,
        "source": (
            "ClientHello recorded off the wire from the system WebView "
            "103.0.5060.129 on a OnePlus 9R running Android 13, "
            "tools/capture/phone_capture.py, "
            "tools/capture/raw/android_webview103.json"
        ),
    },
    {
        # The platform stack reached through HttpsURLConnection: 17 ciphers
        # (the extra ECDSA CBC suites) and ALPN that offers only http/1.1.
        "file": "android_conscrypt13.json",
        "name": "android_conscrypt13",
        "library": "conscrypt",
        "family": "android",
        "client": "Android 13 platform TLS (HttpsURLConnection / Conscrypt)",
        "version": "13",
        "platform": "android",
        "source": (
            "ClientHello recorded off the wire from HttpsURLConnection on a "
            "OnePlus 9R running Android 13, confirmed by the tls.peet.ws "
            "report for the same connection (t13d1713h1_5b57614c22b0_"
            "eca864cca44a); the same hello was recorded off the Android "
            "cloud phone (redroid Android 13, real network, Conscrypt 2.5.2 "
            "as the provider), tools/capture/phone_capture.py, "
            "tools/capture/raw/android_conscrypt13.json"
        ),
    },
    {
        # Conscrypt 1.4.2 predates TLS 1.3 in this configuration and offers
        # no session_ticket, so its hello is the platform stack's TLS 1.2
        # predecessor: t12d1409h1.
        "file": "android_conscrypt1_4_2.json",
        "name": "android_conscrypt1_4_2",
        "library": "conscrypt",
        "family": "android",
        "client": "Conscrypt 1.4.2 on Android 13",
        "version": "1.4.2",
        "platform": "android",
        # The capture offers no TLS 1.3 suites and no supported_versions,
        # so the record has to cap the version explicitly; BoringSSL would
        # otherwise enable 1.3 by default and send a different hello.
        "min_version": "1.2",
        "max_version": "1.2",
        "source": (
            "ClientHello recorded off the wire from HttpsURLConnection with "
            "Conscrypt 1.4.2 installed as the JCA provider, on a redroid "
            "Android 13 device (x86_64), tools/capture/android_matrix.py, "
            "tools/capture/raw/android_conscrypt1_4_2.json"
        ),
    },
    {
        # Conscrypt 2.7 and later drop one extension, which moves both the
        # a-segment (t13d1712) and the c hash.
        "file": "android_conscrypt2_7_0.json",
        "name": "android_conscrypt2_7",
        "library": "conscrypt",
        "family": "android",
        "client": "Conscrypt 2.7.0 on Android 13",
        "version": "2.7.0",
        "platform": "android",
        "source": (
            "ClientHello recorded off the wire from HttpsURLConnection with "
            "Conscrypt 2.7.0 installed as the JCA provider, on a redroid "
            "Android 13 device (x86_64), tools/capture/android_matrix.py, "
            "tools/capture/raw/android_conscrypt2_7_0.json"
        ),
    },
    {
        # OkHttp 3.12 on Android 13 offers no ALPN and no session_ticket:
        # t13d1511 (ALPN 00), against OkHttp 4's t13d1513. The relayed
        # connection to tls.peet.ws came back t13d1510 because the CONNECT
        # proxy strips ALPN, so the direct listener capture is the evidence.
        "file": "android_okhttp3_12_0.json",
        "name": "android_okhttp3_12",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 3.12.0 on Android 13",
        "version": "3.12.0",
        "platform": "android",
        "source": (
            "ClientHello recorded off the wire from an APK that links OkHttp "
            "3.12.0, on a redroid Android 13 device (x86_64); this probe "
            "build sends no ALPN extension, so the a-segment reads "
            "t13d151100 where an uncapped 3.12 would read t13d1511h1 - the "
            "ciphers, extensions and c hash are the client's own, "
            "tools/capture/phone_capture.py, "
            "tools/capture/raw/android_okhttp3_12_0.json"
        ),
    },
    {
        # OkHttp 5 changed its TLS shape: the same 15 ciphers and signature
        # algorithms as 4.x but only 12 extensions (no session_ticket), hence
        # the a-segment t13d1512. Captured through the real service, so the
        # HTTP/2 settings are the server's record of what OkHttp 5 sent.
        "file": "android_okhttp5_sdk33.json",
        "name": "android_okhttp5",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 5.0.0 on Android 13",
        "version": "5.0.0",
        "platform": "android",
        "source": (
            "ClientHello recorded by a listener on a redroid Android 13 "
            "(SDK 33, x86_64) device running an APK that links OkHttp 5.0.0, "
            "then relayed to tls.peet.ws whose report (ja4, ja4_r, HTTP/2 "
            "frames, Akamai fingerprint) is stored here; "
            "tools/capture/phone_capture.py --echo, "
            "tools/capture/raw/android_okhttp5_sdk33.json"
        ),
    },
    {
        # OkHttp 3.14.9 sends what OkHttp 4 sends on the same TLS provider -
        # the difference between them is the Kotlin layer, not the hello.
        "file": "android_okhttp3_14_9_sdk33.json",
        "name": "android_okhttp3_14_9",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 3.14.9 on Android 13",
        "version": "3.14.9",
        "platform": "android",
        "source": (
            "ClientHello recorded by a listener on a redroid Android 13 "
            "(SDK 33, x86_64) device running an APK that links OkHttp 3.14.9, "
            "then relayed to tls.peet.ws whose report is stored here; the "
            "same hello OkHttp 4 sends on this platform; "
            "tools/capture/phone_capture.py --echo, "
            "tools/capture/raw/android_okhttp3_14_9_sdk33.json"
        ),
    },
    {
        "file": "webkitgtk26_4.json",
        "name": "webkitgtk26_4",
        "family": "safari",
        "library": "webkitgtk",
        "client": "WebKitGTK 2.52 (Linux)",
        "version": "26.4",
        "platform": "linux",
    },
    {
        "file": "tlsclient_safari27_2.json",
        "name": "tlsclient_safari27_2",
        "family": "safari",
        "library": "webkit-macos",
        "client": "Safari 27.2 (tls-client master profile)",
        "version": "27.2",
        "platform": "macos",
    },
    {
        "file": "cronet_android100.json",
        "name": "cronet_android100",
        "family": "android",
        "library": "cronet",
        "client": "Cronet 100.0.4891.0 (Chromium network stack in an Android app)",
        "version": "100",
        "platform": "android",
        "source": (
            "ClientHello recorded off the wire from a Cronet 100.0.4891.0 "
            "engine running on Android 13 (redroid), "
            "tools/capture/cronet_capture.py, "
            "tools/capture/raw/cronet_android100.json"
        ),
    },
    {
        "file": "swiftnio_ssl.json",
        "name": "swiftnio_ssl",
        "family": "ios",
        "library": "swiftnio",
        "client": "SwiftNIO / NIOSSL 2.36 (AsyncHTTPClient stack)",
        "version": "2.36",
        "source": (
            "ClientHello and HTTP/2 frames recorded off the wire from a "
            "swift-nio-ssl 2.36 + swift-nio-http2 client "
            "(tools/capture/swiftnio_capture.py), "
            "tools/capture/raw/swiftnio_ssl.json"
        ),
        "platform": "ios",
    },
    {
        "file": "chrome158.json",
        "name": "chrome158",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "158.0.8127.18",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome159.json",
        "name": "chrome159",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "159.0.8144.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "chrome160.json",
        "name": "chrome160",
        "family": "chrome",
        "client": "Chrome for Testing Canary (headless)",
        "version": "160.0.8167.0",
        "platform": "linux",
        "permute_extensions": True,
        # QUIC fields from the same binary's NetLog (--log-net-log
        # --net-log-capture-mode=IncludeSensitive) over a real H3 connection to
        # quic.nginx.org. Transport parameters and SETTINGS are what Chromium
        # logged as sent; the record's h2 pseudo order and settings carry over.
        "http3": {
            "settings": "1:65536;6:262144;7:100;51:1;GREASE",
            "pseudo_order": "masp",
            # NetLog over quic.nginx.org sends google_connection_options
            # ORIG,NOIP for a non-Google origin (ECCP is added only for
            # Google's own hosts), so the generic-origin value is recorded.
            # Eight real H3 requests in the NetLog agree on this order. The
            # navigations never happened, so upgrade-insecure-requests and
            # sec-fetch-user keep their position from the http2 capture.
            "header_order": (
                "sec-ch-ua-platform,user-agent,sec-ch-ua,sec-ch-ua-mobile,accept,"
                "sec-fetch-site,sec-fetch-mode,sec-fetch-dest,referer,"
                "accept-encoding,accept-language,priority"
            ),
            "transport_parameters": (
                # 14: active_connection_id_limit, which Chrome sends as 5.
                # Leaving it out makes the peer assume RFC 9000's default 2.
                "12584:0x4f5249474e4f4950;15:AUTO;GREASE;4:15728640;32:65536;"
                "5:6291456;9:103;1:30000;6:6291456;7:6291456;"
                "17:1@1,GREASE;3:1472;8:100;14:5"
            ),
        },
    },
    {
        "file": "firefox121.json",
        "name": "firefox121",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "121.0",
        "platform": "linux",
    },
    {
        "file": "firefox122.json",
        "name": "firefox122",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "122.0",
        "platform": "linux",
    },
    {
        "file": "firefox124.json",
        "name": "firefox124",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "124.0",
        "platform": "linux",
    },
    {
        "file": "firefox125.json",
        "name": "firefox125",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "125.0",
        "platform": "linux",
    },
    {
        "file": "firefox126.json",
        "name": "firefox126",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "126.0",
        "platform": "linux",
    },
    {
        "file": "firefox127.json",
        "name": "firefox127",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "127.0",
        "platform": "linux",
    },
    {
        "file": "firefox128.json",
        "name": "firefox128",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "128.0",
        "platform": "linux",
    },
    {
        "file": "firefox129.json",
        "name": "firefox129",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "129.0",
        "platform": "linux",
    },
    {
        "file": "firefox130.json",
        "name": "firefox130",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "130.0",
        "platform": "linux",
    },
    {
        "file": "firefox131.json",
        "name": "firefox131",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "131.0",
        "platform": "linux",
    },
    {
        "file": "firefox134.json",
        "name": "firefox134",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "134.0",
        "platform": "linux",
    },
    {
        "file": "firefox136.json",
        "name": "firefox136",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "136.0",
        "platform": "linux",
    },
    {
        "file": "firefox137.json",
        "name": "firefox137",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "137.0",
        "platform": "linux",
    },
    {
        "file": "firefox138.json",
        "name": "firefox138",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "138.0",
        "platform": "linux",
    },
    {
        "file": "firefox139.json",
        "name": "firefox139",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "139.0",
        "platform": "linux",
    },
    {
        "file": "firefox140.json",
        "name": "firefox140",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "140.0",
        "platform": "linux",
    },
    {
        "file": "firefox141.json",
        "name": "firefox141",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "141.0",
        "platform": "linux",
    },
    {
        "file": "firefox142.json",
        "name": "firefox142",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "142.0",
        "platform": "linux",
    },
    {
        "file": "firefox143.json",
        "name": "firefox143",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "143.0",
        "platform": "linux",
    },
    {
        "file": "firefox144_official.json",
        "name": "firefox144_official",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "144.0",
        "platform": "linux",
    },
    {
        "file": "firefox145.json",
        "name": "firefox145",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "145.0",
        "platform": "linux",
    },
    {
        "file": "firefox146.json",
        "name": "firefox146",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "146.0",
        "platform": "linux",
    },
    {
        "file": "firefox149.json",
        "name": "firefox149",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "149.0",
        "platform": "linux",
    },
    {
        "file": "firefox150.json",
        "name": "firefox150",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "150.0",
        "platform": "linux",
    },
    {
        "file": "firefox151.json",
        "name": "firefox151",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "151.0",
        "platform": "linux",
    },
    {
        "file": "firefox152.json",
        "name": "firefox152",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "152.0",
        "platform": "linux",
    },
    {
        "file": "firefox153_official.json",
        "name": "firefox153_official",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "153.0",
        "platform": "linux",
    },
    {
        "file": "firefox154_official.json",
        "name": "firefox154_official",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "154.0",
        "platform": "linux",
    },
    {
        "file": "firefox155_official.json",
        "name": "firefox155_official",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "155.0",
        "platform": "linux",
    },
    {
        "file": "firefox156.json",
        "name": "firefox156",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "156.0",
        "platform": "linux",
    },
    {
        "file": "firefox157.json",
        "name": "firefox157",
        "family": "firefox",
        "client": "Firefox (headless, official build)",
        "version": "157.0",
        "platform": "linux",
    },
    {
        "file": "firefox158.json",
        "name": "firefox158",
        "family": "firefox",
        "client": "Firefox (headless)",
        "version": "158.0.1",
        "platform": "linux",
    },
    {
        "file": "firefox159.json",
        "name": "firefox159",
        "family": "firefox",
        "client": "Firefox (headless)",
        "version": "159.0.1",
        "platform": "linux",
    },
    {
        "file": "firefox160.json",
        "name": "firefox160",
        "family": "firefox",
        "client": "Firefox (headless, candidate)",
        "version": "160.0",
        "platform": "linux",
    },
    {
        "file": "firefox161.json",
        "name": "firefox161",
        "family": "firefox",
        "client": "Firefox (headless, beta)",
        "version": "161.0b1",
        "platform": "linux",
    },
    {
        "file": "firefox162.json",
        "name": "firefox162",
        "family": "firefox",
        "client": "Firefox (headless, nightly)",
        "version": "162.0a1",
        "platform": "linux",
    },
    {
        "file": "android_confirmed.json",
        "name": "android_confirmed",
        "library": "conscrypt",
        "family": "android",
        "client": "Confirmed Android app (tls-client profile)",
        "version": "",
        "platform": "android",
    },
    {
        "file": "android_okhttp13.json",
        "name": "android_okhttp13",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4.12 on Android 13 (tls-client profile, verified on a device)",
        "version": "13",
        "platform": "android",
        "source": (
            "tls.peet.ws capture of the profile, matched byte for byte by a "
            "real OkHttp 4.12 client on a OnePlus 9R running Android 13 - same "
            "JA4, same server-side ja4_r, same HTTP/2 fingerprint - and again "
            "on the Android cloud phone (redroid Android 13, real network), "
            "where tls.peet.ws reported the same ja4 and Akamai fingerprint "
            "(tools/capture/phone_capture.py --echo), "
            "tools/capture/raw/android_okhttp13.json"
        ),
    },
    {
        "file": "android_confirmed2.json",
        "name": "android_confirmed2",
        "library": "conscrypt",
        "family": "android",
        "client": "Confirmed Android app, second profile (tls-client)",
        "version": "",
        "platform": "android",
    },
    {
        "file": "android_mesh.json",
        "name": "android_mesh",
        # A Chromium-shaped hello (GREASE, SCT, old ALPS, compress_certificate)
        # whose JA4 and extension order are exactly those of the system WebView
        # recorded on a real Android 13 phone: the app renders in a WebView,
        # not in Conscrypt.
        "library": "webview",
        "family": "android",
        "client": "Mesh Android app, system WebView (tls-client profile)",
        "version": "",
        "platform": "android",
    },
    {
        "file": "android_mesh1.json",
        "name": "android_mesh1",
        "library": "conscrypt",
        "family": "android",
        "client": "Mesh Android app, HTTP/1.1 (tls-client profile)",
        "version": "",
        "platform": "android",
    },
    {
        "file": "android_okhttp7.json",
        "name": "android_okhttp7",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 7 (tls-client profile)",
        "version": "7",
        "platform": "android",
    },
    {
        "file": "android_okhttp8.json",
        "name": "android_okhttp8",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 8 (tls-client profile)",
        "version": "8",
        "platform": "android",
        # The tls.peet.ws capture of this profile printed the extension
        # count as one digit; the ciphers, extensions, signature algorithms
        # and both hashes match the hello an APK linking OkHttp 4.12 sent on
        # a redroid Android 8.1 device (tools/capture/android_matrix.py).
        # Its ciphers hash to d34a8e72043a, the cipher list an OkHttp 3.12
        # capped at TLS 1.2 sent on a real Android 13 device. The TLS 1.2
        # extension list itself has not been reproduced on a device,
        # because no Android 8.1 runtime is available here; the capture's
        # a-segment also had a one-digit extension count, corrected in the
        # raw.
        "source": "tls.peet.ws capture, tools/capture/raw/android_okhttp8.json",
    },
    {
        "file": "android_okhttp9.json",
        "name": "android_okhttp9",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 9 (tls-client profile)",
        "version": "9",
        "platform": "android",
        # The tls.peet.ws capture of this profile printed the extension
        # count as one digit; the ciphers, extensions, signature algorithms
        # and both hashes match the hello an APK linking OkHttp 4.12 sent on
        # a redroid Android 9 device (tools/capture/android_matrix.py).
        # Its ciphers hash to d34a8e72043a, the cipher list an OkHttp 3.12
        # capped at TLS 1.2 sent on a real Android 13 device. The TLS 1.2
        # extension list itself has not been reproduced on a device,
        # because no Android 9 runtime is available here; the capture's
        # a-segment also had a one-digit extension count, corrected in the
        # raw.
        "source": "tls.peet.ws capture, tools/capture/raw/android_okhttp9.json",
    },
    {
        "file": "android_okhttp10.json",
        "name": "android_okhttp10",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 10 (tls-client profile)",
        "version": "10",
        "platform": "android",
    },
    {
        "file": "android_okhttp11.json",
        "name": "android_okhttp11",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 11 (tls-client profile)",
        "version": "11",
        "platform": "android",
    },
    {
        "file": "android_okhttp12.json",
        "name": "android_okhttp12",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 12 (tls-client profile)",
        "version": "12",
        "platform": "android",
    },
    {
        "file": "android_nike.json",
        "name": "android_nike",
        "library": "conscrypt",
        "family": "android",
        "client": "Nike Android app (tls-client profile)",
        "version": "",
        "platform": "android",
    },
    {
        "file": "android_zalando.json",
        "name": "android_zalando",
        "library": "conscrypt",
        "family": "android",
        "client": "Zalando Android app (tls-client profile)",
        "version": "",
        "platform": "android",
    },
    {
        "file": "ios_confirmed.json",
        "name": "ios_confirmed",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (Confirmed profile)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "ios_safari18_5.json",
        "name": "ios_safari18_5",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 18.5",
        "version": "18.5",
        "platform": "ios",
    },
    {
        "file": "ios_safari26.json",
        "name": "ios_safari26",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 26.0",
        "version": "26.0",
        "platform": "ios",
    },
    {
        "file": "opera91.json",
        "name": "opera91",
        "family": "opera",
        "client": "Opera (tls-client profile)",
        "version": "91",
        "platform": "windows",
    },
    {
        "file": "tlsclient_brave146.json",
        "name": "tlsclient_brave146",
        "family": "brave",
        "client": "Brave (tls-client profile)",
        "version": "146",
        "platform": "windows",
    },
    {
        "file": "tlsclient_cloudflare.json",
        "name": "tlsclient_cloudflare",
        "family": "cloudflare",
        "client": "Cloudflare custom profile (tls-client)",
        "version": "custom",
        "platform": "linux",
    },
    {
        "file": "tlsclient_chrome103.json",
        "name": "tlsclient_chrome103",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "103",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome104.json",
        "name": "tlsclient_chrome104",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "104",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome105.json",
        "name": "tlsclient_chrome105",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "105",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome106.json",
        "name": "tlsclient_chrome106",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "106",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome107.json",
        "name": "tlsclient_chrome107",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "107",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome108.json",
        "name": "tlsclient_chrome108",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "108",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome109.json",
        "name": "tlsclient_chrome109",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "109",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome110.json",
        "name": "tlsclient_chrome110",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "110",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome111.json",
        "name": "tlsclient_chrome111",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "111",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome112.json",
        "name": "tlsclient_chrome112",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "112",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome117.json",
        "name": "tlsclient_chrome117",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "117",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome120.json",
        "name": "tlsclient_chrome120",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "120",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome124.json",
        "name": "tlsclient_chrome124",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "124",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome131.json",
        "name": "tlsclient_chrome131",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "131",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome133.json",
        "name": "tlsclient_chrome133",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "133",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome144.json",
        "name": "tlsclient_chrome144",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "144",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome146.json",
        "name": "tlsclient_chrome146",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "146",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome150.json",
        "name": "tlsclient_chrome150",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "150",
        "platform": "windows",
    },
    {
        "file": "tlsclient_chrome152.json",
        "name": "tlsclient_chrome152",
        "family": "chrome",
        "client": "Chrome (tls-client profile)",
        "version": "152",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox102.json",
        "name": "tlsclient_firefox102",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "102",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox104.json",
        "name": "tlsclient_firefox104",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "104",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox105.json",
        "name": "tlsclient_firefox105",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "105",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox106.json",
        "name": "tlsclient_firefox106",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "106",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox108.json",
        "name": "tlsclient_firefox108",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "108",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox110.json",
        "name": "tlsclient_firefox110",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "110",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox117.json",
        "name": "tlsclient_firefox117",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "117",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox120.json",
        "name": "tlsclient_firefox120",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "120",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox123.json",
        "name": "tlsclient_firefox123",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "123",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox132.json",
        "name": "tlsclient_firefox132",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "132",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox133.json",
        "name": "tlsclient_firefox133",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "133",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox135.json",
        "name": "tlsclient_firefox135",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "135",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox147.json",
        "name": "tlsclient_firefox147",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "147",
        "platform": "windows",
    },
    {
        "file": "tlsclient_firefox148.json",
        "name": "tlsclient_firefox148",
        "family": "firefox",
        "client": "Firefox (tls-client profile)",
        "version": "148",
        "platform": "windows",
    },
    {
        "file": "tlsclient_opera89.json",
        "name": "tlsclient_opera89",
        "family": "opera",
        "client": "Opera (tls-client profile)",
        "version": "89",
        "platform": "windows",
    },
    {
        "file": "tlsclient_opera90.json",
        "name": "tlsclient_opera90",
        "family": "opera",
        "client": "Opera (tls-client profile)",
        "version": "90",
        "platform": "windows",
    },
    {
        "file": "tlsclient_safari15_6_1.json",
        "name": "tlsclient_safari15_6_1",
        "library": "webkit-macos",
        "family": "safari",
        "client": "Safari on macOS (tls-client profile)",
        "version": "15.6.1",
        "platform": "macos",
    },
    {
        "file": "tlsclient_safari16.json",
        "name": "tlsclient_safari16",
        "library": "webkit-macos",
        "family": "safari",
        "client": "Safari on macOS (tls-client profile)",
        "version": "16.0",
        "platform": "macos",
    },
    {
        "file": "tlsclient_safari_ipad15_6.json",
        "name": "tlsclient_safari_ipad15_6",
        "library": "webkit",
        "family": "safari",
        "client": "Safari on iPad (tls-client profile)",
        "version": "15.6",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mms.json",
        "name": "tlsclient_ios_mms",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (MMS profile)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mms2.json",
        "name": "tlsclient_ios_mms2",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (MMS profile 2)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mms3.json",
        "name": "tlsclient_ios_mms3",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (MMS profile 3)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mesh.json",
        "name": "tlsclient_ios_mesh",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (Mesh profile)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mesh2.json",
        "name": "tlsclient_ios_mesh2",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (Mesh profile 2)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_nike.json",
        "name": "tlsclient_ios_nike",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (Nike profile)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_zalando.json",
        "name": "tlsclient_ios_zalando",
        "family": "ios",
        "library": "cfnetwork",
        "client": "NSURLSession app (Zalando profile)",
        "version": "",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari15_5.json",
        "name": "tlsclient_ios_safari15_5",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 15.5",
        "version": "15.5",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari15_6.json",
        "name": "tlsclient_ios_safari15_6",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 15.6",
        "version": "15.6",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari16.json",
        "name": "tlsclient_ios_safari16",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 16.0",
        "version": "16.0",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari17.json",
        "name": "tlsclient_ios_safari17",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 17.0",
        "version": "17.0",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari18.json",
        "name": "tlsclient_ios_safari18",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 18.0",
        "version": "18.0",
        "platform": "ios",
    },
    {
        "file": "utls_chrome58.json",
        "name": "utls_chrome58",
        "family": "chrome",
        "client": "Chrome 58 (uTLS ClientHello)",
        "version": "58",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome62.json",
        "name": "utls_chrome62",
        "family": "chrome",
        "client": "Chrome 62 (uTLS ClientHello)",
        "version": "62",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome70.json",
        "name": "utls_chrome70",
        "family": "chrome",
        "client": "Chrome 70 (uTLS ClientHello)",
        "version": "70",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome72.json",
        "name": "utls_chrome72",
        "family": "chrome",
        "client": "Chrome 72 (uTLS ClientHello)",
        "version": "72",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome83.json",
        "name": "utls_chrome83",
        "family": "chrome",
        "client": "Chrome 83 (uTLS ClientHello)",
        "version": "83",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome87.json",
        "name": "utls_chrome87",
        "family": "chrome",
        "client": "Chrome 87 (uTLS ClientHello)",
        "version": "87",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome96.json",
        "name": "utls_chrome96",
        "family": "chrome",
        "client": "Chrome 96 (uTLS ClientHello)",
        "version": "96",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome100.json",
        "name": "utls_chrome100",
        "family": "chrome",
        "client": "Chrome 100 (uTLS ClientHello)",
        "version": "100",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome102.json",
        "name": "utls_chrome102",
        "family": "chrome",
        "client": "Chrome 102 (uTLS ClientHello)",
        "version": "102",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome106shuffle.json",
        "name": "utls_chrome106shuffle",
        "family": "chrome",
        "client": "Chrome 106 with shuffled extensions (uTLS)",
        "version": "106 shuffled",
        "platform": "windows",
        "http1_capture": True,
        "permute_extensions": True,
    },
    {
        "file": "utls_chrome115pq.json",
        "name": "utls_chrome115pq",
        "family": "chrome",
        "client": "Chrome 115 with PQ key share (uTLS)",
        "version": "115 PQ",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome120.json",
        "name": "utls_chrome120",
        "family": "chrome",
        "client": "Chrome 120 (uTLS ClientHello)",
        "version": "120",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome120pq.json",
        "name": "utls_chrome120pq",
        "family": "chrome",
        "client": "Chrome 120 with PQ key share (uTLS)",
        "version": "120 PQ",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome131.json",
        "name": "utls_chrome131",
        "family": "chrome",
        "client": "Chrome 131 (uTLS ClientHello)",
        "version": "131",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_chrome133.json",
        "name": "utls_chrome133",
        "family": "chrome",
        "client": "Chrome 133 (uTLS ClientHello)",
        "version": "133",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox55.json",
        "name": "utls_firefox55",
        "family": "firefox",
        "client": "Firefox 55 (uTLS ClientHello)",
        "version": "55",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox56.json",
        "name": "utls_firefox56",
        "family": "firefox",
        "client": "Firefox 56 (uTLS ClientHello)",
        "version": "56",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox63.json",
        "name": "utls_firefox63",
        "family": "firefox",
        "client": "Firefox 63 (uTLS ClientHello)",
        "version": "63",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox65.json",
        "name": "utls_firefox65",
        "family": "firefox",
        "client": "Firefox 65 (uTLS ClientHello)",
        "version": "65",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox99.json",
        "name": "utls_firefox99",
        "family": "firefox",
        "client": "Firefox 99 (uTLS ClientHello)",
        "version": "99",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox102.json",
        "name": "utls_firefox102",
        "family": "firefox",
        "client": "Firefox 102 (uTLS ClientHello)",
        "version": "102",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox105.json",
        "name": "utls_firefox105",
        "family": "firefox",
        "client": "Firefox 105 (uTLS ClientHello)",
        "version": "105",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_firefox120.json",
        "name": "utls_firefox120",
        "family": "firefox",
        "client": "Firefox 120 (uTLS ClientHello)",
        "version": "120",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_safari16.json",
        "name": "utls_safari16",
        "library": "webkit-macos",
        "family": "safari",
        "client": "Safari 16.0 (uTLS ClientHello)",
        "version": "16.0",
        "platform": "macos",
        "http1_capture": True,
    },
    {
        "file": "utls_ios11.json",
        "name": "utls_ios11",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 11.1 (uTLS)",
        "version": "11.1",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_ios12.json",
        "name": "utls_ios12",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 12.1 (uTLS)",
        "version": "12.1",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_ios13.json",
        "name": "utls_ios13",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 13 (uTLS)",
        "version": "13.0",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_ios14.json",
        "name": "utls_ios14",
        "family": "ios",
        "library": "webkit",
        "client": "Safari on iOS 14 (uTLS)",
        "version": "14.0",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_android11okhttp.json",
        "name": "utls_android11okhttp",
        "library": "conscrypt",
        "family": "okhttp",
        "client": "OkHttp on Android 11 (uTLS ClientHello)",
        "version": "11",
        "platform": "android",
        "http1_capture": True,
        # The profile was defined by the uTLS library, but the hello it
        # defines is the one OkHttp sends on Android 8-11: OkHttp 3.12
        # capped at TLS 1.2 on a real Android 13 device produced the same
        # c hash (036209cd1ead) with the same 12 ciphers, extensions and
        # signature algorithms. Only the ALPN label differs, because that
        # capture went through the capped socket factory.
        "source": (
            "tls.peet.ws capture of the uTLS ClientHelloID for "
            "android11okhttp (refraction-networking/utls, sent by its Go "
            "harness); the shape is confirmed on real hardware by OkHttp "
            "3.12 with TLS 1.2 capped on an Android 13 device - same "
            "ciphers, extensions, signature algorithms and c hash "
            "(036209cd1ead), tools/capture/raw/utls_android11okhttp.json"
        ),
    },
    {
        "file": "utls_edge85.json",
        "name": "utls_edge85",
        "family": "edge",
        "client": "Edge 85 (uTLS ClientHello)",
        "version": "85",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_edge106.json",
        "name": "utls_edge106",
        "family": "edge",
        "client": "Edge 106 (uTLS ClientHello)",
        "version": "106",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_360_7_5.json",
        "name": "utls_360_7_5",
        "family": "360",
        "client": "360 Browser 7.5 (uTLS ClientHello)",
        "version": "7.5",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_360_11_0.json",
        "name": "utls_360_11_0",
        "family": "360",
        "client": "360 Browser 11.0 (uTLS ClientHello)",
        "version": "11.0",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "utls_qq11_1.json",
        "name": "utls_qq11_1",
        "family": "qq",
        "client": "QQ Browser 11.1 (uTLS ClientHello)",
        "version": "11.1",
        "platform": "windows",
        "http1_capture": True,
    },
    {
        "file": "go1.21.json",
        "name": "go1.21",
        "family": "go",
        "client": "Go net/http",
        "version": "go1.21.13",
        "platform": "linux",
    },
    {
        "file": "go1.22.json",
        "name": "go1.22",
        "family": "go",
        "client": "Go net/http",
        "version": "go1.22.x",
        "platform": "linux",
    },
    {
        "file": "go1.23.json",
        "name": "go1.23",
        "family": "go",
        "client": "Go net/http",
        "version": "go1.23.x",
        "platform": "linux",
    },
    {
        "file": "go1.24.json",
        "name": "go1.24",
        "family": "go",
        "client": "Go net/http",
        "version": "go1.24.x",
        "platform": "linux",
    },
    {
        "file": "node24_https.json",
        "name": "node24_https",
        "family": "node",
        "client": "Node.js https",
        "version": "24 (OpenSSL 3.5)",
        "platform": "linux",
    },
    {
        "file": "node24_http2.json",
        "name": "node24_http2",
        "family": "node",
        "client": "Node.js http2",
        "version": "24 (OpenSSL 3.5)",
        "platform": "linux",
    },
    {
        "file": "curl7.88.1_h2.json",
        "name": "curl7.88.1_h2",
        "family": "curl",
        "client": "libcurl with OpenSSL, HTTP/2",
        "version": "7.88.1 (OpenSSL 1.1.1t)",
        "platform": "linux",
    },
    {
        "file": "curl7.88.1_http1.json",
        "name": "curl7.88.1_http1",
        "family": "curl",
        "client": "libcurl with OpenSSL, HTTP/1.1",
        "version": "7.88.1 (OpenSSL 1.1.1t)",
        "platform": "linux",
    },
    {
        "file": "curl8.10.1_h2.json",
        "name": "curl8.10.1_h2",
        "family": "curl",
        "client": "libcurl with OpenSSL, HTTP/2",
        "version": "8.10.1 (OpenSSL 3.x)",
        "platform": "linux",
    },
    {
        "file": "curl8.10.1_http1.json",
        "name": "curl8.10.1_http1",
        "family": "curl",
        "client": "libcurl with OpenSSL, HTTP/1.1",
        "version": "8.10.1 (OpenSSL 3.x)",
        "platform": "linux",
    },
    {
        "file": "python3.9_urllib.json",
        "name": "python3.9_urllib",
        "family": "python",
        "client": "Python urllib",
        "version": "3.9.24 (OpenSSL 3.5)",
        "platform": "linux",
    },
    {
        "file": "python3.11_urllib.json",
        "name": "python3.11_urllib",
        "family": "python",
        "client": "Python urllib",
        "version": "3.10-3.13 (OpenSSL 3.5)",
        "platform": "linux",
    },
    {
        "file": "java8_urlconn.json",
        "name": "java8_urlconn",
        "family": "java",
        "client": "Java HttpsURLConnection",
        "version": "8u504",
        "platform": "linux",
    },
    {
        "file": "java11_httpclient.json",
        "name": "java11_httpclient",
        "family": "java",
        "client": "Java HttpClient",
        "version": "11 (Temurin)",
        "platform": "linux",
    },
    {
        "file": "java11_urlconn.json",
        "name": "java11_urlconn",
        "family": "java",
        "client": "Java HttpsURLConnection",
        "version": "11 (Temurin)",
        "platform": "linux",
    },
    {
        "file": "java17_urlconn.json",
        "name": "java17_urlconn",
        "family": "java",
        "client": "Java HttpsURLConnection",
        "version": "17 (Temurin)",
        "platform": "linux",
    },
    {
        "file": "openssl1.1_sclient.json",
        "name": "openssl1.1_sclient",
        "family": "openssl",
        "client": "OpenSSL s_client",
        "version": "1.1.1w (Alpine 3.15)",
        "platform": "linux",
    },
    {
        "file": "openssl3.3_sclient.json",
        "name": "openssl3.3_sclient",
        "family": "openssl",
        "client": "OpenSSL s_client",
        "version": "3.3.7 (Alpine 3.20)",
        "platform": "linux",
    },
    {
        "file": "wget1.21_bookworm.json",
        "name": "wget1.21_bookworm",
        "family": "wget",
        "client": "GNU Wget + GnuTLS",
        "version": "1.21.3 (Debian bookworm)",
        "platform": "linux",
    },
    {
        "file": "php8.1_streams.json",
        "name": "php8.1_streams",
        "family": "php",
        "client": "PHP streams",
        "version": "8.1.34 (OpenSSL 3.5)",
        "platform": "linux",
    },
    {
        "file": "go1.20.json",
        "name": "go1.20",
        "family": "go",
        "client": "Go net/http",
        "version": "go1.20 (pre-1.21 extension set)",
        "platform": "linux",
    },
    {
        "file": "python3.8_urllib.json",
        "name": "python3.8_urllib",
        "family": "python",
        "client": "Python urllib",
        "version": "3.8.20 (OpenSSL 1.1.1)",
        "platform": "linux",
    },
    {
        "file": "ruby3.3_nethttp.json",
        "name": "ruby3.3_nethttp",
        "family": "ruby",
        "client": "Ruby Net::HTTP",
        "version": "3.3.13 (OpenSSL 3.5)",
        "platform": "linux",
    },
    {
        "file": "deno_fetch.json",
        "name": "deno_fetch",
        "family": "deno",
        "client": "Deno fetch",
        "version": "2.9.8 (rustls)",
        "platform": "linux",
    },
    {
        "file": "dart_httpclient.json",
        "name": "dart_httpclient",
        "family": "dart",
        "client": "Dart dart:io HttpClient",
        "version": "3.13",
        "platform": "linux",
    },
    {
        "file": "erlang_ssl.json",
        "name": "erlang_ssl",
        "family": "erlang",
        "client": "Erlang/OTP ssl over httpc",
        "version": "OTP 27",
        "platform": "linux",
    },
    {
        "file": "dotnet8_http1.json",
        "name": "dotnet8_http1",
        "family": "dotnet",
        "client": ".NET HttpClient, HTTP/1.1",
        "version": "8.0.33 (SocketsHttpHandler + OpenSSL)",
        "platform": "linux",
    },
    {
        "file": "chrome113.json",
        "name": "chrome113",
        "family": "chrome",
        "client": "Chrome for Testing (headless)",
        "version": "113.0.5672.0",
        "platform": "linux",
        "permute_extensions": True,
    },
    {
        "file": "dotnet8_http2.json",
        "name": "dotnet8_http2",
        "family": "dotnet",
        "client": ".NET HttpClient, HTTP/2",
        "version": "8.0.33 (SocketsHttpHandler + OpenSSL)",
        "platform": "linux",
    },
]

ALIASES = [
    ("chrome_android", "chrome131_android", "chrome", "Chrome for Android", "android"),
    ("safari_ios", "safari270_ios", "safari", "Safari on iOS", "ios"),
    ("okhttp_android", "okhttp4_android", "okhttp", "OkHttp on Android", "android"),
    # One alias per library version the grid actually captured, so a caller
    # can ask for the version rather than for the base record. Each points
    # at a record built from a real ClientHello; the name says which build
    # produced it.
    ("okhttp_4_9_3_android", "android_okhttp13", "okhttp",
     "OkHttp 4.9.3 on Android (captured on SDK 29-34)", "android"),
    ("okhttp_4_10_0_android", "android_okhttp13", "okhttp",
     "OkHttp 4.10.0 on Android (captured on SDK 29-34)", "android"),
    ("okhttp_4_12_0_android", "android_okhttp13", "okhttp",
     "OkHttp 4.12.0 on Android (captured on SDK 29-34)", "android"),
    ("conscrypt_2_1_0_android", "android_conscrypt13", "conscrypt",
     "Conscrypt 2.1.0 on Android 13 runtime (SDK 27-34)", "android"),
    ("cronet_98_android", "android_cronet101", "cronet",
     "Cronet 98.0.4758.87 on Android (captured on SDK 33)", "android"),
    ("cronet_102_android", "android_cronet101", "cronet",
     "Cronet 102.5005.125 on Android (captured on SDK 33)", "android"),
    ("cronet_108_android", "android_cronet101", "cronet",
     "Cronet 108.5359.79 on Android (captured on SDK 33)", "android"),
    ("okhttp_5_1_0_android", "android_okhttp5", "okhttp",
     "OkHttp 5.1.0 on Android (captured on SDK 33)", "android"),
    ("okhttp_5_2_2_android", "android_okhttp5", "okhttp",
     "OkHttp 5.2.2 on Android (captured on SDK 33)", "android"),
    ("okhttp_5_3_2_android", "android_okhttp5", "okhttp",
     "OkHttp 5.3.2 on Android (captured on SDK 33)", "android"),
    ("okhttp_5_4_0_android", "android_okhttp5", "okhttp",
     "OkHttp 5.4.0 on Android (captured on SDK 33)", "android"),
    ("okhttp_5_5_1_android", "android_okhttp5", "okhttp",
     "OkHttp 5.5.1 on Android (captured on SDK 33)", "android"),
    ("okhttp_3_12_0_android", "android_okhttp3_12", "okhttp",
     "OkHttp 3.12.0 on Android (captured on SDK 33)", "android"),
    ("conscrypt_2_7_0_android", "android_conscrypt2_7", "conscrypt",
     "Conscrypt 2.7.0 on Android (captured on SDK 33)", "android"),
    ("conscrypt_1_4_2_android", "android_conscrypt1_4_2", "conscrypt",
     "Conscrypt 1.4.2 on Android (captured on SDK 33)", "android"),
    ("conscrypt_2_5_2_android", "android_conscrypt13", "conscrypt",
     "Conscrypt 2.5.2 on Android 13 runtime (SDK 27-34)", "android"),
    ("golang", "go1.26", "go", "Go net/http", "linux"),
    ("python", "python3.12_requests", "python", "Python requests", "linux"),
    ("curl", "curl8.5_h2", "curl", "libcurl with OpenSSL", "linux"),
    ("java", "java21_httpclient", "java", "Java HttpClient", "linux"),
    ("node", "node22_http2", "node", "Node.js HTTP/2", "linux"),
    ("bun", "bun1.3.14", "bun", "Bun fetch", "linux"),
    ("php", "php8.3_curl", "php", "PHP curl extension", "linux"),
    ("wget", "wget1.21.4", "wget", "GNU Wget", "linux"),
    ("perl", "perl5_lwp", "perl", "Perl LWP::UserAgent", "linux"),
    ("rust", "rust_reqwest_rustls", "rust", "reqwest with rustls", "linux"),
    ("httpx", "python3.12_httpx", "python", "Python httpx", "linux"),
    ("chrome", "chromium156", "chrome", "Chromium", "linux"),
    ("firefox", "firefox158", "firefox", "Firefox", "linux"),
    ("android", "android_okhttp13", "okhttp", "OkHttp on Android", "android"),
    ("android7", "android_okhttp7", "okhttp", "OkHttp on Android 7", "android"),
    ("android8", "android_okhttp8", "okhttp", "OkHttp on Android 8", "android"),
    ("android9", "android_okhttp9", "okhttp", "OkHttp on Android 9", "android"),
    ("android10", "android_okhttp10", "okhttp", "OkHttp on Android 10", "android"),
    ("android11", "android_okhttp11", "okhttp", "OkHttp on Android 11", "android"),
    ("android12", "android_okhttp12", "okhttp", "OkHttp on Android 12", "android"),
    ("nike", "android_nike", "android", "Nike Android app", "android"),
    ("zalando", "android_zalando", "android", "Zalando Android app", "android"),
    ("ios", "ios_safari26", "safari", "Safari on iOS", "ios"),
    ("opera", "opera91", "opera", "Opera", "windows"),
    ("openssl", "openssl3_sclient", "openssl", "OpenSSL s_client", "linux"),
    ("ruby", "ruby3.3_nethttp", "ruby", "Ruby Net::HTTP", "linux"),
    ("deno", "deno_fetch", "deno", "Deno fetch", "linux"),
    ("dart", "dart_httpclient", "dart", "Dart dart:io HttpClient", "linux"),
    ("erlang", "erlang_ssl", "erlang", "Erlang/OTP ssl", "linux"),
    ("dotnet", "dotnet8_http2", "dotnet", ".NET HttpClient", "linux"),
]

GROUP_CODES_BY_NAME = {
    "X25519MLKEM768": "X25519MLKEM768",
    "X25519": "X25519",
    "P-256": "P-256",
    "P-384": "P-384",
    "P-521": "P-521",
    "ffdhe2048": "ffdhe2048",
    "ffdhe3072": "ffdhe3072",
    "X25519Kyber768Draft00": "X25519Kyber768Draft00",
}


TLS13_CIPHERS = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}


def is_tls13(name):
    return name in TLS13_CIPHERS


SUPPORTED_CERT_COMPRESSION = {"zlib", "brotli", "zstd"}


def extension_id(entry):
    match = re.search(r"\((\d+)\)", entry["name"])
    if match is None:
        # tls.peet.ws prints extensions it does not know by number, e.g.
        # "Unknown extension 51764".
        match = re.search(r"extension (\d+)$", entry["name"])
    return int(match.group(1)) if match else None


def grease_code(code):
    """GREASE values are 0x?a?a: both bytes equal with a low nibble of a."""
    return (code >> 8) == (code & 0xFF) and (code & 0x0F) == 0x0A


def is_grease_label(label):
    return "GREASE" in label


def parse_hex(value):
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def extension_map(tls):
    out = {}
    for entry in tls["extensions"]:
        ext_id = extension_id(entry)
        if ext_id is not None:
            out[ext_id] = entry
    return out


def group_name(label):
    """Map a captured supported_groups label to a BoringSSL group name."""
    code = re.search(r"\((\d+)\)", label)
    if code:
        return GROUP_CODES.get(int(code.group(1)))
    unknown = re.search(r"Unknown curve (\d+)", label)
    if unknown:
        return GROUP_CODES.get(int(unknown.group(1)))
    return GROUP_CODES_BY_NAME.get(label)


def sigalgs_from(tls):
    for entry in tls["extensions"]:
        if entry["name"].startswith("signature_algorithms (13)"):
            values = entry.get("signature_algorithms") or []
            out = []
            for value in values:
                if value.startswith("0x"):
                    code = int(value, 16)
                    out.append(SIGALG_CODES.get(code, value))
                else:
                    out.append(value)
            return out
    return []


def summarize(label, dropped, kept):
    if not dropped:
        return None
    shown = dropped if len(dropped) <= 4 else dropped[:4]
    more = "" if len(dropped) <= 4 else f" and {len(dropped) - 4} more"
    return (
        f"BoringSSL cannot send {len(dropped)} captured {label}: "
        + ", ".join(shown)
        + more
        + f" ({len(kept)} sent)."
    )


SIGALG_NAME_TO_CODE = {
    "ecdsa_secp256r1_sha256": 0x0403,
    "ecdsa_secp384r1_sha384": 0x0503,
    "ecdsa_secp521r1_sha512": 0x0603,
    "rsa_pss_rsae_sha256": 0x0804,
    "rsa_pss_rsae_sha384": 0x0805,
    "rsa_pss_rsae_sha512": 0x0806,
    "rsa_pkcs1_sha256": 0x0401,
    "rsa_pkcs1_sha384": 0x0501,
    "rsa_pkcs1_sha512": 0x0601,
    "ed25519": 0x0807,
    "rsa_pkcs1_sha1": 0x0201,
    "ecdsa_sha1": 0x0203,
    "mldsa44": 0x0904,
    "mldsa65": 0x0905,
    "mldsa87": 0x0906,
}


def sigalg_code(name):
    """Map a captured signature algorithm label to its code point."""
    if isinstance(name, int):
        return name
    text = str(name)
    if text.startswith("0x"):
        return int(text, 16)
    return SIGALG_NAME_TO_CODE.get(text)



def capture_source(name, filename):
    """Say what kind of client produced a capture, not just where the file is.

    The `utls_` and `tlsclient_` records are a library's ClientHello definition
    sent by a Go harness. That is a real handshake against tls.peet.ws - the
    bytes are genuine - but the client is the profile, not a browser process,
    and the source line should not read as if a browser had been run.
    """
    path = "tools/capture/raw/" + filename
    if name.startswith("utls_"):
        return (
            "tls.peet.ws capture of the uTLS ClientHelloID for "
            + name[len("utls_"):] + " (refraction-networking/utls, sent by "
            "its Go harness), " + path
        )
    if name.startswith("tlsclient_"):
        return (
            "tls.peet.ws capture of the tls-client profile "
            + name[len("tlsclient_"):] + " (bogdanfinn/tls-client, sent by "
            "its Go harness), " + path
        )
    return "tls.peet.ws capture, " + path


def build_record(spec):
    grease_settings = False
    path = os.path.join(RAW, spec["file"])
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    tls = data["tls"]
    exts = extension_map(tls)
    deviations = list(spec.get("deviations") or [])
    if spec.get("http1_capture"):
        # The uTLS harness narrows ALPN so it can speak HTTP/1.1 on the raw
        # socket; the TLS shape is still the library's own ClientHello.
        deviations.append(
            "The capture ran over HTTP/1.1: ALPN advertises only http/1.1, not "
            "the client's full h2 list."
        )

    captured_ciphers = tls.get("ciphers") or []
    grease = any(is_grease_label(name) for name in captured_ciphers)
    ciphers = [name for name in captured_ciphers if name in SUPPORTED_CIPHERS]
    dropped_ciphers = [
        name
        for name in captured_ciphers
        if name not in SUPPORTED_CIPHERS and not is_grease_label(name)
    ]
    note = summarize("cipher suites", dropped_ciphers, ciphers)
    if note:
        deviations.append(note)
    first_cipher = next(
        (name for name in captured_ciphers if not is_grease_label(name)), None
    )
    if (
        first_cipher
        and not is_tls13(first_cipher)
        and any(is_tls13(name) for name in ciphers)
    ):
        deviations.append(
            "BoringSSL always sends the TLS 1.3 cipher suites before the TLS 1.2 "
            "suites; the capture lists them after the TLS 1.2 suites."
        )

    captured_groups = []
    group_entry = exts.get(10)
    if group_entry:
        for label in group_entry.get("supported_groups") or []:
            if is_grease_label(label):
                grease = True
                continue
            captured_groups.append(group_name(label) or label)
    curves = [name for name in captured_groups if name in GROUP_CODES.values()]
    dropped_groups = [name for name in captured_groups if name not in GROUP_CODES.values()]
    note = summarize("groups", dropped_groups, curves)
    if note:
        deviations.append(note)

    sigalgs = []
    dropped_sigalgs = []
    grease_sigalg = False
    for name in sigalgs_from(tls):
        if name.startswith("0x") and grease_code(parse_hex(name) or 0):
            # A GREASE sigalg now rides along in the raw code point list, so
            # it is no longer a deviation.
            grease_sigalg = True
            continue
        if name in SUPPORTED_SIGALGS:
            sigalgs.append(name)
        else:
            dropped_sigalgs.append(name)
    note = summarize("signature algorithms", dropped_sigalgs, sigalgs)
    if note:
        deviations.append(note)
    # A GREASE sigalg is carried by the raw code point list, so it is not a
    # deviation any more. `grease_sigalg` only marks that the caller must use
    # that path.

    captured_exts = [
        ext_id
        for ext_id in (extension_id(e) for e in tls["extensions"])
        if ext_id is not None
    ]
    extension_order = [ext_id for ext_id in captured_exts if ext_id in SUPPORTED_EXTENSIONS]
    dropped_exts = [
        f"{ext_id} ({EXTENSION_NAMES.get(ext_id, 'unknown')})"
        for ext_id in captured_exts
        if ext_id not in SUPPORTED_EXTENSIONS and ext_id != 21
    ]
    if dropped_exts:
        deviations.append(
            "BoringSSL never sends captured extension "
            + ", ".join(dropped_exts)
            + "."
        )
    # A capture with pre_shared_key came from a resumed session. The record
    # marks that (`tls.pre_shared_key`) and the session cache reproduces the
    # extension on the second connection, so it is not a deviation.
    grease_extensions = sum(
        1 for entry in tls["extensions"] if is_grease_label(entry.get("name", ""))
    )
    if grease_extensions > 2:
        deviations.append(
            f"The capture carries {grease_extensions} GREASE extensions; BoringSSL "
            "emits at most two, one first and one last."
        )
    # Padding is now exact: SSL_CTX_set_force_padding_len sends the captured
    # length, or suppresses the extension when the capture has none, so the
    # size-dependent F5 padding can no longer diverge from the capture.

    key_shares = []
    key_entry = exts.get(51)
    if key_entry:
        for share in key_entry.get("shared_keys") or []:
            for label in share:
                if is_grease_label(label):
                    grease = True
                    continue
                name = group_name(label)
                if name:
                    key_shares.append(name)

    # The record has a single GREASE switch, but BoringSSL applies it to the
    # cipher, group, version, key-share and extension lists together. Some
    # clients (Nike's Android app) GREASE only the key share, so say so.
    greased_lists = []
    if any(is_grease_label(name) for name in captured_ciphers):
        greased_lists.append("cipher suite")
    if any(is_grease_label(entry.get("name", "")) for entry in tls["extensions"]):
        greased_lists.append("extension")
    if any(
        is_grease_label(label)
        for label in (exts.get(10) or {}).get("supported_groups") or []
    ):
        greased_lists.append("group")
    if any(
        is_grease_label(value)
        for value in (exts.get(43) or {}).get("versions") or []
    ):
        greased_lists.append("version")
    if any(
        is_grease_label(label)
        for share in (exts.get(51) or {}).get("shared_keys") or []
        for label in share
    ):
        greased_lists.append("key share")
    # A capture that greases some lists but not the cipher list can be
    # reproduced exactly now: the vendored BoringSSL has a switch that keeps
    # GREASE out of the cipher list while the others still carry it.
    skip_cipher_grease = grease and "cipher suite" not in greased_lists
    if grease and len(greased_lists) < 5 and not skip_cipher_grease:
        deviations.append(
            "The capture greases only the "
            + (", ".join(greased_lists) if greased_lists else "nothing")
            + "; BoringSSL's GREASE switch greases the cipher, group, version, "
            "key-share and extension lists together."
        )

    alpn = None
    alpn_entry = exts.get(16)
    if alpn_entry:
        alpn = alpn_entry.get("protocols")

    versions = []
    version_entry = exts.get(43)
    if version_entry:
        for value in version_entry.get("versions") or []:
            if is_grease_label(value) or not value.startswith("TLS 1."):
                grease = grease or is_grease_label(value)
                continue
            versions.append(value.replace("TLS ", ""))
    if not versions:
        # A TLS 1.2-only client sends no supported_versions extension. The
        # negotiated record version is then the only version it offers.
        record_version = data["tls"].get("tls_version_record") or data["tls"].get(
            "tls_version_negotiated"
        )
        # A hello with no supported_versions is capped at the record
        # version: a TLS 1.2 record (771) means "TLS 1.2 and below", which
        # BoringSSL reproduces with min 1.2 / max 1.2. Reading the raw
        # record-version byte (769, the historical 1.0 value) would wrongly
        # cap the client at 1.0.
        negotiated = data["tls"].get("tls_version_negotiated")
        versions = {
            "769": ["1.2"],
            "770": ["1.2"],
            "771": ["1.2"],
            "772": ["1.3"],
        }.get(str(negotiated or record_version), [])
    min_version = min(versions) if versions else None
    max_version = max(versions) if versions else None
    if 23 not in captured_exts and max_version in ("1.2", "1.3"):
        # BoringSSL enables extended master secret unconditionally for TLS 1.2
        # and later, so a capture without it cannot be reproduced exactly.
        deviations.append(
            "BoringSSL always sends extended_master_secret (23); the capture "
            "omits it."
        )

    cert_compression = []
    compression_entry = exts.get(27)
    if compression_entry:
        for label in compression_entry.get("algorithms") or []:
            name = label.split(" (")[0]
            if name in SUPPORTED_CERT_COMPRESSION:
                cert_compression.append(name)
            else:
                deviations.append(
                    f"BoringSSL cannot send the captured certificate compression {name}."
                )

    record_size_limit = None
    limit_entry = exts.get(28)
    if limit_entry:
        record_size_limit = parse_hex(limit_entry.get("data"))
        if record_size_limit is None:
            deviations.append(
                "The captured record_size_limit value could not be read; "
                "the transport leaves the extension unset."
            )

    delegated_credentials = []
    delegated_entry = exts.get(34)
    if delegated_entry:
        for value in delegated_entry.get("signature_hash_algorithms") or []:
            if value.startswith("0x"):
                code = parse_hex(value)
                value = SIGALG_CODES.get(code, value)
            if value in SUPPORTED_SIGALGS:
                delegated_credentials.append(value)
            else:
                deviations.append(
                    f"BoringSSL cannot send the delegated credential algorithm {value}."
                )

    # Extension 51764 carries a u16 list length followed by length-prefixed
    # trust-anchor identifiers. BoringSSL's SSL_set1_requested_trust_anchors
    # takes exactly the inner list, so keep those bytes and drop the length.
    trust_anchors = None
    trust_entry = exts.get(51764) or {}
    if trust_entry.get("data"):
        payload = bytes.fromhex(trust_entry["data"])
        if len(payload) >= 2 and int.from_bytes(payload[:2], "big") == len(payload) - 2:
            # An empty identifier list still advertises the extension, which is
            # what e.g. tlsclient_chrome146's capture does. Keep the empty
            # string so the record says "send 51764" rather than "no 51764".
            trust_anchors = payload[2:].hex()

    # Chrome 58-70 offer the deprecated ChannelID extension (30032).
    channel_id = 30032 in exts

    # pre_shared_key means the capture came from a resumed session: the
    # record needs the session cache on to reproduce that ClientHello.
    resumed = 41 in exts

    # The capture's padding length (RFC 7685). Padding is a consequence of
    # the ClientHello size: BoringSSL, OpenSSL and Go all pad a hello that is
    # 256-511 bytes long into a 508-byte handshake, and every padded capture
    # in this corpus lands exactly there once the reported length is halved.
    #
    # tls.peet.ws reports `padding_data_length` as the length of the padding's
    # hex string, i.e. twice the byte count: a real Android hello whose
    # extension carries 242 bytes arrives from the echo as 484. Verified by
    # recording the same hello on the wire (tools/capture/phone_capture.py)
    # and comparing it with the echo of that same connection.
    pad_entry = exts.get(21) or {}
    padding_len = pad_entry.get("padding_data_length")
    if padding_len and "peetprint" in tls:
        padding_len //= 2

    alps_old = 17513 in exts
    alps_new = 17613 in exts

    tls_record = {
        "ciphers": ":".join(ciphers),
        "curves": ":".join(curves),
        "sigalgs": ":".join(sigalgs),
        "extension_order": "-".join(str(ext_id) for ext_id in extension_order),
        "key_shares": ":".join(key_shares),
        "grease": grease,
        "permute_extensions": bool(spec.get("permute_extensions", False)),
        "session_ticket": 35 in exts,
        "ocsp_stapling": 5 in exts,
        "signed_cert_timestamps": 18 in exts,
        "ech_grease": 65037 in exts,
        "alps": alps_old or alps_new,
        "new_alps_codepoint": alps_new,
        "renegotiation": 65281 in exts,
        "psk_dhe_ke": 45 in exts,
        "preserve_tls13_cipher_list": True,
    }
    if cert_compression:
        tls_record["cert_compression"] = ":".join(cert_compression)
    if record_size_limit is not None:
        tls_record["record_size_limit"] = record_size_limit
    if delegated_credentials:
        tls_record["delegated_credentials"] = ":".join(delegated_credentials)
    if skip_cipher_grease:
        tls_record["grease_skip_ciphers"] = True
    # NPN (13172) is deprecated; only the oldest iOS captures carry it, and
    # the vendored BoringSSL can emit it on request.
    if 13172 in exts:
        tls_record["offer_npn"] = True
    if trust_anchors is not None:
        tls_record["trust_anchors"] = trust_anchors
    if channel_id:
        tls_record["channel_id"] = True
    if 21 in exts and not padding_len:
        # An empty padding extension is a legal, distinct case: the client
        # sent the extension with no payload. Keep it so extension 21 stays
        # in the hello (it is part of the JA4 c hash).
        tls_record["padding"] = {"send": {"len": 0}}
    elif 21 in exts:
        # The capture's padding came from the transport's size rule, not from
        # the client: leave the extension's presence to the transport. Writing
        # the captured length down as a fixed value would make the record
        # wrong the moment the hello's length changes - which it does for
        # every different SNI.
        tls_record.pop("padding", None)
    else:
        # No padding in the capture: suppress BoringSSL's automatic 256-511
        # byte padding so the live ClientHello cannot grow one.
        tls_record["padding"] = "omit"
    if resumed:
        tls_record["pre_shared_key"] = True
    # Chrome 156+ sends sigalg codepoints BoringSSL has no name for (ML-DSA, a
    # GREASE value). Record the capture's exact list so the extension carries
    # them verbatim. This is driven by the capture, not a per-record flag, so
    # every Chrome record gets it.
    raw = (exts.get(13) or {}).get("signature_algorithms") or []
    codes = [sigalg_code(name) for name in raw]
    if raw and all(code is not None for code in codes):
        tls_record["sigalg_codes"] = codes

    # Extension 4832 (Chromium's server padding request). It is sent with the
    # captured payload when the patch carrying the writer is in the build.
    pad_entry = exts.get(4832)
    if pad_entry and pad_entry.get("data"):
        payload = bytes.fromhex(pad_entry["data"])
        if len(payload) == 2:
            tls_record["server_padding_request"] = int.from_bytes(payload, "big")
    if spec.get("server_padding_request") is not None:
        tls_record["server_padding_request"] = spec["server_padding_request"]
    # ALPN: BoringSSL can only offer h2, http/1.1 and h3. A capture may also
    # list http/1.0 (WebKitGTK does); it is dropped and recorded, because the
    # transport would reject it.
    if alpn:
        unsendable = [p for p in alpn if p not in ("h2", "http/1.1", "h3")]
        if unsendable:
            deviations.append(
                "The capture lists ALPN " + ", ".join(unsendable) +
                ", which BoringSSL cannot offer; those entries are dropped."
            )
            alpn = [p for p in alpn if p in ("h2", "http/1.1", "h3")]
    # Always record ALPN. An empty list means the client sends no ALPN
    # extension, which is different from "the transport decides".
    tls_record["alpn"] = alpn or []
    if min_version:
        tls_record["min_version"] = min_version
        tls_record["max_version"] = max_version

    http2 = None
    http2_data = data.get("http2")
    if http2_data:
        settings = []
        window_update = None
        pseudo_order = None
        initial_window = None
        no_priority = None
        request_headers = []
        authority = None
        for frame in http2_data.get("sent_frames") or []:
            kind = frame.get("frame_type")
            if kind == "SETTINGS":
                for setting in frame.get("settings") or []:
                    name, _, value = setting.partition(" = ")
                    setting_id = SETTING_IDS.get(name)
                    if setting_id is None:
                        # An unknown id in a capture is GREASE: Chrome picks a
                        # random 16-bit id and value each connection. The h2
                        # crate's SettingId is a closed enum, so it cannot be
                        # sent; note it instead of inventing a value.
                        if re.search(r"UNKNOWN_SETTING_\d+", name):
                            grease_settings = True
                        continue
                    settings.append((setting_id, int(value)))
                    if setting_id == 4:
                        initial_window = int(value)
                    if setting_id == 9:
                        no_priority = int(value) != 0
            elif kind == "WINDOW_UPDATE" and window_update is None:
                window_update = frame.get("increment")
            elif kind == "HEADERS" and pseudo_order is None:
                headers = frame.get("headers") or []
                letters = []
                for header in headers:
                    name, _, value = header.partition(": ")
                    if name == ":authority":
                        authority = value
                    if name in PSEUDO_LETTERS:
                        letters.append(PSEUDO_LETTERS[name])
                    else:
                        request_headers.append((name, value))
                pseudo_order = "".join(letters)
        priority_frames = sum(
            1
            for frame in http2_data.get("sent_frames") or []
            if frame.get("frame_type") == "PRIORITY"
        )
        # PRIORITY frames are reproduced (http2.priorities), so they are
        # not a deviation any more; `priority_frames` still drives the field.
        if authority and authority.endswith(":443"):
            deviations.append(
                "The capture sends :authority with the default :443 port; "
                "the transport omits the default port."
            )
        http2 = {
            "settings": ";".join(f"{setting_id}:{value}" for setting_id, value in settings),
            "pseudo_order": pseudo_order,
        }
        if window_update is not None:
            http2["window_update"] = window_update
        if initial_window is not None:
            http2["initial_window_size"] = initial_window
        if no_priority is not None:
            http2["no_priority"] = no_priority
        if not settings:
            deviations.append(
                "The transport cannot send an empty HTTP/2 SETTINGS frame; "
                "INITIAL_WINDOW_SIZE=65535 is sent instead."
            )
        headers = request_headers
    else:
        headers = []
        http1 = data.get("http1") or {}
        for line in http1.get("headers") or []:
            name, _, value = line.partition(": ")
            if name.lower() in ("host", "connection"):
                continue
            headers.append((name, value))

    record = {
        "name": spec["name"],
        "family": spec["family"],
        "client": spec["client"],
        "version": spec["version"],
        "platform": spec["platform"],
        **({"library": spec["library"]} if spec.get("library") else {}),
        "source": spec.get("source") or capture_source(spec["name"], spec["file"]),
        "fidelity": fidelity(
            len(dropped_ciphers),
            len(dropped_groups),
            len(dropped_sigalgs),
            len(dropped_exts),
            deviations,
        ),
        "deviations": deviations,
        "tls": tls_record,
        "headers": [[name, value] for name, value in headers],
        "http1_only": not http2_data,
    }
    # A captured GREASE HTTP/2 setting means the browser greases its SETTINGS
    # frame. The value is random per connection, so the record only says
    # "send one", never a fixed id.
    if http2 is not None:
        if grease_settings:
            http2["grease_settings"] = True
        record["http2"] = http2
        # Standalone PRIORITY frames (Firefox 102-123 send six before the
        # first HEADERS). They are part of the Akamai fingerprint's third
        # segment, so they have to be reproduced.
        frames = (http2_data.get("sent_frames") or []) if http2_data else []
        priorities = [
            {
                "stream_id": frame["stream_id"],
                "depends_on": frame["priority"]["depends_on"],
                "weight": frame["priority"]["weight"],
                "exclusive": bool(frame["priority"]["exclusive"]),
            }
            for frame in frames
            if frame.get("frame_type") == "PRIORITY" and frame.get("priority")
        ]
        if priorities:
            http2["priorities"] = priorities
    if spec.get("http3"):
        record["http3"] = dict(spec["http3"])
    return record


def fidelity(ciphers, groups, sigalgs, exts, deviations):
    # The padding note is a length-dependent side effect, not a field that was
    # dropped. A ClientHello outside 256-511 bytes never gets it, so it does
    # not by itself lower fidelity.
    substantive = [
        note
        for note in deviations
        if "padding extension (21)" not in note
        and "capture ran over HTTP/1.1" not in note
    ]
    total = ciphers + groups + sigalgs + exts
    if total == 0 and not substantive:
        return "exact"
    if ciphers > 5 or total > 8:
        return "partial"
    return "close"


def main():
    records = []
    for spec in PROFILES:
        records.append(build_record(spec))
    by_name = {record["name"]: record for record in records}
    for name, base, family, client, platform in ALIASES:
        alias = {
            "name": name,
            "family": family,
            "client": client,
            "platform": platform,
            "source": f"alias of {base}",
            "extends": base,
        }
        # A preset alias has no capture of its own, so it has no fidelity.
        if base in by_name:
            alias["fidelity"] = by_name[base]["fidelity"]
        records.append(alias)
    names = [record["name"] for record in records]
    if len(names) != len(set(names)):
        sys.exit("duplicate fingerprint names")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump({"fingerprints": records}, handle, indent=2)
        handle.write("\n")
    print(f"wrote {len(records)} records to {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
