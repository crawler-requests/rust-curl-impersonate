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

# Extension ids in BoringSSL's kExtensions table (ssl/extensions.cc).
SUPPORTED_EXTENSIONS = {
    0, 5, 10, 11, 13, 14, 16, 18, 23, 27, 28, 34, 35, 41, 42, 43, 44, 45, 47,
    51, 57, 65037, 65281, 17513, 17613, 65445,
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
        "client": "Chromium (headless)",
        "version": "157.0.8103.38",
        "platform": "linux",
        "permute_extensions": True,
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
        "family": "android",
        "client": "Confirmed Android app (tls-client profile)",
        "version": "ConfirmedAndroid",
        "platform": "android",
    },
    {
        "file": "android_okhttp13.json",
        "name": "android_okhttp13",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 13 (tls-client profile)",
        "version": "OkHttp 4 / Android 13",
        "platform": "android",
    },
    {
        "file": "android_confirmed2.json",
        "name": "android_confirmed2",
        "family": "android",
        "client": "Confirmed Android app, second profile (tls-client)",
        "version": "ConfirmedAndroid2",
        "platform": "android",
    },
    {
        "file": "android_mesh.json",
        "name": "android_mesh",
        "family": "android",
        "client": "Mesh Android app (tls-client profile)",
        "version": "MeshAndroid",
        "platform": "android",
    },
    {
        "file": "android_mesh1.json",
        "name": "android_mesh1",
        "family": "android",
        "client": "Mesh Android app, HTTP/1.1 (tls-client profile)",
        "version": "MeshAndroid2",
        "platform": "android",
    },
    {
        "file": "android_okhttp7.json",
        "name": "android_okhttp7",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 7 (tls-client profile)",
        "version": "OkHttp 4 / Android 7",
        "platform": "android",
    },
    {
        "file": "android_okhttp8.json",
        "name": "android_okhttp8",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 8 (tls-client profile)",
        "version": "OkHttp 4 / Android 8",
        "platform": "android",
    },
    {
        "file": "android_okhttp9.json",
        "name": "android_okhttp9",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 9 (tls-client profile)",
        "version": "OkHttp 4 / Android 9",
        "platform": "android",
    },
    {
        "file": "android_okhttp10.json",
        "name": "android_okhttp10",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 10 (tls-client profile)",
        "version": "OkHttp 4 / Android 10",
        "platform": "android",
    },
    {
        "file": "android_okhttp11.json",
        "name": "android_okhttp11",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 11 (tls-client profile)",
        "version": "OkHttp 4 / Android 11",
        "platform": "android",
    },
    {
        "file": "android_okhttp12.json",
        "name": "android_okhttp12",
        "family": "okhttp",
        "client": "OkHttp 4 on Android 12 (tls-client profile)",
        "version": "OkHttp 4 / Android 12",
        "platform": "android",
    },
    {
        "file": "android_nike.json",
        "name": "android_nike",
        "family": "android",
        "client": "Nike Android app (tls-client profile)",
        "version": "NikeAndroidMobile",
        "platform": "android",
    },
    {
        "file": "android_zalando.json",
        "name": "android_zalando",
        "family": "android",
        "client": "Zalando Android app (tls-client profile)",
        "version": "ZalandoAndroidMobile",
        "platform": "android",
    },
    {
        "file": "ios_confirmed.json",
        "name": "ios_confirmed",
        "family": "ios",
        "client": "Confirmed iOS app (tls-client profile)",
        "version": "ConfirmedIos",
        "platform": "ios",
    },
    {
        "file": "ios_safari18_5.json",
        "name": "ios_safari18_5",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
        "version": "18.5",
        "platform": "ios",
    },
    {
        "file": "ios_safari26.json",
        "name": "ios_safari26",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
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
        "family": "safari",
        "client": "Safari on macOS (tls-client profile)",
        "version": "15.6.1",
        "platform": "macos",
    },
    {
        "file": "tlsclient_safari16.json",
        "name": "tlsclient_safari16",
        "family": "safari",
        "client": "Safari on macOS (tls-client profile)",
        "version": "16.0",
        "platform": "macos",
    },
    {
        "file": "tlsclient_safari_ipad15_6.json",
        "name": "tlsclient_safari_ipad15_6",
        "family": "safari",
        "client": "Safari on iPad (tls-client profile)",
        "version": "15.6",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mms.json",
        "name": "tlsclient_ios_mms",
        "family": "ios",
        "client": "iOS MMS app (tls-client profile)",
        "version": "MMSIos",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mms2.json",
        "name": "tlsclient_ios_mms2",
        "family": "ios",
        "client": "iOS MMS app, second profile (tls-client)",
        "version": "MMSIos2",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mms3.json",
        "name": "tlsclient_ios_mms3",
        "family": "ios",
        "client": "iOS MMS app, third profile (tls-client)",
        "version": "MMSIos3",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mesh.json",
        "name": "tlsclient_ios_mesh",
        "family": "ios",
        "client": "iOS Mesh app (tls-client profile)",
        "version": "MeshIos",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_mesh2.json",
        "name": "tlsclient_ios_mesh2",
        "family": "ios",
        "client": "iOS Mesh app, second profile (tls-client)",
        "version": "MeshIos2",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_nike.json",
        "name": "tlsclient_ios_nike",
        "family": "ios",
        "client": "Nike iOS app (tls-client profile)",
        "version": "NikeIosMobile",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_zalando.json",
        "name": "tlsclient_ios_zalando",
        "family": "ios",
        "client": "Zalando iOS app (tls-client profile)",
        "version": "ZalandoIosMobile",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari15_5.json",
        "name": "tlsclient_ios_safari15_5",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
        "version": "15.5",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari15_6.json",
        "name": "tlsclient_ios_safari15_6",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
        "version": "15.6",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari16.json",
        "name": "tlsclient_ios_safari16",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
        "version": "16.0",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari17.json",
        "name": "tlsclient_ios_safari17",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
        "version": "17.0",
        "platform": "ios",
    },
    {
        "file": "tlsclient_ios_safari18.json",
        "name": "tlsclient_ios_safari18",
        "family": "safari",
        "client": "Safari on iOS (tls-client profile)",
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
        "family": "safari",
        "client": "Safari 16.0 (uTLS ClientHello)",
        "version": "16.0",
        "platform": "macos",
        "http1_capture": True,
    },
    {
        "file": "utls_ios11.json",
        "name": "utls_ios11",
        "family": "safari",
        "client": "Safari on iOS 11.1 (uTLS ClientHello)",
        "version": "11.1",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_ios12.json",
        "name": "utls_ios12",
        "family": "safari",
        "client": "Safari on iOS 12.1 (uTLS ClientHello)",
        "version": "12.1",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_ios13.json",
        "name": "utls_ios13",
        "family": "safari",
        "client": "Safari on iOS 13 (uTLS ClientHello)",
        "version": "13",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_ios14.json",
        "name": "utls_ios14",
        "family": "safari",
        "client": "Safari on iOS 14 (uTLS ClientHello)",
        "version": "14",
        "platform": "ios",
        "http1_capture": True,
    },
    {
        "file": "utls_android11okhttp.json",
        "name": "utls_android11okhttp",
        "family": "okhttp",
        "client": "OkHttp on Android 11 (uTLS ClientHello)",
        "version": "Android 11 OkHttp",
        "platform": "android",
        "http1_capture": True,
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


def build_record(spec):
    path = os.path.join(RAW, spec["file"])
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    tls = data["tls"]
    exts = extension_map(tls)
    deviations = []
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
            grease = True
            grease_sigalg = True
            continue
        if name in SUPPORTED_SIGALGS:
            sigalgs.append(name)
        else:
            dropped_sigalgs.append(name)
    note = summarize("signature algorithms", dropped_sigalgs, sigalgs)
    if note:
        deviations.append(note)
    if grease_sigalg:
        deviations.append(
            "BoringSSL does not put a GREASE value in signature_algorithms; it "
            "greases the cipher, group, version, key-share and extension lists."
        )

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
    # The capture came from a resumed session (or one where the test page was
    # hit twice), so it carries a pre_shared_key with a real binder. BoringSSL
    # only emits pre_shared_key when the caller supplies a session ticket; a
    # fresh handshake from this crate has none.
    if 41 in captured_exts:
        deviations.append(
            "The capture carries pre_shared_key (41) from a resumed session; "
            "BoringSSL emits it only when a cached session ticket is supplied, "
            "so a fresh handshake sends no PSK extension."
        )
    grease_extensions = sum(
        1 for entry in tls["extensions"] if is_grease_label(entry.get("name", ""))
    )
    if grease_extensions > 2:
        deviations.append(
            f"The capture carries {grease_extensions} GREASE extensions; BoringSSL "
            "emits at most two, one first and one last."
        )
    if 21 in captured_exts:
        deviations.append(
            "The capture carries the padding extension (21); BoringSSL emits "
            "padding only when the emulated ClientHello length is 256-511 "
            "bytes, so the live length may differ."
        )
    else:
        deviations.append(
            "BoringSSL appends a padding extension (21) when the ClientHello "
            "is between 256 and 511 bytes; the capture has none."
        )

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
    if grease and len(greased_lists) < 5:
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
        versions = {
            "769": ["1.0"],
            "770": ["1.1"],
            "771": ["1.2"],
            "772": ["1.3"],
        }.get(str(record_version), [])
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
        if priority_frames:
            deviations.append(
                f"The capture sends {priority_frames} RFC 7540 PRIORITY frames; the "
                "transport sends none."
            )
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
        "source": "tls.peet.ws capture, tools/capture/raw/" + spec["file"],
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
    if http2 is not None:
        record["http2"] = http2
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
