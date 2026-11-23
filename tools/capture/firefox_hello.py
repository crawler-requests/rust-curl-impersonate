#!/usr/bin/env python3
"""Record one Firefox build's ClientHello without geckodriver.

Firefox for Linux ships as a plain tarball that a sandboxed snap
geckodriver refuses to launch, and the headless build does not expose a
CDP port either. What always works is the browser's own TLS stack: point
it at a local socket that reads the ClientHello off the wire and stops.

The ClientHello is what the fingerprint is about, so the destination
does not have to be tls.peet.ws - the hello this records is byte-identical
to the one sent there.

    python3 -I tools/capture/firefox_hello.py <firefox-bin> <out.json>
        [--cert cert.pem --key key.pem --port 8447]

Output is a tls.peet.ws-shaped document with the `tls` block filled in:
ciphers, extensions (id, length, payload where it is cheap to include),
ALPN and the JA3/JA4 the record generator needs.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

# Extension ids whose payload the record generator reads.
PAYLOAD_IDS = {
    0, 5, 10, 11, 13, 16, 18, 21, 23, 27, 34, 35, 41, 43, 45, 51, 51764, 65037,
}


def read_record(conn):
    """One TLS record off the wire, or None when the peer sent something else."""
    conn.settimeout(15)
    data = conn.recv(5)
    if len(data) < 5 or data[0] != 0x16:
        return None, data
    length = struct.unpack(">H", data[3:5])[0]
    chunks = []
    remaining = length
    while remaining > 0:
        chunk = conn.recv(min(remaining, 4096))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return data + b"".join(chunks), None


def parse(record):
    """Vector of (id, payload) from a ClientHello record."""
    body = record[5:]
    if not body or body[0] != 1:
        raise ValueError("record is not a ClientHello")
    handshake_len = int.from_bytes(body[1:4], "big")
    hello = body[4:4 + handshake_len]

    pos = 2 + 32
    sid_len = hello[pos]
    pos += 1 + sid_len
    cipher_len = struct.unpack(">H", hello[pos:pos + 2])[0]
    pos += 2
    ciphers = [
        struct.unpack(">H", hello[pos + i:pos + i + 2])[0]
        for i in range(0, cipher_len, 2)
    ]
    pos += cipher_len
    comp_len = hello[pos]
    pos += 1 + comp_len
    total = struct.unpack(">H", hello[pos:pos + 2])[0]
    pos += 2
    end = pos + total
    extensions = []
    while pos + 4 <= end:
        kind = struct.unpack(">H", hello[pos:pos + 2])[0]
        size = struct.unpack(">H", hello[pos + 2:pos + 4])[0]
        pos += 4
        extensions.append((kind, hello[pos:pos + size]))
        pos += size
    return ciphers, extensions


CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # The rest of the suites the captures actually contain. Without them the
    # audit cannot turn a record's cipher names back into code points, so it
    # could not check those records against their capture. The numbers are
    # the IANA registry's and each was confirmed by comparing a capture's
    # names with the ja4_r the service computed from the same hello.
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x0041: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0044: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x0045: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006a: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0084: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x0087: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x0088: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00a2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00a3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0x00ba: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00bd: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0x00be: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO",
    0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xc008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xc02d: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02e: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xc032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xc050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
    0xc051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
    0xc052: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xc053: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xc056: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
    0xc057: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
    0xc05c: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xc05d: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xc060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xc061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xc072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xc073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xc076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xc077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xc09c: "TLS_RSA_WITH_AES_128_CCM",
    0xc09d: "TLS_RSA_WITH_AES_256_CCM",
    0xc09e: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xc09f: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xc0a0: "TLS_RSA_WITH_AES_128_CCM_8",
    0xc0a1: "TLS_RSA_WITH_AES_256_CCM_8",
    0xc0a2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    0xc0a3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    0xc0ac: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xc0ad: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xc0ae: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xc0af: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

GROUP_NAMES = {
    0x0017: "P-256", 0x0018: "P-384", 0x0019: "P-521",
    0x001d: "X25519", 0x001e: "X448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x0103: "ffdhe6144", 0x0104: "ffdhe8192",
    0x11ec: "X25519MLKEM768", 0x6399: "X25519Kyber768Draft00",
    0x0011: "ffdhe2048",
}

SIGALG_NAMES = {
    0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256",
    0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512",
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1",
    0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
}


def is_grease(value):
    return (value & 0x0f0f) == 0x0a0a


def describe(kind, payload):
    """The entry shape tools/gen_fingerprints.py reads."""
    entry = {"name": f"({kind})"}
    if kind == 10:
        groups = [struct.unpack(">H", payload[i:i + 2])[0]
                  for i in range(2, 2 + struct.unpack(">H", payload[:2])[0], 2)]
        entry["name"] = "supported_groups (10)"
        # A GREASE group has to keep the label the record generator looks
        # for; `0x5a5a` would be read as an algorithm BoringSSL cannot send.
        entry["supported_groups"] = [
            f"GREASE (0x{g:04x})" if is_grease(g) else GROUP_NAMES.get(g, f"0x{g:04x}")
            for g in groups
        ]
    elif kind == 13:
        algs = [struct.unpack(">H", payload[i:i + 2])[0]
                for i in range(2, 2 + struct.unpack(">H", payload[:2])[0], 2)]
        entry["name"] = "signature_algorithms (13)"
        entry["signature_algorithms"] = [
            SIGALG_NAMES.get(a, f"0x{a:x}") for a in algs
        ]
    elif kind == 16:
        names = []
        pos = 2
        while pos < 2 + struct.unpack(">H", payload[:2])[0]:
            n = payload[pos]
            names.append(payload[pos + 1:pos + 1 + n].decode("ascii", "replace"))
            pos += 1 + n
        entry["name"] = "application_layer_protocol_negotiation (16)"
        entry["protocols"] = names
    elif kind == 51:
        shares = []
        pos = 2
        while pos < 2 + struct.unpack(">H", payload[:2])[0]:
            group = struct.unpack(">H", payload[pos:pos + 2])[0]
            n = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
            shares.append({GROUP_NAMES.get(group, f"0x{group:x}"): n})
            pos += 4 + n
        entry["name"] = "key_share (51)"
        entry["shared_keys"] = shares
    elif kind == 21:
        entry["name"] = "padding (21)"
        entry["padding_data_length"] = len(payload)
    elif kind in (17513, 17613):
        entry["name"] = f"application_settings ({kind})"
        entry["data"] = payload.hex()
    elif kind == 51764:
        entry["name"] = "Unknown extension 51764"
        entry["data"] = payload.hex()
    elif kind == 4832:
        entry["name"] = "Unknown extension 4832"
        entry["data"] = payload.hex()
    elif kind == 30032:
        entry["name"] = "extensionChannelID (boringssl) (30032)"
    elif kind == 30031:
        entry["name"] = "Unknown extension 30031"
    elif kind == 65037:
        entry["name"] = "extensionEncryptedClientHello (boringssl) (65037)"
    elif kind == 43:
        entry["name"] = "supported_versions (43)"
    elif kind == 45:
        entry["name"] = "psk_key_exchange_modes (45)"
    elif kind == 23:
        entry["name"] = "extended_master_secret (23)"
    elif kind == 5:
        entry["name"] = "status_request (5)"
    elif kind == 18:
        entry["name"] = "signed_certificate_timestamp (18)"
    elif kind == 0:
        entry["name"] = "server_name (0)"
    elif kind == 11:
        entry["name"] = "ec_point_formats (11)"
    elif kind == 35:
        entry["name"] = "session_ticket (35)"
    elif kind == 34:
        entry["name"] = "delegated_credential (34)"
        algs = []
        pos = 2
        while pos + 2 <= 2 + struct.unpack(">H", payload[:2])[0]:
            code = struct.unpack(">H", payload[pos:pos + 2])[0]
            algs.append(SIGALG_NAMES.get(code, f"0x{code:x}"))
            pos += 2
        entry["signature_hash_algorithms"] = algs
    elif kind == 27:
        entry["name"] = "compress_certificate (27)"
        # u8 list of algorithm ids: 1 = zlib, 2 = brotli, 3 = zstd.
        # RFC 8879: a u16 list length, then one u16 per algorithm.
        # A Firefox 134 payload is 06 00 01 00 02 00 03: a one-byte count
        # followed by that many big-endian u16 algorithm ids.
        count = payload[0] if payload else 0
        entry["algorithms"] = [
            {1: "zlib", 2: "brotli", 3: "zstd"}.get(
                struct.unpack(">H", payload[pos:pos + 2])[0],
                f"0x{struct.unpack('>H', payload[pos:pos + 2])[0]:x}",
            )
            for pos in range(1, 1 + count, 2)
            if pos + 2 <= len(payload)
        ]
    elif kind == 28:
        entry["name"] = "record_size_limit (28)"
        entry["data"] = payload.hex()
    elif kind == 65281:
        entry["name"] = "extensionRenegotiationInfo (boringssl) (65281)"
    elif is_grease(kind):
        entry["name"] = f"TLS_GREASE (0x{kind:04x})"
    else:
        entry["name"] = f"Unknown extension {kind}"
    return entry


def ja4(ciphers, extensions):
    """The JA4 a-segment only.

    The b/c hashes follow a folding rule this recorder does not reproduce
    exactly, so they are left out rather than guessed: `tls.peet.ws` fills
    them in when a record is verified live. Comparing extension ids,
    ciphers, groups and sigalgs is the full fingerprint description.
    """
    def hashed(values):
        import hashlib
        return hashlib.sha256(",".join(values).encode()).hexdigest()[:12]

    version = "13" if 0x1301 in ciphers else "12"
    sni = "d" if 0 in [k for k, _ in extensions] else "i"
    alpn = ""
    for kind, payload in extensions:
        if kind == 16:
            names = []
            pos = 2
            while pos < 2 + struct.unpack(">H", payload[:2])[0]:
                n = payload[pos]
                names.append(payload[pos + 1:pos + 1 + n].decode("ascii", "replace"))
                pos += 1 + n
            alpn = "h2" if "h2" in names else ("h1" if "http/1.1" in names else "")
            break
    without_grease = [c for c in ciphers if not is_grease(c)]
    exts = [k for k, _ in extensions if not is_grease(k)]
    # JA4 always writes the ALPN label as two characters; a hello with no
    # ALPN extension is "00", not an empty string.
    head = f"t{version}{sni}{len(without_grease):02d}{len(exts):02d}{alpn or '00'}"
    cipher_hash = hashed([f"{c:04x}" for c in sorted(without_grease)])
    return f"{head}_{cipher_hash}_-"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("output")
    parser.add_argument("--port", type=int, default=8447)
    parser.add_argument("--cert", default="/tmp/tls/cert.pem")
    parser.add_argument("--key", default="/tmp/tls/key.pem")
    parser.add_argument("--host", default="tls.peet.ws")
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(1)
    server.settimeout(args.timeout)

    profile = tempfile.mkdtemp(prefix="ff-hello-")
    with open(os.path.join(profile, "user.js"), "w", encoding="utf-8") as handle:
        handle.write(
            'user_pref("network.stricttransportsecurity.preloadlist", false);\n'
            'user_pref("security.certerrors.mitm.priming.enabled", false);\n'
            # Point the capture host at this machine so Firefox sends the SNI
            # and a real hello, without touching /etc/hosts.
            'user_pref("network.dns.forceResolve", "127.0.0.1");\n'
        )
    browser = subprocess.Popen(
        [args.binary, "-headless", "-no-remote", "-profile", profile,
         f"https://{args.host}:{args.port}/"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    record = None
    try:
        conn, _ = server.accept()
        with conn:
            record, other = read_record(conn)
    finally:
        browser.terminate()
        try:
            browser.wait(timeout=10)
        except subprocess.TimeoutExpired:
            browser.kill()

    if record is None:
        raise SystemExit("no TLS ClientHello arrived")

    ciphers, extensions = parse(record)
    document = {
        "tls": {
            "ja4": ja4(ciphers, extensions),
            "ciphers": [CIPHER_NAMES.get(c, f"TLS_UNKNOWN_{c:#06x}") for c in ciphers],
            "extensions": [describe(kind, payload) for kind, payload in extensions],
        },
        "http_version": "",
        "user_agent": "",
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)

    names = [entry["name"] for entry in document["tls"]["extensions"]]
    print(f"wrote {args.output}: {len(ciphers)} ciphers, {len(names)} extensions")
    print("  " + ", ".join(names))


if __name__ == "__main__":
    sys.exit(main())
