#!/usr/bin/env python3
"""Generate src/profile/generated.rs from curl-impersonate's impersonate.c.

Reads the added lines of patches/curl.patch (the impersonations[] table) and
emits one Rust function per browser target. Only fields the transport can
actually send are emitted; HTTP/3 and ML-DSA entries are recorded as dropped.
"""

import re
import sys

H2 = {
    "1": "SettingId::HeaderTableSize",
    "2": "SettingId::EnablePush",
    "3": "SettingId::MaxConcurrentStreams",
    "4": "SettingId::InitialWindowSize",
    "5": "SettingId::MaxFrameSize",
    "6": "SettingId::MaxHeaderListSize",
    "8": "SettingId::EnableConnectProtocol",
    "9": "SettingId::NoRfc7540Priorities",
}
H2_SETTER = {
    "1": ("header_table_size", "u32"),
    "2": ("enable_push", "bool"),
    "3": ("max_concurrent_streams", "u32"),
    "4": ("initial_window_size", "u32"),
    "5": ("max_frame_size", "u32"),
    "6": ("max_header_list_size", "u32"),
    "8": ("enable_connect_protocol", "bool"),
    "9": ("no_rfc7540_priorities", "bool"),
}
PSEUDO = {
    "m": "PseudoId::Method",
    "a": "PseudoId::Authority",
    "s": "PseudoId::Scheme",
    "p": "PseudoId::Path",
}
# curl-impersonate extension ids that BoringSSL's extension order accepts.
EXT = {
    "0": "ExtensionType::SERVER_NAME",
    "5": "ExtensionType::STATUS_REQUEST",
    "10": "ExtensionType::SUPPORTED_GROUPS",
    "11": "ExtensionType::EC_POINT_FORMATS",
    "13": "ExtensionType::SIGNATURE_ALGORITHMS",
    "16": "ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION",
    "18": "ExtensionType::CERTIFICATE_TIMESTAMP",
    "23": "ExtensionType::EXTENDED_MASTER_SECRET",
    "27": "ExtensionType::CERT_COMPRESSION",
    "28": "ExtensionType::RECORD_SIZE_LIMIT",
    "34": "ExtensionType::DELEGATED_CREDENTIAL",
    "35": "ExtensionType::SESSION_TICKET",
    "43": "ExtensionType::SUPPORTED_VERSIONS",
    "45": "ExtensionType::PSK_KEY_EXCHANGE_MODES",
    "51": "ExtensionType::KEY_SHARE",
    "65037": "ExtensionType::ENCRYPTED_CLIENT_HELLO",
    "65281": "ExtensionType::RENEGOTIATE",
}
KEY_SHARE = {
    "X25519MLKEM768": "KeyShare::X25519_MLKEM768",
    "X25519Kyber768Draft00": "KeyShare::X25519_KYBER768_DRAFT00",
    "X25519": "KeyShare::X25519",
    "P-256": "KeyShare::P256",
    "P-384": "KeyShare::P384",
    "P-521": "KeyShare::P521",
    "ffdhe2048": "KeyShare::FFDHE2048",
    "ffdhe3072": "KeyShare::FFDHE3072",
}
COMPRESSOR = {"brotli": "BrotliCompressor", "zlib": "ZlibCompressor", "zstd": "ZstdCompressor"}
KNOWN_HEADERS = {
    "user-agent": "header::USER_AGENT",
    "accept": "header::ACCEPT",
    "accept-encoding": "header::ACCEPT_ENCODING",
    "accept-language": "header::ACCEPT_LANGUAGE",
    "upgrade-insecure-requests": "header::UPGRADE_INSECURE_REQUESTS",
    "te": "header::TE",
}

MLDSA = ("mldsa44", "mldsa65", "mldsa87")


def take_expr(rest):
    """Read one initializer value, respecting nested braces and parentheses.

    The value starts at depth zero. An opening brace raises the depth, so the
    matching close returns to zero and is included; the comma after it ends the
    value.
    """
    depth = 0
    out = []
    for ch in rest:
        if ch in "{(":
            depth += 1
        elif ch in "})":
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
        if depth < 0:
            break
    return "".join(out)

def grab(block, field):
    match = re.search(r"\." + field + r"\s*=\s*", block)
    return take_expr(block[match.end():]).strip() if match else None


def string(expr):
    """Concatenate the C string literals in an initializer, ignoring newlines."""
    if expr is None or re.search(r"=\s*NULL\b", expr):
        return None
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', expr)
    return "".join(unescape(part) for part in parts) or None


def boolean(expr):
    return expr == "true"


def integer(expr):
    if expr is None:
        return None
    try:
        return int(expr)
    except ValueError:
        return None


def unescape(literal):
    return literal.encode().decode("unicode_escape")


def headers(expr):
    """Each header is its own C string literal inside the brace initializer."""
    if not expr:
        return []
    return [unescape(part) for part in re.findall(r'"((?:[^"\\]|\\.)*)"', expr)]

def rust_str(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def fn_name(target):
    return "profile_" + target


def parse(path):
    """Read the impersonations[] table with a line-oriented state machine.

    Each preset starts at a line that is exactly two spaces followed by an
    opening brace and ends at a line that is exactly two spaces followed by a
    closing brace. Field values are either a single token or a run of adjacent
    string literals; a brace value collects every string literal up to its
    matching close.
    """
    lines = open(path).read().splitlines()
    start_at = next(i for i, line in enumerate(lines) if "impersonations[]" in line)

    def field_at(block, index):
        """Return the value lines of the field declared at index.

        A value continues onto following lines while braces are unbalanced or
        the next line is only a string literal, which is how the cipher and
        signature lists are wrapped.
        """
        collected = [block[index]]
        depth = block[index].count("{") - block[index].count("}")
        while True:
            if depth > 0:
                index += 1
            elif index + 1 < len(block) and re.match(r'\s*"[^"]*"\s*,?\s*$', block[index + 1]):
                index += 1
            else:
                break
            collected.append(block[index])
            depth += block[index].count("{") - block[index].count("}")
        return collected

    rows = []
    block = None
    for line in lines[start_at + 1:]:
        if line.startswith("};"):
            break
        if line == "  {":
            block = [line]
            continue
        if block is None:
            continue
        block.append(line)
        if line.startswith("  }"):
            fields = {}
            for index, content in enumerate(block):
                match = re.match(r"\s*\.([a-z0-9_]+)\s*=\s*(.*)", content)
                if match:
                    fields[match.group(1)] = field_at(block, index)
            text_of = lambda name: "\n".join(fields.get(name, []))
            rows.append({
                "target": string(text_of("target")),
                "ciphers": string(text_of("ciphers")),
                "curves": string(text_of("curves")),
                "sig": string(text_of("sig_hash_algs")),
                "permute": boolean(re.search(r"=\s*(\w+)", text_of("tls_permute_extensions")).group(1)) if "tls_permute_extensions" in fields else False,
                "ticket": boolean(re.search(r"=\s*(\w+)", text_of("tls_session_ticket")).group(1)) if "tls_session_ticket" in fields else False,
                "certcomp": string(text_of("cert_compression")),
                "grease": boolean(re.search(r"=\s*(\w+)", text_of("tls_grease")).group(1)) if "tls_grease" in fields else False,
                "new_alps": boolean(re.search(r"=\s*(\w+)", text_of("tls_use_new_alps_codepoint")).group(1)) if "tls_use_new_alps_codepoint" in fields else False,
                "sct": boolean(re.search(r"=\s*(\w+)", text_of("tls_signed_cert_timestamps")).group(1)) if "tls_signed_cert_timestamps" in fields else False,
                "extorder": string(text_of("tls_extension_order")),
                "keyshare_limit": integer(re.search(r"=\s*(-?\d+)", text_of("tls_key_shares_limit")).group(1)) if "tls_key_shares_limit" in fields else None,
                "recsize": integer(re.search(r"=\s*(-?\d+)", text_of("tls_record_size_limit")).group(1)) if "tls_record_size_limit" in fields else None,
                "delegated": string(text_of("tls_delegated_credentials")),
                "ech": string(text_of("ech")),
                "h2settings": string(text_of("http2_settings")),
                "h2window": integer(re.search(r"=\s*(-?\d+)", text_of("http2_window_update")).group(1)) if "http2_window_update" in fields else None,
                "h2weight": integer(re.search(r"=\s*(-?\d+)", text_of("http2_stream_weight")).group(1)) if "http2_stream_weight" in fields else None,
                "h2excl": integer(re.search(r"=\s*(-?\d+)", text_of("http2_stream_exclusive")).group(1)) if "http2_stream_exclusive" in fields else None,
                "h2pseudo": string(text_of("http2_pseudo_headers_order")),
                "h3settings": string(text_of("http3_settings")),
                "headers": headers(text_of("http_headers")),
            })
            block = None
    return rows

def emit_profile(row):
    target = row["target"]
    out = [f"fn {fn_name(target)}() -> Emulation {{"]

    dropped = [name for name in (row["sig"] or "").split(":") if name in MLDSA]
    sigalgs = ":".join(name for name in (row["sig"] or "").split(":") if name and name not in MLDSA)

    out.append("    let tls = TlsOptions::builder()")
    out.append(f"        .grease_enabled({str(row['grease']).lower()})")
    out.append("        .enable_ocsp_stapling(true)")
    out.append(f"        .enable_signed_cert_timestamps({str(row['sct']).lower()})")
    out.append(f"        .session_ticket({str(row['ticket']).lower()})")
    if row["curves"]:
        out.append(f"        .curves_list({rust_str(row['curves'])})")
    if sigalgs:
        out.append(f"        .sigalgs_list({rust_str(sigalgs)})")
    out.append(f"        .cipher_list({rust_str(row['ciphers'])})")
    out.append("        .preserve_tls13_cipher_list(true)")
    out.append("        .min_tls_version(TlsVersion::TLS_1_2)")
    out.append("        .max_tls_version(TlsVersion::TLS_1_3)")
    out.append(f"        .permute_extensions({str(row['permute']).lower()})")
    out.append("        .pre_shared_key(true)")
    out.append(f"        .enable_ech_grease({str(row['ech'] == 'true').lower()})")
    if row["new_alps"]:
        out.append("        .alps_protocols([AlpsProtocol::HTTP2])")
        out.append("        .alps_use_new_codepoint(true)")
    if row["delegated"]:
        out.append(f"        .delegated_credentials({rust_str(row['delegated'])})")
    if row["recsize"] not in (None, 0):
        out.append(f"        .record_size_limit({row['recsize']})")
    if row["extorder"]:
        ids = ", ".join(EXT[part] for part in row["extorder"].split("-"))
        out.append(f"        .extension_permutation(&[{ids}])")
    if row["keyshare_limit"] and row["curves"]:
        shares = ", ".join(
            KEY_SHARE[name] for name in row["curves"].split(":")[: row["keyshare_limit"]]
        )
        out.append(f"        .key_shares(&[{shares}])")
    if row["certcomp"]:
        compressors = ", ".join(
            f"&{COMPRESSOR[name]} as &dyn CertificateCompressor"
            for name in row["certcomp"].split(",")
        )
        out.append(f"        .certificate_compressors(&[{compressors}])")
    out.append("        .build();")

    out.append("    let http2 = Http2Options::builder()")
    order = []
    for part in (row["h2settings"] or "").split(";"):
        ident, value = part.split(":")
        setter, kind = H2_SETTER[ident]
        rendered = value if kind == "u32" else ("true" if value == "1" else "false")
        out.append(f"        .{setter}({rendered})")
        order.append(H2[ident])
    if row["h2window"]:
        out.append(f"        .initial_connection_window_size({row['h2window']})")
    if row["h2weight"]:
        weight = row["h2weight"] - 1
        exclusive = "true" if row["h2excl"] else "false"
        out.append(
            f"        .headers_stream_dependency(StreamDependency::new(StreamId::zero(), {weight}, {exclusive}))"
        )
    if row["h2pseudo"]:
        pseudos = ", ".join(PSEUDO[char] for char in row["h2pseudo"])
        out.append("        .headers_pseudo_order(")
        out.append("            PseudoOrder::builder()")
        out.append(f"                .extend([{pseudos}])")
        out.append("                .build(),")
        out.append("        )")
    if order:
        out.append("        .settings_order(")
        out.append("            SettingsOrder::builder()")
        out.append(f"                .extend([{', '.join(order)}])")
        out.append("                .build(),")
        out.append("        )")
    out.append("        .build();")

    out.append("    let mut headers = HeaderMap::new();")
    for entry in row["headers"]:
        name, value = entry.split(": ", 1)
        key = KNOWN_HEADERS.get(name.lower(), f"header::HeaderName::from_static({rust_str(name.lower())})")
        out.append(f"    headers.insert({key}, HeaderValue::from_static({rust_str(value)}));")

    out.append("    Emulation::builder()")
    out.append("        .tls_options(tls)")
    out.append("        .http2_options(http2)")
    out.append("        .headers(headers)")
    out.append(f"        .build(wreq::Group::new({rust_str(target)}))")
    out.append("}")
    out.append("")
    return "\n".join(out), dropped


def main():
    rows = parse(sys.argv[1])
    parts = []
    match_arms = []
    targets = []
    notes = []
    for row in rows:
        body, dropped = emit_profile(row)
        parts.append(body)
        targets.append(row["target"])
        match_arms.append(f'        "{row["target"]}" => {fn_name(row["target"])}(),')
        if dropped or row["h3settings"] or row["recsize"] == 0:
            bits = []
            if dropped:
                bits.append("drops signature algorithms " + ", ".join(dropped))
            if row["h3settings"]:
                bits.append("HTTP/3 settings have no QUIC transport")
            if row["recsize"] == 0:
                bits.append("record_size_limit 0 is rejected by BoringSSL and omitted")
            notes.append(f'    "{row["target"]}" => "{"; ".join(bits)}",')

    target_list = "\n".join(f"    {rust_str(target)}," for target in targets)
    text = f"""//! Browser profiles generated from curl-impersonate's `impersonations[]`.
//!
//! Regenerated by `tools/gen_profiles.py` from the added lines of
//! `patches/curl.patch`. Do not edit by hand.

use wreq::header::{{HeaderMap, HeaderValue}};
use wreq::http2::{{
    Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
}};
use wreq::tls::compress::CertificateCompressor;
use wreq::tls::{{AlpsProtocol, ExtensionType, KeyShare, TlsOptions, TlsVersion}};
use wreq::{{header, Emulation}};

use super::compress::{{BrotliCompressor, ZlibCompressor, ZstdCompressor}};

/// Every browser target recorded in curl-impersonate's `lib/impersonate.c`.
pub const TARGETS: &[&str] = &[
{target_list}
];

/// Resolve a curl-impersonate target to the settings sent on the wire.
pub fn emulation(target: &str) -> Option<Emulation> {{
    Some(match target {{
{chr(10).join(match_arms)}
        _ => return None,
    }})
}}

/// Why a target's wire settings differ from curl-impersonate's preset.
pub fn deviation(target: &str) -> Option<&'static str> {{
    Some(match target {{
{chr(10).join(notes)}
        _ => return None,
    }})
}}

{chr(10).join(parts)}"""
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
