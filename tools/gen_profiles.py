#!/usr/bin/env python3
"""Generate src/profile/generated.rs from curl-impersonate's impersonate.c.

Reads the added lines of patches/curl.patch (the impersonations[] table) and
emits one Rust function per browser target. ML-DSA signature algorithms have no
TLS code point in BoringSSL, so they are dropped and recorded. HTTP/3 presets
are emitted as Http3Profile values consumed by the QUIC transport.
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
    "57": "ExtensionType::QUIC_TRANSPORT_PARAMETERS_STANDARD",
    "17613": "ExtensionType::APPLICATION_SETTINGS",
    "51764": "ExtensionType::from(51764)",
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
                "h3curves": string(text_of("http3_curves")),
                "h3sig": string(text_of("http3_sig_hash_algs")),
                "h3extorder": string(text_of("http3_tls_extension_order")),
                "h3pseudo": string(text_of("http3_pseudo_headers_order")),
                "h3headers": headers(text_of("http3_headers")),
                "h3headerorder": string(text_of("http3_http_header_order")),
                "quicparams": string(text_of("quic_transport_parameters")),
                "quiccid": string(text_of("quic_cid_length")),
                "quicpn": integer(re.search(r"=\s*(-?\d+)", text_of("quic_initial_packet_number")).group(1)) if "quic_initial_packet_number" in fields else None,
                "headers": headers(text_of("http_headers")),
                # Applied by src/profile/behavior.rs. Not emitted into generated.rs;
                # update that table when impersonations[] changes these fields.
                "split_cookies": boolean(re.search(r"=\s*(\w+)", text_of("split_cookies")).group(1)) if "split_cookies" in fields else False,
                "form_boundary": string(text_of("form_boundary")),
            })
            block = None
    return rows


def h3_settings_list(spec):
    """Render curl-impersonate's `id:value;GREASE` string as Rust entries."""
    items = []
    for part in spec.split(";"):
        if part == "GREASE":
            items.append("H3Setting::Grease")
        else:
            ident, value = part.split(":")
            items.append(f"H3Setting::Value({ident}, {value})")
    return ", ".join(items)


def emit_http3(row):
    """Emit the QUIC-only overrides of one preset.

    curl-impersonate applies http3_curves, http3_sig_hash_algs and
    http3_tls_extension_order only to QUIC connections, falling back to the TLS
    values when one is unset. http3_headers replaces the default headers only
    when the preset sets it.
    """
    target = row["target"]
    curves = row["h3curves"] or row["curves"]
    sig = row["h3sig"] if row["h3sig"] is not None else row["sig"]
    sigalgs = ":".join(name for name in (sig or "").split(":") if name and name not in MLDSA)
    extorder = row["h3extorder"] or row["extorder"]
    headerorder = row["h3headerorder"]

    lines = [f"fn http3_{fn_name(target)}() -> Http3Profile {{"]
    lines.append("    Http3Profile {")
    lines.append(f"        grease: {str(row['grease']).lower()},")
    lines.append(f"        signed_cert_timestamps: {str(row['sct']).lower()},")
    lines.append(f"        session_ticket: {str(row['ticket']).lower()},")
    lines.append(f"        curves: {rust_str(curves or '')},")
    lines.append(f"        sigalgs: {rust_str(sigalgs)},")
    lines.append(f"        ciphers: {rust_str(row['ciphers'])},")
    lines.append(f"        permute_extensions: {str(row['permute']).lower()},")
    lines.append(f"        ech_grease: {str(row['ech'] == 'true').lower()},")
    lines.append(f"        new_alps: {str(row['new_alps']).lower()},")
    lines.append(f"        delegated_credentials: {('Some(' + rust_str(row['delegated']) + ')') if row['delegated'] else 'None'},")
    lines.append(f"        record_size_limit: {('Some(' + str(row['recsize']) + ')') if row['recsize'] is not None else 'None'},")
    if extorder:
        ids = ", ".join(EXT[part] for part in extorder.split("-"))
        if "ExtensionType::from" in ids:
            # ExtensionType's constructor is not const, so a permutation that
            # names an extension btls leaves unnamed cannot live in a static.
            lines.append(f"        extension_permutation: Box::leak(Box::new([{ids}])),")
        else:
            lines.append(f"        extension_permutation: &[{ids}],")
    else:
        lines.append("        extension_permutation: &[],")
    if row["keyshare_limit"] and curves:
        shares = ", ".join(KEY_SHARE[name] for name in curves.split(":")[: row["keyshare_limit"]])
        lines.append(f"        key_shares: &[{shares}],")
    else:
        lines.append("        key_shares: &[],")
    if row["certcomp"]:
        compressors = ", ".join(f'"{name}"' for name in row["certcomp"].split(","))
        lines.append(f"        cert_compression: &[{compressors}],")
    else:
        lines.append("        cert_compression: &[],")
    lines.append(f"        settings: &[{h3_settings_list(row['h3settings'])}],")
    lines.append(f"        transport_parameters: {rust_str(row['quicparams'] or '')},")
    lines.append(f"        cid_profile: {('Some(' + rust_str(row['quiccid']) + ')') if row['quiccid'] else 'None'},")
    lines.append(f"        initial_packet_number: {'None' if row['quicpn'] is None else 'Some(' + str(row['quicpn']) + ')'},")
    lines.append(f"        pseudo_order: {rust_str(row['h3pseudo'] or '')},")
    lines.append(f"        header_order: {('Some(' + rust_str(headerorder) + ')') if headerorder else 'None'},")
    headers = row["h3headers"] or row["headers"]
    lines.append("        headers: &[")
    for entry in headers:
        name, value = entry.split(": ", 1)
        lines.append(f"            ({rust_str(name)}, {rust_str(value)}),")
    lines.append("        ],")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


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
    # BoringSSL treats 0 as "do not send the extension", which is exactly what
    # curl-impersonate's presets use 0 to mean, so the value is passed through.
    if row["recsize"] is not None:
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

    # curl-impersonate sends the preset headers in table order. HeaderMap does
    # not preserve order, so the order is recorded separately and applied by
    # wreq's orig_headers, which reorders the outgoing header block.
    out.append("    let mut headers = HeaderMap::new();")
    out.append("    let mut header_order = OrigHeaderMap::new();")
    for entry in row["headers"]:
        name, value = entry.split(": ", 1)
        key = KNOWN_HEADERS.get(name.lower(), f"header::HeaderName::from_static({rust_str(name.lower())})")
        out.append(f"    headers.insert({key}, HeaderValue::from_static({rust_str(value)}));")
        out.append(f"    header_order.insert({rust_str(name)});")

    out.append("    Emulation::builder()")
    out.append("        .tls_options(tls)")
    out.append("        .http2_options(http2)")
    out.append("        .headers(headers)")
    out.append("        .orig_headers(header_order)")
    out.append(f"        .build(wreq::Group::new({rust_str(target)}))")
    out.append("}")
    out.append("")
    return "\n".join(out), dropped


def main():
    rows = parse(sys.argv[1])
    parts = []
    match_arms = []
    http3_parts = []
    http3_arms = []
    targets = []
    notes = []
    for row in rows:
        body, dropped = emit_profile(row)
        parts.append(body)
        targets.append(row["target"])
        match_arms.append(f'        "{row["target"]}" => {fn_name(row["target"])}(),')
        if row["h3settings"]:
            http3_parts.append(emit_http3(row))
            http3_arms.append(f'        "{row["target"]}" => Some(http3_{fn_name(row["target"])}()),')
        if dropped:
            notes.append(f'    "{row["target"]}" => "drops signature algorithms {", ".join(dropped)}",')

    target_list = "\n".join(f"    {rust_str(target)}," for target in targets)
    http3_match = chr(10).join(http3_arms) if http3_arms else "        // no preset carries HTTP/3"
    text = f"""//! Browser profiles generated from curl-impersonate's `impersonations[]`.
//!
//! Regenerated by `tools/gen_profiles.py` from the added lines of
//! `patches/curl.patch`. Do not edit by hand.

use wreq::header::{{HeaderMap, HeaderValue, OrigHeaderMap}};
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

/// One HTTP/3 SETTINGS entry, in the order curl-impersonate sends it.
///
/// `Grease` stands for the literal `GREASE` token, which curl-impersonate turns
/// into a random setting id of the form `0x1f * N + 0x21` with a random value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3Setting {{
    /// A setting with a fixed id and value.
    Value(u64, u64),
    /// A GREASE setting whose id and value are chosen per connection.
    Grease,
}}

/// The QUIC-only settings of one browser preset.
///
/// curl-impersonate keeps these separate from the TLS and HTTP/2 settings and
/// applies them only after HTTP/3 is negotiated. An empty `key_shares` or
/// `cert_compression` means the preset sets no limit or no compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http3Profile {{
    /// TLS GREASE, matching the preset's `tls_grease`.
    pub grease: bool,
    /// Signed certificate timestamps extension.
    pub signed_cert_timestamps: bool,
    /// TLS session ticket extension.
    pub session_ticket: bool,
    /// Key exchange groups for the QUIC ClientHello.
    pub curves: &'static str,
    /// Signature algorithms for the QUIC ClientHello, with ML-DSA names removed.
    pub sigalgs: &'static str,
    /// Cipher list, shared with the TLS preset.
    pub ciphers: &'static str,
    /// BoringSSL's permuted-extension behavior.
    pub permute_extensions: bool,
    /// ECH grease extension.
    pub ech_grease: bool,
    /// Use the new ALPS codepoint.
    pub new_alps: bool,
    /// Delegated credentials signature algorithms, when the preset sets them.
    pub delegated_credentials: Option<&'static str>,
    /// Record size limit. `Some(0)` means the extension is not sent.
    pub record_size_limit: Option<u16>,
    /// ClientHello extension order for the QUIC handshake.
    pub extension_permutation: &'static [ExtensionType],
    /// Key shares, truncated to the preset's `tls_key_shares_limit`.
    pub key_shares: &'static [KeyShare],
    /// Certificate compression algorithms, in preset order.
    pub cert_compression: &'static [&'static str],
    /// HTTP/3 SETTINGS, in preset order.
    pub settings: &'static [H3Setting],
    /// QUIC transport parameters in curl-impersonate's `id:value` syntax.
    pub transport_parameters: &'static str,
    /// Connection id length profile, `webkit` or `firefox`.
    pub cid_profile: Option<&'static str>,
    /// Initial packet number. `-1` is Neqo's biased random range 1..=1024.
    pub initial_packet_number: Option<i64>,
    /// HTTP/3 pseudo-header order, letters `m`, `a`, `s`, `p`.
    pub pseudo_order: &'static str,
    /// HTTP/3 header order. `None` keeps the preset's HTTP header order.
    pub header_order: Option<&'static str>,
    /// HTTP/3 request headers. The preset's own `http3_headers` when set, else
    /// the default headers.
    pub headers: &'static [(&'static str, &'static str)],
}}

/// The HTTP/3 settings of a preset, when it carries any.
pub fn http3(target: &str) -> Option<Http3Profile> {{
    match target {{
{http3_match}
        _ => None,
    }}
}}

{chr(10).join(parts)}
{chr(10).join(http3_parts)}"""
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
