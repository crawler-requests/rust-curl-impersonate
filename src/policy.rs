//! Pure decisions the shipped client applies before it opens a connection.
//!
//! Header merge, cookie splitting, redirect classification, packet-number
//! checks, connection-id profiles and trust-anchor encoding live here so the
//! handshake, the HTTP/3 send path and the WebSocket path all call one
//! implementation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::profile::H3Setting;

/// `name` or `name:yes` / `name:no`. `yes` installs the preset's base headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpersonateSpec {
    pub name: String,
    pub base_headers: bool,
}

/// Parse `CURLOPT_IMPERSONATE` / `CURL_IMPERSONATE`.
pub fn parse_impersonate(spec: &str) -> Result<ImpersonateSpec, String> {
    let (name, base_headers) = match spec.split_once(':') {
        Some((name, "yes")) => (name, true),
        Some((name, "no")) => (name, false),
        Some(_) => return Err("impersonate flag must be yes or no".to_string()),
        None => (spec, true),
    };
    if name.is_empty() {
        return Err("impersonate name is empty".to_string());
    }
    Ok(ImpersonateSpec {
        name: name.to_string(),
        base_headers,
    })
}

/// An explicit target wins. The environment value is used only when the caller
/// did not choose one.
pub fn select_impersonate<'a>(
    explicit: Option<&'a str>,
    environment: Option<&'a str>,
) -> Option<&'a str> {
    explicit.or(environment)
}

/// Replace a matching default, drop it when the caller value is empty, and
/// keep every other default. New names are appended.
pub fn merge_headers(
    defaults: &[(String, String)],
    caller: &[(String, String)],
) -> Vec<(String, String)> {
    let mut out = defaults.to_vec();
    for (name, value) in caller {
        if let Some(index) = out
            .iter()
            .position(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            if value.is_empty() {
                out.remove(index);
            } else {
                out[index].1 = value.clone();
            }
        } else if !value.is_empty() {
            out.push((name.clone(), value.clone()));
        }
    }
    out
}

/// `order` is a comma-separated header list. Named headers move to the front.
/// Headers the order does not mention keep their relative order after that.
pub fn order_headers(headers: &[(String, String)], order: &str) -> Vec<(String, String)> {
    let wanted: Vec<&str> = order
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let mut out = Vec::with_capacity(headers.len());
    for name in wanted {
        if let Some(header) = headers
            .iter()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            if !out
                .iter()
                .any(|(existing, _): &(String, String)| existing.eq_ignore_ascii_case(name))
            {
                out.push(header.clone());
            }
        }
    }
    for header in headers {
        if !out
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(&header.0))
        {
            out.push(header.clone());
        }
    }
    out
}

/// Which HTTP version a cookie header is being built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieProtocol {
    Http1,
    Http2,
    Http3,
}

/// HTTP/1.1 keeps one `Cookie` header. HTTP/2 and HTTP/3 split when the preset
/// asks for it.
pub fn split_for(protocol: CookieProtocol, preset_splits: bool) -> bool {
    preset_splits && protocol != CookieProtocol::Http1
}

/// Letters `m`, `a`, `s`, `p` only, in the order given.
pub fn pseudo_letters(spec: &str) -> Result<Vec<char>, String> {
    if spec.is_empty() {
        return Err("pseudo-header order is empty".to_string());
    }
    let mut seen = [false; 4];
    let mut letters = Vec::new();
    for letter in spec.chars() {
        // Captures report the order as `a,m,p,s`; presets use `amps`. Accept
        // either spelling.
        if letter == ',' || letter.is_ascii_whitespace() {
            continue;
        }
        let index = match letter {
            'm' => 0,
            'a' => 1,
            's' => 2,
            'p' => 3,
            _ => return Err(format!("pseudo-header order rejects {letter}")),
        };
        if seen[index] {
            return Err(format!("pseudo-header order repeats {letter}"));
        }
        seen[index] = true;
        letters.push(letter);
    }
    if letters.is_empty() {
        return Err("pseudo-header order is empty".to_string());
    }
    Ok(letters)
}

/// One `id:value` pair from `CURLOPT_HTTP2_SETTINGS` or `CURLOPT_HTTP3_SETTINGS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingPair {
    pub id: u64,
    pub value: u64,
}

/// Parse `1:v;2:v`. `GREASE` is an HTTP/3 grease setting.
pub fn setting_pairs(spec: &str) -> Result<Vec<SettingPair>, String> {
    if spec.is_empty() {
        return Err("settings are empty".to_string());
    }
    let mut pairs = Vec::new();
    for token in spec.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if token.eq_ignore_ascii_case("GREASE") {
            return Err("this settings list is not HTTP/3".to_string());
        }
        let Some((id, value)) = token.split_once(':') else {
            return Err(format!("setting {token} is not id:value"));
        };
        let id = id.parse::<u64>().map_err(|_| format!("setting id {id}"))?;
        let value = value
            .parse::<u64>()
            .map_err(|_| format!("setting value {value}"))?;
        pairs.push(SettingPair { id, value });
    }
    if pairs.is_empty() {
        return Err("settings are empty".to_string());
    }
    Ok(pairs)
}

/// HTTP/3 settings, including a `GREASE` token.
pub fn http3_settings(spec: &str) -> Result<Vec<H3Setting>, String> {
    if spec.is_empty() {
        return Err("http3 settings are empty".to_string());
    }
    let mut settings = Vec::new();
    for token in spec.split(';') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if token.eq_ignore_ascii_case("GREASE") {
            settings.push(H3Setting::Grease);
            continue;
        }
        let Some((id, value)) = token.split_once(':') else {
            return Err(format!("http3 setting {token} is not id:value"));
        };
        let id = id.parse::<u64>().map_err(|_| format!("setting id {id}"))?;
        let value = value
            .parse::<u64>()
            .map_err(|_| format!("setting value {value}"))?;
        settings.push(H3Setting::Value(id, value));
    }
    if settings.is_empty() {
        return Err("http3 settings are empty".to_string());
    }
    Ok(settings)
}

/// `0-5-10` decimal extension type ids.
pub fn extension_ids(spec: &str) -> Result<Vec<u16>, String> {
    if spec.is_empty() {
        return Err("extension order is empty".to_string());
    }
    let mut ids = Vec::new();
    for part in spec.split('-') {
        if part.is_empty() {
            return Err("extension order has an empty id".to_string());
        }
        let id = part
            .parse::<u16>()
            .map_err(|_| format!("extension id {part}"))?;
        ids.push(id);
    }
    Ok(ids)
}

/// `0..=2147483647` or `-1`. Anything else is an argument error.
pub fn check_initial_packet_number(value: i64) -> Result<(), String> {
    if value == -1 || (0..=2_147_483_647).contains(&value) {
        Ok(())
    } else {
        Err("initial packet number must be -1 or 0..=2147483647".to_string())
    }
}

/// `webkit` or `firefox` connection-id profiles.
pub fn cid_profile(spec: &str) -> Result<&'static str, String> {
    match spec {
        "webkit" => Ok("webkit"),
        "firefox" => Ok("firefox"),
        _ => Err("connection id profile must be webkit or firefox".to_string()),
    }
}

/// Drop the three ML-DSA names BoringSSL will not install.
pub fn install_sigalgs(list: &str) -> String {
    list.split(':')
        .filter(|name| !matches!(*name, "mldsa44" | "mldsa65" | "mldsa87"))
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(":")
}

pub fn contains_mldsa(list: &str) -> bool {
    list.split(':')
        .any(|name| matches!(name, "mldsa44" | "mldsa65" | "mldsa87"))
}

/// Certificate compression names the handshake knows.
pub fn cert_compression_names(spec: &str) -> Result<Vec<String>, String> {
    if spec.is_empty() {
        return Err("certificate compression is empty".to_string());
    }
    let mut names = Vec::new();
    for name in spec.split(|c| c == ',' || c == ':') {
        let name = name.trim();
        if !matches!(name, "zlib" | "brotli" | "zstd") {
            return Err(format!("unknown certificate compression {name}"));
        }
        names.push(name.to_string());
    }
    Ok(names)
}

/// Trust-anchor advertisement. Empty input still advertises the extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchors {
    /// Wire bytes passed to `SSL_CTX_set1_requested_trust_anchors`.
    pub wire: Vec<u8>,
    /// Each identifier, so a test can compare the set without the random order.
    pub ids: Vec<Vec<u8>>,
}

/// Comma-separated relative OIDs under `1.3.6.1.4.1`, shuffled into wire order.
///
/// An empty string advertises support and names no anchor. The bytes are the
/// DER contents of the full OID, length-prefixed the way BoringSSL expects.
pub fn trust_anchors(spec: &str) -> Result<TrustAnchors, String> {
    if spec.is_empty() {
        return Ok(TrustAnchors {
            wire: Vec::new(),
            ids: Vec::new(),
        });
    }
    let mut ids = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("trust anchor list has an empty oid".to_string());
        }
        ids.push(encode_relative_oid(part)?);
    }
    shuffle(&mut ids);
    let mut wire = Vec::new();
    for id in &ids {
        if id.is_empty() || id.len() > 255 {
            return Err("trust anchor does not fit in one byte of length".to_string());
        }
        wire.push(id.len() as u8);
        wire.extend_from_slice(id);
    }
    Ok(TrustAnchors { wire, ids })
}

fn encode_relative_oid(relative: &str) -> Result<Vec<u8>, String> {
    let mut arcs = vec![1u64, 3, 6, 1, 4, 1];
    for piece in relative.split('.') {
        if piece.is_empty() {
            return Err("empty oid arc".to_string());
        }
        let arc = piece
            .parse::<u64>()
            .map_err(|_| format!("oid arc {piece}"))?;
        arcs.push(arc);
    }
    let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for arc in arcs.iter().skip(2) {
        out.extend(base128(*arc));
    }
    Ok(out)
}

fn base128(mut value: u64) -> Vec<u8> {
    let mut bytes = vec![((value & 0x7f) as u8)];
    value >>= 7;
    while value > 0 {
        bytes.push((value & 0x7f) as u8 | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}

fn shuffle(items: &mut [Vec<u8>]) {
    if items.len() < 2 {
        return;
    }
    let mut entropy = [0u8; 8];
    getrandom::fill(&mut entropy).ok();
    let mut state = u64::from_le_bytes(entropy) | 1;
    for index in (1..items.len()).rev() {
        state = state.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        let pick = (state as usize) % (index + 1);
        items.swap(index, pick);
    }
}

/// HTTP and SOCKS4a/SOCKS5h resolve the origin. SOCKS4 and SOCKS5 do not.
pub fn delegates_origin_dns(proxy_url: Option<&str>) -> bool {
    let Some(url) = proxy_url else {
        return false;
    };
    let scheme = url.split("://").next().unwrap_or("");
    matches!(scheme, "http" | "https" | "socks4a" | "socks5h")
}

/// A redirected connection to these addresses is rejected by `CURLFOLLOW_SAFE`.
pub fn redirect_address_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => ipv4_blocked(addr),
        IpAddr::V6(addr) => ipv6_blocked(addr),
    }
}

fn ipv4_blocked(addr: Ipv4Addr) -> bool {
    addr.is_loopback() || addr.is_private() || addr.is_link_local()
}

fn ipv6_blocked(addr: Ipv6Addr) -> bool {
    addr.is_loopback() || unique_local(addr) || addr.is_unicast_link_local()
}

fn unique_local(addr: Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// `true` when a stored TLS session may be reused for this credential generation.
pub fn reuse_session(stored_generation: u64, current_generation: u64, no_reuse: bool) -> bool {
    !no_reuse || stored_generation == current_generation
}

/// `SET` or `DELETE`, a tab, then a Netscape cookie line.
pub fn cookie_change_line(action: &str, netscape: &str) -> String {
    format!("{action}\t{netscape}")
}

/// Status, a tab, then the request URL that returned it.
pub fn redirect_history_line(status: u16, url: &str) -> String {
    format!("{status}\t{url}")
}

/// Headers used once the protocol is known.
///
/// HTTP/3 uses the caller's HTTP/3 list when set, otherwise the profile's
/// HTTP/3 defaults. Fallback and HTTP/2 use the regular defaults.
pub fn negotiated_headers(
    http3: bool,
    http3_override: Option<&[(String, String)]>,
    profile_http3: Option<&[(&str, &str)]>,
    regular: &[(String, String)],
) -> Vec<(String, String)> {
    if http3 {
        if let Some(headers) = http3_override {
            return headers.to_vec();
        }
        if let Some(headers) = profile_http3 {
            return headers
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect();
        }
    }
    regular.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_trust_anchors_advertise_nothing_specific() {
        let anchors = trust_anchors("").unwrap();
        assert!(anchors.wire.is_empty());
        assert!(anchors.ids.is_empty());
    }

    #[test]
    fn trust_anchor_oids_sit_under_the_prefix() {
        let anchors = trust_anchors("1.2").unwrap();
        assert_eq!(anchors.ids.len(), 1);
        assert_eq!(anchors.ids[0], encode_relative_oid("1.2").unwrap());
        assert_eq!(anchors.wire[0] as usize, anchors.ids[0].len());
    }
}
