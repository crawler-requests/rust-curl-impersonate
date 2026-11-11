//! QUIC transport parameter encoding.
//!
//! curl-impersonate stores a preset's transport parameters as an `id:value`
//! string and encodes it itself, then hands the raw bytes to ngtcp2. The
//! encoding is what a peer observes, so this module reproduces it: varint ids,
//! GREASE tokens, the `15:AUTO` source connection id, the `12583:AUTO` initial
//! RTT and the version-information lists all follow `quic_transport_params_from_string`
//! in curl-impersonate's `patches/curl.patch`.

use std::time::Duration;

use quinn::VarInt;

/// The largest QUIC variable-length integer, 2^62 - 1.
const VARINT_MAX: u64 = 0x3fff_ffff_ffff_ffff;

/// `initial_source_connection_id`. Its value is the local source connection id.
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
/// `version_information`, sent as a list of 32-bit versions.
const VERSION_INFORMATION: u64 = 0x11;
/// The draft code point for version information.
const VERSION_INFORMATION_DRAFT: u64 = 0xff73db;
/// Chrome's private initial RTT parameter, in microseconds.
const INITIAL_RTT: u64 = 0x3127;
/// Chrome's private version parameter, sent as four big-endian bytes.
const GOOGLE_VERSION: u64 = 0x4752;

/// GREASE transport parameter ids are `31 * N + 27`.
const GREASE_ID_BASE: u64 = 27;
const GREASE_ID_STEP: u64 = 31;
/// A GREASE value is between 1 and 8 random bytes.
const GREASE_VALUE_MAX_LEN: u64 = 8;

/// `12583:AUTO` centers the initial RTT on RFC 9002's 333ms, plus or minus 50ms.
const INITIAL_RTT_US_BASE: u64 = 333_000;
const INITIAL_RTT_US_JITTER: u64 = 50_000;

/// Server-only parameters a client preset must not send a value for.
const SERVER_ONLY: [u64; 6] = [
    0x00, // original_destination_connection_id
    0x02, // stateless_reset_token
    0x0d, // preferred_address
    0x10, // retry_source_connection_id
    VERSION_INFORMATION,
    VERSION_INFORMATION_DRAFT,
];

/// The randomness the encoder needs.
///
/// Every method maps onto one `Curl_rand` call in curl-impersonate, so a test
/// can pin the bytes by feeding fixed output.
pub trait Rng {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// Randomness drawn from the operating system.
pub struct SystemRng;

impl Rng for SystemRng {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("os randomness");
    }
}

/// One encoded transport parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedParam {
    /// The parameter id.
    pub id: u64,
    /// The raw value bytes.
    pub value: Vec<u8>,
}

/// The result of encoding a preset's transport parameter string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedParams {
    /// The bytes handed to BoringSSL through `SSL_set_quic_transport_params`.
    pub bytes: Vec<u8>,
    /// The parameters in encode order, for tests and for the values quinn has
    /// to agree with.
    pub params: Vec<EncodedParam>,
    /// `max_idle_timeout` in milliseconds, when the preset sets it.
    pub max_idle_timeout: Option<Duration>,
    /// `initial_max_data`.
    pub initial_max_data: Option<u64>,
    /// `initial_max_stream_data_bidi_local`.
    pub initial_max_stream_data_bidi_local: Option<u64>,
    /// `initial_max_stream_data_bidi_remote`.
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    /// `initial_max_stream_data_uni`.
    pub initial_max_stream_data_uni: Option<u64>,
    /// `initial_max_streams_bidi`.
    pub initial_max_streams_bidi: Option<u64>,
    /// `initial_max_streams_uni`.
    pub initial_max_streams_uni: Option<u64>,
    /// `max_udp_payload_size`.
    pub max_udp_payload_size: Option<u64>,
    /// `max_datagram_frame_size`.
    pub max_datagram_frame_size: Option<u64>,
    /// Chrome's initial RTT guess, when the preset sets `12583`.
    pub initial_rtt: Option<Duration>,
}

/// Encode a curl-impersonate transport parameter string.
///
/// `source_connection_id` supplies the bytes for `15:AUTO`. `15:` with an empty
/// value encodes a zero-length connection id, which is how Chrome's older
/// presets force an empty source connection id.
pub fn encode(
    spec: &str,
    source_connection_id: &[u8],
    rng: &mut impl Rng,
) -> Result<EncodedParams, ParamError> {
    let mut out = EncodedParams {
        bytes: Vec::new(),
        params: Vec::new(),
        max_idle_timeout: None,
        initial_max_data: None,
        initial_max_stream_data_bidi_local: None,
        initial_max_stream_data_bidi_remote: None,
        initial_max_stream_data_uni: None,
        initial_max_streams_bidi: None,
        initial_max_streams_uni: None,
        max_udp_payload_size: None,
        max_datagram_frame_size: None,
        initial_rtt: None,
    };

    for token in spec.split(';').filter(|token| !token.is_empty()) {
        if token.eq_ignore_ascii_case("GREASE") {
            let (id, value) = grease(rng);
            append(&mut out, id, &value);
            continue;
        }

        let (id_text, value_text) = match token.split_once(':') {
            Some((id, value)) => (id, Some(value)),
            None => (token, None),
        };
        let id = parse_u64(id_text)?;

        if SERVER_ONLY.contains(&id) && !matches_version_information(id, value_text) {
            return Err(ParamError::ServerOnly(id));
        }

        if id == INITIAL_SOURCE_CONNECTION_ID {
            let value = match value_text {
                Some(text) if text.eq_ignore_ascii_case("AUTO") => source_connection_id.to_vec(),
                Some("") => Vec::new(),
                _ => return Err(ParamError::BadValue(id)),
            };
            append(&mut out, id, &value);
            continue;
        }

        if matches_version_information(id, value_text) {
            let value = version_information(value_text.unwrap(), rng)?;
            append(&mut out, id, &value);
            continue;
        }

        if id == GOOGLE_VERSION {
            let value = value_text.ok_or(ParamError::BadValue(id))?;
            let number = parse_u64(value)?;
            if number > u32::MAX as u64 {
                return Err(ParamError::BadValue(id));
            }
            append(&mut out, id, &(number as u32).to_be_bytes());
            continue;
        }

        if let Some(text) =
            value_text.filter(|text| text.starts_with("0x") || text.starts_with("0X"))
        {
            append(
                &mut out,
                id,
                &decode_hex(&text[2..]).ok_or(ParamError::BadValue(id))?,
            );
            continue;
        }

        let number = match value_text {
            Some(text)
                if id == INITIAL_RTT
                    && (text.eq_ignore_ascii_case("AUTO")
                        || text.eq_ignore_ascii_case("RANDOM")) =>
            {
                initial_rtt(rng)
            }
            Some(text) => parse_u64(text)?,
            None => 0,
        };
        if number > VARINT_MAX {
            return Err(ParamError::OutOfRange(id));
        }
        record(&mut out, id, number);
        append(&mut out, id, &varint(number));
    }

    Ok(out)
}

/// Whether a preset's transport parameters force an empty source connection id.
///
/// curl-impersonate checks for a `15:` token with an empty value and, when no
/// connection id profile is set, generates no source connection id at all.
pub fn forces_empty_source_connection_id(spec: &str) -> bool {
    spec.split(';').any(|token| token == "15:")
}

/// The destination and source connection id lengths for a preset.
///
/// `webkit` uses an 8-byte destination and an empty source. `firefox`
/// randomizes the destination between 8 and 20 bytes and uses a 3-byte source.
/// Anything else uses the maximum length for both, unless the parameters force
/// an empty source connection id.
pub fn connection_id_lengths(
    profile: Option<&str>,
    spec: &str,
    rng: &mut impl Rng,
) -> (usize, usize) {
    match profile {
        Some("webkit") => (8, 0),
        Some("firefox") => {
            let mut byte = [0u8; 1];
            rng.fill(&mut byte);
            let value = byte[0];
            let mut length = 5 + (value & (value >> 4)) as usize;
            if length < 8 {
                length = 8;
            }
            (length, 3)
        }
        _ if forces_empty_source_connection_id(spec) => (20, 0),
        _ => (20, 20),
    }
}

/// The initial packet number a preset asks for.
///
/// `-1` is Neqo's biased distribution over 1..=1024. The resolved value is the
/// packet number on the first Initial.
pub fn initial_packet_number(preset: i64, rng: &mut impl Rng) -> u32 {
    if preset < 0 {
        let mut bytes = [0u8; 2];
        rng.fill(&mut bytes);
        let high = if bytes[1] > 224 { bytes[1] - 224 } else { 0 };
        (bytes[0] & 0x1f) as u32 + ((high as u32) << 5) + 1
    } else {
        preset as u32
    }
}

/// Apply the flow-control values quinn honors to a transport config.
///
/// quinn builds its own transport parameters from this config, and the peer
/// enforces whatever the handshake advertised. The two have to agree, so every
/// value the preset sets and quinn acts on is copied here. Parameters quinn
/// does not act on stay only in the raw bytes.
pub fn apply_flow_control(encoded: &EncodedParams, config: &mut quinn::TransportConfig) {
    if let Some(value) = encoded.max_idle_timeout {
        config.max_idle_timeout(Some(quinn::IdleTimeout::try_from(value).unwrap()));
    }
    if let Some(value) = encoded.initial_max_data {
        config.receive_window(VarInt::from_u64(value).unwrap());
    }
    // quinn keeps one stream window for every direction. A preset that sets
    // the three separately is represented by the local bidirectional window,
    // which is the one governing streams this client opens.
    if let Some(value) = encoded.initial_max_stream_data_bidi_local {
        config.stream_receive_window(VarInt::from_u64(value).unwrap());
    }
    if let Some(value) = encoded.initial_max_streams_bidi {
        config.max_concurrent_bidi_streams(VarInt::from_u64(value).unwrap());
    }
    if let Some(value) = encoded.initial_max_streams_uni {
        config.max_concurrent_uni_streams(VarInt::from_u64(value).unwrap());
    }
    if let Some(value) = encoded.max_datagram_frame_size {
        config.datagram_receive_buffer_size(Some(value as usize));
    }
    if let Some(value) = encoded.initial_rtt {
        config.initial_rtt(value);
    }
}

/// A transport parameter string this encoder rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamError {
    /// A token's id or value is not a number.
    BadNumber,
    /// A parameter needs a value this encoder cannot build.
    BadValue(u64),
    /// A server-only parameter was given a numeric value.
    ServerOnly(u64),
    /// A value does not fit in a QUIC varint.
    OutOfRange(u64),
}

fn matches_version_information(id: u64, value: Option<&str>) -> bool {
    value.is_some() && (id == VERSION_INFORMATION || id == VERSION_INFORMATION_DRAFT)
}

fn record(out: &mut EncodedParams, id: u64, value: u64) {
    let slot = match id {
        0x01 => &mut out.max_idle_timeout,
        0x04 => {
            out.initial_max_data = Some(value);
            return;
        }
        0x05 => {
            out.initial_max_stream_data_bidi_local = Some(value);
            return;
        }
        0x06 => {
            out.initial_max_stream_data_bidi_remote = Some(value);
            return;
        }
        0x07 => {
            out.initial_max_stream_data_uni = Some(value);
            return;
        }
        0x08 => {
            out.initial_max_streams_bidi = Some(value);
            return;
        }
        0x09 => {
            out.initial_max_streams_uni = Some(value);
            return;
        }
        0x03 => {
            out.max_udp_payload_size = Some(value);
            return;
        }
        0x20 => {
            out.max_datagram_frame_size = Some(value);
            return;
        }
        INITIAL_RTT => {
            out.initial_rtt = Some(Duration::from_micros(value));
            return;
        }
        _ => return,
    };
    *slot = Some(Duration::from_millis(value));
}

fn append(out: &mut EncodedParams, id: u64, value: &[u8]) {
    write_varint(&mut out.bytes, id);
    write_varint(&mut out.bytes, value.len() as u64);
    out.bytes.extend_from_slice(value);
    out.params.push(EncodedParam {
        id,
        value: value.to_vec(),
    });
}

fn grease(rng: &mut impl Rng) -> (u64, Vec<u8>) {
    let max_n = (VARINT_MAX - GREASE_ID_BASE) / GREASE_ID_STEP;
    let id = GREASE_ID_STEP * (random_u64(rng) % (max_n + 1)) + GREASE_ID_BASE;
    let mut len = [0u8; 1];
    rng.fill(&mut len);
    let len = (len[0] as u64 % GREASE_VALUE_MAX_LEN) + 1;
    let mut value = vec![0u8; len as usize];
    rng.fill(&mut value);
    (id, value)
}

fn initial_rtt(rng: &mut impl Rng) -> u64 {
    let mut bytes = [0u8; 2];
    rng.fill(&mut bytes);
    let span = INITIAL_RTT_US_JITTER * 2 + 1;
    let offset = (u64::from(bytes[0]) << 8 | u64::from(bytes[1])) % span;
    (INITIAL_RTT_US_BASE - INITIAL_RTT_US_JITTER) + offset
}

/// Encode `chosen@a,b,...` as the chosen version followed by the available
/// versions, each a big-endian u32. `GREASE` in the available list becomes four
/// bytes whose low nibble is `0xa`.
fn version_information(spec: &str, rng: &mut impl Rng) -> Result<Vec<u8>, ParamError> {
    let (chosen, available) = spec.split_once('@').ok_or(ParamError::BadNumber)?;
    if chosen.is_empty() || available.is_empty() {
        return Err(ParamError::BadNumber);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&parse_version(chosen, false, rng)?.to_be_bytes());
    for token in available.split(',') {
        if token.is_empty() {
            return Err(ParamError::BadNumber);
        }
        out.extend_from_slice(&parse_version(token, true, rng)?.to_be_bytes());
    }
    Ok(out)
}

fn parse_version(token: &str, allow_grease: bool, rng: &mut impl Rng) -> Result<u32, ParamError> {
    if allow_grease && token.eq_ignore_ascii_case("GREASE") {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes);
        let mut version = 0u32;
        for byte in bytes {
            version = (version << 8) | u32::from((byte & 0xf0) | 0x0a);
        }
        return Ok(version);
    }
    parse_u64(token)?
        .try_into()
        .map_err(|_| ParamError::BadNumber)
}

fn parse_u64(text: &str) -> Result<u64, ParamError> {
    if text.is_empty() {
        return Err(ParamError::BadNumber);
    }
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(rest) => (rest, 16),
        None => (text, 10),
    };
    u64::from_str_radix(digits, radix).map_err(|_| ParamError::BadNumber)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

fn random_u64(rng: &mut impl Rng) -> u64 {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes);
    u64::from_be_bytes(bytes)
}

/// The QUIC variable-length integer encoding of `value`.
pub fn varint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(&mut out, value);
    out
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    if value <= 0x3f {
        out.push(value as u8);
    } else if value <= 0x3fff {
        out.push(0x40 | (value >> 8) as u8);
        out.push(value as u8);
    } else if value <= 0x3fff_ffff {
        out.push(0x80 | (value >> 24) as u8);
        out.extend_from_slice(&(value as u32).to_be_bytes()[1..]);
    } else {
        out.push(0xc0 | (value >> 56) as u8);
        out.extend_from_slice(&value.to_be_bytes()[1..]);
    }
}

/// A [`Rng`] that replays fixed bytes, for tests.
pub struct ScriptedRng {
    bytes: Vec<u8>,
    cursor: usize,
}

impl ScriptedRng {
    /// Replay `bytes`, panicking if the encoder reads past the end.
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            cursor: 0,
        }
    }
}

impl Rng for ScriptedRng {
    fn fill(&mut self, buf: &mut [u8]) {
        let end = self.cursor + buf.len();
        buf.copy_from_slice(&self.bytes[self.cursor..end]);
        self.cursor = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_use_the_shortest_encoding() {
        assert_eq!(varint(0), [0x00]);
        assert_eq!(varint(63), [0x3f]);
        assert_eq!(varint(64), [0x40, 0x40]);
        assert_eq!(varint(16383), [0x7f, 0xff]);
        assert_eq!(varint(16384), [0x80, 0x00, 0x40, 0x00]);
        assert_eq!(varint(65536), [0x80, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn chrome145_encodes_empty_source_connection_id_and_version_info() {
        // Random bytes are consumed in token order. The version GREASE is read
        // before the initial RTT, and the parameter GREASE last.
        let mut rng = ScriptedRng::new(&[
            0x00, 0x00, 0xff, 0x10, // grease version -> 0x0a0afa1a
            0x20, 0x30, // rtt offset 0x2030 -> 291240us
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // grease id N = 0 -> 27
            0x00, // grease length 1
            0xab, // grease value
        ]);
        let encoded = encode(
            "1:30000;15:;17:1@1,GREASE;12583:AUTO;18258:1;GREASE",
            b"source-id",
            &mut rng,
        )
        .unwrap();

        assert_eq!(encoded.max_idle_timeout, Some(Duration::from_millis(30000)));
        assert_eq!(encoded.initial_rtt, Some(Duration::from_micros(291_240)));
        assert_eq!(
            encoded.params[1],
            EncodedParam {
                id: 0x0f,
                value: Vec::new()
            }
        );
        // chosen version 1, available version 1, then the grease version.
        assert_eq!(
            encoded.params[2].value,
            [0, 0, 0, 1, 0, 0, 0, 1, 0x0a, 0x0a, 0xfa, 0x1a]
        );
        // 18258 is four big-endian bytes, not a varint.
        assert_eq!(
            encoded.params[4],
            EncodedParam {
                id: 0x4752,
                value: vec![0, 0, 0, 1]
            }
        );
        assert_eq!(encoded.params[5].id, 27);
        assert_eq!(encoded.params[5].value, vec![0xab]);
        assert!(forces_empty_source_connection_id(
            "1:30000;15:;17:1@1,GREASE"
        ));
    }

    #[test]
    fn auto_source_connection_id_copies_the_local_id() {
        let mut rng = ScriptedRng::new(&[]);
        let encoded = encode("15:AUTO", b"abc", &mut rng).unwrap();
        assert_eq!(encoded.params[0].value, b"abc");
    }

    #[test]
    fn hex_values_are_raw_bytes() {
        let mut rng = ScriptedRng::new(&[]);
        let encoded = encode("12584:0x4f524947", b"", &mut rng).unwrap();
        assert_eq!(encoded.params[0].value, b"ORIG");
    }

    #[test]
    fn a_large_id_uses_a_four_byte_varint() {
        let mut rng = ScriptedRng::new(&[]);
        let encoded = encode("4278716424:0x09", b"", &mut rng).unwrap();
        assert_eq!(encoded.params[0].id, 4_278_716_424);
        assert_eq!(encoded.params[0].value, vec![0x09]);
        // The id is past the four-byte range, so the encoding uses eight bytes
        // and starts with the 0xc0 prefix.
        assert_eq!(encoded.bytes[0] & 0xc0, 0xc0);
    }

    #[test]
    fn server_only_parameters_are_rejected() {
        let mut rng = ScriptedRng::new(&[]);
        assert_eq!(encode("0:1", b"", &mut rng), Err(ParamError::ServerOnly(0)));
    }

    #[test]
    fn firefox_connection_id_length_stays_between_8_and_20() {
        let mut short = ScriptedRng::new(&[0x00]);
        assert_eq!(
            connection_id_lengths(Some("firefox"), "", &mut short),
            (8, 3)
        );
        let mut long = ScriptedRng::new(&[0xff]);
        assert_eq!(
            connection_id_lengths(Some("firefox"), "", &mut long),
            (20, 3)
        );
        let mut rng = ScriptedRng::new(&[]);
        assert_eq!(connection_id_lengths(Some("webkit"), "", &mut rng), (8, 0));
        assert_eq!(connection_id_lengths(None, "15:", &mut rng), (20, 0));
    }

    #[test]
    fn neqo_packet_number_stays_inside_1_to_1024() {
        let mut low = ScriptedRng::new(&[0x00, 0x00]);
        assert_eq!(initial_packet_number(-1, &mut low), 1);
        let mut high = ScriptedRng::new(&[0xff, 0xff]);
        // (0xff & 0x1f) + ((0xff - 224) << 5) + 1 = 31 + (31 << 5) + 1 = 1024.
        assert_eq!(initial_packet_number(-1, &mut high), 1024);
        let mut rng = ScriptedRng::new(&[]);
        assert_eq!(initial_packet_number(1, &mut rng), 1);
    }
}
