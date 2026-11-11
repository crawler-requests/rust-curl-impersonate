//! HTTP/3 frames.
//!
//! curl-impersonate submits a preset's HTTP/3 SETTINGS through nghttp3 and
//! writes request headers in the preset's pseudo-header and header order. The
//! `h3` crate fixes both orders, so the frames are written here instead.
//!
//! QPACK encoding uses the `qpack` crate's stateless encoder, which emits
//! fields in the order it is given and never touches the dynamic table. That
//! matches what the presets produce: no preset relies on QPACK compression
//! beyond the static table.

use bytes::{Buf, BufMut, BytesMut};
use qpack::{encode_stateless, HeaderField};

use crate::profile::H3Setting;

/// A control stream type.
const STREAM_CONTROL: u64 = 0x00;
/// A QPACK encoder stream type.
const STREAM_ENCODER: u64 = 0x02;
/// A QPACK decoder stream type.
const STREAM_DECODER: u64 = 0x03;

/// Frame types.
const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const FRAME_SETTINGS: u64 = 0x04;

/// The control stream preface: the stream type followed by the SETTINGS frame.
///
/// GREASE settings take a random id of the form `0x1f * N + 0x21` and a random
/// value, which is how Chrome fills the `GREASE` token. `rng` supplies the
/// bytes, so a test can pin the result.
pub fn control_preface(settings: &[H3Setting], rng: &mut impl crate::quic::Rng) -> Vec<u8> {
    let mut out = BytesMut::new();
    write_varint(&mut out, STREAM_CONTROL);
    write_settings(&mut out, settings, rng);
    out.to_vec()
}

/// The QPACK encoder stream preface. Stateless encoding sends nothing on it,
/// but the stream itself has to exist.
pub fn encoder_preface() -> Vec<u8> {
    varint(STREAM_ENCODER)
}

/// The QPACK decoder stream preface.
pub fn decoder_preface() -> Vec<u8> {
    varint(STREAM_DECODER)
}

/// A HEADERS frame carrying `headers` in the given order.
///
/// `headers` is the pseudo-headers followed by the regular headers, already
/// arranged the way the preset wants them on the wire.
pub fn headers_frame(headers: &[(&str, &str)]) -> Vec<u8> {
    let fields: Vec<HeaderField> = headers
        .iter()
        .map(|(name, value)| HeaderField::new(*name, *value))
        .collect();
    let mut block = BytesMut::new();
    encode_stateless(&mut block, &fields).expect("stateless qpack encoding");
    frame(FRAME_HEADERS, &block)
}

/// A DATA frame.
pub fn data_frame(payload: &[u8]) -> Vec<u8> {
    frame(FRAME_DATA, payload)
}

/// One decoded HTTP/3 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A HEADERS frame, QPACK-encoded.
    Headers(Vec<u8>),
    /// A DATA frame.
    Data(Vec<u8>),
    /// A frame this client does not act on.
    Other,
}

/// Decode the next frame from `buf`, removing it.
///
/// Returns `None` when the buffer does not yet hold a whole frame.
pub fn decode_frame(buf: &mut BytesMut) -> Option<Frame> {
    let mut cursor = &buf[..];
    let frame_type = read_varint(&mut cursor)?;
    let len = read_varint(&mut cursor)? as usize;
    let header_len = buf.len() - cursor.len();
    if cursor.len() < len {
        return None;
    }
    let payload = cursor[..len].to_vec();
    buf.advance(header_len + len);
    Some(match frame_type {
        FRAME_HEADERS => Frame::Headers(payload),
        FRAME_DATA => Frame::Data(payload),
        _ => Frame::Other,
    })
}

/// Decode a HEADERS frame payload into header fields, in wire order.
///
/// Only blocks the stateless encoder produced can be decoded here: anything
/// referencing the dynamic table is rejected.
pub fn decode_headers(payload: &[u8]) -> Result<Vec<(String, String)>, qpack::DecoderError> {
    let decoded = qpack::decode_stateless(&mut &payload[..], u64::MAX)?;
    Ok(decoded
        .fields
        .into_iter()
        .map(|field| {
            let (name, value) = field.into_inner();
            (
                String::from_utf8_lossy(&name).into_owned(),
                String::from_utf8_lossy(&value).into_owned(),
            )
        })
        .collect())
}

fn write_settings(
    out: &mut BytesMut,
    settings: &[H3Setting],
    rng: &mut impl crate::quic::params::Rng,
) {
    let mut payload = BytesMut::new();
    for setting in settings {
        let (id, value) = match setting {
            H3Setting::Value(id, value) => (*id, *value),
            H3Setting::Grease => grease_setting(rng),
        };
        write_varint(&mut payload, id);
        write_varint(&mut payload, value);
    }
    write_varint(out, FRAME_SETTINGS);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(&payload);
}

/// A GREASE setting id is `0x1f * N + 0x21`, with `N` drawn from a `u32` so the
/// id stays in the range Chrome actually emits.
fn grease_setting(rng: &mut impl crate::quic::params::Rng) -> (u64, u64) {
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes);
    let n = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as u64;
    let value = u32::from_be_bytes(bytes[4..].try_into().unwrap()) as u64;
    (0x1f * n + 0x21, value)
}

fn frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::new();
    write_varint(&mut out, frame_type);
    write_varint(&mut out, payload.len() as u64);
    out.extend_from_slice(payload);
    out.to_vec()
}

fn varint(value: u64) -> Vec<u8> {
    let mut out = BytesMut::new();
    write_varint(&mut out, value);
    out.to_vec()
}

fn write_varint(out: &mut BytesMut, value: u64) {
    if value <= 0x3f {
        out.put_u8(value as u8);
    } else if value <= 0x3fff {
        out.put_u16(0x4000 | value as u16);
    } else if value <= 0x3fff_ffff {
        out.put_u32(0x8000_0000 | value as u32);
    } else {
        out.put_u64(0xc000_0000_0000_0000 | value);
    }
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut raw = [0u8; 8];
    raw[8 - len..].copy_from_slice(&buf[..len]);
    buf.advance(len);
    let value = u64::from_be_bytes(raw);
    let mask = !(0b11 << (len * 8 - 2));
    Some(value & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::params::ScriptedRng;

    #[test]
    fn settings_keep_preset_order_and_expand_grease() {
        let settings = [
            H3Setting::Value(1, 65536),
            H3Setting::Value(7, 100),
            H3Setting::Grease,
        ];
        // N = 0 -> id 0x21, value 0x01020304.
        let mut rng = ScriptedRng::new(&[0, 0, 0, 0, 1, 2, 3, 4]);
        let preface = control_preface(&settings, &mut rng);

        // Stream type 0, then a SETTINGS frame. 65536 needs a four-byte varint.
        assert_eq!(preface[0], 0x00);
        assert_eq!(preface[1], FRAME_SETTINGS as u8);
        let mut payload = &preface[3..];
        assert_eq!(read_varint(&mut payload), Some(1));
        assert_eq!(read_varint(&mut payload), Some(65536));
        assert_eq!(read_varint(&mut payload), Some(7));
        assert_eq!(read_varint(&mut payload), Some(100));
        assert_eq!(read_varint(&mut payload), Some(0x21));
        assert_eq!(read_varint(&mut payload), Some(0x01020304));
        assert!(payload.is_empty());
    }

    #[test]
    fn headers_round_trip_in_order() {
        let headers = [
            (":method", "GET"),
            (":authority", "example.com"),
            (":scheme", "https"),
            (":path", "/"),
            ("user-agent", "test"),
        ];
        let frame = headers_frame(&headers);
        let mut buf = BytesMut::from(&frame[..]);
        let Frame::Headers(payload) = decode_frame(&mut buf).unwrap() else {
            panic!("expected headers");
        };
        assert_eq!(
            decode_headers(&payload).unwrap(),
            headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn decode_waits_for_a_complete_frame() {
        let frame = data_frame(b"hello");
        let mut buf = BytesMut::from(&frame[..frame.len() - 1]);
        assert!(decode_frame(&mut buf).is_none());
        buf.extend_from_slice(&frame[frame.len() - 1..]);
        assert_eq!(decode_frame(&mut buf), Some(Frame::Data(b"hello".to_vec())));
    }
}
