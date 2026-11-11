//! WebSocket upgrade headers and permessage-deflate framing.
//!
//! The handshake offers `permessage-deflate; client_max_window_bits`. Once the
//! peer accepts, text and binary payloads are raw-deflated and the `00 00 ff ff`
//! sync trailer is removed. Control frames stay uncompressed. Deflate combined
//! with raw mode is an argument error. Asking for the extension when zlib is
//! not linked is a not-built error and does not offer the extension.

use std::fmt;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use wreq::header::{HeaderMap, HeaderName, HeaderValue};

use crate::prepare::WEBSOCKET_EXTENSION;

/// Headers added to a WebSocket handshake that offers permessage-deflate.
pub fn deflate_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("sec-websocket-extensions"),
        HeaderValue::from_static(WEBSOCKET_EXTENSION),
    );
    headers
}

/// zlib is linked into this crate through `flate2`.
pub fn zlib_is_linked() -> bool {
    true
}

/// Why a WebSocket deflate operation was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    /// Deflate was combined with raw mode, or the frame is not a data frame.
    Argument(&'static str),
    /// The extension was requested where zlib is not available.
    NotBuilt(&'static str),
}

impl WsError {
    pub fn is_argument(&self) -> bool {
        matches!(self, WsError::Argument(_))
    }

    pub fn is_not_built(&self) -> bool {
        matches!(self, WsError::NotBuilt(_))
    }
}

impl fmt::Display for WsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WsError::Argument(message) | WsError::NotBuilt(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for WsError {}

/// One WebSocket frame after the handshake, before masking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub opcode: u8,
    pub rsv1: bool,
    pub payload: Vec<u8>,
}

/// Compressor used after the peer accepts `permessage-deflate`.
///
/// Context takeover stays on: the offer does not send
/// `client_no_context_takeover`, so one compressor serves the connection.
pub struct MessageCodec {
    compress: Compress,
    decompress: Decompress,
}

impl MessageCodec {
    pub fn new() -> Self {
        Self {
            compress: Compress::new(Compression::default(), false),
            decompress: Decompress::new(false),
        }
    }

    /// Encode one frame.
    ///
    /// `raw` together with this codec is an argument error. Control opcodes
    /// `0x8`, `0x9` and `0xA` are copied through with `rsv1` clear.
    pub fn encode(&mut self, opcode: u8, payload: &[u8], raw: bool) -> Result<WsFrame, WsError> {
        if raw {
            return Err(WsError::Argument(
                "permessage-deflate cannot be combined with raw mode",
            ));
        }
        if is_control(opcode) {
            return Ok(WsFrame {
                opcode,
                rsv1: false,
                payload: payload.to_vec(),
            });
        }
        if !matches!(opcode, 0x1 | 0x2) {
            return Err(WsError::Argument("opcode is not text, binary, or control"));
        }
        let compressed = deflate_message(&mut self.compress, payload)?;
        Ok(WsFrame {
            opcode,
            rsv1: true,
            payload: compressed,
        })
    }

    /// Reverse [`Self::encode`]. Uncompressed frames, including control frames,
    /// are returned as they are.
    pub fn decode(&mut self, frame: &WsFrame) -> Result<Vec<u8>, WsError> {
        if !frame.rsv1 {
            return Ok(frame.payload.clone());
        }
        let mut input = frame.payload.clone();
        input.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        inflate_message(&mut self.decompress, &input)
    }
}

/// `compress_vec` writes only into spare capacity, so grow until the sync
/// flush finishes. One compressor stays live for the connection.
fn deflate_message(compress: &mut Compress, payload: &[u8]) -> Result<Vec<u8>, WsError> {
    let mut output = Vec::new();
    let mut rest = payload;
    for _ in 0..64 {
        output.reserve(rest.len().saturating_add(64).max(64));
        let in_before = compress.total_in();
        let out_before = compress.total_out();
        let status = compress
            .compress_vec(rest, &mut output, FlushCompress::Sync)
            .map_err(|_| WsError::Argument("deflate failed"))?;
        let consumed = usize::try_from(compress.total_in() - in_before)
            .map_err(|_| WsError::Argument("deflate consumed past the payload"))?;
        let produced = compress.total_out() - out_before;
        if consumed > rest.len() {
            return Err(WsError::Argument("deflate consumed past the payload"));
        }
        rest = &rest[consumed..];
        match status {
            Status::Ok | Status::StreamEnd if rest.is_empty() => {
                if output.ends_with(&[0x00, 0x00, 0xff, 0xff]) {
                    output.truncate(output.len() - 4);
                }
                return Ok(output);
            }
            Status::Ok | Status::StreamEnd | Status::BufError => {
                if consumed == 0 && produced == 0 {
                    output.reserve(output.capacity().saturating_mul(2).max(128));
                }
            }
        }
    }
    Err(WsError::Argument("deflate did not finish"))
}

fn inflate_message(decompress: &mut Decompress, input: &[u8]) -> Result<Vec<u8>, WsError> {
    let mut plain = Vec::new();
    let mut rest = input;
    for _ in 0..64 {
        plain.reserve(rest.len().saturating_add(64).max(64));
        let in_before = decompress.total_in();
        let out_before = decompress.total_out();
        let status = decompress
            .decompress_vec(rest, &mut plain, FlushDecompress::Sync)
            .map_err(|_| WsError::Argument("inflate failed"))?;
        let consumed = usize::try_from(decompress.total_in() - in_before)
            .map_err(|_| WsError::Argument("inflate consumed past the frame"))?;
        let produced = decompress.total_out() - out_before;
        if consumed > rest.len() {
            return Err(WsError::Argument("inflate consumed past the frame"));
        }
        rest = &rest[consumed..];
        match status {
            Status::Ok | Status::StreamEnd if rest.is_empty() => return Ok(plain),
            Status::Ok | Status::StreamEnd | Status::BufError => {
                if consumed == 0 && produced == 0 {
                    plain.reserve(plain.capacity().saturating_mul(2).max(128));
                }
            }
        }
    }
    Err(WsError::Argument("inflate did not finish"))
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

fn is_control(opcode: u8) -> bool {
    matches!(opcode, 0x8 | 0x9 | 0xA)
}

/// A WebSocket upgrade that offers `permessage-deflate`.
///
/// The extension header is the map passed to the underlying builder. wreq
/// attaches `Upgrade` and `Sec-WebSocket-Key` only inside `send`, so
/// [`Self::extensions`] is how a caller reads the offer before the handshake.
pub struct WebSocketUpgrade {
    pub(crate) inner: wreq::ws::WebSocketRequestBuilder,
    pub(crate) extensions: HeaderMap,
    pub(crate) headers: Vec<(String, String)>,
}

impl WebSocketUpgrade {
    /// The `Sec-WebSocket-Extensions` value this upgrade will send.
    pub fn extensions(&self) -> &str {
        self.extensions
            .get(wreq::header::SEC_WEBSOCKET_EXTENSIONS)
            .and_then(|value| value.to_str().ok())
            .expect("permessage-deflate offer")
    }

    /// Header list installed on this upgrade, after a WebSocket header override.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Codec used once the peer accepts the extension this upgrade offered.
    pub fn accepted_codec(&self) -> MessageCodec {
        MessageCodec::new()
    }

    /// Finish the handshake.
    pub async fn send(self) -> crate::Result<wreq::ws::WebSocketResponse> {
        self.inner.send().await
    }
}
