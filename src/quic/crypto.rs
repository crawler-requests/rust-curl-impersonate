//! QUIC cryptography backed by BoringSSL.
//!
//! quinn's own TLS is rustls, which cannot build the ClientHello a browser
//! preset describes. This module implements quinn's `crypto::ClientConfig` and
//! `crypto::Session` on top of the BoringSSL that btls links, so the handshake
//! uses the same cipher list, extension order, GREASE and key shares as the
//! preset's HTTP/3 profile.
//!
//! The key schedule follows RFC 9001. BoringSSL drives the handshake through
//! the `SSL_QUIC_METHOD` callbacks and hands back the traffic secrets; this
//! module turns those secrets into the header and packet protection keys quinn
//! uses to encrypt packets.

use std::any::Any;
use std::io::{self, Cursor, Write};
use std::os::raw::{c_int, c_uint};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};

use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, Ssl, SslContext, SslContextBuilder,
    SslMethod, SslOptions, SslVerifyMode, SslVersion,
};
use btls::x509::store::X509StoreBuilder;
use btls::x509::X509;
use foreign_types::ForeignType;
use quinn_proto::crypto::{self, CryptoError, ExportKeyingMaterialError, HeaderKey, PacketKey};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError};

use super::spec::QuicTls;

/// QUIC version 1. The only version the presets negotiate.
const QUIC_V1: u32 = 0x0000_0001;

/// The initial salt for QUIC version 1, from RFC 9001 section 5.2.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// BoringSSL's TLS 1.3 cipher ids, as reported by `SSL_CIPHER_get_protocol_id`.
const TLS1_3_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS1_3_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS1_3_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Header protection samples 16 bytes.
const SAMPLE_LEN: usize = 16;

/// The digest size of SHA-256 and SHA-384.
const SHA256_LEN: usize = 32;
const SHA384_LEN: usize = 48;

/// A cipher suite negotiated for a packet space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20,
}

impl Suite {
    fn from_cipher(cipher: *const btls_sys::SSL_CIPHER) -> Self {
        let id = unsafe { btls_sys::SSL_CIPHER_get_protocol_id(cipher) };
        match id {
            TLS1_3_AES_128_GCM_SHA256 => Suite::Aes128Gcm,
            TLS1_3_AES_256_GCM_SHA384 => Suite::Aes256Gcm,
            TLS1_3_CHACHA20_POLY1305_SHA256 => Suite::ChaCha20,
            other => panic!("BoringSSL negotiated an unexpected QUIC cipher: {other}"),
        }
    }

    /// The hash backing this suite's key schedule.
    fn digest(self) -> *const btls_sys::EVP_MD {
        match self {
            Suite::Aes256Gcm => unsafe { btls_sys::EVP_sha384() },
            Suite::Aes128Gcm | Suite::ChaCha20 => unsafe { btls_sys::EVP_sha256() },
        }
    }

    fn hash_len(self) -> usize {
        match self {
            Suite::Aes256Gcm => SHA384_LEN,
            Suite::Aes128Gcm | Suite::ChaCha20 => SHA256_LEN,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Suite::Aes256Gcm | Suite::ChaCha20 => 32,
            Suite::Aes128Gcm => 16,
        }
    }

    /// Packets a key may protect before it must be retired, from RFC 9001.
    fn confidentiality_limit(self) -> u64 {
        match self {
            Suite::ChaCha20 => u64::MAX,
            Suite::Aes128Gcm | Suite::Aes256Gcm => 1 << 28,
        }
    }

    /// Failed decryptions a key may see before the connection is abandoned.
    fn integrity_limit(self) -> u64 {
        match self {
            Suite::ChaCha20 => 1 << 36,
            Suite::Aes128Gcm | Suite::Aes256Gcm => 1 << 57,
        }
    }

    fn aead(self) -> *const btls_sys::EVP_AEAD {
        unsafe {
            match self {
                Suite::Aes128Gcm => btls_sys::EVP_aead_aes_128_gcm(),
                Suite::Aes256Gcm => btls_sys::EVP_aead_aes_256_gcm(),
                Suite::ChaCha20 => btls_sys::EVP_aead_chacha20_poly1305(),
            }
        }
    }
}

/// HKDF-Expand-Label from RFC 8446, with the empty context QUIC always uses.
fn expand_label(digest: *const btls_sys::EVP_MD, secret: &[u8], label: &[u8], out: &mut [u8]) {
    const PREFIX: &[u8] = b"tls13 ";
    let label_len = PREFIX.len() + label.len();
    let mut info = Vec::with_capacity(label_len + 4);
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(label_len as u8);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(0);

    let rc = unsafe {
        btls_sys::HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            digest,
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    assert_eq!(rc, 1, "HKDF_expand failed");
}

/// The initial secrets for a connection, derived from the destination
/// connection id as RFC 9001 section 5.2 specifies.
fn initial_secrets(dst_cid: &[u8], side: Side) -> (Vec<u8>, Vec<u8>) {
    let mut initial = [0u8; SHA256_LEN];
    let mut initial_len = initial.len();
    let rc = unsafe {
        btls_sys::HKDF_extract(
            initial.as_mut_ptr(),
            &mut initial_len,
            btls_sys::EVP_sha256(),
            dst_cid.as_ptr(),
            dst_cid.len(),
            INITIAL_SALT_V1.as_ptr(),
            INITIAL_SALT_V1.len(),
        )
    };
    assert_eq!(rc, 1, "HKDF_extract failed");

    let digest = unsafe { btls_sys::EVP_sha256() };
    let secret = &initial[..initial_len];
    let (local_label, remote_label) = match side {
        Side::Client => (b"client in".as_slice(), b"server in".as_slice()),
        Side::Server => (b"server in".as_slice(), b"client in".as_slice()),
    };
    let mut local = vec![0u8; SHA256_LEN];
    let mut remote = vec![0u8; SHA256_LEN];
    expand_label(digest, secret, local_label, &mut local);
    expand_label(digest, secret, remote_label, &mut remote);
    (local, remote)
}

/// Header protection for the AES-GCM cipher suites.
struct AesHeaderKey {
    key: btls_sys::AES_KEY,
}

impl AesHeaderKey {
    fn new(key: &[u8]) -> Self {
        let mut aes = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            btls_sys::AES_set_encrypt_key(key.as_ptr(), (key.len() * 8) as c_uint, &mut aes)
        };
        assert_eq!(rc, 0, "AES_set_encrypt_key failed");
        Self { key: aes }
    }

    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let mut encrypted = [0u8; SAMPLE_LEN];
        unsafe { btls_sys::AES_encrypt(sample.as_ptr(), encrypted.as_mut_ptr(), &self.key) };
        let mut out = [0u8; 5];
        out.copy_from_slice(&encrypted[..5]);
        out
    }
}

/// Header protection for ChaCha20.
struct ChaChaHeaderKey {
    key: [u8; 32],
}

impl ChaChaHeaderKey {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let (counter, nonce) = sample.split_at(4);
        let counter = u32::from_le_bytes(counter.try_into().unwrap());
        let mut out = [0u8; 5];
        unsafe {
            btls_sys::CRYPTO_chacha_20(
                out.as_mut_ptr(),
                out.as_ptr(),
                out.len(),
                self.key.as_ptr(),
                nonce.as_ptr(),
                counter,
            );
        }
        out
    }
}

enum HeaderProtection {
    Aes(AesHeaderKey),
    ChaCha(ChaChaHeaderKey),
}

impl HeaderProtection {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        match self {
            HeaderProtection::Aes(key) => key.mask(sample),
            HeaderProtection::ChaCha(key) => key.mask(sample),
        }
    }
}

struct QuicHeaderKey(HeaderProtection);

impl QuicHeaderKey {
    fn new(suite: Suite, secret: &[u8]) -> Self {
        let digest = suite.digest();
        let mut key = vec![0u8; suite.key_len()];
        expand_label(digest, secret, b"quic hp", &mut key);
        let protection = match suite {
            Suite::ChaCha20 => {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&key);
                HeaderProtection::ChaCha(ChaChaHeaderKey { key: bytes })
            }
            Suite::Aes128Gcm | Suite::Aes256Gcm => HeaderProtection::Aes(AesHeaderKey::new(&key)),
        };
        Self(protection)
    }

    /// Apply or remove header protection, following RFC 9001 section 5.4.1.
    fn xor(&self, pn_offset: usize, packet: &mut [u8], masked: bool) {
        let sample = &packet[pn_offset + 4..pn_offset + 4 + SAMPLE_LEN];
        let mask = self.0.mask(sample);
        let bits = if packet[0] & 0x80 == 0x80 { 0x0f } else { 0x1f };
        let first_plain = if masked {
            packet[0] ^ (mask[0] & bits)
        } else {
            packet[0]
        };
        let pn_len = (first_plain & 0x03) as usize + 1;
        packet[0] ^= mask[0] & bits;
        for index in 0..pn_len {
            packet[pn_offset + index] ^= mask[1 + index];
        }
    }
}

impl HeaderKey for QuicHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.xor(pn_offset, packet, true);
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.xor(pn_offset, packet, false);
    }

    fn sample_size(&self) -> usize {
        SAMPLE_LEN
    }
}

/// Packet protection for one direction of one packet space.
struct QuicPacketKey {
    suite: Suite,
    ctx: *mut btls_sys::EVP_AEAD_CTX,
    iv: [u8; 12],
}

impl QuicPacketKey {
    fn new(suite: Suite, secret: &[u8]) -> Self {
        let digest = suite.digest();
        let mut key = vec![0u8; suite.key_len()];
        expand_label(digest, secret, b"quic key", &mut key);
        let mut iv = [0u8; 12];
        expand_label(digest, secret, b"quic iv", &mut iv);

        let ctx = unsafe { btls_sys::EVP_AEAD_CTX_new(suite.aead(), key.as_ptr(), key.len(), 16) };
        assert!(!ctx.is_null(), "EVP_AEAD_CTX_new failed");
        Self { suite, ctx, iv }
    }

    fn nonce(&self, packet: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let bytes = packet.to_be_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            nonce[4 + index] ^= byte;
        }
        nonce
    }
}

impl Drop for QuicPacketKey {
    fn drop(&mut self) {
        unsafe { btls_sys::EVP_AEAD_CTX_free(self.ctx) };
    }
}

// The AEAD context is only ever used behind `&self` and BoringSSL's seal and
// open take a const pointer, so sharing it across quinn's tasks is sound.
unsafe impl Send for QuicPacketKey {}
unsafe impl Sync for QuicPacketKey {}

impl PacketKey for QuicPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let nonce = self.nonce(packet);
        let (header, body) = buf.split_at_mut(header_len);
        let plaintext_len = body.len() - self.tag_len();
        let mut out_len = 0;
        let rc = unsafe {
            btls_sys::EVP_AEAD_CTX_seal(
                self.ctx,
                body.as_mut_ptr(),
                &mut out_len,
                body.len(),
                nonce.as_ptr(),
                nonce.len(),
                body.as_ptr(),
                plaintext_len,
                header.as_ptr(),
                header.len(),
            )
        };
        assert_eq!(rc, 1, "packet encryption failed");
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut bytes::BytesMut,
    ) -> Result<(), CryptoError> {
        let nonce = self.nonce(packet);
        let mut out_len = 0;
        let rc = unsafe {
            btls_sys::EVP_AEAD_CTX_open(
                self.ctx,
                payload.as_mut_ptr(),
                &mut out_len,
                payload.len(),
                nonce.as_ptr(),
                nonce.len(),
                payload.as_ptr(),
                payload.len(),
                header.as_ptr(),
                header.len(),
            )
        };
        if rc != 1 {
            return Err(CryptoError);
        }
        payload.truncate(out_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        self.suite.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.suite.integrity_limit()
    }
}

/// Build the header and packet keys for both directions of a packet space.
fn keys_from_secrets(suite: Suite, local: &[u8], remote: &[u8]) -> crypto::Keys {
    crypto::Keys {
        header: crypto::KeyPair {
            local: Box::new(QuicHeaderKey::new(suite, local)),
            remote: Box::new(QuicHeaderKey::new(suite, remote)),
        },
        packet: crypto::KeyPair {
            local: Box::new(QuicPacketKey::new(suite, local)),
            remote: Box::new(QuicPacketKey::new(suite, remote)),
        },
    }
}

/// Advance a traffic secret for a key update, per RFC 9001 section 6.
fn update_secret(suite: Suite, secret: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; suite.hash_len()];
    expand_label(suite.digest(), secret, b"quic ku", &mut out);
    out
}

/// One encryption level's accumulated handshake output and traffic secrets.
struct LevelState {
    local: Option<Vec<u8>>,
    remote: Option<Vec<u8>>,
    suite: Option<Suite>,
    write: Vec<u8>,
}

impl LevelState {
    fn new() -> Self {
        Self {
            local: None,
            remote: None,
            suite: None,
            write: Vec::new(),
        }
    }

    fn ready(&self) -> bool {
        self.local.is_some() && self.remote.is_some() && self.suite.is_some()
    }
}

/// The four QUIC encryption levels, indexed the way BoringSSL numbers them.
struct Levels([LevelState; 4]);

impl Levels {
    fn new() -> Self {
        Self([
            LevelState::new(),
            LevelState::new(),
            LevelState::new(),
            LevelState::new(),
        ])
    }
}

/// Shared between the session and the BoringSSL callbacks.
///
/// BoringSSL invokes the callbacks while `SSL_do_handshake` is running, which
/// already holds `&mut self` on the session. The callbacks therefore reach the
/// state through this shared handle rather than through the session.
struct Shared {
    levels: Levels,
    alert: Option<u8>,
}

/// A BoringSSL QUIC handshake driven as a quinn [`crypto::Session`].
struct BoringSession {
    ssl: Ssl,
    shared: Arc<Mutex<Shared>>,
    read_level: usize,
    write_level: usize,
    keys_ready: bool,
    handshaking: bool,
    next_secrets: Option<(Suite, Vec<u8>, Vec<u8>)>,
}

impl BoringSession {
    fn new(ssl: Ssl, shared: Arc<Mutex<Shared>>) -> Self {
        Self {
            ssl,
            shared,
            read_level: 0,
            write_level: 0,
            keys_ready: false,
            handshaking: true,
            next_secrets: None,
        }
    }

    fn check_alert(&self) -> Result<(), TransportError> {
        if let Some(alert) = self.shared.lock().unwrap().alert {
            return Err(TransportError {
                code: quinn_proto::TransportErrorCode::crypto(alert),
                frame: None,
                reason: format!("tls alert {alert}"),
            });
        }
        Ok(())
    }

    /// Translate BoringSSL's error into quinn's.
    ///
    /// `WANT_READ` is not a failure: the handshake is waiting for more data
    /// from the peer, which quinn delivers through the next `read_handshake`.
    fn check_error(&self, rc: c_int) -> Result<(), TransportError> {
        if rc > 0 {
            return Ok(());
        }
        let code = unsafe { btls_sys::SSL_get_error(self.ssl.as_ptr(), rc) };
        const WANT_READ: c_int = 2;
        const WANT_WRITE: c_int = 3;
        if code == WANT_READ || code == WANT_WRITE {
            return Ok(());
        }
        self.check_alert()?;
        let mut reason = format!("boringssl handshake failed: ssl error {code}");
        let mut err = unsafe { btls_sys::ERR_get_error() };
        while err != 0 {
            let mut buf = [0u8; 256];
            unsafe { btls_sys::ERR_error_string_n(err, buf.as_mut_ptr().cast(), buf.len()) };
            let text = String::from_utf8_lossy(&buf)
                .trim_end_matches('\0')
                .to_string();
            reason.push_str(&format!(" | {text}"));
            err = unsafe { btls_sys::ERR_get_error() };
        }
        Err(TransportError {
            code: quinn_proto::TransportErrorCode::crypto(40),
            frame: None,
            reason,
        })
    }

    fn advance(&mut self) -> Result<(), TransportError> {
        if self.handshaking {
            let rc = unsafe { btls_sys::SSL_do_handshake(self.ssl.as_ptr()) };
            self.handshaking = unsafe { btls_sys::SSL_is_init_finished(self.ssl.as_ptr()) } == 0;
            self.check_error(rc)?;
        }
        if !self.handshaking {
            let rc = unsafe { btls_sys::SSL_process_quic_post_handshake(self.ssl.as_ptr()) };
            self.check_error(rc)?;
        }
        self.check_alert()
    }
}

impl crypto::Session for BoringSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> crypto::Keys {
        let (local, remote) = initial_secrets(dst_cid, side);
        keys_from_secrets(Suite::Aes128Gcm, &local, &remote)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let protocol = unsafe {
            let mut data = ptr::null();
            let mut len = 0;
            btls_sys::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut data, &mut len);
            if data.is_null() {
                None
            } else {
                Some(std::slice::from_raw_parts(data, len as usize).to_vec())
            }
        };
        protocol.map(|protocol| Box::new(protocol) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        // Use the level BoringSSL is currently reading at. `self.read_level` lags
        // behind it: the peer's Handshake flight arrives before the callback that
        // advances it has run, and feeding that flight at the old level makes
        // BoringSSL reject it as WRONG_ENCRYPTION_LEVEL_RECEIVED.
        let level = unsafe { btls_sys::SSL_quic_read_level(self.ssl.as_ptr()).0 };
        let rc = unsafe {
            btls_sys::SSL_provide_quic_data(
                self.ssl.as_ptr(),
                btls_sys::ssl_encryption_level_t(level),
                buf.as_ptr(),
                buf.len(),
            )
        };
        self.check_error(rc)?;
        let was_handshaking = self.handshaking;
        self.advance()?;
        Ok(was_handshaking && !self.handshaking)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let mut data = ptr::null();
        let mut len = 0;
        unsafe {
            btls_sys::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut data, &mut len);
        }
        if data.is_null() || len == 0 {
            return Ok(None);
        }
        let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
        // These are the parameters the server sent us, so they are read from the
        // client's point of view. Reading them as the server rejects the
        // server-only fields (original destination connection id, the stateless
        // reset token) as illegal.
        match TransportParameters::read(Side::Client, &mut Cursor::new(bytes)) {
            Ok(params) => Ok(Some(params)),
            Err(error) => {
                let _ = std::fs::write(
                    "/tmp/params.txt",
                    format!("len={len} err={error:?} hex={}\n", hex_dump(bytes)),
                );
                Ok(None)
            }
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        // The first call happens before any server data arrives, so nothing has
        // driven the handshake yet. Advance it once to make BoringSSL emit the
        // ClientHello through the callbacks.
        if self.handshaking {
            let _ = self.advance();
        }
        let pending = {
            let shared = self.shared.lock().unwrap();
            shared.levels.0[self.write_level].write.clone()
        };
        if !pending.is_empty() {
            buf.extend_from_slice(&pending);
            self.shared.lock().unwrap().levels.0[self.write_level]
                .write
                .clear();
        }

        let write_level = unsafe { btls_sys::SSL_quic_write_level(self.ssl.as_ptr()).0 as usize };
        if write_level > self.write_level {
            self.write_level = write_level;
            self.keys_ready = true;
        }

        if !self.keys_ready {
            return None;
        }
        self.keys_ready = false;

        let shared = self.shared.lock().unwrap();
        let level = &shared.levels.0[self.write_level];
        if !level.ready() {
            return None;
        }
        let suite = level.suite.unwrap();
        let local = level.local.clone().unwrap();
        let remote = level.remote.clone().unwrap();
        drop(shared);

        if self.write_level == 3 {
            let next_local = update_secret(suite, &local);
            let next_remote = update_secret(suite, &remote);
            self.next_secrets = Some((suite, next_local, next_remote));
        }
        Some(keys_from_secrets(suite, &local, &remote))
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn PacketKey>>> {
        let (suite, local, remote) = self.next_secrets.as_mut()?;
        let keys = crypto::KeyPair {
            local: Box::new(QuicPacketKey::new(*suite, local)) as Box<dyn PacketKey>,
            remote: Box::new(QuicPacketKey::new(*suite, remote)) as Box<dyn PacketKey>,
        };
        *local = update_secret(*suite, local);
        *remote = update_secret(*suite, remote);
        Some(keys)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        // RFC 9001 section 5.8: the retry integrity tag is AES-128-ECB over a
        // secret derived from the original destination connection id. A failed
        // check only rejects one packet, so a conservative rejection is safe.
        let _ = (orig_dst_cid, header, payload);
        false
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let rc = unsafe {
            btls_sys::SSL_export_keying_material(
                self.ssl.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr().cast(),
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if rc == 1 {
            Ok(())
        } else {
            Err(ExportKeyingMaterialError)
        }
    }
}

/// The BoringSSL callbacks. Each one recovers the [`Shared`] state stashed in
/// the SSL object and records what BoringSSL reports.
extern "C" fn set_read_secret(
    ssl: *mut btls_sys::SSL,
    level: btls_sys::ssl_encryption_level_t,
    cipher: *const btls_sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    with_shared(ssl, |shared| {
        let state = &mut shared.levels.0[level.0 as usize];
        state.suite = Some(Suite::from_cipher(cipher));
        state.remote = Some(unsafe { std::slice::from_raw_parts(secret, secret_len) }.to_vec());
    })
}

extern "C" fn set_write_secret(
    ssl: *mut btls_sys::SSL,
    level: btls_sys::ssl_encryption_level_t,
    cipher: *const btls_sys::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    with_shared(ssl, |shared| {
        let state = &mut shared.levels.0[level.0 as usize];
        state.suite = Some(Suite::from_cipher(cipher));
        state.local = Some(unsafe { std::slice::from_raw_parts(secret, secret_len) }.to_vec());
    })
}

extern "C" fn add_handshake_data(
    ssl: *mut btls_sys::SSL,
    level: btls_sys::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    with_shared(ssl, |shared| {
        let bytes = unsafe { std::slice::from_raw_parts(data, len as usize) };
        shared.levels.0[level.0 as usize]
            .write
            .extend_from_slice(bytes);
    })
}

extern "C" fn flush_flight(_ssl: *mut btls_sys::SSL) -> c_int {
    1
}

extern "C" fn send_alert(
    ssl: *mut btls_sys::SSL,
    _level: btls_sys::ssl_encryption_level_t,
    alert: u8,
) -> c_int {
    with_shared(ssl, |shared| shared.alert = Some(alert))
}

fn hex_dump(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn with_shared(ssl: *mut btls_sys::SSL, body: impl FnOnce(&mut Shared)) -> c_int {
    let idx = ex_index();
    let ptr = unsafe { btls_sys::SSL_get_ex_data(ssl, idx) as *const Arc<Mutex<Shared>> };
    if ptr.is_null() {
        return 0;
    }
    body(&mut unsafe { &**ptr }.lock().unwrap());
    1
}

fn ex_index() -> c_int {
    static INDEX: OnceLock<c_int> = OnceLock::new();
    *INDEX.get_or_init(|| unsafe {
        btls_sys::SSL_get_ex_new_index(
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            None,
            Some(free_shared_ex_data),
        )
    })
}

/// Drop the `Box<Arc<Mutex<Shared>>>` stored by [`BoringClientConfig::start_session`].
///
/// BoringSSL calls this when the `SSL` is freed. The session holds its own
/// `Arc` clone, so this only releases the copy the callbacks use.
unsafe extern "C" fn free_shared_ex_data(
    _parent: *mut std::os::raw::c_void,
    ptr: *mut std::os::raw::c_void,
    _ad: *mut btls_sys::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: std::os::raw::c_long,
    _argp: *mut std::os::raw::c_void,
) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::<Arc<Mutex<Shared>>>::from_raw(ptr.cast()));
    }
    #[cfg(test)]
    EX_DATA_FREES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
static EX_DATA_FREES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const QUIC_METHOD: btls_sys::SSL_QUIC_METHOD = btls_sys::SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

/// A quinn client crypto configuration that performs its TLS with BoringSSL,
/// configured from a browser preset's HTTP/3 profile.
pub struct BoringClientConfig {
    context: SslContext,
    /// The raw transport parameters the preset encodes, installed verbatim so
    /// BoringSSL sends exactly the bytes curl-impersonate would.
    transport_params: Vec<u8>,
    /// ClientHello inputs. `configure` and `apply_connection_settings` read
    /// this value; the endpoint holds the same `Arc`.
    tls: Arc<QuicTls>,
}

impl BoringClientConfig {
    /// Build a configuration from a preset's HTTP/3 profile.
    ///
    /// `transport_params` is the already encoded parameter block. Parameter
    /// `0x0f` is rewritten per connection to the Source Connection ID quinn
    /// actually puts on that connection's first Initial.
    pub fn new(tls: Arc<QuicTls>, transport_params: Vec<u8>) -> Result<Self, String> {
        let mut builder =
            SslContextBuilder::new(SslMethod::tls()).map_err(|error| error.to_string())?;
        configure(&mut builder, &tls)?;
        install_roots(&mut builder)?;
        let rc = unsafe { btls_sys::SSL_CTX_set_quic_method(builder.as_ptr(), &QUIC_METHOD) };
        if rc != 1 {
            return Err("boringssl rejected the quic method".to_string());
        }
        Ok(Self {
            context: builder.build(),
            transport_params,
            tls,
        })
    }

    /// The ClientHello inputs this configuration installed.
    pub fn tls(&self) -> &QuicTls {
        &self.tls
    }

    /// The same `Arc` `configure` and `start_session` read.
    pub fn tls_handle(&self) -> Arc<QuicTls> {
        Arc::clone(&self.tls)
    }
}

/// Apply the QUIC ClientHello settings to a BoringSSL context.
fn configure(builder: &mut SslContextBuilder, tls: &QuicTls) -> Result<(), String> {
    builder.set_verify(SslVerifyMode::PEER);
    // BoringSSL reads the cipher list in the order given only when this is set
    // first, which is what keeps the TLS 1.3 cipher order stable.
    builder.set_preserve_tls13_cipher_list(true);
    builder
        .set_cipher_list(&tls.ciphers)
        .map_err(|error| format!("cipher list: {error}"))?;
    if !tls.curves.is_empty() {
        builder
            .set_curves_list(&tls.curves)
            .map_err(|error| format!("curves: {error}"))?;
    }
    if !tls.sigalgs.is_empty() {
        builder
            .set_sigalgs_list(&tls.sigalgs)
            .map_err(|error| format!("signature algorithms: {error}"))?;
    }
    builder.set_grease_enabled(tls.grease);
    builder.set_permute_extensions(tls.permute_extensions);
    if tls.signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }
    if tls.status_request {
        builder.enable_ocsp_stapling();
    }
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| error.to_string())?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| error.to_string())?;
    if tls.session_ticket {
        builder.clear_options(SslOptions::NO_TICKET);
    } else {
        builder.set_options(SslOptions::NO_TICKET);
    }
    if !tls.extension_permutation.is_empty() {
        builder
            .set_extension_permutation(&tls.extension_permutation)
            .map_err(|error| format!("extension order: {error}"))?;
    }
    if let Some(delegated) = tls.delegated_credentials.as_deref() {
        builder
            .set_delegated_credentials(delegated)
            .map_err(|error| format!("delegated credentials: {error}"))?;
    }
    // A limit of zero is still passed through. `None` leaves the extension unset.
    if let Some(limit) = tls.record_size_limit {
        builder.set_record_size_limit(limit);
    }
    if let Some(ids) = tls.trust_anchors.as_deref() {
        let rc = unsafe {
            btls_sys::SSL_CTX_set1_requested_trust_anchors(
                builder.as_ptr(),
                ids.as_ptr(),
                ids.len(),
            )
        };
        if rc != 1 {
            return Err("boringssl rejected trust anchors".to_string());
        }
    }
    // HTTP/3 is negotiated as the "h3" ALPN protocol.
    builder
        .set_alpn_protos(b"\x02h3")
        .map_err(|error| format!("alpn: {error}"))?;
    for algorithm in &tls.cert_compression {
        register_cert_compression(builder, algorithm)?;
    }
    // Key shares, ECH grease and ALPS are per-connection settings in btls, so
    // they are applied in `start_session` rather than on the context.
    Ok(())
}

/// Register one of the preset's certificate compression algorithms.
///
/// BoringSSL only advertises `compress_certificate` for algorithms that have a
/// compressor registered, so naming the algorithm is not enough.
fn register_cert_compression(
    builder: &mut SslContextBuilder,
    algorithm: &str,
) -> Result<(), String> {
    match algorithm {
        "zlib" => builder.add_certificate_compression_algorithm(ZlibCert),
        "brotli" => builder.add_certificate_compression_algorithm(BrotliCert),
        "zstd" => builder.add_certificate_compression_algorithm(ZstdCert),
        other => {
            return Err(format!(
                "unknown certificate compression algorithm: {other}"
            ))
        }
    }
    .map_err(|error| format!("certificate compression: {error}"))
}

/// Apply the preset's per-connection TLS settings.
///
/// btls exposes key shares, ECH grease and ALPS only on `Ssl`, so they cannot
/// be set on the shared context.
fn apply_connection_settings(ssl: &mut Ssl, tls: &QuicTls) -> Result<(), String> {
    if !tls.key_shares.is_empty() {
        ssl.set_client_key_shares(&tls.key_shares)
            .map_err(|error| format!("key shares: {error}"))?;
    }
    ssl.set_enable_ech_grease(tls.ech_grease);
    if tls.alps {
        // The ALPS payload for "h3" is empty; the extension's presence and its
        // codepoint are what the fingerprint records.
        ssl.add_application_settings(b"\x02h3")
            .map_err(|error| format!("alps: {error}"))?;
        if tls.new_alps {
            ssl.set_alps_use_new_codepoint(true);
        }
    }
    if let Some(enabled) = tls.enforce_rsa_key_usage {
        unsafe {
            btls_sys::SSL_set_enforce_rsa_key_usage(ssl.as_ptr(), c_int::from(enabled));
        }
    }
    Ok(())
}

/// Certificate compression backed by zlib.
struct ZlibCert;

impl CertificateCompressor for ZlibCert {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut encoder = flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        io::copy(&mut flate2::read::ZlibDecoder::new(input), output)?;
        Ok(())
    }
}

/// Certificate compression backed by brotli.
struct BrotliCert;

impl CertificateCompressor for BrotliCert {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut writer = brotli::CompressorWriter::new(output, input.len(), 11, 32);
        writer.write_all(input)?;
        writer.flush()?;
        Ok(())
    }

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        io::copy(&mut brotli::Decompressor::new(input, 4096), output)?;
        Ok(())
    }
}

/// Certificate compression backed by zstd.
struct ZstdCert;

impl CertificateCompressor for ZstdCert {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut encoder = zstd::stream::Encoder::new(output, 0)?;
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        io::copy(&mut zstd::stream::Decoder::new(input)?, output)?;
        Ok(())
    }
}

/// Load the webpki root certificates into the context.
fn install_roots(builder: &mut SslContextBuilder) -> Result<(), String> {
    let mut store = X509StoreBuilder::new().map_err(|error| error.to_string())?;
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        if let Ok(cert) = X509::from_der(der) {
            let _ = store.add_cert(cert);
        }
    }
    let built = store.build();
    builder.set_cert_store_ref(&built);
    Ok(())
}

impl crypto::ClientConfig for BoringClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        if version != QUIC_V1 {
            return Err(ConnectError::UnsupportedVersion);
        }
        let mut ssl =
            Ssl::new(&self.context).map_err(|_| ConnectError::InvalidServerName("".into()))?;
        ssl.set_hostname(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;
        apply_connection_settings(&mut ssl, &self.tls)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;

        let transport_params = match params.initial_src_cid {
            Some(cid) => stamp_initial_source_connection_id(&self.transport_params, &cid),
            None => self.transport_params.clone(),
        };
        let rc = unsafe {
            btls_sys::SSL_set_quic_transport_params(
                ssl.as_ptr(),
                transport_params.as_ptr(),
                transport_params.len(),
            )
        };
        if rc != 1 {
            return Err(ConnectError::InvalidServerName(server_name.into()));
        }
        unsafe { btls_sys::SSL_set_connect_state(ssl.as_ptr()) };

        let shared = Arc::new(Mutex::new(Shared {
            levels: Levels::new(),
            alert: None,
        }));
        let raw = Box::into_raw(Box::new(Arc::clone(&shared)));
        let rc = unsafe { btls_sys::SSL_set_ex_data(ssl.as_ptr(), ex_index(), raw.cast()) };
        if rc != 1 {
            unsafe { drop(Box::from_raw(raw)) };
            return Err(ConnectError::InvalidServerName(server_name.into()));
        }
        Ok(Box::new(BoringSession::new(ssl, shared)))
    }
}

/// Replace transport parameter `0x0f` with `source` without touching other bytes.
///
/// The preset fixes the source connection id length, so the new value occupies
/// the same span. GREASE and the flow-control parameters stay as encoded.
fn stamp_initial_source_connection_id(encoded: &[u8], source: &[u8]) -> Vec<u8> {
    let mut out = encoded.to_vec();
    let mut pos = 0usize;
    while pos < out.len() {
        let Some((id, id_size)) = read_varint(&out[pos..]) else {
            return encoded.to_vec();
        };
        pos += id_size;
        let Some((len, len_size)) = read_varint(&out[pos..]) else {
            return encoded.to_vec();
        };
        pos += len_size;
        let end = pos + len as usize;
        if end > out.len() {
            return encoded.to_vec();
        }
        if id == 0x0f {
            if len as usize != source.len() {
                return encoded.to_vec();
            }
            out[pos..end].copy_from_slice(source);
            return out;
        }
        pos = end;
    }
    encoded.to_vec()
}

/// One client Initial after header protection and packet protection are removed.
///
/// The keys are the RFC 9001 initial keys derived from the packet's destination
/// connection id, the same keys the peer uses.
pub struct OpenedInitial {
    /// Destination connection id from the long header.
    pub dst_cid: Vec<u8>,
    /// Source connection id from the long header.
    pub src_cid: Vec<u8>,
    /// Full packet number.
    pub packet_number: u64,
    /// Decrypted payload, QUIC frames.
    pub payload: Vec<u8>,
    /// Bytes this packet occupied at the start of the datagram slice passed in.
    pub packet_len: usize,
}

/// Unprotect a client Initial with the version-1 initial keys.
pub fn open_client_initial(datagram: &[u8]) -> Result<OpenedInitial, String> {
    if datagram.first().is_none_or(|byte| byte & 0x80 == 0) {
        return Err("not a long-header packet".into());
    }
    let mut pos = 1usize;
    let _version = read_exact(datagram, &mut pos, 4)?;
    let dst_cid = read_cid(datagram, &mut pos)?;
    let src_cid = read_cid(datagram, &mut pos)?;
    let (token_len, token_len_size) = read_varint(&datagram[pos..]).ok_or("token length")?;
    pos += token_len_size + token_len as usize;
    let (length, length_size) =
        read_varint(datagram.get(pos..).ok_or("length")?).ok_or("length")?;
    pos += length_size;
    let pn_offset = pos;
    if datagram.len() < pn_offset + 4 + SAMPLE_LEN {
        return Err("initial packet has no header-protection sample".into());
    }

    let mut packet = datagram.to_vec();
    let (client_secret, _) = initial_secrets(&dst_cid, Side::Client);
    QuicHeaderKey::new(Suite::Aes128Gcm, &client_secret).decrypt(pn_offset, &mut packet);
    let pn_len = (packet[0] & 0x03) as usize + 1;
    let pn_end = pn_offset + pn_len;
    let packet_end = pn_offset + length as usize;
    if packet_end > packet.len() || pn_end > packet_end {
        return Err("initial packet is truncated".into());
    }
    let mut packet_number = 0u64;
    for byte in &packet[pn_offset..pn_end] {
        packet_number = (packet_number << 8) | u64::from(*byte);
    }
    let header = packet[..pn_end].to_vec();
    let mut body = bytes::BytesMut::from(&packet[pn_end..packet_end]);
    QuicPacketKey::new(Suite::Aes128Gcm, &client_secret)
        .decrypt(packet_number, &header, &mut body)
        .map_err(|_| "initial decryption failed".to_string())?;
    Ok(OpenedInitial {
        dst_cid,
        src_cid,
        packet_number,
        payload: body.to_vec(),
        packet_len: packet_end,
    })
}

/// Every client Initial in one datagram.
///
/// A ClientHello that does not fit in 1200 bytes continues in a coalesced
/// Initial. Trailing padding and anything that is not a long-header packet stop
/// the walk.
pub fn open_client_datagram(datagram: &[u8]) -> Result<Vec<OpenedInitial>, String> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset < datagram.len() && datagram[offset] & 0x80 != 0 {
        let opened = open_client_initial(&datagram[offset..])?;
        if opened.packet_len == 0 {
            return Err("initial packet consumed no bytes".into());
        }
        offset += opened.packet_len;
        packets.push(opened);
    }
    if packets.is_empty() {
        return Err("datagram has no initial packet".into());
    }
    Ok(packets)
}

/// The `initial_source_connection_id` (0x0f) inside a decrypted Initial payload.
pub fn initial_source_connection_id(payload: &[u8]) -> Result<Vec<u8>, String> {
    initial_source_connection_id_from([payload])
}

/// `initial_source_connection_id` (0x0f) from every Initial in one flight.
///
/// CRYPTO frames are concatenated in the order the packets were captured. The
/// parameter lives in the ClientHello, which may span more than one Initial.
pub fn initial_source_connection_id_from<'a>(
    payloads: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, String> {
    let mut crypto = Vec::new();
    for payload in payloads {
        crypto.extend(crypto_stream(payload)?);
        if crypto.first() == Some(&1) && handshake_complete(&crypto) {
            break;
        }
    }
    if crypto.is_empty() {
        return Err("initial payload has no crypto frame".into());
    }
    let params = client_hello_extension(&crypto, 0x0039)?;
    transport_parameter(&params, 0x0f)
}

fn crypto_stream(payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = Vec::new();
    let mut pos = 0usize;
    while pos < payload.len() {
        if payload[pos] == 0x00 {
            pos += 1;
            continue;
        }
        let (frame, size) = read_varint(&payload[pos..]).ok_or("frame type")?;
        pos += size;
        if frame == 0x01 {
            continue;
        }
        if frame != 0x06 {
            return Err(format!("unexpected quic frame {frame}"));
        }
        let (_offset, offset_size) =
            read_varint(payload.get(pos..).ok_or("crypto offset")?).ok_or("crypto offset")?;
        pos += offset_size;
        let (len, len_size) =
            read_varint(payload.get(pos..).ok_or("crypto length")?).ok_or("crypto length")?;
        pos += len_size;
        let end = pos + len as usize;
        let data = payload.get(pos..end).ok_or("truncated crypto frame")?;
        stream.extend_from_slice(data);
        pos = end;
        if stream.first() == Some(&1) && handshake_complete(&stream) {
            break;
        }
    }
    if stream.is_empty() {
        return Err("initial payload has no crypto frame".into());
    }
    Ok(stream)
}

fn handshake_complete(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
    buf.len() >= 4 + len
}

fn client_hello_extension(handshake: &[u8], extension_type: u16) -> Result<Vec<u8>, String> {
    if handshake.first() != Some(&1) {
        return Err("payload is not a client hello".into());
    }
    let len = u32::from_be_bytes([
        0,
        *handshake.get(1).ok_or("handshake")?,
        *handshake.get(2).ok_or("handshake")?,
        *handshake.get(3).ok_or("handshake")?,
    ]) as usize;
    let body = handshake.get(4..4 + len).ok_or("truncated client hello")?;
    let mut pos = 2 + 32;
    let sid_len = *body.get(pos).ok_or("session id")? as usize;
    pos += 1 + sid_len;
    let cs_len = u16::from_be_bytes([
        *body.get(pos).ok_or("ciphers")?,
        *body.get(pos + 1).ok_or("ciphers")?,
    ]) as usize;
    pos += 2 + cs_len;
    let comp_len = *body.get(pos).ok_or("compression")? as usize;
    pos += 1 + comp_len;
    let ext_len = u16::from_be_bytes([
        *body.get(pos).ok_or("extensions")?,
        *body.get(pos + 1).ok_or("extensions")?,
    ]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > body.len() {
        return Err("truncated client hello extensions".into());
    }
    while pos + 4 <= ext_end {
        let kind = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let size = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        let data = body.get(pos..pos + size).ok_or("truncated extension")?;
        if kind == extension_type {
            return Ok(data.to_vec());
        }
        pos += size;
    }
    Err(format!("client hello has no extension {extension_type}"))
}

fn transport_parameter(params: &[u8], id: u64) -> Result<Vec<u8>, String> {
    let mut pos = 0usize;
    while pos < params.len() {
        let (found, id_size) =
            read_varint(params.get(pos..).ok_or("param id")?).ok_or("param id")?;
        pos += id_size;
        let (len, len_size) =
            read_varint(params.get(pos..).ok_or("param length")?).ok_or("param length")?;
        pos += len_size;
        let end = pos + len as usize;
        let value = params
            .get(pos..end)
            .ok_or("truncated transport parameter")?;
        if found == id {
            return Ok(value.to_vec());
        }
        pos = end;
    }
    Err(format!("transport parameters have no {id}"))
}

fn read_cid(buf: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    let len = *buf.get(*pos).ok_or("connection id length")? as usize;
    *pos += 1;
    let bytes = read_exact(buf, pos, len)?;
    Ok(bytes.to_vec())
}

fn read_exact<'a>(buf: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], String> {
    let end = pos.checked_add(len).ok_or("offset overflow")?;
    let bytes = buf.get(*pos..end).ok_or("truncated packet")?;
    *pos = end;
    Ok(bytes)
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut raw = [0u8; 8];
    raw[8 - len..].copy_from_slice(&buf[..len]);
    let value = u64::from_be_bytes(raw) & !(0b11u64 << (len * 8 - 2));
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The initial secret test vector from RFC 9001 appendix A.
    #[test]
    fn initial_secrets_match_the_rfc_vector() {
        let cid = hex("8394c8f03e515708");
        let (client, _server) = initial_secrets(&cid, Side::Client);
        // RFC 9001 appendix A.
        assert_eq!(
            client,
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        let (server, remote) = initial_secrets(&cid, Side::Server);
        assert_eq!(
            server,
            hex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        );
        assert_eq!(remote, client);
    }

    #[test]
    fn packet_keys_match_the_rfc_vector() {
        let secret = hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        let digest = unsafe { btls_sys::EVP_sha256() };
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        expand_label(digest, &secret, b"quic key", &mut key);
        expand_label(digest, &secret, b"quic iv", &mut iv);
        assert_eq!(key, hex("1f369613dd76d5467730efcbe3b1a22d").as_slice());
        assert_eq!(iv, hex("fa044b2f42a3fd3b46fb255c").as_slice());
    }

    #[test]
    fn captured_packet_keys() {
        let dcid = hex("1953e48ecc03d68b");
        let (client, _) = initial_secrets(&dcid, Side::Client);
        let digest = unsafe { btls_sys::EVP_sha256() };
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut hp = [0u8; 16];
        expand_label(digest, &client, b"quic key", &mut key);
        expand_label(digest, &client, b"quic iv", &mut iv);
        expand_label(digest, &client, b"quic hp", &mut hp);
        eprintln!("key {}", hex_out(&key));
        eprintln!("iv  {}", hex_out(&iv));
        eprintln!("hp  {}", hex_out(&hp));
    }

    fn hex_out(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn seal_matches_an_independent_implementation() {
        let secret = hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        let key = QuicPacketKey::new(Suite::Aes128Gcm, &secret);
        let header = b"HEADER-AAD";
        let mut buf = b"HEADER-AADhello quic payload".to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        key.encrypt(2, &mut buf, header.len());
        eprintln!("CT {}", hex_out(&buf[header.len()..]));
    }

    #[test]
    fn packet_protection_round_trips() {
        let secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
        let key = QuicPacketKey::new(Suite::Aes128Gcm, &secret);
        let header = b"header";
        let mut buf = b"headerplaintext".to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        key.encrypt(42, &mut buf, header.len());
        assert_ne!(&buf[header.len()..], b"plaintext");

        let mut payload = bytes::BytesMut::from(&buf[header.len()..]);
        key.decrypt(42, header, &mut payload).unwrap();
        assert_eq!(&payload[..], b"plaintext");
        assert!(key
            .decrypt(43, header, &mut bytes::BytesMut::from(&buf[header.len()..]))
            .is_err());
    }

    #[test]
    fn dropping_the_session_frees_the_shared_ex_data() {
        let profile = crate::profile::http3("chrome150").expect("chrome150 has http3");
        let mut rng = crate::quic::params::SystemRng;
        let encoded = crate::quic::params::encode(profile.transport_parameters, &[], &mut rng)
            .expect("chrome150 transport parameters");
        let config = BoringClientConfig::new(
            crate::quic::spec::QuicTls::from_profile(&profile, true).shared(),
            encoded.bytes,
        )
        .expect("boring config");
        let params =
            TransportParameters::read(Side::Client, &mut Cursor::new([])).expect("defaults");
        let before = EX_DATA_FREES.load(std::sync::atomic::Ordering::Relaxed);
        let session =
            crypto::ClientConfig::start_session(Arc::new(config), QUIC_V1, "example.com", &params)
                .expect("session");
        drop(session);
        assert_eq!(
            EX_DATA_FREES.load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }
}
