use cbor4ii::core::dec::Decode;
use cbor4ii::core::enc::{Encode, Write};
use cbor4ii::core::{dec, enc, types};
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use getrandom::fill as random_fill;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{OpaqueAccountState, OpaqueSessionState};

/// XChaCha20-Poly1305 nonce and authentication-tag sizes from ADR 0002.
pub const RECORD_NONCE_BYTES: usize = 24;
pub const RECORD_AEAD_TAG_BYTES: usize = 16;
const MAX_RECORD_PLAINTEXT_BYTES: usize = 1_048_576;
const MAX_RECORD_BYTES: usize = MAX_RECORD_PLAINTEXT_BYTES + RECORD_AEAD_TAG_BYTES;
const MAX_AAD_BYTES: usize = 256;
const RECORD_KEY_DOMAIN: &[u8] = b"telegraph/storage-record-key/v1";

/// Bounded record kinds permitted by the storage profile. The text values
/// are part of the authenticated, deterministic CBOR representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Account,
    Session,
    Channel,
    Dedup,
    Prekey,
}

impl RecordType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Session => "session",
            Self::Channel => "channel",
            Self::Dedup => "dedup",
            Self::Prekey => "prekey",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "account" => Self::Account,
            "session" => Self::Session,
            "channel" => Self::Channel,
            "dedup" => Self::Dedup,
            "prekey" => Self::Prekey,
            _ => return None,
        })
    }
}

/// Exact storage AAD fields. `record_id` is always a 16-byte identifier;
/// domain is fixed by this crate and is not an additional caller field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordAad {
    record_type: RecordType,
    record_id: [u8; 16],
    record_schema: u64,
    record_version: u64,
}

impl RecordAad {
    pub const fn new(
        record_type: RecordType,
        record_id: [u8; 16],
        record_schema: u64,
        record_version: u64,
    ) -> Self {
        Self { record_type, record_id, record_schema, record_version }
    }

    pub const fn record_type(&self) -> RecordType {
        self.record_type
    }

    pub const fn record_id(&self) -> &[u8; 16] {
        &self.record_id
    }

    pub const fn record_schema(&self) -> u64 {
        self.record_schema
    }

    pub const fn record_version(&self) -> u64 {
        self.record_version
    }

    /// Encode exactly `{0: record_type, 1: record_id, 2: record_schema,
    /// 3: record_version}` with canonical CBOR widths and map ordering.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut writer = VecWriter::new(MAX_AAD_BYTES);
        writer.push(&[0xa4]).map_err(|_| RecordError::Encoding)?;
        self.encode_value(&mut writer).map_err(|_| RecordError::Encoding)?;
        Ok(writer.into_inner())
    }

    fn encode_value<W: enc::Write>(&self, writer: &mut W) -> Result<(), enc::Error<W::Error>> {
        0u8.encode(writer)?;
        self.record_type.as_str().encode(writer)?;
        1u8.encode(writer)?;
        types::Bytes(self.record_id.as_slice()).encode(writer)?;
        2u8.encode(writer)?;
        self.record_schema.encode(writer)?;
        3u8.encode(writer)?;
        self.record_version.encode(writer)
    }

    /// Strictly decode canonical AAD. A re-encode comparison rejects trailing
    /// bytes, non-canonical integer widths, duplicate keys, and reordered keys.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.is_empty() || bytes.len() > MAX_AAD_BYTES {
            return Err(RecordError::InvalidAad);
        }
        let mut reader = cbor4ii::core::utils::SliceReader::new(bytes);
        let Some(len) = types::Map::len(&mut reader).map_err(|_| RecordError::InvalidAad)? else {
            return Err(RecordError::InvalidAad);
        };
        if len != 4 {
            return Err(RecordError::InvalidAad);
        }
        let key0 = u8::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        if key0 != 0 {
            return Err(RecordError::InvalidAad);
        }
        let kind = <&str>::decode(&mut reader)
            .map_err(|_| RecordError::InvalidAad)
            .and_then(|value| RecordType::from_str(value).ok_or(RecordError::InvalidAad))?;
        let key1 = u8::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        if key1 != 1 {
            return Err(RecordError::InvalidAad);
        }
        let types::Bytes(id) =
            types::Bytes::<&[u8]>::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        let record_id: [u8; 16] = id.try_into().map_err(|_| RecordError::InvalidAad)?;
        let key2 = u8::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        if key2 != 2 {
            return Err(RecordError::InvalidAad);
        }
        let record_schema = u64::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        let key3 = u8::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        if key3 != 3 {
            return Err(RecordError::InvalidAad);
        }
        let record_version = u64::decode(&mut reader).map_err(|_| RecordError::InvalidAad)?;
        let aad = Self::new(kind, record_id, record_schema, record_version);
        if aad.encode()? != bytes {
            return Err(RecordError::InvalidAad);
        }
        Ok(aad)
    }

    fn hkdf_info(&self) -> Zeroizing<Vec<u8>> {
        let mut info = Zeroizing::new(Vec::with_capacity(
            RECORD_KEY_DOMAIN.len() + self.record_type.as_str().len() + 16,
        ));
        info.extend_from_slice(RECORD_KEY_DOMAIN);
        info.extend_from_slice(self.record_type.as_str().as_bytes());
        info.extend_from_slice(&self.record_schema.to_be_bytes());
        info.extend_from_slice(&self.record_version.to_be_bytes());
        info
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    InvalidAad,
    InvalidEnvelope,
    TooLarge,
    Randomness,
    Encoding,
    Authentication,
    KeyDerivation,
}

/// Sealed storage record. Ciphertext contains the 16-byte tag at its end.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordEnvelope {
    nonce: [u8; RECORD_NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl RecordEnvelope {
    pub fn from_parts(
        nonce: [u8; RECORD_NONCE_BYTES],
        ciphertext: &[u8],
    ) -> Result<Self, RecordError> {
        if ciphertext.len() < RECORD_AEAD_TAG_BYTES {
            return Err(RecordError::InvalidEnvelope);
        }
        if ciphertext.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge);
        }
        let mut copy = Vec::new();
        copy.try_reserve_exact(ciphertext.len()).map_err(|_| RecordError::TooLarge)?;
        copy.extend_from_slice(ciphertext);
        Ok(Self { nonce, ciphertext: copy })
    }

    pub const fn nonce(&self) -> &[u8; RECORD_NONCE_BYTES] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn ciphertext_mut(&mut self) -> &mut [u8] {
        &mut self.ciphertext
    }

    pub fn open(
        &self,
        master_key: &[u8; 32],
        aad: &RecordAad,
    ) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        open_record(master_key, aad, self)
    }
}

/// Seal an adapter-owned account state. Provider pickle bytes never cross the
/// public API, and an account state cannot be stored under another record kind.
pub fn seal_account_state(
    master_key: &[u8; 32],
    aad: &RecordAad,
    state: &OpaqueAccountState,
) -> Result<RecordEnvelope, RecordError> {
    if aad.record_type != RecordType::Account {
        return Err(RecordError::InvalidAad);
    }
    seal_record_inner(master_key, aad, state.as_bytes())
}

/// Authenticate and open one account state record into an opaque adapter type.
pub fn open_account_state(
    master_key: &[u8; 32],
    aad: &RecordAad,
    envelope: &RecordEnvelope,
) -> Result<OpaqueAccountState, RecordError> {
    if aad.record_type != RecordType::Account {
        return Err(RecordError::InvalidAad);
    }
    OpaqueAccountState::from_bytes(open_record_inner(master_key, aad, envelope)?)
        .map_err(|_| RecordError::InvalidEnvelope)
}

pub fn seal_session_state(
    master_key: &[u8; 32],
    aad: &RecordAad,
    state: &OpaqueSessionState,
) -> Result<RecordEnvelope, RecordError> {
    if aad.record_type != RecordType::Session {
        return Err(RecordError::InvalidAad);
    }
    seal_record_inner(master_key, aad, state.as_bytes())
}

pub fn open_session_state(
    master_key: &[u8; 32],
    aad: &RecordAad,
    envelope: &RecordEnvelope,
) -> Result<OpaqueSessionState, RecordError> {
    if aad.record_type != RecordType::Session {
        return Err(RecordError::InvalidAad);
    }
    OpaqueSessionState::from_bytes(open_record_inner(master_key, aad, envelope)?)
        .map_err(|_| RecordError::InvalidEnvelope)
}

pub fn seal_record(
    master_key: &[u8; 32],
    aad: &RecordAad,
    plaintext: &[u8],
) -> Result<RecordEnvelope, RecordError> {
    if matches!(aad.record_type, RecordType::Account | RecordType::Session) {
        return Err(RecordError::InvalidAad);
    }
    seal_record_inner(master_key, aad, plaintext)
}

fn seal_record_inner(
    master_key: &[u8; 32],
    aad: &RecordAad,
    plaintext: &[u8],
) -> Result<RecordEnvelope, RecordError> {
    if plaintext.len() > MAX_RECORD_PLAINTEXT_BYTES {
        return Err(RecordError::TooLarge);
    }
    let aad_bytes = aad.encode()?;
    let key = derive_record_key(master_key, aad)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| RecordError::KeyDerivation)?;
    let mut nonce = [0u8; RECORD_NONCE_BYTES];
    random_fill(&mut nonce).map_err(|_| RecordError::Randomness)?;
    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(plaintext.len() + RECORD_AEAD_TAG_BYTES)
        .map_err(|_| RecordError::TooLarge)?;
    ciphertext.extend_from_slice(plaintext);
    if cipher
        .encrypt_in_place(
            &XNonce::try_from(nonce.as_slice()).map_err(|_| RecordError::InvalidEnvelope)?,
            &aad_bytes,
            &mut ciphertext,
        )
        .is_err()
    {
        ciphertext.zeroize();
        return Err(RecordError::Authentication);
    }
    RecordEnvelope::from_parts(nonce, &ciphertext)
}

pub fn open_record(
    master_key: &[u8; 32],
    aad: &RecordAad,
    envelope: &RecordEnvelope,
) -> Result<Zeroizing<Vec<u8>>, RecordError> {
    if matches!(aad.record_type, RecordType::Account | RecordType::Session) {
        return Err(RecordError::InvalidAad);
    }
    open_record_inner(master_key, aad, envelope)
}

fn open_record_inner(
    master_key: &[u8; 32],
    aad: &RecordAad,
    envelope: &RecordEnvelope,
) -> Result<Zeroizing<Vec<u8>>, RecordError> {
    if envelope.ciphertext.len() < RECORD_AEAD_TAG_BYTES {
        return Err(RecordError::InvalidEnvelope);
    }
    if envelope.ciphertext.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge);
    }
    let aad_bytes = aad.encode()?;
    let key = derive_record_key(master_key, aad)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| RecordError::KeyDerivation)?;
    let mut plaintext = envelope.ciphertext.clone();
    cipher
        .decrypt_in_place(
            &XNonce::try_from(envelope.nonce.as_slice())
                .map_err(|_| RecordError::InvalidEnvelope)?,
            &aad_bytes,
            &mut plaintext,
        )
        .map_err(|_| {
            plaintext.zeroize();
            RecordError::Authentication
        })?;
    Ok(Zeroizing::new(plaintext))
}

fn derive_record_key(
    master_key: &[u8; 32],
    aad: &RecordAad,
) -> Result<Zeroizing<[u8; 32]>, RecordError> {
    let hkdf = Hkdf::<Sha256>::new(Some(aad.record_id.as_slice()), master_key);
    let info = aad.hkdf_info();
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, key.as_mut()).map_err(|_| RecordError::KeyDerivation)?;
    Ok(key)
}

struct VecWriter {
    buf: Vec<u8>,
    limit: usize,
}

impl VecWriter {
    fn new(limit: usize) -> Self {
        Self { buf: Vec::new(), limit }
    }

    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

impl enc::Write for VecWriter {
    type Error = std::io::Error;

    fn push(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let next = self
            .buf
            .len()
            .checked_add(input.len())
            .ok_or_else(|| std::io::Error::other("CBOR too large"))?;
        if next > self.limit {
            return Err(std::io::Error::other("CBOR too large"));
        }
        self.buf
            .try_reserve(input.len())
            .map_err(|_| std::io::Error::other("allocation failed"))?;
        self.buf.extend_from_slice(input);
        Ok(())
    }
}

#[allow(dead_code)]
fn _strict_decode_traits_are_linked<R: dec::Read<'static>>() {}
