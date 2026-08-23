//! Telegraph's neutral, relay-facing wire framing.
//!
//! This crate intentionally stops at an opaque envelope.  It does not know
//! about a cryptographic profile, a transcript, a confirmation value, a
//! provider key, a Codex thread, or plaintext.  The CBOR implementation is a
//! schema-specific wrapper around cbor4ii's `core` traits: no generic CBOR map
//! is decoded at the protocol boundary.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(unused_must_use)]

use cbor4ii::core::{
    dec::{Decode, Read},
    enc::{Encode, Write},
    error::{DecodeError, Never},
    types::{Bytes, Map},
    utils::SliceReader,
};
use std::fmt;

/// The maximum ciphertext field accepted by the neutral outer envelope.
pub const MAX_CIPHERTEXT_LEN: usize = 65_536;

/// The maximum size of a complete, deterministic outer envelope.
pub const MAX_ENVELOPE_LEN: usize = 69_632;

/// The largest opaque routing handle accepted for one ID field.
pub const MAX_OPAQUE_ID_LEN: usize = 256;

/// Compatibility aliases that make the wire limits easy to discover.
pub const MAX_CIPHERTEXT: usize = MAX_CIPHERTEXT_LEN;
pub const MAX_ENVELOPE_SIZE: usize = MAX_ENVELOPE_LEN;

/// The only version implemented by this neutral framing crate.
pub const SUPPORTED_MAJOR: u16 = 1;
pub const SUPPORTED_MINOR: u16 = 0;

const ENVELOPE_FIELD_COUNT: usize = 6;
const VERSION_FIELD_COUNT: usize = 2;

/// Stable classes returned by bounded frame parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    EmptyInput,
    Truncated,
    Malformed,
    IndefiniteLength,
    TrailingBytes,
    NonCanonical,
    DuplicateKey,
    OutOfOrderKey,
    UnknownKey,
    WrongType,
    UnsupportedVersion,
    OversizedCiphertext,
    OversizedEnvelope,
    OversizedOpaqueId,
    EmptyOpaqueId,
    InvalidSize,
    InvalidStatus,
    InvalidErrorCode,
    EncodeFailure,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyInput => "empty protocol input",
            Self::Truncated => "truncated CBOR input",
            Self::Malformed => "malformed CBOR input",
            Self::IndefiniteLength => "indefinite CBOR length",
            Self::TrailingBytes => "trailing bytes after CBOR item",
            Self::NonCanonical => "non-canonical CBOR encoding",
            Self::DuplicateKey => "duplicate CBOR map key",
            Self::OutOfOrderKey => "out-of-order CBOR map key",
            Self::UnknownKey => "unknown CBOR map key",
            Self::WrongType => "wrong CBOR type",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::OversizedCiphertext => "ciphertext exceeds protocol limit",
            Self::OversizedEnvelope => "envelope exceeds protocol limit",
            Self::OversizedOpaqueId => "opaque ID exceeds protocol limit",
            Self::EmptyOpaqueId => "opaque ID must not be empty",
            Self::InvalidSize => "invalid envelope size field",
            Self::InvalidStatus => "invalid status code",
            Self::InvalidErrorCode => "invalid error code",
            Self::EncodeFailure => "CBOR encoding failed",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// A protocol major/minor pair.  It contains no profile or provider name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    pub const fn current() -> Self {
        Self::new(SUPPORTED_MAJOR, SUPPORTED_MINOR)
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn is_supported(self) -> bool {
        self.major == SUPPORTED_MAJOR && self.minor == SUPPORTED_MINOR
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::current()
    }
}

/// Shared private storage for the two opaque routing-handle newtypes.
#[derive(Clone, PartialEq, Eq, Hash)]
struct OpaqueBytes(Vec<u8>);

impl fmt::Debug for OpaqueBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OpaqueBytes").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

impl OpaqueBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ProtocolError> {
        let bytes = bytes.into();
        validate_opaque_id(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A bounded opaque mailbox routing handle.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MailboxId(OpaqueBytes);

impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MailboxId").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

impl MailboxId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ProtocolError> {
        Ok(Self(OpaqueBytes::new(bytes)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for MailboxId {
    type Error = ProtocolError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A bounded opaque delivery idempotency handle.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DeliveryId(OpaqueBytes);

impl fmt::Debug for DeliveryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DeliveryId").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

impl DeliveryId {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ProtocolError> {
        Ok(Self(OpaqueBytes::new(bytes)?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<u8>> for DeliveryId {
    type Error = ProtocolError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// An opaque outer envelope suitable for relay-facing transport.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    version: ProtocolVersion,
    mailbox_id: MailboxId,
    delivery_id: DeliveryId,
    ciphertext: Vec<u8>,
    expires_at: u64,
    size: u64,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope")
            .field("version", &self.version)
            .field("mailbox_id", &self.mailbox_id)
            .field("delivery_id", &self.delivery_id)
            .field("ciphertext_len", &self.ciphertext.len())
            .field("expires_at", &self.expires_at)
            .field("size", &self.size)
            .finish()
    }
}

impl Envelope {
    /// Construct a canonical envelope.  The wire `size` field is calculated
    /// from the fixed schema and is never supplied by a caller.
    pub fn new(
        version: ProtocolVersion,
        mailbox_id: MailboxId,
        delivery_id: DeliveryId,
        ciphertext: Vec<u8>,
        expires_at: u64,
    ) -> Result<Self, ProtocolError> {
        validate_envelope_parts(version, &mailbox_id, &delivery_id, &ciphertext)?;
        let mut envelope =
            Self { version, mailbox_id, delivery_id, ciphertext, expires_at, size: 0 };
        let Some(encoded) = envelope.encode_with_size() else {
            return Err(ProtocolError::OversizedEnvelope);
        };
        envelope.size = encoded.len() as u64;
        Ok(envelope)
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    pub fn mailbox_id(&self) -> &MailboxId {
        &self.mailbox_id
    }

    pub fn delivery_id(&self) -> &DeliveryId {
        &self.delivery_id
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The complete encoded envelope size, including its size field.
    pub fn size(&self) -> usize {
        self.size as usize
    }

    /// Encode using the fixed schema and canonical shortest forms.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        validate_envelope_parts(
            self.version,
            &self.mailbox_id,
            &self.delivery_id,
            &self.ciphertext,
        )?;
        let bytes = self.encode_with_size().ok_or(ProtocolError::OversizedEnvelope)?;
        if bytes.len() > MAX_ENVELOPE_LEN {
            return Err(ProtocolError::OversizedEnvelope);
        }
        Ok(bytes)
    }

    /// Decode one complete canonical envelope.  No generic CBOR map is used.
    pub fn from_bytes(input: &[u8]) -> Result<Self, ProtocolError> {
        decode_envelope(input)
    }

    fn encode_with_size(&self) -> Option<Vec<u8>> {
        // The encoded size itself is a field.  It only changes its CBOR width
        // at finite boundaries, so a small bounded fixed-point loop suffices.
        let mut declared_size = self.size;
        for _ in 0..8 {
            let bytes = encode_wire(self, declared_size).ok()?;
            let next = u64::try_from(bytes.len()).ok()?;
            if next == declared_size {
                return Some(bytes);
            }
            declared_size = next;
        }
        None
    }
}

/// Encode an envelope without exposing any inner payload model.
pub fn encode_envelope(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    envelope.to_bytes()
}

/// Decode one complete deterministic envelope.
pub fn decode_envelope(input: &[u8]) -> Result<Envelope, ProtocolError> {
    if input.is_empty() {
        return Err(ProtocolError::EmptyInput);
    }
    if input.len() > MAX_ENVELOPE_LEN {
        return Err(ProtocolError::OversizedEnvelope);
    }

    let mut reader = SliceReader::new(input);
    let map_len = Map::len(&mut reader).map_err(map_decode_error)?;
    let Some(map_len) = map_len else {
        return Err(ProtocolError::IndefiniteLength);
    };
    if map_len != ENVELOPE_FIELD_COUNT {
        return Err(ProtocolError::UnknownKey);
    }

    let mut version = None;
    let mut mailbox_id = None;
    let mut delivery_id = None;
    let mut ciphertext = None;
    let mut expires_at = None;
    let mut declared_size = None;
    let mut previous_key = None;

    for _ in 0..map_len {
        let key = decode_u64(&mut reader)?;
        check_key_order(previous_key, key, key < ENVELOPE_FIELD_COUNT as u64)?;
        previous_key = Some(key);

        match key {
            0 => version = Some(decode_version(&mut reader)?),
            1 => mailbox_id = Some(decode_mailbox_id(&mut reader)?),
            2 => delivery_id = Some(decode_delivery_id(&mut reader)?),
            3 => {
                let Bytes(bytes) = Bytes::<&[u8]>::decode(&mut reader).map_err(map_decode_error)?;
                if bytes.len() > MAX_CIPHERTEXT_LEN {
                    return Err(ProtocolError::OversizedCiphertext);
                }
                ciphertext = Some(bytes.to_vec());
            }
            4 => expires_at = Some(decode_u64(&mut reader)?),
            5 => declared_size = Some(decode_u64(&mut reader)?),
            _ => return Err(ProtocolError::UnknownKey),
        }
    }

    if !reader.fill(1).map_err(|_| ProtocolError::Malformed)?.as_ref().is_empty() {
        return Err(ProtocolError::TrailingBytes);
    }

    let version = version.ok_or(ProtocolError::UnknownKey)?;
    if !version.is_supported() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let mailbox_id = mailbox_id.ok_or(ProtocolError::UnknownKey)?;
    let delivery_id = delivery_id.ok_or(ProtocolError::UnknownKey)?;
    let ciphertext = ciphertext.ok_or(ProtocolError::UnknownKey)?;
    let expires_at = expires_at.ok_or(ProtocolError::UnknownKey)?;
    let size = declared_size.ok_or(ProtocolError::UnknownKey)?;
    if size != input.len() as u64 || size as usize > MAX_ENVELOPE_LEN {
        return Err(ProtocolError::InvalidSize);
    }

    let envelope = Envelope { version, mailbox_id, delivery_id, ciphertext, expires_at, size };
    let canonical = envelope.encode_with_size().ok_or(ProtocolError::EncodeFailure)?;
    if canonical != input {
        return Err(ProtocolError::NonCanonical);
    }
    Ok(envelope)
}

fn decode_version(reader: &mut SliceReader<'_>) -> Result<ProtocolVersion, ProtocolError> {
    let len = Map::len(reader).map_err(map_decode_error)?;
    let Some(len) = len else {
        return Err(ProtocolError::IndefiniteLength);
    };
    if len != VERSION_FIELD_COUNT {
        return Err(ProtocolError::UnknownKey);
    }

    let mut major = None;
    let mut minor = None;
    let mut previous_key = None;
    for _ in 0..len {
        let key = decode_u64(reader)?;
        check_key_order(previous_key, key, key < VERSION_FIELD_COUNT as u64)?;
        previous_key = Some(key);
        match key {
            0 => major = Some(decode_u16(reader)?),
            1 => minor = Some(decode_u16(reader)?),
            _ => return Err(ProtocolError::UnknownKey),
        }
    }
    let major = major.ok_or(ProtocolError::UnknownKey)?;
    let minor = minor.ok_or(ProtocolError::UnknownKey)?;
    Ok(ProtocolVersion::new(major, minor))
}

fn decode_opaque_bytes(reader: &mut SliceReader<'_>) -> Result<OpaqueBytes, ProtocolError> {
    let Bytes(bytes) = Bytes::<&[u8]>::decode(reader).map_err(map_decode_error)?;
    validate_opaque_id(bytes)?;
    OpaqueBytes::new(bytes.to_vec())
}

fn decode_mailbox_id(reader: &mut SliceReader<'_>) -> Result<MailboxId, ProtocolError> {
    Ok(MailboxId(decode_opaque_bytes(reader)?))
}

fn decode_delivery_id(reader: &mut SliceReader<'_>) -> Result<DeliveryId, ProtocolError> {
    Ok(DeliveryId(decode_opaque_bytes(reader)?))
}

fn decode_u16(reader: &mut SliceReader<'_>) -> Result<u16, ProtocolError> {
    u16::decode(reader).map_err(map_decode_error)
}

fn decode_u64(reader: &mut SliceReader<'_>) -> Result<u64, ProtocolError> {
    u64::decode(reader).map_err(map_decode_error)
}

fn check_key_order(previous_key: Option<u64>, key: u64, known: bool) -> Result<(), ProtocolError> {
    if let Some(previous_key) = previous_key {
        if key == previous_key {
            return Err(ProtocolError::DuplicateKey);
        }
        if key < previous_key {
            return Err(ProtocolError::OutOfOrderKey);
        }
    }
    if !known {
        return Err(ProtocolError::UnknownKey);
    }
    Ok(())
}

fn validate_opaque_id(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::EmptyOpaqueId);
    }
    if bytes.len() > MAX_OPAQUE_ID_LEN {
        return Err(ProtocolError::OversizedOpaqueId);
    }
    Ok(())
}

fn validate_envelope_parts(
    version: ProtocolVersion,
    mailbox_id: &MailboxId,
    delivery_id: &DeliveryId,
    ciphertext: &[u8],
) -> Result<(), ProtocolError> {
    if !version.is_supported() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    validate_opaque_id(mailbox_id.as_bytes())?;
    validate_opaque_id(delivery_id.as_bytes())?;
    if ciphertext.len() > MAX_CIPHERTEXT_LEN {
        return Err(ProtocolError::OversizedCiphertext);
    }
    Ok(())
}

fn encode_wire(envelope: &Envelope, declared_size: u64) -> Result<Vec<u8>, ProtocolError> {
    let mut writer = BoundedWriter::new(MAX_ENVELOPE_LEN);
    Map::bounded(ENVELOPE_FIELD_COUNT, &mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    0u64.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    encode_version(envelope.version, &mut writer)?;
    1u64.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    Bytes(envelope.mailbox_id.as_bytes())
        .encode(&mut writer)
        .map_err(|_| ProtocolError::EncodeFailure)?;
    2u64.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    Bytes(envelope.delivery_id.as_bytes())
        .encode(&mut writer)
        .map_err(|_| ProtocolError::EncodeFailure)?;
    3u64.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    Bytes(envelope.ciphertext.as_slice())
        .encode(&mut writer)
        .map_err(|_| ProtocolError::EncodeFailure)?;
    4u64.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    envelope.expires_at.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    5u64.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    declared_size.encode(&mut writer).map_err(|_| ProtocolError::EncodeFailure)?;
    Ok(writer.into_inner())
}

fn encode_version(
    version: ProtocolVersion,
    writer: &mut BoundedWriter,
) -> Result<(), ProtocolError> {
    Map::bounded(VERSION_FIELD_COUNT, writer).map_err(|_| ProtocolError::EncodeFailure)?;
    0u64.encode(writer).map_err(|_| ProtocolError::EncodeFailure)?;
    u64::from(version.major).encode(writer).map_err(|_| ProtocolError::EncodeFailure)?;
    1u64.encode(writer).map_err(|_| ProtocolError::EncodeFailure)?;
    u64::from(version.minor).encode(writer).map_err(|_| ProtocolError::EncodeFailure)?;
    Ok(())
}

struct BoundedWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl BoundedWriter {
    fn new(max: usize) -> Self {
        Self { bytes: Vec::new(), max }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    type Error = BoundedWriteError;

    fn push(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        let new_len = self.bytes.len().checked_add(input.len()).ok_or(BoundedWriteError)?;
        if new_len > self.max {
            return Err(BoundedWriteError);
        }
        self.bytes.try_reserve(input.len()).map_err(|_| BoundedWriteError)?;
        self.bytes.extend_from_slice(input);
        Ok(())
    }
}

#[derive(Debug)]
struct BoundedWriteError;

impl fmt::Display for BoundedWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded CBOR writer capacity exceeded")
    }
}

impl std::error::Error for BoundedWriteError {}

fn map_decode_error(error: DecodeError<Never>) -> ProtocolError {
    match error {
        DecodeError::Eof { .. } => ProtocolError::Truncated,
        DecodeError::RequireLength { found: cbor4ii::core::error::Len::Indefinite, .. } => {
            ProtocolError::IndefiniteLength
        }
        DecodeError::RequireLength { .. } => ProtocolError::Malformed,
        DecodeError::LengthOverflow { .. } | DecodeError::CastOverflow { .. } => {
            ProtocolError::OversizedEnvelope
        }
        DecodeError::Mismatch { .. } | DecodeError::Unsupported { .. } => ProtocolError::WrongType,
        DecodeError::DepthOverflow { .. } => ProtocolError::Malformed,
        DecodeError::ArithmeticOverflow { .. }
        | DecodeError::RequireBorrowed { .. }
        | DecodeError::RequireUtf8 { .. }
        | DecodeError::Custom { .. }
        | DecodeError::Read(_) => ProtocolError::Malformed,
        // The dependency marks this error enum non-exhaustive.  Keep future
        // variants bounded and opaque rather than exposing decoder details.
        _ => ProtocolError::Malformed,
    }
}

#[cfg(test)]
mod tests;
