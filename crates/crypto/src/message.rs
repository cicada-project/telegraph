use crate::{CryptoError, OLM_VERSION, checked_message_bytes};
use vodozemac::olm::{Message, OlmMessage, PreKeyMessage};
use zeroize::Zeroizing;

/// Whether an encoded Olm message is the initial pre-key form or a normal
/// ratchet message.  The value is metadata only; it is not authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    PreKey,
    Normal,
}

/// Publicly parseable Olm message header fields.  No plaintext, private key,
/// or ratchet secret is retained here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OlmPublicMetadata {
    pub kind: MessageKind,
    pub message_version: u8,
    pub sender_identity_curve25519: Option<[u8; 32]>,
    pub base_or_ephemeral_curve25519: Option<[u8; 32]>,
    pub selected_one_time_curve25519: Option<[u8; 32]>,
    pub ratchet_public_curve25519: [u8; 32],
    pub chain_or_message_index: u64,
}

/// A parsed message.  This type owns only the encoded public message and its
/// provider parse result; it never exposes provider internals.
#[derive(Clone)]
pub struct ParsedMessage {
    bytes: Vec<u8>,
    message: OlmMessage,
    metadata: OlmPublicMetadata,
}

impl ParsedMessage {
    /// Parse a vodozemac type-tagged message (`0` pre-key, `1` normal).
    pub fn parse(message_type: u8, bytes: &[u8]) -> Result<Self, CryptoError> {
        checked_message_bytes(bytes)?;
        if message_type > 1 {
            return Err(CryptoError::MessageDecode);
        }
        let parsed = OlmMessage::from_parts(message_type as usize, bytes)
            .map_err(|_| CryptoError::MessageDecode)?;
        let metadata = metadata_for(&parsed)?;
        if metadata.message_version != 3 {
            return Err(CryptoError::UnsupportedMessageVersion);
        }
        Ok(Self { bytes: bytes.to_vec(), message: parsed, metadata })
    }

    pub fn kind(&self) -> MessageKind {
        self.metadata.kind
    }

    pub fn metadata(&self) -> OlmPublicMetadata {
        self.metadata
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn provider_message(&self) -> &OlmMessage {
        &self.message
    }
}

/// The bytes and public metadata produced by one successful `Session::encrypt`.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedMessage {
    kind: MessageKind,
    bytes: Vec<u8>,
    metadata: OlmPublicMetadata,
}

impl EncryptedMessage {
    pub fn from_parts(kind: MessageKind, bytes: &[u8]) -> Result<Self, CryptoError> {
        let parsed = message_for_type(kind, bytes)?;
        Ok(Self { kind, bytes: bytes.to_vec(), metadata: parsed.metadata() })
    }

    pub fn to_parts(&self) -> (MessageKind, Vec<u8>) {
        (self.kind, self.bytes.clone())
    }

    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    pub const fn metadata(&self) -> OlmPublicMetadata {
        self.metadata
    }

    pub fn parse(&self) -> Result<ParsedMessage, CryptoError> {
        let tag = match self.kind {
            MessageKind::PreKey => 0,
            MessageKind::Normal => 1,
        };
        ParsedMessage::parse(tag, &self.bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Result of accepting an inbound message.  The plaintext is deliberately an
/// opaque byte vector; callers decide whether it is a confirmation or an
/// application inner record.
#[derive(PartialEq, Eq)]
pub struct InboundMessage {
    plaintext: Zeroizing<Vec<u8>>,
    metadata: OlmPublicMetadata,
}

impl InboundMessage {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub const fn metadata(&self) -> OlmPublicMetadata {
        self.metadata
    }
}

/// A semantic alias used by the pairing layer for confirmation payloads.  No
/// parser or independent MAC is provided: successful Olm decryption is the
/// authentication operation required by ADR 0002.
#[derive(PartialEq, Eq)]
pub struct SessionAuthenticatedMessage {
    plaintext: Zeroizing<Vec<u8>>,
    metadata: OlmPublicMetadata,
}

impl SessionAuthenticatedMessage {
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub const fn metadata(&self) -> OlmPublicMetadata {
        self.metadata
    }
}

pub(crate) fn from_provider_message(message: OlmMessage) -> Result<EncryptedMessage, CryptoError> {
    let (kind, bytes) = match &message {
        OlmMessage::PreKey(_) => (MessageKind::PreKey, message.to_parts().1),
        OlmMessage::Normal(_) => (MessageKind::Normal, message.to_parts().1),
    };
    checked_message_bytes(&bytes)?;
    let metadata = metadata_for(&message)?;
    if metadata.message_version != OLM_VERSION + 2 {
        return Err(CryptoError::UnsupportedMessageVersion);
    }
    Ok(EncryptedMessage { kind, bytes, metadata })
}

fn metadata_for(message: &OlmMessage) -> Result<OlmPublicMetadata, CryptoError> {
    match message {
        OlmMessage::PreKey(prekey) => {
            let inner = prekey.message();
            Ok(OlmPublicMetadata {
                kind: MessageKind::PreKey,
                message_version: inner.version(),
                sender_identity_curve25519: Some(prekey.identity_key().to_bytes()),
                base_or_ephemeral_curve25519: Some(prekey.base_key().to_bytes()),
                selected_one_time_curve25519: Some(prekey.one_time_key().to_bytes()),
                ratchet_public_curve25519: inner.ratchet_key().to_bytes(),
                chain_or_message_index: inner.chain_index(),
            })
        }
        OlmMessage::Normal(normal) => Ok(OlmPublicMetadata {
            kind: MessageKind::Normal,
            message_version: normal.version(),
            sender_identity_curve25519: None,
            base_or_ephemeral_curve25519: None,
            selected_one_time_curve25519: None,
            ratchet_public_curve25519: normal.ratchet_key().to_bytes(),
            chain_or_message_index: normal.chain_index(),
        }),
    }
}

pub(crate) fn message_for_type(
    kind: MessageKind,
    bytes: &[u8],
) -> Result<ParsedMessage, CryptoError> {
    let type_tag = match kind {
        MessageKind::PreKey => 0,
        MessageKind::Normal => 1,
    };
    ParsedMessage::parse(type_tag, bytes)
}

pub(crate) fn inbound_from_plaintext(
    plaintext: Zeroizing<Vec<u8>>,
    metadata: OlmPublicMetadata,
) -> InboundMessage {
    InboundMessage { plaintext, metadata }
}

pub(crate) fn confirmation_from_plaintext(
    plaintext: Zeroizing<Vec<u8>>,
    metadata: OlmPublicMetadata,
) -> SessionAuthenticatedMessage {
    SessionAuthenticatedMessage { plaintext, metadata }
}

#[allow(dead_code)]
fn _provider_types_are_publicly_parseable(_: &Message, _: &PreKeyMessage) {}
