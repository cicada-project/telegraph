//! Narrow Telegraph adapter for the fixed classical Olm v1 profile.
//!
//! This crate deliberately exposes only the public vodozemac account/session
//! contract.  It does not expose library-internal ratchet material, a root
//! key, custom DH operations, or a replacement protocol.  The selected
//! provider is vodozemac 0.10.0 at immutable release commit
//! `bb39ec65357989f975e0d47f9fb35e0656180151` (Apache-2.0, Rust 1.85).  The
//! dependency is built with `default-features = false`; in particular the
//! libolm compatibility and experimental session-config features are absent.
//!
//! The implementation is a cryptographic adapter only.  It is not Signal,
//! X3DH, PQXDH, Sesame, or an E2EE/product implementation.  Pairing,
//! transcript validation, endpoint authorization, persistence ordering, and
//! transport policy belong to callers.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![deny(unused_must_use)]

mod account;
mod budget;
mod message;
mod record;

pub use account::{
    AccountStateAnchor, DeviceAccount, IdentityPublicKeys, InboundSession, MAX_TOTAL_OTKS,
    OneTimeKey, OpaqueAccountState, OpaqueSessionState, OutboundSession, PrekeySource,
    PublicSessionKeys, TrackedOneTimeKey,
};
pub use budget::{
    AuthBudgetDecision, BudgetError, INVALID_AUTH_ATTEMPT_LIMIT, INVALID_AUTH_STATE_BYTES,
    INVALID_AUTH_WINDOW_SECONDS, InvalidAuthBudget,
};
pub use message::{
    EncryptedMessage, InboundMessage, MessageKind, OlmPublicMetadata, ParsedMessage,
    SessionAuthenticatedMessage,
};
pub use record::{
    RECORD_AEAD_TAG_BYTES, RECORD_NONCE_BYTES, RecordAad, RecordEnvelope, RecordError, RecordType,
    open_account_state, open_record, open_session_state, seal_account_state, seal_record,
    seal_session_state,
};

/// The exact profile string selected by ADR 0002.
pub const PROFILE: &[u8] = b"telegraph/olm-pair/v1";
/// The only session configuration accepted by this adapter.
pub const OLM_VERSION: u8 = 1;
/// vodozemac Olm v1 uses a finite, truncated eight-byte message tag.
pub const OLM_V1_TAG_BYTES: usize = 8;
/// Maximum plaintext accepted by any Olm operation in this MVP profile.
pub const MAX_OLM_PLAINTEXT_BYTES: usize = 16_384;
/// Maximum complete Olm message accepted by this adapter.
pub const MAX_OLM_MESSAGE_BYTES: usize = 65_536;

/// Errors returned without exposing provider internals or sensitive values.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("input exceeds the bounded limit")]
    InputTooLarge,
    #[error("input has an invalid length")]
    InvalidLength,
    #[error("randomness source failed")]
    Randomness,
    #[error("one-time-key policy rejected the message")]
    OtkPolicyRejected,
    #[error("one-time key is unknown or no longer available")]
    UnknownOneTimeKey,
    #[error("fallback keys are not accepted for Telegraph channels")]
    FallbackRejected,
    #[error("the message is not an Olm v1 message")]
    UnsupportedMessageVersion,
    #[error("the message could not be decoded")]
    MessageDecode,
    #[error("the Olm session could not be created")]
    SessionCreation,
    #[error("the Olm operation failed authentication or ratchet validation")]
    OlmOperation,
    #[error("the session is quarantined")]
    Quarantined,
    #[error("authenticated decrypt failed")]
    AuthenticationFailure,
    #[error("one-time-key inventory is malformed")]
    InventoryMalformed,
    #[error("opaque provider state is malformed or unsupported")]
    OpaqueStateMalformed,
    #[error("opaque account state does not match the externally monotonic rollback anchor")]
    RollbackAnchorMismatch,
}

pub(crate) fn checked_message_bytes(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.is_empty() || bytes.len() > MAX_OLM_MESSAGE_BYTES {
        return Err(if bytes.len() > MAX_OLM_MESSAGE_BYTES {
            CryptoError::InputTooLarge
        } else {
            CryptoError::InvalidLength
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
