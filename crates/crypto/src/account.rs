#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};

use getrandom::fill as random_fill;
use sha2::{Digest, Sha256};
use vodozemac::olm::{
    Account, AccountPickle, InboundCreationResult, OlmMessage, PreKeyMessage, Session,
    SessionConfig, SessionKeys, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Curve25519SecretKey, Ed25519PublicKey, Ed25519Signature};
use zeroize::Zeroizing;

use crate::message::{
    EncryptedMessage, InboundMessage, MessageKind, OlmPublicMetadata, SessionAuthenticatedMessage,
    confirmation_from_plaintext, from_provider_message, inbound_from_plaintext, message_for_type,
};
use crate::{CryptoError, MAX_OLM_PLAINTEXT_BYTES, OLM_VERSION, PROFILE};

/// Telegraph's hard cap on simultaneously retained one-time prekeys.
pub const MAX_TOTAL_OTKS: usize = 50;
const MAX_KEY_ID_BYTES: usize = 64;
const MAX_USED_WIRE_IDS: usize = 4_096;
const MAX_INVENTORY_BYTES: usize = 16_384;
const MAX_PROVIDER_ACCOUNT_BYTES: usize = 262_144;
const MAX_PROVIDER_SESSION_BYTES: usize = 1_048_576;
#[cfg(test)]
const ACCOUNT_STATE_V2_HEADER_BYTES: usize = 4 + 1 + 4 + 4 + 2 + 32;
#[cfg(test)]
const ACCOUNT_STATE_V3_HEADER_BYTES: usize = 4 + 1 + 4 + 4 + 2 + 2 + 32;
const ACCOUNT_STATE_HEADER_BYTES: usize = 4 + 1 + 4 + 4 + 4 + 2 + 32;
const PUBLISHED_PROOF_HEADER_BYTES: usize = 4 + 1 + 8 + 32 + 32 + 1;
const PUBLISHED_PROOF_ENTRY_BYTES: usize = 16 + 1 + MAX_KEY_ID_BYTES + 32;
const PUBLISHED_PROOF_SIGNATURE_BYTES: usize = 64;
const MAX_PUBLISHED_PROOFS: usize = MAX_TOTAL_OTKS;
const MAX_SINGLE_PUBLISHED_PROOF_BYTES: usize = PUBLISHED_PROOF_HEADER_BYTES
    + MAX_TOTAL_OTKS * PUBLISHED_PROOF_ENTRY_BYTES
    + PUBLISHED_PROOF_SIGNATURE_BYTES;
const PUBLISHED_PROOF_CHAIN_HEADER_BYTES: usize = 4 + 1 + 1;
const MAX_PUBLISHED_PROOF_CHAIN_BYTES: usize = PUBLISHED_PROOF_CHAIN_HEADER_BYTES
    + MAX_PUBLISHED_PROOFS * (2 + MAX_SINGLE_PUBLISHED_PROOF_BYTES);
const MAX_ACCOUNT_STATE_BYTES: usize = ACCOUNT_STATE_HEADER_BYTES
    + MAX_PROVIDER_ACCOUNT_BYTES
    + MAX_INVENTORY_BYTES
    + MAX_PUBLISHED_PROOF_CHAIN_BYTES
    + MAX_USED_WIRE_IDS * 16;
const MAX_SESSION_STATE_BYTES: usize = 4 + 1 + 4 + MAX_PROVIDER_SESSION_BYTES;
const ACCOUNT_STATE_MAGIC: &[u8; 4] = b"T3AS";
const SESSION_STATE_MAGIC: &[u8; 4] = b"T3SS";
const ACCOUNT_STATE_VERSION: u8 = 4;
const LEGACY_ACCOUNT_STATE_V3_VERSION: u8 = 3;
const LEGACY_ACCOUNT_STATE_V2_VERSION: u8 = 2;
const SESSION_STATE_VERSION: u8 = 2;
const INVENTORY_MAGIC: &[u8; 5] = b"T3OTK";
const INVENTORY_VERSION: u8 = 1;
const PREKEY_FINGERPRINT_DOMAIN: &[u8] = b"telegraph/prekey-bundle-hash/v1";
const ACCOUNT_STATE_BINDING_DOMAIN: &[u8] = b"telegraph/account-state-binding/v4";
const LEGACY_ACCOUNT_STATE_V3_BINDING_DOMAIN: &[u8] = b"telegraph/account-state-binding/v3";
const LEGACY_ACCOUNT_STATE_V2_BINDING_DOMAIN: &[u8] = b"telegraph/account-state-binding/v2";
const PUBLISHED_PROOF_MAGIC: &[u8; 4] = b"T3PB";
const PUBLISHED_PROOF_VERSION: u8 = 1;
const PUBLISHED_PROOF_CHAIN_MAGIC: &[u8; 4] = b"T3PC";
const PUBLISHED_PROOF_CHAIN_VERSION: u8 = 1;
const PUBLISHED_PROOF_DOMAIN: &[u8] = b"telegraph/published-otk-proof/v1";
const USED_WIRE_IDS_DOMAIN: &[u8] = b"telegraph/used-wire-ids/v1";
const ACCOUNT_STATE_ANCHOR_DOMAIN: &[u8] = b"telegraph/account-state-anchor/v1";
const MAX_PROVIDER_CBOR_DEPTH: usize = 32;
const MAX_PROVIDER_CBOR_ITEMS: usize = 65_536;
const MAX_PROVIDER_CONTAINER_ITEMS: u64 = 8_192;

#[cfg(test)]
thread_local! {
    static ACCOUNT_SERDE_DESERIALIZE_CALLS: Cell<usize> = const { Cell::new(0) };
    static SESSION_SERDE_DESERIALIZE_CALLS: Cell<usize> = const { Cell::new(0) };
}

/// Public identity material of a device. Private keys remain provider-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPublicKeys {
    pub ed25519: [u8; 32],
    pub curve25519: [u8; 32],
}

/// Public metadata for one locally tracked Olm one-time key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedOneTimeKey {
    pub wire_id: [u8; 16],
    pub key_id: String,
    pub curve25519: [u8; 32],
    pub fingerprint: [u8; 32],
    pub published: bool,
}

pub type OneTimeKey = TrackedOneTimeKey;

#[derive(Clone, PartialEq, Eq)]
struct PublishedProofEntry {
    wire_id: [u8; 16],
    key_id: String,
    curve25519: [u8; 32],
}

/// One signed snapshot in the bounded proof chain. The complete chain is
/// retained so sequence/link truncation, reordering, insertion, and forks fail
/// closed within one otherwise-current opaque state.
#[derive(Clone)]
struct PublishedBatchProof {
    sequence: u64,
    previous_digest: [u8; 32],
    used_wire_ids_digest: [u8; 32],
    entries: Vec<PublishedProofEntry>,
    signature: [u8; PUBLISHED_PROOF_SIGNATURE_BYTES],
}

/// Relay/prekey inventory classification supplied by the pairing state.
/// Classification is checked before provider session creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrekeySource {
    OneTime([u8; 16]),
    Fallback,
    Unknown,
}

/// Adapter-owned sensitive account state. Its bytes and provider pickle type
/// are intentionally private; storage can only pass it through the dedicated
/// record-AEAD functions.
pub struct OpaqueAccountState(Zeroizing<Vec<u8>>);

/// Domain-separated digest that T3b must persist in a monotonic rollback
/// domain separate from the opaque record itself.
///
/// A complete replay of an older authentic opaque record includes a valid
/// provider pickle and valid proof chain, so cryptographic core validation
/// alone cannot distinguish it from the historical state. T3b must compare
/// this anchor against its externally monotonic current value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountStateAnchor([u8; 32]);

impl AccountStateAnchor {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl OpaqueAccountState {
    pub(crate) fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if bytes.is_empty() || bytes.len() > MAX_ACCOUNT_STATE_BYTES {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn rollback_anchor(&self) -> AccountStateAnchor {
        let mut hasher = Sha256::new();
        hasher.update(ACCOUNT_STATE_ANCHOR_DOMAIN);
        hasher.update(&self.0);
        AccountStateAnchor(hasher.finalize().into())
    }
}

/// Adapter-owned sensitive session state. No provider pickle is exposed.
pub struct OpaqueSessionState(Zeroizing<Vec<u8>>);

impl OpaqueSessionState {
    pub(crate) fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if bytes.is_empty() || bytes.len() > MAX_SESSION_STATE_BYTES {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One device-level provider account and its inseparable public OTK inventory.
pub struct DeviceAccount {
    account: Account,
    inventory: BTreeMap<[u8; 16], TrackedOneTimeKey>,
    used_wire_ids: HashSet<[u8; 16]>,
    published_proofs: Vec<PublishedBatchProof>,
}

impl Default for DeviceAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceAccount {
    pub fn new() -> Self {
        Self {
            account: Account::new(),
            inventory: BTreeMap::new(),
            used_wire_ids: HashSet::new(),
            published_proofs: Vec::new(),
        }
    }

    pub fn identity_public_keys(&self) -> IdentityPublicKeys {
        let keys = self.account.identity_keys();
        IdentityPublicKeys {
            ed25519: *keys.ed25519.as_bytes(),
            curve25519: keys.curve25519.to_bytes(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.account.sign(message).to_bytes()
    }

    pub fn max_one_time_keys(&self) -> usize {
        MAX_TOTAL_OTKS.min(self.account.max_number_of_one_time_keys())
    }

    /// Generate without allowing the provider's eviction behavior to replace
    /// an older tracked key. Repeated calls share the same total budget.
    pub fn generate_one_time_keys(
        &mut self,
        count: usize,
    ) -> Result<Vec<TrackedOneTimeKey>, CryptoError> {
        if count == 0 {
            return Err(CryptoError::InvalidLength);
        }
        let total = self
            .account
            .stored_one_time_key_count()
            .checked_add(count)
            .ok_or(CryptoError::InputTooLarge)?;
        if count > MAX_TOTAL_OTKS || total > self.max_one_time_keys() {
            return Err(CryptoError::InputTooLarge);
        }
        if self.used_wire_ids.len().checked_add(count).is_none_or(|n| n > MAX_USED_WIRE_IDS) {
            return Err(CryptoError::InputTooLarge);
        }
        validate_published_proof_chain(
            &self.account,
            self.inventory.values(),
            &self.used_wire_ids,
            &self.published_proofs,
        )?;

        // Obtain every random wire identifier before mutating provider state.
        let wire_ids = self.fresh_wire_ids(count)?;
        let mut candidate_account = Account::from_pickle(self.account.pickle());
        let generated = candidate_account.generate_one_time_keys(count);
        if !generated.removed.is_empty() {
            return Err(CryptoError::InventoryMalformed);
        }

        let mut new_keys: Vec<_> = candidate_account
            .one_time_keys()
            .into_iter()
            .filter(|(_, public_key)| {
                !self.inventory.values().any(|entry| entry.curve25519 == public_key.to_bytes())
            })
            .collect();
        new_keys.sort_by_key(|(key_id, _)| key_id.to_base64());
        if new_keys.len() != count {
            return Err(CryptoError::InventoryMalformed);
        }
        let mut candidate_inventory = self.inventory.clone();
        let mut candidate_used = self.used_wire_ids.clone();
        let mut generated_batch = Vec::new();
        generated_batch.try_reserve_exact(count).map_err(|_| CryptoError::InputTooLarge)?;
        for ((key_id, public_key), wire_id) in new_keys.into_iter().zip(wire_ids) {
            candidate_used.insert(wire_id);
            let entry = TrackedOneTimeKey {
                wire_id,
                key_id: key_id.to_base64(),
                curve25519: public_key.to_bytes(),
                fingerprint: fingerprint_for(public_key.to_bytes()),
                published: false,
            };
            generated_batch.push(entry.clone());
            candidate_inventory.insert(wire_id, entry);
        }
        validate_account_inventory(&candidate_account, candidate_inventory.values())?;
        let candidate_proofs = next_published_proof_chain(
            &candidate_account,
            candidate_inventory.values(),
            &candidate_used,
            &self.published_proofs,
        )?;
        validate_published_proof_chain(
            &candidate_account,
            candidate_inventory.values(),
            &candidate_used,
            &candidate_proofs,
        )?;
        self.account = candidate_account;
        self.inventory = candidate_inventory;
        self.used_wire_ids = candidate_used;
        self.published_proofs = candidate_proofs;
        generated_batch.sort_by_key(|entry| entry.wire_id);
        Ok(generated_batch)
    }

    pub fn one_time_key_inventory(&self) -> Vec<TrackedOneTimeKey> {
        self.inventory.values().cloned().collect()
    }

    pub fn unpublished_one_time_keys(&self) -> Vec<TrackedOneTimeKey> {
        self.inventory.values().filter(|entry| !entry.published).cloned().collect()
    }

    /// The provider and every mapping are mutated together; callers cannot
    /// provide their own published mapping during restore.
    pub fn publish_one_time_keys(&mut self) -> Result<Vec<TrackedOneTimeKey>, CryptoError> {
        validate_account_inventory(&self.account, self.inventory.values())?;
        validate_published_proof_chain(
            &self.account,
            self.inventory.values(),
            &self.used_wire_ids,
            &self.published_proofs,
        )?;
        if self.inventory.values().all(|entry| entry.published) {
            return Ok(self.one_time_key_inventory());
        }

        // Validate the exact provider mapping while unpublished provider keys
        // are still publicly enumerable. Only then mark a cloned provider and
        // construct a signed snapshot of the resulting published inventory.
        let mut candidate_account = Account::from_pickle(self.account.pickle());
        let mut candidate_inventory = self.inventory.clone();
        candidate_account.mark_keys_as_published();
        for entry in candidate_inventory.values_mut() {
            entry.published = true;
        }
        let candidate_proofs = next_published_proof_chain(
            &candidate_account,
            candidate_inventory.values(),
            &self.used_wire_ids,
            &self.published_proofs,
        )?;
        validate_account_inventory(&candidate_account, candidate_inventory.values())?;
        validate_published_proof_chain(
            &candidate_account,
            candidate_inventory.values(),
            &self.used_wire_ids,
            &candidate_proofs,
        )?;
        self.account = candidate_account;
        self.inventory = candidate_inventory;
        self.published_proofs = candidate_proofs;
        Ok(self.one_time_key_inventory())
    }

    /// Internal seam only. A future public constructor must accept a typed,
    /// verified prekey bundle after the client/profile gate is implemented.
    #[cfg(test)]
    pub(crate) fn create_outbound_session(
        &self,
        peer_identity_curve25519: [u8; 32],
        peer_one_time_curve25519: [u8; 32],
    ) -> Result<OutboundSession, CryptoError> {
        let identity = Curve25519PublicKey::from_bytes(peer_identity_curve25519);
        let one_time = Curve25519PublicKey::from_bytes(peer_one_time_curve25519);
        let session = self
            .account
            .create_outbound_session(SessionConfig::version_1(), identity, one_time)
            .map_err(|_| CryptoError::SessionCreation)?;
        ensure_v1(&session)?;
        Ok(OutboundSession { session })
    }

    /// Accept only a specifically tracked, published one-time key. Fallback
    /// and unknown classifications remain distinct fail-closed outcomes.
    pub fn create_inbound_session(
        &mut self,
        peer_identity_curve25519: [u8; 32],
        message: &EncryptedMessage,
        source: PrekeySource,
    ) -> Result<(InboundSession, InboundMessage), CryptoError> {
        let expected_wire_id = match source {
            PrekeySource::OneTime(wire_id) => wire_id,
            PrekeySource::Fallback => return Err(CryptoError::FallbackRejected),
            PrekeySource::Unknown => return Err(CryptoError::UnknownOneTimeKey),
        };
        if message.kind() != MessageKind::PreKey {
            return Err(CryptoError::OtkPolicyRejected);
        }
        let parsed = message_for_type(message.kind(), message.as_bytes())?;
        let prekey = match parsed.provider_message() {
            OlmMessage::PreKey(prekey) => prekey,
            OlmMessage::Normal(_) => return Err(CryptoError::OtkPolicyRejected),
        };
        let entry =
            self.inventory.get(&expected_wire_id).ok_or(CryptoError::UnknownOneTimeKey)?.clone();
        if !entry.published || prekey.one_time_key().to_bytes() != entry.curve25519 {
            return Err(CryptoError::OtkPolicyRejected);
        }
        validate_published_proof_chain(
            &self.account,
            self.inventory.values(),
            &self.used_wire_ids,
            &self.published_proofs,
        )?;

        let identity = Curve25519PublicKey::from_bytes(peer_identity_curve25519);
        let mut candidate_account = Account::from_pickle(self.account.pickle());
        let InboundCreationResult { session, plaintext } = candidate_account
            .create_inbound_session(SessionConfig::version_1(), identity, prekey)
            .map_err(|_| CryptoError::OlmOperation)?;
        let plaintext = Zeroizing::new(plaintext);
        if plaintext.len() > MAX_OLM_PLAINTEXT_BYTES {
            return Err(CryptoError::InputTooLarge);
        }
        ensure_v1(&session)?;
        let mut candidate_inventory = self.inventory.clone();
        candidate_inventory.remove(&expected_wire_id);
        let candidate_proofs = next_published_proof_chain(
            &candidate_account,
            candidate_inventory.values(),
            &self.used_wire_ids,
            &self.published_proofs,
        )?;
        validate_account_inventory(&candidate_account, candidate_inventory.values())?;
        validate_published_proof_chain(
            &candidate_account,
            candidate_inventory.values(),
            &self.used_wire_ids,
            &candidate_proofs,
        )?;
        self.account = candidate_account;
        self.inventory = candidate_inventory;
        self.published_proofs = candidate_proofs;
        let metadata = parsed.metadata();
        Ok((InboundSession { session }, inbound_from_plaintext(plaintext, metadata)))
    }

    /// Serialize the provider pickle and complete inventory into one versioned
    /// opaque object. Serde is provider-internal storage only, never wire CBOR.
    pub fn export_state(&self) -> Result<OpaqueAccountState, CryptoError> {
        self.export_state_inner(true)
    }

    fn export_state_inner(
        &self,
        require_no_fallback: bool,
    ) -> Result<OpaqueAccountState, CryptoError> {
        validate_account_inventory(&self.account, self.inventory.values())?;
        validate_published_proof_chain(
            &self.account,
            self.inventory.values(),
            &self.used_wire_ids,
            &self.published_proofs,
        )?;
        let provider = serialize_account_pickle(&self.account.pickle())?;
        scan_provider_cbor(&provider, MAX_PROVIDER_ACCOUNT_BYTES)?;
        if require_no_fallback {
            validate_account_provider_has_no_fallback(&provider)?;
        }
        let inventory = encode_inventory(self.inventory.values())?;
        let proofs = encode_published_proof_chain(&self.published_proofs)?;
        let mut used: Vec<_> = self.used_wire_ids.iter().copied().collect();
        used.sort_unstable();
        if used.len() > MAX_USED_WIRE_IDS {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        build_account_state(&provider, &inventory, &proofs, &used)
    }

    pub fn from_state(state: OpaqueAccountState) -> Result<Self, CryptoError> {
        let mut cursor = Cursor::new(state.as_bytes());
        if cursor.take(4)? != ACCOUNT_STATE_MAGIC {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let version = cursor.byte()?;
        let provider_len = cursor.u32()? as usize;
        let inventory_len = cursor.u32()? as usize;
        if provider_len == 0
            || provider_len > MAX_PROVIDER_ACCOUNT_BYTES
            || inventory_len == 0
            || inventory_len > MAX_INVENTORY_BYTES
        {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let (proof_len, used_count) = match version {
            ACCOUNT_STATE_VERSION => (cursor.u32()? as usize, cursor.u16()? as usize),
            LEGACY_ACCOUNT_STATE_V3_VERSION => (cursor.u16()? as usize, cursor.u16()? as usize),
            LEGACY_ACCOUNT_STATE_V2_VERSION => (0, cursor.u16()? as usize),
            _ => return Err(CryptoError::OpaqueStateMalformed),
        };
        let proof_limit = if version == ACCOUNT_STATE_VERSION {
            MAX_PUBLISHED_PROOF_CHAIN_BYTES
        } else {
            MAX_SINGLE_PUBLISHED_PROOF_BYTES
        };
        if proof_len > proof_limit || used_count > MAX_USED_WIRE_IDS {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let expected_binding = cursor.array::<32>()?;
        let provider_bytes = cursor.take(provider_len)?;
        let inventory_bytes = cursor.take(inventory_len)?;
        let proof_bytes = cursor.take(proof_len)?;
        let used_bytes =
            cursor.take(used_count.checked_mul(16).ok_or(CryptoError::OpaqueStateMalformed)?)?;
        if !cursor.is_empty() {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let actual_binding = match version {
            ACCOUNT_STATE_VERSION => account_state_binding_from_bytes(
                provider_bytes,
                inventory_bytes,
                proof_bytes,
                used_count,
                used_bytes,
            )?,
            LEGACY_ACCOUNT_STATE_V3_VERSION => legacy_v3_account_state_binding_from_bytes(
                provider_bytes,
                inventory_bytes,
                proof_bytes,
                used_count,
                used_bytes,
            )?,
            LEGACY_ACCOUNT_STATE_V2_VERSION => legacy_v2_account_state_binding_from_bytes(
                provider_bytes,
                inventory_bytes,
                used_count,
                used_bytes,
            )?,
            _ => unreachable!("version checked above"),
        };
        if actual_binding != expected_binding {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let inventory = decode_inventory(inventory_bytes)?;
        if version != ACCOUNT_STATE_VERSION
            && (!inventory.is_empty() || !proof_bytes.is_empty() || used_count != 0)
        {
            // v2 has no proof and v3 retains only one latest proof. Neither
            // format proves the complete chain/provider mapping required by
            // v4. Only a never-used empty provider account can migrate.
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let published_proofs = if proof_bytes.is_empty() {
            Vec::new()
        } else {
            decode_published_proof_chain(proof_bytes)?
        };
        let mut used_wire_ids = HashSet::with_capacity(used_count);
        let mut used_cursor = Cursor::new(used_bytes);
        let mut previous = None;
        for _ in 0..used_count {
            let wire_id = used_cursor.array::<16>()?;
            if previous.is_some_and(|old| old >= wire_id) || !used_wire_ids.insert(wire_id) {
                return Err(CryptoError::OpaqueStateMalformed);
            }
            previous = Some(wire_id);
        }
        if !used_cursor.is_empty()
            || inventory.iter().any(|entry| !used_wire_ids.contains(&entry.wire_id))
        {
            return Err(CryptoError::OpaqueStateMalformed);
        }

        validate_account_provider_has_no_fallback(provider_bytes)?;
        validate_provider_inventory(provider_bytes, &inventory.iter().collect::<Vec<_>>())?;
        let pickle = deserialize_account_pickle(provider_bytes)?;
        let account = Account::from_pickle(pickle);
        validate_account_inventory(&account, inventory.iter())?;
        validate_published_proof_chain(
            &account,
            inventory.iter(),
            &used_wire_ids,
            &published_proofs,
        )?;
        let inventory = inventory.into_iter().map(|entry| (entry.wire_id, entry)).collect();
        Ok(Self { account, inventory, used_wire_ids, published_proofs })
    }

    /// Restore only when T3b's externally monotonic anchor matches this exact
    /// opaque state. `from_state` alone intentionally cannot detect a replay of
    /// a complete older authentic record and valid proof chain.
    pub fn from_state_with_anchor(
        state: OpaqueAccountState,
        expected_anchor: AccountStateAnchor,
    ) -> Result<Self, CryptoError> {
        if state.rollback_anchor() != expected_anchor {
            return Err(CryptoError::RollbackAnchorMismatch);
        }
        Self::from_state(state)
    }

    #[cfg(test)]
    pub(crate) fn export_state_with_fallback_for_test(
        &self,
    ) -> Result<OpaqueAccountState, CryptoError> {
        self.export_state_inner(false)
    }

    fn fresh_wire_ids(&self, count: usize) -> Result<Vec<[u8; 16]>, CryptoError> {
        let mut fresh = HashSet::with_capacity(count);
        for _ in 0..count {
            let mut accepted = false;
            for _ in 0..16 {
                let mut wire_id = [0u8; 16];
                random_fill(&mut wire_id).map_err(|_| CryptoError::Randomness)?;
                if !self.used_wire_ids.contains(&wire_id) && fresh.insert(wire_id) {
                    accepted = true;
                    break;
                }
            }
            if !accepted {
                return Err(CryptoError::Randomness);
            }
        }
        Ok(fresh.into_iter().collect())
    }

    #[cfg(test)]
    pub(crate) fn generate_fallback_for_test(&mut self, published: bool) -> [u8; 32] {
        self.account.generate_fallback_key();
        let public =
            self.account.fallback_key().into_values().next().expect("test fallback key").to_bytes();
        if published {
            self.account.mark_keys_as_published();
        }
        public
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSessionKeys {
    pub identity_curve25519: [u8; 32],
    pub base_curve25519: [u8; 32],
    pub one_time_curve25519: [u8; 32],
}

pub struct OutboundSession {
    session: Session,
}

pub struct InboundSession {
    session: Session,
}

macro_rules! impl_session {
    ($session:ty) => {
        impl $session {
            pub fn session_id(&self) -> String {
                self.session.session_id()
            }

            pub fn session_keys(&self) -> PublicSessionKeys {
                public_session_keys(self.session.session_keys())
            }

            pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage, CryptoError> {
                if plaintext.len() > MAX_OLM_PLAINTEXT_BYTES {
                    return Err(CryptoError::InputTooLarge);
                }
                let mut candidate = Session::from_pickle(self.session.pickle());
                let message =
                    candidate.encrypt(plaintext).map_err(|_| CryptoError::OlmOperation)?;
                let encrypted = from_provider_message(message)?;
                self.session = candidate;
                Ok(encrypted)
            }

            pub fn encrypt_confirmation(
                &mut self,
                inner_opaque_bytes: &[u8],
            ) -> Result<EncryptedMessage, CryptoError> {
                self.encrypt(inner_opaque_bytes)
            }

            pub fn decrypt(
                &mut self,
                message: &EncryptedMessage,
            ) -> Result<InboundMessage, CryptoError> {
                let parsed = message_for_type(message.kind(), message.as_bytes())?;
                let mut candidate = Session::from_pickle(self.session.pickle());
                let plaintext = candidate
                    .decrypt(parsed.provider_message())
                    .map_err(|_| CryptoError::AuthenticationFailure)?;
                let plaintext = Zeroizing::new(plaintext);
                if plaintext.len() > MAX_OLM_PLAINTEXT_BYTES {
                    return Err(CryptoError::InputTooLarge);
                }
                self.session = candidate;
                Ok(inbound_from_plaintext(plaintext, parsed.metadata()))
            }

            pub fn decrypt_confirmation(
                &mut self,
                message: &EncryptedMessage,
            ) -> Result<SessionAuthenticatedMessage, CryptoError> {
                let parsed = message_for_type(message.kind(), message.as_bytes())?;
                let mut candidate = Session::from_pickle(self.session.pickle());
                let plaintext = candidate
                    .decrypt(parsed.provider_message())
                    .map_err(|_| CryptoError::AuthenticationFailure)?;
                let plaintext = Zeroizing::new(plaintext);
                if plaintext.len() > MAX_OLM_PLAINTEXT_BYTES {
                    return Err(CryptoError::InputTooLarge);
                }
                self.session = candidate;
                Ok(confirmation_from_plaintext(plaintext, parsed.metadata()))
            }

            pub fn export_state(&self) -> Result<OpaqueSessionState, CryptoError> {
                serialize_session_state(&self.session)
            }

            pub fn from_state(state: OpaqueSessionState) -> Result<Self, CryptoError> {
                let session = deserialize_session_state(state)?;
                ensure_v1(&session)?;
                Ok(Self { session })
            }
        }
    };
}

impl_session!(OutboundSession);
impl_session!(InboundSession);

#[cfg(test)]
impl OutboundSession {
    /// Test-only reachability seam: ask the fixed provider to create a valid
    /// message above Telegraph's plaintext policy limit. Production callers
    /// cannot bypass `encrypt`'s preflight.
    pub(crate) fn encrypt_unbounded_for_test(
        &mut self,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage, CryptoError> {
        let mut candidate = Session::from_pickle(self.session.pickle());
        let message = candidate.encrypt(plaintext).map_err(|_| CryptoError::OlmOperation)?;
        let encrypted = from_provider_message(message)?;
        self.session = candidate;
        Ok(encrypted)
    }
}

fn serialize_session_state(session: &Session) -> Result<OpaqueSessionState, CryptoError> {
    let provider = serialize_session_pickle(&session.pickle())?;
    let capacity = 9usize
        .checked_add(provider.len())
        .filter(|n| *n <= MAX_SESSION_STATE_BYTES)
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(capacity).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(SESSION_STATE_MAGIC);
    out.push(SESSION_STATE_VERSION);
    out.extend_from_slice(
        &u32::try_from(provider.len())
            .map_err(|_| CryptoError::OpaqueStateMalformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(&provider);
    OpaqueSessionState::from_bytes(out)
}

fn deserialize_session_state(state: OpaqueSessionState) -> Result<Session, CryptoError> {
    let mut cursor = Cursor::new(state.as_bytes());
    if cursor.take(4)? != SESSION_STATE_MAGIC || cursor.byte()? != SESSION_STATE_VERSION {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let provider_len = cursor.u32()? as usize;
    if provider_len == 0 || provider_len > MAX_PROVIDER_SESSION_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let pickle = deserialize_session_pickle(cursor.take(provider_len)?)?;
    if !cursor.is_empty() {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(Session::from_pickle(pickle))
}

/// A structural checksum binds the exact provider bytes, complete inventory,
/// and durable wire-id history inside one versioned opaque object. It is not
/// an authenticator: authenticity comes from the dedicated storage-record
/// AEAD, whose public API never exposes these bytes. The checksum makes an
/// accidental or internal cross-record mix fail before provider restore.
fn account_state_binding(
    provider: &[u8],
    inventory: &[u8],
    proof: &[u8],
    used: &[[u8; 16]],
) -> Result<[u8; 32], CryptoError> {
    let mut used_bytes = Zeroizing::new(Vec::new());
    used_bytes
        .try_reserve_exact(used.len().checked_mul(16).ok_or(CryptoError::OpaqueStateMalformed)?)
        .map_err(|_| CryptoError::OpaqueStateMalformed)?;
    for wire_id in used {
        used_bytes.extend_from_slice(wire_id);
    }
    account_state_binding_from_bytes(provider, inventory, proof, used.len(), &used_bytes)
}

fn build_account_state(
    provider: &[u8],
    inventory: &[u8],
    proofs: &[u8],
    used: &[[u8; 16]],
) -> Result<OpaqueAccountState, CryptoError> {
    let capacity = ACCOUNT_STATE_HEADER_BYTES
        .checked_add(provider.len())
        .and_then(|n| n.checked_add(inventory.len()))
        .and_then(|n| n.checked_add(proofs.len()))
        .and_then(|n| n.checked_add(used.len().checked_mul(16)?))
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    if capacity > MAX_ACCOUNT_STATE_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let provider_len =
        u32::try_from(provider.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let inventory_len =
        u32::try_from(inventory.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let proof_len = u32::try_from(proofs.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    if proofs.len() > MAX_PUBLISHED_PROOF_CHAIN_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let used_count = u16::try_from(used.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let binding = account_state_binding(provider, inventory, proofs, used)?;
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(capacity).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(ACCOUNT_STATE_MAGIC);
    out.push(ACCOUNT_STATE_VERSION);
    out.extend_from_slice(&provider_len.to_be_bytes());
    out.extend_from_slice(&inventory_len.to_be_bytes());
    out.extend_from_slice(&proof_len.to_be_bytes());
    out.extend_from_slice(&used_count.to_be_bytes());
    out.extend_from_slice(&binding);
    out.extend_from_slice(provider);
    out.extend_from_slice(inventory);
    out.extend_from_slice(proofs);
    for wire_id in used {
        out.extend_from_slice(wire_id);
    }
    OpaqueAccountState::from_bytes(out)
}

#[cfg(test)]
pub(crate) fn rebuild_account_state_for_test(
    provider: &[u8],
    inventory: &[u8],
    proof: &[u8],
    used: &[[u8; 16]],
) -> Result<OpaqueAccountState, CryptoError> {
    build_account_state(provider, inventory, proof, used)
}

fn account_state_binding_from_bytes(
    provider: &[u8],
    inventory: &[u8],
    proof: &[u8],
    used_count: usize,
    used_bytes: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if used_bytes.len() != used_count.checked_mul(16).ok_or(CryptoError::OpaqueStateMalformed)? {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let provider_len =
        u32::try_from(provider.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let inventory_len =
        u32::try_from(inventory.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let proof_len = u32::try_from(proof.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let used_count = u16::try_from(used_count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let mut hasher = Sha256::new();
    hasher.update(ACCOUNT_STATE_BINDING_DOMAIN);
    hasher.update([ACCOUNT_STATE_VERSION]);
    hasher.update(provider_len.to_be_bytes());
    hasher.update(inventory_len.to_be_bytes());
    hasher.update(proof_len.to_be_bytes());
    hasher.update(used_count.to_be_bytes());
    hasher.update(provider);
    hasher.update(inventory);
    hasher.update(proof);
    hasher.update(used_bytes);
    Ok(hasher.finalize().into())
}

fn legacy_v3_account_state_binding_from_bytes(
    provider: &[u8],
    inventory: &[u8],
    proof: &[u8],
    used_count: usize,
    used_bytes: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if used_bytes.len() != used_count.checked_mul(16).ok_or(CryptoError::OpaqueStateMalformed)? {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let provider_len =
        u32::try_from(provider.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let inventory_len =
        u32::try_from(inventory.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let proof_len = u16::try_from(proof.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let used_count = u16::try_from(used_count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_ACCOUNT_STATE_V3_BINDING_DOMAIN);
    hasher.update([LEGACY_ACCOUNT_STATE_V3_VERSION]);
    hasher.update(provider_len.to_be_bytes());
    hasher.update(inventory_len.to_be_bytes());
    hasher.update(proof_len.to_be_bytes());
    hasher.update(used_count.to_be_bytes());
    hasher.update(provider);
    hasher.update(inventory);
    hasher.update(proof);
    hasher.update(used_bytes);
    Ok(hasher.finalize().into())
}

fn legacy_v2_account_state_binding_from_bytes(
    provider: &[u8],
    inventory: &[u8],
    used_count: usize,
    used_bytes: &[u8],
) -> Result<[u8; 32], CryptoError> {
    if used_bytes.len() != used_count.checked_mul(16).ok_or(CryptoError::OpaqueStateMalformed)? {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let provider_len =
        u32::try_from(provider.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let inventory_len =
        u32::try_from(inventory.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let used_count = u16::try_from(used_count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let mut hasher = Sha256::new();
    hasher.update(LEGACY_ACCOUNT_STATE_V2_BINDING_DOMAIN);
    hasher.update([LEGACY_ACCOUNT_STATE_V2_VERSION]);
    hasher.update(provider_len.to_be_bytes());
    hasher.update(inventory_len.to_be_bytes());
    hasher.update(used_count.to_be_bytes());
    hasher.update(provider);
    hasher.update(inventory);
    hasher.update(used_bytes);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(crate) fn rebuild_legacy_account_state_for_test(
    provider: &[u8],
    inventory: &[u8],
    used: &[[u8; 16]],
) -> Result<OpaqueAccountState, CryptoError> {
    let mut used_bytes = Zeroizing::new(Vec::new());
    for wire_id in used {
        used_bytes.extend_from_slice(wire_id);
    }
    let binding =
        legacy_v2_account_state_binding_from_bytes(provider, inventory, used.len(), &used_bytes)?;
    let capacity = ACCOUNT_STATE_V2_HEADER_BYTES
        .checked_add(provider.len())
        .and_then(|n| n.checked_add(inventory.len()))
        .and_then(|n| n.checked_add(used_bytes.len()))
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(capacity).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(ACCOUNT_STATE_MAGIC);
    out.push(LEGACY_ACCOUNT_STATE_V2_VERSION);
    out.extend_from_slice(
        &u32::try_from(provider.len())
            .map_err(|_| CryptoError::OpaqueStateMalformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(inventory.len())
            .map_err(|_| CryptoError::OpaqueStateMalformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(used.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?.to_be_bytes(),
    );
    out.extend_from_slice(&binding);
    out.extend_from_slice(provider);
    out.extend_from_slice(inventory);
    out.extend_from_slice(&used_bytes);
    OpaqueAccountState::from_bytes(out)
}

#[cfg(test)]
pub(crate) fn rebuild_legacy_v3_account_state_for_test(
    provider: &[u8],
    inventory: &[u8],
    proof: &[u8],
    used: &[[u8; 16]],
) -> Result<OpaqueAccountState, CryptoError> {
    if proof.len() > MAX_SINGLE_PUBLISHED_PROOF_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut used_bytes = Zeroizing::new(Vec::new());
    for wire_id in used {
        used_bytes.extend_from_slice(wire_id);
    }
    let binding = legacy_v3_account_state_binding_from_bytes(
        provider,
        inventory,
        proof,
        used.len(),
        &used_bytes,
    )?;
    let capacity = ACCOUNT_STATE_V3_HEADER_BYTES
        .checked_add(provider.len())
        .and_then(|n| n.checked_add(inventory.len()))
        .and_then(|n| n.checked_add(proof.len()))
        .and_then(|n| n.checked_add(used_bytes.len()))
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(capacity).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(ACCOUNT_STATE_MAGIC);
    out.push(LEGACY_ACCOUNT_STATE_V3_VERSION);
    out.extend_from_slice(
        &u32::try_from(provider.len())
            .map_err(|_| CryptoError::OpaqueStateMalformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u32::try_from(inventory.len())
            .map_err(|_| CryptoError::OpaqueStateMalformed)?
            .to_be_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(proof.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?.to_be_bytes(),
    );
    out.extend_from_slice(
        &u16::try_from(used.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?.to_be_bytes(),
    );
    out.extend_from_slice(&binding);
    out.extend_from_slice(provider);
    out.extend_from_slice(inventory);
    out.extend_from_slice(proof);
    out.extend_from_slice(&used_bytes);
    OpaqueAccountState::from_bytes(out)
}

fn serialize_account_pickle(pickle: &AccountPickle) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let bytes = Zeroizing::new(
        cbor4ii::serde::to_vec(Vec::new(), pickle)
            .map_err(|_| CryptoError::OpaqueStateMalformed)?,
    );
    if bytes.is_empty() || bytes.len() > MAX_PROVIDER_ACCOUNT_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    scan_provider_cbor(&bytes, MAX_PROVIDER_ACCOUNT_BYTES)?;
    Ok(bytes)
}

fn deserialize_account_pickle(bytes: &[u8]) -> Result<AccountPickle, CryptoError> {
    parse_account_provider_otks(bytes, true)?;
    #[cfg(test)]
    ACCOUNT_SERDE_DESERIALIZE_CALLS.set(ACCOUNT_SERDE_DESERIALIZE_CALLS.get() + 1);
    let pickle: AccountPickle =
        cbor4ii::serde::from_slice(bytes).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let canonical = serialize_account_pickle(&pickle)?;
    if canonical.as_slice() != bytes {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(pickle)
}

fn serialize_session_pickle(pickle: &SessionPickle) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let bytes = Zeroizing::new(
        cbor4ii::serde::to_vec(Vec::new(), pickle)
            .map_err(|_| CryptoError::OpaqueStateMalformed)?,
    );
    if bytes.is_empty() || bytes.len() > MAX_PROVIDER_SESSION_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    scan_provider_cbor(&bytes, MAX_PROVIDER_SESSION_BYTES)?;
    Ok(bytes)
}

fn deserialize_session_pickle(bytes: &[u8]) -> Result<SessionPickle, CryptoError> {
    scan_provider_cbor(bytes, MAX_PROVIDER_SESSION_BYTES)?;
    #[cfg(test)]
    SESSION_SERDE_DESERIALIZE_CALLS.set(SESSION_SERDE_DESERIALIZE_CALLS.get() + 1);
    let pickle: SessionPickle =
        cbor4ii::serde::from_slice(bytes).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let canonical = serialize_session_pickle(&pickle)?;
    if canonical.as_slice() != bytes {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(pickle)
}

/// Strict, allocation-free CBOR preflight used before Serde can observe a
/// provider pickle. It rejects tags, floats, every simple value except
/// false/true/null, indefinite forms, non-shortest arguments, excessive
/// nesting/items/container lengths, invalid UTF-8, and trailing data. Bounds
/// are intentionally tighter than the outer byte cap.
fn scan_provider_cbor(bytes: &[u8], max_bytes: usize) -> Result<(), CryptoError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut cursor = 0;
    let mut items = 0;
    scan_cbor_item(bytes, &mut cursor, 0, &mut items)?;
    if cursor != bytes.len() {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn scan_account_provider_cbor_for_test(bytes: &[u8]) -> Result<(), CryptoError> {
    scan_provider_cbor(bytes, MAX_PROVIDER_ACCOUNT_BYTES)
}

#[cfg(test)]
pub(crate) fn scan_session_provider_cbor_for_test(bytes: &[u8]) -> Result<(), CryptoError> {
    scan_provider_cbor(bytes, MAX_PROVIDER_SESSION_BYTES)
}

#[cfg(test)]
pub(crate) fn reset_serde_deserialize_counts_for_test() {
    ACCOUNT_SERDE_DESERIALIZE_CALLS.set(0);
    SESSION_SERDE_DESERIALIZE_CALLS.set(0);
}

#[cfg(test)]
pub(crate) fn serde_deserialize_counts_for_test() -> (usize, usize) {
    (ACCOUNT_SERDE_DESERIALIZE_CALLS.get(), SESSION_SERDE_DESERIALIZE_CALLS.get())
}

#[cfg(test)]
pub(crate) fn deserialize_account_pickle_for_test(bytes: &[u8]) -> Result<(), CryptoError> {
    deserialize_account_pickle(bytes).map(drop)
}

#[cfg(test)]
pub(crate) fn deserialize_session_pickle_for_test(bytes: &[u8]) -> Result<(), CryptoError> {
    deserialize_session_pickle(bytes).map(drop)
}

fn scan_cbor_item(
    bytes: &[u8],
    cursor: &mut usize,
    depth: usize,
    items: &mut usize,
) -> Result<(), CryptoError> {
    if depth > MAX_PROVIDER_CBOR_DEPTH {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    *items = items.checked_add(1).ok_or(CryptoError::OpaqueStateMalformed)?;
    if *items > MAX_PROVIDER_CBOR_ITEMS {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let (major, additional, argument) = read_cbor_head(bytes, cursor)?;
    match major {
        0 | 1 => Ok(()),
        2 | 3 => {
            let length =
                usize::try_from(argument).map_err(|_| CryptoError::OpaqueStateMalformed)?;
            let end = cursor.checked_add(length).ok_or(CryptoError::OpaqueStateMalformed)?;
            let value = bytes.get(*cursor..end).ok_or(CryptoError::OpaqueStateMalformed)?;
            if major == 3 && std::str::from_utf8(value).is_err() {
                return Err(CryptoError::OpaqueStateMalformed);
            }
            *cursor = end;
            Ok(())
        }
        4 => {
            if argument > MAX_PROVIDER_CONTAINER_ITEMS {
                return Err(CryptoError::OpaqueStateMalformed);
            }
            for _ in 0..argument {
                scan_cbor_item(bytes, cursor, depth + 1, items)?;
            }
            Ok(())
        }
        5 => {
            if argument > MAX_PROVIDER_CONTAINER_ITEMS {
                return Err(CryptoError::OpaqueStateMalformed);
            }
            for _ in 0..argument {
                scan_cbor_item(bytes, cursor, depth + 1, items)?;
                scan_cbor_item(bytes, cursor, depth + 1, items)?;
            }
            Ok(())
        }
        7 if matches!(additional, 20..=22) => Ok(()),
        _ => Err(CryptoError::OpaqueStateMalformed),
    }
}

fn read_cbor_head(bytes: &[u8], cursor: &mut usize) -> Result<(u8, u8, u64), CryptoError> {
    let initial = *bytes.get(*cursor).ok_or(CryptoError::OpaqueStateMalformed)?;
    *cursor = cursor.checked_add(1).ok_or(CryptoError::OpaqueStateMalformed)?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let (argument, minimum) = match additional {
        value @ 0..=23 => (u64::from(value), 0),
        24 => (u64::from(read_cbor_array::<1>(bytes, cursor)?[0]), 24),
        25 => (u64::from(u16::from_be_bytes(read_cbor_array(bytes, cursor)?)), 1 << 8),
        26 => (u64::from(u32::from_be_bytes(read_cbor_array(bytes, cursor)?)), 1 << 16),
        27 => (u64::from_be_bytes(read_cbor_array(bytes, cursor)?), 1 << 32),
        _ => return Err(CryptoError::OpaqueStateMalformed),
    };
    if argument < minimum {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok((major, additional, argument))
}

fn read_cbor_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], CryptoError> {
    let end = cursor.checked_add(N).ok_or(CryptoError::OpaqueStateMalformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(CryptoError::OpaqueStateMalformed)?
        .try_into()
        .map_err(|_| CryptoError::OpaqueStateMalformed)?;
    *cursor = end;
    Ok(value)
}

fn validate_account_provider_has_no_fallback(bytes: &[u8]) -> Result<(), CryptoError> {
    parse_account_provider_otks(bytes, true).map(drop)
}

#[derive(Clone, Copy)]
struct ProviderOtkEntry {
    key_id: u64,
    curve25519: [u8; 32],
    published: bool,
}

const EMPTY_PROVIDER_OTK_ENTRY: ProviderOtkEntry =
    ProviderOtkEntry { key_id: 0, curve25519: [0; 32], published: false };

struct ProviderOtkSnapshot {
    entries: [ProviderOtkEntry; MAX_TOTAL_OTKS],
    len: usize,
}

/// Pinned vodozemac 0.10.0 `AccountPickle` parser. The parser uses only fixed
/// stack storage. The only bounded provider allocation is the official
/// `Curve25519SecretKey` wrapper used transiently to derive each public key;
/// copied secret bytes are zeroized on every return path.
fn parse_account_provider_otks(
    bytes: &[u8],
    require_no_fallback: bool,
) -> Result<ProviderOtkSnapshot, CryptoError> {
    scan_provider_cbor(bytes, MAX_PROVIDER_ACCOUNT_BYTES)?;
    let mut cursor = 0;
    let (major, _, count) = read_cbor_head(bytes, &mut cursor)?;
    if major != 5 || count != 4 {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut items = 1;
    expect_cbor_text(bytes, &mut cursor, "signing_key")?;
    scan_cbor_item(bytes, &mut cursor, 1, &mut items)?;
    expect_cbor_text(bytes, &mut cursor, "diffie_hellman_key")?;
    scan_cbor_item(bytes, &mut cursor, 1, &mut items)?;
    expect_cbor_text(bytes, &mut cursor, "one_time_keys")?;
    let snapshot = parse_provider_one_time_keys(bytes, &mut cursor)?;
    expect_cbor_text(bytes, &mut cursor, "fallback_keys")?;
    if require_no_fallback {
        validate_empty_fallback_map(bytes, &mut cursor)?;
    } else {
        scan_cbor_item(bytes, &mut cursor, 1, &mut items)?;
    }
    if cursor != bytes.len() {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(snapshot)
}

fn parse_provider_one_time_keys(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<ProviderOtkSnapshot, CryptoError> {
    let (major, _, count) = read_cbor_head(bytes, cursor)?;
    if major != 5 || count != 3 {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    expect_cbor_text(bytes, cursor, "next_key_id")?;
    let next_key_id = read_cbor_unsigned(bytes, cursor)?;
    expect_cbor_text(bytes, cursor, "public_keys")?;
    let (major, _, public_count) = read_cbor_head(bytes, cursor)?;
    let public_count =
        usize::try_from(public_count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    if major != 5 || public_count > MAX_TOTAL_OTKS {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut public_entries = [EMPTY_PROVIDER_OTK_ENTRY; MAX_TOTAL_OTKS];
    let mut previous_public_id = None;
    for index in 0..public_count {
        let key_id = read_cbor_unsigned(bytes, cursor)?;
        if key_id >= next_key_id || previous_public_id.is_some_and(|old| old >= key_id) {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        previous_public_id = Some(key_id);
        let curve25519 = read_cbor_u8_array::<32>(bytes, cursor)?;
        if public_entries[..index].iter().any(|entry| entry.curve25519 == curve25519) {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        public_entries[index] = ProviderOtkEntry { key_id, curve25519, published: false };
    }

    expect_cbor_text(bytes, cursor, "private_keys")?;
    let (major, _, private_count) = read_cbor_head(bytes, cursor)?;
    let private_count =
        usize::try_from(private_count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    if major != 5 || private_count > MAX_TOTAL_OTKS || public_count > private_count {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut snapshot = ProviderOtkSnapshot {
        entries: [EMPTY_PROVIDER_OTK_ENTRY; MAX_TOTAL_OTKS],
        len: private_count,
    };
    let mut matched_public = [false; MAX_TOTAL_OTKS];
    let mut previous_private_id = None;
    for index in 0..private_count {
        let key_id = read_cbor_unsigned(bytes, cursor)?;
        if key_id >= next_key_id || previous_private_id.is_some_and(|old| old >= key_id) {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        previous_private_id = Some(key_id);
        let secret_bytes = Zeroizing::new(read_cbor_u8_array::<32>(bytes, cursor)?);
        let secret = Curve25519SecretKey::from_slice(&secret_bytes);
        let curve25519 = Curve25519PublicKey::from(&secret).to_bytes();
        drop(secret);
        if snapshot.entries[..index].iter().any(|entry| entry.curve25519 == curve25519) {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let public_index =
            public_entries[..public_count].iter().position(|entry| entry.key_id == key_id);
        let published = if let Some(public_index) = public_index {
            if matched_public[public_index] || public_entries[public_index].curve25519 != curve25519
            {
                return Err(CryptoError::OpaqueStateMalformed);
            }
            matched_public[public_index] = true;
            false
        } else {
            true
        };
        snapshot.entries[index] = ProviderOtkEntry { key_id, curve25519, published };
    }
    if matched_public[..public_count].iter().any(|matched| !matched) {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(snapshot)
}

fn validate_provider_inventory(
    bytes: &[u8],
    inventory: &[&TrackedOneTimeKey],
) -> Result<(), CryptoError> {
    let snapshot = parse_account_provider_otks(bytes, false)?;
    if snapshot.len != inventory.len() {
        return Err(CryptoError::InventoryMalformed);
    }
    for provider in &snapshot.entries[..snapshot.len] {
        if !inventory.iter().any(|entry| {
            key_id_matches(provider.key_id, entry.key_id.as_bytes())
                && provider.curve25519 == entry.curve25519
                && provider.published == entry.published
        }) {
            return Err(CryptoError::InventoryMalformed);
        }
    }
    for entry in inventory {
        if !snapshot.entries[..snapshot.len].iter().any(|provider| {
            key_id_matches(provider.key_id, entry.key_id.as_bytes())
                && provider.curve25519 == entry.curve25519
                && provider.published == entry.published
        }) {
            return Err(CryptoError::InventoryMalformed);
        }
    }
    Ok(())
}

fn key_id_matches(key_id: u64, encoded: &[u8]) -> bool {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if encoded.len() != 11 {
        return false;
    }
    let input = key_id.to_be_bytes();
    let expected = [
        ALPHABET[usize::from(input[0] >> 2)],
        ALPHABET[usize::from(((input[0] & 0x03) << 4) | (input[1] >> 4))],
        ALPHABET[usize::from(((input[1] & 0x0f) << 2) | (input[2] >> 6))],
        ALPHABET[usize::from(input[2] & 0x3f)],
        ALPHABET[usize::from(input[3] >> 2)],
        ALPHABET[usize::from(((input[3] & 0x03) << 4) | (input[4] >> 4))],
        ALPHABET[usize::from(((input[4] & 0x0f) << 2) | (input[5] >> 6))],
        ALPHABET[usize::from(input[5] & 0x3f)],
        ALPHABET[usize::from(input[6] >> 2)],
        ALPHABET[usize::from(((input[6] & 0x03) << 4) | (input[7] >> 4))],
        ALPHABET[usize::from((input[7] & 0x0f) << 2)],
    ];
    encoded == expected
}

fn expect_cbor_text(bytes: &[u8], cursor: &mut usize, expected: &str) -> Result<(), CryptoError> {
    (read_cbor_text(bytes, cursor)? == expected)
        .then_some(())
        .ok_or(CryptoError::OpaqueStateMalformed)
}

fn read_cbor_unsigned(bytes: &[u8], cursor: &mut usize) -> Result<u64, CryptoError> {
    let (major, _, value) = read_cbor_head(bytes, cursor)?;
    (major == 0).then_some(value).ok_or(CryptoError::OpaqueStateMalformed)
}

fn read_cbor_u8_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], CryptoError> {
    let (major, _, count) = read_cbor_head(bytes, cursor)?;
    if major != 4 || count != N as u64 {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut value = [0; N];
    for byte in &mut value {
        *byte = u8::try_from(read_cbor_unsigned(bytes, cursor)?)
            .map_err(|_| CryptoError::OpaqueStateMalformed)?;
    }
    Ok(value)
}

fn validate_empty_fallback_map(bytes: &[u8], cursor: &mut usize) -> Result<(), CryptoError> {
    let (major, _, count) = read_cbor_head(bytes, cursor)?;
    if major != 5 || count != 3 {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    expect_cbor_text(bytes, cursor, "key_id")?;
    if read_cbor_unsigned(bytes, cursor)? != 0 {
        return Err(CryptoError::FallbackRejected);
    }
    expect_cbor_text(bytes, cursor, "fallback_key")?;
    if read_cbor_null(bytes, cursor).is_err() {
        return Err(CryptoError::FallbackRejected);
    }
    expect_cbor_text(bytes, cursor, "previous_fallback_key")?;
    if read_cbor_null(bytes, cursor).is_err() {
        return Err(CryptoError::FallbackRejected);
    }
    Ok(())
}

fn read_cbor_text<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a str, CryptoError> {
    let (major, _, length) = read_cbor_head(bytes, cursor)?;
    if major != 3 || length > 64 {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let end = cursor
        .checked_add(usize::try_from(length).map_err(|_| CryptoError::OpaqueStateMalformed)?)
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    let value = bytes.get(*cursor..end).ok_or(CryptoError::OpaqueStateMalformed)?;
    *cursor = end;
    std::str::from_utf8(value).map_err(|_| CryptoError::OpaqueStateMalformed)
}

fn read_cbor_null(bytes: &[u8], cursor: &mut usize) -> Result<(), CryptoError> {
    if bytes.get(*cursor).copied() != Some(0xf6) {
        return Err(CryptoError::FallbackRejected);
    }
    *cursor = cursor.checked_add(1).ok_or(CryptoError::OpaqueStateMalformed)?;
    Ok(())
}

fn ensure_v1(session: &Session) -> Result<(), CryptoError> {
    (session.session_config() == SessionConfig::version_1() && OLM_VERSION == 1)
        .then_some(())
        .ok_or(CryptoError::UnsupportedMessageVersion)
}

fn public_session_keys(keys: SessionKeys) -> PublicSessionKeys {
    PublicSessionKeys {
        identity_curve25519: keys.identity_key.to_bytes(),
        base_curve25519: keys.base_key.to_bytes(),
        one_time_curve25519: keys.one_time_key.to_bytes(),
    }
}

fn fingerprint_for(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREKEY_FINGERPRINT_DOMAIN);
    hasher.update(public);
    hasher.finalize().into()
}

fn published_entries<'a>(
    entries: impl Iterator<Item = &'a TrackedOneTimeKey>,
) -> Result<Vec<PublishedProofEntry>, CryptoError> {
    let mut published = Vec::new();
    published.try_reserve_exact(MAX_TOTAL_OTKS).map_err(|_| CryptoError::InputTooLarge)?;
    for entry in entries.filter(|entry| entry.published) {
        published.push(PublishedProofEntry {
            wire_id: entry.wire_id,
            key_id: entry.key_id.clone(),
            curve25519: entry.curve25519,
        });
    }
    if published.len() > MAX_TOTAL_OTKS
        || published.windows(2).any(|pair| pair[0].wire_id >= pair[1].wire_id)
    {
        return Err(CryptoError::InventoryMalformed);
    }
    Ok(published)
}

fn next_published_proof_chain<'a>(
    account: &Account,
    entries: impl Iterator<Item = &'a TrackedOneTimeKey>,
    used_wire_ids: &HashSet<[u8; 16]>,
    previous: &[PublishedBatchProof],
) -> Result<Vec<PublishedBatchProof>, CryptoError> {
    let entries = published_entries(entries)?;
    if entries.is_empty() && used_wire_ids.is_empty() && previous.is_empty() {
        return Ok(Vec::new());
    }
    if previous.len() >= MAX_PUBLISHED_PROOFS {
        return Err(CryptoError::InputTooLarge);
    }
    let sequence = u64::try_from(previous.len())
        .map_err(|_| CryptoError::OpaqueStateMalformed)?
        .checked_add(1)
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    let previous_digest =
        previous.last().map(published_proof_digest).transpose()?.unwrap_or([0; 32]);
    let mut proof = PublishedBatchProof {
        sequence,
        previous_digest,
        used_wire_ids_digest: used_wire_ids_digest(used_wire_ids)?,
        entries,
        signature: [0; PUBLISHED_PROOF_SIGNATURE_BYTES],
    };
    let statement = published_proof_statement(account, &proof)?;
    proof.signature = account.sign(&statement).to_bytes();
    let mut chain = previous.to_vec();
    chain.try_reserve_exact(1).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    chain.push(proof);
    Ok(chain)
}

fn validate_published_proof_chain<'a>(
    account: &Account,
    inventory: impl Iterator<Item = &'a TrackedOneTimeKey>,
    used_wire_ids: &HashSet<[u8; 16]>,
    proofs: &[PublishedBatchProof],
) -> Result<(), CryptoError> {
    let expected = published_entries(inventory)?;
    if proofs.is_empty() {
        return (expected.is_empty() && used_wire_ids.is_empty())
            .then_some(())
            .ok_or(CryptoError::InventoryMalformed);
    }
    if proofs.len() > MAX_PUBLISHED_PROOFS {
        return Err(CryptoError::InventoryMalformed);
    }
    let mut previous_digest = [0; 32];
    let mut previous_snapshot: Option<(&[PublishedProofEntry], [u8; 32])> = None;
    for (index, proof) in proofs.iter().enumerate() {
        validate_published_proof_entries(&proof.entries)?;
        if proof.sequence
            != u64::try_from(index)
                .map_err(|_| CryptoError::InventoryMalformed)?
                .checked_add(1)
                .ok_or(CryptoError::InventoryMalformed)?
            || proof.previous_digest != previous_digest
            || previous_snapshot.is_some_and(|(entries, used_digest)| {
                entries == proof.entries && used_digest == proof.used_wire_ids_digest
            })
        {
            return Err(CryptoError::InventoryMalformed);
        }
        let statement = published_proof_statement(account, proof)?;
        let signature = Ed25519Signature::from_slice(&proof.signature)
            .map_err(|_| CryptoError::InventoryMalformed)?;
        account
            .identity_keys()
            .ed25519
            .verify(&statement, &signature)
            .map_err(|_| CryptoError::InventoryMalformed)?;
        previous_digest = published_proof_digest(proof)?;
        previous_snapshot = Some((&proof.entries, proof.used_wire_ids_digest));
    }
    let current = proofs.last().ok_or(CryptoError::InventoryMalformed)?;
    if current.used_wire_ids_digest != used_wire_ids_digest(used_wire_ids)?
        || current.entries != expected
    {
        return Err(CryptoError::InventoryMalformed);
    }
    Ok(())
}

fn validate_published_proof_entries(entries: &[PublishedProofEntry]) -> Result<(), CryptoError> {
    if entries.len() > MAX_TOTAL_OTKS {
        return Err(CryptoError::InventoryMalformed);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.key_id.is_empty()
            || entry.key_id.len() > MAX_KEY_ID_BYTES
            || entries[..index].iter().any(|old| {
                old.wire_id >= entry.wire_id
                    || old.key_id == entry.key_id
                    || old.curve25519 == entry.curve25519
            })
        {
            return Err(CryptoError::InventoryMalformed);
        }
    }
    Ok(())
}

fn published_proof_digest(proof: &PublishedBatchProof) -> Result<[u8; 32], CryptoError> {
    Ok(Sha256::digest(encode_published_proof(proof)?).into())
}

fn published_proof_statement(
    account: &Account,
    proof: &PublishedBatchProof,
) -> Result<Vec<u8>, CryptoError> {
    let entries_len = proof.entries.iter().try_fold(0usize, |length, entry| {
        length
            .checked_add(16 + 1 + entry.key_id.len() + 32)
            .ok_or(CryptoError::OpaqueStateMalformed)
    })?;
    let capacity = PUBLISHED_PROOF_DOMAIN
        .len()
        .checked_add(PROFILE.len())
        .and_then(|n| n.checked_add(1 + 1 + 8 + 32 + 32 + 32 + 32 + 1))
        .and_then(|n| n.checked_add(entries_len))
        .ok_or(CryptoError::OpaqueStateMalformed)?;
    let identity = account.identity_keys();
    let mut out = Vec::new();
    out.try_reserve_exact(capacity).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(PUBLISHED_PROOF_DOMAIN);
    out.extend_from_slice(PROFILE);
    out.push(PUBLISHED_PROOF_VERSION);
    out.push(ACCOUNT_STATE_VERSION);
    out.extend_from_slice(&proof.sequence.to_be_bytes());
    out.extend_from_slice(&proof.previous_digest);
    out.extend_from_slice(&proof.used_wire_ids_digest);
    out.extend_from_slice(identity.ed25519.as_bytes());
    out.extend_from_slice(&identity.curve25519.to_bytes());
    out.push(u8::try_from(proof.entries.len()).map_err(|_| CryptoError::InventoryMalformed)?);
    for entry in &proof.entries {
        append_published_proof_entry(&mut out, entry)?;
    }
    Ok(out)
}

fn append_published_proof_entry(
    out: &mut Vec<u8>,
    entry: &PublishedProofEntry,
) -> Result<(), CryptoError> {
    if entry.key_id.is_empty() || entry.key_id.len() > MAX_KEY_ID_BYTES {
        return Err(CryptoError::InventoryMalformed);
    }
    out.extend_from_slice(&entry.wire_id);
    out.push(u8::try_from(entry.key_id.len()).map_err(|_| CryptoError::InventoryMalformed)?);
    out.extend_from_slice(entry.key_id.as_bytes());
    out.extend_from_slice(&entry.curve25519);
    Ok(())
}

fn encode_published_proof(proof: &PublishedBatchProof) -> Result<Vec<u8>, CryptoError> {
    validate_published_proof_entries(&proof.entries)?;
    let mut out = Vec::new();
    out.try_reserve_exact(MAX_SINGLE_PUBLISHED_PROOF_BYTES)
        .map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(PUBLISHED_PROOF_MAGIC);
    out.push(PUBLISHED_PROOF_VERSION);
    out.extend_from_slice(&proof.sequence.to_be_bytes());
    out.extend_from_slice(&proof.previous_digest);
    out.extend_from_slice(&proof.used_wire_ids_digest);
    out.push(u8::try_from(proof.entries.len()).map_err(|_| CryptoError::InventoryMalformed)?);
    for entry in &proof.entries {
        append_published_proof_entry(&mut out, entry)?;
    }
    out.extend_from_slice(&proof.signature);
    if out.len() > MAX_SINGLE_PUBLISHED_PROOF_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(out)
}

fn decode_published_proof(bytes: &[u8]) -> Result<PublishedBatchProof, CryptoError> {
    if bytes.len() < PUBLISHED_PROOF_HEADER_BYTES + PUBLISHED_PROOF_SIGNATURE_BYTES
        || bytes.len() > MAX_SINGLE_PUBLISHED_PROOF_BYTES
    {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(4)? != PUBLISHED_PROOF_MAGIC || cursor.byte()? != PUBLISHED_PROOF_VERSION {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let sequence = cursor.u64()?;
    let previous_digest = cursor.array::<32>()?;
    let used_wire_ids_digest = cursor.array::<32>()?;
    let count = cursor.byte()? as usize;
    if sequence == 0 || count > MAX_TOTAL_OTKS {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut entries = Vec::new();
    entries.try_reserve_exact(count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let mut previous_wire_id = None;
    for _ in 0..count {
        let wire_id = cursor.array::<16>()?;
        if previous_wire_id.is_some_and(|previous| previous >= wire_id) {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        previous_wire_id = Some(wire_id);
        let key_len = cursor.byte()? as usize;
        if key_len == 0 || key_len > MAX_KEY_ID_BYTES {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let key_id = String::from_utf8(cursor.take(key_len)?.to_vec())
            .map_err(|_| CryptoError::OpaqueStateMalformed)?;
        let curve25519 = cursor.array::<32>()?;
        entries.push(PublishedProofEntry { wire_id, key_id, curve25519 });
    }
    let signature = cursor.array::<PUBLISHED_PROOF_SIGNATURE_BYTES>()?;
    if !cursor.is_empty() {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let proof =
        PublishedBatchProof { sequence, previous_digest, used_wire_ids_digest, entries, signature };
    validate_published_proof_entries(&proof.entries)?;
    Ok(proof)
}

fn encode_published_proof_chain(proofs: &[PublishedBatchProof]) -> Result<Vec<u8>, CryptoError> {
    if proofs.is_empty() {
        return Ok(Vec::new());
    }
    if proofs.len() > MAX_PUBLISHED_PROOFS {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(MAX_PUBLISHED_PROOF_CHAIN_BYTES)
        .map_err(|_| CryptoError::OpaqueStateMalformed)?;
    out.extend_from_slice(PUBLISHED_PROOF_CHAIN_MAGIC);
    out.push(PUBLISHED_PROOF_CHAIN_VERSION);
    out.push(u8::try_from(proofs.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?);
    for proof in proofs {
        let encoded = encode_published_proof(proof)?;
        out.extend_from_slice(
            &u16::try_from(encoded.len())
                .map_err(|_| CryptoError::OpaqueStateMalformed)?
                .to_be_bytes(),
        );
        out.extend_from_slice(&encoded);
    }
    if out.len() > MAX_PUBLISHED_PROOF_CHAIN_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(out)
}

fn decode_published_proof_chain(bytes: &[u8]) -> Result<Vec<PublishedBatchProof>, CryptoError> {
    if bytes.len() < PUBLISHED_PROOF_CHAIN_HEADER_BYTES
        || bytes.len() > MAX_PUBLISHED_PROOF_CHAIN_BYTES
    {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(4)? != PUBLISHED_PROOF_CHAIN_MAGIC
        || cursor.byte()? != PUBLISHED_PROOF_CHAIN_VERSION
    {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let count = cursor.byte()? as usize;
    if count == 0 || count > MAX_PUBLISHED_PROOFS {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let mut proofs = Vec::new();
    proofs.try_reserve_exact(count).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    for _ in 0..count {
        let length = cursor.u16()? as usize;
        if length == 0 || length > MAX_SINGLE_PUBLISHED_PROOF_BYTES {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        proofs.push(decode_published_proof(cursor.take(length)?)?);
    }
    if !cursor.is_empty() {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(proofs)
}

fn used_wire_ids_digest(used_wire_ids: &HashSet<[u8; 16]>) -> Result<[u8; 32], CryptoError> {
    if used_wire_ids.len() > MAX_USED_WIRE_IDS {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    let count =
        u16::try_from(used_wire_ids.len()).map_err(|_| CryptoError::OpaqueStateMalformed)?;
    let mut canonical: Vec<_> = used_wire_ids.iter().copied().collect();
    canonical.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(USED_WIRE_IDS_DOMAIN);
    hasher.update(count.to_be_bytes());
    for wire_id in canonical {
        hasher.update(wire_id);
    }
    Ok(hasher.finalize().into())
}

fn validate_account_inventory<'a>(
    account: &Account,
    entries: impl Iterator<Item = &'a TrackedOneTimeKey>,
) -> Result<(), CryptoError> {
    let entries: Vec<_> = entries.collect();
    validate_inventory(&entries)?;
    if entries.len() != account.stored_one_time_key_count() || entries.len() > MAX_TOTAL_OTKS {
        return Err(CryptoError::InventoryMalformed);
    }
    let provider = serialize_account_pickle(&account.pickle())?;
    validate_provider_inventory(&provider, &entries)?;
    let unpublished = account.one_time_keys();
    if entries.iter().filter(|entry| !entry.published).count() != unpublished.len() {
        return Err(CryptoError::InventoryMalformed);
    }
    for (key_id, public) in unpublished {
        let encoded = key_id.to_base64();
        if !entries.iter().any(|entry| {
            !entry.published && entry.key_id == encoded && entry.curve25519 == public.to_bytes()
        }) {
            return Err(CryptoError::InventoryMalformed);
        }
    }
    Ok(())
}

fn validate_inventory(entries: &[&TrackedOneTimeKey]) -> Result<(), CryptoError> {
    if entries.len() > MAX_TOTAL_OTKS {
        return Err(CryptoError::InventoryMalformed);
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.key_id.is_empty()
            || entry.key_id.len() > MAX_KEY_ID_BYTES
            || entry.fingerprint != fingerprint_for(entry.curve25519)
            || entries[..index].iter().any(|old| {
                old.wire_id == entry.wire_id
                    || old.key_id == entry.key_id
                    || old.curve25519 == entry.curve25519
            })
        {
            return Err(CryptoError::InventoryMalformed);
        }
    }
    Ok(())
}

fn encode_inventory<'a>(
    entries: impl Iterator<Item = &'a TrackedOneTimeKey>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let entries: Vec<_> = entries.collect();
    validate_inventory(&entries)?;
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(INVENTORY_MAGIC);
    out.push(INVENTORY_VERSION);
    out.push(u8::try_from(entries.len()).map_err(|_| CryptoError::InventoryMalformed)?);
    for entry in entries {
        let key_id = entry.key_id.as_bytes();
        out.try_reserve(16 + 1 + key_id.len() + 32 + 32 + 1)
            .map_err(|_| CryptoError::OpaqueStateMalformed)?;
        out.extend_from_slice(&entry.wire_id);
        out.push(u8::try_from(key_id.len()).map_err(|_| CryptoError::InventoryMalformed)?);
        out.extend_from_slice(key_id);
        out.extend_from_slice(&entry.curve25519);
        out.extend_from_slice(&entry.fingerprint);
        out.push(u8::from(entry.published));
    }
    if out.len() > MAX_INVENTORY_BYTES {
        return Err(CryptoError::OpaqueStateMalformed);
    }
    Ok(out)
}

fn decode_inventory(bytes: &[u8]) -> Result<Vec<TrackedOneTimeKey>, CryptoError> {
    if bytes.len() < 7 || bytes.len() > MAX_INVENTORY_BYTES {
        return Err(CryptoError::InventoryMalformed);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(5)? != INVENTORY_MAGIC || cursor.byte()? != INVENTORY_VERSION {
        return Err(CryptoError::InventoryMalformed);
    }
    let count = cursor.byte()? as usize;
    if count > MAX_TOTAL_OTKS {
        return Err(CryptoError::InventoryMalformed);
    }
    let mut entries = Vec::with_capacity(count);
    let mut previous_wire_id = None;
    for _ in 0..count {
        let wire_id = cursor.array::<16>()?;
        if previous_wire_id.is_some_and(|previous| previous >= wire_id) {
            return Err(CryptoError::InventoryMalformed);
        }
        previous_wire_id = Some(wire_id);
        let key_len = cursor.byte()? as usize;
        if key_len == 0 || key_len > MAX_KEY_ID_BYTES {
            return Err(CryptoError::InventoryMalformed);
        }
        let key_id = String::from_utf8(cursor.take(key_len)?.to_vec())
            .map_err(|_| CryptoError::InventoryMalformed)?;
        let curve25519 = cursor.array::<32>()?;
        let fingerprint = cursor.array::<32>()?;
        let published = match cursor.byte()? {
            0 => false,
            1 => true,
            _ => return Err(CryptoError::InventoryMalformed),
        };
        entries.push(TrackedOneTimeKey { wire_id, key_id, curve25519, fingerprint, published });
    }
    if !cursor.is_empty() {
        return Err(CryptoError::InventoryMalformed);
    }
    let refs: Vec<_> = entries.iter().collect();
    validate_inventory(&refs)?;
    Ok(entries)
}

#[cfg(test)]
pub(crate) fn decode_inventory_for_test(
    bytes: &[u8],
) -> Result<Vec<TrackedOneTimeKey>, CryptoError> {
    decode_inventory(bytes)
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn byte(&mut self) -> Result<u8, CryptoError> {
        let (&byte, rest) = self.bytes.split_first().ok_or(CryptoError::OpaqueStateMalformed)?;
        self.bytes = rest;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], CryptoError> {
        if self.bytes.len() < count {
            return Err(CryptoError::OpaqueStateMalformed);
        }
        let (head, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CryptoError> {
        self.take(N)?.try_into().map_err(|_| CryptoError::OpaqueStateMalformed)
    }

    fn u16(&mut self) -> Result<u16, CryptoError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CryptoError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CryptoError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[allow(dead_code)]
fn _provider_types_are_private(_: Ed25519PublicKey, _: &PreKeyMessage, _: &OlmPublicMetadata) {}
