//! Durable opaque relay state. The relay never accepts plaintext, private
//! keys, provider state, or a decryption operation.

#![allow(clippy::type_complexity)]

use getrandom::fill as random_fill;
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{
    Connection, ErrorCode, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior,
    params,
};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering as CmpOrdering,
    collections::VecDeque,
    fmt,
    net::IpAddr,
    path::Path,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};
use telegraph_protocol::{
    DeliveryId, Envelope, MAX_CIPHERTEXT_LEN, MAX_ENVELOPE_LEN, MAX_OPAQUE_ID_LEN, MailboxId,
    ProtocolVersion,
};
use tokio::{
    sync::{Semaphore, mpsc, oneshot},
    time::timeout,
};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_CIPHERTEXT_BYTES: usize = MAX_CIPHERTEXT_LEN;
pub const MAX_OUTER_ENVELOPE_BYTES: usize = MAX_ENVELOPE_LEN;
pub const MAX_PUBLIC_PREKEY_BUNDLE_BYTES: usize = 1024;
pub const MAX_CONFIRMATION_TOKEN_BYTES: usize = 1024;
pub const MAX_CLAIM_ATTEMPTS: u32 = 5;
pub const WRITER_QUEUE_CAPACITY: usize = 64;
pub const READ_PERMIT_CAPACITY: usize = 8;
pub const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(100);
pub const NORMAL_DEADLINE: Duration = Duration::from_millis(250);
pub const READ_ADMISSION_DEADLINE: Duration = Duration::from_millis(25);
pub const MAINTENANCE_DEADLINE: Duration = Duration::from_secs(2);
const MAX_AUDIT_ROWS: u64 = 10_000;
const MAX_OPERATION_ROWS: u64 = 100_000;
const MAX_PAIRING_ROWS: u64 = 100_000;
const MAX_PREKEY_ROWS: u64 = 100_000;
const MAX_SOURCE_ROWS: u64 = 100_000;
const MAX_CLAIM_OPERATION_ROWS: u64 = 100_000;
const MAINTENANCE_BATCH_ROWS: i64 = 1_000;
const DEVICE_DOMAIN: &[u8] = b"telegraph/device-code/v2";
const USER_DOMAIN: &[u8] = b"telegraph/user-code/v2";
const CLAIM_DOMAIN: &[u8] = b"telegraph/claim-capability/v2";
const NONCE_DOMAIN: &[u8] = b"telegraph/claim-nonce/v2";
const OPERATION_DOMAIN: &[u8] = b"telegraph/operation/v2";
const SOURCE_DOMAIN: &[u8] = b"telegraph/claim-source/v2";
const TOKEN_DOMAIN: &[u8] = b"telegraph/confirmation-token/v1";
const BUNDLE_DOMAIN: &[u8] = b"telegraph/prekey-bundle/v1";
const AUDIT_DOMAIN: &[u8] = b"telegraph/relay-audit/v2";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[cfg(test)]
struct PollTestGate {
    operation_id: [u8; 16],
    started: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[cfg(test)]
static POLL_TEST_GATE: std::sync::OnceLock<std::sync::Mutex<Option<PollTestGate>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn install_poll_test_gate(gate: PollTestGate) {
    *POLL_TEST_GATE.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap() = Some(gate);
}

#[cfg(test)]
fn pause_poll_for_test(operation_id: [u8; 16]) {
    let mut slot = POLL_TEST_GATE.get_or_init(|| std::sync::Mutex::new(None)).lock().unwrap();
    let gate = if slot.as_ref().is_some_and(|gate| gate.operation_id == operation_id) {
        slot.take()
    } else {
        None
    };
    drop(slot);
    if let Some(gate) = gate {
        let _ = gate.started.send(());
        let _ = gate.release.recv();
    }
}

#[cfg(not(test))]
fn pause_poll_for_test(_operation_id: [u8; 16]) {}

struct MaintenanceBudget {
    remaining: u64,
    committed: u64,
}

enum MaintenanceAttempt<T> {
    Applied(T),
    BudgetExhausted,
    ResourceBlocked,
}

impl MaintenanceBudget {
    fn with_reserved_rows(reserved: u64) -> RelayResult<Self> {
        let remaining = u64::try_from(MAINTENANCE_BATCH_ROWS)
            .map_err(|_| RelayError::Internal)?
            .checked_sub(reserved)
            .ok_or(RelayError::Internal)?;
        Ok(Self { remaining, committed: 0 })
    }

    fn sql_limit(&self) -> RelayResult<i64> {
        i64::try_from(self.remaining).map_err(|_| RelayError::Internal)
    }

    fn attempt<T, F>(
        &mut self,
        tx: &Transaction<'_>,
        operation: F,
    ) -> RelayResult<MaintenanceAttempt<T>>
    where
        F: FnOnce(&Transaction<'_>) -> RelayResult<T>,
    {
        if self.remaining == 0 {
            return Ok(MaintenanceAttempt::BudgetExhausted);
        }
        tx.execute_batch("SAVEPOINT telegraph_maintenance_candidate").map_err(map_sqlite_error)?;
        let before = tx.total_changes();
        let outcome = operation(tx);
        let delta = tx.total_changes().checked_sub(before).ok_or(RelayError::Database)?;
        match outcome {
            Ok(value) if delta <= self.remaining => {
                tx.execute_batch("RELEASE SAVEPOINT telegraph_maintenance_candidate")
                    .map_err(map_sqlite_error)?;
                self.remaining -= delta;
                self.committed = self.committed.checked_add(delta).ok_or(RelayError::Database)?;
                Ok(MaintenanceAttempt::Applied(value))
            }
            Ok(_) => {
                rollback_maintenance_candidate(tx)?;
                Ok(MaintenanceAttempt::BudgetExhausted)
            }
            Err(RelayError::QuotaExceeded) => {
                rollback_maintenance_candidate(tx)?;
                Ok(MaintenanceAttempt::ResourceBlocked)
            }
            Err(error) => {
                rollback_maintenance_candidate(tx)?;
                Err(error)
            }
        }
    }

    fn attempt_limited<T, F>(
        &mut self,
        tx: &Transaction<'_>,
        operation: F,
    ) -> RelayResult<MaintenanceAttempt<T>>
    where
        F: FnOnce(&Transaction<'_>, i64) -> RelayResult<T>,
    {
        let limit = self.sql_limit()?;
        self.attempt(tx, |candidate| operation(candidate, limit))
    }

    fn is_empty(&self) -> bool {
        self.remaining == 0
    }
}

fn rollback_maintenance_candidate(tx: &Transaction<'_>) -> RelayResult<()> {
    tx.execute_batch(
        "ROLLBACK TO SAVEPOINT telegraph_maintenance_candidate; RELEASE SAVEPOINT telegraph_maintenance_candidate",
    )
    .map_err(map_sqlite_error)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RelayStorePolicy {
    pub pairing_ttl_secs: u64,
    pub max_prekey_ttl_secs: u64,
    pub mailbox_ttl_secs: u64,
    pub tombstone_retention_secs: u64,
    pub operation_retention_secs: u64,
    pub mailbox_max_live_rows: u64,
    pub mailbox_max_live_bytes: u64,
    pub mailbox_max_tombstones: u64,
    pub global_max_live_rows: u64,
    pub global_max_live_bytes: u64,
    pub global_max_tombstones: u64,
}

impl fmt::Debug for RelayStorePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStorePolicy")
            .field("pairing_ttl_secs", &self.pairing_ttl_secs)
            .field("max_prekey_ttl_secs", &self.max_prekey_ttl_secs)
            .field("mailbox_ttl_secs", &self.mailbox_ttl_secs)
            .field("tombstone_retention_secs", &self.tombstone_retention_secs)
            .field("operation_retention_secs", &self.operation_retention_secs)
            .field("mailbox_max_live_rows", &self.mailbox_max_live_rows)
            .field("mailbox_max_live_bytes", &self.mailbox_max_live_bytes)
            .field("mailbox_max_tombstones", &self.mailbox_max_tombstones)
            .field("global_max_live_rows", &self.global_max_live_rows)
            .field("global_max_live_bytes", &self.global_max_live_bytes)
            .field("global_max_tombstones", &self.global_max_tombstones)
            .finish()
    }
}

impl RelayStorePolicy {
    pub fn validate(self) -> RelayResult<Self> {
        let nonzero = [
            self.pairing_ttl_secs,
            self.max_prekey_ttl_secs,
            self.mailbox_ttl_secs,
            self.tombstone_retention_secs,
            self.operation_retention_secs,
            self.mailbox_max_live_rows,
            self.mailbox_max_live_bytes,
            self.mailbox_max_tombstones,
            self.global_max_live_rows,
            self.global_max_live_bytes,
            self.global_max_tombstones,
        ]
        .into_iter()
        .all(|value| value > 0 && i64::try_from(value).is_ok());
        if !nonzero
            || self.mailbox_max_live_rows > self.global_max_live_rows
            || self.mailbox_max_live_bytes > self.global_max_live_bytes
            || self.mailbox_max_tombstones > self.global_max_tombstones
            || self.mailbox_max_live_rows > 100_000
            || self.mailbox_max_live_bytes > 1_073_741_824
            || self.mailbox_max_tombstones > 100_000
            || self.operation_retention_secs <= self.pairing_ttl_secs
            || self.operation_retention_secs <= self.max_prekey_ttl_secs
            || self.operation_retention_secs <= self.mailbox_ttl_secs
            || self.operation_retention_secs >= self.tombstone_retention_secs
        {
            return Err(RelayError::InvalidInput);
        }
        Ok(self)
    }
}

struct SecretKeys {
    pairing: Zeroizing<[u8; 32]>,
    source: Zeroizing<[u8; 32]>,
}

/// Deployment-injected secrets. Neither key is written to SQLite or Debug.
pub struct RelayStoreSecrets(Arc<SecretKeys>);

impl RelayStoreSecrets {
    pub fn new(pairing_key: [u8; 32], source_key: [u8; 32]) -> RelayResult<Self> {
        if pairing_key == [0; 32] || source_key == [0; 32] || pairing_key == source_key {
            return Err(RelayError::InvalidInput);
        }
        Ok(Self(Arc::new(SecretKeys {
            pairing: Zeroizing::new(pairing_key),
            source: Zeroizing::new(source_key),
        })))
    }

    pub fn claim_source_deriver(&self) -> ClaimSourceDeriver {
        ClaimSourceDeriver(Arc::clone(&self.0))
    }
}

impl fmt::Debug for RelayStoreSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayStoreSecrets([REDACTED])")
    }
}

/// A stable origin bucket whose bytes cannot be supplied directly by an HTTP body.
pub struct ClaimSource([u8; 16]);

impl fmt::Debug for ClaimSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimSource([REDACTED])")
    }
}

pub struct ClaimSourceDeriver(Arc<SecretKeys>);

impl fmt::Debug for ClaimSourceDeriver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimSourceDeriver([REDACTED])")
    }
}

impl ClaimSourceDeriver {
    /// Derives a stable budget bucket from the socket peer IP observed by the transport.
    /// Forwarded/proxy headers require a separately reviewed HTTP trust policy.
    pub fn derive_peer_ip(&self, peer: IpAddr) -> RelayResult<ClaimSource> {
        let mut canonical = [0u8; 17];
        let bytes = match peer {
            IpAddr::V4(address) => {
                canonical[0] = 4;
                canonical[1..5].copy_from_slice(&address.octets());
                &canonical[..5]
            }
            IpAddr::V6(address) => {
                canonical[0] = 6;
                canonical[1..].copy_from_slice(&address.octets());
                &canonical[..]
            }
        };
        Ok(ClaimSource(hmac16(&self.0.source, SOURCE_DOMAIN, &[bytes])?))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum RelayError {
    InvalidInput,
    PairingUnavailable,
    PrekeyUnavailable,
    Conflict,
    IdempotencyConflict,
    PayloadTooLarge,
    EnvelopeTooLarge,
    Expired,
    QuotaExceeded,
    QueueFull,
    Busy,
    DeadlineExceeded,
    OutcomeUnknown { operation_id: [u8; 16] },
    Database,
    MigrationFailure,
    RuntimeRequired,
    Internal,
}

impl fmt::Debug for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutcomeUnknown { .. } => f.write_str("OutcomeUnknown([REDACTED])"),
            other => f.write_str(other.as_code()),
        }
    }
}

impl RelayError {
    fn as_code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::PairingUnavailable => "pairing_unavailable",
            Self::PrekeyUnavailable => "prekey_unavailable",
            Self::Conflict => "conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::Expired => "expired",
            Self::QuotaExceeded => "quota_exceeded",
            Self::QueueFull => "backpressure",
            Self::Busy => "busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::Database => "database_error",
            Self::MigrationFailure => "migration_failure",
            Self::RuntimeRequired => "runtime_required",
            Self::Internal => "internal_error",
        }
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_code())
    }
}

impl std::error::Error for RelayError {}
pub type RelayResult<T> = Result<T, RelayError>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StoreTime(u64);

impl fmt::Debug for StoreTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreTime([SEALED])")
    }
}

#[cfg(test)]
impl From<u64> for StoreTime {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CreatedPairing {
    pub operation_id: [u8; 16],
    pub intent_id: [u8; 16],
    pub device_code: String,
    pub user_code: String,
    pub expires_at: u64,
}

impl fmt::Debug for CreatedPairing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedPairing")
            .field("operation_id", &"[REDACTED]")
            .field("intent_id", &"[OPAQUE]")
            .field("device_code", &"[REDACTED]")
            .field("user_code", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingState {
    Available,
    Claimed,
    Expired,
    Burned,
    Cancelled,
    Consumed,
}

impl PairingState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Burned => "burned",
            Self::Cancelled => "cancelled",
            Self::Consumed => "consumed",
        }
    }

    fn parse(value: &str) -> RelayResult<Self> {
        match value {
            "available" => Ok(Self::Available),
            "claimed" => Ok(Self::Claimed),
            "expired" => Ok(Self::Expired),
            "burned" => Ok(Self::Burned),
            "cancelled" => Ok(Self::Cancelled),
            "consumed" => Ok(Self::Consumed),
            _ => Err(RelayError::Database),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PairingStatus {
    pub intent_id: [u8; 16],
    pub state: PairingState,
    pub b_nonce: Option<[u8; 16]>,
    pub expires_at: u64,
}

impl fmt::Debug for PairingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingStatus")
            .field("intent_id", &"[OPAQUE]")
            .field("state", &self.state)
            .field("b_nonce", &self.b_nonce.map(|_| "[REDACTED]"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ClaimResult {
    pub intent_id: [u8; 16],
    pub claim_capability: String,
    pub b_nonce: [u8; 16],
}

impl fmt::Debug for ClaimResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimResult")
            .field("intent_id", &"[OPAQUE]")
            .field("claim_capability", &"[REDACTED]")
            .field("b_nonce", &"[OPAQUE]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrekeyState {
    Available,
    Reserved,
    Consumed,
    Burned,
    Tombstoned,
}

impl PrekeyState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Burned => "burned",
            Self::Tombstoned => "tombstoned",
        }
    }

    fn parse(value: &str) -> RelayResult<Self> {
        match value {
            "available" => Ok(Self::Available),
            "reserved" => Ok(Self::Reserved),
            "consumed" => Ok(Self::Consumed),
            "burned" => Ok(Self::Burned),
            "tombstoned" => Ok(Self::Tombstoned),
            _ => Err(RelayError::Database),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalPrekeyBundle(Vec<u8>);

impl CanonicalPrekeyBundle {
    pub fn new(bytes: Vec<u8>) -> RelayResult<Self> {
        validate_canonical_cbor(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CanonicalPrekeyBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CanonicalPrekeyBundle")
            .field(&format_args!("{} opaque bytes", self.0.len()))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPrekey {
    pub prekey_id: [u8; 16],
    pub bundle: CanonicalPrekeyBundle,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPublicPrekey {
    pub prekey_id: [u8; 16],
    pub bundle: CanonicalPrekeyBundle,
    pub bundle_digest: [u8; 32],
    pub state: PrekeyState,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrekeyReservation {
    pub prekey_id: [u8; 16],
    pub reservation_id: [u8; 16],
    pub pairing_id: [u8; 16],
    pub state: PrekeyState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationResult {
    Pending,
    BothComplete,
}

#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueEnvelope {
    pub mailbox_id: Vec<u8>,
    pub delivery_id: Vec<u8>,
    pub protocol_version: ProtocolVersion,
    pub ciphertext: Vec<u8>,
    pub size: usize,
    pub expires_at: u64,
}

impl fmt::Debug for OpaqueEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueEnvelope")
            .field("mailbox_id", &format_args!("{} opaque bytes", self.mailbox_id.len()))
            .field("delivery_id", &format_args!("{} opaque bytes", self.delivery_id.len()))
            .field("protocol_version", &self.protocol_version)
            .field("ciphertext", &format_args!("{} opaque bytes", self.ciphertext.len()))
            .field("size", &self.size)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    Pending,
    Fetched,
    Acked,
    Expired,
    Deleted,
}

impl TransportState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Fetched => "fetched",
            Self::Acked => "acked",
            Self::Expired => "expired",
            Self::Deleted => "deleted",
        }
    }

    fn parse(value: &str) -> RelayResult<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "fetched" => Ok(Self::Fetched),
            "acked" => Ok(Self::Acked),
            "expired" => Ok(Self::Expired),
            "deleted" => Ok(Self::Deleted),
            _ => Err(RelayError::Database),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEnvelope {
    pub envelope: OpaqueEnvelope,
    pub state: TransportState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledDelivery {
    pub delivery_id: Vec<u8>,
    pub state: TransportState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    pub envelopes: Vec<StoredEnvelope>,
    pub settled: Vec<SettledDelivery>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupSummary {
    pub expired_mail: u64,
    pub purged_rows: u64,
    pub expired_pairings: u64,
    pub expired_prekeys: u64,
    /// More eligible maintenance work remains; call cleanup again with a new operation ID.
    pub remaining: bool,
    /// Actual SQLite rows committed by this cleanup transaction, including its audit and ledger.
    pub committed_changes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationReceipt {
    pub result_kind: u8,
    pub completed_at: u64,
}

type AnyResult = RelayResult<Box<dyn std::any::Any + Send>>;
struct WriteRequest {
    operation_id: [u8; 16],
    operation: Box<dyn FnOnce(&mut Connection) -> AnyResult + Send>,
    response: oneshot::Sender<AnyResult>,
    state: Arc<AtomicU8>,
}

const WRITE_QUEUED: u8 = 0;
const WRITE_RUNNING: u8 = 1;
const WRITE_CANCELLED: u8 = 2;
const WRITE_DONE: u8 = 3;
const WRITE_DEADLINE: u8 = 4;

struct QueueCancellation {
    state: Arc<AtomicU8>,
    armed: bool,
}

impl QueueCancellation {
    fn new(state: Arc<AtomicU8>) -> Self {
        Self { state, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for QueueCancellation {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.state.compare_exchange(
                WRITE_QUEUED,
                WRITE_CANCELLED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
    }
}

struct StoreInner {
    writer: mpsc::Sender<WriteRequest>,
    reads: Vec<Arc<Mutex<Connection>>>,
    read_permits: Arc<Semaphore>,
    next_read: AtomicUsize,
    policy: RelayStorePolicy,
    secrets: Arc<SecretKeys>,
}

#[derive(Clone)]
pub struct RelayOpaqueStore {
    inner: Arc<StoreInner>,
}

impl fmt::Debug for RelayOpaqueStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayOpaqueStore").finish_non_exhaustive()
    }
}

trait LedgerValue: Sized + Send + 'static {
    const KIND: u8;
    fn encode(&self) -> Vec<u8>;
    fn decode(bytes: &[u8]) -> RelayResult<Self>;
    fn changes_before_ledger(&self) -> Option<u64> {
        None
    }
    fn set_committed_changes(&mut self, _changes: u64) {}
}

#[derive(Clone, Copy)]
struct PairingRecord {
    intent_id: [u8; 16],
    expires_at: u64,
}

#[derive(Clone, Copy)]
struct ClaimRecord {
    intent_id: [u8; 16],
    accepted: bool,
}

#[derive(Clone, Copy)]
struct AdmissionRecord {
    outcome: u8,
}

#[derive(Clone, PartialEq, Eq)]
struct FetchRecord {
    delivery_ids: Vec<Vec<u8>>,
}

#[derive(Clone, Copy)]
enum ConfirmationRecord {
    Pending,
    BothComplete,
    RejectPairing,
    RejectPrekey,
}

impl LedgerValue for () {
    const KIND: u8 = 0;
    fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        if bytes.is_empty() { Ok(()) } else { Err(RelayError::Database) }
    }
}

impl LedgerValue for PairingRecord {
    const KIND: u8 = 1;
    fn encode(&self) -> Vec<u8> {
        let mut out = self.intent_id.to_vec();
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        if bytes.len() != 24 {
            return Err(RelayError::Database);
        }
        Ok(Self {
            intent_id: array16(&bytes[..16])?,
            expires_at: u64::from_be_bytes(array8(&bytes[16..])?),
        })
    }
}

impl LedgerValue for ClaimRecord {
    const KIND: u8 = 2;
    fn encode(&self) -> Vec<u8> {
        let mut out = self.intent_id.to_vec();
        out.push(u8::from(self.accepted));
        out
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        if bytes.len() != 17 || bytes[16] > 1 {
            return Err(RelayError::Database);
        }
        Ok(Self { intent_id: array16(&bytes[..16])?, accepted: bytes[16] == 1 })
    }
}

impl LedgerValue for AdmissionRecord {
    const KIND: u8 = 8;
    fn encode(&self) -> Vec<u8> {
        vec![self.outcome]
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        match bytes {
            [outcome @ 0..=2] => Ok(Self { outcome: *outcome }),
            _ => Err(RelayError::Database),
        }
    }
}

impl FetchRecord {
    fn encode(&self) -> Vec<u8> {
        let mut output =
            Vec::with_capacity(2 + self.delivery_ids.iter().map(|id| 2 + id.len()).sum::<usize>());
        output
            .extend_from_slice(&u16::try_from(self.delivery_ids.len()).unwrap_or(0).to_be_bytes());
        for id in &self.delivery_ids {
            output.extend_from_slice(&u16::try_from(id.len()).unwrap_or(0).to_be_bytes());
            output.extend_from_slice(id);
        }
        output
    }

    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        if bytes.len() < 2 || bytes.len() > 25_802 {
            return Err(RelayError::Database);
        }
        let count = usize::from(u16::from_be_bytes(array2(&bytes[..2])?));
        if count > 100 {
            return Err(RelayError::Database);
        }
        let mut offset = 2usize;
        let mut delivery_ids = Vec::with_capacity(count);
        for _ in 0..count {
            let length_end = offset.checked_add(2).ok_or(RelayError::Database)?;
            if length_end > bytes.len() {
                return Err(RelayError::Database);
            }
            let length = usize::from(u16::from_be_bytes(array2(&bytes[offset..length_end])?));
            let end = length_end.checked_add(length).ok_or(RelayError::Database)?;
            if end > bytes.len() {
                return Err(RelayError::Database);
            }
            let id = bytes[length_end..end].to_vec();
            validate_id(&id).map_err(|_| RelayError::Database)?;
            if delivery_ids.last().is_some_and(|previous| previous >= &id) {
                return Err(RelayError::Database);
            }
            delivery_ids.push(id);
            offset = end;
        }
        if offset != bytes.len() {
            return Err(RelayError::Database);
        }
        Ok(Self { delivery_ids })
    }
}

impl LedgerValue for PairingState {
    const KIND: u8 = 3;
    fn encode(&self) -> Vec<u8> {
        vec![*self as u8]
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        match bytes {
            [0] => Ok(Self::Available),
            [1] => Ok(Self::Claimed),
            [2] => Ok(Self::Expired),
            [3] => Ok(Self::Burned),
            [4] => Ok(Self::Cancelled),
            [5] => Ok(Self::Consumed),
            _ => Err(RelayError::Database),
        }
    }
}

impl LedgerValue for PrekeyState {
    const KIND: u8 = 4;
    fn encode(&self) -> Vec<u8> {
        vec![*self as u8]
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        match bytes {
            [0] => Ok(Self::Available),
            [1] => Ok(Self::Reserved),
            [2] => Ok(Self::Consumed),
            [3] => Ok(Self::Burned),
            [4] => Ok(Self::Tombstoned),
            _ => Err(RelayError::Database),
        }
    }
}

impl LedgerValue for ConfirmationRecord {
    const KIND: u8 = 5;
    fn encode(&self) -> Vec<u8> {
        vec![*self as u8]
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        match bytes {
            [0] => Ok(Self::Pending),
            [1] => Ok(Self::BothComplete),
            [2] => Ok(Self::RejectPairing),
            [3] => Ok(Self::RejectPrekey),
            _ => Err(RelayError::Database),
        }
    }
}

impl LedgerValue for TransportState {
    const KIND: u8 = 6;
    fn encode(&self) -> Vec<u8> {
        vec![*self as u8]
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        match bytes {
            [0] => Ok(Self::Pending),
            [1] => Ok(Self::Fetched),
            [2] => Ok(Self::Acked),
            [3] => Ok(Self::Expired),
            [4] => Ok(Self::Deleted),
            _ => Err(RelayError::Database),
        }
    }
}

impl LedgerValue for CleanupSummary {
    const KIND: u8 = 7;
    fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> =
            [self.expired_mail, self.purged_rows, self.expired_pairings, self.expired_prekeys]
                .into_iter()
                .flat_map(u64::to_be_bytes)
                .collect();
        encoded.push(u8::from(self.remaining));
        encoded.extend_from_slice(&self.committed_changes.to_be_bytes());
        encoded
    }
    fn decode(bytes: &[u8]) -> RelayResult<Self> {
        if bytes.len() != 41 || bytes[32] > 1 {
            return Err(RelayError::Database);
        }
        Ok(Self {
            expired_mail: u64::from_be_bytes(array8(&bytes[0..8])?),
            purged_rows: u64::from_be_bytes(array8(&bytes[8..16])?),
            expired_pairings: u64::from_be_bytes(array8(&bytes[16..24])?),
            expired_prekeys: u64::from_be_bytes(array8(&bytes[24..32])?),
            remaining: bytes[32] == 1,
            committed_changes: u64::from_be_bytes(array8(&bytes[33..41])?),
        })
    }
    fn changes_before_ledger(&self) -> Option<u64> {
        Some(self.committed_changes)
    }
    fn set_committed_changes(&mut self, changes: u64) {
        self.committed_changes = changes;
    }
}

impl RelayOpaqueStore {
    pub fn timestamp(&self) -> RelayResult<StoreTime> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RelayError::Internal)?
            .as_secs();
        Ok(StoreTime(seconds))
    }

    pub fn open(
        path: impl AsRef<Path>,
        policy: RelayStorePolicy,
        secrets: RelayStoreSecrets,
    ) -> RelayResult<Self> {
        let policy = policy.validate()?;
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| RelayError::RuntimeRequired)?;
        let path = path.as_ref().to_path_buf();
        let mut writer = Connection::open(&path).map_err(map_sqlite_error)?;
        configure_writer(&mut writer)?;
        migrate(&mut writer)?;
        let mut reads = Vec::with_capacity(READ_PERMIT_CAPACITY);
        for _ in 0..READ_PERMIT_CAPACITY {
            let read = Connection::open_with_flags(
                &path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(map_sqlite_error)?;
            configure_read(&read)?;
            reads.push(Arc::new(Mutex::new(read)));
        }
        Self::from_connections(writer, reads, policy, secrets.0, handle)
    }

    pub fn open_in_memory(
        policy: RelayStorePolicy,
        secrets: RelayStoreSecrets,
    ) -> RelayResult<Self> {
        let policy = policy.validate()?;
        let handle =
            tokio::runtime::Handle::try_current().map_err(|_| RelayError::RuntimeRequired)?;
        let random = random_id::<16>()?;
        let uri = format!("file:telegraph-{}?mode=memory&cache=shared", hex16(&random));
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut writer = Connection::open_with_flags(&uri, flags).map_err(map_sqlite_error)?;
        configure_writer(&mut writer)?;
        migrate(&mut writer)?;
        let mut reads = Vec::with_capacity(READ_PERMIT_CAPACITY);
        for _ in 0..READ_PERMIT_CAPACITY {
            let read = Connection::open_with_flags(&uri, flags).map_err(map_sqlite_error)?;
            configure_read(&read)?;
            reads.push(Arc::new(Mutex::new(read)));
        }
        Self::from_connections(writer, reads, policy, secrets.0, handle)
    }

    fn from_connections(
        writer_db: Connection,
        reads: Vec<Arc<Mutex<Connection>>>,
        policy: RelayStorePolicy,
        secrets: Arc<SecretKeys>,
        handle: tokio::runtime::Handle,
    ) -> RelayResult<Self> {
        if reads.len() != READ_PERMIT_CAPACITY {
            return Err(RelayError::Internal);
        }
        let (writer, receiver) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        handle.spawn(writer_loop(receiver, writer_db));
        Ok(Self {
            inner: Arc::new(StoreInner {
                writer,
                reads,
                read_permits: Arc::new(Semaphore::new(READ_PERMIT_CAPACITY)),
                next_read: AtomicUsize::new(0),
                policy,
                secrets,
            }),
        })
    }

    pub fn claim_source_deriver(&self) -> ClaimSourceDeriver {
        ClaimSourceDeriver(Arc::clone(&self.inner.secrets))
    }

    async fn write_connection<T, F>(
        &self,
        operation_id: [u8; 16],
        deadline: Duration,
        operation: F,
    ) -> RelayResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> RelayResult<T> + Send + 'static,
    {
        let (response, receiver) = oneshot::channel();
        let state = Arc::new(AtomicU8::new(WRITE_QUEUED));
        let request = WriteRequest {
            operation_id,
            operation: Box::new(move |db| {
                operation(db).map(|value| Box::new(value) as Box<dyn std::any::Any + Send>)
            }),
            response,
            state: Arc::clone(&state),
        };
        let mut cancellation = QueueCancellation::new(Arc::clone(&state));
        self.inner.writer.try_send(request).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => RelayError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => RelayError::Internal,
        })?;
        let received = match timeout(deadline, receiver).await {
            Ok(result) => result.map_err(|_| RelayError::Internal)?,
            Err(_) => {
                if state
                    .compare_exchange(
                        WRITE_QUEUED,
                        WRITE_DEADLINE,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    cancellation.disarm();
                    return Err(RelayError::DeadlineExceeded);
                }
                cancellation.disarm();
                return Err(RelayError::OutcomeUnknown { operation_id });
            }
        };
        cancellation.disarm();
        let value = received?;
        value.downcast::<T>().map(|boxed| *boxed).map_err(|_| RelayError::Internal)
    }

    async fn write_operation<T, F>(
        &self,
        operation_id: [u8; 16],
        request_digest: [u8; 32],
        now: u64,
        deadline: Duration,
        operation: F,
    ) -> RelayResult<T>
    where
        T: LedgerValue,
        F: FnOnce(&Transaction<'_>) -> RelayResult<T> + Send + 'static,
    {
        self.write_operation_validated(
            operation_id,
            request_digest,
            now,
            deadline,
            |_tx, value| Ok(value),
            operation,
        )
        .await
    }

    async fn write_operation_validated<T, V, F>(
        &self,
        operation_id: [u8; 16],
        request_digest: [u8; 32],
        now: u64,
        deadline: Duration,
        replay_validation: V,
        operation: F,
    ) -> RelayResult<T>
    where
        T: LedgerValue,
        V: FnOnce(&Transaction<'_>, T) -> RelayResult<T> + Send + 'static,
        F: FnOnce(&Transaction<'_>) -> RelayResult<T> + Send + 'static,
    {
        let operation_commitment = operation_commitment(&self.inner.secrets, &operation_id)?;
        let retention = self.inner.policy.operation_retention_secs;
        self.write_connection(operation_id, deadline, move |db| {
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_sqlite_error)?;
            let completed = sqlite_i64(now)?;
            if let Some((old_digest, kind, blob)) = tx
                .query_row(
                    "SELECT request_digest,result_kind,result_blob FROM relay_operations WHERE operation_commitment=?1",
                    params![operation_commitment.as_slice()],
                    |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?)),
                )
                .optional()
                .map_err(map_sqlite_error)?
            {
                if array32(&old_digest)? != request_digest || u8::try_from(kind).map_err(|_|RelayError::Database)? != T::KIND {
                    return Err(RelayError::IdempotencyConflict);
                }
                let value = replay_validation(&tx, T::decode(&blob)?)?;
                tx.commit().map_err(map_sqlite_error)?;
                return Ok(value);
            }
            let mut value = match operation(&tx) {
                Ok(value) => value,
                Err(error) => {
                    let _ = tx.rollback();
                    let _ = audit_failure_best_effort(db, &operation_commitment, &error, now);
                    return Err(error);
                }
            };
            let expires = sqlite_i64(
                now.checked_add(retention).ok_or(RelayError::InvalidInput)?,
            )?;
            let rows: i64 = tx
                .query_row("SELECT count(*) FROM relay_operations", [], |row| row.get(0))
                .map_err(map_sqlite_error)?;
            if rows >= sqlite_i64(MAX_OPERATION_ROWS)? {
                return Err(RelayError::QuotaExceeded);
            }
            if let Some(changes_before_ledger) = value.changes_before_ledger() {
                tx.execute_batch("SAVEPOINT telegraph_ledger_probe")
                    .map_err(map_sqlite_error)?;
                let probe_before = tx.total_changes();
                tx.execute(
                    "INSERT INTO relay_operations(operation_commitment,request_digest,result_kind,result_blob,completed_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![operation_commitment.as_slice(), request_digest.as_slice(), i64::from(T::KIND), value.encode(), completed, expires],
                )
                .map_err(map_sqlite_error)?;
                let probed_ledger_changes = tx
                    .total_changes()
                    .checked_sub(probe_before)
                    .ok_or(RelayError::Database)?;
                tx.execute_batch(
                    "ROLLBACK TO SAVEPOINT telegraph_ledger_probe; RELEASE SAVEPOINT telegraph_ledger_probe",
                )
                .map_err(map_sqlite_error)?;
                let expected_total = changes_before_ledger
                    .checked_add(probed_ledger_changes)
                    .ok_or(RelayError::Database)?;
                if expected_total
                    > u64::try_from(MAINTENANCE_BATCH_ROWS).map_err(|_| RelayError::Internal)?
                {
                    return Err(RelayError::Internal);
                }
                value.set_committed_changes(expected_total);
                let real_before = tx.total_changes();
                tx.execute(
                    "INSERT INTO relay_operations(operation_commitment,request_digest,result_kind,result_blob,completed_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![operation_commitment.as_slice(), request_digest.as_slice(), i64::from(T::KIND), value.encode(), completed, expires],
                )
                .map_err(map_sqlite_error)?;
                let real_ledger_changes = tx
                    .total_changes()
                    .checked_sub(real_before)
                    .ok_or(RelayError::Database)?;
                if changes_before_ledger.checked_add(real_ledger_changes)
                    != Some(expected_total)
                {
                    return Err(RelayError::Internal);
                }
            } else {
                tx.execute(
                    "INSERT INTO relay_operations(operation_commitment,request_digest,result_kind,result_blob,completed_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![operation_commitment.as_slice(), request_digest.as_slice(), i64::from(T::KIND), value.encode(), completed, expires],
                )
                .map_err(map_sqlite_error)?;
            }
            tx.commit().map_err(map_sqlite_error)?;
            Ok(value)
        })
        .await
    }

    async fn read<T, F>(&self, operation: F) -> RelayResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> RelayResult<T> + Send + 'static,
    {
        let permit =
            timeout(READ_ADMISSION_DEADLINE, Arc::clone(&self.inner.read_permits).acquire_owned())
                .await
                .map_err(|_| RelayError::DeadlineExceeded)?
                .map_err(|_| RelayError::Busy)?;
        let index = self.inner.next_read.fetch_add(1, Ordering::Relaxed) % self.inner.reads.len();
        let connection = Arc::clone(&self.inner.reads[index]);
        timeout(
            NORMAL_DEADLINE,
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let guard = connection.lock().map_err(|_| RelayError::Internal)?;
                operation(&guard)
            }),
        )
        .await
        .map_err(|_| RelayError::DeadlineExceeded)?
        .map_err(|_| RelayError::Internal)?
    }

    pub async fn reconcile_operation(
        &self,
        operation_id: [u8; 16],
    ) -> RelayResult<Option<OperationReceipt>> {
        let commitment = operation_commitment(&self.inner.secrets, &operation_id)?;
        self.read(move |db| {
            db.query_row(
                "SELECT request_digest,result_kind,result_blob,completed_at,expires_at FROM relay_operations WHERE operation_commitment=?1",
                params![commitment.as_slice()],
                |row| {
                    let request: Vec<u8> = row.get(0)?;
                    let kind = u8::try_from(row.get::<_, i64>(1)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    let blob: Vec<u8> = row.get(2)?;
                    let completed_at = from_sql_i64(row.get::<_, i64>(3)?)?;
                    let expires_at = from_sql_i64(row.get::<_,i64>(4)?)?;
                    if request.len()!=32 || blob.len()>256 || expires_at<completed_at {return Err(rusqlite::Error::InvalidQuery);}
                    Ok(OperationReceipt { result_kind: kind, completed_at })
                },
            )
            .optional()
            .map_err(map_sqlite_error)
        })
        .await
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum AuditEvent {
    PairingCreated = 1,
    PairingClaimed = 2,
    ClaimRejected = 3,
    PairingCancelled = 4,
    PairingExpired = 5,
    PrekeyPublished = 6,
    PrekeyReserved = 7,
    PrekeyConsumed = 8,
    PrekeyBurned = 9,
    ConfirmationPending = 10,
    ConfirmationComplete = 11,
    ConfirmationRejected = 12,
    MailboxSubmitted = 13,
    MailboxFetched = 14,
    MailboxAcked = 15,
    MailboxDeleted = 16,
    MailboxExpired = 17,
    QuotaRejected = 18,
    Cleanup = 19,
    Checkpoint = 20,
    RequestCancelled = 21,
    DeadlineExceeded = 22,
    OutcomeUnknown = 23,
    Busy = 24,
    Failure = 25,
    AuditDropped = 26,
}

fn audit(
    tx: &Transaction<'_>,
    event: AuditEvent,
    opaque_id: &[u8],
    outcome: u8,
    now: u64,
) -> RelayResult<()> {
    let digest =
        if opaque_id.is_empty() { None } else { Some(commitment(AUDIT_DOMAIN, opaque_id)) };
    tx.execute(
        "INSERT INTO relay_audit(event_code,opaque_id_digest,outcome_code,created_at) VALUES(?1,?2,?3,?4)",
        params![i64::from(event as u8), digest.as_ref().map(<[u8; 32]>::as_slice), i64::from(outcome), sqlite_i64(now)?],
    ).map_err(map_sqlite_error)?;
    tx.execute(
        "DELETE FROM relay_audit WHERE rowid IN (SELECT rowid FROM relay_audit ORDER BY created_at DESC,rowid DESC LIMIT 1 OFFSET ?1)",
        params![sqlite_i64(MAX_AUDIT_ROWS)?],
    ).map_err(map_sqlite_error)?;
    Ok(())
}

fn audit_event_for_error(error: &RelayError) -> AuditEvent {
    match error {
        RelayError::QuotaExceeded => AuditEvent::QuotaRejected,
        RelayError::Busy => AuditEvent::Busy,
        RelayError::DeadlineExceeded => AuditEvent::DeadlineExceeded,
        RelayError::OutcomeUnknown { .. } => AuditEvent::OutcomeUnknown,
        _ => AuditEvent::Failure,
    }
}

fn audit_failure_best_effort(
    db: &mut Connection,
    opaque_id: &[u8],
    error: &RelayError,
    now: u64,
) -> bool {
    audit_event_best_effort(db, audit_event_for_error(error), opaque_id, 1, now)
}

fn audit_event_best_effort(
    db: &mut Connection,
    event: AuditEvent,
    opaque_id: &[u8],
    outcome: u8,
    now: u64,
) -> bool {
    if let Ok(tx) = db.transaction_with_behavior(TransactionBehavior::Immediate) {
        if audit(&tx, event, opaque_id, outcome, now).is_ok() {
            return tx.commit().is_ok();
        }
    }
    false
}

fn terminalize_pairing(
    tx: &Transaction<'_>,
    pairing_id: &[u8; 16],
    terminal: PairingState,
    now: u64,
) -> RelayResult<()> {
    if !matches!(
        terminal,
        PairingState::Expired
            | PairingState::Burned
            | PairingState::Cancelled
            | PairingState::Consumed
    ) {
        return Err(RelayError::InvalidInput);
    }
    let current: (String, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) = tx
        .query_row(
            "SELECT state,claimant_id,claimant_nonce,claim_capability_commitment,b_nonce FROM pairing_intents WHERE intent_id=?1",
            params![pairing_id.as_slice()],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        )
        .map_err(map_sqlite_error)?;
    let state = PairingState::parse(&current.0)?;
    validate_pairing_material(
        state,
        current.1.as_deref(),
        current.2.as_deref(),
        current.3.as_deref(),
        current.4.as_deref(),
    )?;
    let current = state;
    if current == terminal {
        return Ok(());
    }
    if !matches!(current, PairingState::Available | PairingState::Claimed) {
        return Err(RelayError::PairingUnavailable);
    }
    let now_i64 = sqlite_i64(now)?;
    tx.execute(
        "INSERT OR IGNORE INTO relay_tombstones(kind,opaque_id,created_at) VALUES('pairing',?1,?2)",
        params![pairing_id.as_slice(), now_i64],
    )
    .map_err(map_sqlite_error)?;
    tx.execute("INSERT OR IGNORE INTO relay_tombstones(kind,opaque_id,created_at) SELECT 'device_code',device_code_commitment,?2 FROM pairing_intents WHERE intent_id=?1", params![pairing_id.as_slice(),now_i64]).map_err(map_sqlite_error)?;
    tx.execute("INSERT OR IGNORE INTO relay_tombstones(kind,opaque_id,created_at) SELECT 'user_code',user_code_commitment,?2 FROM pairing_intents WHERE intent_id=?1", params![pairing_id.as_slice(),now_i64]).map_err(map_sqlite_error)?;
    tx.execute("INSERT OR IGNORE INTO relay_tombstones(kind,opaque_id,created_at) SELECT 'claim',claim_capability_commitment,?2 FROM pairing_intents WHERE intent_id=?1 AND claim_capability_commitment IS NOT NULL", params![pairing_id.as_slice(),now_i64]).map_err(map_sqlite_error)?;
    tx.execute("INSERT OR IGNORE INTO relay_tombstones(kind,opaque_id,created_at) SELECT 'prekey_reservation',reservation_id,?2 FROM public_prekeys WHERE pairing_id=?1 AND reservation_id IS NOT NULL", params![pairing_id.as_slice(),now_i64]).map_err(map_sqlite_error)?;
    let paired_prekeys: Vec<Vec<u8>> = {
        let mut statement = tx
            .prepare("SELECT prekey_id FROM public_prekeys WHERE pairing_id=?1")
            .map_err(map_sqlite_error)?;
        statement
            .query_map(params![pairing_id.as_slice()], |row| row.get(0))
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?
    };
    let mut reserved_prekeys = Vec::new();
    for prekey in paired_prekeys {
        let prekey_id = array16(&prekey)?;
        let validated = load_prekey_by_id(tx, prekey_id)?.ok_or(RelayError::Database)?;
        if validated.pairing_id != Some(*pairing_id) {
            return Err(RelayError::Database);
        }
        if validated.state == PrekeyState::Reserved {
            reserved_prekeys.push(prekey);
        }
    }
    let prekey_state = if terminal == PairingState::Consumed { "consumed" } else { "burned" };
    tx.execute("UPDATE public_prekeys SET status=?2,updated_at=?3 WHERE pairing_id=?1 AND status='reserved'", params![pairing_id.as_slice(),prekey_state,now_i64]).map_err(map_sqlite_error)?;
    for prekey in reserved_prekeys {
        audit(
            tx,
            if terminal == PairingState::Consumed {
                AuditEvent::PrekeyConsumed
            } else {
                AuditEvent::PrekeyBurned
            },
            &prekey,
            0,
            now,
        )?;
    }
    tx.execute(
        "UPDATE confirmation_reports SET tombstoned=1 WHERE intent_id=?1",
        params![pairing_id.as_slice()],
    )
    .map_err(map_sqlite_error)?;
    tx.execute(
        "UPDATE pairing_intents SET state=?2,claimant_id=NULL,claimant_nonce=NULL,claim_capability_commitment=NULL,b_nonce=NULL,updated_at=?3 WHERE intent_id=?1 AND state IN ('available','claimed')",
        params![pairing_id.as_slice(), terminal.as_str(), now_i64],
    ).map_err(map_sqlite_error)?;
    if terminal == PairingState::Expired {
        audit(tx, AuditEvent::PairingExpired, pairing_id, 0, now)?;
    }
    Ok(())
}

fn source_attempts_exhausted(
    tx: &Transaction<'_>,
    source: &[u8; 16],
    now: i64,
) -> RelayResult<bool> {
    let row: Option<(i64, i64)> = tx
        .query_row(
            "SELECT attempts,expires_at FROM claim_rate_limits WHERE source_id=?1",
            params![source.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_sqlite_error)?;
    match row {
        Some((attempts, expires)) => {
            if !(0..=i64::from(MAX_CLAIM_ATTEMPTS)).contains(&attempts) || expires < 0 {
                return Err(RelayError::Database);
            }
            Ok(expires > now && attempts >= i64::from(MAX_CLAIM_ATTEMPTS))
        }
        None => Ok(false),
    }
}

fn charge_source_attempt(
    tx: &Transaction<'_>,
    source: &[u8; 16],
    now: i64,
    ttl: u64,
) -> RelayResult<()> {
    tx.execute("DELETE FROM claim_rate_limits WHERE source_id IN (SELECT source_id FROM claim_rate_limits WHERE expires_at<=?1 ORDER BY expires_at,source_id LIMIT ?2)", params![now,MAINTENANCE_BATCH_ROWS])
        .map_err(map_sqlite_error)?;
    let rows: i64 = tx
        .query_row("SELECT count(*) FROM claim_rate_limits", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let known: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM claim_rate_limits WHERE source_id=?1)",
            params![source.as_slice()],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    if !known && rows >= sqlite_i64(MAX_SOURCE_ROWS)? {
        return Err(RelayError::QuotaExceeded);
    }
    let expires = now.checked_add(sqlite_i64(ttl)?).ok_or(RelayError::InvalidInput)?;
    tx.execute(
        "INSERT INTO claim_rate_limits(source_id,attempts,window_started,expires_at) VALUES(?1,1,?2,?3) ON CONFLICT(source_id) DO UPDATE SET attempts=CASE WHEN claim_rate_limits.expires_at<=?2 THEN 1 ELSE min(claim_rate_limits.attempts+1,5) END,window_started=CASE WHEN claim_rate_limits.expires_at<=?2 THEN ?2 ELSE claim_rate_limits.window_started END,expires_at=CASE WHEN claim_rate_limits.expires_at<=?2 THEN ?3 ELSE claim_rate_limits.expires_at END",
        params![source.as_slice(),now,expires],
    ).map_err(map_sqlite_error)?;
    Ok(())
}

fn charge_pairing_attempt(
    tx: &Transaction<'_>,
    intent: &[u8; 16],
    attempts: u32,
    now: u64,
) -> RelayResult<()> {
    let next = attempts.saturating_add(1).min(MAX_CLAIM_ATTEMPTS);
    tx.execute(
        "UPDATE pairing_intents SET attempts=?2,updated_at=?3 WHERE intent_id=?1",
        params![intent.as_slice(), i64::from(next), sqlite_i64(now)?],
    )
    .map_err(map_sqlite_error)?;
    if next >= MAX_CLAIM_ATTEMPTS {
        terminalize_pairing(tx, intent, PairingState::Burned, now)?;
    }
    Ok(())
}

fn matching_delivery_state(
    tx: &Transaction<'_>,
    envelope: &OpaqueEnvelope,
    digest: &[u8; 32],
) -> RelayResult<Option<TransportState>> {
    let live: Option<(i64,i64,Vec<u8>,i64,i64,String,Vec<u8>,i64)> = tx.query_row(
        "SELECT protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,status,ciphertext,payload_bytes FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
        params![&envelope.mailbox_id,&envelope.delivery_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional().map_err(map_sqlite_error)?;
    if let Some(row) = live {
        if usize::try_from(row.7).map_err(|_| RelayError::Database)? != row.6.len()
            || row.6.len() > MAX_CIPHERTEXT_BYTES
            || commitment(b"telegraph/opaque-delivery/v1", &row.6) != array32(&row.2)?
        {
            return Err(RelayError::Database);
        }
        let metadata = (row.0, row.1, row.2, row.3, row.4, row.5);
        if delivery_metadata_matches(&metadata, envelope, digest)? {
            return Ok(Some(TransportState::parse(&metadata.5)?));
        }
        return Err(RelayError::IdempotencyConflict);
    }
    let tombstone: Option<(i64,i64,Vec<u8>,i64,i64,String)> = tx.query_row(
        "SELECT protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,status FROM mailbox_tombstones WHERE mailbox_id=?1 AND delivery_id=?2",
        params![&envelope.mailbox_id,&envelope.delivery_id],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
    ).optional().map_err(map_sqlite_error)?;
    if let Some(row) = tombstone {
        if delivery_metadata_matches(&row, envelope, digest)? {
            return Ok(Some(TransportState::parse(&row.5)?));
        }
        return Err(RelayError::IdempotencyConflict);
    }
    Ok(None)
}

fn delivery_metadata_matches(
    row: &(i64, i64, Vec<u8>, i64, i64, String),
    envelope: &OpaqueEnvelope,
    digest: &[u8; 32],
) -> RelayResult<bool> {
    let major = u16::try_from(row.0).map_err(|_| RelayError::Database)?;
    let minor = u16::try_from(row.1).map_err(|_| RelayError::Database)?;
    let version = ProtocolVersion::new(major, minor);
    let size = usize::try_from(row.3).map_err(|_| RelayError::Database)?;
    let expires = from_sql_i64(row.4).map_err(map_sqlite_error)?;
    if !version.is_supported() || size == 0 || size > MAX_OUTER_ENVELOPE_BYTES {
        return Err(RelayError::Database);
    }
    Ok(version == envelope.protocol_version
        && array32(&row.2)? == *digest
        && size == envelope.size
        && expires == envelope.expires_at)
}

fn move_mail_to_tombstone(
    tx: &Transaction<'_>,
    mailbox: &[u8],
    delivery: &[u8],
    target: TransportState,
    now: u64,
) -> RelayResult<()> {
    if !matches!(target, TransportState::Expired | TransportState::Deleted) {
        return Err(RelayError::InvalidInput);
    }
    load_live_state(tx, mailbox, delivery)?.ok_or(RelayError::Database)?;
    let changed = tx.execute(
        "INSERT INTO mailbox_tombstones(mailbox_id,delivery_id,protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,status,created_at,updated_at) SELECT mailbox_id,delivery_id,protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,?3,created_at,?4 FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
        params![mailbox,delivery,target.as_str(),sqlite_i64(now)?],
    ).map_err(map_sqlite_error)?;
    if changed != 1 {
        return Err(RelayError::Database);
    }
    tx.execute(
        "DELETE FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
        params![mailbox, delivery],
    )
    .map_err(map_sqlite_error)?;
    Ok(())
}

fn load_live_state(
    db: &Connection,
    mailbox: &[u8],
    delivery: &[u8],
) -> RelayResult<Option<(TransportState, u64)>> {
    validate_id(mailbox).map_err(|_| RelayError::Database)?;
    validate_id(delivery).map_err(|_| RelayError::Database)?;
    let row: Option<(i64,i64,Vec<u8>,Vec<u8>,i64,i64,i64,String)> = db.query_row(
        "SELECT protocol_major,protocol_minor,ciphertext,payload_digest,payload_bytes,envelope_size,expires_at,status FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
        params![mailbox,delivery],
        |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional().map_err(map_sqlite_error)?;
    let Some((major, minor, ciphertext, digest, payload_bytes, size, expires, state)) = row else {
        return Ok(None);
    };
    let version = ProtocolVersion::new(
        u16::try_from(major).map_err(|_| RelayError::Database)?,
        u16::try_from(minor).map_err(|_| RelayError::Database)?,
    );
    if !version.is_supported()
        || ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || usize::try_from(payload_bytes).map_err(|_| RelayError::Database)? != ciphertext.len()
        || commitment(b"telegraph/opaque-delivery/v1", &ciphertext) != array32(&digest)?
    {
        return Err(RelayError::Database);
    }
    let expires = from_sql_i64(expires).map_err(map_sqlite_error)?;
    let canonical = Envelope::new(
        version,
        MailboxId::new(mailbox.to_vec()).map_err(|_| RelayError::Database)?,
        DeliveryId::new(delivery.to_vec()).map_err(|_| RelayError::Database)?,
        ciphertext,
        expires,
    )
    .map_err(|_| RelayError::Database)?
    .to_bytes()
    .map_err(|_| RelayError::Database)?;
    if usize::try_from(size).map_err(|_| RelayError::Database)? != canonical.len() {
        return Err(RelayError::Database);
    }
    let state = TransportState::parse(&state)?;
    if !matches!(state, TransportState::Pending | TransportState::Fetched | TransportState::Acked) {
        return Err(RelayError::Database);
    }
    Ok(Some((state, expires)))
}

fn load_live_metadata(
    db: &Connection,
    mailbox: &[u8],
    delivery: &[u8],
) -> RelayResult<Option<(TransportState, u64)>> {
    validate_id(mailbox).map_err(|_| RelayError::Database)?;
    validate_id(delivery).map_err(|_| RelayError::Database)?;
    let row: Option<(i64, i64, Vec<u8>, i64, i64, i64, String, i64)> = db
        .query_row(
            "SELECT protocol_major,protocol_minor,payload_digest,payload_bytes,length(ciphertext),envelope_size,status,expires_at FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
            params![mailbox, delivery],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(map_sqlite_error)?;
    let Some((
        major,
        minor,
        digest,
        payload_bytes,
        ciphertext_bytes,
        envelope_size,
        status,
        expires_at,
    )) = row
    else {
        return Ok(None);
    };
    let version = ProtocolVersion::new(
        u16::try_from(major).map_err(|_| RelayError::Database)?,
        u16::try_from(minor).map_err(|_| RelayError::Database)?,
    );
    let payload_bytes = usize::try_from(payload_bytes).map_err(|_| RelayError::Database)?;
    let ciphertext_bytes = usize::try_from(ciphertext_bytes).map_err(|_| RelayError::Database)?;
    let envelope_size = usize::try_from(envelope_size).map_err(|_| RelayError::Database)?;
    let expires_at = from_sql_i64(expires_at).map_err(map_sqlite_error)?;
    let state = TransportState::parse(&status)?;
    let expected_size = Envelope::new(
        version,
        MailboxId::new(mailbox.to_vec()).map_err(|_| RelayError::Database)?,
        DeliveryId::new(delivery.to_vec()).map_err(|_| RelayError::Database)?,
        vec![0; payload_bytes],
        expires_at,
    )
    .map_err(|_| RelayError::Database)?
    .to_bytes()
    .map_err(|_| RelayError::Database)?
    .len();
    if !version.is_supported()
        || array32(&digest).is_err()
        || payload_bytes > MAX_CIPHERTEXT_BYTES
        || ciphertext_bytes != payload_bytes
        || envelope_size != expected_size
        || !matches!(
            state,
            TransportState::Pending | TransportState::Fetched | TransportState::Acked
        )
    {
        return Err(RelayError::Database);
    }
    Ok(Some((state, expires_at)))
}

fn load_fetch_record(
    db: &Connection,
    operation_commitment: &[u8; 32],
    request_digest: &[u8; 32],
    mailbox: &[u8],
    now: u64,
) -> RelayResult<FetchRecord> {
    validate_id(mailbox).map_err(|_| RelayError::Database)?;
    let receipt: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) = db
        .query_row(
            "SELECT request_digest,mailbox_id,selection_blob,selection_digest,expires_at FROM fetch_receipts WHERE operation_commitment=?1",
            params![operation_commitment.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(map_sqlite_error)?;
    let expires_at = from_sql_i64(receipt.4).map_err(map_sqlite_error)?;
    if array32(&receipt.0)? != *request_digest
        || receipt.1 != mailbox
        || array32(&receipt.3)? != commitment(b"telegraph/fetch-selection/v1", &receipt.2)
        || expires_at < now
    {
        return Err(RelayError::Database);
    }
    FetchRecord::decode(&receipt.2)
}

fn load_stored_envelope(
    db: &Connection,
    mailbox: &[u8],
    delivery: &[u8],
) -> RelayResult<Option<StoredEnvelope>> {
    validate_id(mailbox).map_err(|_| RelayError::Database)?;
    validate_id(delivery).map_err(|_| RelayError::Database)?;
    let row: Option<(i64,i64,Vec<u8>,Vec<u8>,i64,i64,i64,String)> = db.query_row(
        "SELECT protocol_major,protocol_minor,ciphertext,payload_digest,payload_bytes,envelope_size,expires_at,status FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
        params![mailbox,delivery],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
    ).optional().map_err(map_sqlite_error)?;
    let Some((major, minor, ciphertext, digest, payload_bytes, size, expires, status)) = row else {
        return Ok(None);
    };
    let version = ProtocolVersion::new(
        u16::try_from(major).map_err(|_| RelayError::Database)?,
        u16::try_from(minor).map_err(|_| RelayError::Database)?,
    );
    if !version.is_supported()
        || ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || usize::try_from(payload_bytes).map_err(|_| RelayError::Database)? != ciphertext.len()
        || commitment(b"telegraph/opaque-delivery/v1", &ciphertext) != array32(&digest)?
    {
        return Err(RelayError::Database);
    }
    let expires = from_sql_i64(expires).map_err(map_sqlite_error)?;
    let canonical = Envelope::new(
        version,
        MailboxId::new(mailbox.to_vec()).map_err(|_| RelayError::Database)?,
        DeliveryId::new(delivery.to_vec()).map_err(|_| RelayError::Database)?,
        ciphertext.clone(),
        expires,
    )
    .map_err(|_| RelayError::Database)?
    .to_bytes()
    .map_err(|_| RelayError::Database)?;
    if usize::try_from(size).map_err(|_| RelayError::Database)? != canonical.len() {
        return Err(RelayError::Database);
    }
    let state = TransportState::parse(&status)?;
    if !matches!(state, TransportState::Pending | TransportState::Fetched | TransportState::Acked) {
        return Err(RelayError::Database);
    }
    Ok(Some(StoredEnvelope {
        envelope: OpaqueEnvelope {
            mailbox_id: mailbox.to_vec(),
            delivery_id: delivery.to_vec(),
            protocol_version: version,
            ciphertext,
            size: canonical.len(),
            expires_at: expires,
        },
        state,
    }))
}

fn load_tombstone_state(
    db: &Connection,
    mailbox: &[u8],
    delivery: &[u8],
) -> RelayResult<Option<TransportState>> {
    validate_id(mailbox).map_err(|_| RelayError::Database)?;
    validate_id(delivery).map_err(|_| RelayError::Database)?;
    let row: Option<(Vec<u8>,Vec<u8>,i64,i64,Vec<u8>,i64,i64,String,i64,i64)> = db.query_row(
        "SELECT mailbox_id,delivery_id,protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,status,created_at,updated_at FROM mailbox_tombstones WHERE mailbox_id=?1 AND delivery_id=?2",
        params![mailbox,delivery],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?)),
    ).optional().map_err(map_sqlite_error)?;
    let Some((
        stored_mailbox,
        stored_delivery,
        major,
        minor,
        digest,
        size,
        expires,
        status,
        created,
        updated,
    )) = row
    else {
        return Ok(None);
    };
    if stored_mailbox != mailbox || stored_delivery != delivery {
        return Err(RelayError::Database);
    }
    let version = ProtocolVersion::new(
        u16::try_from(major).map_err(|_| RelayError::Database)?,
        u16::try_from(minor).map_err(|_| RelayError::Database)?,
    );
    let size = usize::try_from(size).map_err(|_| RelayError::Database)?;
    let expires = from_sql_i64(expires).map_err(map_sqlite_error)?;
    let created = from_sql_i64(created).map_err(map_sqlite_error)?;
    let updated = from_sql_i64(updated).map_err(map_sqlite_error)?;
    let state = TransportState::parse(&status)?;
    if !version.is_supported()
        || array32(&digest).is_err()
        || size == 0
        || size > MAX_OUTER_ENVELOPE_BYTES
        || expires == 0
        || updated < created
        || !matches!(state, TransportState::Expired | TransportState::Deleted)
    {
        return Err(RelayError::Database);
    }
    Ok(Some(state))
}

fn expire_mailbox_rows(
    tx: &Transaction<'_>,
    mailbox: Option<&[u8]>,
    now: u64,
    policy: RelayStorePolicy,
    budget: &mut MaintenanceBudget,
    fail_when_blocked: bool,
) -> RelayResult<u64> {
    if budget.is_empty() {
        return Ok(0);
    }
    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        if let Some(mailbox) = mailbox {
            let mut statement = tx.prepare("SELECT mailbox_id,delivery_id FROM opaque_mailbox WHERE mailbox_id=?1 AND expires_at<=?2 ORDER BY expires_at,delivery_id LIMIT ?3").map_err(map_sqlite_error)?;
            statement
                .query_map(params![mailbox, sqlite_i64(now)?, budget.sql_limit()?], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(map_sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(map_sqlite_error)?
        } else {
            let mut statement = tx
                .prepare("SELECT mailbox_id,delivery_id FROM opaque_mailbox WHERE expires_at<=?1 ORDER BY expires_at,mailbox_id,delivery_id LIMIT ?2")
                .map_err(map_sqlite_error)?;
            statement
                .query_map(params![sqlite_i64(now)?, budget.sql_limit()?], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(map_sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(map_sqlite_error)?
        }
    };
    let mut processed = 0usize;
    for (mailbox, delivery) in &rows {
        if budget.is_empty() {
            break;
        }
        match budget.attempt(tx, |candidate| {
            trim_tombstones(candidate, mailbox, policy, now)?;
            move_mail_to_tombstone(candidate, mailbox, delivery, TransportState::Expired, now)?;
            audit(candidate, AuditEvent::MailboxExpired, delivery, 0, now)
        })? {
            MaintenanceAttempt::Applied(()) => {
                processed = processed.checked_add(1).ok_or(RelayError::Database)?;
            }
            MaintenanceAttempt::BudgetExhausted => {
                if fail_when_blocked {
                    return Err(RelayError::QuotaExceeded);
                }
                break;
            }
            MaintenanceAttempt::ResourceBlocked => {
                if fail_when_blocked {
                    return Err(RelayError::QuotaExceeded);
                }
                continue;
            }
        }
    }
    u64::try_from(processed).map_err(|_| RelayError::Database)
}

fn expire_prekeys(
    tx: &Transaction<'_>,
    now: u64,
    budget: &mut MaintenanceBudget,
) -> RelayResult<u64> {
    if budget.is_empty() {
        return Ok(0);
    }
    let ids: Vec<Vec<u8>> = {
        let mut statement = tx
            .prepare(
                "SELECT prekey_id FROM public_prekeys WHERE status IN ('available','reserved') AND expires_at<=?1 ORDER BY expires_at,prekey_id LIMIT ?2",
            )
            .map_err(map_sqlite_error)?;
        statement
            .query_map(params![sqlite_i64(now)?, budget.sql_limit()?], |row| row.get(0))
            .map_err(map_sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_sqlite_error)?
    };
    let mut processed = 0usize;
    for raw_id in &ids {
        if budget.is_empty() {
            break;
        }
        let id = array16(raw_id)?;
        match budget.attempt(tx, |candidate| {
            let row = load_prekey_by_id(candidate, id)?.ok_or(RelayError::Database)?;
            match row.state {
                PrekeyState::Reserved => {
                    let pairing = row.pairing_id.ok_or(RelayError::Database)?;
                    terminalize_pairing(candidate, &pairing, PairingState::Expired, now)
                }
                PrekeyState::Available => {
                    let changed = candidate
                        .execute(
                            "UPDATE public_prekeys SET status='burned',updated_at=?2 WHERE prekey_id=?1 AND status='available'",
                            params![id.as_slice(), sqlite_i64(now)?],
                        )
                        .map_err(map_sqlite_error)?;
                    if changed != 1 {
                        return Err(RelayError::Database);
                    }
                    audit(candidate, AuditEvent::PrekeyBurned, &id, 1, now)
                }
                _ => Err(RelayError::Database),
            }
        })? {
            MaintenanceAttempt::Applied(()) => {
                processed = processed.checked_add(1).ok_or(RelayError::Database)?;
            }
            MaintenanceAttempt::BudgetExhausted => break,
            MaintenanceAttempt::ResourceBlocked => continue,
        }
    }
    u64::try_from(processed).map_err(|_| RelayError::Database)
}

fn trim_tombstones(
    tx: &Transaction<'_>,
    mailbox: &[u8],
    policy: RelayStorePolicy,
    now: u64,
) -> RelayResult<()> {
    let retention_cutoff = sqlite_i64(now.saturating_sub(policy.tombstone_retention_secs))?;
    let now_i64 = sqlite_i64(now)?;
    let per_mailbox: i64 = tx
        .query_row(
            "SELECT count(*) FROM mailbox_tombstones WHERE mailbox_id=?1",
            params![mailbox],
            |row| row.get(0),
        )
        .map_err(map_sqlite_error)?;
    let mailbox_limit = sqlite_i64(policy.mailbox_max_tombstones)?;
    if per_mailbox >= mailbox_limit {
        let remove = per_mailbox
            .checked_sub(mailbox_limit)
            .and_then(|excess| excess.checked_add(1))
            .ok_or(RelayError::Database)?;
        let remove = remove.min(MAINTENANCE_BATCH_ROWS);
        tx.execute("DELETE FROM mailbox_tombstones WHERE rowid IN (SELECT rowid FROM mailbox_tombstones WHERE mailbox_id=?1 AND expires_at<=?2 AND updated_at<=?3 ORDER BY updated_at,rowid LIMIT ?4)", params![mailbox,now_i64,retention_cutoff,remove]).map_err(map_sqlite_error)?;
        let after: i64 = tx
            .query_row(
                "SELECT count(*) FROM mailbox_tombstones WHERE mailbox_id=?1",
                params![mailbox],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)?;
        if after >= mailbox_limit {
            return Err(RelayError::QuotaExceeded);
        }
    }
    let global: i64 = tx
        .query_row("SELECT count(*) FROM mailbox_tombstones", [], |row| row.get(0))
        .map_err(map_sqlite_error)?;
    let global_limit = sqlite_i64(policy.global_max_tombstones)?;
    if global >= global_limit {
        let remove = global
            .checked_sub(global_limit)
            .and_then(|excess| excess.checked_add(1))
            .ok_or(RelayError::Database)?;
        let remove = remove.min(MAINTENANCE_BATCH_ROWS);
        tx.execute("DELETE FROM mailbox_tombstones WHERE rowid IN (SELECT rowid FROM mailbox_tombstones WHERE expires_at<=?1 AND updated_at<=?2 ORDER BY updated_at,rowid LIMIT ?3)", params![now_i64,retention_cutoff,remove]).map_err(map_sqlite_error)?;
        let after: i64 = tx
            .query_row("SELECT count(*) FROM mailbox_tombstones", [], |row| row.get(0))
            .map_err(map_sqlite_error)?;
        if after >= global_limit {
            return Err(RelayError::QuotaExceeded);
        }
    }
    Ok(())
}

impl RelayOpaqueStore {
    pub async fn submit_envelope(
        &self,
        envelope: Envelope,
        now: impl Into<StoreTime>,
    ) -> RelayResult<TransportState> {
        let now = now.into().0;
        let bytes = envelope.to_bytes().map_err(map_protocol_error)?;
        if bytes.len() > MAX_OUTER_ENVELOPE_BYTES {
            return Err(RelayError::EnvelopeTooLarge);
        }
        self.submit_opaque(
            OpaqueEnvelope {
                mailbox_id: envelope.mailbox_id().as_bytes().to_vec(),
                delivery_id: envelope.delivery_id().as_bytes().to_vec(),
                protocol_version: envelope.protocol_version(),
                ciphertext: envelope.ciphertext().to_vec(),
                size: bytes.len(),
                expires_at: envelope.expires_at(),
            },
            StoreTime(now),
        )
        .await
    }

    pub async fn submit_opaque(
        &self,
        mut envelope: OpaqueEnvelope,
        now: impl Into<StoreTime>,
    ) -> RelayResult<TransportState> {
        let now = now.into().0;
        validate_opaque_input(&envelope, now, self.inner.policy.mailbox_ttl_secs)?;
        let canonical = Envelope::new(
            envelope.protocol_version,
            MailboxId::new(envelope.mailbox_id.clone()).map_err(map_protocol_error)?,
            DeliveryId::new(envelope.delivery_id.clone()).map_err(map_protocol_error)?,
            envelope.ciphertext.clone(),
            envelope.expires_at,
        )
        .map_err(map_protocol_error)?
        .to_bytes()
        .map_err(map_protocol_error)?;
        envelope.size = canonical.len();
        if envelope.size > MAX_OUTER_ENVELOPE_BYTES {
            return Err(RelayError::EnvelopeTooLarge);
        }
        let payload_digest = commitment(b"telegraph/opaque-delivery/v1", &envelope.ciphertext);
        let probe = envelope.clone();
        let probe_digest = payload_digest;
        if let Some(state) = self.read(move |db| {
            let live: Option<(i64,i64,Vec<u8>,i64,i64,String,Vec<u8>,i64)> = db.query_row(
                "SELECT protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,status,ciphertext,payload_bytes FROM opaque_mailbox WHERE mailbox_id=?1 AND delivery_id=?2",
                params![&probe.mailbox_id,&probe.delivery_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
            ).optional().map_err(map_sqlite_error)?;
            if let Some(row) = live {
                if usize::try_from(row.7).map_err(|_|RelayError::Database)? != row.6.len() || row.6.len()>MAX_CIPHERTEXT_BYTES || commitment(b"telegraph/opaque-delivery/v1",&row.6)!=array32(&row.2)? { return Err(RelayError::Database); }
                let metadata=(row.0,row.1,row.2,row.3,row.4,row.5);
                if from_sql_i64(metadata.4).map_err(map_sqlite_error)? <= now { return Ok(None); }
                return if delivery_metadata_matches(&metadata,&probe,&probe_digest)? { Ok(Some(TransportState::parse(&metadata.5)?)) } else { Err(RelayError::IdempotencyConflict) };
            }
            let tomb: Option<(i64,i64,Vec<u8>,i64,i64,String)> = db.query_row(
                "SELECT protocol_major,protocol_minor,payload_digest,envelope_size,expires_at,status FROM mailbox_tombstones WHERE mailbox_id=?1 AND delivery_id=?2",
                params![&probe.mailbox_id,&probe.delivery_id],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            ).optional().map_err(map_sqlite_error)?;
            if let Some(row) = tomb { return if delivery_metadata_matches(&row,&probe,&probe_digest)? { Ok(Some(TransportState::parse(&row.5)?)) } else { Err(RelayError::IdempotencyConflict) }; }
            Ok(None)
        }).await? { return Ok(state); }
        let operation_id =
            operation_key(b"submit-envelope", &[&envelope.mailbox_id, &envelope.delivery_id]);
        let request = request_digest(
            b"submit-envelope",
            &[
                &envelope.mailbox_id,
                &envelope.delivery_id,
                payload_digest.as_slice(),
                &envelope.protocol_version.major().to_be_bytes(),
                &envelope.protocol_version.minor().to_be_bytes(),
                &envelope.size.to_be_bytes(),
                &envelope.expires_at.to_be_bytes(),
            ],
        );
        let policy = self.inner.policy;
        self.write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
            let mut maintenance = MaintenanceBudget::with_reserved_rows(20)?;
            expire_mailbox_rows(
                tx,
                Some(&envelope.mailbox_id),
                now,
                policy,
                &mut maintenance,
                true,
            )?;
            if let Some(state) = matching_delivery_state(tx, &envelope, &payload_digest)? {
                return Ok(state);
            }
            let now_i64 = sqlite_i64(now)?;
            tx.execute(
                "INSERT INTO mailbox_quotas(mailbox_id,max_live_rows,max_live_bytes,max_tombstones,updated_at) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(mailbox_id) DO UPDATE SET max_live_rows=excluded.max_live_rows,max_live_bytes=excluded.max_live_bytes,max_tombstones=excluded.max_tombstones,updated_at=excluded.updated_at",
                params![&envelope.mailbox_id, sqlite_i64(policy.mailbox_max_live_rows)?, sqlite_i64(policy.mailbox_max_live_bytes)?, sqlite_i64(policy.mailbox_max_tombstones)?, now_i64],
            ).map_err(map_sqlite_error)?;
            let (max_rows, max_bytes): (i64, i64) = tx.query_row(
                "SELECT max_live_rows,max_live_bytes FROM mailbox_quotas WHERE mailbox_id=?1",
                params![&envelope.mailbox_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(map_sqlite_error)?;
            let (live_rows, live_bytes): (i64, i64) = tx.query_row(
                "SELECT count(*),coalesce(sum(envelope_size),0) FROM opaque_mailbox WHERE mailbox_id=?1",
                params![&envelope.mailbox_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(map_sqlite_error)?;
            let payload_bytes = sqlite_usize(envelope.ciphertext.len())?;
            let envelope_bytes = sqlite_usize(envelope.size)?;
            if live_rows >= max_rows || live_bytes.checked_add(envelope_bytes).is_none_or(|total| total > max_bytes)
            {
                audit(tx, AuditEvent::QuotaRejected, &envelope.mailbox_id, 0, now)?;
                return Err(RelayError::QuotaExceeded);
            }
            let (global_rows, global_bytes): (i64, i64) = tx.query_row("SELECT count(*),coalesce(sum(envelope_size),0) FROM opaque_mailbox", [], |row| Ok((row.get(0)?, row.get(1)?))).map_err(map_sqlite_error)?;
            let global_max_bytes = sqlite_i64(policy.global_max_live_bytes)?;
            if global_rows >= sqlite_i64(policy.global_max_live_rows)?
                || global_bytes.checked_add(envelope_bytes).is_none_or(|total| total > global_max_bytes)
            {
                audit(tx, AuditEvent::QuotaRejected, &envelope.mailbox_id, 1, now)?;
                return Err(RelayError::QuotaExceeded);
            }
            tx.execute(
                "INSERT INTO opaque_mailbox(mailbox_id,delivery_id,protocol_major,protocol_minor,ciphertext,payload_digest,payload_bytes,envelope_size,expires_at,status,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',?10,?10)",
                params![&envelope.mailbox_id, &envelope.delivery_id, i64::from(envelope.protocol_version.major()), i64::from(envelope.protocol_version.minor()), &envelope.ciphertext, payload_digest.as_slice(), payload_bytes, sqlite_usize(envelope.size)?, sqlite_i64(envelope.expires_at)?, now_i64],
            ).map_err(map_sqlite_error)?;
            audit(tx, AuditEvent::MailboxSubmitted, &envelope.delivery_id, 0, now)?;
            Ok(TransportState::Pending)
        }).await
    }

    /// Returns new pending rows before previously fetched rows. `operation_id`
    /// durably binds the selected delivery IDs so an outcome-unknown retry after
    /// restart never makes a different selection. A replay never substitutes a
    /// different message: selections which have since settled are reported in
    /// `FetchResult::settled` without returning ciphertext.
    pub async fn fetch_mailbox(
        &self,
        operation_id: [u8; 16],
        mailbox_id: &[u8],
        limit: u32,
        now: impl Into<StoreTime>,
    ) -> RelayResult<FetchResult> {
        let now = now.into().0;
        validate_id(mailbox_id)?;
        if limit == 0 || limit > 100 {
            return Err(RelayError::InvalidInput);
        }
        let mailbox = mailbox_id.to_vec();
        let policy = self.inner.policy;
        let request = request_digest(b"fetch-mailbox", &[&mailbox, &limit.to_be_bytes()]);
        let operation_commitment = operation_commitment(&self.inner.secrets, &operation_id)?;
        let replay_mailbox = mailbox.clone();
        let write_mailbox = mailbox.clone();
        let receipt_expiry =
            now.checked_add(policy.operation_retention_secs).ok_or(RelayError::InvalidInput)?;
        self.write_operation_validated(operation_id, request, now, NORMAL_DEADLINE, move |tx, ()| {
            let record = load_fetch_record(
                tx,
                &operation_commitment,
                &request,
                &replay_mailbox,
                now,
            )?;
            let mut maintenance = MaintenanceBudget::with_reserved_rows(0)?;
            for delivery in record.delivery_ids {
                if let Some((state, expires_at)) =
                    load_live_metadata(tx, &replay_mailbox, &delivery)?
                {
                    if expires_at <= now {
                        match maintenance.attempt(tx, |candidate| {
                            trim_tombstones(candidate, &replay_mailbox, policy, now)?;
                            move_mail_to_tombstone(
                                candidate,
                                &replay_mailbox,
                                &delivery,
                                TransportState::Expired,
                                now,
                            )?;
                            audit(candidate, AuditEvent::MailboxExpired, &delivery, 0, now)
                        })? {
                            MaintenanceAttempt::Applied(()) => {}
                            MaintenanceAttempt::BudgetExhausted
                            | MaintenanceAttempt::ResourceBlocked => {
                                return Err(RelayError::QuotaExceeded);
                            }
                        }
                    } else if matches!(state, TransportState::Pending | TransportState::Fetched) {
                        load_stored_envelope(tx, &replay_mailbox, &delivery)?
                            .ok_or(RelayError::Database)?;
                    }
                } else if load_tombstone_state(tx, &replay_mailbox, &delivery)?.is_none() {
                    return Err(RelayError::Database);
                }
            }
            Ok(())
        }, move |tx| {
            let mut maintenance = MaintenanceBudget::with_reserved_rows(250)?;
            expire_mailbox_rows(
                tx,
                Some(&write_mailbox),
                now,
                policy,
                &mut maintenance,
                true,
            )?;
            let invalid_states: i64 = tx.query_row("SELECT count(*) FROM opaque_mailbox WHERE mailbox_id=?1 AND status NOT IN ('pending','fetched','acked')", params![&mailbox], |row| row.get(0)).map_err(map_sqlite_error)?;
            if invalid_states != 0 { return Err(RelayError::Database); }
            let has_pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM opaque_mailbox WHERE mailbox_id=?1 AND status='pending' AND expires_at>?2)", params![&write_mailbox,sqlite_i64(now)?], |row| row.get(0)).map_err(map_sqlite_error)?;
            let selected_state = if has_pending { "pending" } else { "fetched" };
            let delivery_ids: Vec<Vec<u8>> = {
                let mut statement = tx.prepare(
                    "SELECT delivery_id FROM opaque_mailbox WHERE mailbox_id=?1 AND status=?2 AND expires_at>?3 ORDER BY delivery_id LIMIT ?4",
                ).map_err(map_sqlite_error)?;
                statement.query_map(params![&write_mailbox,selected_state,sqlite_i64(now)?,i64::from(limit)], |row| row.get(0)).map_err(map_sqlite_error)?.collect::<Result<Vec<_>,_>>().map_err(map_sqlite_error)?
            };
            for delivery_id in &delivery_ids {
                let row = load_stored_envelope(tx, &write_mailbox, delivery_id)?.ok_or(RelayError::Database)?;
                if row.envelope.delivery_id != *delivery_id
                    || !matches!(row.state, TransportState::Pending | TransportState::Fetched)
                {
                    return Err(RelayError::Database);
                }
                tx.execute("UPDATE opaque_mailbox SET status='fetched',updated_at=?3 WHERE mailbox_id=?1 AND delivery_id=?2 AND status='pending'", params![&write_mailbox, &row.envelope.delivery_id, sqlite_i64(now)?]).map_err(map_sqlite_error)?;
            }
            let selection_blob = FetchRecord { delivery_ids }.encode();
            let selection_digest = commitment(b"telegraph/fetch-selection/v1",&selection_blob);
            tx.execute("INSERT INTO fetch_receipts(operation_commitment,request_digest,mailbox_id,selection_blob,selection_digest,created_at,expires_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![operation_commitment.as_slice(),request.as_slice(),&write_mailbox,selection_blob,selection_digest.as_slice(),sqlite_i64(now)?,sqlite_i64(receipt_expiry)?]).map_err(map_sqlite_error)?;
            audit(tx, AuditEvent::MailboxFetched, &write_mailbox, 0, now)?;
            Ok(())
        }).await?;
        let result_mailbox = mailbox_id.to_vec();
        self.read(move |db| {
            let record =
                load_fetch_record(db, &operation_commitment, &request, &result_mailbox, now)?;
            let mut envelopes = Vec::with_capacity(record.delivery_ids.len());
            let mut settled = Vec::with_capacity(record.delivery_ids.len());
            for delivery in record.delivery_ids {
                if let Some((state, expires_at)) =
                    load_live_metadata(db, &result_mailbox, &delivery)?
                {
                    if expires_at <= now {
                        return Err(RelayError::Database);
                    }
                    if state == TransportState::Acked {
                        settled.push(SettledDelivery {
                            delivery_id: delivery,
                            state: TransportState::Acked,
                        });
                    } else {
                        let mut row = load_stored_envelope(db, &result_mailbox, &delivery)?
                            .ok_or(RelayError::Database)?;
                        row.state = TransportState::Fetched;
                        envelopes.push(row);
                    }
                } else {
                    let state = load_tombstone_state(db, &result_mailbox, &delivery)?
                        .ok_or(RelayError::Database)?;
                    settled.push(SettledDelivery { delivery_id: delivery, state });
                }
            }
            Ok(FetchResult { envelopes, settled })
        })
        .await
    }

    pub async fn acknowledge_transport(
        &self,
        mailbox_id: &[u8],
        delivery_id: &[u8],
        now: impl Into<StoreTime>,
    ) -> RelayResult<TransportState> {
        self.transition_transport(mailbox_id, delivery_id, TransportState::Acked, now.into().0)
            .await
    }

    pub async fn delete_delivery(
        &self,
        mailbox_id: &[u8],
        delivery_id: &[u8],
        now: impl Into<StoreTime>,
    ) -> RelayResult<TransportState> {
        self.transition_transport(mailbox_id, delivery_id, TransportState::Deleted, now.into().0)
            .await
    }

    async fn transition_transport(
        &self,
        mailbox_id: &[u8],
        delivery_id: &[u8],
        target: TransportState,
        now: u64,
    ) -> RelayResult<TransportState> {
        validate_id(mailbox_id)?;
        validate_id(delivery_id)?;
        let mailbox = mailbox_id.to_vec();
        let delivery = delivery_id.to_vec();
        let policy = self.inner.policy;
        let operation_id =
            operation_key(b"transition-transport", &[&mailbox, &delivery, &[target as u8]]);
        let request =
            request_digest(b"transition-transport", &[&mailbox, &delivery, &[target as u8]]);
        self.write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
            if let Some(state) = load_tombstone_state(tx, &mailbox, &delivery)? {
                return Ok(state);
            }
            let Some((old,expires)) = load_live_state(tx,&mailbox,&delivery)? else { return Err(RelayError::InvalidInput); };
            if now >= expires {
                trim_tombstones(tx, &mailbox, policy, now)?;
                move_mail_to_tombstone(tx, &mailbox, &delivery, TransportState::Expired, now)?;
                return Ok(TransportState::Expired);
            }
            match target {
                TransportState::Acked if old == TransportState::Acked => Ok(old),
                TransportState::Acked if matches!(old, TransportState::Pending | TransportState::Fetched) => {
                    tx.execute("UPDATE opaque_mailbox SET status='acked',updated_at=?3 WHERE mailbox_id=?1 AND delivery_id=?2", params![&mailbox,&delivery,sqlite_i64(now)?]).map_err(map_sqlite_error)?;
                    audit(tx, AuditEvent::MailboxAcked, &delivery, 0, now)?;
                    Ok(TransportState::Acked)
                }
                TransportState::Deleted if matches!(old, TransportState::Pending | TransportState::Fetched | TransportState::Acked) => {
                    trim_tombstones(tx, &mailbox, policy, now)?;
                    move_mail_to_tombstone(tx, &mailbox, &delivery, TransportState::Deleted, now)?;
                    audit(tx, AuditEvent::MailboxDeleted, &delivery, 0, now)?;
                    Ok(TransportState::Deleted)
                }
                _ => Err(RelayError::Conflict),
            }
        }).await
    }

    pub async fn depth(&self, mailbox_id: &[u8], now: impl Into<StoreTime>) -> RelayResult<u64> {
        let now = now.into().0;
        validate_id(mailbox_id)?;
        let mailbox = mailbox_id.to_vec();
        self.read(move |db| {
            let delivery_ids: Vec<Vec<u8>> = {
                let mut statement = db
                    .prepare(
                        "SELECT delivery_id FROM opaque_mailbox WHERE mailbox_id=?1 ORDER BY delivery_id",
                    )
                    .map_err(map_sqlite_error)?;
                statement
                    .query_map(params![&mailbox], |row| row.get(0))
                    .map_err(map_sqlite_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(map_sqlite_error)?
            };
            let mut depth = 0u64;
            for delivery in delivery_ids {
                let (state, expires_at) =
                    load_live_state(db, &mailbox, &delivery)?.ok_or(RelayError::Database)?;
                if expires_at > now
                    && matches!(state, TransportState::Pending | TransportState::Fetched)
                {
                    depth = depth.checked_add(1).ok_or(RelayError::Database)?;
                }
            }
            Ok(depth)
        })
        .await
    }
}

impl RelayOpaqueStore {
    pub async fn cleanup(
        &self,
        operation_id: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<CleanupSummary> {
        let now = now.into().0;
        let request = request_digest(b"cleanup", &[&now.to_be_bytes()]);
        let retention = self.inner.policy.tombstone_retention_secs;
        let policy = self.inner.policy;
        self.write_operation(operation_id, request, now, MAINTENANCE_DEADLINE, move |tx| {
            // Two rows are reserved for the durable operation ledger plus one
            // trigger side effect. The final cleanup audit inserts one row and
            // can trim at most one old row. The ledger is probed below, so any
            // larger actual delta fails closed rather than crossing 1000.
            let mut maintenance = MaintenanceBudget::with_reserved_rows(4)?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| {
                candidate.execute("DELETE FROM relay_operations WHERE operation_commitment IN (SELECT operation_commitment FROM relay_operations WHERE expires_at<?1 ORDER BY expires_at,operation_commitment LIMIT ?2)",params![sqlite_i64(now)?,limit]).map_err(map_sqlite_error)
            })?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| {
                candidate.execute("DELETE FROM fetch_receipts WHERE operation_commitment IN (SELECT operation_commitment FROM fetch_receipts WHERE expires_at<?1 ORDER BY expires_at,operation_commitment LIMIT ?2)",params![sqlite_i64(now)?,limit]).map_err(map_sqlite_error)
            })?;
            let purge_before = sqlite_i64(now.saturating_sub(retention))?;
            let delivery_prerequisites_remaining: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM relay_operations WHERE expires_at<?1 UNION ALL SELECT 1 FROM fetch_receipts WHERE expires_at<?1)",
                params![sqlite_i64(now)?],
                |row| row.get(0),
            ).map_err(map_sqlite_error)?;
            let purged_rows = if delivery_prerequisites_remaining {
                0
            } else {
                match maintenance.attempt_limited(tx, |candidate, limit| {
                    candidate.execute("DELETE FROM mailbox_tombstones WHERE rowid IN (SELECT rowid FROM mailbox_tombstones WHERE expires_at<=?1 AND updated_at<=?2 ORDER BY updated_at,rowid LIMIT ?3)", params![sqlite_i64(now)?,purge_before,limit]).map_err(map_sqlite_error)
                })? {
                    MaintenanceAttempt::Applied(rows) => u64::try_from(rows).map_err(|_| RelayError::Database)?,
                    MaintenanceAttempt::BudgetExhausted | MaintenanceAttempt::ResourceBlocked => 0,
                }
            };
            let _ = maintenance.attempt_limited(tx, |candidate, limit| {
                candidate.execute(
                    "DELETE FROM relay_audit WHERE rowid IN (SELECT rowid FROM relay_audit ORDER BY created_at DESC,rowid DESC LIMIT ?1 OFFSET ?2)",
                    params![limit, sqlite_i64(MAX_AUDIT_ROWS)?],
                ).map_err(map_sqlite_error)
            })?;
            let expired_mail =
                expire_mailbox_rows(tx, None, now, policy, &mut maintenance, false)?;
            let expired_pairing_ids: Vec<Vec<u8>> = {
                let mut statement = tx.prepare("SELECT intent_id FROM pairing_intents WHERE state IN ('available','claimed') AND expires_at<=?1 ORDER BY expires_at,intent_id LIMIT ?2").map_err(map_sqlite_error)?;
                statement.query_map(params![sqlite_i64(now)?,maintenance.sql_limit()?], |row| row.get(0)).map_err(map_sqlite_error)?.collect::<Result<Vec<_>,_>>().map_err(map_sqlite_error)?
            };
            let mut expired_pairings = 0usize;
            for intent in expired_pairing_ids {
                if maintenance.is_empty() {
                    break;
                }
                let intent = array16(&intent)?;
                match maintenance.attempt(tx, |candidate| {
                    terminalize_pairing(candidate, &intent, PairingState::Expired, now)
                })? {
                    MaintenanceAttempt::Applied(()) => {
                        expired_pairings = expired_pairings.checked_add(1).ok_or(RelayError::Database)?;
                    }
                    MaintenanceAttempt::BudgetExhausted => break,
                    MaintenanceAttempt::ResourceBlocked => continue,
                }
            }
            let expired_prekeys = expire_prekeys(tx, now, &mut maintenance)?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM claim_rate_limits WHERE source_id IN (SELECT source_id FROM claim_rate_limits WHERE expires_at<=?1 ORDER BY expires_at,source_id LIMIT ?2)", params![sqlite_i64(now)?,limit]).map_err(map_sqlite_error))?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM claim_attempt_operations WHERE operation_id IN (SELECT operation_id FROM claim_attempt_operations WHERE expires_at<=?1 ORDER BY expires_at,operation_id LIMIT ?2)", params![sqlite_i64(now)?,limit]).map_err(map_sqlite_error))?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM confirmation_reports WHERE rowid IN (SELECT c.rowid FROM confirmation_reports c JOIN pairing_intents p ON p.intent_id=c.intent_id WHERE c.tombstoned=1 AND p.state IN ('expired','burned','cancelled','consumed') AND p.updated_at<=?1 ORDER BY p.updated_at,c.intent_id,c.side LIMIT ?2)", params![purge_before,limit]).map_err(map_sqlite_error))?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM public_prekeys WHERE rowid IN (SELECT rowid FROM public_prekeys WHERE status IN ('burned','tombstoned','consumed') AND updated_at<=?1 ORDER BY updated_at,prekey_id LIMIT ?2)", params![purge_before,limit]).map_err(map_sqlite_error))?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM pairing_intents WHERE rowid IN (SELECT p.rowid FROM pairing_intents p WHERE p.state IN ('expired','burned','cancelled','consumed') AND p.updated_at<=?1 AND NOT EXISTS(SELECT 1 FROM confirmation_reports c WHERE c.intent_id=p.intent_id) AND NOT EXISTS(SELECT 1 FROM public_prekeys k WHERE k.pairing_id=p.intent_id) AND NOT EXISTS(SELECT 1 FROM claim_attempt_operations a WHERE a.intent_id=p.intent_id) ORDER BY p.updated_at,p.intent_id LIMIT ?2)", params![purge_before,limit]).map_err(map_sqlite_error))?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM relay_tombstones WHERE rowid IN (SELECT rowid FROM relay_tombstones WHERE created_at<=?1 ORDER BY created_at,kind,opaque_id LIMIT ?2)", params![purge_before,limit]).map_err(map_sqlite_error))?;
            let _ = maintenance.attempt_limited(tx, |candidate, limit| candidate.execute("DELETE FROM mailbox_quotas WHERE mailbox_id IN (SELECT mailbox_id FROM mailbox_quotas WHERE mailbox_id NOT IN (SELECT mailbox_id FROM opaque_mailbox UNION SELECT mailbox_id FROM mailbox_tombstones) ORDER BY mailbox_id LIMIT ?1)", params![limit]).map_err(map_sqlite_error))?;
            let remaining: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM opaque_mailbox WHERE expires_at<=?1 UNION ALL SELECT 1 FROM pairing_intents WHERE state IN ('available','claimed') AND expires_at<=?1 UNION ALL SELECT 1 FROM public_prekeys WHERE status IN ('available','reserved') AND expires_at<=?1 UNION ALL SELECT 1 FROM relay_operations WHERE expires_at<?1 UNION ALL SELECT 1 FROM fetch_receipts WHERE expires_at<?1 UNION ALL SELECT 1 FROM mailbox_tombstones WHERE expires_at<=?1 AND updated_at<=?2 UNION ALL SELECT 1 FROM claim_rate_limits WHERE expires_at<=?1 UNION ALL SELECT 1 FROM claim_attempt_operations WHERE expires_at<=?1 UNION ALL SELECT 1 FROM confirmation_reports c JOIN pairing_intents p ON p.intent_id=c.intent_id WHERE c.tombstoned=1 AND p.updated_at<=?2 UNION ALL SELECT 1 FROM public_prekeys WHERE status IN ('burned','tombstoned','consumed') AND updated_at<=?2 UNION ALL SELECT 1 FROM pairing_intents p WHERE p.state IN ('expired','burned','cancelled','consumed') AND p.updated_at<=?2 AND NOT EXISTS(SELECT 1 FROM confirmation_reports c WHERE c.intent_id=p.intent_id) AND NOT EXISTS(SELECT 1 FROM public_prekeys k WHERE k.pairing_id=p.intent_id) AND NOT EXISTS(SELECT 1 FROM claim_attempt_operations a WHERE a.intent_id=p.intent_id) UNION ALL SELECT 1 FROM relay_tombstones WHERE created_at<=?2 UNION ALL SELECT 1 FROM mailbox_quotas WHERE mailbox_id NOT IN (SELECT mailbox_id FROM opaque_mailbox UNION SELECT mailbox_id FROM mailbox_tombstones) UNION ALL SELECT 1 FROM relay_audit GROUP BY 1 HAVING count(*)>?3 UNION ALL SELECT 1 FROM mailbox_tombstones GROUP BY mailbox_id HAVING count(*)>?4 UNION ALL SELECT 1 FROM mailbox_tombstones GROUP BY 1 HAVING count(*)>?5)",params![sqlite_i64(now)?,purge_before,sqlite_i64(MAX_AUDIT_ROWS)?,sqlite_i64(policy.mailbox_max_tombstones)?,sqlite_i64(policy.global_max_tombstones)?],|row|row.get(0)).map_err(map_sqlite_error)?;
            let audit_before = tx.total_changes();
            audit(tx, AuditEvent::Cleanup, &[], 0, now)?;
            let audit_changes = tx.total_changes().checked_sub(audit_before).ok_or(RelayError::Database)?;
            let committed_changes = maintenance
                .committed
                .checked_add(audit_changes)
                .ok_or(RelayError::Database)?;
            Ok(CleanupSummary { expired_mail, purged_rows, expired_pairings: u64::try_from(expired_pairings).map_err(|_| RelayError::Database)?, expired_prekeys, remaining, committed_changes })
        }).await
    }

    pub async fn checkpoint(
        &self,
        operation_id: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<()> {
        let now = now.into().0;
        let request = request_digest(b"checkpoint", &[&now.to_be_bytes()]);
        let commitment = operation_commitment(&self.inner.secrets, &operation_id)?;
        let retention = self.inner.policy.operation_retention_secs;
        self.write_connection(operation_id, MAINTENANCE_DEADLINE, move |db| {
            db.execute(
                "DELETE FROM relay_operations WHERE operation_commitment IN (SELECT operation_commitment FROM relay_operations WHERE expires_at<?1 ORDER BY expires_at,operation_commitment LIMIT ?2)",
                params![sqlite_i64(now)?, MAINTENANCE_BATCH_ROWS],
            )
            .map_err(map_sqlite_error)?;
            let known: Option<(Vec<u8>,i64)> = db.query_row("SELECT request_digest,result_kind FROM relay_operations WHERE operation_commitment=?1", params![commitment.as_slice()], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(map_sqlite_error)?;
            if let Some((old_request,kind)) = known {
                if array32(&old_request)? == request && u8::try_from(kind).map_err(|_|RelayError::Database)? == 0 { return Ok(()); }
                return Err(RelayError::IdempotencyConflict);
            }
            let operation_rows: i64 = db.query_row("SELECT count(*) FROM relay_operations", [], |row| row.get(0)).map_err(map_sqlite_error)?;
            if operation_rows >= sqlite_i64(MAX_OPERATION_ROWS)? {
                let _ = audit_event_best_effort(db, AuditEvent::QuotaRejected, commitment.as_slice(), 2, now);
                return Err(RelayError::QuotaExceeded);
            }
            db.execute_batch("PRAGMA wal_checkpoint(PASSIVE)").map_err(map_sqlite_error)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(map_sqlite_error)?;
            tx.execute("INSERT INTO relay_operations(operation_commitment,request_digest,result_kind,result_blob,completed_at,expires_at) VALUES(?1,?2,0,x'',?3,?4)", params![commitment.as_slice(),request.as_slice(),sqlite_i64(now)?,sqlite_i64(now.checked_add(retention).ok_or(RelayError::InvalidInput)?)?]).map_err(map_sqlite_error)?;
            audit(&tx, AuditEvent::Checkpoint, &[], 0, now)?;
            tx.commit().map_err(map_sqlite_error)
        }).await
    }
}

impl RelayOpaqueStore {
    pub async fn publish_prekey(
        &self,
        prekey: PublicPrekey,
        now: impl Into<StoreTime>,
    ) -> RelayResult<PrekeyState> {
        let now = now.into().0;
        if prekey.expires_at <= now
            || prekey.expires_at
                > now
                    .checked_add(self.inner.policy.max_prekey_ttl_secs)
                    .ok_or(RelayError::InvalidInput)?
        {
            return Err(RelayError::Expired);
        }
        let bundle_digest = commitment(BUNDLE_DOMAIN, prekey.bundle.as_bytes());
        let probe_id = prekey.prekey_id;
        let probe_bundle = prekey.bundle.0.clone();
        let probe_expiry = prekey.expires_at;
        let probe_digest = bundle_digest;
        if let Some(state) = self
            .read(move |db| {
                load_prekey_by_id(db, probe_id)?
                    .map(|row| {
                        if row.bundle != probe_bundle
                            || row.bundle_digest != probe_digest
                            || row.expires_at != probe_expiry
                        {
                            return Err(RelayError::IdempotencyConflict);
                        }
                        Ok(row.state)
                    })
                    .transpose()
            })
            .await?
        {
            return Ok(state);
        }
        let operation_id = operation_key(b"publish-prekey", &[&prekey.prekey_id]);
        let request = request_digest(
            b"publish-prekey",
            &[&prekey.prekey_id, bundle_digest.as_slice(), &prekey.expires_at.to_be_bytes()],
        );
        let id = prekey.prekey_id;
        let bundle = prekey.bundle.0;
        let expires = prekey.expires_at;
        self.write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
            if let Some(old) = load_prekey_by_id(tx, id)? {
                if old.bundle == bundle && old.bundle_digest == bundle_digest && old.expires_at == expires {
                    return Ok(old.state);
                }
                return Err(RelayError::Conflict);
            }
            let digest_owner: Option<Vec<u8>> = tx.query_row(
                "SELECT prekey_id FROM public_prekeys WHERE bundle_digest=?1",
                params![bundle_digest.as_slice()],
                |row| row.get(0),
            ).optional().map_err(map_sqlite_error)?;
            if digest_owner.is_some() { return Err(RelayError::Conflict); }
            let count: i64 = tx.query_row("SELECT count(*) FROM public_prekeys", [], |row| row.get(0)).map_err(map_sqlite_error)?;
            if count >= sqlite_i64(MAX_PREKEY_ROWS)? { return Err(RelayError::QuotaExceeded); }
            tx.execute(
                "INSERT INTO public_prekeys(prekey_id,bundle,bundle_digest,status,expires_at,created_at,updated_at) VALUES(?1,?2,?3,'available',?4,?5,?5)",
                params![id.as_slice(), bundle, bundle_digest.as_slice(), sqlite_i64(expires)?, sqlite_i64(now)?],
            ).map_err(map_sqlite_error)?;
            audit(tx, AuditEvent::PrekeyPublished, &id, 0, now)?;
            Ok(PrekeyState::Available)
        }).await
    }

    pub async fn read_prekey(&self, prekey_id: [u8; 16]) -> RelayResult<StoredPublicPrekey> {
        self.read(move |db| {
            load_prekey_by_id(db, prekey_id)?
                .map(|row| StoredPublicPrekey {
                    prekey_id,
                    bundle: CanonicalPrekeyBundle(row.bundle),
                    bundle_digest: row.bundle_digest,
                    state: row.state,
                    expires_at: row.expires_at,
                })
                .ok_or(RelayError::PrekeyUnavailable)
        })
        .await
    }

    pub async fn reserve_prekey(
        &self,
        pairing_id: [u8; 16],
        prekey_id: [u8; 16],
        reservation_id: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<PrekeyReservation> {
        let now = now.into().0;
        let operation_id = operation_key(b"reserve-prekey", &[&reservation_id]);
        let request =
            request_digest(b"reserve-prekey", &[&pairing_id, &prekey_id, &reservation_id]);
        let admission = self.write_operation_validated(operation_id, request, now, NORMAL_DEADLINE, move |tx, recorded: AdmissionRecord| {
            if recorded.outcome != 1 {
                return Ok(recorded);
            }
            let current = load_prekey_by_id(tx, prekey_id)?.ok_or(RelayError::Database)?;
            if current.reservation_id != Some(reservation_id)
                || current.pairing_id != Some(pairing_id)
                || current.state != PrekeyState::Reserved
            {
                return Ok(AdmissionRecord { outcome: 0 });
            }
            let pairing: (String,i64,Option<Vec<u8>>,Option<Vec<u8>>,Option<Vec<u8>>,Option<Vec<u8>>) = tx.query_row(
                "SELECT state,expires_at,claimant_id,claimant_nonce,claim_capability_commitment,b_nonce FROM pairing_intents WHERE intent_id=?1",
                params![pairing_id.as_slice()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            ).map_err(map_sqlite_error)?;
            let pairing_state = PairingState::parse(&pairing.0)?;
            validate_pairing_material(pairing_state,pairing.2.as_deref(),pairing.3.as_deref(),pairing.4.as_deref(),pairing.5.as_deref())?;
            if now >= current.expires_at || now >= from_sql_i64(pairing.1).map_err(map_sqlite_error)? {
                if matches!(pairing_state, PairingState::Available | PairingState::Claimed) {
                    terminalize_pairing(tx, &pairing_id, PairingState::Expired, now)?;
                }
                return Ok(AdmissionRecord { outcome: 2 });
            }
            if pairing_state != PairingState::Claimed {
                return Ok(AdmissionRecord { outcome: 0 });
            }
            Ok(recorded)
        }, move |tx| {
            let pairing: Option<(String, i64,Option<Vec<u8>>,Option<Vec<u8>>,Option<Vec<u8>>,Option<Vec<u8>>)> = tx.query_row(
                "SELECT state,expires_at,claimant_id,claimant_nonce,claim_capability_commitment,b_nonce FROM pairing_intents WHERE intent_id=?1",
                params![pairing_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            ).optional().map_err(map_sqlite_error)?;
            let Some((pairing_state, pairing_expiry,claimant,claimant_nonce,claim_capability,b_nonce)) = pairing else { return Ok(AdmissionRecord { outcome: 0 }); };
            let pairing_state = PairingState::parse(&pairing_state)?;
            validate_pairing_material(pairing_state,claimant.as_deref(),claimant_nonce.as_deref(),claim_capability.as_deref(),b_nonce.as_deref())?;
            if now >= from_sql_i64(pairing_expiry).map_err(map_sqlite_error)? {
                if matches!(pairing_state, PairingState::Available | PairingState::Claimed) {
                    terminalize_pairing(tx, &pairing_id, PairingState::Expired, now)?;
                }
                return Ok(AdmissionRecord { outcome: 2 });
            }
            if pairing_state != PairingState::Claimed { return Ok(AdmissionRecord { outcome: 0 }); }
            let existing_for_pairing: Vec<Vec<u8>> = {
                let mut statement = tx.prepare("SELECT prekey_id FROM public_prekeys WHERE pairing_id=?1")
                    .map_err(map_sqlite_error)?;
                statement.query_map(
                params![pairing_id.as_slice()],
                |row| row.get(0)).map_err(map_sqlite_error)?
                    .collect::<Result<Vec<_>,_>>().map_err(map_sqlite_error)?
            };
            for id in &existing_for_pairing {
                let validated = load_prekey_by_id(tx,array16(id)?)?.ok_or(RelayError::Database)?;
                if validated.pairing_id != Some(pairing_id) { return Err(RelayError::Database); }
            }
            let Some(current) = load_prekey_by_id(tx,prekey_id)? else { return Ok(AdmissionRecord { outcome: 0 }); };
            if current.state == PrekeyState::Reserved
                && current.reservation_id == Some(reservation_id)
                && current.pairing_id == Some(pairing_id)
            { return Ok(AdmissionRecord { outcome: 1 }); }
            if now >= current.expires_at && current.state == PrekeyState::Available {
                tx.execute("UPDATE public_prekeys SET status='burned',updated_at=?2 WHERE prekey_id=?1 AND status='available'", params![prekey_id.as_slice(),sqlite_i64(now)?]).map_err(map_sqlite_error)?;
                audit(tx, AuditEvent::PrekeyBurned, &prekey_id, 1, now)?;
                return Ok(AdmissionRecord { outcome: 2 });
            }
            if current.state != PrekeyState::Available || !existing_for_pairing.is_empty() { return Ok(AdmissionRecord { outcome: 0 }); }
            let changed = tx.execute(
                "UPDATE public_prekeys SET status='reserved',reservation_id=?2,pairing_id=?3,updated_at=?4 WHERE prekey_id=?1 AND status='available' AND expires_at>?4",
                params![prekey_id.as_slice(), reservation_id.as_slice(), pairing_id.as_slice(), sqlite_i64(now)?],
            ).map_err(map_sqlite_error)?;
            if changed != 1 { return Ok(AdmissionRecord { outcome: 0 }); }
            audit(tx, AuditEvent::PrekeyReserved, &prekey_id, 0, now)?;
            Ok(AdmissionRecord { outcome: 1 })
        }).await?;
        match admission.outcome {
            1 => {}
            2 => return Err(RelayError::Expired),
            _ => return Err(RelayError::PrekeyUnavailable),
        }
        Ok(PrekeyReservation {
            prekey_id,
            reservation_id,
            pairing_id,
            state: PrekeyState::Reserved,
        })
    }

    pub async fn consume_prekey(
        &self,
        reservation_id: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<PrekeyState> {
        self.transition_prekey(reservation_id, PrekeyState::Consumed, now.into().0).await
    }

    pub async fn burn_prekey(
        &self,
        reservation_id: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<PrekeyState> {
        self.transition_prekey(reservation_id, PrekeyState::Burned, now.into().0).await
    }

    async fn transition_prekey(
        &self,
        reservation_id: [u8; 16],
        target: PrekeyState,
        now: u64,
    ) -> RelayResult<PrekeyState> {
        let operation_id = operation_key(b"transition-prekey", &[&reservation_id, &[target as u8]]);
        let request = request_digest(b"transition-prekey", &[&reservation_id, &[target as u8]]);
        self.write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
            let Some(current) = load_prekey_by_reservation(tx,reservation_id)? else { return Err(RelayError::PrekeyUnavailable); };
            if current.reservation_id != Some(reservation_id) { return Err(RelayError::Database); }
            if current.state == target { return Ok(target); }
            if current.state != PrekeyState::Reserved { return Err(RelayError::PrekeyUnavailable); }
            let expired = now >= current.expires_at;
            let actual = if expired { PrekeyState::Burned } else { target };
            if actual == PrekeyState::Burned {
                let pairing = current.pairing_id.ok_or(RelayError::Database)?;
                terminalize_pairing(tx, &pairing, if expired { PairingState::Expired } else { PairingState::Burned }, now)?;
                return Ok(PrekeyState::Burned);
            }
            tx.execute(
                "UPDATE public_prekeys SET status=?2,updated_at=?3 WHERE reservation_id=?1 AND status='reserved'",
                params![reservation_id.as_slice(), actual.as_str(), sqlite_i64(now)?],
            ).map_err(map_sqlite_error)?;
            audit(tx, AuditEvent::PrekeyConsumed, &current.prekey_id, 0, now)?;
            Ok(actual)
        }).await
    }

    pub async fn reconcile_prekey(&self, reservation_id: [u8; 16]) -> RelayResult<PrekeyState> {
        self.read(move |db| {
            load_prekey_by_reservation(db, reservation_id)?
                .map(|row| row.state)
                .ok_or(RelayError::PrekeyUnavailable)
        })
        .await
    }
}

impl RelayOpaqueStore {
    pub async fn report_creator_confirmation(
        &self,
        pairing_id: [u8; 16],
        device_code: &str,
        token: &[u8],
        now: impl Into<StoreTime>,
    ) -> RelayResult<ConfirmationResult> {
        let device = decode_base64url_16(device_code).ok_or(RelayError::PairingUnavailable)?;
        let capability = keyed_commitment(&self.inner.secrets, DEVICE_DOMAIN, &device)?;
        self.report_confirmation(pairing_id, 0, capability, token, now.into().0).await
    }

    pub async fn report_claimant_confirmation(
        &self,
        pairing_id: [u8; 16],
        claim_capability: &str,
        token: &[u8],
        now: impl Into<StoreTime>,
    ) -> RelayResult<ConfirmationResult> {
        let claim = decode_base64url_16(claim_capability).ok_or(RelayError::PairingUnavailable)?;
        let capability = keyed_commitment(&self.inner.secrets, CLAIM_DOMAIN, &claim)?;
        self.report_confirmation(pairing_id, 1, capability, token, now.into().0).await
    }

    async fn report_confirmation(
        &self,
        pairing_id: [u8; 16],
        side: u8,
        capability_commitment: [u8; 32],
        token: &[u8],
        now: u64,
    ) -> RelayResult<ConfirmationResult> {
        if token.is_empty() || token.len() > MAX_CONFIRMATION_TOKEN_BYTES {
            return Err(RelayError::InvalidInput);
        }
        let token_digest = keyed_commitment(&self.inner.secrets, TOKEN_DOMAIN, token)?;
        let operation_id = operation_key(
            b"report-confirmation",
            &[&pairing_id, &[side], token_digest.as_slice(), capability_commitment.as_slice()],
        );
        let request = request_digest(
            b"report-confirmation",
            &[&pairing_id, &[side], token_digest.as_slice(), capability_commitment.as_slice()],
        );
        let record = self.write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
            let row: Option<(String, i64, Vec<u8>, Option<Vec<u8>>,Option<Vec<u8>>,Option<Vec<u8>>,Option<Vec<u8>>)> = tx.query_row(
                "SELECT state,expires_at,device_code_commitment,claim_capability_commitment,claimant_id,claimant_nonce,b_nonce FROM pairing_intents WHERE intent_id=?1",
                params![pairing_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
            ).optional().map_err(map_sqlite_error)?;
            let Some((state, expires, creator_commitment, claimant_commitment,claimant,claimant_nonce,b_nonce)) = row else { return Ok(ConfirmationRecord::RejectPairing); };
            let state = PairingState::parse(&state)?;
            validate_pairing_material(state,claimant.as_deref(),claimant_nonce.as_deref(),claimant_commitment.as_deref(),b_nonce.as_deref())?;
            let expected = if side == 0 {
                array32(&creator_commitment)?
            } else if let Some(commitment) = claimant_commitment.as_deref() {
                array32(commitment)?
            } else if state == PairingState::Consumed {
                let tombstoned: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM relay_tombstones WHERE kind='claim' AND opaque_id=?1)", params![capability_commitment.as_slice()], |row| row.get(0)).map_err(map_sqlite_error)?;
                if !tombstoned { return Ok(ConfirmationRecord::RejectPairing); }
                capability_commitment
            } else {
                return Ok(ConfirmationRecord::RejectPairing);
            };
            if !constant_time_eq(&expected, &capability_commitment) {
                audit(tx, AuditEvent::ConfirmationRejected, &pairing_id, 1, now)?;
                return Ok(ConfirmationRecord::RejectPairing);
            }
            if let Some(old) = tx.query_row(
                "SELECT token_digest FROM confirmation_reports WHERE intent_id=?1 AND side=?2",
                params![pairing_id.as_slice(), i64::from(side)],
                |row| row.get::<_, Vec<u8>>(0),
            ).optional().map_err(map_sqlite_error)? {
                if old != token_digest { return Err(RelayError::Conflict); }
                return Ok(if state == PairingState::Consumed { ConfirmationRecord::BothComplete } else { ConfirmationRecord::Pending });
            }
            if now >= from_sql_i64(expires).map_err(map_sqlite_error)? {
                if matches!(state, PairingState::Available | PairingState::Claimed) {
                    terminalize_pairing(tx, &pairing_id, PairingState::Expired, now)?;
                }
                return Ok(ConfirmationRecord::RejectPairing);
            }
            if state != PairingState::Claimed {
                audit(tx, AuditEvent::ConfirmationRejected, &pairing_id, 3, now)?;
                return Ok(ConfirmationRecord::RejectPairing);
            }
            let reservations: Vec<Vec<u8>> = {
                let mut statement = tx.prepare("SELECT prekey_id FROM public_prekeys WHERE pairing_id=?1").map_err(map_sqlite_error)?;
                statement.query_map(params![pairing_id.as_slice()], |row| row.get(0)).map_err(map_sqlite_error)?.collect::<Result<Vec<_>, _>>().map_err(map_sqlite_error)?
            };
            if reservations.len() > 1 { return Err(RelayError::Database); }
            if reservations.is_empty() {
                audit(tx, AuditEvent::ConfirmationRejected, &pairing_id, 2, now)?;
                return Ok(ConfirmationRecord::RejectPrekey);
            }
            let reservation = load_prekey_by_id(tx,array16(&reservations[0])?)?.ok_or(RelayError::Database)?;
            if reservation.pairing_id != Some(pairing_id) { return Err(RelayError::Database); }
            if reservation.state != PrekeyState::Reserved || now >= reservation.expires_at {
                terminalize_pairing(tx, &pairing_id, PairingState::Burned, now)?;
                audit(tx, AuditEvent::ConfirmationRejected, &pairing_id, 2, now)?;
                return Ok(ConfirmationRecord::RejectPrekey);
            }
            tx.execute(
                "INSERT INTO confirmation_reports(intent_id,side,token_digest,reported_at) VALUES(?1,?2,?3,?4)",
                params![pairing_id.as_slice(), i64::from(side), token_digest.as_slice(), sqlite_i64(now)?],
            ).map_err(map_sqlite_error)?;
            let count: i64 = tx.query_row("SELECT count(*) FROM confirmation_reports WHERE intent_id=?1", params![pairing_id.as_slice()], |row| row.get(0)).map_err(map_sqlite_error)?;
            if count == 1 {
                audit(tx, AuditEvent::ConfirmationPending, &pairing_id, side, now)?;
                return Ok(ConfirmationRecord::Pending);
            }
            if count != 2 { return Err(RelayError::Database); }
            terminalize_pairing(tx, &pairing_id, PairingState::Consumed, now)?;
            audit(tx, AuditEvent::ConfirmationComplete, &pairing_id, 0, now)?;
            Ok(ConfirmationRecord::BothComplete)
        }).await?;
        match record {
            ConfirmationRecord::Pending => Ok(ConfirmationResult::Pending),
            ConfirmationRecord::BothComplete => Ok(ConfirmationResult::BothComplete),
            ConfirmationRecord::RejectPairing => Err(RelayError::PairingUnavailable),
            ConfirmationRecord::RejectPrekey => Err(RelayError::PrekeyUnavailable),
        }
    }
}

async fn writer_loop(mut receiver: mpsc::Receiver<WriteRequest>, writer: Connection) {
    let writer = Arc::new(Mutex::new(writer));
    let mut pending_audits: VecDeque<(AuditEvent, Vec<u8>)> = VecDeque::new();
    let mut dropped_audits = 0u64;
    while let Some(request) = receiver.recv().await {
        if let Ok(mut guard) = writer.lock() {
            if dropped_audits != 0
                && audit_event_best_effort(
                    &mut guard,
                    AuditEvent::AuditDropped,
                    &[],
                    u8::try_from(dropped_audits).unwrap_or(u8::MAX),
                    0,
                )
            {
                dropped_audits = 0;
            }
            pending_audits
                .retain(|(event, id)| !audit_event_best_effort(&mut guard, *event, id, 1, 0));
        }
        if request
            .state
            .compare_exchange(WRITE_QUEUED, WRITE_RUNNING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            if let Ok(mut guard) = writer.lock() {
                let event = if request.state.load(Ordering::SeqCst) == WRITE_DEADLINE {
                    AuditEvent::DeadlineExceeded
                } else {
                    AuditEvent::RequestCancelled
                };
                if !audit_event_best_effort(&mut guard, event, &request.operation_id, 1, 0) {
                    enqueue_pending_audit(
                        &mut pending_audits,
                        &mut dropped_audits,
                        event,
                        request.operation_id.to_vec(),
                    );
                }
            }
            let _ = request.response.send(Err(RelayError::DeadlineExceeded));
            continue;
        }
        let operation_id = request.operation_id;
        let state = Arc::clone(&request.state);
        let worker_writer = Arc::clone(&writer);
        let response = tokio::task::spawn_blocking(move || {
            let mut guard = worker_writer.lock().map_err(|_| RelayError::Internal)?;
            (request.operation)(&mut guard)
        })
        .await
        .map_err(|_| RelayError::Internal)
        .and_then(|result| result);
        state.store(WRITE_DONE, Ordering::SeqCst);
        if let Err(error) = &response {
            if let Ok(mut guard) = writer.lock() {
                if !audit_failure_best_effort(&mut guard, &operation_id, error, 0) {
                    enqueue_pending_audit(
                        &mut pending_audits,
                        &mut dropped_audits,
                        audit_event_for_error(error),
                        operation_id.to_vec(),
                    );
                }
            }
        }
        if request.response.send(response).is_err() {
            if let Ok(mut guard) = writer.lock() {
                if !audit_failure_best_effort(
                    &mut guard,
                    &operation_id,
                    &RelayError::OutcomeUnknown { operation_id },
                    0,
                ) {
                    enqueue_pending_audit(
                        &mut pending_audits,
                        &mut dropped_audits,
                        AuditEvent::OutcomeUnknown,
                        operation_id.to_vec(),
                    );
                }
            }
        }
    }
}

fn enqueue_pending_audit(
    pending: &mut VecDeque<(AuditEvent, Vec<u8>)>,
    dropped: &mut u64,
    event: AuditEvent,
    opaque_id: Vec<u8>,
) {
    if pending.len() == WRITER_QUEUE_CAPACITY {
        pending.pop_front();
        *dropped = dropped.saturating_add(1);
    }
    pending.push_back((event, opaque_id));
}

impl RelayOpaqueStore {
    pub async fn create_pairing_intent(
        &self,
        now: impl Into<StoreTime>,
    ) -> RelayResult<CreatedPairing> {
        let operation_id = random_id::<16>()?;
        self.create_pairing_intent_with_operation(operation_id, now).await
    }

    pub async fn create_pairing_intent_with_operation(
        &self,
        operation_id: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<CreatedPairing> {
        let now = now.into().0;
        let intent_id = hmac16(
            &self.inner.secrets.pairing,
            b"telegraph/pairing-intent-id/v2",
            &[&operation_id],
        )?;
        let device = hmac16(&self.inner.secrets.pairing, DEVICE_DOMAIN, &[&operation_id])?;
        let user_seed = hmac32(&self.inner.secrets.pairing, USER_DOMAIN, &[&operation_id])?;
        let user_value = u64::from_be_bytes(array8(&user_seed[..8])?) & ((1u64 << 50) - 1);
        let device_code = encode_base64url(&device);
        let user_code = encode_user_code(user_value);
        let device_commitment = keyed_commitment(&self.inner.secrets, DEVICE_DOMAIN, &device)?;
        let user_commitment =
            keyed_commitment(&self.inner.secrets, USER_DOMAIN, user_code.as_bytes())?;
        let op_commitment = operation_commitment(&self.inner.secrets, &operation_id)?;
        let expires =
            now.checked_add(self.inner.policy.pairing_ttl_secs).ok_or(RelayError::InvalidInput)?;
        let request = request_digest(b"create-pairing", &[&operation_id, &now.to_be_bytes()]);
        let record = self
            .write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
                if let Some((old_intent, old_expiry)) = tx
                    .query_row(
                        "SELECT intent_id,expires_at FROM pairing_intents WHERE operation_commitment=?1",
                        params![op_commitment.as_slice()],
                        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()
                    .map_err(map_sqlite_error)?
                {
                    return Ok(PairingRecord {
                        intent_id: array16(&old_intent)?,
                        expires_at: from_sql_i64(old_expiry).map_err(map_sqlite_error)?,
                    });
                }
                let count: i64 = tx
                    .query_row("SELECT count(*) FROM pairing_intents", [], |row| row.get(0))
                    .map_err(map_sqlite_error)?;
                if count >= sqlite_i64(MAX_PAIRING_ROWS)? {
                    return Err(RelayError::QuotaExceeded);
                }
                tx.execute(
                    "INSERT INTO pairing_intents(intent_id,operation_commitment,device_code_commitment,user_code_commitment,state,attempts,expires_at,created_at,updated_at) VALUES(?1,?2,?3,?4,'available',0,?5,?6,?6)",
                    params![intent_id.as_slice(), op_commitment.as_slice(), device_commitment.as_slice(), user_commitment.as_slice(), sqlite_i64(expires)?, sqlite_i64(now)?],
                )
                .map_err(map_sqlite_error)?;
                audit(tx, AuditEvent::PairingCreated, &intent_id, 0, now)?;
                Ok(PairingRecord { intent_id, expires_at: expires })
            })
            .await?;
        Ok(CreatedPairing {
            operation_id,
            intent_id: record.intent_id,
            device_code,
            user_code,
            expires_at: record.expires_at,
        })
    }

    pub async fn poll_pairing(
        &self,
        operation_id: [u8; 16],
        device_code: &str,
        now: impl Into<StoreTime>,
    ) -> RelayResult<PairingStatus> {
        let now = now.into().0;
        let device = decode_base64url_16(device_code).ok_or(RelayError::PairingUnavailable)?;
        let digest = keyed_commitment(&self.inner.secrets, DEVICE_DOMAIN, &device)?;
        let request = request_digest(b"poll-pairing", &[digest.as_slice()]);
        self.write_operation_validated(
            operation_id,
            request,
            now,
            NORMAL_DEADLINE,
            move |tx, _recorded| {
                pause_poll_for_test(operation_id);
                poll_pairing_state(tx, &digest, now)
            },
            move |tx| {
                pause_poll_for_test(operation_id);
                poll_pairing_state(tx, &digest, now)
            },
        )
        .await?;
        self.read(move |db| {
            db.query_row(
                "SELECT intent_id,state,b_nonce,expires_at,claimant_id,claimant_nonce,claim_capability_commitment FROM pairing_intents WHERE device_code_commitment=?1",
                params![digest.as_slice()],
                read_pairing,
            )
            .optional()
            .map_err(map_sqlite_error)?
            .ok_or(RelayError::PairingUnavailable)
        })
        .await
    }

    pub async fn claim_pairing(
        &self,
        user_code: &str,
        source: &ClaimSource,
        claimant_id: [u8; 16],
        claimant_nonce: [u8; 16],
        now: impl Into<StoreTime>,
    ) -> RelayResult<ClaimResult> {
        let now = now.into().0;
        let canonical = normalize_user_code(user_code);
        let code_material = canonical.as_deref().unwrap_or("invalid-code").as_bytes();
        let operation_id = operation_key(
            b"claim-pairing",
            &[&source.0, &claimant_id, &claimant_nonce, code_material],
        );
        let request = hmac32(
            &self.inner.secrets.pairing,
            b"claim-pairing",
            &[&source.0, &claimant_id, &claimant_nonce, code_material],
        )?;
        let user_digest = canonical
            .as_ref()
            .map(|code| keyed_commitment(&self.inner.secrets, USER_DOMAIN, code.as_bytes()))
            .transpose()?;
        let source_id = source.0;
        let ttl = self.inner.policy.pairing_ttl_secs;
        let claim_capability = hmac16(
            &self.inner.secrets.pairing,
            CLAIM_DOMAIN,
            &[&claimant_id, &claimant_nonce, code_material],
        )?;
        let b_nonce = hmac16(
            &self.inner.secrets.pairing,
            NONCE_DOMAIN,
            &[&claimant_id, &claimant_nonce, code_material],
        )?;
        let claim_commitment =
            keyed_commitment(&self.inner.secrets, CLAIM_DOMAIN, &claim_capability)?;
        let attempt_id = hmac32(
            &self.inner.secrets.pairing,
            b"claim-attempt",
            &[&source_id, &claimant_id, &claimant_nonce, code_material],
        )?;
        let record = self
            .write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
                let now_i64 = sqlite_i64(now)?;
                tx.execute("DELETE FROM claim_attempt_operations WHERE operation_id IN (SELECT operation_id FROM claim_attempt_operations WHERE expires_at<=?1 ORDER BY expires_at,operation_id LIMIT ?2)", params![now_i64,MAINTENANCE_BATCH_ROWS])
                    .map_err(map_sqlite_error)?;
                let attempt_rows: i64 = tx.query_row("SELECT count(*) FROM claim_attempt_operations", [], |row| row.get(0)).map_err(map_sqlite_error)?;
                if attempt_rows >= sqlite_i64(MAX_CLAIM_OPERATION_ROWS)? { return Err(RelayError::QuotaExceeded); }
                let row = match user_digest {
                    Some(digest) => tx
                        .query_row(
                            "SELECT intent_id,state,attempts,expires_at,claimant_id,claimant_nonce,claim_capability_commitment,b_nonce FROM pairing_intents WHERE user_code_commitment=?1",
                            params![digest.as_slice()],
                            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<Vec<u8>>>(4)?, row.get::<_, Option<Vec<u8>>>(5)?,row.get::<_,Option<Vec<u8>>>(6)?,row.get::<_,Option<Vec<u8>>>(7)?)),
                        )
                        .optional()
                        .map_err(map_sqlite_error)?,
                    None => None,
                };
                let intent_for_attempt = row.as_ref().map(|entry| entry.0.as_slice());
                let attempt_expiry = sqlite_i64(now.checked_add(ttl).ok_or(RelayError::InvalidInput)?)?;
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO claim_attempt_operations(operation_id,source_id,intent_id,expires_at) VALUES(?1,?2,?3,?4)",
                    params![attempt_id.as_slice(), source_id.as_slice(), intent_for_attempt, attempt_expiry],
                ).map_err(map_sqlite_error)?;
                let stored_attempt: (Vec<u8>,Option<Vec<u8>>,i64) = tx.query_row(
                    "SELECT source_id,intent_id,expires_at FROM claim_attempt_operations WHERE operation_id=?1",
                    params![attempt_id.as_slice()],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
                ).map_err(map_sqlite_error)?;
                let expected_intent = intent_for_attempt.map(array16).transpose()?;
                let stored_intent = strict_optional16(stored_attempt.1.as_deref())?;
                if array16(&stored_attempt.0)? != source_id
                    || stored_intent != expected_intent
                    || stored_attempt.2 != attempt_expiry
                {
                    return Err(RelayError::IdempotencyConflict);
                }
                if inserted == 0 {
                    return Err(RelayError::IdempotencyConflict);
                }
                if source_attempts_exhausted(tx, &source_id, now_i64)? {
                    audit(tx, AuditEvent::ClaimRejected, &source_id, 1, now)?;
                    return Ok(ClaimRecord { intent_id: [0; 16], accepted: false });
                }
                charge_source_attempt(tx, &source_id, now_i64, ttl)?;
                let Some((intent_raw, state_raw, attempts_raw, expires_raw, old_claimant, old_nonce,old_capability,old_b_nonce)) = row else {
                    audit(tx, AuditEvent::ClaimRejected, &source_id, 2, now)?;
                    return Ok(ClaimRecord { intent_id: [0; 16], accepted: false });
                };
                let intent = array16(&intent_raw)?;
                let state = PairingState::parse(&state_raw)?;
                validate_pairing_material(state,old_claimant.as_deref(),old_nonce.as_deref(),old_capability.as_deref(),old_b_nonce.as_deref())?;
                let attempts = u32::try_from(attempts_raw).map_err(|_| RelayError::Database)?;
                let expires = from_sql_i64(expires_raw).map_err(map_sqlite_error)?;
                if now >= expires {
                    if matches!(state, PairingState::Available | PairingState::Claimed) {
                        terminalize_pairing(tx, &intent, PairingState::Expired, now)?;
                    }
                    return Ok(ClaimRecord { intent_id: intent, accepted: false });
                }
                if state == PairingState::Claimed
                    && strict_optional16(old_claimant.as_deref())? == Some(claimant_id)
                    && strict_optional16(old_nonce.as_deref())? == Some(claimant_nonce)
                {
                    return Ok(ClaimRecord { intent_id: intent, accepted: true });
                }
                if state != PairingState::Available {
                    if state == PairingState::Claimed {
                        charge_pairing_attempt(tx, &intent, attempts, now)?;
                    }
                    audit(tx, AuditEvent::ClaimRejected, &intent, 3, now)?;
                    return Ok(ClaimRecord { intent_id: intent, accepted: false });
                }
                let changed = tx.execute(
                    "UPDATE pairing_intents SET state='claimed',claimant_id=?2,claimant_nonce=?3,claim_capability_commitment=?4,b_nonce=?5,updated_at=?6 WHERE intent_id=?1 AND state='available' AND expires_at>?6",
                    params![intent.as_slice(), claimant_id.as_slice(), claimant_nonce.as_slice(), claim_commitment.as_slice(), b_nonce.as_slice(), now_i64],
                ).map_err(map_sqlite_error)?;
                if changed != 1 { return Err(RelayError::Conflict); }
                audit(tx, AuditEvent::PairingClaimed, &intent, 0, now)?;
                Ok(ClaimRecord { intent_id: intent, accepted: true })
            })
            .await?;
        if !record.accepted {
            return Err(RelayError::PairingUnavailable);
        }
        Ok(ClaimResult {
            intent_id: record.intent_id,
            claim_capability: encode_base64url(&claim_capability),
            b_nonce,
        })
    }

    pub async fn cancel_pairing(
        &self,
        device_code: &str,
        now: impl Into<StoreTime>,
    ) -> RelayResult<PairingState> {
        let now = now.into().0;
        let device = decode_base64url_16(device_code).ok_or(RelayError::PairingUnavailable)?;
        let digest = keyed_commitment(&self.inner.secrets, DEVICE_DOMAIN, &device)?;
        let operation_id = operation_key(b"cancel-pairing", &[digest.as_slice()]);
        let request = request_digest(b"cancel-pairing", &[digest.as_slice()]);
        self.write_operation(operation_id, request, now, NORMAL_DEADLINE, move |tx| {
            let row = tx.query_row(
                "SELECT intent_id,state,expires_at FROM pairing_intents WHERE device_code_commitment=?1",
                params![digest.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?)),
            ).optional().map_err(map_sqlite_error)?;
            let Some((intent, state, expires)) = row else { return Err(RelayError::PairingUnavailable); };
            let intent = array16(&intent)?;
            let state = PairingState::parse(&state)?;
            if state == PairingState::Cancelled { return Ok(state); }
            if !matches!(state, PairingState::Available | PairingState::Claimed) {
                return Err(RelayError::PairingUnavailable);
            }
            let terminal = if now >= from_sql_i64(expires).map_err(map_sqlite_error)? {
                PairingState::Expired
            } else {
                PairingState::Cancelled
            };
            terminalize_pairing(tx, &intent, terminal, now)?;
            audit(tx, AuditEvent::PairingCancelled, &intent, terminal as u8, now)?;
            Ok(terminal)
        }).await
    }
}

const MIGRATION_SQL: &str = include_str!("../../migrations/relay_opaque/0001_init.sql");
const MIGRATION_LEDGER_SQL: &str = "CREATE TABLE IF NOT EXISTS relay_opaque_schema_migrations(\
    version INTEGER PRIMARY KEY NOT NULL CHECK(version = 1),\
    migration_checksum BLOB NOT NULL CHECK(length(migration_checksum) = 32),\
    schema_fingerprint BLOB NOT NULL CHECK(length(schema_fingerprint) = 32),\
    applied_at INTEGER NOT NULL CHECK(applied_at >= 0))";
const OWNED_TABLES: &[&str] = &[
    "relay_opaque_schema_migrations",
    "pairing_intents",
    "claim_rate_limits",
    "claim_attempt_operations",
    "confirmation_reports",
    "public_prekeys",
    "opaque_mailbox",
    "mailbox_tombstones",
    "mailbox_quotas",
    "relay_tombstones",
    "relay_operations",
    "fetch_receipts",
    "relay_audit",
];

fn configure_writer(db: &mut Connection) -> RelayResult<()> {
    db.busy_timeout(SQLITE_BUSY_TIMEOUT).map_err(map_sqlite_error)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0; PRAGMA journal_mode=WAL;")
        .map_err(map_sqlite_error)
}

fn configure_read(db: &Connection) -> RelayResult<()> {
    db.busy_timeout(SQLITE_BUSY_TIMEOUT).map_err(map_sqlite_error)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA query_only=ON;").map_err(map_sqlite_error)
}

fn migrate(db: &mut Connection) -> RelayResult<()> {
    let checksum = commitment(b"telegraph/relay-opaque-migration/v1", MIGRATION_SQL.as_bytes());
    let expected = expected_schema_fingerprint()?;
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| RelayError::MigrationFailure)?;
    tx.execute_batch(MIGRATION_LEDGER_SQL).map_err(|_| RelayError::MigrationFailure)?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> = {
        let mut statement = tx.prepare("SELECT version,migration_checksum,schema_fingerprint FROM relay_opaque_schema_migrations ORDER BY version")
            .map_err(|_| RelayError::MigrationFailure)?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|_| RelayError::MigrationFailure)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RelayError::MigrationFailure)?
    };
    if rows.is_empty() {
        tx.execute_batch(MIGRATION_SQL).map_err(|_| RelayError::MigrationFailure)?;
        let actual = schema_fingerprint(&tx).map_err(|_| RelayError::MigrationFailure)?;
        if actual != expected {
            return Err(RelayError::MigrationFailure);
        }
        tx.execute(
            "INSERT INTO relay_opaque_schema_migrations(version,migration_checksum,schema_fingerprint,applied_at) VALUES(1,?1,?2,0)",
            params![checksum.as_slice(), expected.as_slice()],
        ).map_err(|_| RelayError::MigrationFailure)?;
    } else if rows.len() != 1
        || rows[0].0 != 1
        || array32(&rows[0].1).map_err(|_| RelayError::MigrationFailure)? != checksum
        || array32(&rows[0].2).map_err(|_| RelayError::MigrationFailure)? != expected
        || schema_fingerprint(&tx).map_err(|_| RelayError::MigrationFailure)? != expected
    {
        return Err(RelayError::MigrationFailure);
    }
    tx.commit().map_err(|_| RelayError::MigrationFailure)
}

fn expected_schema_fingerprint() -> RelayResult<[u8; 32]> {
    let db = Connection::open_in_memory().map_err(map_sqlite_error)?;
    db.execute_batch(MIGRATION_LEDGER_SQL).map_err(map_sqlite_error)?;
    db.execute_batch(MIGRATION_SQL).map_err(map_sqlite_error)?;
    schema_fingerprint(&db)
}

fn schema_fingerprint(db: &Connection) -> RelayResult<[u8; 32]> {
    let mut statement = db.prepare(
        "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema WHERE type IN ('table','index','trigger') AND name NOT LIKE 'sqlite_autoindex_%' ORDER BY type,name",
    ).map_err(map_sqlite_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(map_sqlite_error)?;
    let mut digest = Sha256::new();
    for row in rows {
        let (kind, name, table, sql) = row.map_err(map_sqlite_error)?;
        if name == "relay_opaque_schema_migrations" || OWNED_TABLES.contains(&table.as_str()) {
            for field in [&kind, &name, &table, &sql] {
                digest.update(
                    u64::try_from(field.len())
                        .map_err(|_| RelayError::MigrationFailure)?
                        .to_be_bytes(),
                );
                digest.update(field.as_bytes());
            }
        }
    }
    Ok(digest.finalize().into())
}

fn hmac32(key: &[u8; 32], domain: &[u8], parts: &[&[u8]]) -> RelayResult<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| RelayError::Internal)?;
    mac.update(domain);
    for part in parts {
        mac.update(&u64::try_from(part.len()).map_err(|_| RelayError::InvalidInput)?.to_be_bytes());
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn hmac16(key: &[u8; 32], domain: &[u8], parts: &[&[u8]]) -> RelayResult<[u8; 16]> {
    array16(&hmac32(key, domain, parts)?[..16])
}

fn operation_commitment(secrets: &SecretKeys, operation_id: &[u8; 16]) -> RelayResult<[u8; 32]> {
    hmac32(&secrets.pairing, OPERATION_DOMAIN, &[operation_id])
}

fn operation_key(domain: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let digest = request_digest(domain, parts);
    let mut output = [0; 16];
    output.copy_from_slice(&digest[..16]);
    output
}

fn request_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn commitment(domain: &[u8], value: &[u8]) -> [u8; 32] {
    request_digest(domain, &[value])
}

fn keyed_commitment(secrets: &SecretKeys, domain: &[u8], value: &[u8]) -> RelayResult<[u8; 32]> {
    hmac32(&secrets.pairing, domain, &[value])
}

fn random_id<const N: usize>() -> RelayResult<[u8; N]> {
    let mut output = [0; N];
    random_fill(&mut output).map_err(|_| RelayError::Internal)?;
    Ok(output)
}

fn array8(bytes: &[u8]) -> RelayResult<[u8; 8]> {
    bytes.try_into().map_err(|_| RelayError::Database)
}
fn array2(bytes: &[u8]) -> RelayResult<[u8; 2]> {
    bytes.try_into().map_err(|_| RelayError::Database)
}
fn array16(bytes: &[u8]) -> RelayResult<[u8; 16]> {
    bytes.try_into().map_err(|_| RelayError::Database)
}
fn array32(bytes: &[u8]) -> RelayResult<[u8; 32]> {
    bytes.try_into().map_err(|_| RelayError::Database)
}
fn strict_optional16(bytes: Option<&[u8]>) -> RelayResult<Option<[u8; 16]>> {
    bytes.map(array16).transpose()
}

fn sqlite_i64(value: u64) -> RelayResult<i64> {
    i64::try_from(value).map_err(|_| RelayError::InvalidInput)
}
fn sqlite_usize(value: usize) -> RelayResult<i64> {
    i64::try_from(value).map_err(|_| RelayError::InvalidInput)
}
fn from_sql_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn map_sqlite_error(error: rusqlite::Error) -> RelayError {
    match &error {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(code.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) =>
        {
            RelayError::Busy
        }
        _ => RelayError::Database,
    }
}

fn map_protocol_error(_: telegraph_protocol::ProtocolError) -> RelayError {
    RelayError::InvalidInput
}

fn read_pairing(row: &Row<'_>) -> rusqlite::Result<PairingStatus> {
    let intent: Vec<u8> = row.get(0)?;
    let state: String = row.get(1)?;
    let nonce: Option<Vec<u8>> = row.get(2)?;
    let claimant: Option<Vec<u8>> = row.get(4)?;
    let claimant_nonce: Option<Vec<u8>> = row.get(5)?;
    let claim_capability: Option<Vec<u8>> = row.get(6)?;
    let state = PairingState::parse(&state).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let b_nonce = nonce
        .map(|value| value.try_into().map_err(|_| rusqlite::Error::InvalidQuery))
        .transpose()?;
    validate_pairing_material(
        state,
        claimant.as_deref(),
        claimant_nonce.as_deref(),
        claim_capability.as_deref(),
        b_nonce.as_ref().map(<[u8; 16]>::as_slice),
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(PairingStatus {
        intent_id: intent.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
        state,
        b_nonce,
        expires_at: from_sql_i64(row.get(3)?)?,
    })
}

fn poll_pairing_state(
    tx: &Transaction<'_>,
    device_commitment: &[u8; 32],
    now: u64,
) -> RelayResult<PairingState> {
    let status = tx
        .query_row(
            "SELECT intent_id,state,b_nonce,expires_at,claimant_id,claimant_nonce,claim_capability_commitment FROM pairing_intents WHERE device_code_commitment=?1",
            params![device_commitment.as_slice()],
            read_pairing,
        )
        .optional()
        .map_err(map_sqlite_error)?
        .ok_or(RelayError::PairingUnavailable)?;
    if now >= status.expires_at
        && matches!(status.state, PairingState::Available | PairingState::Claimed)
    {
        terminalize_pairing(tx, &status.intent_id, PairingState::Expired, now)?;
        return Ok(PairingState::Expired);
    }
    Ok(status.state)
}

fn validate_pairing_material(
    state: PairingState,
    claimant: Option<&[u8]>,
    claimant_nonce: Option<&[u8]>,
    claim_capability: Option<&[u8]>,
    b_nonce: Option<&[u8]>,
) -> RelayResult<()> {
    let present = [
        strict_optional16(claimant)?.is_some(),
        strict_optional16(claimant_nonce)?.is_some(),
        claim_capability.map(array32).transpose()?.is_some(),
        strict_optional16(b_nonce)?.is_some(),
    ];
    let expected = state == PairingState::Claimed;
    if present.into_iter().any(|value| value != expected) {
        return Err(RelayError::Database);
    }
    Ok(())
}

struct ValidatedPrekeyRow {
    prekey_id: [u8; 16],
    bundle: Vec<u8>,
    bundle_digest: [u8; 32],
    state: PrekeyState,
    expires_at: u64,
    reservation_id: Option<[u8; 16]>,
    pairing_id: Option<[u8; 16]>,
}

fn decode_prekey_row(
    expected_id: Option<[u8; 16]>,
    row: (Vec<u8>, Vec<u8>, Vec<u8>, String, i64, Option<Vec<u8>>, Option<Vec<u8>>),
) -> RelayResult<ValidatedPrekeyRow> {
    let prekey_id = array16(&row.0)?;
    if expected_id.is_some_and(|expected| expected != prekey_id) {
        return Err(RelayError::Database);
    }
    let bundle = CanonicalPrekeyBundle::new(row.1).map_err(|_| RelayError::Database)?;
    let bundle_digest = array32(&row.2)?;
    if commitment(BUNDLE_DOMAIN, bundle.as_bytes()) != bundle_digest {
        return Err(RelayError::Database);
    }
    let state = PrekeyState::parse(&row.3)?;
    validate_prekey_material(state, row.5.as_deref(), row.6.as_deref())?;
    Ok(ValidatedPrekeyRow {
        prekey_id,
        bundle: bundle.0,
        bundle_digest,
        state,
        expires_at: from_sql_i64(row.4).map_err(map_sqlite_error)?,
        reservation_id: strict_optional16(row.5.as_deref())?,
        pairing_id: strict_optional16(row.6.as_deref())?,
    })
}

fn load_prekey_by_id(
    db: &Connection,
    prekey_id: [u8; 16],
) -> RelayResult<Option<ValidatedPrekeyRow>> {
    db.query_row(
        "SELECT prekey_id,bundle,bundle_digest,status,expires_at,reservation_id,pairing_id FROM public_prekeys WHERE prekey_id=?1",
        params![prekey_id.as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    )
    .optional()
    .map_err(map_sqlite_error)?
    .map(|row| decode_prekey_row(Some(prekey_id), row))
    .transpose()
}

fn load_prekey_by_reservation(
    db: &Connection,
    reservation_id: [u8; 16],
) -> RelayResult<Option<ValidatedPrekeyRow>> {
    db.query_row(
        "SELECT prekey_id,bundle,bundle_digest,status,expires_at,reservation_id,pairing_id FROM public_prekeys WHERE reservation_id=?1",
        params![reservation_id.as_slice()],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)),
    )
    .optional()
    .map_err(map_sqlite_error)?
    .map(|row| decode_prekey_row(None, row))
    .transpose()
}

fn validate_prekey_material(
    state: PrekeyState,
    reservation: Option<&[u8]>,
    pairing: Option<&[u8]>,
) -> RelayResult<()> {
    let reservation = strict_optional16(reservation)?;
    let pairing = strict_optional16(pairing)?;
    if (state == PrekeyState::Reserved && (reservation.is_none() || pairing.is_none()))
        || (state == PrekeyState::Available && (reservation.is_some() || pairing.is_some()))
        || reservation.is_some() != pairing.is_some()
    {
        return Err(RelayError::Database);
    }
    Ok(())
}

fn validate_id(value: &[u8]) -> RelayResult<()> {
    if value.is_empty() || value.len() > MAX_OPAQUE_ID_LEN {
        return Err(RelayError::InvalidInput);
    }
    Ok(())
}

fn validate_opaque_input(envelope: &OpaqueEnvelope, now: u64, max_ttl: u64) -> RelayResult<()> {
    validate_id(&envelope.mailbox_id)?;
    validate_id(&envelope.delivery_id)?;
    if !envelope.protocol_version.is_supported() {
        return Err(RelayError::InvalidInput);
    }
    if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(RelayError::PayloadTooLarge);
    }
    let maximum = now.checked_add(max_ttl).ok_or(RelayError::InvalidInput)?;
    if envelope.expires_at <= now || envelope.expires_at > maximum {
        return Err(RelayError::Expired);
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}

fn hex16(value: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let value = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        for shift in [18, 12, 6, 0] {
            output.push(char::from(ALPHABET[((value >> shift) & 63) as usize]));
        }
        index += 3;
    }
    match bytes.len() - index {
        1 => {
            let value = u16::from(bytes[index]) << 4;
            output.push(char::from(ALPHABET[usize::from((value >> 6) & 63)]));
            output.push(char::from(ALPHABET[usize::from(value & 63)]));
        }
        2 => {
            let value = (u32::from(bytes[index]) << 10) | (u32::from(bytes[index + 1]) << 2);
            output.push(char::from(ALPHABET[((value >> 12) & 63) as usize]));
            output.push(char::from(ALPHABET[((value >> 6) & 63) as usize]));
            output.push(char::from(ALPHABET[(value & 63) as usize]));
        }
        _ => {}
    }
    output
}

fn decode_base64url_16(value: &str) -> Option<[u8; 16]> {
    if value.len() != 22 || !value.is_ascii() {
        return None;
    }
    let mut output = [0u8; 16];
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let mut written = 0usize;
    for (index, byte) in value.bytes().enumerate() {
        let symbol = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        if index == 21 && symbol & 0x0f != 0 {
            return None;
        }
        accumulator = (accumulator << 6) | u32::from(symbol);
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            if written >= output.len() {
                return None;
            }
            output[written] = ((accumulator >> bits) & 255) as u8;
            written += 1;
        }
    }
    (written == 16 && bits == 4).then_some(output)
}

fn encode_user_code(value: u64) -> String {
    let mut compact = [b'0'; 10];
    for (index, byte) in compact.iter_mut().enumerate() {
        let shift = (9 - index) * 5;
        *byte = CROCKFORD[((value >> shift) & 31) as usize];
    }
    format!(
        "{}-{}",
        std::str::from_utf8(&compact[..5]).unwrap_or("00000"),
        std::str::from_utf8(&compact[5..]).unwrap_or("00000")
    )
}

fn normalize_user_code(value: &str) -> Option<String> {
    if value.len() != 11 || value.as_bytes().get(5) != Some(&b'-') || !value.is_ascii() {
        return None;
    }
    let mut output = String::with_capacity(11);
    for (index, byte) in value.bytes().enumerate() {
        if index == 5 {
            output.push('-');
            continue;
        }
        let upper = byte.to_ascii_uppercase();
        if !CROCKFORD.contains(&upper) {
            return None;
        }
        output.push(char::from(upper));
    }
    Some(output)
}

fn validate_canonical_cbor(bytes: &[u8]) -> RelayResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC_PREKEY_BUNDLE_BYTES {
        return Err(RelayError::InvalidInput);
    }
    let mut scanner = CborScanner { bytes, offset: 0, items: 0 };
    let major = bytes[0] >> 5;
    if major != 5 {
        return Err(RelayError::InvalidInput);
    }
    scanner.item(0)?;
    if scanner.offset != bytes.len() {
        return Err(RelayError::InvalidInput);
    }
    Ok(())
}

struct CborScanner<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
}

impl CborScanner<'_> {
    fn item(&mut self, depth: usize) -> RelayResult<()> {
        if depth > 16 || self.items >= 256 || self.offset >= self.bytes.len() {
            return Err(RelayError::InvalidInput);
        }
        self.items += 1;
        let initial = self.take()?;
        let major = initial >> 5;
        let additional = initial & 31;
        match major {
            0 | 1 => {
                self.argument(additional)?;
            }
            2 | 3 => {
                let length = self.argument(additional)?;
                let length = usize::try_from(length).map_err(|_| RelayError::InvalidInput)?;
                let content = self.take_slice(length)?;
                if major == 3 && std::str::from_utf8(content).is_err() {
                    return Err(RelayError::InvalidInput);
                }
            }
            4 => {
                let length = self.container_length(additional)?;
                for _ in 0..length {
                    self.item(depth + 1)?;
                }
            }
            5 => {
                let length = self.container_length(additional)?;
                let mut previous: Option<(usize, usize)> = None;
                for _ in 0..length {
                    let start = self.offset;
                    self.item(depth + 1)?;
                    let end = self.offset;
                    if let Some((old_start, old_end)) = previous {
                        let old = &self.bytes[old_start..old_end];
                        let new = &self.bytes[start..end];
                        if (old.len(), old).cmp(&(new.len(), new)) != CmpOrdering::Less {
                            return Err(RelayError::InvalidInput);
                        }
                    }
                    previous = Some((start, end));
                    self.item(depth + 1)?;
                }
            }
            7 if matches!(additional, 20..=22) => {}
            _ => return Err(RelayError::InvalidInput),
        }
        Ok(())
    }

    fn container_length(&mut self, additional: u8) -> RelayResult<usize> {
        let value = self.argument(additional)?;
        let length = usize::try_from(value).map_err(|_| RelayError::InvalidInput)?;
        if length > 256 {
            return Err(RelayError::InvalidInput);
        }
        Ok(length)
    }

    fn argument(&mut self, additional: u8) -> RelayResult<u64> {
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.take()?);
                if value < 24 { Err(RelayError::InvalidInput) } else { Ok(value) }
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.take_array()?));
                if value <= u64::from(u8::MAX) { Err(RelayError::InvalidInput) } else { Ok(value) }
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.take_array()?));
                if value <= u64::from(u16::MAX) { Err(RelayError::InvalidInput) } else { Ok(value) }
            }
            27 => {
                let value = u64::from_be_bytes(self.take_array()?);
                if value <= u64::from(u32::MAX) { Err(RelayError::InvalidInput) } else { Ok(value) }
            }
            _ => Err(RelayError::InvalidInput),
        }
    }

    fn take(&mut self) -> RelayResult<u8> {
        let value = *self.bytes.get(self.offset).ok_or(RelayError::InvalidInput)?;
        self.offset += 1;
        Ok(value)
    }
    fn take_array<const N: usize>(&mut self) -> RelayResult<[u8; N]> {
        self.take_slice(N)?.try_into().map_err(|_| RelayError::InvalidInput)
    }
    fn take_slice(&mut self, length: usize) -> RelayResult<&[u8]> {
        let end = self.offset.checked_add(length).ok_or(RelayError::InvalidInput)?;
        let value = self.bytes.get(self.offset..end).ok_or(RelayError::InvalidInput)?;
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
