PRAGMA foreign_keys = ON;

CREATE TABLE pairing_intents (
    intent_id BLOB PRIMARY KEY NOT NULL CHECK(length(intent_id) = 16),
    operation_commitment BLOB UNIQUE NOT NULL CHECK(length(operation_commitment) = 32),
    device_code_commitment BLOB UNIQUE NOT NULL CHECK(length(device_code_commitment) = 32),
    user_code_commitment BLOB UNIQUE NOT NULL CHECK(length(user_code_commitment) = 32),
    state TEXT NOT NULL CHECK(state IN ('available','claimed','expired','burned','cancelled','consumed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
    claimant_id BLOB CHECK(claimant_id IS NULL OR length(claimant_id) = 16),
    claimant_nonce BLOB CHECK(claimant_nonce IS NULL OR length(claimant_nonce) = 16),
    claim_capability_commitment BLOB UNIQUE CHECK(claim_capability_commitment IS NULL OR length(claim_capability_commitment) = 32),
    b_nonce BLOB CHECK(b_nonce IS NULL OR length(b_nonce) = 16),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
);
CREATE INDEX idx_pairing_device_commitment ON pairing_intents(device_code_commitment);
CREATE INDEX idx_pairing_user_commitment ON pairing_intents(user_code_commitment);
CREATE INDEX idx_pairing_expiry ON pairing_intents(state, expires_at);

CREATE TABLE claim_rate_limits (
    source_id BLOB PRIMARY KEY NOT NULL CHECK(length(source_id) = 16),
    attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 5),
    window_started INTEGER NOT NULL CHECK(window_started >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
);
CREATE INDEX idx_claim_rate_expiry ON claim_rate_limits(expires_at);

CREATE TABLE claim_attempt_operations (
    operation_id BLOB PRIMARY KEY NOT NULL CHECK(length(operation_id) = 32),
    source_id BLOB NOT NULL CHECK(length(source_id) = 16),
    intent_id BLOB REFERENCES pairing_intents(intent_id),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
);
CREATE INDEX idx_claim_attempt_expiry ON claim_attempt_operations(expires_at);
CREATE INDEX idx_claim_attempt_intent ON claim_attempt_operations(intent_id);

CREATE TABLE confirmation_reports (
    intent_id BLOB NOT NULL REFERENCES pairing_intents(intent_id),
    side INTEGER NOT NULL CHECK(side IN (0,1)),
    token_digest BLOB NOT NULL CHECK(length(token_digest) = 32),
    reported_at INTEGER NOT NULL CHECK(reported_at >= 0),
    tombstoned INTEGER NOT NULL DEFAULT 0 CHECK(tombstoned IN (0,1)),
    PRIMARY KEY(intent_id, side)
);

CREATE TABLE public_prekeys (
    prekey_id BLOB PRIMARY KEY NOT NULL CHECK(length(prekey_id) = 16),
    bundle BLOB NOT NULL CHECK(length(bundle) BETWEEN 1 AND 1024),
    bundle_digest BLOB UNIQUE NOT NULL CHECK(length(bundle_digest) = 32),
    status TEXT NOT NULL CHECK(status IN ('available','reserved','consumed','burned','tombstoned')),
    reservation_id BLOB UNIQUE CHECK(reservation_id IS NULL OR length(reservation_id) = 16),
    pairing_id BLOB REFERENCES pairing_intents(intent_id) CHECK(pairing_id IS NULL OR length(pairing_id) = 16),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
);
CREATE INDEX idx_prekey_available ON public_prekeys(status, expires_at);
CREATE INDEX idx_prekey_pairing ON public_prekeys(pairing_id, status);
CREATE UNIQUE INDEX idx_prekey_one_reserved_pairing ON public_prekeys(pairing_id) WHERE status = 'reserved';

CREATE TABLE opaque_mailbox (
    mailbox_id BLOB NOT NULL CHECK(length(mailbox_id) BETWEEN 1 AND 256),
    delivery_id BLOB NOT NULL CHECK(length(delivery_id) BETWEEN 1 AND 256),
    protocol_major INTEGER NOT NULL CHECK(protocol_major BETWEEN 0 AND 65535),
    protocol_minor INTEGER NOT NULL CHECK(protocol_minor BETWEEN 0 AND 65535),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) <= 65536),
    payload_digest BLOB NOT NULL CHECK(length(payload_digest) = 32),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes BETWEEN 0 AND 65536),
    envelope_size INTEGER NOT NULL CHECK(envelope_size BETWEEN 1 AND 69632),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
    status TEXT NOT NULL CHECK(status IN ('pending','fetched','acked')),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
    PRIMARY KEY(mailbox_id, delivery_id),
    CHECK(payload_bytes = length(ciphertext))
);
CREATE INDEX idx_mailbox_pending ON opaque_mailbox(mailbox_id, status, expires_at, delivery_id);
CREATE INDEX idx_mailbox_expiry ON opaque_mailbox(status, expires_at);

CREATE TABLE mailbox_tombstones (
    mailbox_id BLOB NOT NULL CHECK(length(mailbox_id) BETWEEN 1 AND 256),
    delivery_id BLOB NOT NULL CHECK(length(delivery_id) BETWEEN 1 AND 256),
    protocol_major INTEGER NOT NULL CHECK(protocol_major BETWEEN 0 AND 65535),
    protocol_minor INTEGER NOT NULL CHECK(protocol_minor BETWEEN 0 AND 65535),
    payload_digest BLOB NOT NULL CHECK(length(payload_digest) = 32),
    envelope_size INTEGER NOT NULL CHECK(envelope_size BETWEEN 1 AND 69632),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
    status TEXT NOT NULL CHECK(status IN ('expired','deleted')),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0),
    PRIMARY KEY(mailbox_id, delivery_id)
);
CREATE INDEX idx_mailbox_tombstone_gc ON mailbox_tombstones(updated_at);

CREATE TABLE mailbox_quotas (
    mailbox_id BLOB PRIMARY KEY NOT NULL CHECK(length(mailbox_id) BETWEEN 1 AND 256),
    max_live_rows INTEGER NOT NULL CHECK(max_live_rows BETWEEN 1 AND 100000),
    max_live_bytes INTEGER NOT NULL CHECK(max_live_bytes BETWEEN 1 AND 1073741824),
    max_tombstones INTEGER NOT NULL CHECK(max_tombstones BETWEEN 1 AND 100000),
    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
);

CREATE TABLE relay_tombstones (
    kind TEXT NOT NULL CHECK(kind IN ('pairing','device_code','user_code','claim','prekey_reservation')),
    opaque_id BLOB NOT NULL,
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    PRIMARY KEY(kind, opaque_id)
);
CREATE INDEX idx_tombstone_created ON relay_tombstones(created_at);

CREATE TABLE relay_operations (
    operation_commitment BLOB PRIMARY KEY NOT NULL CHECK(length(operation_commitment) = 32),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    result_kind INTEGER NOT NULL CHECK(result_kind BETWEEN 0 AND 255),
    result_blob BLOB NOT NULL CHECK(length(result_blob) <= 256),
    completed_at INTEGER NOT NULL CHECK(completed_at >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
);
CREATE INDEX idx_relay_operations_expiry ON relay_operations(expires_at);

CREATE TABLE fetch_receipts (
    operation_commitment BLOB PRIMARY KEY NOT NULL CHECK(length(operation_commitment) = 32),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    mailbox_id BLOB NOT NULL CHECK(length(mailbox_id) BETWEEN 1 AND 256),
    selection_blob BLOB NOT NULL CHECK(length(selection_blob) BETWEEN 2 AND 25802),
    selection_digest BLOB NOT NULL CHECK(length(selection_digest) = 32),
    created_at INTEGER NOT NULL CHECK(created_at >= 0),
    expires_at INTEGER NOT NULL CHECK(expires_at >= created_at)
);
CREATE INDEX idx_fetch_receipts_expiry ON fetch_receipts(expires_at);

CREATE TABLE relay_audit (
    event_code INTEGER NOT NULL CHECK(event_code BETWEEN 1 AND 255),
    opaque_id_digest BLOB CHECK(opaque_id_digest IS NULL OR length(opaque_id_digest) = 32),
    outcome_code INTEGER NOT NULL CHECK(outcome_code BETWEEN 0 AND 255),
    created_at INTEGER NOT NULL CHECK(created_at >= 0)
);
CREATE INDEX idx_audit_created ON relay_audit(created_at);
