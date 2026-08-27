use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc as std_mpsc;
use tempfile::tempdir;

fn policy() -> RelayStorePolicy {
    RelayStorePolicy {
        pairing_ttl_secs: 600,
        max_prekey_ttl_secs: 86_400,
        mailbox_ttl_secs: 86_400,
        tombstone_retention_secs: 604_801,
        operation_retention_secs: 604_800,
        mailbox_max_live_rows: 8,
        mailbox_max_live_bytes: 131_072,
        mailbox_max_tombstones: 8,
        global_max_live_rows: 32,
        global_max_live_bytes: 524_288,
        global_max_tombstones: 32,
    }
}

fn secrets() -> RelayStoreSecrets {
    RelayStoreSecrets::new([0x31; 32], [0x72; 32]).unwrap()
}
fn store() -> RelayOpaqueStore {
    RelayOpaqueStore::open_in_memory(policy(), secrets()).unwrap()
}
fn source(db: &RelayOpaqueStore, value: &[u8]) -> ClaimSource {
    let host = value.first().copied().unwrap_or(1) % 250 + 1;
    db.claim_source_deriver().derive_peer_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, host))).unwrap()
}

fn prekey(id: u8, expires_at: u64) -> PublicPrekey {
    PublicPrekey {
        prekey_id: [id; 16],
        bundle: CanonicalPrekeyBundle::new(vec![0xa1, 0x00, 0x41, id]).unwrap(),
        expires_at,
    }
}

fn envelope(mailbox: u8, delivery: u8, ciphertext: Vec<u8>, expires_at: u64) -> OpaqueEnvelope {
    OpaqueEnvelope {
        mailbox_id: vec![mailbox],
        delivery_id: vec![delivery],
        protocol_version: ProtocolVersion::current(),
        ciphertext,
        size: 1,
        expires_at,
    }
}

async fn poll_at(db: &RelayOpaqueStore, device_code: &str, now: u64) -> RelayResult<PairingStatus> {
    let operation_id =
        operation_key(b"test-poll-pairing", &[device_code.as_bytes(), &now.to_be_bytes()]);
    db.poll_pairing(operation_id, device_code, now).await
}

async fn claimed_with_prekey(
    db: &RelayOpaqueStore,
) -> (CreatedPairing, ClaimResult, PrekeyReservation) {
    let created = db.create_pairing_intent_with_operation([1; 16], 100).await.unwrap();
    let claim = db
        .claim_pairing(&created.user_code, &source(db, b"198.51.100.1"), [2; 16], [3; 16], 101)
        .await
        .unwrap();
    db.publish_prekey(prekey(4, 500), 101).await.unwrap();
    let reservation = db.reserve_prekey(created.intent_id, [4; 16], [5; 16], 102).await.unwrap();
    (created, claim, reservation)
}

async fn count(db: &RelayOpaqueStore, table: &'static str) -> i64 {
    let sql = format!("SELECT count(*) FROM {table}");
    db.read(move |conn| conn.query_row(&sql, [], |row| row.get(0)).map_err(map_sqlite_error))
        .await
        .unwrap()
}

async fn cleanup_reconciled(
    db: &RelayOpaqueStore,
    operation_id: [u8; 16],
    now: u64,
) -> CleanupSummary {
    // A maintenance call can time out while its durable operation is still
    // running.  Reconcile the stable operation ID and replay the ledger
    // result; yielding lets the writer finish without imposing a wall-clock
    // assumption on this test.
    for _ in 0..128 {
        match db.cleanup(operation_id, now).await {
            Ok(summary) => return summary,
            Err(RelayError::OutcomeUnknown { .. }) | Err(RelayError::DeadlineExceeded) => {
                if db.reconcile_operation(operation_id).await.unwrap().is_some() {
                    match db.cleanup(operation_id, now).await {
                        Ok(summary) => return summary,
                        Err(RelayError::OutcomeUnknown { .. })
                        | Err(RelayError::DeadlineExceeded) => {}
                        Err(error) => panic!("cleanup replay failed: {error:?}"),
                    }
                }
                tokio::task::yield_now().await;
            }
            Err(error) => panic!("cleanup failed: {error:?}"),
        }
    }
    panic!("cleanup operation did not reconcile after bounded retries");
}

#[tokio::test]
async fn policy_and_secrets_fail_closed_and_debug_redacts() {
    let mut invalid = policy();
    invalid.pairing_ttl_secs = 0;
    assert_eq!(invalid.validate(), Err(RelayError::InvalidInput));
    assert!(RelayStoreSecrets::new([0; 32], [2; 32]).is_err());
    assert!(RelayStoreSecrets::new([1; 32], [1; 32]).is_err());
    assert_eq!(format!("{:?}", secrets()), "RelayStoreSecrets([REDACTED])");
    assert!(
        secrets()
            .claim_source_deriver()
            .derive_peer_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)))
            .is_ok()
    );
    assert_eq!(format!("{:?}", ClaimSource([9; 16])), "ClaimSource([REDACTED])");
    assert_eq!(format!("{:?}", store().timestamp().unwrap()), "StoreTime([SEALED])");
}

#[tokio::test]
async fn reserve_ledger_replay_rechecks_dynamic_expiry_without_rewriting_receipt() {
    let db = store();
    let (created, _claim, reservation) = claimed_with_prekey(&db).await;
    assert_eq!(
        db.reserve_prekey(
            created.intent_id,
            reservation.prekey_id,
            reservation.reservation_id,
            500
        )
        .await,
        Err(RelayError::Expired)
    );
    assert_eq!(db.read_prekey(reservation.prekey_id).await.unwrap().state, PrekeyState::Burned);
    assert_eq!(poll_at(&db, &created.device_code, 500).await.unwrap().state, PairingState::Expired);
    let operation = operation_key(b"reserve-prekey", &[&reservation.reservation_id]);
    assert_eq!(db.reconcile_operation(operation).await.unwrap().unwrap().result_kind, 8);
}

#[tokio::test]
async fn fetch_receipt_restarts_and_settled_selection_is_not_reselected() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("fetch.db");
    let first = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    first.submit_opaque(envelope(42, 1, vec![7], 1000), 100).await.unwrap();
    let operation = [0x42; 16];
    assert_eq!(first.fetch_mailbox(operation, &[42], 1, 101).await.unwrap().envelopes.len(), 1);
    drop(first);
    let second = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    assert_eq!(second.fetch_mailbox(operation, &[42], 1, 102).await.unwrap().envelopes.len(), 1);
    second.submit_opaque(envelope(42, 2, vec![8], 1000), 102).await.unwrap();
    second.acknowledge_transport(&[42], &[1], 103).await.unwrap();
    let settled = second.fetch_mailbox(operation, &[42], 1, 104).await.unwrap();
    assert!(settled.envelopes.is_empty());
    assert_eq!(
        settled.settled,
        vec![SettledDelivery { delivery_id: vec![1], state: TransportState::Acked }]
    );
    second.delete_delivery(&[42], &[1], 105).await.unwrap();
    let deleted = second.fetch_mailbox(operation, &[42], 1, 106).await.unwrap();
    assert!(deleted.envelopes.is_empty());
    assert_eq!(
        deleted.settled,
        vec![SettledDelivery { delivery_id: vec![1], state: TransportState::Deleted }]
    );
    let next = second.fetch_mailbox([0x43; 16], &[42], 1, 106).await.unwrap();
    assert_eq!(next.envelopes[0].envelope.delivery_id, vec![2]);
    assert_eq!(count(&second, "fetch_receipts").await, 2);
}

#[tokio::test]
async fn prekey_lifecycle_revalidates_bundle_and_max_ttl() {
    let db = store();
    assert_eq!(db.publish_prekey(prekey(77, 86_501), 100).await, Err(RelayError::Expired));
    let (_created, _claim, reservation) = claimed_with_prekey(&db).await;
    let prekey_id = reservation.prekey_id;
    let reservation_id = reservation.reservation_id;
    db.write_connection([0x77; 16], NORMAL_DEADLINE, move |conn| {
        conn.execute(
            "UPDATE public_prekeys SET bundle=x'bf' WHERE prekey_id=?1",
            params![prekey_id.as_slice()],
        )
        .map_err(map_sqlite_error)?;
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(db.reconcile_prekey(reservation_id).await, Err(RelayError::Database));
}

#[test]
fn pending_audit_ring_is_strictly_bounded_and_coalesces_drops() {
    let mut queue = VecDeque::new();
    let mut dropped = 0;
    for value in 0..(WRITER_QUEUE_CAPACITY + 9) {
        enqueue_pending_audit(&mut queue, &mut dropped, AuditEvent::Failure, vec![value as u8]);
    }
    assert_eq!(queue.len(), WRITER_QUEUE_CAPACITY);
    assert_eq!(dropped, 9);
}

#[tokio::test]
async fn maintenance_savepoint_rollback_does_not_poison_following_actual_delta() {
    let db = store();
    db.write_connection([0x7a; 16], NORMAL_DEADLINE, |conn| {
        let tx = conn.transaction().map_err(map_sqlite_error)?;
        let mut maintenance = MaintenanceBudget::with_reserved_rows(999)?;
        assert!(matches!(
            maintenance.attempt(&tx, |candidate| {
                candidate
                    .execute_batch(
                        "INSERT INTO relay_audit(event_code,outcome_code,created_at) VALUES(1,0,1); \
                         INSERT INTO relay_audit(event_code,outcome_code,created_at) VALUES(1,0,1);",
                    )
                    .map_err(map_sqlite_error)
            })?,
            MaintenanceAttempt::BudgetExhausted
        ));
        assert_eq!(
            tx.query_row("SELECT count(*) FROM relay_audit", [], |row| row.get::<_, i64>(0))
                .map_err(map_sqlite_error)?,
            0
        );
        assert!(matches!(
            maintenance.attempt(&tx, |candidate| {
                candidate
                    .execute(
                        "INSERT INTO relay_audit(event_code,outcome_code,created_at) VALUES(1,0,1)",
                        [],
                    )
                    .map(|_| ())
                    .map_err(map_sqlite_error)
            })?,
            MaintenanceAttempt::Applied(())
        ));
        assert_eq!(maintenance.committed, 1);
        tx.commit().map_err(map_sqlite_error)
    })
    .await
    .unwrap();
}

#[test]
fn canonical_codes_reject_padding_and_aliases() {
    let raw = [0xff; 16];
    let encoded = encode_base64url(&raw);
    assert_eq!(decode_base64url_16(&encoded), Some(raw));
    assert!(decode_base64url_16(&(encoded.clone() + "=")).is_none());
    let mut alias = encoded.into_bytes();
    alias[21] = b'_';
    assert!(decode_base64url_16(std::str::from_utf8(&alias).unwrap()).is_none());
    assert!(normalize_user_code("00000-0000O").is_none());
    assert_eq!(normalize_user_code("abcde-fghjk").as_deref(), Some("ABCDE-FGHJK"));
}

#[tokio::test]
async fn low_entropy_operation_does_not_become_a_capability_or_enter_sqlite() {
    let db = store();
    let operation = [0; 16];
    let created = db.create_pairing_intent_with_operation(operation, 100).await.unwrap();
    assert_ne!(created.device_code.as_bytes(), operation);
    assert_ne!(created.user_code, "00000-00000");
    let leaked = created.device_code.clone();
    let rows = db.read(move |conn| {
        let mut statement = conn.prepare("SELECT operation_commitment,device_code_commitment,user_code_commitment FROM pairing_intents").map_err(map_sqlite_error)?;
        statement.query_row([], |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,Vec<u8>>(2)?))).map_err(map_sqlite_error)
    }).await.unwrap();
    assert_eq!(rows.0.len(), 32);
    assert_eq!(rows.1.len(), 32);
    assert_eq!(rows.2.len(), 32);
    assert_ne!(rows.2, commitment(USER_DOMAIN, created.user_code.as_bytes()));
    assert!(!rows.0.windows(leaked.len()).any(|window| window == leaked.as_bytes()));
    assert!(!format!("{created:?}").contains(&created.device_code));
}

#[tokio::test]
async fn pairing_restart_reconciles_with_external_secret_only() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("relay.db");
    let first = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    let created = first.create_pairing_intent_with_operation([7; 16], 100).await.unwrap();
    drop(first);
    let reopened = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    let repeated = reopened.create_pairing_intent_with_operation([7; 16], 100).await.unwrap();
    assert_eq!(created, repeated);
    assert_eq!(
        poll_at(&reopened, &created.device_code, 101).await.unwrap().state,
        PairingState::Available
    );
}

#[tokio::test]
async fn claim_is_single_winner_and_every_attempt_charges_stable_source() {
    let db = store();
    let created = db.create_pairing_intent_with_operation([8; 16], 100).await.unwrap();
    let origin = source(&db, b"203.0.113.9");
    let first = db.claim_pairing(&created.user_code, &origin, [1; 16], [2; 16], 101).await.unwrap();
    assert_eq!(first.intent_id, created.intent_id);
    assert_eq!(
        db.claim_pairing(&created.user_code, &origin, [3; 16], [4; 16], 102).await,
        Err(RelayError::PairingUnavailable)
    );
    for index in 0..4 {
        let _ = db
            .claim_pairing("00000-00000", &origin, [9; 16], [index; 16], 103 + u64::from(index))
            .await;
    }
    assert_eq!(
        db.claim_pairing("11111-11111", &origin, [8; 16], [9; 16], 110).await,
        Err(RelayError::PairingUnavailable)
    );
    assert_eq!(count(&db, "claim_rate_limits").await, 1);
}

#[tokio::test]
async fn exact_claim_retry_does_not_double_charge() {
    let db = store();
    let created = db.create_pairing_intent_with_operation([9; 16], 100).await.unwrap();
    let origin = source(&db, b"origin");
    let first = db.claim_pairing(&created.user_code, &origin, [1; 16], [2; 16], 101).await.unwrap();
    let second =
        db.claim_pairing(&created.user_code, &origin, [1; 16], [2; 16], 101).await.unwrap();
    assert_eq!(first, second);
    let attempts = db
        .read(move |conn| {
            conn.query_row("SELECT attempts FROM claim_rate_limits", [], |row| row.get::<_, i64>(0))
                .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(attempts, 1);
}

#[test]
fn opaque_prekey_cbor_is_bounded_and_deterministic() {
    assert!(CanonicalPrekeyBundle::new(vec![0xa1, 0x00, 0x41, 1]).is_ok());
    assert!(CanonicalPrekeyBundle::new(vec![0xa2, 0x01, 0x00, 0x00, 0x00]).is_err());
    assert!(CanonicalPrekeyBundle::new(vec![0xa1, 0x18, 0x00, 0x00]).is_err());
    assert!(CanonicalPrekeyBundle::new(vec![0xbf, 0xff]).is_err());
    assert!(CanonicalPrekeyBundle::new(vec![0xa1, 0x00, 0x5a, 0xff, 0xff, 0xff, 0xff]).is_err());
    assert!(CanonicalPrekeyBundle::new(vec![0; MAX_PUBLIC_PREKEY_BUNDLE_BYTES + 1]).is_err());
    let mut seed = 0x9e37_79b9u32;
    for length in 1..=MAX_PUBLIC_PREKEY_BUNDLE_BYTES {
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (seed >> 24) as u8;
        }
        assert!(std::panic::catch_unwind(|| CanonicalPrekeyBundle::new(bytes)).is_ok());
    }
}

#[tokio::test]
async fn prekey_is_byte_exact_idempotent_and_terminal_republish_is_stable() {
    let db = store();
    let (_, _, reservation) = claimed_with_prekey(&db).await;
    let read = db.read_prekey([4; 16]).await.unwrap();
    assert_eq!(read.bundle.as_bytes(), &[0xa1, 0x00, 0x41, 4]);
    assert_eq!(db.publish_prekey(prekey(4, 500), 103).await.unwrap(), PrekeyState::Reserved);
    assert_eq!(db.publish_prekey(prekey(4, 501), 103).await, Err(RelayError::IdempotencyConflict));
    assert_eq!(
        db.consume_prekey(reservation.reservation_id, 104).await.unwrap(),
        PrekeyState::Consumed
    );
    assert_eq!(
        db.reconcile_prekey(reservation.reservation_id).await.unwrap(),
        PrekeyState::Consumed
    );
    assert_eq!(db.publish_prekey(prekey(4, 500), 105).await.unwrap(), PrekeyState::Consumed);
}

#[tokio::test]
async fn confirmation_requires_side_capabilities_and_one_live_reservation() {
    let db = store();
    let (created, claim, _) = claimed_with_prekey(&db).await;
    assert_eq!(
        db.report_creator_confirmation(created.intent_id, &claim.claim_capability, b"a", 103).await,
        Err(RelayError::PairingUnavailable)
    );
    assert_eq!(
        db.report_claimant_confirmation(created.intent_id, &created.device_code, b"b", 103).await,
        Err(RelayError::PairingUnavailable)
    );
    assert_eq!(
        db.report_creator_confirmation(created.intent_id, &created.device_code, b"a", 103)
            .await
            .unwrap(),
        ConfirmationResult::Pending
    );
    assert_eq!(
        db.report_claimant_confirmation(created.intent_id, &claim.claim_capability, b"b", 104)
            .await
            .unwrap(),
        ConfirmationResult::BothComplete
    );
    assert_eq!(
        db.report_claimant_confirmation(created.intent_id, &claim.claim_capability, b"b", 104)
            .await
            .unwrap(),
        ConfirmationResult::BothComplete
    );
    assert_eq!(
        poll_at(&db, &created.device_code, 104).await.unwrap().state,
        PairingState::Consumed
    );
    assert_eq!(db.read_prekey([4; 16]).await.unwrap().state, PrekeyState::Consumed);
    assert_eq!(count(&db, "confirmation_reports").await, 2);
}

#[tokio::test]
async fn confirmation_rejects_missing_expired_and_consumed_reservation() {
    let db = store();
    let created = db.create_pairing_intent_with_operation([0x11; 16], 100).await.unwrap();
    let claim = db
        .claim_pairing(&created.user_code, &source(&db, b"x"), [1; 16], [2; 16], 101)
        .await
        .unwrap();
    assert_eq!(
        db.report_creator_confirmation(created.intent_id, &created.device_code, b"a", 102).await,
        Err(RelayError::PrekeyUnavailable)
    );
    db.publish_prekey(prekey(6, 104), 102).await.unwrap();
    let reservation = db.reserve_prekey(created.intent_id, [6; 16], [7; 16], 102).await.unwrap();
    assert_eq!(
        db.report_creator_confirmation(created.intent_id, &created.device_code, b"a2", 104).await,
        Err(RelayError::PrekeyUnavailable)
    );
    assert_eq!(poll_at(&db, &created.device_code, 104).await.unwrap().state, PairingState::Burned);
    assert_eq!(db.burn_prekey(reservation.reservation_id, 104).await.unwrap(), PrekeyState::Burned);
    assert_eq!(
        db.report_claimant_confirmation(created.intent_id, &claim.claim_capability, b"b", 104)
            .await,
        Err(RelayError::PairingUnavailable)
    );
}

#[tokio::test]
async fn expired_prekey_reservation_commits_burn_before_rejection() {
    let db = store();
    let created = db.create_pairing_intent_with_operation([0x21; 16], 100).await.unwrap();
    db.claim_pairing(&created.user_code, &source(&db, b"expired"), [1; 16], [2; 16], 101)
        .await
        .unwrap();
    db.publish_prekey(prekey(9, 103), 101).await.unwrap();
    assert_eq!(
        db.reserve_prekey(created.intent_id, [9; 16], [8; 16], 103).await,
        Err(RelayError::Expired)
    );
    assert_eq!(db.read_prekey([9; 16]).await.unwrap().state, PrekeyState::Burned);
}

#[tokio::test]
async fn transport_is_at_least_once_pending_first_and_tombstones_release_payload() {
    let db = store();
    db.submit_opaque(envelope(1, 1, vec![1], 1000), 100).await.unwrap();
    let first = db.fetch_mailbox([31; 16], &[1], 1, 101).await.unwrap();
    assert_eq!(first.envelopes[0].envelope.delivery_id, vec![1]);
    db.submit_opaque(envelope(1, 2, vec![2], 1000), 102).await.unwrap();
    let second = db.fetch_mailbox([32; 16], &[1], 1, 103).await.unwrap();
    assert_eq!(second.envelopes[0].envelope.delivery_id, vec![2]);
    let repeated = db.fetch_mailbox([33; 16], &[1], 2, 104).await.unwrap();
    assert_eq!(repeated.envelopes.len(), 2);
    db.delete_delivery(&[1], &[1], 105).await.unwrap();
    let bytes = db
        .read(move |conn| {
            conn.query_row("SELECT coalesce(sum(payload_bytes),0) FROM opaque_mailbox", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(bytes, 1);
}

#[tokio::test]
async fn delivery_id_is_idempotent_but_payload_conflicts() {
    let db = store();
    let original = envelope(2, 1, vec![7, 8], 1000);
    assert_eq!(db.submit_opaque(original.clone(), 100).await.unwrap(), TransportState::Pending);
    assert_eq!(db.submit_opaque(original, 100).await.unwrap(), TransportState::Pending);
    assert_eq!(
        db.submit_opaque(envelope(2, 1, vec![9], 1000), 100).await,
        Err(RelayError::IdempotencyConflict)
    );
    db.delete_delivery(&[2], &[1], 101).await.unwrap();
    assert_eq!(
        db.submit_opaque(envelope(2, 1, vec![7, 8], 1000), 102).await.unwrap(),
        TransportState::Deleted
    );
    let typed = Envelope::new(
        ProtocolVersion::current(),
        MailboxId::new(vec![2]).unwrap(),
        DeliveryId::new(vec![2]).unwrap(),
        vec![3],
        1000,
    )
    .unwrap();
    assert_eq!(db.submit_envelope(typed, 103).await.unwrap(), TransportState::Pending);
}

#[tokio::test]
async fn all_public_input_bounds_fail_before_queue_side_effects() {
    let db = store();
    let before = count(&db, "relay_operations").await;
    assert_eq!(db.depth(&vec![1; MAX_OPAQUE_ID_LEN + 1], 1).await, Err(RelayError::InvalidInput));
    assert_eq!(
        db.acknowledge_transport(&[1], &vec![2; MAX_OPAQUE_ID_LEN + 1], 1).await,
        Err(RelayError::InvalidInput)
    );
    assert_eq!(
        db.submit_opaque(envelope(1, 1, vec![0; MAX_CIPHERTEXT_BYTES + 1], 1000), 100).await,
        Err(RelayError::PayloadTooLarge)
    );
    assert_eq!(count(&db, "relay_operations").await, before);
}

#[tokio::test]
async fn corrupt_mail_rows_fail_closed() {
    let db = store();
    db.submit_opaque(envelope(3, 1, vec![1, 2, 3], 1000), 100).await.unwrap();
    db.write_connection([0x31;16], NORMAL_DEADLINE, |conn| {
        conn.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE opaque_mailbox SET payload_digest=zeroblob(32); PRAGMA ignore_check_constraints=OFF;").map_err(map_sqlite_error)
    }).await.unwrap();
    assert_eq!(db.fetch_mailbox([34; 16], &[3], 10, 101).await, Err(RelayError::Database));
}

#[tokio::test]
async fn corrupt_fetched_row_cannot_starve_a_new_pending_row() {
    let db = store();
    db.submit_opaque(envelope(7, 1, vec![1], 1000), 100).await.unwrap();
    db.fetch_mailbox([35; 16], &[7], 10, 101).await.unwrap();
    db.write_connection([0x91;16], NORMAL_DEADLINE, |conn| {
        conn.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE opaque_mailbox SET payload_digest=zeroblob(32) WHERE delivery_id=x'01'; PRAGMA ignore_check_constraints=OFF;").map_err(map_sqlite_error)
    }).await.unwrap();
    db.submit_opaque(envelope(7, 2, vec![2], 1000), 102).await.unwrap();
    let pending = db.fetch_mailbox([36; 16], &[7], 10, 103).await.unwrap();
    assert_eq!(pending.envelopes.len(), 1);
    assert_eq!(pending.envelopes[0].envelope.delivery_id, vec![2]);
    assert_eq!(db.fetch_mailbox([37; 16], &[7], 10, 104).await, Err(RelayError::Database));
}

#[tokio::test]
async fn corrupt_optional_state_size_and_bundle_rows_fail_closed() {
    for sql in [
        "PRAGMA ignore_check_constraints=ON; UPDATE opaque_mailbox SET payload_bytes=99; PRAGMA ignore_check_constraints=OFF;",
        "PRAGMA ignore_check_constraints=ON; UPDATE opaque_mailbox SET envelope_size=1; PRAGMA ignore_check_constraints=OFF;",
        "PRAGMA ignore_check_constraints=ON; UPDATE opaque_mailbox SET status='unknown'; PRAGMA ignore_check_constraints=OFF;",
        "PRAGMA ignore_check_constraints=ON; UPDATE opaque_mailbox SET delivery_id=x''; PRAGMA ignore_check_constraints=OFF;",
    ] {
        let db = store();
        db.submit_opaque(envelope(3, 1, vec![1, 2, 3], 1000), 100).await.unwrap();
        db.write_connection([0x32; 16], NORMAL_DEADLINE, move |conn| {
            conn.execute_batch(sql).map_err(map_sqlite_error)
        })
        .await
        .unwrap();
        assert_eq!(db.fetch_mailbox([38; 16], &[3], 10, 101).await, Err(RelayError::Database));
    }
    let db = store();
    let created = db.create_pairing_intent_with_operation([0x33; 16], 100).await.unwrap();
    db.write_connection([0x34;16], NORMAL_DEADLINE, |conn| conn.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE pairing_intents SET b_nonce=x'01'; PRAGMA ignore_check_constraints=OFF;").map_err(map_sqlite_error)).await.unwrap();
    assert_eq!(poll_at(&db, &created.device_code, 101).await, Err(RelayError::Database));
    let db = store();
    db.publish_prekey(prekey(8, 500), 100).await.unwrap();
    db.write_connection([0x35; 16], NORMAL_DEADLINE, |conn| {
        conn.execute("UPDATE public_prekeys SET bundle=x'bf'", [])
            .map(|_| ())
            .map_err(map_sqlite_error)
    })
    .await
    .unwrap();
    assert_eq!(db.read_prekey([8; 16]).await, Err(RelayError::Database));
}

#[tokio::test]
async fn tombstone_quota_never_evicts_within_retention_and_reuse_waits_for_cleanup() {
    let mut small = policy();
    small.pairing_ttl_secs = 5;
    small.max_prekey_ttl_secs = 5;
    small.mailbox_ttl_secs = 10;
    small.operation_retention_secs = 11;
    small.tombstone_retention_secs = 20;
    small.mailbox_max_tombstones = 2;
    small.global_max_tombstones = 2;
    let db = RelayOpaqueStore::open_in_memory(small, secrets()).unwrap();
    for delivery in 1..=2 {
        db.submit_opaque(envelope(4, delivery, vec![delivery], 105), 100).await.unwrap();
        db.delete_delivery(&[4], &[delivery], 100 + u64::from(delivery)).await.unwrap();
    }
    db.submit_opaque(envelope(4, 3, vec![3], 106), 102).await.unwrap();
    assert_eq!(db.delete_delivery(&[4], &[3], 103).await, Err(RelayError::QuotaExceeded));
    assert_eq!(count(&db, "mailbox_tombstones").await, 2);
    assert_eq!(db.depth(&[4], 103).await.unwrap(), 1);
    assert_eq!(
        db.submit_opaque(envelope(4, 1, vec![1], 105), 104).await.unwrap(),
        TransportState::Deleted
    );
    assert_eq!(
        db.submit_opaque(envelope(4, 1, vec![9], 105), 104).await,
        Err(RelayError::IdempotencyConflict)
    );

    let blocked = db.cleanup([0xc1; 16], 113).await.unwrap();
    assert!(blocked.remaining);
    assert_eq!(count(&db, "mailbox_tombstones").await, 2);
    assert_eq!(
        db.submit_opaque(envelope(4, 4, vec![4], 120), 113).await,
        Err(RelayError::QuotaExceeded)
    );
    assert_eq!(count(&db, "opaque_mailbox").await, 1);
    let delete_operation =
        operation_key(b"transition-transport", &[&[4], &[1], &[TransportState::Deleted as u8]]);
    assert!(db.reconcile_operation(delete_operation).await.unwrap().is_none());
    assert_eq!(db.delete_delivery(&[4], &[1], 113).await.unwrap(), TransportState::Deleted);

    db.cleanup([0xc2; 16], 123).await.unwrap();
    assert_eq!(count(&db, "mailbox_tombstones").await, 1);
    assert_eq!(
        db.submit_opaque(envelope(4, 1, vec![9], 130), 124).await.unwrap(),
        TransportState::Pending
    );
}

#[tokio::test]
async fn policy_lowering_preserves_unexpired_tombstones_and_blocks_new_tombstones() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("lower-tombstone-policy.db");
    let mut high = policy();
    high.pairing_ttl_secs = 5;
    high.max_prekey_ttl_secs = 5;
    high.mailbox_ttl_secs = 10;
    high.operation_retention_secs = 11;
    high.tombstone_retention_secs = 20;
    high.mailbox_max_tombstones = 3;
    high.global_max_tombstones = 3;
    let db = RelayOpaqueStore::open(&path, high, secrets()).unwrap();
    for delivery in 1..=3 {
        let mailbox = 5 + delivery;
        db.submit_opaque(envelope(mailbox, 1, vec![delivery], 105), 100).await.unwrap();
        db.delete_delivery(&[mailbox], &[1], 100 + u64::from(delivery)).await.unwrap();
    }
    drop(db);

    let mut low = high;
    low.mailbox_max_tombstones = 2;
    low.global_max_tombstones = 2;
    let reopened = RelayOpaqueStore::open(&path, low, secrets()).unwrap();
    let summary = reopened.cleanup([0xc3; 16], 104).await.unwrap();
    assert!(summary.remaining);
    assert_eq!(count(&reopened, "mailbox_tombstones").await, 3);
    reopened.submit_opaque(envelope(9, 1, vec![4], 110), 104).await.unwrap();
    assert_eq!(reopened.delete_delivery(&[9], &[1], 104).await, Err(RelayError::QuotaExceeded));
    assert_eq!(count(&reopened, "mailbox_tombstones").await, 3);
}

#[tokio::test]
async fn operation_and_fetch_receipt_expire_before_tombstone_becomes_eligible() {
    let mut boundary = policy();
    boundary.pairing_ttl_secs = 5;
    boundary.max_prekey_ttl_secs = 5;
    boundary.mailbox_ttl_secs = 10;
    boundary.operation_retention_secs = 11;
    boundary.tombstone_retention_secs = 12;
    let db = RelayOpaqueStore::open_in_memory(boundary, secrets()).unwrap();
    let fetch_operation = [0xc4; 16];
    db.submit_opaque(envelope(10, 1, vec![1], 110), 100).await.unwrap();
    db.fetch_mailbox(fetch_operation, &[10], 1, 100).await.unwrap();
    db.delete_delivery(&[10], &[1], 101).await.unwrap();

    let at_111 = db.cleanup([0xc7; 16], 111).await.unwrap();
    assert_eq!(at_111.purged_rows, 0);
    assert_eq!(count(&db, "fetch_receipts").await, 1);
    assert!(db.reconcile_operation(fetch_operation).await.unwrap().is_some());
    assert_eq!(count(&db, "mailbox_tombstones").await, 1);

    let at_112 = db.cleanup([0xc5; 16], 112).await.unwrap();
    assert_eq!(at_112.purged_rows, 0);
    assert_eq!(count(&db, "fetch_receipts").await, 0);
    assert!(db.reconcile_operation(fetch_operation).await.unwrap().is_none());
    assert_eq!(count(&db, "mailbox_tombstones").await, 1);

    let at_113 = db.cleanup([0xc6; 16], 113).await.unwrap();
    assert_eq!(at_113.purged_rows, 1);
    assert_eq!(count(&db, "mailbox_tombstones").await, 0);
}

#[tokio::test]
async fn queued_future_drop_cancels_without_side_effect() {
    let db = store();
    let (started_tx, started_rx) = std_mpsc::sync_channel(0);
    let (release_tx, release_rx) = std_mpsc::sync_channel(0);
    let first_db = db.clone();
    let first = tokio::spawn(async move {
        first_db
            .write_connection([1; 16], Duration::from_secs(1), move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(move || started_rx.recv().unwrap()).await.unwrap();
    let second_db = db.clone();
    let mut queued =
        Box::pin(second_db.write_connection([2; 16], Duration::from_secs(1), |conn| {
            conn.execute(
                "INSERT INTO relay_audit(event_code,outcome_code,created_at) VALUES(1,0,1)",
                [],
            )
            .map_err(map_sqlite_error)?;
            Ok(())
        }));
    tokio::select! { biased; result = &mut queued => panic!("queued operation unexpectedly completed: {result:?}"), _ = tokio::task::yield_now() => {} }
    drop(queued);
    release_tx.send(()).unwrap();
    first.await.unwrap().unwrap();
    db.checkpoint([3; 16], 2).await.unwrap();
    let injected: i64 = db
        .read(move |conn| {
            conn.query_row(
                "SELECT count(*) FROM relay_audit WHERE event_code=1 AND created_at=1",
                [],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(injected, 0);
    let cancelled: i64 = db
        .read(move |conn| {
            conn.query_row("SELECT count(*) FROM relay_audit WHERE event_code=21", [], |row| {
                row.get(0)
            })
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(cancelled, 1);
}

#[tokio::test]
async fn queued_deadline_is_audited_and_never_starts() {
    let db = store();
    let (started_tx, started_rx) = std_mpsc::sync_channel(0);
    let (release_tx, release_rx) = std_mpsc::sync_channel(0);
    let first_db = db.clone();
    let first = tokio::spawn(async move {
        first_db
            .write_connection([0x81; 16], Duration::from_secs(1), move |_| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(move || started_rx.recv().unwrap()).await.unwrap();
    let result = db
        .write_connection([0x82; 16], Duration::from_millis(5), |conn| {
            conn.execute(
                "INSERT INTO relay_audit(event_code,outcome_code,created_at) VALUES(1,0,9)",
                [],
            )
            .map(|_| ())
            .map_err(map_sqlite_error)
        })
        .await;
    assert_eq!(result, Err(RelayError::DeadlineExceeded));
    release_tx.send(()).unwrap();
    first.await.unwrap().unwrap();
    db.checkpoint([0x83; 16], 10).await.unwrap();
    let counts: (i64, i64) = db
        .read(move |conn| {
            conn.query_row(
                "SELECT sum(event_code=22),sum(created_at=9) FROM relay_audit",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(counts, (1, 0));
}

#[tokio::test]
async fn started_timeout_is_outcome_unknown_and_commits_once() {
    let db = store();
    let (started_tx, started_rx) = std_mpsc::sync_channel(0);
    let (release_tx, release_rx) = std_mpsc::sync_channel(0);
    let worker = db.clone();
    let call = tokio::spawn(async move {
        worker
            .write_connection([9; 16], Duration::from_millis(5), move |conn| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                conn.execute(
                    "INSERT INTO relay_audit(event_code,outcome_code,created_at) VALUES(1,0,1)",
                    [],
                )
                .map_err(map_sqlite_error)?;
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(move || started_rx.recv().unwrap()).await.unwrap();
    let result = call.await.unwrap();
    assert_eq!(result, Err(RelayError::OutcomeUnknown { operation_id: [9; 16] }));
    release_tx.send(()).unwrap();
    db.checkpoint([10; 16], 2).await.unwrap();
    let committed: i64 = db
        .read(move |conn| {
            conn.query_row(
                "SELECT count(*) FROM relay_audit WHERE event_code=1 AND created_at=1",
                [],
                |row| row.get(0),
            )
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(committed, 1);
    let unknown: i64 = db
        .read(move |conn| {
            conn.query_row("SELECT count(*) FROM relay_audit WHERE event_code=23", [], |row| {
                row.get(0)
            })
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(unknown, 1);
}

#[tokio::test]
async fn quota_rejection_has_a_durable_redacted_audit_event() {
    let mut one = policy();
    one.mailbox_max_live_rows = 1;
    let db = RelayOpaqueStore::open_in_memory(one, secrets()).unwrap();
    db.submit_opaque(envelope(9, 1, vec![1], 1000), 100).await.unwrap();
    assert_eq!(
        db.submit_opaque(envelope(9, 2, vec![2], 1000), 101).await,
        Err(RelayError::QuotaExceeded)
    );
    let rejected: i64 = db.read(move |conn| {
        conn.query_row("SELECT count(*) FROM relay_audit WHERE event_code=18 AND length(opaque_id_digest)=32",[],|row|row.get(0)).map_err(map_sqlite_error)
    }).await.unwrap();
    assert!(rejected >= 1);
}

#[tokio::test]
async fn natural_mutations_are_restart_idempotent_and_ledger_is_reconcilable() {
    let db = store();
    let _random = db.create_pairing_intent(90).await.unwrap();
    let created = db.create_pairing_intent_with_operation([0x51; 16], 100).await.unwrap();
    assert!(db.reconcile_operation([0x51; 16]).await.unwrap().is_some());
    assert_eq!(
        db.cancel_pairing(&created.device_code, 101).await.unwrap(),
        PairingState::Cancelled
    );
    assert_eq!(
        db.cancel_pairing(&created.device_code, 101).await.unwrap(),
        PairingState::Cancelled
    );
    db.cleanup([0x52; 16], 1000).await.unwrap();
    db.cleanup([0x52; 16], 1000).await.unwrap();
    db.checkpoint([0x53; 16], 1001).await.unwrap();
    db.checkpoint([0x53; 16], 1001).await.unwrap();
}

#[tokio::test]
async fn schema_fingerprint_rejects_owned_drift_but_allows_other_namespace() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("schema.db");
    {
        let db = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
        drop(db);
    }
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE unrelated_module(id INTEGER PRIMARY KEY);").unwrap();
    drop(conn);
    {
        let db = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
        drop(db);
    }
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE INDEX unexpected_owned_index ON pairing_intents(updated_at);")
        .unwrap();
    drop(conn);
    assert!(matches!(
        RelayOpaqueStore::open(&path, policy(), secrets()),
        Err(RelayError::MigrationFailure)
    ));
}

#[tokio::test]
async fn partial_migration_is_rejected_atomically() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("partial.db");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TABLE pairing_intents(intent_id BLOB PRIMARY KEY);").unwrap();
    drop(conn);
    assert!(matches!(
        RelayOpaqueStore::open(&path, policy(), secrets()),
        Err(RelayError::MigrationFailure)
    ));
    let conn = Connection::open(&path).unwrap();
    let migration_ledger_exists: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='relay_opaque_schema_migrations'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migration_ledger_exists, 0);
    let tables: i64 = conn
        .query_row("SELECT count(*) FROM sqlite_schema WHERE type='table'", [], |row| row.get(0))
        .unwrap();
    assert_eq!(tables, 1);
}

#[tokio::test]
async fn operation_request_mismatch_is_rejected() {
    let db = store();
    db.create_pairing_intent_with_operation([0x61; 16], 100).await.unwrap();
    assert_eq!(
        db.create_pairing_intent_with_operation([0x61; 16], 101).await,
        Err(RelayError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn sqlite_busy_is_typed_then_audited_on_next_writer_turn() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("busy.db");
    let db = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        db.create_pairing_intent_with_operation([0xa1; 16], 100).await,
        Err(RelayError::Busy)
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    db.create_pairing_intent_with_operation([0xa1; 16], 100).await.unwrap();
    let busy: i64 = db
        .read(move |conn| {
            conn.query_row("SELECT count(*) FROM relay_audit WHERE event_code=24", [], |row| {
                row.get(0)
            })
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(busy, 1);
}

#[tokio::test]
async fn mutation_results_survive_restart_and_exact_retries() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("restart.db");
    let db = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    let created = db.create_pairing_intent_with_operation([0xb1; 16], 100).await.unwrap();
    let claim = db
        .claim_pairing(&created.user_code, &source(&db, b"restart"), [1; 16], [2; 16], 101)
        .await
        .unwrap();
    db.publish_prekey(prekey(11, 500), 101).await.unwrap();
    db.reserve_prekey(created.intent_id, [11; 16], [12; 16], 102).await.unwrap();
    db.report_creator_confirmation(created.intent_id, &created.device_code, b"creator", 103)
        .await
        .unwrap();
    db.submit_opaque(envelope(12, 1, vec![1, 2], 1000), 103).await.unwrap();
    db.acknowledge_transport(&[12], &[1], 104).await.unwrap();
    drop(db);
    let reopened = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    assert_eq!(
        reopened
            .report_creator_confirmation(created.intent_id, &created.device_code, b"creator", 103)
            .await
            .unwrap(),
        ConfirmationResult::Pending
    );
    assert_eq!(
        reopened
            .report_claimant_confirmation(
                created.intent_id,
                &claim.claim_capability,
                b"claimant",
                105
            )
            .await
            .unwrap(),
        ConfirmationResult::BothComplete
    );
    assert_eq!(reopened.delete_delivery(&[12], &[1], 106).await.unwrap(), TransportState::Deleted);
    assert_eq!(reopened.delete_delivery(&[12], &[1], 106).await.unwrap(), TransportState::Deleted);
}

#[tokio::test]
async fn audit_is_bounded_and_contains_no_raw_capabilities() {
    let db = store();
    let created = db.create_pairing_intent_with_operation([0x71; 16], 100).await.unwrap();
    let rows = db
        .read(move |conn| {
            conn.query_row(
                "SELECT event_code,opaque_id_digest FROM relay_audit LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(map_sqlite_error)
        })
        .await
        .unwrap();
    assert_eq!(rows.0, AuditEvent::PairingCreated as i64);
    assert_eq!(rows.1.len(), 32);
    assert_ne!(rows.1, created.device_code.as_bytes());
}

#[tokio::test]
async fn policy_retention_strictly_covers_every_natural_lifetime_and_overflow() {
    for (pairing, prekey, mailbox) in [(10, 1, 1), (1, 10, 1), (1, 1, 10)] {
        for retention in [9, 10] {
            let mut invalid = policy();
            invalid.pairing_ttl_secs = pairing;
            invalid.max_prekey_ttl_secs = prekey;
            invalid.mailbox_ttl_secs = mailbox;
            invalid.operation_retention_secs = retention;
            invalid.tombstone_retention_secs = 11;
            assert_eq!(invalid.validate(), Err(RelayError::InvalidInput));
        }
        let mut valid = policy();
        valid.pairing_ttl_secs = pairing;
        valid.max_prekey_ttl_secs = prekey;
        valid.mailbox_ttl_secs = mailbox;
        valid.operation_retention_secs = 11;
        valid.tombstone_retention_secs = 12;
        assert!(valid.validate().is_ok());
    }

    let mut boundary = policy();
    boundary.pairing_ttl_secs = 5;
    boundary.max_prekey_ttl_secs = 5;
    boundary.mailbox_ttl_secs = 10;
    boundary.operation_retention_secs = 11;
    boundary.tombstone_retention_secs = 11;
    assert_eq!(boundary.validate(), Err(RelayError::InvalidInput));
    boundary.tombstone_retention_secs = 12;
    assert!(boundary.validate().is_ok());

    let mut invalid = policy();
    invalid.tombstone_retention_secs = invalid.operation_retention_secs - 1;
    assert_eq!(invalid.validate(), Err(RelayError::InvalidInput));
    invalid = policy();
    invalid.operation_retention_secs = i64::MAX as u64;
    invalid.tombstone_retention_secs = u64::MAX;
    assert_eq!(invalid.validate(), Err(RelayError::InvalidInput));
    assert_eq!(
        store().create_pairing_intent_with_operation([0xf0; 16], u64::MAX).await,
        Err(RelayError::InvalidInput)
    );
}

#[tokio::test]
async fn canonical_full_envelope_size_drives_mailbox_and_global_quota() {
    let candidate = envelope(21, 1, vec![7], 1000);
    let canonical_size = Envelope::new(
        candidate.protocol_version,
        MailboxId::new(candidate.mailbox_id.clone()).unwrap(),
        DeliveryId::new(candidate.delivery_id.clone()).unwrap(),
        candidate.ciphertext.clone(),
        candidate.expires_at,
    )
    .unwrap()
    .to_bytes()
    .unwrap()
    .len() as u64;
    assert!(canonical_size > candidate.ciphertext.len() as u64);

    let mut too_small = policy();
    too_small.mailbox_max_live_bytes = canonical_size - 1;
    let db = RelayOpaqueStore::open_in_memory(too_small, secrets()).unwrap();
    assert_eq!(db.submit_opaque(candidate.clone(), 100).await, Err(RelayError::QuotaExceeded));

    let mut exact = policy();
    exact.mailbox_max_live_bytes = canonical_size;
    let db = RelayOpaqueStore::open_in_memory(exact, secrets()).unwrap();
    assert_eq!(db.submit_opaque(candidate.clone(), 100).await.unwrap(), TransportState::Pending);

    let mut global = policy();
    global.mailbox_max_live_bytes = canonical_size;
    global.global_max_live_bytes = canonical_size * 2 - 1;
    let db = RelayOpaqueStore::open_in_memory(global, secrets()).unwrap();
    db.submit_opaque(candidate, 100).await.unwrap();
    assert_eq!(
        db.submit_opaque(envelope(22, 1, vec![7], 1000), 100).await,
        Err(RelayError::QuotaExceeded)
    );

    let mut global_exact = policy();
    global_exact.mailbox_max_live_bytes = canonical_size;
    global_exact.global_max_live_bytes = canonical_size * 2;
    let db = RelayOpaqueStore::open_in_memory(global_exact, secrets()).unwrap();
    db.submit_opaque(envelope(21, 1, vec![7], 1000), 100).await.unwrap();
    db.submit_opaque(envelope(22, 1, vec![7], 1000), 100).await.unwrap();
}

#[tokio::test]
async fn fetch_receipt_expiry_settles_without_ciphertext_or_reselection_after_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("fetch-expiry.db");
    let operation = [0xd1; 16];
    let db = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    db.submit_opaque(envelope(23, 1, vec![0xaa, 0xbb], 103), 100).await.unwrap();
    let first = db.fetch_mailbox(operation, &[23], 1, 101).await.unwrap();
    assert_eq!(first.envelopes.len(), 1);
    drop(db);

    let reopened = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    let replay = reopened.fetch_mailbox(operation, &[23], 1, 103).await.unwrap();
    assert!(replay.envelopes.is_empty());
    assert_eq!(
        replay.settled,
        vec![SettledDelivery { delivery_id: vec![1], state: TransportState::Expired }]
    );
    assert_eq!(count(&reopened, "opaque_mailbox").await, 0);
    let again = reopened.fetch_mailbox(operation, &[23], 1, 104).await.unwrap();
    assert!(again.envelopes.is_empty());
    assert_eq!(again.settled, replay.settled);
}

#[tokio::test]
async fn fetch_receipt_digest_and_selection_corruption_fail_closed() {
    for corruption in [
        "UPDATE fetch_receipts SET selection_digest=zeroblob(32)",
        "UPDATE fetch_receipts SET selection_blob=x'00010100'",
    ] {
        let db = store();
        db.submit_opaque(envelope(25, 1, vec![1], 1000), 100).await.unwrap();
        let operation = [0xd9; 16];
        db.fetch_mailbox(operation, &[25], 1, 101).await.unwrap();
        db.write_connection([0xda; 16], NORMAL_DEADLINE, move |conn| {
            conn.execute_batch(corruption).map_err(map_sqlite_error)
        })
        .await
        .unwrap();
        assert_eq!(db.fetch_mailbox(operation, &[25], 1, 102).await, Err(RelayError::Database));
    }
}

#[tokio::test]
async fn depth_rejects_every_corrupt_live_row_shape() {
    for sql in [
        "UPDATE opaque_mailbox SET payload_digest=zeroblob(32)",
        "UPDATE opaque_mailbox SET payload_bytes=99",
        "UPDATE opaque_mailbox SET envelope_size=1",
        "UPDATE opaque_mailbox SET status='unknown'",
    ] {
        let db = store();
        db.submit_opaque(envelope(24, 1, vec![1, 2, 3], 1000), 100).await.unwrap();
        let statement = format!(
            "PRAGMA ignore_check_constraints=ON; {sql}; PRAGMA ignore_check_constraints=OFF;"
        );
        db.write_connection([0xd2; 16], NORMAL_DEADLINE, move |conn| {
            conn.execute_batch(&statement).map_err(map_sqlite_error)
        })
        .await
        .unwrap();
        assert_eq!(db.depth(&[24], 101).await, Err(RelayError::Database));
    }
}

#[tokio::test]
async fn cleanup_uses_one_shared_thousand_item_budget_and_converges() {
    let mut roomy = policy();
    roomy.mailbox_max_tombstones = 1000;
    roomy.global_max_tombstones = 2000;
    let db = RelayOpaqueStore::open_in_memory(roomy, secrets()).unwrap();
    db.write_connection([0xd3; 16], MAINTENANCE_DEADLINE, |conn| {
        let tx = conn.transaction().map_err(map_sqlite_error)?;
        tx.execute_batch(
            "CREATE TABLE test_trigger_effects(kind TEXT NOT NULL); \
             CREATE TRIGGER test_prekey_cleanup_effect AFTER UPDATE ON public_prekeys BEGIN INSERT INTO test_trigger_effects(kind) VALUES('prekey'); END; \
             CREATE TRIGGER test_ledger_cleanup_effect AFTER INSERT ON relay_operations BEGIN INSERT INTO test_trigger_effects(kind) VALUES('ledger'); END; \
             WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM n WHERE value<10000) \
             INSERT INTO relay_audit(event_code,outcome_code,created_at) SELECT 1,0,0 FROM n;",
        )
        .map_err(map_sqlite_error)?;
        for value in 0u16..100 {
            let mailbox = value.to_be_bytes();
            let delivery = [1u8];
            let ciphertext = vec![u8::try_from(value).unwrap()];
            let digest = commitment(b"telegraph/opaque-delivery/v1", &ciphertext);
            let size = Envelope::new(
                ProtocolVersion::current(),
                MailboxId::new(mailbox.to_vec()).unwrap(),
                DeliveryId::new(delivery.to_vec()).unwrap(),
                ciphertext.clone(),
                10,
            )
            .unwrap()
            .to_bytes()
            .unwrap()
            .len();
            tx.execute(
                "INSERT INTO opaque_mailbox(mailbox_id,delivery_id,protocol_major,protocol_minor,ciphertext,payload_digest,payload_bytes,envelope_size,expires_at,status,created_at,updated_at) VALUES(?1,?2,1,0,?3,?4,1,?5,10,'pending',0,0)",
                params![mailbox.as_slice(), delivery.as_slice(), ciphertext, digest.as_slice(), sqlite_usize(size)?],
            )
            .map_err(map_sqlite_error)?;
        }
        for value in 0u32..100 {
            let mut intent = [0u8; 16];
            intent[..4].copy_from_slice(&value.to_be_bytes());
            let operation = commitment(b"test-operation", &intent);
            let device = commitment(b"test-device", &intent);
            let user = commitment(b"test-user", &intent);
            tx.execute(
                "INSERT INTO pairing_intents(intent_id,operation_commitment,device_code_commitment,user_code_commitment,state,attempts,expires_at,created_at,updated_at) VALUES(?1,?2,?3,?4,'available',0,10,0,0)",
                params![intent.as_slice(), operation.as_slice(), device.as_slice(), user.as_slice()],
            )
            .map_err(map_sqlite_error)?;
        }
        for value in 0u32..1001 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&value.to_be_bytes());
            let mut bundle = vec![0xa1, 0x00, 0x44];
            bundle.extend_from_slice(&value.to_be_bytes());
            let digest = commitment(BUNDLE_DOMAIN, &bundle);
            tx.execute(
                "INSERT INTO public_prekeys(prekey_id,bundle,bundle_digest,status,expires_at,created_at,updated_at) VALUES(?1,?2,?3,'available',10,0,0)",
                params![id.as_slice(), bundle, digest.as_slice()],
            )
            .map_err(map_sqlite_error)?;
        }
        tx.commit().map_err(map_sqlite_error)
    })
    .await
    .unwrap();
    let mut expired_mail = 0u64;
    let mut expired_pairings = 0u64;
    let mut expired_prekeys = 0u64;
    let mut converged = false;
    for pass in 0u8..10 {
        let mut operation = [0xd4; 16];
        operation[15] = pass;
        let summary = cleanup_reconciled(&db, operation, 100).await;
        assert!(summary.committed_changes <= 1000);
        expired_mail += summary.expired_mail;
        expired_pairings += summary.expired_pairings;
        expired_prekeys += summary.expired_prekeys;
        if !summary.remaining {
            converged = true;
            break;
        }
    }
    assert!(converged);
    assert_eq!(expired_mail, 100);
    assert_eq!(expired_pairings, 100);
    assert_eq!(expired_prekeys, 1001);
    assert!(count(&db, "test_trigger_effects").await > 0);
}

#[tokio::test]
async fn poll_started_timeout_is_durable_and_reconciles_after_restart() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("poll-outcome.db");
    let db = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    let created = db.create_pairing_intent_with_operation([0xd6; 16], 100).await.unwrap();
    let operation = [0xd7; 16];
    let (started_tx, started_rx) = std_mpsc::sync_channel(0);
    let (release_tx, release_rx) = std_mpsc::sync_channel(0);
    install_poll_test_gate(PollTestGate {
        operation_id: operation,
        started: started_tx,
        release: release_rx,
    });
    let poller = {
        let db = db.clone();
        let device_code = created.device_code.clone();
        tokio::spawn(async move { db.poll_pairing(operation, &device_code, 700).await })
    };
    tokio::task::yield_now().await;
    started_rx.recv().unwrap();
    assert_eq!(poller.await.unwrap(), Err(RelayError::OutcomeUnknown { operation_id: operation }));
    release_tx.send(()).unwrap();
    db.checkpoint([0xd8; 16], 701).await.unwrap();
    assert_eq!(db.reconcile_operation(operation).await.unwrap().unwrap().result_kind, 3);
    drop(db);

    let reopened = RelayOpaqueStore::open(&path, policy(), secrets()).unwrap();
    assert_eq!(
        reopened.poll_pairing(operation, &created.device_code, 701).await.unwrap().state,
        PairingState::Expired
    );
}

#[tokio::test]
async fn migration_ledger_checksum_fingerprint_and_owned_objects_fail_closed() {
    for column in ["migration_checksum", "schema_fingerprint"] {
        let directory = tempdir().unwrap();
        let path = directory.path().join(format!("{column}.db"));
        drop(RelayOpaqueStore::open(&path, policy(), secrets()).unwrap());
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            &format!("UPDATE relay_opaque_schema_migrations SET {column}=zeroblob(32)"),
            [],
        )
        .unwrap();
        drop(conn);
        assert!(matches!(
            RelayOpaqueStore::open(&path, policy(), secrets()),
            Err(RelayError::MigrationFailure)
        ));
    }

    let directory = tempdir().unwrap();
    let path = directory.path().join("fresh-owned.db");
    drop(RelayOpaqueStore::open(&path, policy(), secrets()).unwrap());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT count(*) FROM relay_opaque_schema_migrations WHERE version=1 AND length(migration_checksum)=32 AND length(schema_fingerprint)=32",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    conn.execute_batch(
        "CREATE TABLE unrelated_extra(id INTEGER PRIMARY KEY, value INTEGER); \
         CREATE INDEX unrelated_extra_value ON unrelated_extra(value); \
         CREATE TRIGGER unrelated_extra_trigger AFTER INSERT ON unrelated_extra BEGIN UPDATE unrelated_extra SET value=NEW.value WHERE id=NEW.id; END;",
    )
    .unwrap();
    drop(conn);
    drop(RelayOpaqueStore::open(&path, policy(), secrets()).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER unexpected_owned_trigger AFTER UPDATE ON public_prekeys BEGIN SELECT 1; END;",
    )
    .unwrap();
    drop(conn);
    assert!(matches!(
        RelayOpaqueStore::open(&path, policy(), secrets()),
        Err(RelayError::MigrationFailure)
    ));
}
