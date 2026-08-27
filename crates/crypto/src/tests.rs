use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};

use zeroize::Zeroizing;

use super::*;

fn paired_sessions() -> (OutboundSession, InboundSession) {
    let alice = DeviceAccount::new();
    let mut bob = DeviceAccount::new();
    let otk = bob.generate_one_time_keys(1).expect("otk generation").remove(0);
    bob.publish_one_time_keys().expect("publish");
    let mut alice_session = alice
        .create_outbound_session(bob.identity_public_keys().curve25519, otk.curve25519)
        .expect("outbound");
    let init = alice_session.encrypt(b"pair-init").expect("initial message");
    let (bob_session, received) = bob
        .create_inbound_session(
            alice.identity_public_keys().curve25519,
            &init,
            PrekeySource::OneTime(otk.wire_id),
        )
        .expect("inbound");
    assert_eq!(received.plaintext(), b"pair-init");
    (alice_session, bob_session)
}

#[test]
fn profile_dependency_and_version_are_fixed() {
    assert_eq!(PROFILE, b"telegraph/olm-pair/v1");
    assert_eq!(OLM_VERSION, 1);
    assert_eq!(OLM_V1_TAG_BYTES, 8);
    assert_eq!(vodozemac::VERSION, "0.10.0");
    assert_eq!(MAX_TOTAL_OTKS, 50);
    assert_eq!(MAX_OLM_PLAINTEXT_BYTES, 16_384);
    assert_eq!(MAX_OLM_MESSAGE_BYTES, 65_536);
}

#[test]
fn plaintext_holders_are_zeroizing_and_raw_outbound_constructor_is_not_public() {
    assert!(std::mem::needs_drop::<InboundMessage>());
    assert!(std::mem::needs_drop::<SessionAuthenticatedMessage>());
    let message_source = include_str!("message.rs");
    assert!(message_source.contains("plaintext: Zeroizing<Vec<u8>>"));
    assert!(!message_source.contains("pub struct InboundMessage {\n    plaintext: Vec<u8>"));
    let account_source = include_str!("account.rs");
    assert!(!account_source.contains("pub fn create_outbound_session"));
    assert!(account_source.contains("pub(crate) fn create_outbound_session"));
}

#[test]
fn account_otk_session_and_bidirectional_confirmation_round_trip() {
    let (mut alice, mut bob) = paired_sessions();
    assert_eq!(alice.session_id(), bob.session_id());

    let from_bob = bob.encrypt_confirmation(b"confirm-b").expect("encrypt B");
    assert_eq!(alice.decrypt_confirmation(&from_bob).expect("decrypt B").plaintext(), b"confirm-b");
    let from_alice = alice.encrypt_confirmation(b"confirm-a").expect("encrypt A");
    assert_eq!(bob.decrypt_confirmation(&from_alice).expect("decrypt A").plaintext(), b"confirm-a");
}

#[test]
fn prekey_source_fallback_unknown_and_wrong_mapping_are_distinct() {
    let alice = DeviceAccount::new();
    let mut bob = DeviceAccount::new();
    let fallback = bob.generate_fallback_for_test(false);
    let mut outbound = alice
        .create_outbound_session(bob.identity_public_keys().curve25519, fallback)
        .expect("fallback outbound");
    let message = outbound.encrypt(b"init").expect("fallback message");
    let alice_identity = alice.identity_public_keys().curve25519;
    assert!(matches!(
        bob.create_inbound_session(alice_identity, &message, PrekeySource::Fallback),
        Err(CryptoError::FallbackRejected)
    ));
    assert!(matches!(
        bob.create_inbound_session(alice_identity, &message, PrekeySource::Unknown),
        Err(CryptoError::UnknownOneTimeKey)
    ));
    assert!(matches!(
        bob.create_inbound_session(alice_identity, &message, PrekeySource::OneTime([9; 16])),
        Err(CryptoError::UnknownOneTimeKey)
    ));
}

#[test]
fn unpublished_key_is_rejected_and_consumed_key_cannot_be_reused() {
    let alice = DeviceAccount::new();
    let mut bob = DeviceAccount::new();
    let otk = bob.generate_one_time_keys(1).expect("generate").remove(0);
    let mut outbound = alice
        .create_outbound_session(bob.identity_public_keys().curve25519, otk.curve25519)
        .expect("outbound");
    let message = outbound.encrypt(b"init").expect("message");
    let identity = alice.identity_public_keys().curve25519;
    assert!(matches!(
        bob.create_inbound_session(identity, &message, PrekeySource::OneTime(otk.wire_id)),
        Err(CryptoError::OtkPolicyRejected)
    ));
    bob.publish_one_time_keys().expect("publish");
    bob.create_inbound_session(identity, &message, PrekeySource::OneTime(otk.wire_id))
        .expect("consume once");
    assert!(matches!(
        bob.create_inbound_session(identity, &message, PrekeySource::OneTime(otk.wire_id)),
        Err(CryptoError::UnknownOneTimeKey)
    ));
}

#[test]
fn repeated_otk_generation_obeys_one_shared_fifty_key_budget() {
    let mut account = DeviceAccount::new();
    let first = account.generate_one_time_keys(23).expect("first batch");
    let second = account.generate_one_time_keys(27).expect("second batch");
    assert_eq!(first.len(), 23);
    assert_eq!(second.len(), 27);
    let first_ids: HashSet<_> = first.iter().map(|entry| entry.wire_id).collect();
    let second_ids: HashSet<_> = second.iter().map(|entry| entry.wire_id).collect();
    assert!(first_ids.is_disjoint(&second_ids));
    let all_ids: HashSet<_> = first_ids.union(&second_ids).copied().collect();
    assert_eq!(all_ids.len(), MAX_TOTAL_OTKS);
    assert_eq!(
        account.one_time_key_inventory().iter().map(|entry| entry.wire_id).collect::<HashSet<_>>(),
        all_ids
    );
    assert_eq!(account.one_time_key_inventory().len(), MAX_TOTAL_OTKS);
    let before = account.export_state().expect("before rejected generation");
    assert!(matches!(account.generate_one_time_keys(1), Err(CryptoError::InputTooLarge)));
    assert_eq!(account.one_time_key_inventory().len(), MAX_TOTAL_OTKS);
    assert_eq!(before.as_bytes(), account.export_state().expect("unchanged").as_bytes());

    account.publish_one_time_keys().expect("publish all");
    assert!(account.unpublished_one_time_keys().is_empty());
    let consumed = account.one_time_key_inventory()[0].clone();
    let alice = DeviceAccount::new();
    let mut outbound = alice
        .create_outbound_session(account.identity_public_keys().curve25519, consumed.curve25519)
        .expect("outbound");
    let initial = outbound.encrypt(b"consume one").expect("initial");
    account
        .create_inbound_session(
            alice.identity_public_keys().curve25519,
            &initial,
            PrekeySource::OneTime(consumed.wire_id),
        )
        .expect("consume");
    let mut restored =
        DeviceAccount::from_state(account.export_state().expect("export")).expect("restore");
    let replacement = restored.generate_one_time_keys(1).expect("replacement");
    assert_eq!(replacement.len(), 1);
    assert!(!all_ids.contains(&replacement[0].wire_id));
}

#[test]
fn account_opaque_state_and_record_aead_restore_published_inventory() {
    let mut account = DeviceAccount::new();
    account.generate_one_time_keys(3).expect("generate");
    account.publish_one_time_keys().expect("publish");
    let identity = account.identity_public_keys();
    let inventory = account.one_time_key_inventory();
    let state = account.export_state().expect("state");
    let aad = RecordAad::new(RecordType::Account, [1; 16], 1, 9);
    let key = [7; 32];
    let envelope = seal_account_state(&key, &aad, &state).expect("seal");
    let restored =
        DeviceAccount::from_state(open_account_state(&key, &aad, &envelope).expect("open"))
            .expect("restore");
    assert_eq!(restored.identity_public_keys(), identity);
    assert_eq!(restored.one_time_key_inventory(), inventory);
    assert!(matches!(open_record(&key, &aad, &envelope), Err(RecordError::InvalidAad)));
    assert!(matches!(seal_record(&key, &aad, b"raw-provider-state"), Err(RecordError::InvalidAad)));
}

#[test]
fn published_inventory_from_equal_account_cannot_be_mixed_even_with_recomputed_binding() {
    let mut one = DeviceAccount::new();
    let mut two = DeviceAccount::new();
    one.generate_one_time_keys(1).expect("one");
    two.generate_one_time_keys(1).expect("two");
    one.publish_one_time_keys().expect("publish one");
    two.publish_one_time_keys().expect("publish two");
    let one_state = one.export_state().expect("one state");
    let two_state = two.export_state().expect("two state");
    assert_eq!(
        account_inventory_bytes(&one_state).len(),
        account_inventory_bytes(&two_state).len()
    );
    let mixed = crate::account::rebuild_account_state_for_test(
        account_provider_bytes(&one_state),
        account_inventory_bytes(&two_state),
        account_published_proof_bytes(&two_state),
        &account_used_wire_ids(&two_state),
    )
    .expect("recomputed structural binding");
    assert!(matches!(DeviceAccount::from_state(mixed), Err(CryptoError::InventoryMalformed)));

    let mut foreign_history = account_used_wire_ids(&one_state);
    let mut extra = [0xa5; 16];
    while foreign_history.contains(&extra) {
        extra[0] = extra[0].wrapping_add(1);
    }
    foreign_history.push(extra);
    foreign_history.sort_unstable();
    let mixed_history = crate::account::rebuild_account_state_for_test(
        account_provider_bytes(&one_state),
        account_inventory_bytes(&one_state),
        account_published_proof_bytes(&one_state),
        &foreign_history,
    )
    .expect("recomputed binding with foreign history");
    assert!(matches!(
        DeviceAccount::from_state(mixed_history),
        Err(CryptoError::InventoryMalformed)
    ));
}

#[test]
fn same_identity_published_provider_key_substitution_fails_exact_mapping() {
    let mut account = DeviceAccount::new();
    account.generate_one_time_keys(2).expect("generate");
    account.publish_one_time_keys().expect("publish");
    let state = account.export_state().expect("state");
    let mut provider = Zeroizing::new(account_provider_bytes(&state).to_vec());
    mutate_first_provider_private_secret(&mut provider).expect("private key mutation");

    // Signing and account-identity fields, inventory, history, and every
    // signed proof remain from the same account. Only one provider OTK secret
    // is replaced, and the structural binding is recomputed.
    let substituted = crate::account::rebuild_account_state_for_test(
        &provider,
        account_inventory_bytes(&state),
        account_published_proof_bytes(&state),
        &account_used_wire_ids(&state),
    )
    .expect("recomputed structural binding");
    let result = DeviceAccount::from_state(substituted);
    assert!(
        matches!(result, Err(CryptoError::InventoryMalformed)),
        "unexpected substitution result: {:?}",
        result.err()
    );
}

#[test]
fn published_proof_chain_rejects_every_signed_field_and_structural_attack() {
    let mut account = DeviceAccount::new();
    account.generate_one_time_keys(2).expect("first batch");
    account.publish_one_time_keys().expect("first publish");
    account.generate_one_time_keys(1).expect("second batch");
    account.publish_one_time_keys().expect("second publish");
    let state = account.export_state().expect("state");
    let proofs = proof_chain_components(account_published_proof_bytes(&state)).expect("proofs");
    assert_eq!(proofs.len(), 4);
    assert!(proofs[1][77] > 0, "second proof has a published snapshot");
    let key_len = usize::from(proofs[1][94]);
    let signed_offsets = [
        12,                  // sequence
        13,                  // previous proof digest
        45,                  // used-wire-id history digest
        77,                  // entry count
        78,                  // entry wire id
        95,                  // entry key id
        95 + key_len,        // entry Curve25519 public key
        proofs[1].len() - 1, // Ed25519 signature
    ];
    for offset in signed_offsets {
        let mut tampered = proofs.clone();
        tampered[1][offset] ^= 1;
        assert_proof_chain_rejected(&state, &tampered);
    }

    let mut truncated = proofs.clone();
    truncated.pop();
    assert_proof_chain_rejected(&state, &truncated);

    let mut reordered = proofs.clone();
    reordered.swap(1, 2);
    assert_proof_chain_rejected(&state, &reordered);

    let mut inserted_old = proofs.clone();
    inserted_old.insert(1, proofs[0].clone());
    assert_proof_chain_rejected(&state, &inserted_old);

    let mut duplicate_sequence = proofs.clone();
    duplicate_sequence[2][5..13].copy_from_slice(&2u64.to_be_bytes());
    assert_proof_chain_rejected(&state, &duplicate_sequence);
}

#[test]
fn published_proof_chain_rejects_a_validly_signed_fork() {
    let mut base = DeviceAccount::new();
    base.generate_one_time_keys(1).expect("base batch");
    let base_state = base.export_state().expect("base");
    let mut branch_a = DeviceAccount::from_state(base_state).expect("branch a");
    let mut branch_b =
        DeviceAccount::from_state(base.export_state().expect("base copy")).expect("branch b");

    branch_a.generate_one_time_keys(1).expect("a second batch");
    branch_a.publish_one_time_keys().expect("a publish");
    branch_b.generate_one_time_keys(1).expect("b second batch");
    branch_b.publish_one_time_keys().expect("b publish");
    let a_state = branch_a.export_state().expect("a state");
    let b_state = branch_b.export_state().expect("b state");
    let a_proofs = proof_chain_components(account_published_proof_bytes(&a_state)).expect("a");
    let b_proofs = proof_chain_components(account_published_proof_bytes(&b_state)).expect("b");
    assert_eq!(a_proofs.len(), 3);
    assert_eq!(b_proofs.len(), 3);
    assert_ne!(a_proofs[1], b_proofs[1]);

    let fork = vec![b_proofs[0].clone(), a_proofs[1].clone(), b_proofs[2].clone()];
    assert_proof_chain_rejected(&b_state, &fork);
}

#[test]
fn proof_chain_is_bounded_and_rejection_leaves_provider_unchanged() {
    let mut account = DeviceAccount::new();
    for _ in 0..49 {
        assert_eq!(account.generate_one_time_keys(1).expect("bounded batch").len(), 1);
    }
    account.publish_one_time_keys().expect("fiftieth proof");
    let before = account.export_state().expect("before cap");
    assert_eq!(account_published_proof_bytes(&before)[5], 50);
    assert!(matches!(account.generate_one_time_keys(1), Err(CryptoError::InputTooLarge)));
    assert_eq!(before.as_bytes(), account.export_state().expect("unchanged").as_bytes());
}

#[test]
fn complete_old_state_requires_t3b_monotonic_anchor_to_reject_rollback() {
    let mut account = DeviceAccount::new();
    account.generate_one_time_keys(1).expect("old state");
    let old_for_core = account.export_state().expect("old core replay");
    let old_for_anchor = account.export_state().expect("old anchored replay");
    account.publish_one_time_keys().expect("advance state");
    let current = account.export_state().expect("current");
    let current_anchor = current.rollback_anchor();

    // This is an intentional boundary: an authentic complete old state and
    // its valid proof chain are internally self-consistent.
    DeviceAccount::from_state(old_for_core).expect("core alone cannot identify full rollback");
    assert!(matches!(
        DeviceAccount::from_state_with_anchor(old_for_anchor, current_anchor),
        Err(CryptoError::RollbackAnchorMismatch)
    ));
    DeviceAccount::from_state_with_anchor(current, current_anchor)
        .expect("current monotonic anchor");
}

#[test]
fn inventory_wire_ids_must_be_in_strict_canonical_order() {
    let mut account = DeviceAccount::new();
    account.generate_one_time_keys(2).expect("two keys");
    let state = account.export_state().expect("state");
    let inventory = account_inventory_bytes(&state);
    let ranges = inventory_entry_ranges(inventory).expect("inventory entries");
    assert_eq!(ranges.len(), 2);
    let mut reordered = inventory[..7].to_vec();
    reordered.extend_from_slice(&inventory[ranges[1].clone()]);
    reordered.extend_from_slice(&inventory[ranges[0].clone()]);
    assert!(matches!(
        crate::account::decode_inventory_for_test(&reordered),
        Err(CryptoError::InventoryMalformed)
    ));
}

#[test]
fn opaque_state_versions_lengths_and_trailing_bytes_are_strict() {
    let account = DeviceAccount::new();
    let account_state = account.export_state().expect("account state");
    for mutation in 0..3 {
        let mut bytes = Zeroizing::new(account_state.as_bytes().to_vec());
        match mutation {
            0 => bytes[4] = 5,
            1 => bytes[5..9].copy_from_slice(&0u32.to_be_bytes()),
            2 => bytes.push(0),
            _ => unreachable!(),
        }
        assert!(matches!(
            DeviceAccount::from_state(OpaqueAccountState::from_bytes(bytes).expect("bounded")),
            Err(CryptoError::OpaqueStateMalformed)
        ));
    }

    let (session, _) = paired_sessions();
    let session_state = session.export_state().expect("session state");
    for mutation in 0..3 {
        let mut bytes = Zeroizing::new(session_state.as_bytes().to_vec());
        match mutation {
            0 => bytes[4] = 3,
            1 => bytes[5..9].copy_from_slice(&0u32.to_be_bytes()),
            2 => bytes.push(0),
            _ => unreachable!(),
        }
        assert!(matches!(
            OutboundSession::from_state(OpaqueSessionState::from_bytes(bytes).expect("bounded")),
            Err(CryptoError::OpaqueStateMalformed)
        ));
    }
}

#[test]
fn account_v2_and_v3_migration_accept_only_never_used_empty_accounts() {
    let empty = DeviceAccount::new();
    let v4 = empty.export_state().expect("v4 state");
    let legacy_v2 = crate::account::rebuild_legacy_account_state_for_test(
        account_provider_bytes(&v4),
        account_inventory_bytes(&v4),
        &account_used_wire_ids(&v4),
    )
    .expect("legacy empty state");
    let legacy_v3 = crate::account::rebuild_legacy_v3_account_state_for_test(
        account_provider_bytes(&v4),
        account_inventory_bytes(&v4),
        account_published_proof_bytes(&v4),
        &account_used_wire_ids(&v4),
    )
    .expect("legacy v3 empty state");
    for legacy in [legacy_v2, legacy_v3] {
        let migrated = DeviceAccount::from_state(legacy).expect("safe empty migration");
        assert!(migrated.one_time_key_inventory().is_empty());
        assert_eq!(migrated.export_state().expect("re-export").as_bytes()[4], 4);
    }

    let mut key_bearing = DeviceAccount::new();
    key_bearing.generate_one_time_keys(2).expect("unpublished keys");
    let v4 = key_bearing.export_state().expect("v4 key-bearing state");
    let unverifiable_v2 = crate::account::rebuild_legacy_account_state_for_test(
        account_provider_bytes(&v4),
        account_inventory_bytes(&v4),
        &account_used_wire_ids(&v4),
    )
    .expect("legacy v2 key-bearing state");
    let unverifiable_v3 = crate::account::rebuild_legacy_v3_account_state_for_test(
        account_provider_bytes(&v4),
        account_inventory_bytes(&v4),
        account_published_proof_bytes(&v4),
        &account_used_wire_ids(&v4),
    )
    .expect("legacy v3 key-bearing state");
    for unverifiable in [unverifiable_v2, unverifiable_v3] {
        assert!(matches!(
            DeviceAccount::from_state(unverifiable),
            Err(CryptoError::OpaqueStateMalformed)
        ));
    }
}

#[test]
fn provider_cbor_unknown_duplicate_reordered_and_trailing_data_fail_closed() {
    let account = DeviceAccount::new();
    let state = account.export_state().expect("account state");
    let provider = account_provider_bytes(&state);
    assert_eq!(provider[0], 0xa4, "provider AccountPickle is one four-field map");

    let mut unknown = provider.to_vec();
    let signing = find_bytes(&unknown, b"signing_key");
    unknown[signing] = b'x';

    let mut duplicate = provider.to_vec();
    let fallback = find_bytes(&duplicate, b"fallback_keys");
    duplicate[fallback..fallback + b"fallback_keys".len()].copy_from_slice(b"one_time_keys");

    let pairs = top_level_map_pairs(provider).expect("provider pairs");
    let mut reordered = vec![provider[0]];
    reordered.extend_from_slice(&provider[pairs[1].clone()]);
    reordered.extend_from_slice(&provider[pairs[0].clone()]);
    for pair in &pairs[2..] {
        reordered.extend_from_slice(&provider[pair.clone()]);
    }
    assert_eq!(reordered.len(), provider.len());

    let mut trailing = provider.to_vec();
    trailing.push(0);

    for bad_provider in [unknown, duplicate, reordered, trailing] {
        let opaque = replace_account_provider(&state, &bad_provider);
        assert!(matches!(
            DeviceAccount::from_state(opaque),
            Err(CryptoError::OpaqueStateMalformed)
        ));
    }

    let mut oversized = Zeroizing::new(state.as_bytes().to_vec());
    oversized[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        DeviceAccount::from_state(OpaqueAccountState::from_bytes(oversized).expect("bounded")),
        Err(CryptoError::OpaqueStateMalformed)
    ));
}

#[test]
fn provider_otk_schema_duplicate_id_wrong_length_and_status_fail_closed() {
    let mut account = DeviceAccount::new();
    account.generate_one_time_keys(2).expect("keys");
    let unpublished = account.export_state().expect("unpublished");

    let mut duplicate_field = Zeroizing::new(account_provider_bytes(&unpublished).to_vec());
    let next_key_id = find_bytes(&duplicate_field, b"next_key_id");
    duplicate_field[next_key_id..next_key_id + 11].copy_from_slice(b"public_keys");
    let duplicate_field_state = replace_account_provider(&unpublished, &duplicate_field);
    assert!(matches!(
        DeviceAccount::from_state(duplicate_field_state),
        Err(CryptoError::OpaqueStateMalformed)
    ));

    let mut duplicate_key_id = Zeroizing::new(account_provider_bytes(&unpublished).to_vec());
    let private_map = find_bytes(&duplicate_key_id, b"private_keys") + b"private_keys".len();
    let (private_count, first_key) = cbor_argument(&duplicate_key_id, private_map).expect("map");
    assert_eq!(private_count, 2);
    let first_value = cbor_item_end(&duplicate_key_id, first_key).expect("first key");
    let second_key = cbor_item_end(&duplicate_key_id, first_value).expect("first secret");
    duplicate_key_id[second_key] = duplicate_key_id[first_key];
    let duplicate_id_state = replace_account_provider(&unpublished, &duplicate_key_id);
    assert!(matches!(
        DeviceAccount::from_state(duplicate_id_state),
        Err(CryptoError::OpaqueStateMalformed)
    ));

    let mut wrong_secret_length = Zeroizing::new(account_provider_bytes(&unpublished).to_vec());
    let private_map = find_bytes(&wrong_secret_length, b"private_keys") + b"private_keys".len();
    let (_, first_key) = cbor_argument(&wrong_secret_length, private_map).expect("map");
    let first_secret = cbor_item_end(&wrong_secret_length, first_key).expect("first key");
    assert_eq!(&wrong_secret_length[first_secret..first_secret + 2], &[0x98, 0x20]);
    wrong_secret_length[first_secret + 1] = 0x1f;
    let wrong_length_state = replace_account_provider(&unpublished, &wrong_secret_length);
    assert!(matches!(
        DeviceAccount::from_state(wrong_length_state),
        Err(CryptoError::OpaqueStateMalformed)
    ));

    account.publish_one_time_keys().expect("publish");
    let published = account.export_state().expect("published");
    let mut wrong_status = account_inventory_bytes(&published).to_vec();
    let ranges = inventory_entry_ranges(&wrong_status).expect("inventory");
    let status = ranges[0].end - 1;
    assert_eq!(wrong_status[status], 1);
    wrong_status[status] = 0;
    let wrong_status_state = crate::account::rebuild_account_state_for_test(
        account_provider_bytes(&published),
        &wrong_status,
        account_published_proof_bytes(&published),
        &account_used_wire_ids(&published),
    )
    .expect("binding");
    assert!(matches!(
        DeviceAccount::from_state(wrong_status_state),
        Err(CryptoError::InventoryMalformed)
    ));
}

#[test]
fn provider_cbor_preflight_enforces_every_structural_budget_before_serde() {
    let account = DeviceAccount::new();
    let state = account.export_state().expect("state");
    let huge_bytes = [0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let huge_map = [0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let invalid_utf8 = [0x61, 0xff];
    let indefinite_array = [0x9f, 0xff];
    let standalone_break = [0xff];
    let non_shortest = [0x18, 0x17];
    let truncated_overflow = [0x5b, 0xff];
    for malformed in [
        &huge_bytes[..],
        &huge_map[..],
        &invalid_utf8,
        &indefinite_array,
        &standalone_break,
        &non_shortest,
        &truncated_overflow,
    ] {
        assert!(matches!(
            crate::account::scan_account_provider_cbor_for_test(malformed),
            Err(CryptoError::OpaqueStateMalformed)
        ));
        assert!(matches!(
            crate::account::scan_session_provider_cbor_for_test(malformed),
            Err(CryptoError::OpaqueStateMalformed)
        ));
        let opaque = replace_account_provider(&state, malformed);
        assert!(matches!(
            DeviceAccount::from_state(opaque),
            Err(CryptoError::OpaqueStateMalformed)
        ));
    }

    let mut depth_at_limit = vec![0x81; 32];
    depth_at_limit.push(0xf6);
    crate::account::scan_account_provider_cbor_for_test(&depth_at_limit)
        .expect("depth 32 accepted by preflight");
    let mut depth_over_limit = vec![0x81; 33];
    depth_over_limit.push(0xf6);
    assert!(matches!(
        crate::account::scan_account_provider_cbor_for_test(&depth_over_limit),
        Err(CryptoError::OpaqueStateMalformed)
    ));

    let mut max_container = vec![0x99, 0x20, 0x00];
    max_container.extend(std::iter::repeat_n(0xf6, 8_192));
    crate::account::scan_account_provider_cbor_for_test(&max_container)
        .expect("container count 8192 accepted");
    assert!(matches!(
        crate::account::scan_account_provider_cbor_for_test(&[0x99, 0x20, 0x01]),
        Err(CryptoError::OpaqueStateMalformed)
    ));

    // 1 root + (1 array + 14 nulls) + 8190 * (1 array + 7 nulls)
    // is exactly 65,536 scanned items.
    let mut exact_item_budget = vec![0x99, 0x1f, 0xff, 0x8e];
    exact_item_budget.extend(std::iter::repeat_n(0xf6, 14));
    for _ in 0..8_190 {
        exact_item_budget.push(0x87);
        exact_item_budget.extend(std::iter::repeat_n(0xf6, 7));
    }
    crate::account::scan_session_provider_cbor_for_test(&exact_item_budget)
        .expect("exact item budget accepted");
    let mut over_item_budget = vec![0x99, 0x20, 0x00];
    for _ in 0..8_192 {
        over_item_budget.push(0x87);
        over_item_budget.extend(std::iter::repeat_n(0xf6, 7));
    }
    assert!(matches!(
        crate::account::scan_session_provider_cbor_for_test(&over_item_budget),
        Err(CryptoError::OpaqueStateMalformed)
    ));

    crate::account::reset_serde_deserialize_counts_for_test();
    assert!(crate::account::deserialize_account_pickle_for_test(&invalid_utf8).is_err());
    assert!(crate::account::deserialize_session_pickle_for_test(&indefinite_array).is_err());
    assert_eq!(crate::account::serde_deserialize_counts_for_test(), (0, 0));
    assert!(crate::account::deserialize_account_pickle_for_test(&[0xa0]).is_err());
    assert!(crate::account::deserialize_session_pickle_for_test(&[0xa0]).is_err());
    assert_eq!(crate::account::serde_deserialize_counts_for_test(), (0, 1));

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut random = vec![0u8; 16_384];
        let mut value = 0xa5a5_1f3d_u32;
        for byte in &mut random {
            value ^= value << 13;
            value ^= value >> 17;
            value ^= value << 5;
            *byte = value as u8;
        }
        let opaque = replace_account_provider(&state, &random);
        assert!(matches!(
            DeviceAccount::from_state(opaque),
            Err(CryptoError::OpaqueStateMalformed)
        ));
        assert!(crate::account::scan_session_provider_cbor_for_test(&random).is_err());
    }));
    assert!(result.is_ok());
}

#[test]
fn provider_cbor_preflight_rejects_tags_floats_and_unapproved_simple_values_before_serde() {
    let forbidden = [
        &[0xc0, 0xf6][..],
        &[0xd8, 0x18, 0xf6],
        &[0xd9, 0x01, 0x00, 0xf6],
        &[0xda, 0x00, 0x01, 0x00, 0x00, 0xf6],
        &[0xdb, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xf6],
        &[0xe0],
        &[0xf3],
        &[0xf7],
        &[0xf8, 0x18],
        &[0xf8, 0xff],
        &[0xf9, 0x3c, 0x00],
        &[0xfa, 0x3f, 0x80, 0x00, 0x00],
        &[0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0xfc],
        &[0xff],
    ];

    for malformed in forbidden {
        assert!(matches!(
            crate::account::scan_account_provider_cbor_for_test(malformed),
            Err(CryptoError::OpaqueStateMalformed)
        ));
        assert!(matches!(
            crate::account::scan_session_provider_cbor_for_test(malformed),
            Err(CryptoError::OpaqueStateMalformed)
        ));

        crate::account::reset_serde_deserialize_counts_for_test();
        assert!(crate::account::deserialize_account_pickle_for_test(malformed).is_err());
        assert!(crate::account::deserialize_session_pickle_for_test(malformed).is_err());
        assert_eq!(
            crate::account::serde_deserialize_counts_for_test(),
            (0, 0),
            "Serde must not observe forbidden provider CBOR {malformed:02x?}"
        );
    }

    for allowed in [&[0xf4][..], &[0xf5], &[0xf6]] {
        crate::account::scan_account_provider_cbor_for_test(allowed)
            .expect("false/true/null are the only allowed simple values");
        crate::account::scan_session_provider_cbor_for_test(allowed)
            .expect("false/true/null are the only allowed simple values");
    }

    let account = DeviceAccount::new();
    let account_state = account.export_state().expect("valid account state");
    let (session, _) = paired_sessions();
    let session_state = session.export_state().expect("valid session state");
    crate::account::reset_serde_deserialize_counts_for_test();
    crate::account::deserialize_account_pickle_for_test(account_provider_bytes(&account_state))
        .expect("valid provider account pickle remains accepted");
    crate::account::deserialize_session_pickle_for_test(session_provider_bytes(&session_state))
        .expect("valid provider session pickle remains accepted");
    assert_eq!(crate::account::serde_deserialize_counts_for_test(), (1, 1));
}

#[test]
fn unpublished_and_published_provider_fallback_state_is_rejected_on_export_and_restore() {
    for published in [false, true] {
        let mut account = DeviceAccount::new();
        account.generate_fallback_for_test(published);
        assert!(matches!(account.export_state(), Err(CryptoError::FallbackRejected)));
        let incompatible = account.export_state_with_fallback_for_test().expect("test state");
        assert!(matches!(
            DeviceAccount::from_state(incompatible),
            Err(CryptoError::FallbackRejected)
        ));
    }
}

#[test]
fn inbound_authentication_failure_and_wrong_source_do_not_advance_account() {
    let alice = DeviceAccount::new();
    let mut bob = DeviceAccount::new();
    let otk = bob.generate_one_time_keys(1).expect("generate").remove(0);
    bob.publish_one_time_keys().expect("publish");
    let mut outbound = alice
        .create_outbound_session(bob.identity_public_keys().curve25519, otk.curve25519)
        .expect("outbound");
    let message = outbound.encrypt(b"init").expect("message");
    let before = bob.export_state().expect("before");
    assert!(matches!(
        bob.create_inbound_session(
            alice.identity_public_keys().curve25519,
            &message,
            PrekeySource::Fallback,
        ),
        Err(CryptoError::FallbackRejected)
    ));
    assert_eq!(before.as_bytes(), bob.export_state().expect("after source").as_bytes());

    let (kind, mut bytes) = message.to_parts();
    *bytes.last_mut().expect("ciphertext") ^= 1;
    let tampered = EncryptedMessage::from_parts(kind, &bytes).expect("parse tampered");
    assert!(matches!(
        bob.create_inbound_session(
            alice.identity_public_keys().curve25519,
            &tampered,
            PrekeySource::OneTime(otk.wire_id),
        ),
        Err(CryptoError::OlmOperation)
    ));
    assert_eq!(before.as_bytes(), bob.export_state().expect("after auth").as_bytes());
}

#[test]
fn session_opaque_state_and_record_aead_restore_ratchet() {
    let (mut alice, bob) = paired_sessions();
    let bob_state = bob.export_state().expect("session state");
    let aad = RecordAad::new(RecordType::Session, [2; 16], 1, 3);
    let key = [8; 32];
    let envelope = seal_session_state(&key, &aad, &bob_state).expect("seal");
    let mut restored =
        InboundSession::from_state(open_session_state(&key, &aad, &envelope).expect("open"))
            .expect("restore");
    let message = alice.encrypt(b"after-restart").expect("encrypt");
    assert_eq!(restored.decrypt(&message).expect("decrypt").plaintext(), b"after-restart");
}

#[test]
fn failed_session_decrypt_and_oversize_encrypt_leave_state_unchanged() {
    let (mut alice, mut bob) = paired_sessions();
    let before = bob.export_state().expect("before");
    let mut message = alice.encrypt(b"tamper-me").expect("encrypt");
    let (kind, mut bytes) = message.to_parts();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    message = EncryptedMessage::from_parts(kind, &bytes).expect("still parseable");
    assert!(matches!(bob.decrypt(&message), Err(CryptoError::AuthenticationFailure)));
    let after = bob.export_state().expect("after");
    assert_eq!(before.as_bytes(), after.as_bytes());

    let oversized = vec![0u8; MAX_OLM_PLAINTEXT_BYTES + 1];
    assert!(matches!(bob.encrypt(&oversized), Err(CryptoError::InputTooLarge)));
    assert_eq!(after.as_bytes(), bob.export_state().expect("unchanged").as_bytes());
}

#[test]
fn provider_valid_oversize_prekey_and_normal_decrypt_do_not_advance_state() {
    let oversized = vec![0x6d; MAX_OLM_PLAINTEXT_BYTES + 1];

    let alice = DeviceAccount::new();
    let mut bob = DeviceAccount::new();
    let otk = bob.generate_one_time_keys(1).expect("generate").remove(0);
    bob.publish_one_time_keys().expect("publish");
    let mut alice_prekey = alice
        .create_outbound_session(bob.identity_public_keys().curve25519, otk.curve25519)
        .expect("outbound");
    let valid_prekey = alice_prekey
        .encrypt_unbounded_for_test(&oversized)
        .expect("provider-valid oversize prekey");
    let before_account = bob.export_state().expect("before account");
    assert!(matches!(
        bob.create_inbound_session(
            alice.identity_public_keys().curve25519,
            &valid_prekey,
            PrekeySource::OneTime(otk.wire_id),
        ),
        Err(CryptoError::InputTooLarge)
    ));
    assert_eq!(
        before_account.as_bytes(),
        bob.export_state().expect("account unchanged").as_bytes()
    );

    let (mut alice_session, mut bob_session) = paired_sessions();
    let valid_normal = alice_session
        .encrypt_unbounded_for_test(&oversized)
        .expect("provider-valid oversize normal message");
    let before_session = bob_session.export_state().expect("before session");
    assert!(matches!(bob_session.decrypt(&valid_normal), Err(CryptoError::InputTooLarge)));
    assert_eq!(
        before_session.as_bytes(),
        bob_session.export_state().expect("session unchanged").as_bytes()
    );
}

#[test]
fn accepted_session_payload_boundary_is_bounded() {
    let (mut alice, mut bob) = paired_sessions();
    let payload = vec![0x5a; MAX_OLM_PLAINTEXT_BYTES];
    let message = alice.encrypt(&payload).expect("16 KiB payload");
    assert!(message.as_bytes().len() <= MAX_OLM_MESSAGE_BYTES);
    assert_eq!(bob.decrypt(&message).expect("decrypt").plaintext(), payload);
}

#[test]
fn record_aad_rejects_noncanonical_and_malformed_table() {
    let aad = RecordAad::new(RecordType::Session, [1; 16], 1, 7);
    let valid = aad.encode().expect("encode");
    assert_eq!(RecordAad::decode(&valid).expect("decode"), aad);
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut nonshortest = valid.clone();
    nonshortest.splice(1..2, [0x18, 0x00]);
    let mut duplicate = valid.clone();
    let key_one = 1 + 1 + 1 + "session".len();
    duplicate[key_one] = 0;
    let mut unknown = valid.clone();
    let last_key = valid.len() - 2;
    unknown[last_key] = 4;
    let mut negative = valid.clone();
    negative[last_key - 2] = 0x20;
    let mut indefinite = valid.clone();
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let reordered = {
        let mut bytes = vec![0xa4, 0x01, 0x50];
        bytes.extend_from_slice(&[1; 16]);
        bytes.extend_from_slice(&[0x00, 0x67]);
        bytes.extend_from_slice(b"session");
        bytes.extend_from_slice(&[0x02, 0x01, 0x03, 0x07]);
        bytes
    };
    for bad in
        [Vec::new(), trailing, nonshortest, duplicate, unknown, negative, indefinite, reordered]
    {
        assert!(matches!(RecordAad::decode(&bad), Err(RecordError::InvalidAad)));
    }
}

#[test]
fn record_aead_rejects_each_tamper_and_each_aad_field_change() {
    let aad = RecordAad::new(RecordType::Channel, [3; 16], 2, 11);
    let key = [4; 32];
    let envelope = seal_record(&key, &aad, b"sensitive-state").expect("seal");
    let second = seal_record(&key, &aad, b"sensitive-state").expect("seal again");
    assert_ne!(envelope.nonce(), second.nonce());
    assert_eq!(&*open_record(&key, &aad, &envelope).expect("open"), b"sensitive-state");

    let wrong_aads = [
        RecordAad::new(RecordType::Dedup, [3; 16], 2, 11),
        RecordAad::new(RecordType::Channel, [5; 16], 2, 11),
        RecordAad::new(RecordType::Channel, [3; 16], 3, 11),
        RecordAad::new(RecordType::Channel, [3; 16], 2, 12),
    ];
    for wrong in wrong_aads {
        assert!(matches!(open_record(&key, &wrong, &envelope), Err(RecordError::Authentication)));
    }
    assert!(matches!(open_record(&[9; 32], &aad, &envelope), Err(RecordError::Authentication)));

    let mut bad_nonce = *envelope.nonce();
    bad_nonce[0] ^= 1;
    let bad_nonce = RecordEnvelope::from_parts(bad_nonce, envelope.ciphertext()).expect("parts");
    assert!(matches!(open_record(&key, &aad, &bad_nonce), Err(RecordError::Authentication)));
    for index in [0, envelope.ciphertext().len() - 1] {
        let mut tampered = envelope.clone();
        tampered.ciphertext_mut()[index] ^= 1;
        assert!(matches!(open_record(&key, &aad, &tampered), Err(RecordError::Authentication)));
    }
    assert!(!envelope.ciphertext().windows(15).any(|w| w == b"sensitive-state"));
}

#[test]
fn invalid_auth_budget_exact_attempts_window_restart_rollback_and_repair() {
    for stop in 1..INVALID_AUTH_ATTEMPT_LIMIT {
        let mut budget = InvalidAuthBudget::new();
        for attempt in 1..=stop {
            assert_eq!(
                budget.record_invalid_auth(100),
                AuthBudgetDecision::InvalidAuth { attempts: attempt }
            );
        }
        let restored = InvalidAuthBudget::decode(&budget.encode()).expect("restart");
        assert_eq!(restored, budget);
    }

    let mut boundary = InvalidAuthBudget::new();
    assert_eq!(boundary.record_invalid_auth(100), AuthBudgetDecision::InvalidAuth { attempts: 1 });
    assert_eq!(boundary.record_invalid_auth(699), AuthBudgetDecision::InvalidAuth { attempts: 2 });
    assert_eq!(boundary.record_invalid_auth(700), AuthBudgetDecision::InvalidAuth { attempts: 1 });
    assert_eq!(boundary.window_started_at(), Some(700));

    let mut rollback = InvalidAuthBudget::new();
    rollback.record_invalid_auth(u64::MAX);
    assert_eq!(rollback.record_invalid_auth(0), AuthBudgetDecision::Quarantined);
    assert!(rollback.is_quarantined());
    assert_eq!(rollback.record_valid_auth(u64::MAX), AuthBudgetDecision::Quarantined);
    assert_eq!(InvalidAuthBudget::repaired(), InvalidAuthBudget::new());

    let mut near_overflow = InvalidAuthBudget::new();
    assert_eq!(
        near_overflow.record_invalid_auth(u64::MAX - 599),
        AuthBudgetDecision::InvalidAuth { attempts: 1 }
    );
    assert_eq!(
        near_overflow.record_invalid_auth(u64::MAX),
        AuthBudgetDecision::InvalidAuth { attempts: 2 }
    );
}

#[test]
fn eighth_invalid_auth_quarantines_and_survives_restart() {
    let mut budget = InvalidAuthBudget::new();
    for attempt in 1..INVALID_AUTH_ATTEMPT_LIMIT {
        assert_eq!(
            budget.record_invalid_auth(100),
            AuthBudgetDecision::InvalidAuth { attempts: attempt }
        );
    }
    assert_eq!(budget.record_invalid_auth(100), AuthBudgetDecision::Quarantined);
    let mut restored = InvalidAuthBudget::decode(&budget.encode()).expect("restore");
    assert_eq!(restored.record_invalid_auth(700), AuthBudgetDecision::Quarantined);
}

#[test]
fn invalid_auth_state_decode_rejects_malformed_table() {
    let valid = InvalidAuthBudget::new().encode();
    let mut bad_magic = valid;
    bad_magic[0] ^= 1;
    let mut bad_version = valid;
    bad_version[4] = 2;
    let mut too_many = valid;
    too_many[5] = 9;
    let mut bad_window_flag = valid;
    bad_window_flag[6] = 2;
    let mut bad_quarantine_flag = valid;
    bad_quarantine_flag[15] = 2;
    let mut zero_with_window = valid;
    zero_with_window[6] = 1;
    let mut attempt_without_window = valid;
    attempt_without_window[5] = 1;
    let mut eighth_not_quarantined = valid;
    eighth_not_quarantined[5] = 8;
    eighth_not_quarantined[6] = 1;
    for bad in [
        bad_magic,
        bad_version,
        too_many,
        bad_window_flag,
        bad_quarantine_flag,
        zero_with_window,
        attempt_without_window,
        eighth_not_quarantined,
    ] {
        assert!(InvalidAuthBudget::decode(&bad).is_err());
    }
    assert!(matches!(InvalidAuthBudget::decode(&valid[..15]), Err(BudgetError::InvalidLength)));
}

#[test]
fn bounded_random_message_inputs_never_panic() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut state = 0x9e37_79b9_u32;
        for len in 0..=1_024 {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            for kind in [0, 1, 2, u8::MAX] {
                let _ = ParsedMessage::parse(kind, &bytes);
            }
        }
        let oversized = vec![0u8; MAX_OLM_MESSAGE_BYTES + 1];
        assert!(matches!(ParsedMessage::parse(0, &oversized), Err(CryptoError::InputTooLarge)));
    }));
    assert!(result.is_ok());
}

const ACCOUNT_STATE_HEADER: usize = 51;

fn account_provider_bytes(state: &OpaqueAccountState) -> &[u8] {
    let length = u32::from_be_bytes(state.as_bytes()[5..9].try_into().expect("length")) as usize;
    &state.as_bytes()[ACCOUNT_STATE_HEADER..ACCOUNT_STATE_HEADER + length]
}

fn account_inventory_bytes(state: &OpaqueAccountState) -> &[u8] {
    let provider_len =
        u32::from_be_bytes(state.as_bytes()[5..9].try_into().expect("length")) as usize;
    let inventory_len =
        u32::from_be_bytes(state.as_bytes()[9..13].try_into().expect("length")) as usize;
    let start = ACCOUNT_STATE_HEADER + provider_len;
    &state.as_bytes()[start..start + inventory_len]
}

fn session_provider_bytes(state: &OpaqueSessionState) -> &[u8] {
    let provider_len =
        u32::from_be_bytes(state.as_bytes()[5..9].try_into().expect("length")) as usize;
    &state.as_bytes()[9..9 + provider_len]
}

fn account_published_proof_bytes(state: &OpaqueAccountState) -> &[u8] {
    let provider_len =
        u32::from_be_bytes(state.as_bytes()[5..9].try_into().expect("length")) as usize;
    let inventory_len =
        u32::from_be_bytes(state.as_bytes()[9..13].try_into().expect("length")) as usize;
    let proof_len =
        u32::from_be_bytes(state.as_bytes()[13..17].try_into().expect("length")) as usize;
    let start = ACCOUNT_STATE_HEADER + provider_len + inventory_len;
    &state.as_bytes()[start..start + proof_len]
}

fn account_used_wire_ids(state: &OpaqueAccountState) -> Vec<[u8; 16]> {
    let provider_len =
        u32::from_be_bytes(state.as_bytes()[5..9].try_into().expect("length")) as usize;
    let inventory_len =
        u32::from_be_bytes(state.as_bytes()[9..13].try_into().expect("length")) as usize;
    let proof_len =
        u32::from_be_bytes(state.as_bytes()[13..17].try_into().expect("length")) as usize;
    let count = u16::from_be_bytes(state.as_bytes()[17..19].try_into().expect("count")) as usize;
    let start = ACCOUNT_STATE_HEADER + provider_len + inventory_len + proof_len;
    state.as_bytes()[start..]
        .chunks_exact(16)
        .take(count)
        .map(|chunk| chunk.try_into().expect("wire id"))
        .collect()
}

fn replace_account_provider(state: &OpaqueAccountState, provider: &[u8]) -> OpaqueAccountState {
    crate::account::rebuild_account_state_for_test(
        provider,
        account_inventory_bytes(state),
        account_published_proof_bytes(state),
        &account_used_wire_ids(state),
    )
    .expect("opaque state")
}

fn proof_chain_components(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.get(..4)? != b"T3PC" || *bytes.get(4)? != 1 {
        return None;
    }
    let count = usize::from(*bytes.get(5)?);
    if count == 0 || count > 50 {
        return None;
    }
    let mut cursor = 6usize;
    let mut proofs = Vec::with_capacity(count);
    for _ in 0..count {
        let length =
            usize::from(u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?));
        cursor = cursor.checked_add(2)?;
        let end = cursor.checked_add(length)?;
        proofs.push(bytes.get(cursor..end)?.to_vec());
        cursor = end;
    }
    (cursor == bytes.len()).then_some(proofs)
}

fn encode_proof_chain_components(proofs: &[Vec<u8>]) -> Vec<u8> {
    let mut chain = Vec::new();
    chain.extend_from_slice(b"T3PC");
    chain.push(1);
    chain.push(u8::try_from(proofs.len()).expect("bounded proof count"));
    for proof in proofs {
        chain.extend_from_slice(
            &u16::try_from(proof.len()).expect("bounded proof length").to_be_bytes(),
        );
        chain.extend_from_slice(proof);
    }
    chain
}

fn assert_proof_chain_rejected(state: &OpaqueAccountState, proofs: &[Vec<u8>]) {
    let chain = encode_proof_chain_components(proofs);
    let tampered = crate::account::rebuild_account_state_for_test(
        account_provider_bytes(state),
        account_inventory_bytes(state),
        &chain,
        &account_used_wire_ids(state),
    )
    .expect("recomputed structural binding");
    assert!(matches!(
        DeviceAccount::from_state(tampered),
        Err(CryptoError::InventoryMalformed | CryptoError::OpaqueStateMalformed)
    ));
}

fn mutate_first_provider_private_secret(provider: &mut [u8]) -> Option<()> {
    let field = find_bytes(provider, b"private_keys");
    let map_start = field.checked_add(b"private_keys".len())?;
    let (count, mut cursor) = cbor_argument(provider, map_start)?;
    if provider.get(map_start)? >> 5 != 5 || count == 0 {
        return None;
    }
    cursor = cbor_item_end(provider, cursor)?;
    let initial = *provider.get(cursor)?;
    let major = initial >> 5;
    let (length, value_start) = cbor_argument(provider, cursor)?;
    if length != 32 {
        return None;
    }
    match major {
        2 => {
            // Avoid X25519's clamped low bits in byte zero.
            let byte = provider.get_mut(value_start + 1)?;
            *byte ^= 1;
        }
        4 => {
            // Avoid X25519's clamped low bits in byte zero.
            let element = cbor_item_end(provider, value_start)?;
            let encoded = *provider.get(element)?;
            if encoded >> 5 != 0 {
                return None;
            }
            match encoded & 0x1f {
                value @ 0..=22 => provider[element] = value + 1,
                23 => provider[element] = 0,
                24 => {
                    let byte = provider.get_mut(element + 1)?;
                    *byte = if *byte == u8::MAX { u8::MAX - 1 } else { (*byte).max(24) + 1 };
                }
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(())
}

fn inventory_entry_ranges(bytes: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    let count = usize::from(*bytes.get(6)?);
    let mut cursor = 7usize;
    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        let start = cursor;
        cursor = cursor.checked_add(16)?;
        let key_len = usize::from(*bytes.get(cursor)?);
        cursor = cursor.checked_add(1 + key_len + 32 + 32 + 1)?;
        if cursor > bytes.len() {
            return None;
        }
        ranges.push(start..cursor);
    }
    (cursor == bytes.len()).then_some(ranges)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).position(|window| window == needle).expect("field name")
}

fn top_level_map_pairs(bytes: &[u8]) -> Option<Vec<std::ops::Range<usize>>> {
    if bytes.first()? >> 5 != 5 {
        return None;
    }
    let (count, mut cursor) = cbor_argument(bytes, 0)?;
    let mut pairs = Vec::with_capacity(usize::try_from(count).ok()?);
    for _ in 0..count {
        let start = cursor;
        cursor = cbor_item_end(bytes, cursor)?;
        cursor = cbor_item_end(bytes, cursor)?;
        pairs.push(start..cursor);
    }
    (cursor == bytes.len()).then_some(pairs)
}

fn cbor_item_end(bytes: &[u8], start: usize) -> Option<usize> {
    let initial = *bytes.get(start)?;
    let major = initial >> 5;
    let (argument, mut cursor) = cbor_argument(bytes, start)?;
    match major {
        0 | 1 => Some(cursor),
        2 | 3 => {
            cursor.checked_add(usize::try_from(argument).ok()?).filter(|end| *end <= bytes.len())
        }
        4 => {
            for _ in 0..argument {
                cursor = cbor_item_end(bytes, cursor)?;
            }
            Some(cursor)
        }
        5 => {
            for _ in 0..argument {
                cursor = cbor_item_end(bytes, cursor)?;
                cursor = cbor_item_end(bytes, cursor)?;
            }
            Some(cursor)
        }
        6 => cbor_item_end(bytes, cursor),
        7 if initial & 0x1f <= 27 => Some(cursor),
        _ => None,
    }
}

fn cbor_argument(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let additional = *bytes.get(start)? & 0x1f;
    let mut cursor = start.checked_add(1)?;
    let (argument, width) = match additional {
        value @ 0..=23 => (u64::from(value), 0),
        24 => (u64::from(*bytes.get(cursor)?), 1),
        25 => (u64::from(u16::from_be_bytes(bytes.get(cursor..cursor + 2)?.try_into().ok()?)), 2),
        26 => (u64::from(u32::from_be_bytes(bytes.get(cursor..cursor + 4)?.try_into().ok()?)), 4),
        27 => (u64::from_be_bytes(bytes.get(cursor..cursor + 8)?.try_into().ok()?), 8),
        _ => return None,
    };
    cursor = cursor.checked_add(width)?;
    Some((argument, cursor))
}
