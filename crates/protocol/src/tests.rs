use super::*;

fn sample(ciphertext: Vec<u8>) -> Envelope {
    Envelope::new(
        ProtocolVersion::current(),
        MailboxId::new(vec![1]).expect("test mailbox ID"),
        DeliveryId::new(vec![2]).expect("test delivery ID"),
        ciphertext,
        4,
    )
    .expect("valid test envelope")
}

fn sample_bytes() -> Vec<u8> {
    sample(vec![3]).to_bytes().expect("canonical test bytes")
}

fn replace(mut input: Vec<u8>, index: usize, value: u8) -> Vec<u8> {
    input[index] = value;
    input
}

fn replace_size(input: &mut [u8], size: u8) {
    let last = input.len() - 1;
    input[last] = size;
}

fn uint_len(value: usize) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        _ => 5,
    }
}

fn bytes_len(value: usize) -> usize {
    match value {
        0..=23 => 1 + value,
        24..=255 => 2 + value,
        256..=65_535 => 3 + value,
        _ => 5 + value,
    }
}

fn raw_frame_len(mailbox_len: usize, delivery_len: usize, ciphertext_len: usize) -> usize {
    let fixed_without_size = 7
        + 1
        + bytes_len(mailbox_len)
        + 1
        + bytes_len(delivery_len)
        + 1
        + bytes_len(ciphertext_len)
        + 1
        + uint_len(4)
        + 1;
    let mut declared_size = 0;
    for _ in 0..8 {
        let next = fixed_without_size + uint_len(declared_size);
        if next == declared_size {
            return next;
        }
        declared_size = next;
    }
    declared_size
}

fn append_uint(output: &mut Vec<u8>, value: usize) {
    match value {
        0..=23 => output.push(value as u8),
        24..=255 => output.extend_from_slice(&[0x18, value as u8]),
        256..=65_535 => output.extend_from_slice(&[0x19, (value >> 8) as u8, value as u8]),
        _ => output.extend_from_slice(&[
            0x1a,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]),
    }
}

fn append_bytes(output: &mut Vec<u8>, len: usize, fill: u8) {
    match len {
        0..=23 => output.push(0x40 | len as u8),
        24..=255 => output.extend_from_slice(&[0x58, len as u8]),
        256..=65_535 => output.extend_from_slice(&[0x59, (len >> 8) as u8, len as u8]),
        _ => output.extend_from_slice(&[
            0x5a,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]),
    }
    output.resize(output.len() + len, fill);
}

fn raw_frame(mailbox_len: usize, delivery_len: usize, ciphertext_len: usize) -> Vec<u8> {
    let size = raw_frame_len(mailbox_len, delivery_len, ciphertext_len);
    let mut output = Vec::with_capacity(size);
    output.extend_from_slice(&[0xa6, 0x00, 0xa2, 0x00, 0x01, 0x01, 0x00]);
    output.extend_from_slice(&[0x01]);
    append_bytes(&mut output, mailbox_len, 0x11);
    output.extend_from_slice(&[0x02]);
    append_bytes(&mut output, delivery_len, 0x22);
    output.extend_from_slice(&[0x03]);
    append_bytes(&mut output, ciphertext_len, 0x33);
    output.extend_from_slice(&[0x04, 0x04, 0x05]);
    append_uint(&mut output, size);
    output
}

#[test]
fn canonical_roundtrip_and_fixture_are_stable() {
    let encoded = sample_bytes();
    assert_eq!(
        encoded,
        vec![
            0xa6, 0x00, 0xa2, 0x00, 0x01, 0x01, 0x00, 0x01, 0x41, 0x01, 0x02, 0x41, 0x02, 0x03,
            0x41, 0x03, 0x04, 0x04, 0x05, 0x14,
        ]
    );
    let decoded = decode_envelope(&encoded).expect("canonical frame");
    assert_eq!(decoded, sample(vec![3]));
    assert_eq!(decoded.to_bytes().expect("re-encode"), encoded);
    assert_eq!(encode_envelope(&decoded).expect("free function"), encoded);
}

#[test]
fn canonical_roundtrip_table_covers_length_boundaries() {
    for len in [0usize, 1, 23, 24, 255, 256, 1_024, MAX_CIPHERTEXT_LEN] {
        let frame = sample(vec![0x5a; len]);
        let bytes = frame.to_bytes().expect("bounded frame");
        assert!(bytes.len() <= MAX_ENVELOPE_LEN);
        let decoded = Envelope::from_bytes(&bytes).expect("round-trip");
        let expected_ciphertext = vec![0x5a; len];
        assert_eq!(decoded.ciphertext(), expected_ciphertext.as_slice());
        assert_eq!(decoded.size(), bytes.len());
        assert_eq!(decoded.to_bytes().expect("canonical re-encode"), bytes);
    }
}

#[test]
fn non_shortest_integer_and_length_forms_are_rejected() {
    let canonical = sample_bytes();

    // Version major 1 encoded as uint8(1), instead of the shortest 0x01.
    let mut non_shortest_integer = canonical.clone();
    non_shortest_integer.splice(4..5, [0x18, 0x01]);
    let integer_len = non_shortest_integer.len() as u8;
    replace_size(&mut non_shortest_integer, integer_len);
    assert!(decode_envelope(&non_shortest_integer).is_err());

    // Mailbox ID length 1 encoded with an unnecessary uint8 length.
    let mut non_shortest_length = canonical;
    non_shortest_length.splice(8..9, [0x58, 0x01]);
    let length_len = non_shortest_length.len() as u8;
    replace_size(&mut non_shortest_length, length_len);
    assert!(decode_envelope(&non_shortest_length).is_err());
}

#[test]
fn duplicate_out_of_order_and_unknown_keys_are_rejected() {
    let canonical = sample_bytes();

    // Key 4 becomes a duplicate key 3.
    let duplicate = replace(canonical.clone(), 16, 0x03);
    assert_eq!(decode_envelope(&duplicate), Err(ProtocolError::DuplicateKey));

    // Key 4 becomes key 0, which moves backwards.
    let out_of_order = replace(canonical.clone(), 16, 0x00);
    assert_eq!(decode_envelope(&out_of_order), Err(ProtocolError::OutOfOrderKey));

    // Key 5 becomes an unknown key 6.
    let unknown = replace(canonical, 18, 0x06);
    assert_eq!(decode_envelope(&unknown), Err(ProtocolError::UnknownKey));
}

#[test]
fn indefinite_map_and_bytes_are_rejected() {
    let canonical = sample_bytes();

    let mut indefinite_map = canonical.clone();
    indefinite_map[0] = 0xbf;
    assert_eq!(decode_envelope(&indefinite_map), Err(ProtocolError::IndefiniteLength));

    // The mailbox bytestring is changed from definite `41 01` to an
    // indefinite sequence.  The schema's borrowed-bytes decoder rejects it.
    let mut indefinite_bytes = canonical;
    indefinite_bytes.splice(8..10, [0x5f, 0x41, 0x01, 0xff]);
    let indefinite_len = indefinite_bytes.len() as u8;
    replace_size(&mut indefinite_bytes, indefinite_len);
    assert!(decode_envelope(&indefinite_bytes).is_err());
}

#[test]
fn trailing_and_truncated_input_are_rejected() {
    let canonical = sample_bytes();
    let mut trailing = canonical.clone();
    trailing.push(0x00);
    assert_eq!(decode_envelope(&trailing), Err(ProtocolError::TrailingBytes));

    for end in 0..canonical.len() {
        assert!(decode_envelope(&canonical[..end]).is_err(), "truncation at {end}");
    }
}

#[test]
fn version_and_resource_limits_fail_closed() {
    let canonical = sample_bytes();
    let unknown_version = replace(canonical, 4, 0x02);
    assert_eq!(decode_envelope(&unknown_version), Err(ProtocolError::UnsupportedVersion));

    assert_eq!(MailboxId::new(Vec::new()), Err(ProtocolError::EmptyOpaqueId));
    assert_eq!(
        DeliveryId::new(vec![0; MAX_OPAQUE_ID_LEN + 1]),
        Err(ProtocolError::OversizedOpaqueId)
    );
    assert_eq!(
        Envelope::new(
            ProtocolVersion::current(),
            MailboxId::new(vec![1]).expect("test mailbox ID"),
            DeliveryId::new(vec![2]).expect("test delivery ID"),
            vec![0; MAX_CIPHERTEXT_LEN + 1],
            0,
        ),
        Err(ProtocolError::OversizedCiphertext)
    );
    let oversized_input = vec![0; MAX_ENVELOPE_LEN + 1];
    assert_eq!(decode_envelope(&oversized_input), Err(ProtocolError::OversizedEnvelope));
}

#[test]
fn decode_side_ciphertext_and_outer_boundaries_are_enforced() {
    let too_large_ciphertext = raw_frame(1, 1, MAX_CIPHERTEXT_LEN + 1);
    assert_eq!(decode_envelope(&too_large_ciphertext), Err(ProtocolError::OversizedCiphertext));

    let within_limit = raw_frame(MAX_OPAQUE_ID_LEN, MAX_OPAQUE_ID_LEN, MAX_CIPHERTEXT_LEN);
    assert!(within_limit.len() <= MAX_ENVELOPE_LEN);
    let decoded = decode_envelope(&within_limit).expect("maximum fields remain valid");
    assert_eq!(decoded.ciphertext().len(), MAX_CIPHERTEXT_LEN);

    // Exactly the outer limit still enters bounded parsing; malformed content
    // is rejected as malformed rather than being mistaken for an oversize.
    let mut exact_malformed =
        vec![0xa6, 0x00, 0xa2, 0x00, 0x01, 0x01, 0x00, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff];
    exact_malformed.resize(MAX_ENVELOPE_LEN, 0);
    assert_eq!(decode_envelope(&exact_malformed), Err(ProtocolError::Malformed));
}

#[test]
fn length_bomb_and_declared_size_mismatch_fail_structurally() {
    // A definite bytestring claims four GiB while only its header is present;
    // decoding must return before any allocation proportional to that claim.
    let length_bomb =
        vec![0xa6, 0x00, 0xa2, 0x00, 0x01, 0x01, 0x00, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff];
    assert!(decode_envelope(&length_bomb).is_err());

    let mut wrong_size = sample_bytes();
    let wrong_size_value = wrong_size.len() as u8 - 1;
    replace_size(&mut wrong_size, wrong_size_value);
    assert_eq!(decode_envelope(&wrong_size), Err(ProtocolError::InvalidSize));
}

#[test]
fn arbitrary_bounded_bytes_never_panic() {
    let mut state = 0x9e37_79b9u64;
    for len in 0..=2_048usize {
        let mut bytes = vec![0u8; len];
        for byte in &mut bytes {
            // A tiny deterministic PRNG keeps this property-style test
            // dependency-free and repeatable on the MSRV toolchain.
            state ^= state << 7;
            state ^= state >> 9;
            state ^= state << 8;
            *byte = state as u8;
        }
        let result = std::panic::catch_unwind(|| decode_envelope(&bytes));
        assert!(result.is_ok(), "decoder panicked for length {len}");
    }
}
