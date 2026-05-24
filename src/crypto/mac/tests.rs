use super::*;

#[test]
fn test_mac_deterministic() {
    let key = [0x42; MAC_KEY_SIZE];
    let data = b"some payload";
    assert_eq!(compute(&key, data), compute(&key, data));
}

#[test]
fn test_mac_key_dependence() {
    let data = b"same data";
    let k1 = [0x11; MAC_KEY_SIZE];
    let k2 = [0x22; MAC_KEY_SIZE];
    assert_ne!(compute(&k1, data), compute(&k2, data));
}

#[test]
fn test_mac_data_dependence() {
    let key = [0x42; MAC_KEY_SIZE];
    assert_ne!(compute(&key, b"alpha"), compute(&key, b"beta"));
}

#[test]
fn test_mac_incremental_matches_oneshot() {
    let key = [0x42; MAC_KEY_SIZE];
    let part1 = b"first half ";
    let part2 = b"second half";

    let mut builder = MacBuilder::new(&key);
    builder.update(part1);
    builder.update(part2);
    let streamed = builder.finalize();

    let mut full = Vec::new();
    full.extend_from_slice(part1);
    full.extend_from_slice(part2);
    let oneshot = compute(&key, &full);

    assert_eq!(
        streamed, oneshot,
        "Streaming MAC must equal oneshot MAC for the same input"
    );
}

#[test]
fn test_verify_constant_time_correctness() {
    let key = [0x42; MAC_KEY_SIZE];
    let data = b"payload";
    let tag = compute(&key, data);
    let mut tampered = tag;
    tampered[0] ^= 1;

    assert!(verify(&tag, &tag));
    assert!(!verify(&tag, &tampered));
}
