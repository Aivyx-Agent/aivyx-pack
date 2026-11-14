//! The compiled-in Aivyx publisher keys, and packs signed with each.
//!
//! `tests/fixtures/{primary,backup}.aivyxpack` are the `coder-base`
//! template (renamed `fixture`) signed with the primary and backup key.
//! aivyx-pa and aivyx-coder copy them into their own tests.

use aivyx_pack::{
    AIVYX_PUBLISHER_KEYS, PackError, decode_verifying_key, read_bundle_bytes, verify_bundle,
};

const PRIMARY: &[u8] = include_bytes!("fixtures/primary.aivyxpack");
const BACKUP: &[u8] = include_bytes!("fixtures/backup.aivyxpack");

#[test]
fn there_are_two_distinct_built_in_keys_and_both_decode() {
    assert_eq!(AIVYX_PUBLISHER_KEYS.len(), 2);
    assert_ne!(AIVYX_PUBLISHER_KEYS[0], AIVYX_PUBLISHER_KEYS[1]);
    for key in AIVYX_PUBLISHER_KEYS {
        assert!(
            decode_verifying_key(key).is_some(),
            "{key} is not an Ed25519 key"
        );
    }
}

#[test]
fn a_pack_signed_with_either_key_verifies_with_no_trusted_publishers() {
    for (name, bytes, key) in [
        ("primary", PRIMARY, AIVYX_PUBLISHER_KEYS[0]),
        ("backup", BACKUP, AIVYX_PUBLISHER_KEYS[1]),
    ] {
        let bundle = read_bundle_bytes(bytes).unwrap();
        let signer = verify_bundle(&bundle, &[]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(signer, decode_verifying_key(key).unwrap(), "{name}");
    }
}

#[test]
fn a_changed_byte_in_a_built_in_signed_pack_is_refused() {
    let mut bundle = read_bundle_bytes(PRIMARY).unwrap();
    let last = bundle.payload.len() - 1;
    bundle.payload[last] ^= 1;
    assert!(matches!(
        verify_bundle(&bundle, &[]),
        Err(PackError::BadSignature)
    ));
}
