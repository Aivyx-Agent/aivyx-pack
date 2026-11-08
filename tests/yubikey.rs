//! YubiKey signing and provisioning against `aivyx-yubi`'s `FakeCard` (no
//! real card is ever touched). Run with `cargo test --features test-util`.
//!
//! `FakeCard`'s key and signature are fixed byte patterns, not real
//! Ed25519: its public key ([0xAB; 32]) is not a valid curve point, and its
//! signature does not verify. So no FakeCard run can produce a bundle that
//! verifies, and these tests check the refusals instead: whatever the card
//! does wrong, no file is written.

use std::path::PathBuf;

use aivyx_pack::PackError;
use aivyx_pack::yubikey::{Provisioned, check_provisioned, init_card, write_bundle_on_card};
use aivyx_yubi::testing::FakeCard;
use aivyx_yubi::{SecretString, YubiError};
use ed25519_dalek::SigningKey;
use openpgp_card::Card;
use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::crypto::SigningAlgo;
use openpgp_card::ocard::data::TouchPolicy;

const USER_PIN: &str = "246810";
const ADMIN_PIN: &str = "13579135";

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aivyx-pack-yubikey-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn changed_pins() -> FakeCard {
    FakeCard::new()
        .with_changed_user_pin(USER_PIN.as_bytes())
        .with_changed_admin_pin(ADMIN_PIN.as_bytes())
}

/// The signing call `YubiKeySigner::sign` makes, against a fake card: open
/// a transaction, verify the User PIN for signing, sign.
fn fake_sign(fake: &FakeCard, message: &[u8]) -> Result<[u8; 64], YubiError> {
    let mut card = Card::new(fake.clone())?;
    let mut tx = card.transaction()?;
    tx.verify_user_signing_pin(SecretString::from(USER_PIN))?;
    let signature = tx.card().signature_for_hash(SigningAlgo::ECC, message)?;
    signature
        .try_into()
        .map_err(|_| YubiError::Other("not 64 bytes".into()))
}

/// Run `init_card` on a fresh transaction of `fake`, counting how often the
/// Admin PIN was asked for.
fn init(fake: &FakeCard, overwrite_confirmed: bool) -> (Result<Provisioned, PackError>, u32) {
    let mut card = Card::new(fake.clone()).unwrap();
    let mut tx = card.transaction().unwrap();
    let mut asked = 0;
    let mut admin_pin = || {
        asked += 1;
        Ok(SecretString::from(ADMIN_PIN))
    };
    let result = init_card(&mut tx, overwrite_confirmed, &mut admin_pin, &mut |_| {});
    (result, asked)
}

#[test]
fn init_provisions_a_card_with_changed_pins() {
    let fake = changed_pins();
    let (result, asked) = init(&fake, false);
    let provisioned = result.unwrap();
    assert_eq!(asked, 1);
    assert!(fake.signing_key_generated());
    assert_eq!(provisioned.public_key, FakeCard::fake_public_key());
    assert_eq!(provisioned.card_serial, "0006:00112233");

    // Touch policy is now Fixed.
    let mut card = Card::new(fake.clone()).unwrap();
    let mut tx = card.transaction().unwrap();
    let uif = tx.user_interaction_flag(KeyType::Signing).unwrap().unwrap();
    assert_eq!(uif.touch_policy(), TouchPolicy::Fixed);
}

#[test]
fn init_refuses_a_card_with_default_pins() {
    let fake = FakeCard::new();
    let (result, asked) = init(&fake, false);
    let err = result.unwrap_err().to_string();
    assert!(err.contains("factory default"), "{err}");
    assert!(err.contains("never changes a PIN"), "{err}");
    assert_eq!(asked, 0, "the Admin PIN is not asked for");
    assert!(!fake.signing_key_generated());
}

#[test]
fn init_refuses_a_card_whose_pin_retries_are_reduced() {
    let fake = changed_pins();
    {
        let mut card = Card::new(fake.clone()).unwrap();
        let mut tx = card.transaction().unwrap();
        tx.verify_user_pin(SecretString::from("000000"))
            .unwrap_err();
    }
    let (result, asked) = init(&fake, false);
    let err = result.unwrap_err().to_string();
    assert!(err.contains("gpg --card-status"), "{err}");
    assert_eq!(asked, 0);
    assert!(!fake.signing_key_generated());
    // The refusal itself presented no PIN.
    assert_eq!(fake.user_pin_retries_left(), 2);
    assert_eq!(fake.admin_pin_retries_left(), 3);
}

#[test]
fn init_refuses_an_occupied_slot_unless_confirmed() {
    let fake = changed_pins();
    init(&fake, false).0.unwrap();
    // Each init's factory-default probe spends one User PIN retry; the
    // closing check's test signature (a correct User PIN) restores it.
    // Without it the next init stops at "retries reduced".
    fake_sign(&fake, b"test").unwrap();

    let (result, asked) = init(&fake, false);
    let err = result.unwrap_err().to_string();
    assert!(err.contains("already holds a key"), "{err}");
    assert_eq!(asked, 0);

    // After the operator typed the serial back, it overwrites.
    let (result, _) = init(&fake, true);
    result.unwrap();
}

#[test]
fn init_warns_about_retries_on_a_wrong_admin_pin() {
    let fake = changed_pins();
    let mut card = Card::new(fake.clone()).unwrap();
    let mut tx = card.transaction().unwrap();
    let mut admin_pin = || Ok(SecretString::from("99999999"));
    let err = init_card(&mut tx, false, &mut admin_pin, &mut |_| {})
        .unwrap_err()
        .to_string();
    assert!(err.contains("Admin PIN verification failed"), "{err}");
    assert!(err.contains("limited retries"), "{err}");
    assert!(!fake.signing_key_generated());
}

#[test]
fn the_fake_cards_key_is_refused_before_signing_and_nothing_is_written() {
    // What `build --yubikey` does with this card: its Signature-slot key
    // (FakeCard::fake_public_key, as provisioned above) is not a valid
    // Ed25519 point, so the bundle is refused before the card is asked to
    // sign.
    let fake = changed_pins();
    let provisioned = init(&fake, false).0.unwrap();
    let out = tempdir("fake-key").join("x.aivyxpack");
    let mut sign = |m: &[u8]| fake_sign(&fake, m);
    let err =
        write_bundle_on_card(b"payload", &provisioned.public_key, &mut sign, &out).unwrap_err();
    assert!(matches!(err, PackError::Signer(ref m) if m.contains("not a valid Ed25519")));
    assert!(
        fake.last_signed_data().is_empty(),
        "the card was not asked to sign"
    );
    assert!(!out.exists());
}

#[test]
fn a_card_signature_that_does_not_verify_leaves_no_file() {
    // The card is asked to sign exactly the payload; its signature does
    // not verify against the key the bundle would name, so nothing is
    // written.
    let fake = changed_pins();
    init(&fake, false).0.unwrap();
    let named_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let out = tempdir("bad-sig").join("x.aivyxpack");
    let mut sign = |m: &[u8]| fake_sign(&fake, m);
    let err = write_bundle_on_card(b"payload bytes", &named_key, &mut sign, &out).unwrap_err();
    assert!(matches!(err, PackError::BadSignature), "{err}");
    assert_eq!(fake.last_signed_data(), b"payload bytes");
    assert!(!out.exists());
}

#[test]
fn a_card_removed_mid_signature_leaves_no_file() {
    let fake = changed_pins();
    init(&fake, false).0.unwrap();
    let fake = fake.with_card_removed_mid_signature();
    let named_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let out = tempdir("removed").join("x.aivyxpack");
    let mut sign = |m: &[u8]| fake_sign(&fake, m);
    let err = write_bundle_on_card(b"payload", &named_key, &mut sign, &out).unwrap_err();
    assert!(
        matches!(err, PackError::Signer(ref m) if m.contains("RemovedCard")),
        "{err}"
    );
    assert!(!out.exists());
}

#[test]
fn the_closing_check_fails_on_the_fake_cards_signature() {
    // `yubikey-init`'s closing check signs a test message and verifies it:
    // the fake card's fixed signature must not pass it.
    let fake = changed_pins();
    let provisioned = init(&fake, false).0.unwrap();
    let mut sign = |m: &[u8]| fake_sign(&fake, m);
    let err = check_provisioned(&provisioned, &provisioned.public_key, &mut sign)
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a valid Ed25519"), "{err}");
}
