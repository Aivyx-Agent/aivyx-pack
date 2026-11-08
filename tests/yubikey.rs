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
use aivyx_pack::yubikey::{
    OVERWRITE_FLAG, Provisioned, check_provisioned, closing_check_failed, confirm_overwrite,
    encode_card_key, init_card, write_bundle_on_card,
};
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

/// What `yubikey-init` sees for `fake`: its entry in the card listing.
fn summary(fake: &FakeCard) -> aivyx_yubi::discovery::CardSummary {
    let backends = std::iter::once(Ok(fake.clone().into()));
    let mut cards = aivyx_yubi::discovery::list_cards_from(backends).unwrap();
    assert_eq!(cards.len(), 1);
    cards.remove(0)
}

#[test]
fn overwriting_an_occupied_slot_needs_the_flag_and_the_typed_serial() {
    let fake = changed_pins();
    assert!(!summary(&fake).has_signature_key);
    let mut never = || -> Result<String, String> { panic!("must not prompt") };
    assert!(!confirm_overwrite(&summary(&fake), false, false, &mut never).unwrap());

    init(&fake, false).0.unwrap();
    fake_sign(&fake, b"test").unwrap(); // restores the User PIN retry the probe used
    let card = summary(&fake);
    assert!(card.has_signature_key);

    // No flag: refused, naming the flag, before any prompt.
    let err = confirm_overwrite(&card, false, true, &mut never)
        .unwrap_err()
        .to_string();
    assert!(err.contains(OVERWRITE_FLAG), "{err}");
    // Flag but no terminal: refused.
    assert!(confirm_overwrite(&card, true, false, &mut never).is_err());
    // Flag and a wrong serial: refused.
    let mut wrong = || Ok("0006:99999999\n".to_string());
    assert!(confirm_overwrite(&card, true, true, &mut wrong).is_err());
    // init_card itself still refuses without the confirmation, naming the flag.
    let (result, asked) = init(&fake, false);
    assert!(result.unwrap_err().to_string().contains(OVERWRITE_FLAG));
    assert_eq!(asked, 0);

    // Flag and the right serial: confirmed, and init_card overwrites.
    let mut right = || Ok(format!("{}\n", card.serial));
    let confirmed = confirm_overwrite(&card, true, true, &mut right).unwrap();
    assert!(confirmed);
    let (result, asked) = init(&fake, confirmed);
    assert_eq!(result.unwrap().public_key, FakeCard::fake_public_key());
    assert_eq!(asked, 1);
}

#[test]
fn a_failed_closing_check_still_prints_the_new_key() {
    let fake = changed_pins();
    let provisioned = init(&fake, false).0.unwrap();
    let text = closing_check_failed(&provisioned, "PIN incorrect");
    assert!(
        text.contains(&encode_card_key(&FakeCard::fake_public_key())),
        "{text}"
    );
    assert!(text.contains("WAS provisioned"), "{text}");
    assert!(text.contains("gpg --card-status"), "{text}");
}
