//! YubiKey signing for pack publishers (Cargo feature `yubikey`): sign a
//! bundle with a key held in a YubiKey's OpenPGP Signature slot, and
//! provision that slot. So a publisher key, such as the Hub's, can live
//! only in hardware.
//!
//! The card work is done by `aivyx-yubi`. This module holds the parts of
//! the `aivyx-pack` command that can be tested without hardware: each
//! function takes either the signing step as a closure or an already-open
//! card transaction, so the tests drive them with `aivyx-yubi`'s
//! `FakeCard`. The CLI (`src/bin/aivyx-pack.rs`) does the prompting, opens
//! the real card, and calls these.
//!
//! One card holds one Signature-slot key. A card provisioned for packs
//! must hold only the pack key: never `aivyx-pa`'s federation identity
//! key, which uses the same slot.
//!
//! **This is the CLI's internals, not a stable API** (hence
//! `#[doc(hidden)]`). These functions do not run the CLI's guards on their
//! own: a caller must still require `--overwrite-existing-key` and the
//! typed serial before overwriting a key ([`confirm_overwrite`]), and must
//! close the provisioning transaction and its card before opening a
//! `YubiKeySigner` (finding C-1 in `aivyx-pa`'s `federation.rs`). Use the
//! `aivyx-pack` command.

use std::path::Path;

use base64::Engine as _;

use aivyx_yubi::{SecretString, YubiError, discovery, pin, provision};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openpgp_card::{Card, state::Transaction};

use crate::{PackError, write_bundle_with};

/// A card's signing step (`YubiKeySigner::sign`, or a fake card in tests).
pub type CardSignFn<'a> = dyn FnMut(&[u8]) -> Result<[u8; 64], YubiError> + 'a;

/// The message `yubikey-init` signs to check a freshly provisioned card.
pub const TEST_MESSAGE: &[u8] = b"aivyx-pack yubikey-init test signature";

/// What the card says its public key is, as an Ed25519 verifying key.
pub fn card_verifying_key(public_key: &[u8; 32]) -> Result<VerifyingKey, PackError> {
    VerifyingKey::from_bytes(public_key).map_err(|_| {
        PackError::Signer("the card's Signature-slot key is not a valid Ed25519 public key".into())
    })
}

/// Sign `payload` on a card and write the bundle to `out`. `public_key` is
/// the card's Signature-slot key (`YubiKeySigner::public_key`), and `sign`
/// is the card's signing call (`YubiKeySigner::sign`). The signature is
/// checked before anything is written ([`write_bundle_with`]), so a card
/// removed mid-signature, a wrong PIN or a wrong card leaves no file.
/// Returns the verifying key the bundle names as its publisher.
pub fn write_bundle_on_card(
    payload: &[u8],
    public_key: &[u8; 32],
    sign: &mut CardSignFn<'_>,
    out: &Path,
) -> Result<VerifyingKey, PackError> {
    let key = card_verifying_key(public_key)?;
    let mut sign = |m: &[u8]| sign(m).map_err(|e| PackError::Signer(e.to_string()));
    write_bundle_with(payload, &key, &mut sign, out)?;
    Ok(key)
}

/// Pick the card `yubikey-init` provisions from the attached cards. With
/// `--serial`, the card with that serial; without it, the only card
/// attached (several attached is refused, so the wrong card is never
/// re-keyed by accident). Ported from `aivyx-pa`'s `federation.rs`
/// (`choose_card`).
pub fn choose_card<'a>(
    cards: &'a [discovery::CardSummary],
    serial: Option<&str>,
) -> Result<&'a discovery::CardSummary, PackError> {
    if let Some(serial) = serial {
        return cards.iter().find(|c| c.serial == serial).ok_or_else(|| {
            PackError::Signer(format!(
                "no attached YubiKey has serial {serial} (attached: {})",
                describe_cards(cards)
            ))
        });
    }
    match cards {
        [] => Err(PackError::Signer(
            "no YubiKey found: check that pcscd is running and a YubiKey is inserted".into(),
        )),
        [one] => Ok(one),
        _ => Err(PackError::Signer(format!(
            "several YubiKeys are attached ({}): pass --serial <serial> to choose one",
            describe_cards(cards)
        ))),
    }
}

/// `"<serial> (Signature slot empty|occupied), ..."`, or `"none"`.
pub fn describe_cards(cards: &[discovery::CardSummary]) -> String {
    if cards.is_empty() {
        return "none".into();
    }
    cards
        .iter()
        .map(|c| format!("{} ({})", c.serial, slot_state(c.has_signature_key)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// How the Signature slot is described in `yubikey-init`'s output.
pub fn slot_state(has_key: bool) -> &'static str {
    if has_key {
        "Signature slot occupied"
    } else {
        "Signature slot empty"
    }
}

/// The flag that allows `yubikey-init` to overwrite an occupied slot.
pub const OVERWRITE_FLAG: &str = "--overwrite-existing-key";

/// Whether `yubikey-init` may overwrite `card`'s Signature slot, ported
/// from `aivyx-pa`'s `federation yubikey-init`: an empty slot needs
/// nothing (`Ok(false)`). An occupied one needs both
/// `--overwrite-existing-key` (`overwrite_flag`) and the operator typing
/// the card serial back at an interactive terminal (`read_typed`, called
/// only when both of the others hold); then `Ok(true)`. Anything else is
/// refused before any PIN is asked for.
pub fn confirm_overwrite(
    card: &discovery::CardSummary,
    overwrite_flag: bool,
    interactive: bool,
    read_typed: &mut dyn FnMut() -> Result<String, String>,
) -> Result<bool, PackError> {
    if !card.has_signature_key {
        return Ok(false);
    }
    let serial = &card.serial;
    if !overwrite_flag {
        return Err(PackError::Signer(format!(
            "card {serial}'s Signature slot already holds a key: refusing to overwrite it (it \
             may be a GPG signing key or aivyx-pa's federation identity key). Run again with \
             {OVERWRITE_FLAG} once you are sure that key may be destroyed."
        )));
    }
    if !interactive {
        return Err(PackError::Signer(format!(
            "{OVERWRITE_FLAG} needs an interactive terminal to confirm card {serial}'s serial: \
             refusing"
        )));
    }
    let typed = read_typed().map_err(PackError::Signer)?;
    if !typed_serial_confirms_overwrite(serial, &typed) {
        return Err(PackError::Signer(
            "that is not the card's serial: stopping without touching the card".into(),
        ));
    }
    Ok(true)
}

/// The overwrite confirmation: the operator typed the card's serial back
/// exactly (surrounding whitespace, such as the newline, ignored).
pub fn typed_serial_confirms_overwrite(expected_serial: &str, typed: &str) -> bool {
    typed.trim() == expected_serial
}

/// A freshly provisioned card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provisioned {
    /// The card serial, as `aivyx_yubi::discovery::read_serial` renders it.
    pub card_serial: String,
    /// The new Signature-slot Ed25519 public key.
    pub public_key: [u8; 32],
}

/// Provision the Signature slot of an open card for pack signing: the
/// card-side half of `yubikey-init`, ported from `aivyx-pa`'s
/// `federation yubikey-init` with every guard it has.
///
/// - An occupied Signature slot is refused unless `overwrite_confirmed`
///   (the CLI sets it only from [`confirm_overwrite`]: the flag plus the
///   typed serial).
///   Checked again here, on the open card, not only from the earlier
///   listing.
/// - PINs: [`pin::require_pin_changed`], called exactly once. It refuses a
///   PIN whose retry counter is below maximum
///   ([`pin::require_pin_retries_at_maximum`], checked first, before any
///   PIN is presented) and a factory-default User or Admin PIN. This never
///   changes a PIN.
/// - `admin_pin` is asked for only after those checks pass.
/// - Generates an Ed25519 key in the Signature slot, then sets its touch
///   policy to Fixed (every signature needs a physical touch).
///
/// The caller must close this transaction and its card before opening a
/// `YubiKeySigner` on the same card (finding C-1 in `aivyx-pa`'s
/// `federation.rs`): PC/SC blocks forever on a second transaction.
/// `progress` receives one line per step.
pub fn init_card(
    tx: &mut Card<Transaction<'_>>,
    overwrite_confirmed: bool,
    admin_pin: &mut dyn FnMut() -> Result<SecretString, String>,
    progress: &mut dyn FnMut(&str),
) -> Result<Provisioned, PackError> {
    let fail = |e: YubiError| PackError::Signer(e.to_string());

    let occupied = provision::signature_slot_has_key(tx).map_err(fail)?;
    if occupied && !overwrite_confirmed {
        return Err(PackError::Signer(format!(
            "this card's Signature slot already holds a key: refusing to overwrite it \
                 (it may be a GPG signing key or aivyx-pa's federation identity key) without \
                 {OVERWRITE_FLAG} and the typed serial"
        )));
    }

    pin::require_pin_changed(tx).map_err(|e| {
        let guidance = match &e {
            YubiError::PinRetriesReduced { .. } => {
                "Check the card's retry counters with `gpg --card-status` before doing \
                 anything else: aivyx-pack does not try to recover a reduced retry counter."
            }
            _ => {
                "aivyx-pack never changes a PIN for you. Change both the User and the Admin \
                 PIN first (e.g. `gpg --card-edit`, then `admin`, then `passwd`), then run \
                 `aivyx-pack yubikey-init` again."
            }
        };
        PackError::Signer(format!("{e}\n\n{guidance}"))
    })?;

    let admin_pin = admin_pin().map_err(PackError::Signer)?;
    let mut admin = tx.as_admin_card(admin_pin).map_err(|e| {
        let e = YubiError::from(e);
        let description = if matches!(e, YubiError::PinBlocked { .. }) {
            "the Admin PIN is blocked (too many failed attempts). The Admin PIN cannot \
             unblock itself: only a Reset Code, if one was set, or a full card reset \
             (TERMINATE + ACTIVATE, which erases every key) recovers from this."
                .to_string()
        } else {
            format!("Admin PIN verification failed: {e}")
        };
        PackError::Signer(format!(
            "{description}\n\n\
             Warning: this failed attempt used one of the Admin PIN's limited retries, and \
             the factory-default PIN check earlier in this command used one too. A blocked \
             Admin PIN cannot be recovered without wiping the card: check the retry counter \
             (`gpg --card-status`) before trying again."
        ))
    })?;

    progress(if occupied {
        "generating an Ed25519 key in the Signature slot (overwriting the existing key, as confirmed)..."
    } else {
        "generating an Ed25519 key in the Signature slot..."
    });
    let public_key = if occupied {
        provision::generate_signature_key_overwriting(&mut admin)
    } else {
        provision::generate_signature_key(&mut admin)
    }
    .map_err(|e| PackError::Signer(format!("Signature-slot key generation failed: {e}")))?;

    progress(
        "setting the Signature slot's touch policy to fixed (every signature will need a touch)...",
    );
    provision::set_signature_touch_policy_fixed(&mut admin)
        .map_err(|e| PackError::Signer(format!("setting the touch policy failed: {e}")))?;

    // `admin`'s borrow of `tx` ends with its last use above.
    let card_serial = discovery::read_serial(tx).map_err(fail)?;
    Ok(Provisioned {
        card_serial,
        public_key: public_key.into(),
    })
}

/// `yubikey-init`'s closing check, after the provisioning transaction is
/// closed: a fresh signer (`YubiKeySigner::new_for_serial`) reports the
/// key provisioning just generated, and a test signature from it
/// verifies. `YubiKeySigner::sign` itself refuses to sign unless the touch
/// policy is Fixed, so a passing check also shows the touch policy took
/// effect.
pub fn check_provisioned(
    provisioned: &Provisioned,
    signer_public_key: &[u8; 32],
    sign: &mut CardSignFn<'_>,
) -> Result<(), PackError> {
    if signer_public_key != &provisioned.public_key {
        return Err(PackError::Signer(
            "the card reports a different Signature-slot key than provisioning generated".into(),
        ));
    }
    let key = card_verifying_key(&provisioned.public_key)?;
    let signature = sign(TEST_MESSAGE)
        .map_err(|e| PackError::Signer(format!("the test signature failed: {e}")))?;
    key.verify(TEST_MESSAGE, &Signature::from_bytes(&signature))
        .map_err(|_| {
            PackError::Signer(
                "the card's test signature does not verify against its public key".into(),
            )
        })
}

/// The base64 form of a card public key, as `encode_verifying_key` prints
/// it (raw bytes, so it works even for a key that is not a valid point).
pub fn encode_card_key(public_key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(public_key)
}

/// `yubikey-init`'s message when the closing check fails after the card
/// was re-keyed: the card holds the new key either way, so its verifying
/// key is printed, with a warning about the User PIN retries already used.
pub fn closing_check_failed(provisioned: &Provisioned, error: &str) -> String {
    format!(
        "card {serial} WAS provisioned (its old Signature-slot key is gone), but the closing \
         check failed: {error}\n\
         new verifying key: {key}\n\
         Warning: the factory-default PIN check already used one User PIN retry, and a \
         mistyped User PIN in this check may have used another. Check the counter with \
         `gpg --card-status` before trying again: a blocked User PIN needs the Admin PIN to \
         reset. To check the card again without re-keying it, sign a test pack with \
         `aivyx-pack build <staging-dir> --yubikey --serial {serial} --out <file>`.",
        serial = provisioned.card_serial,
        key = encode_card_key(&provisioned.public_key),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(serial: &str, has_signature_key: bool) -> discovery::CardSummary {
        discovery::CardSummary {
            serial: serial.into(),
            has_signature_key,
        }
    }

    #[test]
    fn choose_card_needs_a_card() {
        assert!(choose_card(&[], None).is_err());
    }

    #[test]
    fn choose_card_takes_the_only_card() {
        let cards = [card("0006:00112233", false)];
        assert_eq!(choose_card(&cards, None).unwrap().serial, "0006:00112233");
    }

    #[test]
    fn choose_card_refuses_to_guess_between_several() {
        let cards = [card("a", false), card("b", true)];
        let err = choose_card(&cards, None).unwrap_err().to_string();
        assert!(err.contains("--serial"), "{err}");
        assert_eq!(choose_card(&cards, Some("b")).unwrap().serial, "b");
        assert!(choose_card(&cards, Some("c")).is_err());
    }

    #[test]
    fn the_overwrite_confirmation_must_be_the_exact_serial() {
        assert!(typed_serial_confirms_overwrite(
            "0006:00112233",
            "0006:00112233\n"
        ));
        assert!(!typed_serial_confirms_overwrite("0006:00112233", "yes\n"));
        assert!(!typed_serial_confirms_overwrite(
            "0006:00112233",
            "0006:0011223\n"
        ));
        assert!(!typed_serial_confirms_overwrite("0006:00112233", ""));
    }

    #[test]
    fn confirm_overwrite_needs_the_flag_a_terminal_and_the_serial() {
        let empty = card("0006:00112233", false);
        let full = card("0006:00112233", true);
        let mut never = || -> Result<String, String> { panic!("must not prompt") };
        assert!(!confirm_overwrite(&empty, false, false, &mut never).unwrap());

        let err = confirm_overwrite(&full, false, true, &mut never)
            .unwrap_err()
            .to_string();
        assert!(err.contains(OVERWRITE_FLAG), "{err}");
        let err = confirm_overwrite(&full, true, false, &mut never)
            .unwrap_err()
            .to_string();
        assert!(err.contains("interactive terminal"), "{err}");

        let mut wrong = || Ok("yes\n".to_string());
        assert!(confirm_overwrite(&full, true, true, &mut wrong).is_err());
        let mut right = || Ok("0006:00112233\n".to_string());
        assert!(confirm_overwrite(&full, true, true, &mut right).unwrap());
    }

    #[test]
    fn the_closing_check_failure_names_the_new_key_and_the_retries() {
        let p = Provisioned {
            card_serial: "0006:00112233".into(),
            public_key: [5; 32],
        };
        let text = closing_check_failed(&p, "PIN incorrect");
        assert!(text.contains(&encode_card_key(&[5; 32])), "{text}");
        assert!(text.contains("gpg --card-status"), "{text}");
        assert!(text.contains("PIN incorrect"), "{text}");
    }

    #[test]
    fn encode_card_key_matches_encode_verifying_key() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key();
        assert_eq!(
            encode_card_key(&key.to_bytes()),
            crate::encode_verifying_key(&key)
        );
    }

    #[test]
    fn check_provisioned_refuses_a_different_key() {
        let p = Provisioned {
            card_serial: "s".into(),
            public_key: [1; 32],
        };
        let mut sign = |_: &[u8]| -> Result<[u8; 64], YubiError> { unreachable!() };
        assert!(check_provisioned(&p, &[2; 32], &mut sign).is_err());
    }

    #[test]
    fn check_provisioned_accepts_a_signature_that_verifies() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let p = Provisioned {
            card_serial: "s".into(),
            public_key: key.verifying_key().to_bytes(),
        };
        let mut sign = |m: &[u8]| Ok(key.sign(m).to_bytes());
        check_provisioned(&p, &p.public_key.clone(), &mut sign).unwrap();
        let mut bad = |_: &[u8]| Ok([0u8; 64]);
        assert!(check_provisioned(&p, &p.public_key.clone(), &mut bad).is_err());
    }
}
