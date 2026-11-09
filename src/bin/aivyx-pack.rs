//! `aivyx-pack` — the publisher's tool for Aivyx packs: make a signing key,
//! build and sign a pack, and inspect one. Users install packs with their
//! product's own command (`aivyx-pa pack install`, `aivyx-coder pack
//! install`).

use std::path::Path;
use std::process::ExitCode;

use aivyx_pack::hub::{HubCheckOptions, hub_check, sign_hub_index};
use aivyx_pack::{
    AIVYX_PUBLISHER_KEYS, PackError, build_payload, describe, encode_verifying_key,
    keygen_to_file, load_signing_key, read_any_manifest, read_bundle, verify_bundle,
    write_bundle,
};

const USAGE: &str = "usage:
  aivyx-pack keygen <keyfile>
  aivyx-pack build <staging-dir> --key <keyfile> --out <file>
  aivyx-pack build <staging-dir> --yubikey [--serial <serial>] --out <file>
  aivyx-pack yubikey-init [--serial <serial>] [--overwrite-existing-key]
  aivyx-pack inspect <file> [--trust <base64-key>]... [--allow-untrusted]
  aivyx-pack hub-check <hub-public-dir> [--trust <base64-key>]... [--allow-placeholders]
                       [--require-signature] [--site-dist <dir>]
  aivyx-pack hub-sign <hub-public-dir> --key <keyfile>
  aivyx-pack hub-sign <hub-public-dir> --yubikey [--serial <serial>]";

const NO_YUBIKEY: &str =
    "this aivyx-pack was built without YubiKey support (cargo build --features yubikey)";

/// Who signs a `build`.
// Without the `yubikey` feature, `serial` is parsed but never used.
#[cfg_attr(not(feature = "yubikey"), allow(dead_code))]
enum Signer {
    KeyFile(String),
    YubiKey { serial: Option<String> },
}

#[cfg_attr(not(feature = "yubikey"), allow(dead_code))]
enum Command {
    Keygen { keyfile: String },
    Build { staging: String, signer: Signer, out: String },
    YubikeyInit { serial: Option<String>, overwrite_existing_key: bool },
    Inspect { file: String, trust: Vec<String>, allow_untrusted: bool },
    HubCheck {
        dir: String,
        trust: Vec<String>,
        allow_placeholders: bool,
        require_signature: bool,
        site_dist: Option<String>,
    },
    HubSign { dir: String, signer: Signer },
    Help,
}

impl Command {
    /// `build --yubikey` and `yubikey-init` need the `yubikey` feature.
    fn needs_yubikey(&self) -> bool {
        matches!(
            self,
            Command::YubikeyInit { .. }
                | Command::Build { signer: Signer::YubiKey { .. }, .. }
                | Command::HubSign { signer: Signer::YubiKey { .. }, .. }
        )
    }
}

/// A path or value argument. One starting with `-` is almost certainly a
/// mistyped option, so it is refused rather than used as a file name
/// (`./-name` names such a file).
fn operand<'a>(what: &str, value: &'a str) -> Result<&'a str, String> {
    if value.starts_with('-') {
        return Err(format!(
            "{what} {value:?} starts with '-' and looks like an option (write ./{value} for such a name)"
        ));
    }
    Ok(value)
}

/// `Err` is a usage error (exit 2).
fn parse(args: &[String]) -> Result<Command, String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    if words.iter().any(|w| matches!(*w, "--help" | "-h")) {
        return Ok(Command::Help);
    }
    match words.as_slice() {
        [] | ["help"] => Ok(Command::Help),
        ["keygen", keyfile] => {
            Ok(Command::Keygen { keyfile: operand("keyfile", keyfile)?.to_string() })
        }
        ["build", staging, rest @ ..] => {
            let staging = operand("staging dir", staging)?;
            let (mut key, mut out, mut yubikey, mut serial) = (None, None, false, None);
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                if *flag == "--yubikey" {
                    yubikey = true;
                    continue;
                }
                if !matches!(*flag, "--key" | "--out" | "--serial") {
                    return Err(format!("unknown option {flag}"));
                }
                let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
                let value = operand(&format!("the value of {flag}:"), value)?;
                match *flag {
                    "--key" => key = Some(value.to_string()),
                    "--out" => out = Some(value.to_string()),
                    "--serial" => serial = Some(value.to_string()),
                    other => return Err(format!("unknown option {other}")),
                }
            }
            let signer = match (key, yubikey) {
                (Some(_), true) => return Err("build takes --key or --yubikey, not both".into()),
                (Some(_), false) if serial.is_some() => {
                    return Err("--serial goes with --yubikey".into());
                }
                (Some(key), false) => Signer::KeyFile(key),
                (None, true) => Signer::YubiKey { serial },
                (None, false) => return Err("build needs --key <keyfile> or --yubikey".into()),
            };
            Ok(Command::Build {
                staging: staging.to_string(),
                signer,
                out: out.ok_or("build needs --out <file>")?,
            })
        }
        ["yubikey-init", rest @ ..] => {
            let (mut serial, mut overwrite_existing_key) = (None, false);
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                match *flag {
                    "--serial" => {
                        let v = it.next().ok_or("--serial needs a value")?;
                        serial = Some(operand("the value of --serial:", v)?.to_string())
                    }
                    "--overwrite-existing-key" => overwrite_existing_key = true,
                    other => return Err(format!("unknown option {other}")),
                }
            }
            Ok(Command::YubikeyInit { serial, overwrite_existing_key })
        }
        ["inspect", file, rest @ ..] => {
            let file = operand("file", file)?;
            let (mut trust, mut allow_untrusted) = (Vec::new(), false);
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                match *flag {
                    "--trust" => {
                        let v = it.next().ok_or("--trust needs a key")?;
                        trust.push(operand("the value of --trust:", v)?.to_string())
                    }
                    "--allow-untrusted" => allow_untrusted = true,
                    other => return Err(format!("unknown option {other}")),
                }
            }
            Ok(Command::Inspect { file: file.to_string(), trust, allow_untrusted })
        }
        ["hub-check", dir, rest @ ..] => {
            let dir = operand("hub dir", dir)?;
            let (mut trust, mut allow_placeholders, mut require_signature) =
                (Vec::new(), false, false);
            let mut site_dist = None;
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                match *flag {
                    "--trust" => {
                        let v = it.next().ok_or("--trust needs a key")?;
                        trust.push(operand("the value of --trust:", v)?.to_string())
                    }
                    "--site-dist" => {
                        let v = it.next().ok_or("--site-dist needs a directory")?;
                        site_dist = Some(operand("the value of --site-dist:", v)?.to_string())
                    }
                    "--allow-placeholders" => allow_placeholders = true,
                    "--require-signature" => require_signature = true,
                    other => return Err(format!("unknown option {other}")),
                }
            }
            Ok(Command::HubCheck {
                dir: dir.to_string(),
                trust,
                allow_placeholders,
                require_signature,
                site_dist,
            })
        }
        ["hub-sign", dir, rest @ ..] => {
            let dir = operand("hub dir", dir)?;
            let (mut key, mut yubikey, mut serial) = (None, false, None);
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                if *flag == "--yubikey" {
                    yubikey = true;
                    continue;
                }
                if !matches!(*flag, "--key" | "--serial") {
                    return Err(format!("unknown option {flag}"));
                }
                let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
                let value = operand(&format!("the value of {flag}:"), value)?.to_string();
                if *flag == "--key" {
                    key = Some(value)
                } else {
                    serial = Some(value)
                }
            }
            let signer = match (key, yubikey) {
                (Some(_), true) => return Err("hub-sign takes --key or --yubikey, not both".into()),
                (Some(_), false) if serial.is_some() => {
                    return Err("--serial goes with --yubikey".into());
                }
                (Some(key), false) => Signer::KeyFile(key),
                (None, true) => Signer::YubiKey { serial },
                (None, false) => return Err("hub-sign needs --key <keyfile> or --yubikey".into()),
            };
            Ok(Command::HubSign { dir: dir.to_string(), signer })
        }
        _ => Err("unknown command".into()),
    }
}

fn run(cmd: Command) -> Result<(), String> {
    let err = |e: PackError| e.to_string();
    match cmd {
        Command::Help => println!("{USAGE}"),
        Command::Keygen { keyfile } => {
            if Path::new(&keyfile).exists() {
                return Err(format!("refusing to overwrite {keyfile}"));
            }
            let pubkey = keygen_to_file(Path::new(&keyfile)).map_err(err)?;
            println!("wrote the signing key to {keyfile} — keep it secret");
            println!("verifying key (users trust packs signed with it):");
            println!("  {pubkey}");
        }
        Command::Build { staging, signer, out } => {
            let payload = build_payload(Path::new(&staging)).map_err(err)?;
            let manifest = read_any_manifest(&payload).map_err(err)?;
            match signer {
                Signer::KeyFile(key) => {
                    let key = load_signing_key(Path::new(&key)).map_err(err)?;
                    write_bundle(&payload, &key, Path::new(&out)).map_err(err)?;
                }
                #[cfg(feature = "yubikey")]
                Signer::YubiKey { serial } => {
                    yubikey::build(&payload, serial.as_deref(), Path::new(&out))?
                }
                // Unreachable: `main` stops first (exit 2).
                #[cfg(not(feature = "yubikey"))]
                Signer::YubiKey { .. } => return Err(NO_YUBIKEY.into()),
            }
            println!(
                "built {out}: {} v{} ({})",
                manifest.name(),
                manifest.version(),
                describe::kind(&manifest)
            );
        }
        #[cfg(feature = "yubikey")]
        Command::YubikeyInit { serial, overwrite_existing_key } => {
            yubikey::init(serial.as_deref(), overwrite_existing_key)?
        }
        #[cfg(not(feature = "yubikey"))]
        Command::YubikeyInit { .. } => return Err(NO_YUBIKEY.into()),
        Command::Inspect { file, trust, allow_untrusted } => {
            let bundle = read_bundle(Path::new(&file)).map_err(err)?;
            match verify_bundle(&bundle, &trust) {
                Ok(_) => println!("signature: VERIFIED (trusted publisher)"),
                Err(e @ PackError::UntrustedPublisher { .. }) if allow_untrusted => {
                    println!("signature: NOT TRUSTED — {e}");
                }
                Err(e) => return Err(e.to_string()),
            }
            let manifest = read_any_manifest(&bundle.payload).map_err(err)?;
            print!("{}", describe::describe(&manifest));
        }
        Command::HubCheck { dir, trust, allow_placeholders, require_signature, site_dist } => {
            let opts = HubCheckOptions {
                builtin_keys: AIVYX_PUBLISHER_KEYS,
                trust: &trust,
                allow_placeholders,
                require_signature,
                site_dist: site_dist.as_deref().map(Path::new),
            };
            let report = hub_check(Path::new(&dir), &opts);
            // One line per finding on stdout, greppable by CI.
            for w in &report.warnings {
                println!("! warning: {w}");
            }
            for p in &report.problems {
                println!("\u{2717} {p}");
            }
            if !report.ok() {
                return Err(format!("hub check failed: {} problem(s)", report.problems.len()));
            }
            let signed = if report.index_signed { ", index signed" } else { "" };
            println!("\u{2713} hub ok: {} packs{signed}", report.packs);
        }
        Command::HubSign { dir, signer } => match signer {
            Signer::KeyFile(key) => {
                let key = load_signing_key(Path::new(&key)).map_err(err)?;
                sign_hub_index(Path::new(&dir), &key).map_err(err)?;
                println!("signed {dir}/packs/index.json -> packs/index.json.sig");
                println!("  key: {}", encode_verifying_key(&key.verifying_key()));
            }
            #[cfg(feature = "yubikey")]
            Signer::YubiKey { serial } => yubikey::hub_sign(Path::new(&dir), serial.as_deref())?,
            #[cfg(not(feature = "yubikey"))]
            Signer::YubiKey { .. } => return Err(NO_YUBIKEY.into()),
        },
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = match parse(&args) {
        Ok(cmd) => cmd,
        Err(why) => {
            eprintln!("aivyx-pack: {why}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if cmd.needs_yubikey() && !cfg!(feature = "yubikey") {
        eprintln!("aivyx-pack: {NO_YUBIKEY}");
        return ExitCode::from(2);
    }
    match run(cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("aivyx-pack: {why}");
            ExitCode::from(1)
        }
    }
}

/// `build --yubikey` and `yubikey-init`: the prompting and the real card.
/// Everything that can be tested without hardware is in
/// `aivyx_pack::yubikey`.
#[cfg(feature = "yubikey")]
mod yubikey {
    use std::io::{self, IsTerminal, Write as _};
    use std::path::Path;

    use aivyx_pack::encode_verifying_key;
    use aivyx_pack::yubikey::{
        check_provisioned, choose_card, closing_check_failed, confirm_overwrite, encode_card_key,
        init_card, slot_state, write_bundle_on_card,
    };
    use aivyx_yubi::{SecretString, YubiError, YubiKeySigner, discovery};

    fn prompt_pin(prompt: &str) -> Result<SecretString, String> {
        rpassword::prompt_password(prompt)
            .map(SecretString::from)
            .map_err(|e| format!("could not read the PIN: {e}"))
    }

    fn open_signer(pin: SecretString, serial: Option<&str>) -> Result<YubiKeySigner, String> {
        match serial {
            Some(serial) => YubiKeySigner::new_for_serial(pin, serial),
            None => YubiKeySigner::new(pin),
        }
        .map_err(|e| format!("could not open the YubiKey: {e}"))
    }

    /// `build <staging> --yubikey [--serial S] --out <file>`.
    pub fn build(payload: &[u8], serial: Option<&str>, out: &Path) -> Result<(), String> {
        let pin = prompt_pin("YubiKey user PIN: ")?;
        let signer = open_signer(pin, serial)?;
        println!("touch the YubiKey to sign…");
        let key = write_bundle_on_card(payload, &signer.public_key(), &mut |m| signer.sign(m), out)
            .map_err(|e| e.to_string())?;
        println!("signed on YubiKey {}", signer.card_serial());
        println!("verifying key (users trust packs signed with it):");
        println!("  {}", encode_verifying_key(&key));
        Ok(())
    }

    /// `hub-sign <dir> --yubikey [--serial S]`.
    pub fn hub_sign(hub: &Path, serial: Option<&str>) -> Result<(), String> {
        let pin = prompt_pin("YubiKey user PIN: ")?;
        let signer = open_signer(pin, serial)?;
        println!("touch the YubiKey to sign…");
        let key = aivyx_pack::yubikey::sign_hub_index_on_card(
            hub,
            &signer.public_key(),
            &mut |m| signer.sign(m),
        )
        .map_err(|e| e.to_string())?;
        println!("signed {}/packs/index.json -> packs/index.json.sig", hub.display());
        println!("  on YubiKey {}, key: {}", signer.card_serial(), encode_verifying_key(&key));
        Ok(())
    }

    /// `yubikey-init [--serial S]`: provision a card's Signature slot for
    /// pack signing. Ported from `aivyx-pa`'s `federation yubikey-init`.
    pub fn init(serial: Option<&str>, overwrite_existing_key: bool) -> Result<(), String> {
        let say = |line: &str| eprintln!("aivyx-pack yubikey-init: {line}");
        say(
            "this card's Signature slot will hold only this pack key. Never use it for \
             aivyx-pa's federation identity key: a card has one Signature slot, and one \
             key cannot be both.",
        );
        say("listing attached YubiKeys (pcscd must be running)...");
        let cards = discovery::list_cards().map_err(|e| e.to_string())?;
        for card in &cards {
            say(&format!(
                "  found card {} ({})",
                card.serial,
                slot_state(card.has_signature_key)
            ));
        }
        let chosen = choose_card(&cards, serial).map_err(|e| e.to_string())?;
        let chosen_serial = chosen.serial.clone();
        say(&format!("using card {chosen_serial}"));

        // An occupied slot is overwritten only with --overwrite-existing-key
        // and the serial typed back at a real terminal. Asked before any PIN.
        let overwrite_confirmed = confirm_overwrite(
            chosen,
            overwrite_existing_key,
            io::stdin().is_terminal(),
            &mut || {
                eprint!(
                    "aivyx-pack yubikey-init: card {chosen_serial}'s Signature slot already \
                     holds a key (it may be a GPG signing key, or aivyx-pa's federation identity \
                     key). Provisioning PERMANENTLY DESTROYS it. Type the card's serial to \
                     confirm: "
                );
                io::stderr().flush().map_err(|e| e.to_string())?;
                let mut typed = String::new();
                io::stdin()
                    .read_line(&mut typed)
                    .map_err(|e| format!("could not read the confirmation: {e}"))?;
                Ok(typed)
            },
        )
        .map_err(|e| e.to_string())?;

        let mut card =
            discovery::discover_real_card_by_serial(&chosen_serial).map_err(|e| e.to_string())?;
        let mut tx = card
            .transaction()
            .map_err(YubiError::from)
            .map_err(|e| format!("could not open a card transaction: {e}"))?;
        let provisioned = init_card(
            &mut tx,
            overwrite_confirmed,
            &mut || prompt_pin("Admin PIN (input hidden): "),
            &mut |line| say(line),
        )
        .map_err(|e| e.to_string())?;

        // Finding C-1 in aivyx-pa's federation.rs: close the provisioning
        // transaction and the card before `YubiKeySigner` opens its own.
        // PC/SC blocks forever on a second exclusive transaction on the
        // same reader, which would hang here after the card is re-keyed.
        drop(tx);
        drop(card);

        say(&format!(
            "provisioned card {}; checking it with a test signature...",
            provisioned.card_serial
        ));
        // The card is re-keyed by now: if this check fails, still print the
        // new key, and warn about the User PIN retries already used.
        let checked = (|| {
            let pin = prompt_pin("User PIN (input hidden, for the test signature): ")?;
            let signer = open_signer(pin, Some(&provisioned.card_serial))?;
            say("touch the YubiKey to sign the test message…");
            check_provisioned(&provisioned, &signer.public_key(), &mut |m| signer.sign(m))
                .map_err(|e| e.to_string())
        })();
        checked.map_err(|e| closing_check_failed(&provisioned, &e))?;

        say("the test signature verifies (the touch policy is fixed: it needed a touch).");
        println!("card serial: {}", provisioned.card_serial);
        println!("verifying key (users trust packs signed with it):");
        println!("  {}", encode_card_key(&provisioned.public_key));
        println!(
            "this card now holds this pack key in its Signature slot. Keep it for packs \
             only: never provision aivyx-pa's federation identity key on it."
        );
        println!(
            "sign packs with: aivyx-pack build <staging-dir> --yubikey --serial {} --out <file>",
            provisioned.card_serial
        );
        Ok(())
    }
}
