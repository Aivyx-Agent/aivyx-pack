//! `aivyx-pack` — the publisher's tool for Aivyx packs: make a signing key,
//! build and sign a pack, and inspect one. Users install packs with their
//! product's own command (`aivyx-pa pack install`, `aivyx-coder pack
//! install`).

use std::path::Path;
use std::process::ExitCode;

use aivyx_pack::{
    PackError, build_payload, describe, keygen_to_file, load_signing_key, read_any_manifest,
    read_bundle, verify_bundle, write_bundle,
};

const USAGE: &str = "usage:
  aivyx-pack keygen <keyfile>
  aivyx-pack build <staging-dir> --key <keyfile> --out <file>
  aivyx-pack inspect <file> [--trust <base64-key>]... [--allow-untrusted]";

enum Command {
    Keygen { keyfile: String },
    Build { staging: String, key: String, out: String },
    Inspect { file: String, trust: Vec<String>, allow_untrusted: bool },
    Help,
}

/// `Err` is a usage error (exit 2).
fn parse(args: &[String]) -> Result<Command, String> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        [] | ["help"] | ["--help"] | ["-h"] => Ok(Command::Help),
        ["keygen", keyfile] => Ok(Command::Keygen { keyfile: keyfile.to_string() }),
        ["build", staging, rest @ ..] => {
            let (mut key, mut out) = (None, None);
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
                match *flag {
                    "--key" => key = Some(value.to_string()),
                    "--out" => out = Some(value.to_string()),
                    other => return Err(format!("unknown option {other}")),
                }
            }
            Ok(Command::Build {
                staging: staging.to_string(),
                key: key.ok_or("build needs --key <keyfile>")?,
                out: out.ok_or("build needs --out <file>")?,
            })
        }
        ["inspect", file, rest @ ..] => {
            let (mut trust, mut allow_untrusted) = (Vec::new(), false);
            let mut it = rest.iter();
            while let Some(flag) = it.next() {
                match *flag {
                    "--trust" => {
                        trust.push(it.next().ok_or("--trust needs a key")?.to_string())
                    }
                    "--allow-untrusted" => allow_untrusted = true,
                    other => return Err(format!("unknown option {other}")),
                }
            }
            Ok(Command::Inspect { file: file.to_string(), trust, allow_untrusted })
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
        Command::Build { staging, key, out } => {
            let key = load_signing_key(Path::new(&key)).map_err(err)?;
            let payload = build_payload(Path::new(&staging)).map_err(err)?;
            let manifest = read_any_manifest(&payload).map_err(err)?;
            write_bundle(&payload, &key, Path::new(&out)).map_err(err)?;
            println!(
                "built {out}: {} v{} ({})",
                manifest.name(),
                manifest.version(),
                describe::kind(&manifest)
            );
        }
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
    match run(cmd) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("aivyx-pack: {why}");
            ExitCode::from(1)
        }
    }
}
