//! The `aivyx-pack` publisher command, end to end.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aivyx-pack"))
}

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aivyx-pack-cli-{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const MANIFEST: &str = r#"
format = 2
name = "business-manager"
version = "0.1.0"
publisher = "Aivyx"
products = ["pa", "coder"]

[pa]
min_version = "0.18.0"
template = "pa/aivyx-pa.toml"
requires = ["gmail", "calendar"]

[coder]
min_version = "0.5.0"
agents_file = "coder/AGENTS.md"
"#;

fn write_config_pack(dir: &Path) -> PathBuf {
    let staging = dir.join("staging");
    for (rel, body) in [
        ("manifest.toml", MANIFEST),
        ("pa/aivyx-pa.toml", "[profile]\n"),
        ("coder/AGENTS.md", "# Instructions\n"),
    ] {
        let path = staging.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
    staging
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn keygen_build_inspect_round_trip() {
    let dir = tempdir("roundtrip");
    let key = dir.join("key.bin");
    let out = bin().args(["keygen", s(&key)]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let pubkey = stdout.lines().find(|l| l.starts_with("  ")).unwrap().trim().to_string();
    assert_eq!(bin().args(["keygen", s(&key)]).output().unwrap().status.code(), Some(1), "no overwrite");

    let staging = write_config_pack(&dir);
    let pack = dir.join("bm.aivyxpack");
    let out = bin()
        .args(["build", s(&staging), "--key", s(&key), "--out", s(&pack)])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("config pack for pa, coder"));

    let out = bin().args(["inspect", s(&pack), "--trust", &pubkey]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(text.contains("signature: VERIFIED"), "{text}");
    assert!(text.contains("requires: gmail, calendar"), "{text}");

    let out = bin().args(["inspect", s(&pack)]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "untrusted without --allow-untrusted");
    let out = bin().args(["inspect", s(&pack), "--allow-untrusted"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("signature: NOT TRUSTED"));
}

#[test]
fn unknown_command_prints_usage() {
    let out = bin().arg("frobnicate").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("aivyx-pack build"));
    let out = bin().args(["build", "x", "--key", "k"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "missing --out is a usage error");
}

#[test]
fn build_takes_one_signer() {
    let both = bin().args(["build", "x", "--key", "k", "--yubikey", "--out", "o"]).output().unwrap();
    assert_eq!(both.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&both.stderr).contains("not both"));
    let neither = bin().args(["build", "x", "--out", "o"]).output().unwrap();
    assert_eq!(neither.status.code(), Some(2));
    let serial = bin().args(["build", "x", "--key", "k", "--serial", "1", "--out", "o"]).output();
    assert_eq!(serial.unwrap().status.code(), Some(2), "--serial needs --yubikey");
}

#[cfg(not(feature = "yubikey"))]
#[test]
fn yubikey_commands_need_the_feature() {
    let no_support =
        "this aivyx-pack was built without YubiKey support (cargo build --features yubikey)";
    for args in [
        &["build", "x", "--yubikey", "--out", "o"][..],
        &["build", "x", "--yubikey", "--serial", "1", "--out", "o"][..],
        &["yubikey-init"][..],
        &["yubikey-init", "--serial", "1"][..],
        &["yubikey-init", "--overwrite-existing-key", "--serial", "1"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).contains(no_support), "{args:?}");
    }
}

/// Runs the CLI in an empty directory; returns (exit code, stdout, stderr)
/// and asserts the run created nothing there.
fn run_in_empty_dir(tag: &str, args: &[&str]) -> (Option<i32>, String, String) {
    let dir = tempdir(tag);
    let out = bin().args(args).current_dir(&dir).output().unwrap();
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert!(left.is_empty(), "{args:?} created {left:?}");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn help_anywhere_prints_usage_and_writes_nothing() {
    for args in [
        &["keygen", "--help"][..],
        &["keygen", "-h"][..],
        &["--help"][..],
        &["build", "--help"][..],
        &["build", "x", "--key", "k", "--out", "o", "-h"][..],
        &["inspect", "--help"][..],
        &["yubikey-init", "--help"][..],
    ] {
        let (code, stdout, _) = run_in_empty_dir("help", args);
        assert_eq!(code, Some(0), "{args:?}");
        assert!(stdout.contains("aivyx-pack keygen"), "{args:?}");
    }
}

#[test]
fn dash_leading_operands_are_usage_errors_and_write_nothing() {
    for args in [
        &["keygen", "-x"][..],
        &["keygen", "--"][..],
        &["keygen", "-"][..],
        &["keygen", "--bogus"][..],
        &["build", "--", "--key", "k", "--out", "o"][..],
        &["build", "-s", "--key", "k", "--out", "o"][..],
        &["build", "--key", "k", "--out", "o"][..],
        &["build", "x", "--key", "-k", "--out", "o"][..],
        &["build", "x", "--key", "k", "--out", "-o"][..],
        &["build", "x", "--key", "k", "--out", "--yubikey"][..],
        &["inspect", "-f"][..],
        &["inspect", "f", "--trust", "-t"][..],
    ] {
        let (code, _, stderr) = run_in_empty_dir("dash", args);
        assert_eq!(code, Some(2), "{args:?}");
        assert!(stderr.contains("aivyx-pack:"), "{args:?}");
    }
}

#[test]
fn dot_slash_names_a_dash_file() {
    let dir = tempdir("dotslash");
    let out = bin().args(["keygen", "./-key"]).current_dir(&dir).output().unwrap();
    assert!(out.status.success());
    assert!(dir.join("-key").is_file());
}
