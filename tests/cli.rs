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
