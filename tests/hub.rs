//! `hub-check` and `hub-sign`: a Hub folder in a temp dir, a throwaway key.

use std::path::{Path, PathBuf};
use std::process::Command;

use aivyx_pack::hub::{
    HubCheckOptions, HubIndex, HubReport, hub_check, parse_publisher_keys, sign_hub_index,
    verify_hub_index,
};
use aivyx_pack::{build_payload, encode_verifying_key, write_bundle};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "aivyx-pack-hub-{tag}-{}",
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
min_version = "1.0.0"
template = "pa/aivyx-pa.toml"

[coder]
min_version = "1.0.0"
agents_file = "coder/AGENTS.md"
"#;

const FILE: &str = "business-manager-0.1.0.aivyxpack";

/// A good Hub: one signed format 2 pack, its index entry and a key file.
struct Hub {
    dir: PathBuf,
    key: SigningKey,
    pubkey: String,
}

impl Hub {
    fn new(tag: &str) -> Hub {
        let dir = tempdir(tag);
        let key = SigningKey::from_bytes(&rand::random());
        let pubkey = encode_verifying_key(&key.verifying_key());
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
        let public = dir.join("public");
        std::fs::create_dir_all(public.join("packs")).unwrap();
        let payload = build_payload(&staging).unwrap();
        write_bundle(&payload, &key, &public.join("packs").join(FILE)).unwrap();
        std::fs::write(
            public.join("publisher-key.txt"),
            format!("# primary — YubiKey serial 12345678\n\n{pubkey}\n"),
        )
        .unwrap();
        let hub = Hub {
            dir: public,
            key,
            pubkey,
        };
        hub.write_index(&hub.entry());
        hub
    }

    fn entry(&self) -> serde_json::Value {
        let bytes = std::fs::read(self.dir.join("packs").join(FILE)).unwrap();
        let sha: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        serde_json::json!({
            "name": "business-manager",
            "display_name": "Business Manager",
            "version": "0.1.0",
            "description": "Runs the business side.",
            "license": "free",
            "format": 2,
            "products": ["pa", "coder"],
            "min_version": { "pa": "1.0.0", "coder": "1.0.0" },
            "file": FILE,
            "size": bytes.len(),
            "sha256": sha,
        })
    }

    fn write_index(&self, entry: &serde_json::Value) {
        let index = serde_json::json!({ "schema_version": 2, "packs": [entry] });
        std::fs::write(
            self.dir.join("packs/index.json"),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();
    }

    fn edit(&self, f: impl FnOnce(&mut serde_json::Value)) {
        let mut entry = self.entry();
        f(&mut entry);
        self.write_index(&entry);
    }

    /// Checked with the throwaway key as the only built-in key.
    fn check(&self) -> HubReport {
        self.check_with(|_| {})
    }

    fn check_with<'a>(&'a self, tweak: impl FnOnce(&mut HubCheckOptions<'a>)) -> HubReport {
        // Leaked: the options borrow it for as long as the caller's own
        // injected lists (a test process, so the leak is harmless).
        let builtin: &'a [&'a str] = Box::leak(Box::new([self.pubkey.as_str()]));
        let mut opts = HubCheckOptions {
            builtin_keys: builtin,
            trust: &[],
            allow_placeholders: false,
            require_signature: false,
            site_dist: None,
        };
        tweak(&mut opts);
        hub_check(&self.dir, &opts)
    }
}

/// Exactly one problem, containing `want`.
fn one_problem(report: &HubReport, want: &str) {
    assert_eq!(report.problems.len(), 1, "{:#?}", report.problems);
    assert!(
        report.problems[0].contains(want),
        "{:?} lacks {want:?}",
        report.problems[0]
    );
}

#[test]
fn a_good_hub_passes() {
    let hub = Hub::new("good");
    let r = hub.check();
    assert!(r.ok(), "{:#?}", r.problems);
    assert_eq!(r.packs, 1);
    assert!(r.warnings.is_empty());
    assert!(!r.index_signed);
    let index = HubIndex::parse(&std::fs::read(hub.dir.join("packs/index.json")).unwrap());
    assert!(index.unwrap().problems().is_empty());
}

#[test]
fn a_wrong_sha256_fails() {
    let hub = Hub::new("sha");
    hub.edit(|e| e["sha256"] = "0".repeat(64).into());
    one_problem(&hub.check(), "sha256 is ");
}

#[test]
fn a_wrong_size_fails() {
    let hub = Hub::new("size");
    hub.edit(|e| e["size"] = 1.into());
    one_problem(&hub.check(), "size is ");
}

#[test]
fn a_bad_bundle_signature_fails() {
    // The bundle re-signed by a key that is not built in.
    let hub = Hub::new("badsig");
    let other = SigningKey::from_bytes(&rand::random());
    let path = hub.dir.join("packs").join(FILE);
    let bundle = aivyx_pack::read_bundle(&path).unwrap();
    write_bundle(&bundle.payload, &other, &path).unwrap();
    hub.write_index(&hub.entry());
    one_problem(&hub.check(), "not a built-in publisher key");
    // `--trust` lets it through.
    let trust = [encode_verifying_key(&other.verifying_key())];
    assert!(hub.check_with(|o| o.trust = &trust).ok());

    // A signature that doesn't verify under the named, trusted key.
    let mut tar = tar::Builder::new(Vec::new());
    for (name, bytes) in [
        ("payload.tar.gz", bundle.payload.as_slice()),
        ("signature.bin", &[0u8; 64][..]),
        ("publisher.txt", hub.pubkey.as_bytes()),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, name, bytes).unwrap();
    }
    std::fs::write(&path, tar.into_inner().unwrap()).unwrap();
    hub.write_index(&hub.entry());
    one_problem(&hub.check(), "signature: signature verification FAILED");
}

#[test]
fn an_index_field_disagreeing_with_the_signed_manifest_fails() {
    let hub = Hub::new("mismatch");
    hub.edit(|e| e["min_version"]["coder"] = "2.0.0".into());
    one_problem(
        &hub.check(),
        "min_version.coder is Some(\"2.0.0\") in the index",
    );
    hub.edit(|e| {
        e["products"] = serde_json::json!(["pa"]);
        e["min_version"] = serde_json::json!({ "pa": "1.0.0" });
    });
    let r = hub.check();
    assert_eq!(r.problems.len(), 2, "{:#?}", r.problems);
    assert!(
        r.problems
            .iter()
            .all(|p| p.contains("disagrees with the signed manifest"))
    );
}

#[test]
fn a_renamed_version_is_caught_by_the_file_name_and_the_manifest() {
    // The index claims 0.2.0 for the 0.1.0 bundle renamed to match.
    let hub = Hub::new("version");
    let mut e = hub.entry();
    let packs = hub.dir.join("packs");
    std::fs::rename(
        packs.join(FILE),
        packs.join("business-manager-0.2.0.aivyxpack"),
    )
    .unwrap();
    e["version"] = "0.2.0".into();
    e["file"] = "business-manager-0.2.0.aivyxpack".into();
    hub.write_index(&e);
    one_problem(
        &hub.check(),
        "version is \"0.2.0\" in the index, \"0.1.0\" in the bundle",
    );
}

#[test]
fn an_unlisted_bundle_fails() {
    let hub = Hub::new("stray");
    std::fs::copy(
        hub.dir.join("packs").join(FILE),
        hub.dir.join("packs/old-0.0.1.aivyxpack"),
    )
    .unwrap();
    one_problem(&hub.check(), "packs/old-0.0.1.aivyxpack: not listed");
}

#[test]
fn a_file_with_a_path_is_refused_and_never_opened() {
    let hub = Hub::new("dotdot");
    // A real bundle one level up, where `../` would reach.
    std::fs::copy(hub.dir.join("packs").join(FILE), hub.dir.join(FILE)).unwrap();
    hub.edit(|e| e["file"] = format!("../{FILE}").into());
    let r = hub.check();
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("must be a plain file name")),
        "{:#?}",
        r.problems
    );
    // The bundle in packs/ is now unlisted; nothing reports on ../.
    assert!(r.problems.iter().any(|p| p.contains("not listed")));
    assert!(!r.problems.iter().any(|p| p.starts_with("packs/../")));
}

#[test]
fn a_missing_bundle_and_a_wrong_file_name_fail() {
    let hub = Hub::new("missing");
    let mut e = hub.entry();
    std::fs::remove_file(hub.dir.join("packs").join(FILE)).unwrap();
    one_problem(&hub.check(), "but missing");
    e["file"] = "other.aivyxpack".into();
    hub.write_index(&e);
    one_problem(&hub.check(), "must be \"business-manager-0.1.0.aivyxpack\"");
}

#[test]
fn the_schema_is_strict() {
    let hub = Hub::new("schema");
    hub.edit(|e| e["download_url"] = "https://example.com/x".into());
    one_problem(&hub.check(), "unknown field `download_url`");
    hub.edit(|e| e["min_version"]["daemon"] = "1.0.0".into());
    one_problem(&hub.check(), "unknown field `daemon`");
    hub.edit(|e| {
        e["min_version"] = serde_json::json!({ "pa": "1.0.0" });
    });
    one_problem(&hub.check(), "min_version has no \"coder\"");
    std::fs::write(
        hub.dir.join("packs/index.json"),
        r#"{"schema_version": 1, "packs": []}"#,
    )
    .unwrap();
    let r = hub.check();
    assert!(r.problems.iter().any(|p| p.contains("schema_version is 1")));
}

#[test]
fn placeholders_fail_unless_allowed() {
    let hub = Hub::new("placeholder");
    hub.edit(|e| e["sha256"] = "PLACEHOLDER_NOT_YET_SIGNED".into());
    // One line for the placeholder; the entry's other checks are skipped,
    // and its file still counts as listed.
    one_problem(&hub.check(), "packs[0].sha256 is a placeholder");
    let r = hub.check_with(|o| o.allow_placeholders = true);
    assert!(r.ok(), "{:#?}", r.problems);
    assert_eq!(r.warnings.len(), 1);
    assert!(r.warnings[0].contains("placeholder"));
    // Case-insensitive, anywhere.
    hub.edit(|e| e["description"] = "coming soon (placeholder)".into());
    one_problem(&hub.check(), "packs[0].description is a placeholder");
}

#[test]
fn the_key_file_format() {
    let k = parse_publisher_keys(
        "# primary\n\n  # indented comment\nAAAA\nnot base64!\n\
         O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=\n",
    );
    assert_eq!(k.keys.len(), 1);
    assert_eq!(k.problems.len(), 2, "{:#?}", k.problems);
    assert!(k.problems[0].contains("line 4"), "{}", k.problems[0]);
    assert!(k.problems[1].contains("line 5"), "{}", k.problems[1]);
    assert!(!k.placeholder);

    let hub = Hub::new("keyfile");
    let path = hub.dir.join("publisher-key.txt");
    std::fs::write(&path, format!("{}\nbm90IGEga2V5\n", hub.pubkey)).unwrap();
    one_problem(
        &hub.check(),
        "line 2: \"bm90IGEga2V5\" is not a base64 Ed25519",
    );
    std::fs::write(&path, "# no keys at all\n").unwrap();
    // (With the throwaway key built in, its absence is reported too.)
    let r = hub.check();
    assert!(
        r.problems.iter().any(|p| p.contains("lists no keys")),
        "{:#?}",
        r.problems
    );
}

#[test]
fn the_key_file_must_equal_the_built_in_list() {
    let hub = Hub::new("keyset");
    let backup = encode_verifying_key(&SigningKey::from_bytes(&rand::random()).verifying_key());
    // The built-in list has a backup key the file lacks.
    let builtin = [hub.pubkey.as_str(), backup.as_str()];
    let trust = [hub.pubkey.clone()];
    let r = hub.check_with(|o| {
        o.builtin_keys = &builtin;
        o.trust = &trust;
    });
    one_problem(&r, "missing the built-in publisher key");
    // The file has a key the built-in list lacks.
    let path = hub.dir.join("publisher-key.txt");
    std::fs::write(&path, format!("{}\n# backup\n{backup}\n", hub.pubkey)).unwrap();
    one_problem(&hub.check(), "which is not a built-in publisher key");
    // Equal sets, any order: fine.
    std::fs::write(&path, format!("{backup}\n{}\n", hub.pubkey)).unwrap();
    assert!(hub.check_with(|o| o.builtin_keys = &builtin).ok());
}

#[test]
fn a_placeholder_key_file_is_allowed_only_before_the_built_in_list_is_filled() {
    let hub = Hub::new("keyplaceholder");
    std::fs::write(
        hub.dir.join("publisher-key.txt"),
        "# PLACEHOLDER — not a real key\nPLACEHOLDER_NOT_A_REAL_KEY_0000\n",
    )
    .unwrap();
    let trust = [hub.pubkey.clone()];
    let r = hub.check_with(|o| {
        o.builtin_keys = &[];
        o.trust = &trust;
        o.allow_placeholders = true;
    });
    assert!(r.ok(), "{:#?}", r.problems);
    assert_eq!(r.warnings.len(), 1);
    let r = hub.check_with(|o| {
        o.builtin_keys = &[];
        o.trust = &trust;
    });
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("contains a placeholder"))
    );
    // Once the built-in list is filled, the flag no longer covers it.
    let r = hub.check_with(|o| o.allow_placeholders = true);
    assert!(
        r.problems.iter().any(|p| p.contains("no longer empty")),
        "{:#?}",
        r.problems
    );
}

#[test]
fn a_signed_index_verifies_and_a_tampered_one_does_not() {
    let hub = Hub::new("signed");
    let r = hub.check_with(|o| o.require_signature = true);
    one_problem(&r, "index.json.sig is missing");

    sign_hub_index(&hub.dir, &hub.key).unwrap();
    let r = hub.check_with(|o| o.require_signature = true);
    assert!(r.ok(), "{:#?}", r.problems);
    assert!(r.index_signed);
    let names: Vec<_> = std::fs::read_dir(hub.dir.join("packs"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(names.is_empty(), "no temp file is left: {names:?}");

    // Any change to the bytes after signing, even whitespace.
    let path = hub.dir.join("packs/index.json");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(b'\n');
    std::fs::write(&path, bytes).unwrap();
    one_problem(&hub.check(), "does not verify against any key");
}

#[test]
fn an_index_signed_by_a_key_not_in_the_key_file_fails() {
    let hub = Hub::new("signedother");
    sign_hub_index(&hub.dir, &SigningKey::from_bytes(&rand::random())).unwrap();
    one_problem(&hub.check(), "does not verify against any key");
}

#[test]
fn a_payload_signature_is_not_an_index_signature() {
    // The publisher key signing the raw index bytes, as it signs a bundle
    // payload: without the domain prefix, it must not be accepted.
    let hub = Hub::new("domain");
    let index = std::fs::read(hub.dir.join("packs/index.json")).unwrap();
    let raw = hub.key.sign(&index).to_bytes();
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
    std::fs::write(hub.dir.join("packs/index.json.sig"), &b64).unwrap();
    one_problem(&hub.check(), "does not verify against any key");
    assert!(verify_hub_index(&index, &b64, &[hub.key.verifying_key()]).is_err());
    // And the prefixed signature is accepted.
    let good = hub
        .key
        .sign(&aivyx_pack::hub::hub_index_message(&index))
        .to_bytes();
    let good = base64::engine::general_purpose::STANDARD.encode(good);
    assert!(verify_hub_index(&index, &good, &[hub.key.verifying_key()]).is_ok());
}

#[test]
fn hub_sign_refuses_an_index_that_is_not_schema_2() {
    let hub = Hub::new("signbad");
    std::fs::write(hub.dir.join("packs/index.json"), r#"{"schema_version": 1}"#).unwrap();
    assert!(sign_hub_index(&hub.dir, &hub.key).is_err());
    assert!(!hub.dir.join("packs/index.json.sig").exists());
}

#[test]
fn site_dist_scan_fails_on_inline_code_and_private_links() {
    let hub = Hub::new("site");
    let dist = hub.dir.clone();
    std::fs::write(
        dist.join("index.html"),
        "<!doctype html><html><head><script src=\"/theme.js\"></script>\
         <link rel=stylesheet href=\"/site.css\"></head>\
         <body><a href=\"https://github.com/Aivyx-Agent/aivyx-pack\">pack</a></body></html>",
    )
    .unwrap();
    let r = hub.check_with(|o| o.site_dist = Some(&dist));
    assert!(r.ok(), "a clean page passes: {:#?}", r.problems);

    std::fs::create_dir_all(dist.join("docs")).unwrap();
    std::fs::write(
        dist.join("docs/index.html"),
        "<html>\n<script>toggle()</script>\n<style>p{}</style>\n<p style=\"x\">\n\
         <a href=\"https://www.github.com/aivyx-agent/AIVYX-HUB#status\">status</a>\n",
    )
    .unwrap();
    let r = hub.check_with(|o| o.site_dist = Some(&dist));
    assert_eq!(r.problems.len(), 4, "{:#?}", r.problems);
    for (p, (line, want)) in r.problems.iter().zip([
        (2, "inline <script>"),
        (3, "inline <style> element"),
        (4, "inline style=\""),
        (5, "private repo aivyx-hub"),
    ]) {
        assert!(
            p.starts_with(&format!("site: docs/index.html:{line}: ")),
            "{p}"
        );
        assert!(p.contains(want), "{p}");
    }
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aivyx-pack"))
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn the_commands_end_to_end() {
    let hub = Hub::new("cli");
    let keyfile = hub.dir.parent().unwrap().join("key.bin");
    std::fs::write(&keyfile, hub.key.to_bytes()).unwrap();

    // AIVYX_PUBLISHER_KEYS is empty, so the bundle needs --trust.
    let out = bin().args(["hub-check", s(&hub.dir)]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("\u{2717} packs/") && l.contains("--trust")),
        "{stdout}"
    );

    let out = bin()
        .args(["hub-sign", s(&hub.dir), "--key", s(&keyfile)])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains(&hub.pubkey));

    let out = bin()
        .args([
            "hub-check",
            s(&hub.dir),
            "--trust",
            &hub.pubkey,
            "--require-signature",
            "--site-dist",
            s(&hub.dir),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert_eq!(stdout.trim(), "\u{2713} hub ok: 1 packs, index signed");
}

#[test]
fn hub_command_usage_errors() {
    for args in [
        &["hub-check"][..],
        &["hub-check", "-d"][..],
        &["hub-check", "d", "--trust"][..],
        &["hub-check", "d", "--trust", "-k"][..],
        &["hub-check", "d", "--site-dist", "--allow-placeholders"][..],
        &["hub-check", "d", "--bogus"][..],
        &["hub-sign", "d"][..],
        &["hub-sign", "-d", "--key", "k"][..],
        &["hub-sign", "d", "--key", "-k"][..],
        &["hub-sign", "d", "--key", "k", "--yubikey"][..],
        &["hub-sign", "d", "--key", "k", "--serial", "1"][..],
    ] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
    for args in [&["hub-check", "--help"][..], &["hub-sign", "d", "-h"][..]] {
        let out = bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("aivyx-pack hub-sign"));
    }
}

#[cfg(not(feature = "yubikey"))]
#[test]
fn hub_sign_on_a_yubikey_needs_the_feature() {
    let out = bin().args(["hub-sign", "d", "--yubikey"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("without YubiKey support"));
}

#[test]
fn a_format_1_pack_lists_one_bundle_per_target() {
    let hub = Hub::new("format1");
    let staging = hub.dir.parent().unwrap().join("staging1");
    std::fs::create_dir_all(staging.join("bin")).unwrap();
    std::fs::write(
        staging.join("manifest.toml"),
        "name = \"kitchen\"\nversion = \"1.0.0\"\ntarget = \"x86_64-unknown-linux-gnu\"\n\
         min_daemon_version = \"1.0.0\"\npublisher = \"Aivyx\"\n",
    )
    .unwrap();
    std::fs::write(staging.join("bin/tool"), b"#!fake").unwrap();
    let file = "kitchen-1.0.0-x86_64-unknown-linux-gnu.aivyxpack";
    let path = hub.dir.join("packs").join(file);
    write_bundle(&build_payload(&staging).unwrap(), &hub.key, &path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let sha: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut kitchen = serde_json::json!({
        "name": "kitchen", "display_name": "Kitchen", "version": "1.0.0",
        "description": "d", "license": "free", "format": 1, "products": ["pa"],
        "min_version": { "pa": "1.0.0" },
        "targets": [{
            "target": "x86_64-unknown-linux-gnu", "file": file,
            "size": bytes.len(), "sha256": sha,
        }],
    });
    let write = |k: &serde_json::Value| {
        let index = serde_json::json!({ "schema_version": 2, "packs": [hub.entry(), k] });
        std::fs::write(hub.dir.join("packs/index.json"), index.to_string()).unwrap();
    };
    write(&kitchen);
    let r = hub.check();
    assert!(r.ok(), "{:#?}", r.problems);
    assert_eq!(r.packs, 2);

    kitchen["targets"][0]["target"] = "aarch64-apple-darwin".into();
    write(&kitchen);
    let r = hub.check();
    assert!(
        r.problems
            .iter()
            .any(|p| p.contains("must be \"kitchen-1.0.0-aarch64-apple-darwin")),
        "{:#?}",
        r.problems
    );

    kitchen["targets"][0]["target"] = "x86_64-unknown-linux-gnu".into();
    kitchen["file"] = file.into();
    write(&kitchen);
    one_problem(&hub.check(), "a format 1 pack lists targets, not file");
}
