//! The Aivyx Hub's pack manifest (`packs/index.json`, schema 2) and the
//! checks `aivyx-pack hub-check` and `aivyx-pack hub-sign` run on a Hub's
//! public folder.
//!
//! A Hub folder holds:
//!
//! - `publisher-key.txt`: `#` comment lines, blank lines, and one base64
//!   Ed25519 verifying key per other line;
//! - `packs/index.json`: the manifest ([`HubIndex`]);
//! - `packs/index.json.sig`: optional, a detached base64 Ed25519 signature
//!   over [`HUB_INDEX_SIGNING_PREFIX`] followed by the exact bytes of
//!   `index.json` (see [`hub_index_message`]);
//! - `packs/<name>-<version>.aivyxpack`: the bundles the manifest lists.
//!
//! The prefix separates the two things a publisher key signs: a bundle
//! signature is over raw `payload.tar.gz` bytes, an index signature is over
//! the prefixed index, so neither can be passed off as the other.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Manifest, PackError, Product, SignFn, bundle_temp_path, check_name, decode_verifying_key,
    is_plain_version, read_any_manifest, read_bundle, verify_bundle_against,
};

mod site;
pub use site::check_site;

/// The only `schema_version` this crate reads.
pub const HUB_SCHEMA_VERSION: u32 = 2;

/// What an index signature signs before the index bytes: domain
/// separation from bundle payload signatures.
pub const HUB_INDEX_SIGNING_PREFIX: &[u8] = b"aivyx-hub-index-v1\0";

/// `packs/index.json`, relative to the Hub folder.
pub const INDEX_PATH: &str = "packs/index.json";
/// `packs/index.json.sig`, relative to the Hub folder.
pub const INDEX_SIG_PATH: &str = "packs/index.json.sig";
/// `publisher-key.txt`, relative to the Hub folder.
pub const PUBLISHER_KEY_PATH: &str = "publisher-key.txt";

/// An index larger than this is refused unread.
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024;

/// `packs/index.json`, schema 2.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HubIndex {
    /// Always 2.
    pub schema_version: u32,
    pub packs: Vec<HubEntry>,
}

/// One pack version the Hub lists.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HubEntry {
    pub name: String,
    pub display_name: String,
    /// `x.y.z`.
    pub version: String,
    pub description: String,
    /// `"free"` for now.
    pub license: String,
    /// The bundle's manifest format: 1 (tool pack) or 2 (config pack).
    pub format: u32,
    /// Which products the pack has a part for.
    pub products: Vec<Product>,
    /// Oldest product version per listed product, and only those.
    pub min_version: MinVersion,
    /// Format 2: the bundle, a plain file name `<name>-<version>.aivyxpack`
    /// next to `index.json`. Clients fetch the manifest's URL directory plus
    /// this name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Format 2: the bundle's size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Format 2: the bundle's sha256, 64 lowercase hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Format 1: one bundle per target platform (instead of `file`, `size`
    /// and `sha256`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<HubTarget>,
}

/// Per-product minimum versions (`x.y.z`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MinVersion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pa: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coder: Option<String>,
}

impl MinVersion {
    pub fn get(&self, product: Product) -> Option<&str> {
        match product {
            Product::Pa => self.pa.as_deref(),
            Product::Coder => self.coder.as_deref(),
        }
    }
}

/// A format 1 pack's bundle for one platform.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HubTarget {
    /// Rust target triple.
    pub target: String,
    /// `<name>-<version>-<target>.aivyxpack`.
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

/// One bundle an entry lists.
#[derive(Debug, Clone, Copy)]
pub struct HubFile<'a> {
    pub file: &'a str,
    pub size: u64,
    pub sha256: &'a str,
    /// Format 1 only.
    pub target: Option<&'a str>,
}

impl HubIndex {
    /// Parse `index.json`: `schema_version` must be 2 and the shape exact
    /// (unknown fields are refused). Field values are checked by
    /// [`HubIndex::problems`].
    pub fn parse(bytes: &[u8]) -> Result<Self, PackError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|e| PackError::BadManifest(format!("not JSON: {e}")))?;
        Self::from_value(value).map_err(PackError::BadManifest)
    }

    fn from_value(value: serde_json::Value) -> Result<Self, String> {
        match value.get("schema_version") {
            Some(v) if v.as_u64() == Some(HUB_SCHEMA_VERSION.into()) => {}
            Some(v) => {
                return Err(format!("schema_version is {v}, not {HUB_SCHEMA_VERSION}"));
            }
            None => return Err("no schema_version".into()),
        }
        serde_json::from_value(value).map_err(|e| format!("not a schema 2 Hub manifest: {e}"))
    }

    /// Every field-level problem, one line each (placeholders are not
    /// looked for here; [`hub_check`] does that).
    pub fn problems(&self) -> Vec<String> {
        let mut out: Vec<String> = (self.packs.iter().enumerate())
            .flat_map(|(i, entry)| entry.problems(i))
            .collect();
        out.extend(self.duplicates());
        out
    }

    /// A name and version, or a file, listed twice.
    fn duplicates(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut files = BTreeSet::new();
        for entry in &self.packs {
            if !seen.insert((entry.name.as_str(), entry.version.as_str())) {
                out.push(format!(
                    "{INDEX_PATH}: lists {} {} twice",
                    entry.name, entry.version
                ));
            }
            for f in entry.files() {
                if !files.insert(f.file) {
                    out.push(format!("{INDEX_PATH}: lists file {:?} twice", f.file));
                }
            }
        }
        out
    }
}

impl HubEntry {
    /// The bundles this entry lists (whether or not their fields are valid).
    pub fn files(&self) -> Vec<HubFile<'_>> {
        match (&self.file, self.size, &self.sha256) {
            (Some(file), Some(size), Some(sha256)) if self.targets.is_empty() => {
                vec![HubFile {
                    file,
                    size,
                    sha256,
                    target: None,
                }]
            }
            _ => self
                .targets
                .iter()
                .map(|t| HubFile {
                    file: &t.file,
                    size: t.size,
                    sha256: &t.sha256,
                    target: Some(&t.target),
                })
                .collect(),
        }
    }

    fn label(&self, i: usize) -> String {
        format!("{INDEX_PATH}: packs[{i}] ({:?})", self.name)
    }

    /// Field-level problems with this entry, one line each.
    pub fn problems(&self, i: usize) -> Vec<String> {
        let at = self.label(i);
        let mut out = Vec::new();
        let mut bad = |msg: String| out.push(format!("{at}: {msg}"));
        if check_name(&self.name).is_err() {
            bad(format!(
                "name {:?} must be alphanumeric/dash/underscore",
                self.name
            ));
        }
        if !is_plain_version(&self.version) {
            bad(format!("version {:?} must be x.y.z", self.version));
        }
        for (field, value) in [
            ("display_name", &self.display_name),
            ("description", &self.description),
            ("license", &self.license),
        ] {
            if value.trim().is_empty() {
                bad(format!("{field} is empty"));
            }
        }
        if !matches!(self.format, 1 | 2) {
            bad(format!("format {} is not 1 or 2", self.format));
        }
        if self.products.is_empty() {
            bad("products is empty".into());
        }
        for (j, p) in self.products.iter().enumerate() {
            if self.products[..j].contains(p) {
                bad(format!("products lists {:?} twice", p.as_str()));
            }
        }
        if self.format == 1 && self.products != [Product::Pa] {
            bad("a format 1 pack's products must be [\"pa\"]".into());
        }
        for product in [Product::Pa, Product::Coder] {
            let listed = self.products.contains(&product);
            match (listed, self.min_version.get(product)) {
                (true, None) => bad(format!("min_version has no {:?}", product.as_str())),
                (false, Some(_)) => bad(format!(
                    "min_version has {:?}, which products doesn't list",
                    product.as_str()
                )),
                (true, Some(v)) if !is_plain_version(v) => bad(format!(
                    "min_version.{} {v:?} must be x.y.z",
                    product.as_str()
                )),
                _ => {}
            }
        }
        let single = [
            self.file.is_some(),
            self.size.is_some(),
            self.sha256.is_some(),
        ];
        match self.format {
            2 => {
                if single != [true; 3] {
                    bad("a format 2 pack needs file, size and sha256".into());
                }
                if !self.targets.is_empty() {
                    bad("a format 2 pack has no targets".into());
                }
                if let Some(file) = &self.file {
                    let want = format!("{}-{}.aivyxpack", self.name, self.version);
                    if let Some(msg) = file_problem(file, &want) {
                        bad(msg);
                    }
                }
                if let Some(sha) = self.sha256.as_ref().filter(|s| !is_sha256_hex(s)) {
                    bad(format!("sha256 {sha:?} must be 64 lowercase hex digits"));
                }
            }
            1 => {
                if single != [false; 3] {
                    bad("a format 1 pack lists targets, not file, size or sha256".into());
                }
                if self.targets.is_empty() {
                    bad("a format 1 pack needs at least one target".into());
                }
                let mut seen = BTreeSet::new();
                for t in &self.targets {
                    if !is_target(&t.target) {
                        bad(format!("target {:?} is not a target triple", t.target));
                        continue;
                    }
                    if !seen.insert(t.target.as_str()) {
                        bad(format!("target {:?} is listed twice", t.target));
                    }
                    let want = format!("{}-{}-{}.aivyxpack", self.name, self.version, t.target);
                    if let Some(msg) = file_problem(&t.file, &want) {
                        bad(msg);
                    }
                    if !is_sha256_hex(&t.sha256) {
                        bad(format!(
                            "target {:?}: sha256 {:?} must be 64 lowercase hex digits",
                            t.target, t.sha256
                        ));
                    }
                }
            }
            _ => {}
        }
        out
    }
}

/// A plain file name with no path in it.
pub fn is_plain_file_name(file: &str) -> bool {
    !file.is_empty()
        && !file.contains(['/', '\\', '\0'])
        && !file.contains("..")
        && !file.starts_with('.')
}

fn file_problem(file: &str, want: &str) -> Option<String> {
    if !is_plain_file_name(file) {
        Some(format!(
            "file {file:?} must be a plain file name (no '/', no '..')"
        ))
    } else if file != want {
        Some(format!("file {file:?} must be {want:?}"))
    } else {
        None
    }
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_target(s: &str) -> bool {
    !s.is_empty()
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn is_placeholder(s: &str) -> bool {
    s.to_ascii_lowercase().contains("placeholder")
}

/// `(json path, value)` for every key or string anywhere in `value` that
/// contains `PLACEHOLDER` (any case).
fn placeholders(value: &serde_json::Value, path: String, out: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::String(s) if is_placeholder(s) => out.push((path, s.clone())),
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                placeholders(v, format!("{path}[{i}]"), out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if is_placeholder(k) {
                    out.push((child.clone(), k.clone()));
                }
                placeholders(v, child, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// The index signature
// ---------------------------------------------------------------------------

/// What an index signature signs: [`HUB_INDEX_SIGNING_PREFIX`] followed by
/// the exact bytes of `index.json`.
pub fn hub_index_message(index: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(HUB_INDEX_SIGNING_PREFIX.len() + index.len());
    m.extend_from_slice(HUB_INDEX_SIGNING_PREFIX);
    m.extend_from_slice(index);
    m
}

/// Check a detached index signature (`index.json.sig`'s text: base64 of
/// 64 bytes) against `keys`. Returns the key that verified.
pub fn verify_hub_index(
    index: &[u8],
    sig_b64: &str,
    keys: &[VerifyingKey],
) -> Result<VerifyingKey, PackError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|_| PackError::BadEntry("index.json.sig", "not base64".into()))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| PackError::BadEntry("index.json.sig", "must be 64 bytes".into()))?;
    let sig = Signature::from_bytes(&arr);
    let message = hub_index_message(index);
    keys.iter()
        .find(|k| k.verify(&message, &sig).is_ok())
        .copied()
        .ok_or(PackError::BadSignature)
}

/// Sign `<hub>/packs/index.json` with any Ed25519 signer and write
/// `<hub>/packs/index.json.sig`. The index must parse as schema 2. The
/// signature is checked against `public_key` before anything is written,
/// and the file goes through a unique temp file and a rename, so a failed
/// signature or write leaves an existing `.sig` untouched.
pub fn sign_hub_index_with(
    hub: &Path,
    public_key: &VerifyingKey,
    sign: &mut SignFn<'_>,
) -> Result<(), PackError> {
    let index = read_index_bytes(&hub.join(INDEX_PATH))?;
    HubIndex::parse(&index)?;
    let message = hub_index_message(&index);
    let signature = Signature::from_bytes(&sign(&message)?);
    public_key
        .verify(&message, &signature)
        .map_err(|_| PackError::BadSignature)?;
    let text = format!(
        "{}\n",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    write_file_atomic(&hub.join(INDEX_SIG_PATH), text.as_bytes())
}

/// [`sign_hub_index_with`] with a key file's signing key.
pub fn sign_hub_index(hub: &Path, key: &SigningKey) -> Result<(), PackError> {
    let mut sign = |m: &[u8]| Ok(key.sign(m).to_bytes());
    sign_hub_index_with(hub, &key.verifying_key(), &mut sign)
}

fn read_index_bytes(path: &Path) -> Result<Vec<u8>, PackError> {
    let len = std::fs::metadata(path)?.len();
    if len > MAX_INDEX_BYTES {
        return Err(PackError::BadManifest(format!(
            "{} is larger than the {MAX_INDEX_BYTES}-byte limit",
            path.display()
        )));
    }
    Ok(std::fs::read(path)?)
}

/// Write `bytes` to a new uniquely named temp file beside `out`, sync it and
/// rename it over `out`; the temp file is removed if a step fails.
fn write_file_atomic(out: &Path, bytes: &[u8]) -> Result<(), PackError> {
    let tmp = bundle_temp_path(out)?;
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, out)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    // Make the rename durable (best effort, as for bundles).
    #[cfg(unix)]
    if result.is_ok() {
        let dir = out.parent().filter(|d| !d.as_os_str().is_empty());
        if let Some(Ok(dir)) = dir.map(std::fs::File::open) {
            let _ = dir.sync_all();
        }
    }
    Ok(result?)
}

// ---------------------------------------------------------------------------
// publisher-key.txt
// ---------------------------------------------------------------------------

/// A parsed `publisher-key.txt`.
#[derive(Debug, Default)]
pub struct PublisherKeyFile {
    /// The valid keys, in file order.
    pub keys: Vec<VerifyingKey>,
    /// One line per malformed key line.
    pub problems: Vec<String>,
    /// True when any line (comments included) contains `PLACEHOLDER`.
    pub placeholder: bool,
}

/// Parse `publisher-key.txt`: blank lines and `#` comment lines are
/// skipped; every other line is one base64 Ed25519 verifying key. A
/// non-comment line containing `PLACEHOLDER` is not a key and not a
/// problem here: it sets `placeholder`.
pub fn parse_publisher_keys(text: &str) -> PublisherKeyFile {
    let mut out = PublisherKeyFile::default();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if is_placeholder(line) {
            out.placeholder = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match decode_verifying_key(line) {
            Some(k) if !out.keys.contains(&k) => out.keys.push(k),
            Some(_) => out.problems.push(format!(
                "{PUBLISHER_KEY_PATH} line {}: the key {line:?} is listed twice",
                n + 1
            )),
            None => out.problems.push(format!(
                "{PUBLISHER_KEY_PATH} line {}: {:?} is not a base64 Ed25519 verifying key",
                n + 1,
                excerpt(line)
            )),
        }
    }
    out
}

fn excerpt(s: &str) -> String {
    let mut e: String = s.chars().take(60).collect();
    if s.chars().count() > 60 {
        e.push('…');
    }
    e
}

// ---------------------------------------------------------------------------
// hub-check
// ---------------------------------------------------------------------------

/// Options for [`hub_check`].
#[derive(Debug, Clone, Copy)]
pub struct HubCheckOptions<'a> {
    /// The built-in publisher keys (base64). The CLI passes
    /// [`crate::AIVYX_PUBLISHER_KEYS`]; tests inject their own.
    pub builtin_keys: &'a [&'a str],
    /// Extra keys bundles may be signed with (`--trust`).
    pub trust: &'a [String],
    /// Placeholders are warnings, not problems (pre-launch builds).
    pub allow_placeholders: bool,
    /// A missing `index.json.sig` is a problem.
    pub require_signature: bool,
    /// Also scan the built site's HTML ([`check_site`]).
    pub site_dist: Option<&'a Path>,
}

/// What [`hub_check`] found.
#[derive(Debug, Default)]
pub struct HubReport {
    /// Problems: each one fails the check.
    pub problems: Vec<String>,
    /// Allowed placeholders.
    pub warnings: Vec<String>,
    /// How many entries `index.json` lists.
    pub packs: usize,
    /// Whether `index.json.sig` was present and verified.
    pub index_signed: bool,
}

impl HubReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Check a Hub's public folder: the manifest, every bundle it lists, stray
/// bundles, `publisher-key.txt` and the index signature (see the module
/// docs). Never stops at the first problem.
pub fn hub_check(hub: &Path, opts: &HubCheckOptions<'_>) -> HubReport {
    let mut r = HubReport::default();
    let publisher_keys = check_publisher_keys(hub, opts, &mut r);
    let index_bytes = match read_index_bytes(&hub.join(INDEX_PATH)) {
        Ok(b) => Some(b),
        Err(e) => {
            r.problems.push(format!("{INDEX_PATH}: {e}"));
            None
        }
    };
    if let Some(bytes) = &index_bytes {
        // `None` when the index didn't parse: then what it lists is
        // unknown, so stray bundles aren't reported.
        if let Some(listed) = check_index(hub, bytes, opts, &mut r) {
            check_stray_bundles(hub, &listed, &mut r);
        }
        check_index_signature(hub, bytes, &publisher_keys, opts, &mut r);
    }
    if let Some(site) = opts.site_dist {
        r.problems.extend(check_site(site));
    }
    r
}

fn check_publisher_keys(
    hub: &Path,
    opts: &HubCheckOptions<'_>,
    r: &mut HubReport,
) -> Vec<VerifyingKey> {
    let text = match std::fs::read_to_string(hub.join(PUBLISHER_KEY_PATH)) {
        Ok(t) => t,
        Err(e) => {
            r.problems.push(format!("{PUBLISHER_KEY_PATH}: {e}"));
            return Vec::new();
        }
    };
    let file = parse_publisher_keys(&text);
    r.problems.extend(file.problems);
    let placeholder_ok = opts.allow_placeholders && opts.builtin_keys.is_empty();
    if file.placeholder {
        if placeholder_ok {
            r.warnings.push(format!(
                "{PUBLISHER_KEY_PATH} is a placeholder (allowed until the built-in key list is filled)"
            ));
        } else if opts.allow_placeholders {
            r.problems.push(format!(
                "{PUBLISHER_KEY_PATH} contains a placeholder, and the built-in key list is no longer empty"
            ));
        } else {
            r.problems
                .push(format!("{PUBLISHER_KEY_PATH} contains a placeholder"));
        }
    }
    if file.keys.is_empty() && !(file.placeholder && placeholder_ok) {
        r.problems.push(format!(
            "{PUBLISHER_KEY_PATH} lists no keys (one base64 key per line)"
        ));
    }
    if !opts.builtin_keys.is_empty() {
        let builtin: BTreeSet<[u8; 32]> = opts
            .builtin_keys
            .iter()
            .filter_map(|k| decode_verifying_key(k))
            .map(|k| k.to_bytes())
            .collect();
        let published: BTreeSet<[u8; 32]> = file.keys.iter().map(|k| k.to_bytes()).collect();
        let b64 = |k: &[u8; 32]| base64::engine::general_purpose::STANDARD.encode(k);
        for k in published.difference(&builtin) {
            r.problems.push(format!(
                "{PUBLISHER_KEY_PATH} lists {}, which is not a built-in publisher key",
                b64(k)
            ));
        }
        for k in builtin.difference(&published) {
            r.problems.push(format!(
                "{PUBLISHER_KEY_PATH} is missing the built-in publisher key {}",
                b64(k)
            ));
        }
    }
    file.keys
}

fn check_index(
    hub: &Path,
    bytes: &[u8],
    opts: &HubCheckOptions<'_>,
    r: &mut HubReport,
) -> Option<BTreeSet<String>> {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(e) => {
            r.problems.push(format!("{INDEX_PATH}: not JSON: {e}"));
            return None;
        }
    };
    let mut found = Vec::new();
    placeholders(&value, String::new(), &mut found);
    // Entries (by index) holding a placeholder: their field and bundle
    // checks are skipped, since the placeholder line already says why.
    let mut placeholder_entries = BTreeSet::new();
    for (path, v) in &found {
        let line = format!("{INDEX_PATH}: {path} is a placeholder ({:?})", excerpt(v));
        if opts.allow_placeholders {
            r.warnings.push(line);
        } else {
            r.problems.push(line);
        }
        if let Some(i) = path
            .strip_prefix("packs[")
            .and_then(|rest| rest.split(']').next())
            .and_then(|n| n.parse::<usize>().ok())
        {
            placeholder_entries.insert(i);
        }
    }
    let index = match HubIndex::from_value(value) {
        Ok(i) => i,
        Err(e) => {
            r.problems.push(format!("{INDEX_PATH}: {e}"));
            return None;
        }
    };
    r.packs = index.packs.len();
    r.problems.extend(index.duplicates());
    let mut listed = BTreeSet::new();
    for entry in &index.packs {
        for f in entry.files() {
            if is_plain_file_name(f.file) {
                listed.insert(f.file.to_string());
            }
        }
    }
    for (i, entry) in index.packs.iter().enumerate() {
        if placeholder_entries.contains(&i) {
            continue;
        }
        let problems = entry.problems(i);
        if !problems.is_empty() {
            // Never open a file named by an entry that didn't validate.
            r.problems.extend(problems);
            continue;
        }
        for f in entry.files() {
            check_bundle(hub, entry, i, f, opts, r);
        }
    }
    Some(listed)
}

fn check_bundle(
    hub: &Path,
    entry: &HubEntry,
    i: usize,
    f: HubFile<'_>,
    opts: &HubCheckOptions<'_>,
    r: &mut HubReport,
) {
    let at = format!("packs/{}", f.file);
    let mut bad = |msg: String| r.problems.push(format!("{at}: {msg}"));
    let path = hub.join("packs").join(f.file);
    match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_file() => {
            if m.len() != f.size {
                bad(format!(
                    "size is {}, but packs[{i}] says {}",
                    m.len(),
                    f.size
                ));
            }
        }
        Ok(_) => return bad("is not a regular file".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return bad(format!("is listed in packs[{i}] but missing"));
        }
        Err(e) => return bad(e.to_string()),
    }
    match sha256_file(&path) {
        Ok(sum) if sum != f.sha256 => {
            bad(format!("sha256 is {sum}, but packs[{i}] says {}", f.sha256))
        }
        Ok(_) => {}
        Err(e) => return bad(e.to_string()),
    }
    let bundle = match read_bundle(&path) {
        Ok(b) => b,
        Err(e) => return bad(format!("not a readable bundle: {e}")),
    };
    let trusted = opts
        .builtin_keys
        .iter()
        .copied()
        .chain(opts.trust.iter().map(String::as_str));
    match verify_bundle_against(&bundle, trusted) {
        Ok(_) => {}
        Err(PackError::UntrustedPublisher { hint }) => bad(format!(
            "signed by {hint}, which is not a built-in publisher key (or --trust)"
        )),
        Err(e) => bad(format!("signature: {e}")),
    }
    let manifest = match read_any_manifest(&bundle.payload) {
        Ok(m) => m,
        Err(e) => return bad(format!("manifest: {e}")),
    };
    for msg in manifest_mismatches(entry, f.target, &manifest) {
        bad(format!(
            "packs[{i}] disagrees with the signed manifest: {msg}"
        ));
    }
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// How an index entry disagrees with the manifest signed inside its bundle.
fn manifest_mismatches(entry: &HubEntry, target: Option<&str>, m: &Manifest) -> Vec<String> {
    let mut out = Vec::new();
    let mut cmp = |field: &str, index: &str, signed: &str| {
        if index != signed {
            out.push(format!(
                "{field} is {index:?} in the index, {signed:?} in the bundle"
            ));
        }
    };
    cmp("name", &entry.name, m.name());
    cmp("version", &entry.version, m.version());
    let (format, products, mins): (u32, Vec<Product>, BTreeMap<Product, &str>) = match m {
        Manifest::Binary(b) => {
            cmp("target", target.unwrap_or(""), &b.target);
            (
                1,
                vec![Product::Pa],
                BTreeMap::from([(Product::Pa, b.min_daemon_version.as_str())]),
            )
        }
        Manifest::Config(c) => {
            let mut mins = BTreeMap::new();
            if let Some(pa) = &c.pa {
                mins.insert(Product::Pa, pa.min_version.as_str());
            }
            if let Some(coder) = &c.coder {
                mins.insert(Product::Coder, coder.min_version.as_str());
            }
            (c.format, c.products.clone(), mins)
        }
    };
    if entry.format != format {
        out.push(format!(
            "format is {} in the index, {format} in the bundle",
            entry.format
        ));
    }
    let set = |p: &[Product]| p.iter().map(|p| p.as_str()).collect::<BTreeSet<_>>();
    if set(&entry.products) != set(&products) {
        out.push(format!(
            "products are {:?} in the index, {:?} in the bundle",
            set(&entry.products),
            set(&products)
        ));
    }
    for product in [Product::Pa, Product::Coder] {
        let (index, signed) = (entry.min_version.get(product), mins.get(&product).copied());
        if index != signed {
            out.push(format!(
                "min_version.{} is {index:?} in the index, {signed:?} in the bundle",
                product.as_str()
            ));
        }
    }
    out
}

fn check_index_signature(
    hub: &Path,
    index: &[u8],
    keys: &[VerifyingKey],
    opts: &HubCheckOptions<'_>,
    r: &mut HubReport,
) {
    let sig = match std::fs::read_to_string(hub.join(INDEX_SIG_PATH)) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if opts.require_signature {
                r.problems
                    .push(format!("{INDEX_SIG_PATH} is missing (--require-signature)"));
            }
            return;
        }
        Err(e) => return r.problems.push(format!("{INDEX_SIG_PATH}: {e}")),
    };
    if keys.is_empty() {
        return r.problems.push(format!(
            "{INDEX_SIG_PATH}: {PUBLISHER_KEY_PATH} has no key to check it with"
        ));
    }
    match verify_hub_index(index, &sig, keys) {
        Ok(_) => r.index_signed = true,
        Err(PackError::BadSignature) => r.problems.push(format!(
            "{INDEX_SIG_PATH} does not verify against any key in {PUBLISHER_KEY_PATH} \
             (index changed after signing, or signed with another key)"
        )),
        Err(e) => r.problems.push(format!("{INDEX_SIG_PATH}: {e}")),
    }
}

fn check_stray_bundles(hub: &Path, listed: &BTreeSet<String>, r: &mut HubReport) {
    let dir = hub.join("packs");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut stray: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "aivyxpack"))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_none_or(|n| !listed.contains(n))
        })
        .collect();
    stray.sort();
    for p in stray {
        r.problems.push(format!(
            "packs/{}: not listed in {INDEX_PATH}",
            p.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_file_names() {
        for ok in ["a-1.0.0.aivyxpack", "x"] {
            assert!(is_plain_file_name(ok), "{ok}");
        }
        for bad in ["", "../x", "a/b", "a\\b", "..", ".hidden", "a..b"] {
            assert!(!is_plain_file_name(bad), "{bad}");
        }
    }

    #[test]
    fn schema_version_is_checked_before_shape() {
        let v1 = br#"{"schema_version": 1, "packs": [{"download_url": "x"}]}"#;
        let err = HubIndex::parse(v1).unwrap_err().to_string();
        assert!(err.contains("schema_version is 1"), "{err}");
        let unknown = br#"{"schema_version": 2, "packs": [], "extra": 1}"#;
        assert!(HubIndex::parse(unknown).is_err());
        assert_eq!(
            HubIndex::parse(br#"{"schema_version": 2, "packs": []}"#)
                .unwrap()
                .packs,
            []
        );
    }

    #[test]
    fn placeholders_are_found_in_keys_and_nested_values() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"a": ["ok", "x_Placeholder"], "PLACEHOLDER_KEY": 1, "b": {"c": "fine"}}"#,
        )
        .unwrap();
        let mut found = Vec::new();
        placeholders(&v, String::new(), &mut found);
        let paths: Vec<_> = found.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, ["PLACEHOLDER_KEY", "a[1]"]);
    }
}
