//! `aivyx-pack check <dir>`: everything a config pack must pass before it
//! is built, in one report. In order: the manifest and the files it names;
//! each product's own `pack check` (run as a child process, so this crate
//! stays free of product code); the pack's `checks.toml`; a build with a
//! throwaway key, read back by each product.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::checks::{load_checks, run_checks};
use crate::{Manifest, Product, build_payload, write_bundle};

/// The first product versions whose `pack check` has the tool lints.
const PA_LINTS: (u64, u64, u64) = (1, 2, 0);
const CODER_LINTS: (u64, u64, u64) = (1, 1, 0);

pub struct CheckOptions {
    /// A product that isn't installed is a note, not a failure.
    pub allow_unchecked: bool,
}

/// One step of the report.
pub struct Step {
    pub name: String,
    pub problems: Vec<String>,
    pub notes: Vec<String>,
}

impl Step {
    fn new(name: &str) -> Self {
        Step {
            name: name.to_string(),
            problems: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// `env_var` when set and non-empty, else `name` on `PATH`.
pub fn find_product(env_var: &str, name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env_var).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The first `x.y.z` in a `--version` line.
fn version_of(text: &str) -> Option<(u64, u64, u64)> {
    text.split_whitespace().find_map(|w| {
        let mut it = w
            .trim_start_matches('v')
            .split('.')
            .map(|n| n.parse::<u64>().ok());
        match (it.next()??, it.next()??, it.next()??) {
            (a, b, c) if it.next().is_none() => Some((a, b, c)),
            _ => None,
        }
    })
}

fn indent(notes: &mut Vec<String>, bytes: &[u8]) {
    for line in String::from_utf8_lossy(bytes)
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        notes.push(format!("  {line}"));
    }
}

/// A temp folder removed when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Build `dir` with a fresh throwaway key; the bundle lives in the scratch dir.
fn trial_build(dir: &Path) -> Result<(PathBuf, Scratch), String> {
    let scratch = Scratch(
        std::env::temp_dir().join(format!(
            "aivyx-pack-check-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        )),
    );
    std::fs::create_dir_all(&scratch.0).map_err(|e| e.to_string())?;
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let payload = build_payload(dir).map_err(|e| e.to_string())?;
    let out = scratch.0.join("trial.aivyxpack");
    write_bundle(&payload, &key, &out).map_err(|e| e.to_string())?;
    Ok((out, scratch))
}

pub fn check_dir(dir: &Path, opts: &CheckOptions) -> Vec<Step> {
    let mut steps = Vec::new();

    let mut format = Step::new("format");
    let manifest = match std::fs::read_to_string(dir.join("manifest.toml"))
        .map_err(|e| format!("can't read manifest.toml: {e}"))
        .and_then(|t| Manifest::parse(&t).map_err(|e| e.to_string()))
    {
        Ok(Manifest::Config(m)) => Some(m),
        Ok(Manifest::Binary(_)) => {
            format.problems.push(
                "this is a tool pack (format 1); `check` is for config packs (format 2)".into(),
            );
            None
        }
        Err(e) => {
            format.problems.push(e);
            None
        }
    };
    if let Some(m) = &manifest {
        for (field, rel, is_dir) in m.paths() {
            let path = dir.join(rel);
            if !(if is_dir {
                path.is_dir()
            } else {
                path.is_file()
            }) {
                format.problems.push(format!(
                    "{field} names {rel:?} but there is no such {}",
                    if is_dir { "folder" } else { "file" }
                ));
            }
        }
    }
    steps.push(format);
    let Some(m) = manifest else {
        return steps;
    };

    let mut bins: Vec<(&str, PathBuf)> = Vec::new();
    for product in &m.products {
        let (env, name, lints) = match product {
            Product::Pa => ("AIVYX_PA", "aivyx-pa", PA_LINTS),
            Product::Coder => ("AIVYX_CODER", "aivyx-coder", CODER_LINTS),
        };
        let mut step = Step::new(name);
        match find_product(env, name) {
            None => {
                let msg = format!(
                    "{} part not checked: {name} not found (set {env} or put it on PATH)",
                    product.as_str()
                );
                if opts.allow_unchecked {
                    step.notes.push(msg)
                } else {
                    step.problems.push(msg)
                }
            }
            Some(bin) => {
                let version = Command::new(&bin)
                    .arg("--version")
                    .output()
                    .ok()
                    .and_then(|o| version_of(&String::from_utf8_lossy(&o.stdout)));
                match version {
                    Some(v) => {
                        step.notes
                            .push(format!("checked with {name} {}.{}.{}", v.0, v.1, v.2));
                        if v < lints {
                            step.notes.push(format!(
                                "{} part checked without tool lints ({name} < {}.{}.{})",
                                product.as_str(),
                                lints.0,
                                lints.1,
                                lints.2
                            ));
                        }
                    }
                    None => step.notes.push(format!("couldn't read {name}'s version")),
                }
                match Command::new(&bin).args(["pack", "check"]).arg(dir).output() {
                    Ok(out) => {
                        indent(&mut step.notes, &out.stdout);
                        indent(&mut step.notes, &out.stderr);
                        if !out.status.success() {
                            step.problems
                                .push(format!("{name} pack check found problems (above)"));
                        }
                    }
                    Err(e) => step
                        .problems
                        .push(format!("couldn't run {}: {e}", bin.display())),
                }
                bins.push((name, bin));
            }
        }
        steps.push(step);
    }

    let mut step = Step::new("checks.toml");
    match load_checks(dir) {
        Ok(None) => step.notes.push("no checks.toml".into()),
        Ok(Some(c)) => step.problems = run_checks(dir, &m, &c),
        Err(e) => step.problems.push(e),
    }
    steps.push(step);

    let mut step = Step::new("build");
    match trial_build(dir) {
        Err(e) => step.problems.push(format!("doesn't build: {e}")),
        Ok((bundle, _scratch)) => {
            for (name, bin) in &bins {
                match Command::new(bin)
                    .args(["pack", "inspect"])
                    .arg(&bundle)
                    .arg("--allow-untrusted")
                    .output()
                {
                    Ok(o) if o.status.success() => {
                        step.notes.push(format!("{name} reads the built bundle"))
                    }
                    Ok(o) => {
                        indent(&mut step.notes, &o.stdout);
                        indent(&mut step.notes, &o.stderr);
                        step.problems
                            .push(format!("{name} can't read the built bundle"));
                    }
                    Err(e) => step
                        .problems
                        .push(format!("couldn't run {}: {e}", bin.display())),
                }
            }
        }
    }
    steps.push(step);
    steps
}

pub fn passed(steps: &[Step]) -> bool {
    steps.iter().all(|s| s.problems.is_empty())
}

pub fn render(steps: &[Step]) -> String {
    let mut out = String::new();
    for s in steps {
        let mark = if s.problems.is_empty() { "✓" } else { "✗" };
        out.push_str(&format!("{mark} {}\n", s.name));
        for n in &s.notes {
            out.push_str(&format!("    {n}\n"));
        }
        for p in &s.problems {
            out.push_str(&format!("  - {p}\n"));
        }
    }
    let count: usize = steps.iter().map(|s| s.problems.len()).sum();
    out.push_str(&if count == 0 {
        "The pack passes.\n".to_string()
    } else {
        format!(
            "{count} problem{} (above).\n",
            if count == 1 { "" } else { "s" }
        )
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_versions_from_version_lines() {
        assert_eq!(version_of("aivyx-pa 1.2.0"), Some((1, 2, 0)));
        assert_eq!(version_of("aivyx-coder v1.1.0\n"), Some((1, 1, 0)));
        assert_eq!(version_of("no version here"), None);
    }
}
