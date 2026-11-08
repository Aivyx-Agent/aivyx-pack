//! Format 2 — config packs: configuration only, no binaries, one file for
//! every platform. A pack has an aivyx-pa part (`[pa]`), an aivyx-coder part
//! (`[coder]`), or both; `products` lists which, and a part is present
//! exactly when its product is listed. Every path a part names stays inside
//! that part's folder (`pa/…`, `coder/…`).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{PackError, check_name, safe_relative, semverish};

/// The product a part is for.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    Pa,
    Coder,
}

impl Product {
    /// The part's folder and table name (`pa`, `coder`).
    pub fn as_str(self) -> &'static str {
        match self {
            Product::Pa => "pa",
            Product::Coder => "coder",
        }
    }
}

/// The aivyx-pa part: the template a new agent starts from, plus what it
/// brings and needs.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PaPart {
    /// Oldest aivyx-pa (`x.y.z`) that can install this part.
    pub min_version: String,
    /// The starter `aivyx-pa.toml`.
    pub template: String,
    /// A team config TOML.
    #[serde(default)]
    pub team_config: Option<String>,
    /// A folder of `<skill>/SKILL.md`.
    #[serde(default)]
    pub skills: Option<String>,
    /// Integrations the pack needs connected (`gmail`, `calendar`, …).
    #[serde(default)]
    pub requires: Vec<String>,
    /// Integrations the pack can use when connected.
    #[serde(default)]
    pub optional: Vec<String>,
}

/// The aivyx-coder part: a layer switched on per project.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CoderPart {
    /// Oldest aivyx-coder (`x.y.z`) that can install this part.
    pub min_version: String,
    /// Extra instructions, added on top of the user's own.
    pub agents_file: String,
    /// A folder of `<skill>/SKILL.md`.
    #[serde(default)]
    pub skills: Option<String>,
    /// A team roster TOML.
    #[serde(default)]
    pub roster: Option<String>,
    /// MCP server definitions (enabled only with the user's consent).
    #[serde(default)]
    pub mcp: Option<String>,
    /// `coder/settings.toml`: verification commands (format 2, coder 1.0.0+).
    #[serde(default)]
    pub settings: Option<String>,
}

/// `coder/settings.toml`: the only settings a pack may set.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CoderSettings {
    #[serde(default)]
    pub verification: PackVerification,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackVerification {
    pub command: Option<String>,
    pub scoped_command: Option<String>,
    #[serde(default)]
    pub final_checks: Vec<String>,
}

/// Parse a pack's `coder/settings.toml`: only `[verification]` commands, none empty.
pub fn check_coder_settings(text: &str) -> Result<CoderSettings, PackError> {
    let s: CoderSettings = toml::from_str(text).map_err(|e| bad(format!("settings: {e}")))?;
    let v = &s.verification;
    let empty = |c: &String| c.trim().is_empty();
    if v.command.iter().any(empty)
        || v.scoped_command.iter().any(empty)
        || v.final_checks.iter().any(empty)
    {
        return Err(bad("settings: empty command"));
    }
    let ctl = |c: &String| c.chars().any(char::is_control);
    if v.command.iter().any(ctl) || v.scoped_command.iter().any(ctl) || v.final_checks.iter().any(ctl) {
        return Err(bad("settings: command contains a control character"));
    }
    // Coder runs these without a shell (split at whitespace), so shell syntax
    // can never work; refuse it now. `{touched_paths}` is the one placeholder.
    const SHELL: &str = "&|;<>$`'\"(){}*?[]~#\\";
    for c in v.command.iter().chain(&v.scoped_command).chain(&v.final_checks) {
        for word in c.split_whitespace().filter(|w| *w != "{touched_paths}") {
            if let Some(ch) = word.chars().find(|ch| SHELL.contains(*ch)) {
                return Err(bad(format!(
                    "settings: command contains shell syntax (`{ch}`); pack commands run without a shell \u{2014} write one program and its arguments"
                )));
            }
        }
    }
    Ok(s)
}

/// A format-2 manifest.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigPackManifest {
    /// Always 2.
    pub format: u32,
    pub name: String,
    pub version: String,
    /// Publisher display label (informational; trust comes from keys).
    pub publisher: String,
    pub products: Vec<Product>,
    #[serde(default)]
    pub pa: Option<PaPart>,
    #[serde(default)]
    pub coder: Option<CoderPart>,
}

fn bad(msg: impl Into<String>) -> PackError {
    PackError::BadManifest(msg.into())
}

fn check_version(field: &str, v: &str) -> Result<(), PackError> {
    semverish(v)
        .map(|_| ())
        .ok_or_else(|| bad(format!("{field} {v:?} must be x.y.z")))
}

fn check_path(field: &str, path: &str, part: Product) -> Result<(), PackError> {
    let p = Path::new(path);
    // A file or folder *inside* the part's folder: at least two components.
    let inside = p.components().count() >= 2
        && p.components().next().is_some_and(|c| c.as_os_str() == part.as_str());
    if !safe_relative(p) || !inside {
        return Err(bad(format!(
            "{field} {path:?} must be a relative path inside {}/",
            part.as_str()
        )));
    }
    Ok(())
}

impl ConfigPackManifest {
    pub fn parse(text: &str) -> Result<Self, PackError> {
        let m: ConfigPackManifest = toml::from_str(text).map_err(|e| bad(e.to_string()))?;
        if m.format != 2 {
            return Err(bad(format!("format must be 2, not {}", m.format)));
        }
        check_name(&m.name)?;
        check_version("version", &m.version)?;
        if m.products.is_empty() {
            return Err(bad("products must list at least one of \"pa\", \"coder\""));
        }
        for (i, p) in m.products.iter().enumerate() {
            if m.products[..i].contains(p) {
                return Err(bad(format!("products lists {:?} twice", p.as_str())));
            }
        }
        for (product, present) in [(Product::Pa, m.pa.is_some()), (Product::Coder, m.coder.is_some())] {
            let listed = m.products.contains(&product);
            if listed != present {
                let name = product.as_str();
                return Err(bad(if listed {
                    format!("products lists {name:?} but there is no [{name}] part")
                } else {
                    format!("there is a [{name}] part but products doesn't list {name:?}")
                }));
            }
        }
        if let Some(pa) = &m.pa {
            check_version("pa.min_version", &pa.min_version)?;
        }
        if let Some(coder) = &m.coder {
            check_version("coder.min_version", &coder.min_version)?;
            if coder.settings.is_some()
                && semverish(&coder.min_version).is_some_and(|v| v < (1, 0, 0))
            {
                return Err(bad("coder.settings needs coder.min_version 1.0.0 or later"));
            }
        }
        for (field, path, part, _) in m.named_paths() {
            check_path(field, path, part)?;
        }
        Ok(m)
    }

    /// `(field, path, part, is_dir)` for every path the manifest names.
    fn named_paths(&self) -> Vec<(&'static str, &str, Product, bool)> {
        let mut out = Vec::new();
        if let Some(pa) = &self.pa {
            out.push(("pa.template", pa.template.as_str(), Product::Pa, false));
            if let Some(p) = &pa.team_config {
                out.push(("pa.team_config", p.as_str(), Product::Pa, false));
            }
            if let Some(p) = &pa.skills {
                out.push(("pa.skills", p.as_str(), Product::Pa, true));
            }
        }
        if let Some(coder) = &self.coder {
            out.push(("coder.agents_file", coder.agents_file.as_str(), Product::Coder, false));
            for (field, p, dir) in [
                ("coder.skills", &coder.skills, true),
                ("coder.roster", &coder.roster, false),
                ("coder.mcp", &coder.mcp, false),
                ("coder.settings", &coder.settings, false),
            ] {
                if let Some(p) = p {
                    out.push((field, p.as_str(), Product::Coder, dir));
                }
            }
        }
        out
    }

    /// `(field, path, is_dir)` for every path the manifest names — what a
    /// staging dir must hold before the pack is built.
    pub fn paths(&self) -> Vec<(&'static str, &str, bool)> {
        self.named_paths()
            .into_iter()
            .map(|(field, path, _, dir)| (field, path, dir))
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const BM: &str = r#"
format = 2
name = "business-manager"
version = "0.1.0"
publisher = "Aivyx"
products = ["pa", "coder"]

[pa]
min_version = "0.18.0"
template = "pa/aivyx-pa.toml"
team_config = "pa/team.toml"
skills = "pa/skills"
requires = ["gmail", "calendar"]
optional = ["notion"]

[coder]
min_version = "0.5.0"
agents_file = "coder/AGENTS.md"
skills = "coder/skills"
"#;

    #[test]
    fn parses_the_spec_example() {
        let m = ConfigPackManifest::parse(BM).unwrap();
        assert_eq!(m.products, vec![Product::Pa, Product::Coder]);
        assert_eq!(m.pa.as_ref().unwrap().requires, vec!["gmail", "calendar"]);
        assert_eq!(m.coder.as_ref().unwrap().agents_file, "coder/AGENTS.md");
        assert_eq!(m.paths().len(), 5);
    }

    #[test]
    fn a_part_must_match_the_products_list() {
        let only_pa = BM.replace(r#"products = ["pa", "coder"]"#, r#"products = ["pa"]"#);
        let err = ConfigPackManifest::parse(&only_pa).unwrap_err().to_string();
        assert!(err.contains("coder"), "{err}");
        let twice = BM.replace(r#"products = ["pa", "coder"]"#, r#"products = ["pa", "pa", "coder"]"#);
        assert!(ConfigPackManifest::parse(&twice).is_err());
    }

    #[test]
    fn paths_stay_inside_their_part() {
        for bad in ["../evil.toml", "/etc/passwd", "coder/AGENTS.md", "pa/../coder/x", "pa"] {
            let text = BM.replace(
                r#"template = "pa/aivyx-pa.toml""#,
                &format!("template = {bad:?}"),
            );
            assert!(ConfigPackManifest::parse(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn versions_must_be_x_y_z() {
        let text = BM.replace(r#"min_version = "0.18.0""#, r#"min_version = "latest""#);
        assert!(ConfigPackManifest::parse(&text).is_err());
    }

    #[test]
    fn unknown_keys_and_bad_names_are_refused() {
        let extra = BM.replace("publisher = \"Aivyx\"", "publisher = \"Aivyx\"\ntarget = \"x\"");
        assert!(ConfigPackManifest::parse(&extra).is_err());
        let name = BM.replace("business-manager", "../bm");
        assert!(ConfigPackManifest::parse(&name).is_err());
    }

    #[test]
    fn coder_settings_needs_min_version_1() {
        let text = BM
            .replace("min_version = \"0.5.0\"", "min_version = \"0.9.0\"")
            .replace(
                "agents_file = \"coder/AGENTS.md\"",
                "agents_file = \"coder/AGENTS.md\"\nsettings = \"coder/settings.toml\"",
            );
        let err = ConfigPackManifest::parse(&text).unwrap_err().to_string();
        assert!(err.contains("coder.settings needs coder.min_version 1.0.0 or later"), "{err}");
        let ok = text.replace("0.9.0", "1.0.0");
        assert!(ConfigPackManifest::parse(&ok).is_ok());
    }

    #[test]
    fn coder_settings_path_must_be_inside_coder() {
        let text = BM
            .replace("min_version = \"0.5.0\"", "min_version = \"1.0.0\"")
            .replace(
                "agents_file = \"coder/AGENTS.md\"",
                "agents_file = \"coder/AGENTS.md\"\nsettings = \"../x.toml\"",
            );
        assert!(ConfigPackManifest::parse(&text).is_err());
    }

    #[test]
    fn settings_file_allows_only_verification_commands() {
        let ok = "[verification]\ncommand = \"cargo test\"\nfinal_checks = [\"cargo fmt --check\"]\n";
        let s = check_coder_settings(ok).unwrap();
        assert_eq!(s.verification.command.as_deref(), Some("cargo test"));
        for bad in [
            "[backend]\nmodel = \"x\"\n",
            "[verification]\nfinal_check_retries = 5\n",
            "[permissions]\nmode = \"auto\"\n",
            "[verification]\ncommand = \"\"\n",
            "[verification]\nfinal_checks = [\"  \"]\n",
        ] {
            assert!(check_coder_settings(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_commands_refuse_control_characters() {
        for ch in ["\\n", "\\r", "\\u001b"] {
            for bad in [
                format!("[verification]\ncommand = \"a{ch}b\"\n"),
                format!("[verification]\nscoped_command = \"a{ch}b\"\n"),
                format!("[verification]\nfinal_checks = [\"ok\", \"a{ch}b\"]\n"),
            ] {
                let err = check_coder_settings(&bad).unwrap_err().to_string();
                assert!(err.contains("command contains a control character"), "{bad:?}: {err}");
            }
        }
    }

    #[test]
    fn coder_settings_version_compares_numerically() {
        let text = BM
            .replace("min_version = \"0.5.0\"", "min_version = \"0.10.0\"")
            .replace(
                "agents_file = \"coder/AGENTS.md\"",
                "agents_file = \"coder/AGENTS.md\"\nsettings = \"coder/settings.toml\"",
            );
        assert!(ConfigPackManifest::parse(&text).is_err());
    }

    #[test]
    fn settings_commands_refuse_shell_syntax() {
        for bad in [
            "cargo build && cargo test", "a | b", "x; y", "echo \\\"hi\\\"", "echo 'hi'",
            "echo $HOME", "ls *.rs", "a > b", "echo {touched_paths}x", "a #c",
        ] {
            let t = format!("[verification]\ncommand = \"{bad}\"\n");
            let err = check_coder_settings(&t).unwrap_err().to_string();
            assert!(err.contains("shell syntax"), "{bad}: {err}");
            let t = format!("[verification]\nfinal_checks = [\"{bad}\"]\n");
            assert!(check_coder_settings(&t).is_err(), "{bad}");
            let t = format!("[verification]\nscoped_command = \"{bad}\"\n");
            assert!(check_coder_settings(&t).is_err(), "{bad}");
        }
        for ok in [
            "cargo test", "cargo clippy --all-targets -- -D warnings", "cargo fmt --check",
            "rustfmt --check {touched_paths}",
        ] {
            let t = format!("[verification]\ncommand = \"{ok}\"\nscoped_command = \"{ok}\"\nfinal_checks = [\"{ok}\"]\n");
            check_coder_settings(&t).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
    }
}
