//! `aivyx-pack new <dir>`: a new config pack from the built-in templates,
//! with a manifest and a starter `checks.toml`, ready for `check`.

use std::path::Path;

use crate::checks::CHECKS_FILE;
use crate::{ConfigPackManifest, Product};

pub struct NewOptions {
    pub name: String,
    pub products: Vec<Product>,
    pub publisher: String,
    pub requires: Vec<String>,
    pub optional: Vec<String>,
}

const PA_FILES: &[(&str, &str)] = &[
    (
        "pa/aivyx-pa.toml",
        include_str!("../templates/pa/aivyx-pa.toml"),
    ),
    ("pa/team.toml", include_str!("../templates/pa/team.toml")),
    (
        "pa/skills/example/SKILL.md",
        include_str!("../templates/pa/skills/example/SKILL.md"),
    ),
];

const CODER_FILES: &[(&str, &str)] = &[
    (
        "coder/AGENTS.md",
        include_str!("../templates/coder/AGENTS.md"),
    ),
    (
        "coder/mcp.example.toml",
        include_str!("../templates/coder/mcp.example.toml"),
    ),
    (
        "coder/team.example.toml",
        include_str!("../templates/coder/team.example.toml"),
    ),
    (
        "coder/skills/example/SKILL.md",
        include_str!("../templates/coder/skills/example/SKILL.md"),
    ),
];

/// A TOML string literal.
fn quoted(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn list(v: &[String]) -> String {
    format!(
        "[{}]",
        v.iter().map(|s| quoted(s)).collect::<Vec<_>>().join(", ")
    )
}

fn manifest_text(o: &NewOptions) -> String {
    let products: Vec<String> = o.products.iter().map(|p| p.as_str().to_string()).collect();
    let mut t = format!(
        "# A config pack (format 2). Bump `version` for every release.\n\
         format = 2\nname = {}\nversion = \"0.1.0\"\npublisher = {}\nproducts = {}\n",
        quoted(&o.name),
        quoted(&o.publisher),
        list(&products)
    );
    if o.products.contains(&Product::Pa) {
        t.push_str(&format!(
            "\n[pa]\n# The oldest aivyx-pa that can install this pack.\nmin_version = \"1.0.0\"\n\
             template = \"pa/aivyx-pa.toml\"\nteam_config = \"pa/team.toml\"\nskills = \"pa/skills\"\n\
             # Integrations the pack needs, and ones it can use. Known names: gmail,\n\
             # calendar, drive, contacts (set up with `aivyx-pa connect`), and notion,\n\
             # obsidian, n8n, toolkit, vision (tool processes).\nrequires = {}\noptional = {}\n",
            list(&o.requires),
            list(&o.optional)
        ));
    }
    if o.products.contains(&Product::Coder) {
        t.push_str(
            "\n[coder]\n# The oldest aivyx-coder that can install this pack.\nmin_version = \"1.0.0\"\n\
             agents_file = \"coder/AGENTS.md\"\nskills = \"coder/skills\"\n\
             # roster = \"coder/team.toml\"   rename team.example.toml and uncomment to ship a roster\n\
             # mcp = \"coder/mcp.toml\"       rename mcp.example.toml and uncomment to ship MCP servers\n",
        );
    }
    t
}

fn checks_text(o: &NewOptions) -> String {
    let mut t = String::from(
        "# What this pack promises, checked by `aivyx-pack check`. Never shipped in\n\
         # the bundle. Every key is optional; the aivyx-pack README lists each rule.\n\
         sections = [\"When\", \"Steps\", \"Never\"]\n",
    );
    if o.products.contains(&Product::Pa) {
        t.push_str(
            "\n[pa]\nskills = [\"example\"]\n\
             # forbid_tools = [\"gmail.send\", \"fs.delete\"]\n\
             # autonomy = \"assisted\"\n# supervised = [\"fs\"]\n# least_privilege = true\n\
             # routine_names = [\"weekly-review\"]\n\
             #\n# [pa.roles.default]\n# mentions = [\"never send\"]\n\
             #\n# [pa.skill.example]\n# runs_on = [\"role:default\"]\n# mentions = [\"...\"]\n# forbids = [\"...\"]\n\
             #\n# [pa.routines.weekly-review]\n# cron = \"0 0 16 * * Fri\"\n# team_mission = true\n# mentions = [\"...\"]\n\
             #\n# [pa.team]\n# lead = \"lead\"\n# members = [\"lead\", \"researcher\", \"writer\"]\n\
             # every_member_holds = [\"skill_defaults.read\"]\n# every_member_scopes = [\"team.message\"]\n\
             #\n# [pa.team.member.researcher]\n# holds = [\"web.fetch\"]\n# holds_only = [\"web.fetch\", \"memory.read\"]\n\
             # forbid_tools = [\"memory.write\"]\n# scopes_only = [\"memory.read\"]\n# forbid_scope_prefixes = [\"email.\"]\n",
        );
    }
    if o.products.contains(&Product::Coder) {
        t.push_str(
            "\n[coder]\nskills = [\"example\"]\n\
             # forbid_in_steps = [\"git_push\", \"delete_file\"]\n# agents_mentions = [\"plain language\"]\n\
             #\n# [coder.skill.example]\n# mentions = [\"...\"]\n# forbids = [\"...\"]\n",
        );
    }
    t
}

fn write(dir: &Path, rel: &str, text: &str) -> Result<(), String> {
    let path = dir.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("can't create {}: {e}", parent.display()))?;
    }
    std::fs::write(&path, text).map_err(|e| format!("can't write {}: {e}", path.display()))
}

pub fn scaffold(dir: &Path, o: &NewOptions) -> Result<(), String> {
    if o.products.is_empty() {
        return Err("a pack needs at least one of pa, coder".into());
    }
    if dir.exists() {
        let mut entries =
            std::fs::read_dir(dir).map_err(|e| format!("can't read {}: {e}", dir.display()))?;
        if entries.next().is_some() {
            return Err(format!(
                "{} isn't empty; `new` only writes into a new or empty folder",
                dir.display()
            ));
        }
    }
    let manifest = manifest_text(o);
    ConfigPackManifest::parse(&manifest).map_err(|e| e.to_string())?;
    write(dir, "manifest.toml", &manifest)?;
    write(dir, CHECKS_FILE, &checks_text(o))?;
    if o.products.contains(&Product::Pa) {
        for (rel, text) in PA_FILES {
            write(dir, rel, text)?;
        }
    }
    if o.products.contains(&Product::Coder) {
        for (rel, text) in CODER_FILES {
            write(dir, rel, text)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(products: Vec<Product>) -> NewOptions {
        NewOptions {
            name: "my-pack".into(),
            products,
            publisher: "Aivyx".into(),
            requires: vec!["gmail".into()],
            optional: vec![],
        }
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aivyx-pack-new-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn writes_a_pack_whose_promises_hold() {
        for (tag, products) in [
            ("both", vec![Product::Pa, Product::Coder]),
            ("pa", vec![Product::Pa]),
            ("coder", vec![Product::Coder]),
        ] {
            let dir = tmp(tag);
            scaffold(&dir, &opts(products)).unwrap();
            let manifest = ConfigPackManifest::parse(
                &std::fs::read_to_string(dir.join("manifest.toml")).unwrap(),
            )
            .unwrap();
            let checks = crate::checks::load_checks(&dir).unwrap().unwrap();
            assert_eq!(
                crate::checks::run_checks(&dir, &manifest, &checks),
                Vec::<String>::new(),
                "{tag}"
            );
            crate::build_payload(&dir).unwrap();
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn refuses_a_non_empty_folder() {
        let dir = tmp("busy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("x"), "x").unwrap();
        let err = scaffold(&dir, &opts(vec![Product::Pa])).unwrap_err();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("isn't empty"), "{err}");
    }

    #[test]
    fn refuses_a_bad_name() {
        let dir = tmp("bad-name");
        let mut o = opts(vec![Product::Pa]);
        o.name = "Bad Name!".into();
        assert!(scaffold(&dir, &o).is_err());
        assert!(!dir.join("manifest.toml").exists());
    }
}
