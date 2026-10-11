//! A plain-text description of a manifest, for `aivyx-pack inspect` and
//! the products' own `pack inspect`.

use crate::{Manifest, PackManifest};
use crate::config_pack::ConfigPackManifest;

/// Pack-supplied text as it may reach a terminal: control characters —
/// escape sequences that move the cursor or erase a line, newlines that
/// would forge one — shown escaped, so a pack can't disguise what the user
/// reads before installing it.
pub fn shown(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { c.escape_default().to_string() } else { c.to_string() })
        .collect()
}

/// One line saying what kind of pack this is: `tool pack for <target>` or
/// `config pack for pa, coder`.
pub fn kind(manifest: &Manifest) -> String {
    match manifest {
        Manifest::Binary(m) => format!("tool pack for {}", shown(&m.target)),
        Manifest::Config(m) => format!(
            "config pack for {}",
            m.products.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// Everything a user should see before installing.
pub fn describe(manifest: &Manifest) -> String {
    match manifest {
        Manifest::Binary(m) => describe_binary(m),
        Manifest::Config(m) => describe_config(m),
    }
}

fn describe_binary(m: &PackManifest) -> String {
    let mut out = format!(
        "pack:        {} v{}\npublisher:   {}\nkind:        tool pack\ntarget:      {}\nmin daemon:  {}\n",
        m.name,
        m.version,
        shown(&m.publisher),
        shown(&m.target),
        m.min_daemon_version
    );
    for tp in &m.tool_processes {
        out.push_str(&format!("tool process: {} (bin/{})\n", shown(&tp.name), shown(&tp.bin)));
    }
    if let Some(team) = &m.team_config {
        out.push_str(&format!("team config: config/{}\n", shown(team)));
    }
    out
}

fn list(items: &[String]) -> String {
    if items.is_empty() {
        "(none)".to_string()
    } else {
        items.iter().map(|i| shown(i)).collect::<Vec<_>>().join(", ")
    }
}

fn describe_config(m: &ConfigPackManifest) -> String {
    let mut out = format!(
        "pack:        {} v{}\npublisher:   {}\nkind:        config pack\n",
        m.name,
        m.version,
        shown(&m.publisher)
    );
    if let Some(pa) = &m.pa {
        out.push_str(&format!("\naivyx-pa part (needs aivyx-pa {} or later)\n", pa.min_version));
        out.push_str(&format!("  template:    {}\n", shown(&pa.template)));
        if let Some(p) = &pa.team_config {
            out.push_str(&format!("  team config: {}\n", shown(p)));
        }
        if let Some(p) = &pa.skills {
            out.push_str(&format!("  skills:      {}\n", shown(p)));
        }
        out.push_str(&format!("  requires: {}\n", list(&pa.requires)));
        out.push_str(&format!("  optional: {}\n", list(&pa.optional)));
    }
    if let Some(coder) = &m.coder {
        out.push_str(&format!(
            "\naivyx-coder part (needs aivyx-coder {} or later)\n",
            coder.min_version
        ));
        out.push_str(&format!("  instructions: {}\n", shown(&coder.agents_file)));
        for (label, p) in [("skills:      ", &coder.skills), ("roster:      ", &coder.roster), ("MCP servers: ", &coder.mcp)] {
            if let Some(p) = p {
                out.push_str(&format!("  {label} {}\n", shown(p)));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_pack::tests::BM;

    #[test]
    fn a_config_pack_lists_its_parts_and_needs() {
        let m = Manifest::parse(BM).unwrap();
        assert_eq!(kind(&m), "config pack for pa, coder");
        let text = describe(&m);
        assert!(text.contains("aivyx-pa part (needs aivyx-pa 0.18.0 or later)"), "{text}");
        assert!(text.contains("  requires: gmail, calendar\n"), "{text}");
        assert!(text.contains("  optional: notion\n"), "{text}");
        assert!(text.contains("  instructions: coder/AGENTS.md\n"), "{text}");
    }

    #[test]
    fn pack_text_cant_disguise_the_description() {
        // An escape sequence could erase a line before it's read, and a
        // newline could forge one ("kind: config pack" on a tool pack).
        let mut m: toml::Table = toml::from_str(BM).unwrap();
        m.insert(
            "publisher".into(),
            toml::Value::String("Aivyx\u{1b}[1A\u{1b}[2K\nkind:        trusted".into()),
        );
        let text = describe(&Manifest::parse(&toml::to_string(&m).unwrap()).unwrap());
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(!text.contains("\nkind:        trusted"), "{text}");
        assert!(text.contains("publisher:   Aivyx\\u{1b}[1A"), "{text}");
        assert_eq!(shown("plain text"), "plain text");
    }
}
