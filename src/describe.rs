//! A plain-text description of a manifest, for `aivyx-pack inspect` and
//! the products' own `pack inspect`.

use crate::{Manifest, PackManifest};
use crate::config_pack::ConfigPackManifest;

/// One line saying what kind of pack this is: `tool pack for <target>` or
/// `config pack for pa, coder`.
pub fn kind(manifest: &Manifest) -> String {
    match manifest {
        Manifest::Binary(m) => format!("tool pack for {}", m.target),
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
        m.name, m.version, m.publisher, m.target, m.min_daemon_version
    );
    for tp in &m.tool_processes {
        out.push_str(&format!("tool process: {} (bin/{})\n", tp.name, tp.bin));
    }
    if let Some(team) = &m.team_config {
        out.push_str(&format!("team config: config/{team}\n"));
    }
    out
}

fn list(items: &[String]) -> String {
    if items.is_empty() { "(none)".to_string() } else { items.join(", ") }
}

fn describe_config(m: &ConfigPackManifest) -> String {
    let mut out = format!(
        "pack:        {} v{}\npublisher:   {}\nkind:        config pack\n",
        m.name, m.version, m.publisher
    );
    if let Some(pa) = &m.pa {
        out.push_str(&format!("\naivyx-pa part (needs aivyx-pa {} or later)\n", pa.min_version));
        out.push_str(&format!("  template:    {}\n", pa.template));
        if let Some(p) = &pa.team_config {
            out.push_str(&format!("  team config: {p}\n"));
        }
        if let Some(p) = &pa.skills {
            out.push_str(&format!("  skills:      {p}\n"));
        }
        out.push_str(&format!("  requires: {}\n", list(&pa.requires)));
        out.push_str(&format!("  optional: {}\n", list(&pa.optional)));
    }
    if let Some(coder) = &m.coder {
        out.push_str(&format!(
            "\naivyx-coder part (needs aivyx-coder {} or later)\n",
            coder.min_version
        ));
        out.push_str(&format!("  instructions: {}\n", coder.agents_file));
        for (label, p) in [("skills:      ", &coder.skills), ("roster:      ", &coder.roster), ("MCP servers: ", &coder.mcp)] {
            if let Some(p) = p {
                out.push_str(&format!("  {label} {p}\n"));
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
}
