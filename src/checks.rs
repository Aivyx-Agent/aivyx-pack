//! `checks.toml`: a publisher's own promises about one config pack, such as
//! "nothing sends" or "exactly these nine skills". `aivyx-pack check` runs
//! them. The file sits at the pack's root, beside `manifest.toml`, and is
//! never put in a bundle (a bundle holds only the manifest and the product
//! folders). Each product's own `pack check` covers the general rules; these
//! are the pack's.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use crate::{CoderPart, ConfigPackManifest, PaPart};

/// The file, at the pack's root.
pub const CHECKS_FILE: &str = "checks.toml";

/// aivyx-pa's team tools: a member may hold them without a skill naming them.
pub const PA_TEAM_TOOLS: &[&str] = &[
    "decompose_task",
    "delegate_task",
    "query_agent",
    "verify_output",
    "synthesize_results",
    "send_message",
    "read_message",
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checks {
    /// Sections every skill must have: `When` means a `**When:**` line.
    #[serde(default)]
    pub sections: Vec<String>,
    pub pa: Option<PaChecks>,
    pub coder: Option<CoderChecks>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaChecks {
    /// Exactly these skills.
    pub skills: Option<Vec<String>>,
    /// In no allowlist, and named in no skill.
    #[serde(default)]
    pub forbid_tools: Vec<String>,
    /// The template's `[autonomy] level`.
    pub autonomy: Option<String>,
    /// Exactly these `[[autonomy.override]]` areas, each at `supervised`.
    pub supervised: Option<Vec<String>>,
    /// Every team member but the lead holds only tools named by the skills
    /// it `runs_on`, plus the team tools and `skill_defaults.*`.
    #[serde(default)]
    pub least_privilege: bool,
    /// Exactly these `[[schedule]]` routines.
    pub routine_names: Option<Vec<String>>,
    #[serde(default)]
    pub roles: BTreeMap<String, RoleChecks>,
    #[serde(default)]
    pub skill: BTreeMap<String, PaSkillChecks>,
    #[serde(default)]
    pub routines: BTreeMap<String, RoutineChecks>,
    pub team: Option<TeamChecks>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleChecks {
    /// In the role's `system_prompt`.
    #[serde(default)]
    pub mentions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaSkillChecks {
    /// Team members, or `role:<name>`, who between them hold every tool the
    /// skill names.
    #[serde(default)]
    pub runs_on: Vec<String>,
    #[serde(default)]
    pub mentions: Vec<String>,
    #[serde(default)]
    pub forbids: Vec<String>,
    /// Replaces the top-level `sections` for this skill.
    pub sections: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutineChecks {
    pub cron: Option<String>,
    /// A `team_mission` with a goal, no `prompt` or `role`, and no
    /// `pack_config` (it runs the installed team).
    #[serde(default)]
    pub team_mission: bool,
    /// In its goal (a team mission) or its prompt.
    #[serde(default)]
    pub mentions: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamChecks {
    pub name: Option<String>,
    pub lead: Option<String>,
    /// Exactly these members.
    pub members: Option<Vec<String>>,
    #[serde(default)]
    pub every_member_holds: Vec<String>,
    #[serde(default)]
    pub every_member_scopes: Vec<String>,
    #[serde(default)]
    pub member: BTreeMap<String, MemberChecks>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberChecks {
    /// At least these tools.
    #[serde(default)]
    pub holds: Vec<String>,
    /// At most these tools (the team tools are always allowed).
    pub holds_only: Option<Vec<String>>,
    #[serde(default)]
    pub forbid_tools: Vec<String>,
    /// For each scope base named here, exactly these scopes of that base.
    #[serde(default)]
    pub scopes_only: Vec<String>,
    #[serde(default)]
    pub forbid_scope_prefixes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoderChecks {
    /// Exactly these skills.
    pub skills: Option<Vec<String>>,
    /// Backticked in no skill's `**Steps:**` section.
    #[serde(default)]
    pub forbid_in_steps: Vec<String>,
    /// In `AGENTS.md`.
    #[serde(default)]
    pub agents_mentions: Vec<String>,
    #[serde(default)]
    pub skill: BTreeMap<String, CoderSkillChecks>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoderSkillChecks {
    #[serde(default)]
    pub mentions: Vec<String>,
    #[serde(default)]
    pub forbids: Vec<String>,
    pub sections: Option<Vec<String>>,
}

/// Read `<dir>/checks.toml`; `Ok(None)` when the pack has none.
pub fn load_checks(dir: &Path) -> Result<Option<Checks>, String> {
    let path = dir.join(CHECKS_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("can't read {CHECKS_FILE}: {e}"))?;
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| format!("{CHECKS_FILE}: {e}"))
}

/// Every broken promise, one line each; empty when all hold.
pub fn run_checks(dir: &Path, manifest: &ConfigPackManifest, checks: &Checks) -> Vec<String> {
    let mut p = Vec::new();
    match (&manifest.pa, &checks.pa) {
        (None, Some(_)) => {
            p.push("checks.toml has [pa] checks, but the pack has no aivyx-pa part".into())
        }
        (None, None) => {}
        (Some(part), c) => match PaView::load(dir, part) {
            Ok(view) => pa_rules(&view, c.as_ref(), &checks.sections, &mut p),
            Err(e) => p.push(e),
        },
    }
    match (&manifest.coder, &checks.coder) {
        (None, Some(_)) => {
            p.push("checks.toml has [coder] checks, but the pack has no aivyx-coder part".into())
        }
        (None, None) => {}
        (Some(part), c) => match CoderView::load(dir, part) {
            Ok(view) => coder_rules(&view, c.as_ref(), &checks.sections, &mut p),
            Err(e) => p.push(e),
        },
    }
    p
}

// ---- text ------------------------------------------------------------------

/// Lowercased, every run of whitespace one space.
fn norm(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn mentions(text: &str, needle: &str) -> bool {
    norm(text).contains(&norm(needle))
}

/// Whether `text` names `tool` as a whole name: `gmail.draft` matches
/// "use gmail.draft." but not "gmail.drafts" or "x.gmail.draft".
fn names_tool(text: &str, tool: &str) -> bool {
    let (text, tool) = (text.to_lowercase(), tool.to_lowercase());
    if tool.is_empty() {
        return false;
    }
    let part = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(i) = text[from..].find(&tool) {
        let start = from + i;
        let end = start + tool.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !(part(c) || c == '.'));
        let mut after = text[end..].chars();
        let after_ok = match after.next() {
            None => true,
            Some(c) if part(c) => false,
            Some('.') => !after.next().is_some_and(part),
            Some(_) => true,
        };
        if before_ok && after_ok {
            return true;
        }
        from = start + text[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

fn has_section(text: &str, name: &str) -> bool {
    text.contains(&format!("**{name}:**"))
}

/// The text between `**Steps:**` and `**Never:**` (or the end).
fn steps(text: &str) -> &str {
    let Some((_, rest)) = text.split_once("**Steps:**") else {
        return "";
    };
    rest.split_once("**Never:**").map_or(rest, |(s, _)| s)
}

fn text_rules(p: &mut Vec<String>, what: &str, text: &str, must: &[String], must_not: &[String]) {
    for m in must {
        if !mentions(text, m) {
            p.push(format!("{what} doesn't mention {m:?}"));
        }
    }
    for f in must_not {
        if mentions(text, f) {
            p.push(format!("{what} mentions {f:?}, which checks.toml forbids"));
        }
    }
}

fn section_rules(p: &mut Vec<String>, what: &str, text: &str, wanted: &[String]) {
    for s in wanted {
        if !has_section(text, s) {
            p.push(format!("{what} has no **{s}:** section"));
        }
    }
}

fn exact_set(
    p: &mut Vec<String>,
    what: &str,
    got: impl IntoIterator<Item = String>,
    want: &[String],
) {
    let got: BTreeSet<String> = got.into_iter().collect();
    let want: BTreeSet<String> = want.iter().cloned().collect();
    let missing: Vec<&String> = want.difference(&got).collect();
    let extra: Vec<&String> = got.difference(&want).collect();
    if !missing.is_empty() {
        p.push(format!("{what}: missing {missing:?}"));
    }
    if !extra.is_empty() {
        p.push(format!("{what}: not listed in checks.toml {extra:?}"));
    }
}

fn base(scope: &str) -> &str {
    scope.split(':').next().unwrap_or(scope)
}

// ---- reading the pack ------------------------------------------------------

fn read_toml(dir: &Path, rel: &str) -> Result<toml::Table, String> {
    let text =
        std::fs::read_to_string(dir.join(rel)).map_err(|e| format!("can't read {rel}: {e}"))?;
    text.parse::<toml::Table>()
        .map_err(|e| format!("{rel}: {e}"))
}

fn tables<'a>(t: &'a toml::Table, key: &str) -> Vec<&'a toml::Table> {
    t.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_table()).collect())
        .unwrap_or_default()
}

fn string(t: &toml::Table, key: &str) -> String {
    t.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn strings(t: &toml::Table, key: &str) -> Vec<String> {
    t.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// `<rel>/<name>/SKILL.md` for every skill folder, by name.
fn read_skills(dir: &Path, rel: Option<&str>) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let Some(rel) = rel else {
        return Ok(out);
    };
    let entries = std::fs::read_dir(dir.join(rel)).map_err(|e| format!("can't read {rel}: {e}"))?;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(String::from) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(entry.path().join("SKILL.md")) {
            out.insert(name, text);
        }
    }
    Ok(out)
}

/// A role or a team member: who holds which tools and scopes.
struct Holder {
    label: String,
    name: String,
    tools: Vec<String>,
    scopes: Vec<String>,
    prompt: String,
}

impl Holder {
    fn from(t: &toml::Table, kind: &str) -> Self {
        let name = string(t, "name");
        Holder {
            label: format!("{kind} `{name}`"),
            name,
            tools: strings(t, "tool_allowlist"),
            scopes: strings(t, "capability_scopes"),
            prompt: string(t, "system_prompt"),
        }
    }
}

struct Routine {
    name: String,
    cron: String,
    prompt: Option<String>,
    has_role: bool,
    goal: Option<String>,
    has_pack_config: bool,
}

struct Team {
    name: String,
    lead: String,
    members: Vec<Holder>,
}

struct PaView {
    roles: Vec<Holder>,
    team: Option<Team>,
    autonomy: Option<String>,
    overrides: Vec<(String, String)>,
    routines: Vec<Routine>,
    skills: BTreeMap<String, String>,
}

impl PaView {
    fn load(dir: &Path, part: &PaPart) -> Result<Self, String> {
        let template = read_toml(dir, &part.template)?;
        let roles = tables(&template, "role")
            .into_iter()
            .map(|t| Holder::from(t, "role"))
            .collect();
        let autonomy_table = template.get("autonomy").and_then(|v| v.as_table());
        let autonomy = autonomy_table
            .and_then(|a| a.get("level"))
            .and_then(|v| v.as_str())
            .map(String::from);
        let overrides = autonomy_table
            .map(|a| {
                tables(a, "override")
                    .into_iter()
                    .map(|o| (string(o, "domain"), string(o, "level")))
                    .collect()
            })
            .unwrap_or_default();
        let routines = tables(&template, "schedule")
            .into_iter()
            .map(|t| {
                let mission = t.get("team_mission").and_then(|v| v.as_table());
                Routine {
                    name: string(t, "name"),
                    cron: string(t, "cron"),
                    prompt: t.get("prompt").and_then(|v| v.as_str()).map(String::from),
                    has_role: t.contains_key("role"),
                    goal: mission
                        .and_then(|m| m.get("goal"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    has_pack_config: mission.is_some_and(|m| m.contains_key("pack_config")),
                }
            })
            .collect();
        let team = match &part.team_config {
            None => None,
            Some(rel) => {
                let doc = read_toml(dir, rel)?;
                let t = doc
                    .get("team")
                    .and_then(|v| v.as_table())
                    .ok_or(format!("{rel} has no [team] table"))?;
                Some(Team {
                    name: string(t, "name"),
                    lead: string(t, "lead"),
                    members: tables(t, "member")
                        .into_iter()
                        .map(|m| Holder::from(m, "team member"))
                        .collect(),
                })
            }
        };
        let skills = read_skills(dir, part.skills.as_deref())?;
        Ok(PaView {
            roles,
            team,
            autonomy,
            overrides,
            routines,
            skills,
        })
    }

    fn holders(&self) -> impl Iterator<Item = &Holder> {
        self.roles
            .iter()
            .chain(self.team.iter().flat_map(|t| t.members.iter()))
    }

    /// A team member by name, or a role as `role:<name>`.
    fn holder(&self, who: &str) -> Option<&Holder> {
        match who.strip_prefix("role:") {
            Some(role) => self.roles.iter().find(|r| r.name == role),
            None => self.team.as_ref()?.members.iter().find(|m| m.name == who),
        }
    }
}

struct CoderView {
    agents: String,
    skills: BTreeMap<String, String>,
}

impl CoderView {
    fn load(dir: &Path, part: &CoderPart) -> Result<Self, String> {
        let agents = std::fs::read_to_string(dir.join(&part.agents_file))
            .map_err(|e| format!("can't read {}: {e}", part.agents_file))?;
        Ok(CoderView {
            agents,
            skills: read_skills(dir, part.skills.as_deref())?,
        })
    }
}

// ---- the rules -------------------------------------------------------------

fn pa_rules(v: &PaView, c: Option<&PaChecks>, default_sections: &[String], p: &mut Vec<String>) {
    let none = PaChecks::default();
    let c = c.unwrap_or(&none);

    for (name, text) in &v.skills {
        let wanted = c
            .skill
            .get(name)
            .and_then(|s| s.sections.as_deref())
            .unwrap_or(default_sections);
        section_rules(p, &format!("pa skill `{name}`"), text, wanted);
    }
    if let Some(want) = &c.skills {
        exact_set(p, "pa skills", v.skills.keys().cloned(), want);
    }

    for h in v.holders() {
        for t in c.forbid_tools.iter().filter(|t| h.tools.contains(t)) {
            p.push(format!(
                "{} holds `{t}`, which checks.toml forbids",
                h.label
            ));
        }
    }
    for (name, text) in &v.skills {
        for t in c.forbid_tools.iter().filter(|t| names_tool(text, t)) {
            p.push(format!(
                "pa skill `{name}` names `{t}`, which checks.toml forbids"
            ));
        }
    }

    if let Some(want) = &c.autonomy {
        let got = v.autonomy.as_deref().unwrap_or("(not set)");
        if got != want {
            p.push(format!("the template's autonomy is `{got}`, not `{want}`"));
        }
    }
    if let Some(want) = &c.supervised {
        exact_set(
            p,
            "autonomy overrides",
            v.overrides.iter().map(|(d, _)| d.clone()),
            want,
        );
        for (d, level) in v.overrides.iter().filter(|(_, l)| l != "supervised") {
            p.push(format!(
                "the `{d}` autonomy override is `{level}`, not `supervised`"
            ));
        }
    }

    for (name, rc) in &c.roles {
        match v.roles.iter().find(|r| &r.name == name) {
            None => p.push(format!(
                "checks.toml names role `{name}`, which the template doesn't have"
            )),
            Some(r) => text_rules(
                p,
                &format!("role `{name}`'s prompt"),
                &r.prompt,
                &rc.mentions,
                &[],
            ),
        }
    }

    // The tool names a skill can be said to name: every tool the pack's
    // roles and members hold, plus the forbidden ones.
    let universe: BTreeSet<&str> = v
        .holders()
        .flat_map(|h| h.tools.iter().map(String::as_str))
        .chain(c.forbid_tools.iter().map(String::as_str))
        .collect();
    let named = |text: &str| -> BTreeSet<&str> {
        universe
            .iter()
            .copied()
            .filter(|t| names_tool(text, t))
            .collect()
    };

    for (name, sc) in &c.skill {
        let Some(text) = v.skills.get(name) else {
            p.push(format!(
                "checks.toml names pa skill `{name}`, which the pack doesn't have"
            ));
            continue;
        };
        text_rules(
            p,
            &format!("pa skill `{name}`"),
            text,
            &sc.mentions,
            &sc.forbids,
        );
        if sc.runs_on.is_empty() {
            continue;
        }
        let mut held: BTreeSet<&str> = BTreeSet::new();
        for who in &sc.runs_on {
            match v.holder(who) {
                Some(h) => held.extend(h.tools.iter().map(String::as_str)),
                None => p.push(format!(
                    "pa skill `{name}` runs_on `{who}`, which isn't a team member or `role:<name>`"
                )),
            }
        }
        let missing: Vec<&str> = named(text)
            .into_iter()
            .filter(|t| !held.contains(t))
            .collect();
        if !missing.is_empty() {
            p.push(format!(
                "pa skill `{name}` names {missing:?}, which {:?} don't hold",
                sc.runs_on
            ));
        }
    }

    if c.least_privilege {
        match &v.team {
            None => p.push("least_privilege is set, but the pack has no team".into()),
            Some(team) => {
                for m in team.members.iter().filter(|m| m.name != team.lead) {
                    let mut used: BTreeSet<&str> = PA_TEAM_TOOLS.iter().copied().collect();
                    for (skill, sc) in &c.skill {
                        if sc.runs_on.iter().any(|w| w == &m.name) {
                            if let Some(text) = v.skills.get(skill) {
                                used.extend(named(text));
                            }
                        }
                    }
                    let extra: Vec<&str> = m
                        .tools
                        .iter()
                        .map(String::as_str)
                        .filter(|t| !used.contains(t) && !t.starts_with("skill_defaults."))
                        .collect();
                    if !extra.is_empty() {
                        p.push(format!(
                            "{} holds {extra:?}, which no skill it runs names",
                            m.label
                        ));
                    }
                }
            }
        }
    }

    if let Some(want) = &c.routine_names {
        exact_set(
            p,
            "routines",
            v.routines.iter().map(|r| r.name.clone()),
            want,
        );
    }
    for (name, rc) in &c.routines {
        let Some(r) = v.routines.iter().find(|r| &r.name == name) else {
            p.push(format!(
                "checks.toml names routine `{name}`, which the template doesn't have"
            ));
            continue;
        };
        if let Some(cron) = rc.cron.as_ref().filter(|c| **c != r.cron) {
            p.push(format!(
                "routine `{name}` runs at `{}`, not `{cron}`",
                r.cron
            ));
        }
        if rc.team_mission {
            if r.goal.is_none() || r.prompt.is_some() || r.has_role {
                p.push(format!(
                    "routine `{name}` isn't a team mission (a team_mission goal, no prompt or role)"
                ));
            }
            if r.has_pack_config {
                p.push(format!("routine `{name}` sets team_mission.pack_config; it should run the installed team"));
            }
        }
        let body = r.goal.as_deref().or(r.prompt.as_deref()).unwrap_or("");
        text_rules(p, &format!("routine `{name}`"), body, &rc.mentions, &[]);
    }

    if let Some(tc) = &c.team {
        team_rules(v.team.as_ref(), tc, p);
    }
}

fn team_rules(team: Option<&Team>, tc: &TeamChecks, p: &mut Vec<String>) {
    let Some(team) = team else {
        p.push("checks.toml has [pa.team] checks, but the pack has no team config".into());
        return;
    };
    if let Some(n) = tc.name.as_ref().filter(|n| **n != team.name) {
        p.push(format!("the team is named `{}`, not `{n}`", team.name));
    }
    if let Some(l) = tc.lead.as_ref().filter(|l| **l != team.lead) {
        p.push(format!("the team's lead is `{}`, not `{l}`", team.lead));
    }
    if let Some(want) = &tc.members {
        exact_set(
            p,
            "team members",
            team.members.iter().map(|m| m.name.clone()),
            want,
        );
    }
    for m in &team.members {
        for t in tc
            .every_member_holds
            .iter()
            .filter(|t| !m.tools.contains(t))
        {
            p.push(format!("{} doesn't hold `{t}`", m.label));
        }
        for s in tc
            .every_member_scopes
            .iter()
            .filter(|s| !m.scopes.contains(s))
        {
            p.push(format!("{} doesn't have the `{s}` scope", m.label));
        }
    }
    for (name, mc) in &tc.member {
        let Some(m) = team.members.iter().find(|m| &m.name == name) else {
            p.push(format!(
                "checks.toml names team member `{name}`, which the team doesn't have"
            ));
            continue;
        };
        let missing: Vec<&String> = mc.holds.iter().filter(|t| !m.tools.contains(t)).collect();
        if !missing.is_empty() {
            p.push(format!("{} doesn't hold {missing:?}", m.label));
        }
        if let Some(only) = &mc.holds_only {
            let extra: Vec<&String> = m
                .tools
                .iter()
                .filter(|t| !only.contains(t) && !PA_TEAM_TOOLS.contains(&t.as_str()))
                .collect();
            if !extra.is_empty() {
                p.push(format!(
                    "{} holds {extra:?}, beyond its holds_only",
                    m.label
                ));
            }
        }
        for t in mc.forbid_tools.iter().filter(|t| m.tools.contains(t)) {
            p.push(format!(
                "{} holds `{t}`, which checks.toml forbids it",
                m.label
            ));
        }
        let bases: BTreeSet<&str> = mc.scopes_only.iter().map(|s| base(s)).collect();
        for b in bases {
            let got: BTreeSet<&str> = m
                .scopes
                .iter()
                .map(String::as_str)
                .filter(|s| base(s) == b)
                .collect();
            let want: BTreeSet<&str> = mc
                .scopes_only
                .iter()
                .map(String::as_str)
                .filter(|s| base(s) == b)
                .collect();
            if got != want {
                p.push(format!(
                    "{} has `{b}` scopes {got:?}, not {want:?}",
                    m.label
                ));
            }
        }
        for prefix in &mc.forbid_scope_prefixes {
            let bad: Vec<&String> = m
                .scopes
                .iter()
                .filter(|s| s.starts_with(prefix.as_str()))
                .collect();
            if !bad.is_empty() {
                p.push(format!(
                    "{} has {bad:?}, which checks.toml forbids ({prefix}*)",
                    m.label
                ));
            }
        }
    }
}

fn coder_rules(
    v: &CoderView,
    c: Option<&CoderChecks>,
    default_sections: &[String],
    p: &mut Vec<String>,
) {
    let none = CoderChecks::default();
    let c = c.unwrap_or(&none);
    for (name, text) in &v.skills {
        let wanted = c
            .skill
            .get(name)
            .and_then(|s| s.sections.as_deref())
            .unwrap_or(default_sections);
        section_rules(p, &format!("coder skill `{name}`"), text, wanted);
        for t in &c.forbid_in_steps {
            if steps(text).contains(&format!("`{t}`")) {
                p.push(format!(
                    "coder skill `{name}` uses `{t}` in its steps, which checks.toml forbids"
                ));
            }
        }
    }
    if let Some(want) = &c.skills {
        exact_set(p, "coder skills", v.skills.keys().cloned(), want);
    }
    text_rules(p, "AGENTS.md", &v.agents, &c.agents_mentions, &[]);
    for (name, sc) in &c.skill {
        match v.skills.get(name) {
            None => p.push(format!(
                "checks.toml names coder skill `{name}`, which the pack doesn't have"
            )),
            Some(text) => text_rules(
                p,
                &format!("coder skill `{name}`"),
                text,
                &sc.mentions,
                &sc.forbids,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const MANIFEST: &str = r#"format = 2
name = "demo"
version = "0.1.0"
publisher = "Aivyx"
products = ["pa", "coder"]

[pa]
min_version = "1.0.0"
template = "pa/aivyx-pa.toml"
team_config = "pa/team.toml"
skills = "pa/skills"

[coder]
min_version = "1.0.0"
agents_file = "coder/AGENTS.md"
skills = "coder/skills"
"#;

    const TEMPLATE: &str = r#"[[role]]
name = "default"
system_prompt = "Draft only; never send. Start from business-profile."
tool_allowlist = ["memory.read", "gmail.draft"]
capability_scopes = ["memory.read", "email.write"]

[autonomy]
level = "assisted"

[[autonomy.override]]
domain = "email"
level = "supervised"

[[schedule]]
name = "morning"
cron = "0 30 7 * * Mon-Fri"

[schedule.team_mission]
goal = "Read business-profile, then run `brief`; draft only."
"#;

    const TEAM: &str = r#"[team]
name = "demo"
lead = "lead"

[[team.member]]
name = "lead"
tool_allowlist = ["delegate_task", "memory.read"]
capability_scopes = ["team.delegate", "memory.read", "team.message"]

[[team.member]]
name = "inbox"
tool_allowlist = ["gmail.draft", "skill_defaults.read", "send_message"]
capability_scopes = ["email.write", "team.message", "memory.read:topic:leads*"]
"#;

    const PA_SKILL: &str = "---\nname: brief\ndescription: d\n---\n\n**When:** mornings.\n\n**Steps:**\n1. Inbox uses gmail.draft.\n\n**Never:** never send.\n";
    const CODER_SKILL: &str = "---\nname: tidy\ndescription: d\n---\n\n**When:** asked.\n\n**Steps:**\n1. Use `read_file`; say how to undo it.\n\n**Never:** push.\n";
    const AGENTS: &str = "Use plain language. Load `tidy` with `load_skill`.\n";

    const CHECKS: &str = r#"sections = ["When", "Steps", "Never"]

[pa]
skills = ["brief"]
forbid_tools = ["gmail.send"]
autonomy = "assisted"
supervised = ["email"]
least_privilege = true
routine_names = ["morning"]

[pa.roles.default]
mentions = ["never send", "business-profile"]

[pa.skill.brief]
runs_on = ["inbox"]
mentions = ["gmail.draft", "never send"]
forbids = ["gmail.send"]

[pa.routines.morning]
cron = "0 30 7 * * Mon-Fri"
team_mission = true
mentions = ["business-profile", "`brief`", "draft"]

[pa.team]
name = "demo"
lead = "lead"
members = ["lead", "inbox"]
every_member_scopes = ["team.message"]

[pa.team.member.lead]
holds = ["delegate_task", "memory.read"]
holds_only = ["memory.read"]

[pa.team.member.inbox]
holds = ["gmail.draft"]
forbid_tools = ["contacts.update"]
scopes_only = ["memory.read:topic:leads*"]
forbid_scope_prefixes = ["budget."]

[coder]
skills = ["tidy"]
forbid_in_steps = ["git_push"]
agents_mentions = ["plain language"]

[coder.skill.tidy]
mentions = ["how to undo"]
"#;

    fn pack(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aivyx-pack-checks-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for (rel, text) in [
            ("manifest.toml", MANIFEST),
            ("pa/aivyx-pa.toml", TEMPLATE),
            ("pa/team.toml", TEAM),
            ("pa/skills/brief/SKILL.md", PA_SKILL),
            ("coder/AGENTS.md", AGENTS),
            ("coder/skills/tidy/SKILL.md", CODER_SKILL),
            (CHECKS_FILE, CHECKS),
        ] {
            let path = dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn edit(dir: &Path, rel: &str, from: &str, to: &str) {
        let path = dir.join(rel);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(from), "{rel} has no {from:?}");
        std::fs::write(path, text.replacen(from, to, 1)).unwrap();
    }

    fn problems(dir: &Path) -> Vec<String> {
        let manifest =
            ConfigPackManifest::parse(&std::fs::read_to_string(dir.join("manifest.toml")).unwrap())
                .unwrap();
        let checks = load_checks(dir).unwrap().expect("has checks.toml");
        let out = run_checks(dir, &manifest, &checks);
        std::fs::remove_dir_all(dir).ok();
        out
    }

    /// Mutate a good pack and expect exactly one problem containing `want`.
    fn fails(tag: &str, rel: &str, from: &str, to: &str, want: &str) {
        let dir = pack(tag);
        edit(&dir, rel, from, to);
        let p = problems(&dir);
        assert!(
            p.iter().any(|l| l.contains(want)),
            "{tag}: wanted {want:?} in {p:#?}"
        );
    }

    #[test]
    fn a_pack_keeping_its_promises_passes() {
        assert_eq!(problems(&pack("good")), Vec::<String>::new());
    }

    #[test]
    fn unknown_keys_are_refused() {
        let dir = pack("unknown");
        edit(&dir, CHECKS_FILE, "least_privilege", "least_privelege");
        let err = load_checks(&dir).unwrap_err();
        std::fs::remove_dir_all(&dir).ok();
        assert!(err.contains("least_privelege"), "{err}");
    }

    #[test]
    fn no_checks_file_is_none() {
        let dir = pack("none");
        std::fs::remove_file(dir.join(CHECKS_FILE)).unwrap();
        assert!(load_checks(&dir).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn names_tool_matches_whole_names_only() {
        assert!(names_tool("Use gmail.draft.", "gmail.draft"));
        assert!(names_tool("`gmail.draft`", "gmail.draft"));
        assert!(!names_tool("gmail.drafts", "gmail.draft"));
        assert!(!names_tool("x.gmail.draft", "gmail.draft"));
        assert!(!names_tool("gmail.draft.more", "gmail.draft"));
    }

    #[test]
    fn mentions_ignores_case_and_line_wrapping() {
        assert!(mentions("Never\n   Send it", "never send"));
    }

    #[test]
    fn each_rule_catches_its_break() {
        fails(
            "section",
            "pa/skills/brief/SKILL.md",
            "**Never:**",
            "**Not:**",
            "no **Never:** section",
        );
        fails(
            "forbid-held",
            "pa/team.toml",
            "\"gmail.draft\", \"skill",
            "\"gmail.send\", \"gmail.draft\", \"skill",
            "holds `gmail.send`",
        );
        fails(
            "forbid-text",
            "pa/skills/brief/SKILL.md",
            "1. Inbox",
            "1. Never gmail.send; Inbox",
            "names `gmail.send`",
        );
        fails(
            "autonomy",
            "pa/aivyx-pa.toml",
            "level = \"assisted\"",
            "level = \"manual\"",
            "autonomy is `manual`",
        );
        fails(
            "supervised",
            "pa/aivyx-pa.toml",
            "level = \"supervised\"",
            "level = \"manual\"",
            "override is `manual`",
        );
        fails(
            "role",
            "pa/aivyx-pa.toml",
            "never send",
            "do send",
            "doesn't mention \"never send\"",
        );
        fails(
            "runs-on",
            "pa/skills/brief/SKILL.md",
            "1. Inbox",
            "1. Check memory.read; Inbox",
            "which [\"inbox\"] don't hold",
        );
        fails(
            "least",
            "pa/team.toml",
            "\"gmail.draft\", \"skill",
            "\"gmail.draft\", \"memory.read\", \"skill",
            "which no skill it runs names",
        );
        fails(
            "mentions",
            "pa/skills/brief/SKILL.md",
            "never send",
            "sometimes",
            "doesn't mention \"never send\"",
        );
        fails(
            "forbids",
            "pa/skills/brief/SKILL.md",
            "mornings",
            "mornings, maybe gmail.send",
            "forbids",
        );
        fails(
            "routine-cron",
            "pa/aivyx-pa.toml",
            "0 30 7",
            "0 0 9",
            "runs at `0 0 9",
        );
        fails(
            "routine-mission",
            "pa/aivyx-pa.toml",
            "cron = \"0 30 7 * * Mon-Fri\"",
            "cron = \"0 30 7 * * Mon-Fri\"\nprompt = \"x\"",
            "isn't a team mission",
        );
        fails(
            "routine-text",
            "pa/aivyx-pa.toml",
            "draft only",
            "send it",
            "doesn't mention \"draft\"",
        );
        fails(
            "routine-names",
            "pa/aivyx-pa.toml",
            "name = \"morning\"",
            "name = \"dawn\"",
            "routines: missing",
        );
        fails(
            "team-lead",
            "pa/team.toml",
            "lead = \"lead\"",
            "lead = \"inbox\"",
            "lead is `inbox`",
        );
        fails(
            "members",
            "pa/team.toml",
            "name = \"inbox\"",
            "name = \"post\"",
            "team members: missing",
        );
        fails(
            "every-scope",
            "pa/team.toml",
            "[\"email.write\", \"team.message\"",
            "[\"email.write\"",
            "doesn't have the `team.message` scope",
        );
        fails(
            "holds",
            "pa/team.toml",
            "[\"gmail.draft\", \"skill",
            "[\"skill",
            "doesn't hold [\"gmail.draft\"]",
        );
        fails(
            "holds-only",
            "pa/team.toml",
            "[\"delegate_task\", \"memory.read\"]",
            "[\"delegate_task\", \"memory.read\", \"web.search\"]",
            "beyond its holds_only",
        );
        fails(
            "member-forbid",
            "pa/team.toml",
            "\"send_message\"]",
            "\"send_message\", \"contacts.update\"]",
            "holds `contacts.update`",
        );
        fails(
            "scopes-only",
            "pa/team.toml",
            "memory.read:topic:leads*",
            "memory.read",
            "`memory.read` scopes",
        );
        fails(
            "scope-prefix",
            "pa/team.toml",
            "\"team.message\", \"memory",
            "\"team.message\", \"budget.read\", \"memory",
            "budget.",
        );
        fails(
            "coder-steps",
            "coder/skills/tidy/SKILL.md",
            "Use `read_file`",
            "Use `git_push`",
            "uses `git_push` in its steps",
        );
        fails(
            "agents",
            "coder/AGENTS.md",
            "plain language",
            "jargon",
            "AGENTS.md doesn't mention",
        );
        fails(
            "coder-mentions",
            "coder/skills/tidy/SKILL.md",
            "how to undo",
            "what",
            "doesn't mention \"how to undo\"",
        );
    }

    #[test]
    fn exact_skill_sets_catch_missing_and_extra() {
        let dir = pack("skill-set");
        let extra = dir.join("pa/skills/extra/SKILL.md");
        std::fs::create_dir_all(extra.parent().unwrap()).unwrap();
        std::fs::write(extra, PA_SKILL.replace("name: brief", "name: extra")).unwrap();
        std::fs::create_dir_all(dir.join("coder/skills/gone")).unwrap();
        std::fs::remove_dir_all(dir.join("coder/skills/tidy")).unwrap();
        let p = problems(&dir);
        assert!(
            p.iter()
                .any(|l| l.contains("pa skills: not listed in checks.toml [\"extra\"]")),
            "{p:#?}"
        );
        assert!(
            p.iter()
                .any(|l| l.contains("coder skills: missing [\"tidy\"]")),
            "{p:#?}"
        );
    }

    #[test]
    fn checks_for_a_missing_part_are_reported() {
        let dir = pack("no-coder");
        edit(
            &dir,
            "manifest.toml",
            "products = [\"pa\", \"coder\"]",
            "products = [\"pa\"]",
        );
        let text = std::fs::read_to_string(dir.join("manifest.toml")).unwrap();
        let cut = text.find("\n[coder]").unwrap();
        std::fs::write(dir.join("manifest.toml"), &text[..cut]).unwrap();
        let p = problems(&dir);
        assert!(
            p.iter().any(|l| l.contains("no aivyx-coder part")),
            "{p:#?}"
        );
    }
}
