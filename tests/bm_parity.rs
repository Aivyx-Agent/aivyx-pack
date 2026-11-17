//! Business Manager parity: for each Python test that the pack's
//! `checks.toml` and the products' lints replaced, a mutation the Python test
//! would have caught makes `aivyx-pack check` fail.
//!
//! The pack is private, so nothing of it is embedded here: the test copies it
//! from `AIVYX_BM_DIR` at run time and edits the copy.
//!
//! AIVYX_BM_DIR=<aivyx-verticals>/packs/business-manager AIVYX_PA=<bin> AIVYX_CODER=<bin> \
//!   cargo test --test bm_parity -- --ignored
//!
//! Three Python tests have no row, on purpose:
//! - `test_identity_and_integrations` and `test_both_products_and_the_coder_part`
//!   pinned manifest values; the format check validates the manifest now.
//! - `test_each_step_names_only_tools_its_specialist_holds` was a sentence
//!   heuristic; `least_privilege` and the tool lints cover what it was after.
//!
//! Every mutation replaces all occurrences of its `from` text, so a promise
//! that a pack states in several places is broken everywhere.

use std::path::{Path, PathBuf};

use aivyx_pack::check::{CheckOptions, check_dir, render};

fn copy(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let (from, to) = (e.path(), dst.join(e.file_name()));
        if from.is_dir() {
            if e.file_name() != "tests" && e.file_name() != "__pycache__" {
                copy(&from, &to);
            }
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

fn fresh(tag: &str) -> PathBuf {
    let bm = PathBuf::from(std::env::var("AIVYX_BM_DIR").expect("set AIVYX_BM_DIR"));
    let dir = std::env::temp_dir().join(format!("aivyx-bm-parity-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    copy(&bm, &dir);
    dir
}

/// Replace every `from` in `rel` (which must contain it).
fn edit(dir: &Path, rel: &str, from: &str, to: &str) {
    let path = dir.join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "{rel} has no {from:?}");
    std::fs::write(path, text.replace(from, to)).unwrap();
}

/// Write a well-formed extra skill folder at `rel` (relative to the pack).
fn add_skill(dir: &Path, rel: &str) {
    let skill = dir.join(rel).join("extra");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        "---\nname: extra\ndescription: An extra skill.\n---\n\n# Extra\n\n**When:** never.\n\n**Steps:**\n1. Nothing.\n\n**Never:** anything.\n",
    )
    .unwrap();
}

fn problems(dir: &Path) -> String {
    let steps = check_dir(
        dir,
        &CheckOptions {
            allow_unchecked: false,
        },
    );
    let text = render(&steps);
    let _ = std::fs::remove_dir_all(dir);
    text
}

#[test]
#[ignore = "needs AIVYX_BM_DIR, AIVYX_PA and AIVYX_CODER"]
fn the_unmodified_pack_passes() {
    let text = problems(&fresh("clean"));
    assert!(text.contains("The pack passes."), "{text}");
}

#[test]
#[ignore = "needs AIVYX_BM_DIR, AIVYX_PA and AIVYX_CODER"]
fn an_extra_pa_skill_is_a_problem() {
    // test_exactly_these_nine
    let dir = fresh("pa-extra");
    add_skill(&dir, "pa/skills");
    let text = problems(&dir);
    assert!(
        text.contains("pa skills: not listed in checks.toml [\"extra\"]"),
        "{text}"
    );
}

#[test]
#[ignore = "needs AIVYX_BM_DIR, AIVYX_PA and AIVYX_CODER"]
fn an_extra_coder_skill_is_a_problem() {
    // test_exactly_these_four (coder)
    let dir = fresh("coder-extra");
    add_skill(&dir, "coder/skills");
    let text = problems(&dir);
    assert!(
        text.contains("coder skills: not listed in checks.toml [\"extra\"]"),
        "{text}"
    );
}

const TEAM: &str = "pa/team.toml";
const PA: &str = "pa/aivyx-pa.toml";

/// `(python test, file, edits as (from, to), expected problem text)`.
type Case = (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
);

const CASES: &[Case] = &[
    (
        "test_shape (pa)",
        "pa/skills/weekly-review/SKILL.md",
        &[("**Never:**", "**Not:**")],
        "no **Never:** section",
    ),
    (
        "test_outgoing_skills_are_drafts_only",
        "pa/skills/inbox-triage/SKILL.md",
        &[("never send", "maybe send")],
        "doesn't mention \"never send\"",
    ),
    (
        "test_no_skill_tells_the_agent_to_use_a_forbidden_tool",
        "pa/skills/invoice-chase/SKILL.md",
        &[(
            "5. Report a table",
            "5. Use gmail.send, then report a table",
        )],
        "names `gmail.send`",
    ),
    (
        "test_every_skill_starts_from_the_profile",
        "pa/skills/cash-summary/SKILL.md",
        &[("business-profile", "the-profile")],
        "doesn't mention \"business-profile\"",
    ),
    (
        "test_who_runs_each_skill_holds_every_tool_it_names",
        "pa/skills/weekly-review/SKILL.md",
        &[("2. `task.list`:", "2. `budget.record`, `task.list`:")],
        "don't hold",
    ),
    (
        "test_each_specialist_holds_only_tools_its_steps_name",
        TEAM,
        &[
            (
                "\"budget.categories\", \"drive.search\",",
                "\"budget.categories\", \"web.search\", \"drive.search\",",
            ),
            (
                "\"budget.read\", \"drive.read\",",
                "\"budget.read\", \"web.search\", \"drive.read\",",
            ),
        ],
        "which no skill it runs names",
    ),
    (
        "test_tender_watch_calendar_events_invite_nobody",
        "pa/skills/tender-watch/SKILL.md",
        &[("no attendees", "attendees")],
        "\"no attendees\"",
    ),
    (
        "test_leads_and_tenders_have_their_own_topics",
        "pa/skills/lead-research/SKILL.md",
        &[("topic `leads`", "topic `notes`")],
        "\"topic `leads`\"",
    ),
    (
        "test_exactly_these_five_at_these_times",
        PA,
        &[("0 30 7 * * Mon-Fri", "0 30 8 * * Mon-Fri")],
        "runs at",
    ),
    (
        "test_each_is_a_team_mission_that_reads_the_profile_and_its_skills",
        PA,
        &[("`cash-summary` skill", "cash skill")],
        "doesn't mention \"`cash-summary`\"",
    ),
    (
        "test_shape (team)",
        TEAM,
        &[("lead = \"manager\"", "lead = \"books\"")],
        "lead is `books`",
    ),
    (
        "test_the_manager_delegates_and_reads_only",
        TEAM,
        &[
            (
                "\"send_message\", \"read_message\",",
                "\"send_message\", \"read_message\", \"web.search\",",
            ),
            (
                "\"team.delegate\", \"team.message\",",
                "\"team.delegate\", \"team.message\", \"web.search\",",
            ),
        ],
        "beyond its holds_only",
    ),
    (
        "test_each_specialist_owns_its_area",
        TEAM,
        &[
            (
                "\"gmail.read\", \"gmail.draft\", \"calendar.upcoming\"",
                "\"gmail.read\", \"calendar.upcoming\"",
            ),
            (
                "\"email.read\", \"email.write\", \"calendar.read\"",
                "\"email.read\", \"calendar.read\"",
            ),
        ],
        "doesn't hold",
    ),
    (
        "test_scout_memory_is_limited_to_its_topics",
        TEAM,
        &[("\"memory.read:topic:leads*\",", "\"memory.read\",")],
        "`memory.read` scopes",
    ),
    (
        "test_only_customers_and_operations_change_records",
        TEAM,
        &[
            (
                "\"drive.recent_files\", \"calc.eval\",",
                "\"drive.recent_files\", \"task.create\", \"calc.eval\",",
            ),
            (
                "\"budget.read\", \"drive.read\",",
                "\"budget.read\", \"task.write\", \"drive.read\",",
            ),
        ],
        "holds `task.create`",
    ),
    (
        "test_every_member_reads_its_skills_and_talks_to_the_team",
        TEAM,
        &[(
            "\"calendar.upcoming\", \"memory.read\", \"skill_defaults.read\",",
            "\"calendar.upcoming\", \"memory.read\",",
        )],
        "doesn't hold `skill_defaults.read`",
    ),
    (
        "test_assisted_with_outgoing_areas_supervised",
        PA,
        &[(
            "domain = \"email\"\nlevel = \"supervised\"",
            "domain = \"email\"\nlevel = \"manual\"",
        )],
        "override is `manual`",
    ),
    (
        "test_nothing_sends_or_destroys",
        TEAM,
        &[(
            "\"gmail.draft\", \"contacts.search\"",
            "\"gmail.draft\", \"gmail.send\", \"contacts.search\"",
        )],
        "holds `gmail.send`",
    ),
    (
        "test_every_tool_has_its_scope",
        TEAM,
        &[(
            "\"email.read\", \"email.write\", \"calendar.read\"",
            "\"email.read\", \"calendar.read\"",
        )],
        "not the `email.write` scope",
    ),
    (
        "test_no_scope_without_a_tool_that_needs_it",
        TEAM,
        &[(
            "\"web.search\", \"net.fetch\", \"memory.read:topic:business-profile*\"",
            "\"web.search\", \"net.fetch\", \"budget.read\", \"memory.read:topic:business-profile*\"",
        )],
        "none of its tools needs it",
    ),
    (
        "test_template_keeps_integration_writes_gated",
        PA,
        &[(
            "trust_ceiling = \"Trusted\"\n\n# Autonomy",
            "trust_ceiling = \"Trusted\"\n\n[access]\nconfirm_destructive = false\n\n# Autonomy",
        )],
        "[access]",
    ),
    (
        "test_default_role_says_drafts_only",
        PA,
        &[("you never send email", "you send email")],
        "prompt doesn't mention \"never send\"",
    ),
    (
        "test_the_four_rules",
        "coder/AGENTS.md",
        &[("Plain language.", "Jargon.")],
        "AGENTS.md doesn't mention \"plain language\"",
    ),
    (
        "test_agents_md_points_to_each_skill",
        "coder/AGENTS.md",
        &[("`data-cleanup`", "the last one")],
        "doesn't name the pack's skill `data-cleanup`",
    ),
    (
        "test_shape (coder)",
        "coder/skills/website-update/SKILL.md",
        &[("**When:**", "**If:**")],
        "no **When:** section",
    ),
    (
        "test_every_tool_named_exists_in_aivyx_coder",
        "coder/skills/website-update/SKILL.md",
        &[("`read_file`", "`read_fil`")],
        "isn't an aivyx-coder tool",
    ),
    (
        "test_steps_leave_publishing_and_deleting_to_the_owner",
        "coder/skills/website-update/SKILL.md",
        &[(
            "2. `read_file` the page",
            "2. `git_push`, then `read_file` the page",
        )],
        "uses `git_push` in its steps",
    ),
    (
        "test_every_skill_gives_a_concrete_undo",
        "coder/skills/data-cleanup/SKILL.md",
        &[("Say how to undo it", "Say what changed")],
        "doesn't mention \"say how to undo it\"",
    ),
    (
        "test_no_skill_reads_a_whole_data_file_blind",
        "coder/skills/data-cleanup/SKILL.md",
        &[("head -n 20", "cat")],
        "\"head -n 20\"",
    ),
];

#[test]
#[ignore = "needs AIVYX_BM_DIR, AIVYX_PA and AIVYX_CODER"]
fn every_replaced_python_test_has_a_failing_case() {
    assert!(!CASES.is_empty());
    let mut failures = Vec::new();
    for (i, (test, rel, edits, want)) in CASES.iter().enumerate() {
        let dir = fresh(&format!("case{i}"));
        for (from, to) in *edits {
            edit(&dir, rel, from, to);
        }
        let text = problems(&dir);
        if !text.contains(want) {
            failures.push(format!("{test}: wanted {want:?} in:\n{text}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
