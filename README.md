# aivyx-pack

The signed bundle format for **Aivyx vertical packs** — shared by
[aivyx-pa](https://github.com/Aivyx-Agent/aivyx-pa) and
[aivyx-coder](https://github.com/Aivyx-Agent/aivyx-coder), so both verify
and unpack packs with exactly the same code. A small library (build, sign,
verify, unpack) plus an `aivyx-pack` command for pack publishers.

Source-available under [BUSL-1.1](LICENSE) — free for personal and
non-commercial use; see [`COMMERCIAL.md`](COMMERCIAL.md).

## The bundle

A pack is one file, `<name>-<version>.aivyxpack`: a plain tar with exactly
three entries.

| Entry | What |
|---|---|
| `payload.tar.gz` | the signed unit: `manifest.toml` plus the pack's files |
| `signature.bin` | a 64-byte Ed25519 signature over the raw `payload.tar.gz` bytes |
| `publisher.txt` | the publisher's verifying key (base64) — only a selector: it must match a key the user already trusts |

The signature proves the pack is authentic and untampered; it is not DRM.
Unpacking refuses absolute paths, `..`, symlinks and hard links, and caps
both entry size and decompression ratio.

## Manifest formats

**Format 1 — tool packs** (aivyx-pa's original format; `format` absent or
`1`): tool-process binaries under `bin/`, team configs under `config/`, built
for one `target` platform.

**Format 2 — config packs**: configuration only, no binaries, one file for
every platform. A pack has an aivyx-pa part, an aivyx-coder part, or both:

```toml
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
requires = ["gmail", "calendar", "contacts", "drive", "toolkit"]
optional = ["notion"]

[coder]
min_version = "0.5.0"
agents_file = "coder/AGENTS.md"
skills = "coder/skills"
# roster = "coder/team.toml"
# mcp = "coder/mcp.toml"
```

Every path stays inside its part's folder (`pa/…`, `coder/…`), and a part is
present exactly when its product is listed. Only the listed parts' folders
are packed.

## For publishers: the `aivyx-pack` command

```
aivyx-pack keygen <keyfile>                              # new signing key (secret, 0600)
aivyx-pack build <staging-dir> --key <keyfile> --out <file>
aivyx-pack inspect <file> [--trust <base64-key>]... [--allow-untrusted]
```

`build` checks the manifest and that every file it names exists before
signing. Users install packs with their product's own command
(`aivyx-pa pack install`, `aivyx-coder pack install`).

## Using the crate

Not on crates.io; consumers pin it by commit:

```toml
aivyx-pack = { git = "https://github.com/Aivyx-Agent/aivyx-pack", rev = "<sha>" }
```
