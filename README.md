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
# settings = "coder/settings.toml"   # needs min_version 1.0.0 or later
```

Every path stays inside its part's folder (`pa/…`, `coder/…`), and a part is
present exactly when its product is listed. Only the listed parts' folders
are packed.

`coder/settings.toml` may hold only a `[verification]` table (`command`,
`scoped_command`, `final_checks`). Coder asks the user before running any of
it, and runs each command without a shell: one program and its arguments,
split at whitespace. Shell syntax, quoting and control characters are
refused at build time; the only placeholder is the whole word
`{touched_paths}`.

## For publishers: the `aivyx-pack` command

```
aivyx-pack keygen <keyfile>                              # new signing key (secret, 0600)
aivyx-pack build <staging-dir> --key <keyfile> --out <file>
aivyx-pack build <staging-dir> --yubikey [--serial <serial>] --out <file>
aivyx-pack yubikey-init [--serial <serial>] [--overwrite-existing-key]   # put a pack key on a YubiKey
aivyx-pack inspect <file> [--trust <base64-key>]... [--allow-untrusted]
```

`build` checks the manifest and that every file it names exists before
signing. Users install packs with their product's own command
(`aivyx-pa pack install`, `aivyx-coder pack install`).

### Signing on a YubiKey

Build with `cargo build --release --features yubikey` (needs `libpcsclite`
to build and `pcscd` running to use). Then the publisher key can live only
in hardware, in the Signature slot of a YubiKey's OpenPGP applet:

- `yubikey-init` generates an Ed25519 key on the card and prints its
  verifying key. It refuses a card whose PINs are still the factory
  defaults or whose PIN retry counters are below maximum (it never changes
  a PIN). It refuses a card whose Signature slot already holds a key
  unless you pass `--overwrite-existing-key` and then type the card serial
  back. It sets the touch policy to fixed and ends by signing a test
  message and checking it; if that check fails (say, a mistyped User PIN),
  the card is re-keyed anyway, so it still prints the new verifying key and
  tells you to check the PIN retry counter with `gpg --card-status`.
- `build --yubikey` asks for the user PIN and signs on the card (touch it
  when asked). The signature is checked before the bundle is written, so a
  wrong card or a pulled card leaves no file.

A card has one Signature slot. A card that holds a pack key must hold only
that key: never put `aivyx-pa`'s federation identity key on the same card.
Without the feature, `--yubikey` and `yubikey-init` exit 2 and say so.

## Using the crate

Not on crates.io; consumers pin it by commit:

```toml
aivyx-pack = { git = "https://github.com/Aivyx-Agent/aivyx-pack", rev = "<sha>" }
```
