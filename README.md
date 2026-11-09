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
aivyx-pack hub-check <hub-public-dir> [--trust <base64-key>]... [--allow-placeholders]
                     [--require-signature] [--site-dist <dir>]
aivyx-pack hub-sign <hub-public-dir> --key <keyfile>
aivyx-pack hub-sign <hub-public-dir> --yubikey [--serial <serial>]
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

## The Hub: `hub-check` and `hub-sign`

The Aivyx Hub serves packs from a public folder laid out like this:

```
publisher-key.txt          # the publisher's verifying keys
packs/index.json           # the manifest, schema 2
packs/index.json.sig       # its detached signature (optional until required)
packs/<name>-<version>.aivyxpack
```

`packs/index.json` (the `aivyx_pack::hub` module holds its types; unknown
fields are refused):

```json
{
  "schema_version": 2,
  "packs": [
    {
      "name": "business-manager",
      "display_name": "Business Manager",
      "version": "0.1.0",
      "description": "…",
      "license": "free",
      "format": 2,
      "products": ["pa", "coder"],
      "min_version": { "pa": "1.0.0", "coder": "1.0.0" },
      "file": "business-manager-0.1.0.aivyxpack",
      "size": 12345,
      "sha256": "<64 lowercase hex>"
    }
  ]
}
```

- `file` is a plain file name, exactly `<name>-<version>.aivyxpack`, next to
  `index.json`: a client fetches the manifest's URL directory plus `file`.
  There is no download URL.
- `min_version` has a key for each product in `products`, and no other.
- A format 1 entry has `"products": ["pa"]` and, instead of `file`, `size`
  and `sha256`, a `targets` list of `{ "target", "file", "size", "sha256" }`
  with `file` = `<name>-<version>-<target>.aivyxpack`.

`publisher-key.txt` holds `#` comment lines (say which card holds each key),
blank lines, and one base64 Ed25519 verifying key per other line:

```
# primary — YubiKey serial <serial>
<base64 verifying key>
# backup — YubiKey serial <serial>, sealed
<base64 verifying key>
```

**`hub-check <dir>`** exits 1 and prints one line per problem, each starting
with `✗`, or ends with `✓ hub ok: N packs` (`, index signed` when the
signature verified). It checks that:

- the manifest parses as schema 2, with no key given twice anywhere, and
  every field is well formed;
- no value in it is a placeholder: a string starting with `PLACEHOLDER`
  (exact case; prose that mentions the word is fine);
- each listed bundle exists, has the listed size and sha256, is signed by a
  built-in publisher key (`AIVYX_PUBLISHER_KEYS`; `--trust` adds one), and
  its signed manifest agrees with the entry on name, version, format,
  products and each `min_version` (and target, for format 1). The bundle is
  read once, and size, hash and signature are all checked on those bytes;
- every `.aivyxpack` in `packs/` (any case) is listed, and `packs/` has no
  subfolders;
- `publisher-key.txt` has at least one key, every key line is a valid key,
  and, once `AIVYX_PUBLISHER_KEYS` is filled, its keys are exactly that list;
- `packs/index.json.sig`, if present, verifies (strict Ed25519) against a
  key in `publisher-key.txt`. `--require-signature` makes its absence a
  problem.

`--allow-placeholders` turns placeholders into `! warning:` lines, for
pre-launch builds. A placeholder excuses only its own field: every other
check still runs, and a bundle with a real `file` is always checked (a
placeholder `sha256` skips only the hash comparison). A placeholder `publisher-key.txt` (a non-comment line starting with
`PLACEHOLDER`) is accepted only while `AIVYX_PUBLISHER_KEYS` is empty.

`--site-dist <dir>` also scans every `.html`, `.htm`, `.xhtml` and `.svg`
file under the built site (often the same folder) for what the Hub's
Content-Security-Policy (`script-src 'self'; style-src 'self'`) would break
and for leaks. A folder with no such file fails. It flags:

- a `<script>` without a `src` (or with an empty one), of any type; a
  non-JavaScript type, such as JSON-LD, is reported as an inline data
  script to serve as a file;
- a `<style>` element or a `style="…"` attribute;
- an inline event handler attribute (`onclick=` and the like), and a
  `javascript:` URL in a URL attribute (`href`, `src`, `action`,
  `formaction`, `xlink:href`, `data`, `poster`, `cite`, `background`,
  `srcset`);
- any link to `github.com/Aivyx-Agent/<private repo>` or
  `raw.githubusercontent.com/Aivyx-Agent/<private repo>`, in an attribute,
  in text, or in a script or style body. The private repos are aivyx-hub,
  aivyx-verticals, aivyx-ecosystem, aivyx-website, aivyx-brand,
  aivyx-wallpapers, aivyx-coder-bench, aivyx-coder-samples and
  aivyx-deploy. Matching ignores case and catches `www.`; character
  references (`&#47;`, `&#x2F;`, `&sol;`, `&period;`, `&colon;`, `&amp;`)
  are decoded first.

Each line names the file, the line and an excerpt. Comments are skipped.

**`hub-sign <dir>`** signs the exact bytes of `packs/index.json` and writes
the base64 signature to `packs/index.json.sig`. The index must parse as
schema 2. As with bundles, the signature is checked before anything is
written, and the file goes through a temp file and a rename. `--yubikey`
signs on the card (the `yubikey` feature; same PIN prompt and touch as
`build --yubikey`).

The signed message is `b"aivyx-hub-index-v1\0"` followed by the index bytes,
never the bare index: a bundle signature is over raw payload bytes, so the
prefix keeps one kind of signature from ever passing as the other. A client
that reads the manifest should verify it the same way
(`aivyx_pack::hub::verify_hub_index`) and refuse a lower version than the one
installed.

## Using the crate

Not on crates.io; consumers pin it by commit:

```toml
aivyx-pack = { git = "https://github.com/Aivyx-Agent/aivyx-pack", rev = "<sha>" }
```
