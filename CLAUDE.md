# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

`aivyx-pack` is the signed `.aivyxpack` bundle format for Aivyx vertical
packs — a pure library (manifest parsing, build, sign, verify, unpack) plus
the `aivyx-pack` publisher CLI. It was extracted from `aivyx-pa`'s
`crates/aivyx-pack` (history preserved) so `aivyx-pa` and `aivyx-coder`
share one implementation. See `README.md` for the format.

## Build, test, lint

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

## Rules

- **Consumers pin this crate by git rev, so this repo MUST stay public.**
- **Never change what an existing manifest format means.** Format 1 (tool
  packs) is frozen; format 2 is config-only. A new kind of pack is a new
  `format` number, dispatched in `Manifest::parse`.
- No engine dependencies: this crate knows nothing about aivyx-pa or
  aivyx-coder internals. Product-specific checks (does a template load as a
  real config?) live in each product's `pack check`.
- Anything touching verification or unpacking needs a test for the attack
  it closes.
- Commits are signed off (`git commit -s`).
