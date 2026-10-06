# Security Policy

aivyx-pack decides whether a pack is trusted and what it writes to disk, so
it is security-sensitive by design.

## In scope

- A bundle that verifies when it shouldn't: a signature, publisher-key or
  manifest check that can be bypassed.
- Unpacking that writes outside the install directory (absolute paths,
  `..`, symlinks, hard links) or can be made to exhaust memory or disk
  before verification.
- A manifest that installers trust but that names paths outside its pack.

## Reporting a vulnerability

Email **jccorbett67@gmail.com** with details. Please don't open a public
issue for a vulnerability. We aim to resolve or provide a remediation plan
for a confirmed vulnerability within 90 days of the report, or coordinate
a later disclosure date directly with the reporter. Credit is offered in
release notes at the reporter's preference.
