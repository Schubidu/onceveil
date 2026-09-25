# Security policy

Onceveil is security-sensitive software and is currently in early development.

## Supported versions

There is no supported production release yet. Until `v0.1.0` is published, the repository should be treated as development software and not used for production secrets.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability or include real secrets, credentials, tokens, private keys, or sensitive URLs in an issue or pull request.

Use GitHub's private vulnerability reporting / Security Advisory flow for this repository when available.

If private reporting is unavailable, open a public issue containing no exploit details or sensitive material and ask the maintainer for a private reporting channel.

## Security design

The executable security invariants and threat model are intentionally defined in issue #2 before Onceveil implements secret storage or reveal behavior.
