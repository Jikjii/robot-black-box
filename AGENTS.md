# Agent guidelines

All coding agents in this repo follow the working rules in [CLAUDE.md](CLAUDE.md): work comes from
`TODO.md`, one item per commit, tests must pass, nobody but Geraldo pushes to `main`.

## Review guidelines

This is evidence software: a log that a court or insurer may rely on. Review for:

1. **Tamper evidence.** Any path where changed, deleted, reordered or appended bytes could still pass
   `blackbox verify`, or where verify blames the wrong record.
2. **Canonical encoding.** Hashing and stored lines must use the same canonical JSON; flag anything that
   could let two different byte strings verify as the same record.
3. **Keys.** Private keys never logged, printed, committed or written with loose file permissions.
   Verification must be able to pin a trusted public key.
4. **Format changes.** Any change to the record format must bump the `v` field and update verify and its
   tests in the same commit.
5. **Tests.** Behavior changes need tests; CI must stay green on Python 3.11 to 3.13.

Skip style nits; flag only issues that affect correctness, security or evidence value.
