# Working rules for agents in this repo

This is the robot black box: liability-grade incident evidence for robots. A tamper-evident,
cryptographically signed event recorder whose logs can hold up as evidence (EU product-liability
claims, Machinery Regulation logging). Demo target: Oct 30, 2026. YC Winter 2027 deadline: Nov 2, 2026.

## Branches
- The nightly Builder pushes only to `builder/nightly`. Nobody pushes to `main` except Geraldo, who merges.
- Never force-push. Never delete branches.

## How work is taken
- Work comes from `TODO.md`. One TODO item per commit; tick the item in the same commit.
- The nightly Builder takes items from the top. Daytime sessions take items from the bottom, so they never collide.
- Commit only when the full test suite passes (`pytest -q`). If an item can't go green, commit no code for it:
  add an indented note under the item saying what blocks it.
- Append an entry to `BUILDLOG.md` at the end of every session: date (America/New_York), items done or
  blocked, passing test count, next item, anything that needs Geraldo's decision.

## Code
- Python 3.11+. Package lives in `src/blackbox`, tests in `tests/`.
- Minimal dependencies: `cryptography` for Ed25519. No web frameworks.
- CI (`.github/workflows/ci.yml`) runs pytest on Python 3.11, 3.12 and 3.13 for every push and pull request.

## Log format invariants (do not break)
- One record per line, canonical JSON (sorted keys, no spaces, UTF-8), newline-terminated.
- Every record carries `prev` (hash of the previous record) and `hash` (SHA-256 of its own body),
  and `sig` (Ed25519 signature over the hash). Record 0 is the `genesis` record holding the public key.
- Any change to the format must bump the `v` field and update `verify` and its tests in the same commit.
- Private keys (`*.key`) are never committed.
