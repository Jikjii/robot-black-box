# Build log

## 2026-10-11 (America/New_York): jump-start session
- Done: project skeleton with CI (Python 3.11–3.13), CLAUDE.md working rules, TODO.md demo checklist.
- Done: item 1, the hash-chained, Ed25519-signed log with `blackbox keygen`, `append` and `verify`.
- Done: item 3, the exhaustive tamper test: 6,816 tampered copies of a sample incident log (every byte flipped three ways, and deleted) all fail verify and blame the right record.
- Tests: 25 passing locally on Python 3.13.
- Codex review on PR #1 found three P1 issues, all fixed with tests: (1) dropping the last records went undetected, so `blackbox head` and `verify --anchor` now prove the log still reaches a saved head; (2) `keygen --force` could keep an old file's loose permissions, so keys are now written to a fresh owner-only file and moved into place; (3) two writers could fork the chain, so every append now takes an exclusive lock and re-reads the head from disk.
- Codex rounds 2 and 3 found two more P1s, both fixed with tests: an explicitly empty `--anchor` or `--pubkey` (say, an unset shell variable) silently disabled the check; both now fail with exit code 2. Round 4 found only two P2s, queued under Hardening in TODO.md.
- Tests after fixes: 38 passing; CI green on every push.
- Next: item 2, the recorder that ingests timestamped robot events from a JSONL stream.
- Needs Geraldo: where the signing key lives on a real robot. It's a file for the demo; a TPM or secure element is the production answer.
