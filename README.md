# robot-black-box

Liability-grade black box for robots: a tamper-evident, cryptographically signed incident recorder.

Every event a robot logs (joint states, e-stops, faults) is chained to the one before it with SHA-256 and
signed with the robot's Ed25519 key. Change, delete or reorder a single byte afterwards and `blackbox verify`
fails and names the first record that no longer checks out.

## Try it

```bash
pip install -e ".[dev]"

blackbox keygen robot.key                     # writes robot.key (secret) and robot.key.pub
blackbox append incident.log --key robot.key --type estop --data '{"source": "operator"}'
blackbox append incident.log --key robot.key --type fault --data '{"code": "E-217"}'
blackbox verify incident.log --pubkey robot.key.pub
```

### Prove nothing was cut from the end

A hash chain shows that nothing was changed, deleted or reordered, but it can't show on its own that
the last records weren't dropped. Save the head hash somewhere outside the log (a ticket, an email,
a timestamping service), then verify against it later:

```bash
blackbox head incident.log                          # prints the head hash to save
blackbox verify incident.log --anchor <saved hash>  # fails if the log no longer reaches it
```

Several processes can append to one log at the same time; each append takes an exclusive file lock
(POSIX) and re-reads the head, so the chain never forks.

## Log format (v1)

One record per line in canonical JSON (sorted keys, no whitespace, UTF-8):

| Field | Meaning |
|---|---|
| `seq` | 0, 1, 2, … with no gaps |
| `ts`, `type`, `data` | when it happened, what happened, the payload |
| `prev` | hash of the previous record (64 zeros for record 0) |
| `hash` | SHA-256 of the record body (everything except `hash` and `sig`) |
| `sig` | Ed25519 signature over `hash` |

Record 0 is a `genesis` record carrying the public key. Pass `--pubkey` to `verify` to pin the key you
trust instead of the one the log asserts.
