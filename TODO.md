## Demo by Oct 30
- [x] Hash-chained, Ed25519-signed append-only event log + `blackbox verify` CLI
- [ ] Recorder that ingests timestamped robot events (joint states, e-stops, faults) from a JSONL stream; ROS 2 adapter behind an optional extra
- [x] Tamper test: flipping any single byte makes verify fail and name the first bad record
- [ ] `blackbox replay` prints the incident timeline around an e-stop or fault
- [ ] demo.sh: record a simulated incident, verify, tamper, verify fails, replay, in under a minute
- [ ] README quickstart and a 60-second demo walkthrough

## Later (not for the demo)
- Anchor the head automatically: `blackbox head` + `verify --anchor` exist; next is publishing periodic anchors to an external timestamping service without manual steps.
- Keep the signing key in hardware (TPM or secure element) instead of a file.
