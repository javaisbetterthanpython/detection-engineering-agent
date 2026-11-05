# Lessons

- `sed` on this machine is GNU sed (gsed); use `sed -i 's/..//'` without the BSD `''` argument.
- Smoke-test the real inference boundary EARLY (right after the llm wrapper lands), not after the whole build: the opus-5-5 rejection by the installed CLI would have been caught in tier 1.
- Workflow agents die on API ENOTFOUND with no retry; keep workflows resumable (same run id) and check journal.jsonl for which phases actually ran before trusting a "completed" status.
- In a run→diagnose→fix loop, the LAST fix is never exercised. Order loops as fix→run (or add a final run after the loop) so every change is validated by the real path.
- An adversarial reviewer with an unbounded finding space plus a fixed round budget guarantees failure. Anchor severity to the claim under test (the idea's attack_steps) and let deterministic gates (recall over ingested evasion events) be the proof of coverage.
- "Deploy a server" from this user means a cloud host (DigitalOcean via doctl), never the laptop. Ask size/lifecycle/visibility before spending or publishing.
