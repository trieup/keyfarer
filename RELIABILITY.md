# Reliability

Reliability requirements stated as measurable bars an agent can verify.

## Bars

| Concern | Bar | How to verify |
|---------|-----|---------------|
| Vault round trip integrity | 100%: seal then restore reproduces byte-identical files | `go test ./core/vault -run RoundTrip` |
| Tamper detection | Any corrupted vault byte fails decryption loudly | `go test ./core/vault -run Corrupt` |
| Guard false negatives | Staged managed secret value is always blocked | `go test ./core/guard` |
| CLI cold start | < 100ms for `status` on a 50-file vault | `time bin/keyfarer status` in a seeded repo |
| Seal latency | < 2s for a 10MB secret set (scrypt dominates) | `time bin/keyfarer seal` |

## Critical user journeys

1. New machine restore: `git clone` then `keyfarer restore` with the vault key
   recovers every secret file with original permissions. Success: `status` reports
   clean.
2. Agent uses a secret via MCP without seeing it: `run_with_secrets` executes and
   returns output; the transcript contains no secret value.
3. Accidental commit blocked: staging a managed plaintext file causes the
   pre-commit hook to fail with a clear message.

## Failure handling

- Prefer follow-up runs for flaky tests over indefinite blocking.
- Capture recurring failures as docs or tooling, not tribal knowledge.
