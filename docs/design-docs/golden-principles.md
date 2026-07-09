# Golden principles

Opinionated, mechanical rules that keep the codebase legible and consistent for
future agent runs. Each principle is enforced by a lint or test where possible.

## Principles

1. All cryptography goes through `core/vault`. No other package imports
   `filippo.io/age` or low-level crypto primitives.
   Enforced by: `core/arch_test.go` (TestCryptoIsolation).
2. Layer direction is one-way: types -> persistence -> service -> runtime.
   Enforced by: Go `internal/` visibility plus `core/arch_test.go`
   (TestLayerDirection).
3. Service packages never print. They return values and errors; the runtime layer
   owns all user-visible output. Enforced by: `core/arch_test.go` (TestNoPrinting).
4. Secret values never appear in error messages. Wrap errors with context about
   paths and operations, not contents. Enforced by: review + guard tests.
5. Parse at the boundary. Config files, vault headers, and MCP inputs are validated
   into typed structs before use. Enforced by: code review and boundary tests.
6. Keep files under ~400 lines. Split by responsibility when approaching the limit.
   Enforced by: `core/arch_test.go` (TestFileSize).

## Lint error message convention

Custom check messages must inject remediation instructions:

```
[RULE_ID] <what is wrong>.
Why: <the invariant this protects>.
Fix: <concrete step>.
See: <doc link>.
```

## Cleanup cadence

Run `make lint`, `make test`, and `make docs-check` before every PR. A recurring
doc-gardening and debt-paydown pass picks items from
[../exec-plans/tech-debt-tracker.md](../exec-plans/tech-debt-tracker.md).
