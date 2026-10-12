# AGENTS.md

Operational notes for agents working in this repo. Humans: see README.md for the full explainer.

## Build, test, validate

```sh
make              # fmt-check, vet, test, build -> bin/iamsentry
make build        # go build -> bin/iamsentry
make test         # go test ./...
make vet          # go vet ./...
make fmt          # gofmt -w .
make fmt-check    # fails if gofmt would change anything
golangci-lint run # lint, matches CI (.github/workflows/ci.yml); no Makefile target yet
```

Run `make` (or at minimum `fmt-check`, `vet`, `test`) plus `golangci-lint run` before considering any change done. `gofmt` and `golangci-lint` are enforced in CI, not optional.

## Layout

- `cmd/iamsentry` — CLI entrypoint
- `internal/policy` — IAM policy document parsing
- `internal/rules` — Rego/OPA rule engine
- `internal/rules/builtin` — built-in Rego rules shipped with iamsentry
- `internal/denylist` — `CheckAccessNotGranted` deny list handling
- `internal/suppress` — inline suppression comment handling
- `internal/awsval` — AWS Access Analyzer validation layer
- `internal/render` — output formatting (text, SARIF, GitHub annotations)
- `internal/input` — file discovery/scanning for policy inputs
- `action.yml` — GitHub Action wrapper around the CLI
- `examples/`, `testdata/` — sample policies and fixtures used by tests

## Conventions

- Small, atomic diffs. One concern per change. Never mix formatting and logic changes.
- Comments only for WHY, never what the code does.
- For bug fixes: add a failing test first (each internal package has a sibling `_test.go`), then fix.
- Before changing behavior around rules, denylist, or suppressions: identify root cause with concrete evidence (a failing policy example, a rule output, a test), not just a symptom.
- Releases are tagged, not automatic on merge — don't assume a merge to main publishes a release (see `.goreleaser.yaml`).
- Never install extra dependencies unless explicitly asked.
