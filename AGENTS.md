# AGENTS.md - sneakers-release

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

The Sneakers release: the Helm charts for every service (`charts/`), the `sneakers` umbrella that
installs them with optional bundled PostgreSQL, Valkey and Ory Kratos and Hydra, and the pinned
release manifest (`manifest/release.yaml`). The appliance is the recommended deployment; Helm is
the supported alternative.

Two things to know before changing it:

- The manifest and the charts pin the same versions. `scripts/check-manifest.py` fails CI when
  they differ, so change both together.
- The service charts share their templates (`charts/sneakers-lib`) and one values schema
  (`charts/sneakers-lib/service.schema.json`). Edit the schema there and run
  `scripts/sync-schemas.sh`.
- The call graph lives in each chart's `workloadIdentity.callers`, which drives both the
  NetworkPolicy and the callee's allowed service accounts. `scripts/check-edges.py` and
  `test/kind/run.sh` hold the same table; change all three together, with docs/install.md. The
  bundled pieces' callers live in `charts/sneakers/values.yaml` (Valkey),
  `charts/postgres/values.yaml` and `charts/sneakers/templates/bundled-networkpolicies.yaml`
  (Kratos and Hydra), and the same two checks.

## Layout

- `charts/sneakers-lib/` - the library chart: every service resource, plus the shared schema
- `charts/<service>/` - one chart per service, including the two web apps (`web-staff`,
  `web-admin`): `values.yaml`, `values.schema.json`, and a template that includes the library
- `charts/postgres/` - the bundled single-instance PostgreSQL
- `charts/sneakers/` - the umbrella: dependencies, the bundled Secrets, the `helm test` pod
- `manifest/release.yaml` - the pinned release
- `scripts/` - `install-tools.sh` (pinned, checksum-checked tools), `check-charts.sh`, the
  manifest, defaults, edges and web checks, `sync-schemas.sh`
- `test/ci/` - values for rendering in CI; `test/kind/` - the install test
- `docs/` - install, values, and the manual release checks

## Build, test, lint

- Tools: `scripts/install-tools.sh bin helm kubeconform` (add `kind kubectl` for the install test)
- Chart checks: `PATH="$PWD/bin:$PATH" scripts/check-charts.sh` (lint, render, schema refusals,
  kubeconform, production-safe defaults, service-to-service edges, manifest)
- Install test: create a kind cluster, then `test/kind/build-images.sh` and `test/kind/run.sh`
- Lint: `yamllint .` and `actionlint`
- Chart dependencies are resolved by `helm dependency build`; the `charts/*/charts/` archives are
  never committed. `Chart.lock` files are.

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Defaults are production-safe and the schemas enforce the security ones: a change that makes a
  root filesystem writable or turns off `runAsNonRoot` fails validation on purpose.
- `sneakers-release` `main` takes changes only through a PR approved by the release-review group.
- `go.mod` holds tagged releases only: no `replace` directive, and no pseudo-version (`@main`,
  `@<sha>`) of a `github.com/Bugs5382/*` or `github.com/Sneakers-PAM/*` module; the
  `proto-sync / check` job fails on either. To compile and test against a local package checkout,
  use a git-ignored `go.work` beside `go.mod` (`go work init . ../go-<pkg>`, which writes
  `use . ../go-<pkg>`); `go.work` and `go.work.sum` are in `.gitignore`.
