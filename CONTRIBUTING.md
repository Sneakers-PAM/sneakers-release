# Contributing to sneakers-release

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Check the charts with `scripts/check-charts.sh`, after `scripts/install-tools.sh bin helm
  kubeconform` and with `bin/` on your `PATH`. The install test is `test/kind/run.sh` against a
  throwaway kind cluster; see [README.md](README.md).
- A version changes in two places: the charts and `manifest/release.yaml`. Change both in the same
  pull request; `scripts/check-manifest.py` fails when they disagree.
- The service charts share one values schema, `charts/sneakers-lib/service.schema.json`. Edit it
  there and run `scripts/sync-schemas.sh`.
- Keep the defaults production-safe: JSON logs at `error`, requests and limits, non-root pods on a
  read-only root filesystem, NetworkPolicies and PodDisruptionBudgets. A development setting goes
  in a values file of its own, never in a chart's `values.yaml`.
- Never commit chart archives (`charts/*/charts/*.tgz`) or a secret of any kind, sealed or not.
- No real names, hosts, addresses or other identifiers in charts, values, tests or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
- Changes to `main` need the release-review group's approval as well as green CI.
