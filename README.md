# Release 📦

> 🧭 The Sneakers release: Helm charts for every service and the pinned manifest that holds k0s, every image and every third-party component at one version.

A Sneakers release is applied whole. `manifest/release.yaml` names every service image, the k0s
version and each third-party chart and image; the charts in `charts/` pin the same versions, and CI
fails when the two disagree.

## 🧭 Which way to run Sneakers

- 🖥️ **The appliance (recommended):** a single-node k0s image built from an org-signed release, with
  the maintenance screen, scheduled automatic updates, database snapshots and automatic rollback.
  See the `sneakers-appliance` repository.
- ☸️ **Helm on your own Kubernetes (supported alternative):** the `sneakers` umbrella chart in this
  repository. You run upgrades, backups and the cluster yourself; there is no maintenance screen
  and no automatic update window.

## ✨ Highlights

- 🧩 **One chart per service:** identity, vault, workflow, audit, notify, connector, sshbroker,
  gateway and mcp, each usable alone, plus the `sneakers` umbrella that installs them together.
- 🔌 **Bundled or bring your own:** PostgreSQL, Valkey and Ory Kratos come bundled and on by
  default; Ory Hydra is bundled and off. Turn any of them off and point the services at your own.
- 🛡️ **Production-safe defaults:** JSON logs at error level, requests and limits, non-root pods on a
  read-only root filesystem, NetworkPolicies, PodDisruptionBudgets and a schema for every chart's
  values.
- 📌 **Pinned:** every third-party chart and image is pinned by version and digest.

## 🚀 Install with Helm

```bash
helm repo add valkey https://valkey.io/valkey-helm/
helm repo add ory https://k8s.ory.sh/helm/charts
helm dependency build charts/sneakers

kubectl create namespace sneakers
kubectl -n sneakers create secret generic sneakers-vault-root-key \
  --from-literal=VAULT_ROOT_KEK="$(openssl rand -base64 32)"

helm install sneakers charts/sneakers -n sneakers \
  --set global.host=sneakers.example.org \
  --set vault.secretEnv.VAULT_ROOT_KEK.secretName=sneakers-vault-root-key
helm test sneakers -n sneakers
```

The charts aren't published to a registry yet, so install from a checkout. Back up the root key
Secret with the database: without it no stored secret can be opened.

## 📚 Where to look

- [docs/install.md](docs/install.md): requirements, installing, ingress, bringing your own
  PostgreSQL, Valkey or Kratos, upgrades and uninstalling.
- [docs/values.md](docs/values.md): every value of the umbrella and the service charts.
- [docs/release-checks.md](docs/release-checks.md): the manual checks run on a release candidate
  before it's tagged.
- [manifest/release.yaml](manifest/release.yaml): the pinned release.

## 🛠️ Develop

```bash
scripts/install-tools.sh bin helm kubeconform   # pinned, checksum-checked tools
PATH="$PWD/bin:$PATH" scripts/check-charts.sh  # lint, render, schemas, defaults, edges, manifest
```

The install test (`test/kind/run.sh`, run by the Install Test workflow) builds every service image
from its repository, installs the umbrella on a throwaway kind cluster, upgrades it in place, runs
`helm test` and checks that each service's port takes only its callers, and that a callee refuses a
caller with the wrong service account.

## ⚖️ License

Apache-2.0 (c) 2026 The Sneakers-PAM Authors
