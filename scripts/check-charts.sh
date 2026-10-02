#!/usr/bin/env bash
# Lint and render every chart, check the values schemas, the production-safe
# defaults, the service-to-service edges and the release manifest. Needs helm,
# kubeconform and python3 with PyYAML. KUBE_VERSION is the Kubernetes version
# manifests are checked against.
set -euo pipefail
cd "$(dirname "$0")/.."
KUBE_VERSION="${KUBE_VERSION:-1.36.4}"
services=(identity vault workflow audit notify connector sshbroker gateway mcp)
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# must_fail <description> <command...>: the command has to exit non-zero.
must_fail() {
  local what="$1"; shift
  if "$@" >"$out/neg.log" 2>&1; then
    fail "expected a failure: ${what}"
  fi
  echo "ok (refused): ${what}"
}

step "service schemas in sync"
scripts/sync-schemas.sh --check

step "dependencies"
scripts/build-deps.sh

step "helm lint"
helm lint --strict charts/sneakers-lib
helm lint --strict charts/postgres --set auth.existingSecret=ci
for svc in "${services[@]}"; do
  helm lint --strict "charts/${svc}" -f "test/ci/standalone/${svc}.yaml"
done
helm lint --strict charts/sneakers -f test/ci/values.yaml

step "helm template (values checked against each values.schema.json)"
for svc in "${services[@]}"; do
  helm template ci "charts/${svc}" -n sneakers -f "test/ci/standalone/${svc}.yaml" >"$out/${svc}.yaml"
done
helm template ci charts/postgres -n sneakers --set auth.existingSecret=ci >"$out/postgres.yaml"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml >"$out/sneakers.yaml"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f test/kind/values.yaml >/dev/null
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set hydra.enabled=true >"$out/sneakers-hydra.yaml"

step "guards and schema refusals"
must_fail "the umbrella without a vault root key" helm template ci charts/sneakers -n sneakers
must_fail "a service without its database DSN" helm template ci charts/vault -n sneakers
must_fail "an unknown log level" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.logLevel=verbose
must_fail "a writable root filesystem" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set gateway.securityContext.readOnlyRootFilesystem=false
must_fail "a misspelt service key" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set gateway.replica=3
must_fail "an ingress with no host" helm template ci charts/mcp -n sneakers -f test/ci/standalone/mcp.yaml --set ingress.enabled=true --set global.host=
must_fail "postgres without its Secret" helm template ci charts/postgres -n sneakers
must_fail "a token check with no callers" helm template ci charts/connector -n sneakers -f test/ci/standalone/connector.yaml --set workloadIdentity.verify=true
must_fail "an unknown caller" helm template ci charts/vault -n sneakers -f test/ci/standalone/vault.yaml --set 'workloadIdentity.callers={gateway,admin}'
must_fail "SSO without its client secret" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set sso.enabled=true --set sso.publicURL=https://sso.example.org
must_fail "SSO without its public URL" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set sso.enabled=true --set sso.clientSecret.secretName=polis
must_fail "a Polis URL with SSO off" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set env.POLIS_PUBLIC_URL=https://sso.example.org
must_fail "a projected token over the workload tokens" helm template ci charts/vault -n sneakers -f test/ci/standalone/vault.yaml --set projectedToken.enabled=true

step "SSO wiring"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml >"$out/sso-off.yaml"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml \
  --set sso.enabled=true --set sso.publicURL=https://sso.example.org \
  --set sso.clientSecret.secretName=polis >"$out/sso-on.yaml"
python3 scripts/check-sso.py "$out/sso-off.yaml" "$out/sso-on.yaml"

step "kubeconform (Kubernetes ${KUBE_VERSION})"
kubeconform -strict -summary -kubernetes-version "${KUBE_VERSION}" "$out"/*.yaml

step "production-safe defaults"
python3 scripts/check-defaults.py <"$out/sneakers.yaml"

step "service-to-service edges"
python3 scripts/check-edges.py <"$out/sneakers.yaml"
python3 scripts/check-edges.py <"$out/sneakers-hydra.yaml"

step "release manifest"
python3 scripts/check-manifest.py

echo
echo "all chart checks passed"
