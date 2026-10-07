#!/usr/bin/env bash
# Lint and render every chart, check the values schemas, the production-safe
# defaults, the service-to-service edges and the release manifest. Needs helm,
# kubeconform and python3 with PyYAML. KUBE_VERSION is the Kubernetes version
# manifests are checked against.
set -euo pipefail
cd "$(dirname "$0")/.."
KUBE_VERSION="${KUBE_VERSION:-1.36.4}"
services=(identity vault workflow audit notify connector sshbroker gateway mcp web-staff web-admin)
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
# The arm64 install test: the small-box example under the install test values.
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f charts/sneakers/examples/values-small-box.yaml -f test/kind/values.yaml >/dev/null
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set hydra.enabled=true >"$out/sneakers-hydra.yaml"
for box in small large; do
  helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f "charts/sneakers/examples/values-${box}-box.yaml" >"$out/sneakers-${box}-box.yaml"
  helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f "charts/sneakers/examples/values-${box}-box.yaml" --set hydra.enabled=true >"$out/sneakers-${box}-box-hydra.yaml"
done

# The API server address a cluster's rehearsal names (test/migrate/rehearsal.sh reads it from the
# kubernetes endpoints); a documentation address here.
rehearsal_api=(--set 'rehearsal.apiServer.addresses={192.0.2.10/32}' --set rehearsal.apiServer.port=6443)
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f migrate/deploy/migrate-callers-values.yaml -f test/migrate/rehearsal-values.yaml "${rehearsal_api[@]}" >"$out/sneakers-rehearsal.yaml"
python3 - "$out/sneakers-rehearsal.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
np = [d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "sneakers-rehearsal-egress"]
assert np, "rehearsal mode renders no egress policy"
spec = np[0]["spec"]
assert spec["podSelector"] == {} and spec["policyTypes"] == ["Egress"], spec
assert all("ipBlock" not in t for rule in spec["egress"] for t in rule.get("to", [])), "the namespace-wide rehearsal egress must not allow an address block"
# The services that check caller tokens fetch the cluster's signing keys from
# the API server; only they, and only there.
api = [d for d in docs if d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "sneakers-rehearsal-api-server"]
assert api, "rehearsal mode renders no API server egress for the token checkers"
a = api[0]["spec"]
checkers = sorted(["identity", "vault", "workflow", "audit", "notify", "sshbroker"])
assert a["podSelector"] == {"matchExpressions": [{"key": "app.kubernetes.io/component", "operator": "In", "values": checkers}]}, a["podSelector"]
assert a["policyTypes"] == ["Egress"], a
assert a["egress"] == [{"to": [{"ipBlock": {"cidr": "192.0.2.10/32"}}], "ports": [{"port": 6443, "protocol": "TCP"}]}], a["egress"]
for kind in ("Deployment",):
    names = {d["metadata"]["name"] for d in docs if d["kind"] == kind}
    for svc in ("connector", "sshbroker", "mcp"):
        assert not any(svc in n for n in names), f"rehearsal mode renders the {svc}"
print("ok: rehearsal mode denies egress and runs no automation")
PY
if grep -q sneakers-rehearsal-egress "$out/sneakers.yaml"; then fail "the default install renders the rehearsal egress policy"; fi
python3 - <<'PY'
import yaml
layer = yaml.safe_load(open("migrate/deploy/migrate-callers-values.yaml"))
for svc in ("vault", "audit"):
    want = yaml.safe_load(open(f"charts/{svc}/values.yaml"))["workloadIdentity"]["callers"] + ["migrate"]
    assert layer[svc]["workloadIdentity"]["callers"] == want, f"migrate-callers-values.yaml: {svc} callers must be the chart default plus migrate: {want}"
want = yaml.safe_load(open("charts/postgres/values.yaml"))["networkPolicy"]["from"] + [{"app.kubernetes.io/part-of": "sneakers", "app.kubernetes.io/component": "migrate"}]
assert layer["postgres"]["networkPolicy"]["from"] == want, "migrate-callers-values.yaml: the PostgreSQL list must be its default plus migrate"
print("ok: the migrate callers layer is the chart defaults plus migrate")
PY
# A cutover: the production install plus the migrate callers, no rehearsal mode.
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f migrate/deploy/migrate-callers-values.yaml >"$out/sneakers-cutover.yaml"
if grep -q 'sneakers-rehearsal-' "$out/sneakers-cutover.yaml"; then fail "the cutover callers layer renders a rehearsal policy"; fi
python3 - "$out/sneakers-rehearsal.yaml" "$out/sneakers.yaml" "$out/sneakers-cutover.yaml" <<'PY'
import sys, yaml
def load(p):
    return [d for d in yaml.safe_load_all(open(p)) if d]
def migrate_edge(docs, svc):
    pol = [d for d in docs if d["kind"] == "NetworkPolicy"
           and d["spec"]["podSelector"].get("matchLabels", {}).get("app.kubernetes.io/name") == "sneakers-" + svc]
    assert pol, f"no NetworkPolicy for the {svc}"
    net = any(p.get("podSelector", {}).get("matchLabels", {}).get("app.kubernetes.io/component") == "migrate"
              for r in pol[0]["spec"].get("ingress", []) for p in r.get("from", []))
    dep = [d for d in docs if d["kind"] == "Deployment"
           and d["spec"]["selector"]["matchLabels"].get("app.kubernetes.io/name") == "sneakers-" + svc]
    assert dep, f"no Deployment for the {svc}"
    env = {e["name"]: e.get("value", "") for c in dep[0]["spec"]["template"]["spec"]["containers"] for e in c.get("env", [])}
    sa = "sneakers/sneakers-migrate" in env.get("WORKLOAD_ALLOWED_SERVICEACCOUNTS", "").split(",")
    return net, sa
for svc in ("vault", "audit"):
    assert migrate_edge(load(sys.argv[1]), svc) == (True, True), f"rehearsal mode does not admit sneakers-migrate to the {svc}"
    assert migrate_edge(load(sys.argv[3]), svc) == (True, True), f"the cutover callers do not admit sneakers-migrate to the {svc}"
    assert migrate_edge(load(sys.argv[2]), svc) == (False, False), f"the default install admits sneakers-migrate to the {svc}"
def migrate_data(docs):
    # The Jobs read and write the target databases and Kratos admin directly.
    def admits(rule):
        return any(p.get("podSelector", {}).get("matchLabels", {}).get("app.kubernetes.io/component") == "migrate"
                   for p in rule.get("from", []))
    pg = [d for d in docs if d["kind"] == "NetworkPolicy" and any(pt.get("port") == "postgres" for r in d["spec"].get("ingress", []) for pt in r.get("ports", []))]
    kr = [d for d in docs if d["kind"] == "NetworkPolicy" and d["spec"]["podSelector"].get("matchLabels", {}).get("app.kubernetes.io/name") == "kratos"]
    assert pg and kr, "no PostgreSQL or Kratos NetworkPolicy"
    pg_ok = any(admits(r) for r in pg[0]["spec"]["ingress"])
    kr_ok = any(admits(r) and any(pt.get("port") == 4434 for pt in r.get("ports", [])) for r in kr[0]["spec"]["ingress"])
    kr_public = any(admits(r) and any(pt.get("port") == 4433 for pt in r.get("ports", [])) for r in kr[0]["spec"]["ingress"])
    return pg_ok, kr_ok, kr_public
assert migrate_data(load(sys.argv[1])) == (True, True, False), "rehearsal mode must admit sneakers-migrate to PostgreSQL and Kratos admin only"
assert migrate_data(load(sys.argv[3])) == (True, True, False), "the cutover callers must admit sneakers-migrate to PostgreSQL and Kratos admin only"
assert migrate_data(load(sys.argv[2])) == (False, False, False), "the default install admits sneakers-migrate to PostgreSQL or Kratos"
print("ok: the migrate callers, in a rehearsal and a cutover, admit sneakers-migrate to the vault, audit, PostgreSQL and Kratos admin; the default install doesn't")
PY

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
must_fail "an mfaMaxAge that isn't a Go duration" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.mfaMaxAge=thirty-minutes

step "SSO wiring"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml >"$out/sso-off.yaml"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml \
  --set sso.enabled=true --set sso.publicURL=https://sso.example.org \
  --set sso.clientSecret.secretName=polis >"$out/sso-on.yaml"
python3 scripts/check-sso.py "$out/sso-off.yaml" "$out/sso-on.yaml"

step "global.mfaMaxAge"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.mfaMaxAge=90m >"$out/sneakers-mfa.yaml"
python3 - "$out/sneakers-mfa.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
cms = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ConfigMap"}
for name in ("sneakers-vault", "sneakers-workflow", "sneakers-gateway"):
    assert cms[name]["data"].get("MFA_MAX_AGE") == "90m", f"{name}: MFA_MAX_AGE did not take global.mfaMaxAge"
print("ok: global.mfaMaxAge sets MFA_MAX_AGE on the vault, the workflow and the gateway")
PY

step "mcp.enabled"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set mcp.enabled=false >"$out/sneakers-mcp-off.yaml"
python3 - "$out/sneakers.yaml" "$out/sneakers-mcp-off.yaml" <<'PY'
import sys, yaml
on_docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
off_docs = [d for d in yaml.safe_load_all(open(sys.argv[2])) if d]
on_names = {d["metadata"]["name"] for d in on_docs if d["kind"] in ("Deployment", "Service")}
assert "sneakers-mcp" in on_names, "mcp.enabled: true renders no mcp Deployment or Service"
off_names = {d["metadata"]["name"] for d in off_docs if d["kind"] in ("Deployment", "Service")}
assert "sneakers-mcp" not in off_names, "mcp.enabled: false still renders mcp resources"
print("ok: mcp.enabled renders the mcp resources on, and none off")
PY

step "web apps"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml \
  --set gateway.ingress.enabled=true --set web-staff.ingress.enabled=true \
  --set web-admin.ingress.enabled=true --set global.sso.enabled=true >"$out/sneakers-web.yaml"
python3 scripts/check-web.py "$out/sneakers.yaml" "$out/sneakers-web.yaml"
must_fail "rehearsal mode without the API server address" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f migrate/deploy/migrate-callers-values.yaml -f test/migrate/rehearsal-values.yaml
for svc in connector sshbroker mcp; do
  must_fail "rehearsal mode with the ${svc} on" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f migrate/deploy/migrate-callers-values.yaml -f test/migrate/rehearsal-values.yaml "${rehearsal_api[@]}" --set "${svc}.enabled=true"
done

step "sneakers-migrate Job manifests"
NAMESPACE=sneakers JOB_NAME=sneakers-migrate-import MIGRATE_IMAGE=ci.example.org/sneakers-migrate:ci \
  COMMAND_ARGS='["import", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key"]' \
  envsubst <migrate/deploy/import-job.yaml >"$out/migrate-import.yaml"
SOURCE_NAMESPACE=sneakers-old MIGRATE_IMAGE=ci.example.org/sneakers-migrate:ci HOLDER_IMAGE=ci.example.org/holder:ci \
  RECIPIENT=age1example envsubst <migrate/deploy/export-job.yaml >"$out/migrate-export.yaml"
NAMESPACE=sneakers API_SERVER_CIDR=192.0.2.10/32 API_SERVER_PORT=6443 envsubst <migrate/deploy/rehearsal-egress.yaml >"$out/migrate-egress.yaml"
if grep -h -v '^[[:space:]]*#' "$out"/migrate-*.yaml | grep -q '\${'; then fail "a Job manifest placeholder was not filled"; fi
python3 - "$out/migrate-import.yaml" <<'PY'
import sys, yaml
job = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d and d["kind"] == "Job"][0]
labels = job["spec"]["template"]["metadata"]["labels"]
want = {"app.kubernetes.io/part-of": "sneakers", "app.kubernetes.io/component": "migrate", "app.kubernetes.io/instance": "sneakers"}
assert all(labels.get(k) == v for k, v in want.items()), f"the import Job pod labels {labels} don't match the vault and audit caller policy"
assert job["spec"]["template"]["spec"]["serviceAccountName"] == "sneakers-migrate"
print("ok: the import Job runs as the migrate caller")
PY

step "kubeconform (Kubernetes ${KUBE_VERSION})"
kubeconform -strict -summary -kubernetes-version "${KUBE_VERSION}" "$out"/*.yaml

step "production-safe defaults"
python3 scripts/check-defaults.py <"$out/sneakers.yaml"

step "sizing: every figure is a value, and the example values' budgets"
python3 scripts/check-resources.py templates
# The small-box example (docs/values.md) must leave room for the operating
# system and Kubernetes on a 4 GB board, with Hydra on or off.
python3 scripts/check-resources.py budget "$out/sneakers-small-box.yaml" 1Gi 3Gi
python3 scripts/check-resources.py budget "$out/sneakers-small-box-hydra.yaml" 1Gi 3Gi
python3 scripts/check-resources.py budget "$out/sneakers-large-box-hydra.yaml" 16Gi 48Gi
must_fail "the chart defaults within the small-box budget" python3 scripts/check-resources.py budget "$out/sneakers.yaml" 1Gi 3Gi
for box in small large; do
  python3 scripts/check-defaults.py <"$out/sneakers-${box}-box.yaml"
done

step "service-to-service edges"
python3 scripts/check-edges.py <"$out/sneakers.yaml"
python3 scripts/check-edges.py <"$out/sneakers-hydra.yaml"

step "release manifest"
python3 scripts/check-manifest.py

echo
echo "all chart checks passed"
