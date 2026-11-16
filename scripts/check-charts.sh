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

step "the database host and sslmode"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set hydra.enabled=true --set global.database.host=sneakers-db-new --set global.database.sslmode=require >"$out/sneakers-db.yaml"
python3 - "$out/sneakers-hydra.yaml" "$out/sneakers-db.yaml" <<'PY'
import base64, re, sys, yaml

def dsns(path):
    found = {}
    for d in yaml.safe_load_all(open(path)):
        if not d:
            continue
        if d["kind"] == "Secret":
            for k, v in (d.get("data") or {}).items():
                if k == "dsn":
                    found[d["metadata"]["name"]] = re.sub(r":[^:@]+@", ":x@", base64.b64decode(v).decode())
        if d["kind"] == "ConfigMap" and (d.get("data") or {}).get("DATABASE_DSN", "").startswith("postgres://"):
            found[d["metadata"]["name"]] = d["data"]["DATABASE_DSN"]
    return found

defaults, moved = dsns(sys.argv[1]), dsns(sys.argv[2])
assert len(defaults) == 6, defaults
assert defaults.keys() == moved.keys(), (defaults, moved)
for name, dsn in defaults.items():
    assert "@sneakers-postgres:5432/" in dsn and dsn.endswith("?sslmode=disable"), dsn
    assert moved[name] == dsn.replace("@sneakers-postgres:", "@sneakers-db-new:").replace("sslmode=disable", "sslmode=require"), moved[name]
print("ok: every DSN follows global.database, and the default is unchanged")
PY
must_fail "an sslmode libpq doesn't know" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.database.sslmode=maybe

step "postgres-ha, the cluster the services move to"
scripts/check-chart-digest.sh
must_fail "a postgres-ha chart that isn't the pinned digest" env PGHA_CHART="$(ls charts/sneakers/charts/valkey-*.tgz)" scripts/check-chart-digest.sh
mkdir "$out/pgha"
pgha_values=(-n sneakers -f test/ci/values.yaml -f charts/sneakers/examples/values-small-box.yaml --set hydra.enabled=true)
pgha_on=(--set postgres-ha.enabled=true --set 'postgres-ha.postgresql.allowedCIDRs={192.0.2.0/24}')
pgha_arch=(--set global.arch=arm64 --set-string 'valkey.nodeSelector.kubernetes\.io/arch=arm64'
  --set-string 'kratos.deployment.nodeSelector.kubernetes\.io/arch=arm64'
  --set-string 'hydra.deployment.nodeSelector.kubernetes\.io/arch=arm64')
helm template ci charts/sneakers "${pgha_values[@]}" >"$out/pgha/off.yaml"
helm template ci charts/sneakers "${pgha_values[@]}" "${pgha_on[@]}" >"$out/pgha/certmanager.yaml"
# kubeconform has no schema for cert-manager's kinds, so it reads the render without them.
helm template ci charts/sneakers "${pgha_values[@]}" "${pgha_on[@]}" \
  --set postgres-ha.tls.certManager.enabled=false --set postgres-ha.tls.existingSecret=sneakers-pgha-tls >"$out/pgha.yaml"
must_fail "postgres-ha without a pod network" helm template ci charts/sneakers "${pgha_values[@]}" --set postgres-ha.enabled=true
must_fail "global.arch with no kubernetes.io/arch on postgres-ha" helm template ci charts/sneakers "${pgha_values[@]}" "${pgha_on[@]}" "${pgha_arch[@]}"
helm template ci charts/sneakers "${pgha_values[@]}" "${pgha_on[@]}" "${pgha_arch[@]}" \
  --set-string 'postgres-ha.nodeSelector.kubernetes\.io/arch=arm64' >/dev/null
# On Cilium the members reach the API server only through its kube-apiserver entity, so the
# chart has to be able to render that policy, and not by default.
helm template ci charts/sneakers "${pgha_values[@]}" "${pgha_on[@]}" --set postgres-ha.networkPolicy.cilium.enabled=true >"$out/pgha/cilium.yaml"
grep -q '^kind: CiliumNetworkPolicy' "$out/pgha/cilium.yaml" || fail "postgres-ha.networkPolicy.cilium.enabled renders no CiliumNetworkPolicy"
if grep -q '^kind: CiliumNetworkPolicy' "$out/pgha/certmanager.yaml"; then
  fail "postgres-ha renders a CiliumNetworkPolicy by default"
fi
echo "ok: the Cilium policy renders only when asked for"
python3 - "$out/pgha/off.yaml" "$out/pgha/certmanager.yaml" "$out/pgha.yaml" <<'PY'
import collections, sys, yaml

def load(path):
    return [d for d in yaml.safe_load_all(open(path)) if d]

def key(d):
    return (d["kind"], d["metadata"]["name"])

off, docs, nocm = load(sys.argv[1]), load(sys.argv[2]), load(sys.argv[3])
# Off is the default, so a plain upgrade starts no second cluster.
assert not any("pgha" in d["metadata"]["name"] for d in off), "postgres-ha renders while it's off"
# Beside charts/postgres: no name twice, and nothing the umbrella renders changes.
for render in docs, nocm:
    dup = [k for k, n in collections.Counter(key(d) for d in render).items() if n > 1]
    assert not dup, f"rendered twice: {dup}"
was, now = {key(d): d for d in off}, {key(d): d for d in docs}
# The Secrets the umbrella generates differ on every render.
changed = [k for k, d in was.items() if k not in now or (k[0] != "Secret" and d != now[k])]
assert not changed, f"turning postgres-ha on changed: {changed}"
added = [d for k, d in now.items() if k not in was]
assert all(d["metadata"]["name"].startswith("sneakers-pgha") for d in added), [key(d) for d in added]
assert not any(d["kind"].startswith("Cluster") for d in added), "postgres-ha has a cluster-scoped object"
print(f"ok: {len(added)} objects of its own, and none of the umbrella's {len(off)} change")
sts = now[("StatefulSet", "sneakers-pgha")]
assert sts["spec"]["replicas"] == 1, sts["spec"]["replicas"]
assert not any("pgbouncer" in d["metadata"]["name"] and d["kind"] in ("Deployment", "Service") for d in docs), "PgBouncer is on"
c = sts["spec"]["template"]["spec"]["containers"][0]
env = {e["name"]: e.get("value") for e in c["env"]}
assert "--locale=en_US.UTF-8" in env["PGHA_INITDB_ARGS"], env["PGHA_INITDB_ARGS"]
assert env["PGHA_SYNC_MODE"] == "off", env["PGHA_SYNC_MODE"]
old = yaml.safe_load(open("charts/postgres/values.yaml"))
new = yaml.safe_load(open("charts/sneakers/values.yaml"))["postgres-ha"]
assert [d["name"] for d in new["databases"]] == old["databases"], "the two clusters' databases differ"
assert all(d["owner"] == old["auth"]["username"] for d in new["databases"]), new["databases"]
want = [{"podSelector": {"matchLabels": f}} for f in old["networkPolicy"]["from"]]
assert new["networkPolicy"]["allowedClients"] == want, "the two clusters' client lists differ"
box = yaml.safe_load(open("charts/sneakers/examples/values-small-box.yaml"))
small, got = box["postgres"], box["postgres-ha"]
assert got["resources"] == small["resources"], "the small box's PostgreSQL sizes differ"
for k in ("shared_buffers", "effective_cache_size", "work_mem", "maintenance_work_mem"):
    assert got["postgresql"]["parameters"][k] == small["parameters"][k], k
print("ok: its own name, one member, no PgBouncer, en_US, the old cluster's databases and clients")
PY

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

step "mTLS certificates (global.internalTLS)"
# kubeconform has no schema for cert-manager's kinds, so the checks read the render.
mtls_args=(-n sneakers -f test/ci/values.yaml)
helm template ci charts/sneakers "${mtls_args[@]}" >"$out/mtls-on.yaml"
helm template ci charts/sneakers "${mtls_args[@]}" --set global.internalTLS.enabled=false >"$out/mtls-off.yaml"
helm template ci charts/sneakers "${mtls_args[@]}" --set global.internalTLS.issuerRef.name=corp-ca --set global.internalTLS.issuerRef.kind=ClusterIssuer \
  --set mcp.enabled=false >"$out/mtls-ref.yaml"
python3 - "$out/mtls-on.yaml" "$out/mtls-off.yaml" "$out/mtls-ref.yaml" <<'PY'
import sys, yaml

def load(path):
    return [d for d in yaml.safe_load_all(open(path)) if d]

def by(docs, kind):
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == kind}

CM = ("Issuer", "Certificate", "ClusterIssuer")
on, off, ref = (load(p) for p in sys.argv[1:4])
services = ["identity", "vault", "workflow", "audit", "notify", "connector", "sshbroker", "gateway", "mcp"]

# The default is on, and the chain is bootstrap Issuer, root Certificate, CA Issuer.
issuers, certs = by(on, "Issuer"), by(on, "Certificate")
boot = issuers["sneakers-mtls-bootstrap"]
assert boot["spec"] == {"selfSigned": {}}, boot["spec"]
ca = certs["sneakers-mtls-ca"]["spec"]
assert ca["isCA"] is True and ca["secretName"] == "sneakers-mtls-ca", ca
assert ca["issuerRef"]["name"] == "sneakers-mtls-bootstrap" and ca["issuerRef"]["kind"] == "Issuer", ca["issuerRef"]
assert ca["duration"] == "87600h", "the root is valid 10 years"
assert ca["privateKey"] == {"algorithm": "ECDSA", "size": 256}, ca["privateKey"]
assert issuers["sneakers-mtls"]["spec"] == {"ca": {"secretName": "sneakers-mtls-ca"}}, issuers["sneakers-mtls"]["spec"]

# One Certificate per service that speaks gRPC, none for the web apps or the root.
leaf = {n: c for n, c in certs.items() if n != "sneakers-mtls-ca"}
assert sorted(leaf) == sorted(f"sneakers-{s}" for s in services), sorted(leaf)
for svc in services:
    c = leaf[f"sneakers-{svc}"]["spec"]
    assert c["secretName"] == f"sneakers-{svc}-tls", c["secretName"]
    assert c["issuerRef"] == {"name": "sneakers-mtls", "kind": "Issuer", "group": "cert-manager.io"}, c["issuerRef"]
    assert c["usages"] == ["server auth", "client auth"], c["usages"]
    assert c["privateKey"] == {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"}, c["privateKey"]
    assert c["duration"] == "720h" and c["renewBefore"] == "240h", (c["duration"], c["renewBefore"])
    n = f"sneakers-{svc}"
    assert c["dnsNames"] == [n, f"{n}.sneakers", f"{n}.sneakers.svc", f"{n}.sneakers.svc.cluster.local"], c["dnsNames"]
    assert c["uris"] == [f"spiffe://sneakers/ns/sneakers/sa/{n}"], c["uris"]
    assert leaf[n]["metadata"]["labels"]["app.kubernetes.io/part-of"] == "sneakers"

# Off is the rc.7 render: no cert-manager object at all.
assert not [d for d in off if d["kind"] in CM], "global.internalTLS.enabled=false renders cert-manager objects"

# A cluster's own issuer: no bootstrap, no root, no CA Issuer, and the leaves use it.
assert "sneakers-mtls-ca" not in by(ref, "Certificate") and not by(ref, "Issuer"), "issuerRef still creates the CA"
rl = by(ref, "Certificate")
assert sorted(rl) == sorted(f"sneakers-{s}" for s in services if s != "mcp"), sorted(rl)
assert all(c["spec"]["issuerRef"]["name"] == "corp-ca" and c["spec"]["issuerRef"]["kind"] == "ClusterIssuer" for c in rl.values())
print(f"ok: mTLS renders the CA chain and {len(leaf)} service certificates, and none when off")
PY
must_fail "an issuerRef kind cert-manager doesn't have" helm template ci charts/sneakers "${mtls_args[@]}" --set global.internalTLS.issuerRef.name=x --set global.internalTLS.issuerRef.kind=Secret
must_fail "internalTLS.enabled that isn't a boolean" helm template ci charts/sneakers "${mtls_args[@]}" --set global.internalTLS.enabled=maybe

step "mTLS pod wiring (global.internalTLS)"
helm template ci charts/sneakers "${mtls_args[@]}" >"$out/mtls-pods-on.yaml"
helm template ci charts/sneakers "${mtls_args[@]}" --set global.internalTLS.enabled=false >"$out/mtls-pods-off.yaml"
python3 - "$out/mtls-pods-on.yaml" "$out/mtls-pods-off.yaml" <<'PY'
import sys, yaml

def load(path):
    return [d for d in yaml.safe_load_all(open(path)) if d]

def pod(docs, svc):
    dep = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == f"sneakers-{svc}")
    spec = dep["spec"]["template"]["spec"]
    cm = next(d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == f"sneakers-{svc}")
    return spec, spec["containers"][0], cm["data"]

on, off = load(sys.argv[1]), load(sys.argv[2])
# The services that read the three files, and the plain health port each one answers on.
health = {"identity": 9091, "audit": 9091, "notify": 9091, "vault": 9092, "sshbroker": 9098}
no_health_port = ["gateway", "mcp"]   # their probes stay on the plain HTTP port
not_yet = ["workflow", "connector"]   # no mTLS in the service yet
D = "/var/run/sneakers/tls"
for svc in list(health) + no_health_port:
    spec, c, data = pod(on, svc)
    vols = {v["name"]: v for v in spec["volumes"]}
    assert vols["mtls"]["secret"]["secretName"] == f"sneakers-{svc}-tls", vols["mtls"]
    assert vols["mtls"]["secret"]["defaultMode"] == 0o440, vols["mtls"]
    mounts = {m["name"]: m for m in c["volumeMounts"]}
    assert mounts["mtls"] == {"name": "mtls", "mountPath": D, "readOnly": True}, mounts["mtls"]
    assert not any(m.get("subPath") for m in c["volumeMounts"]), f"{svc}: a subPath mount never updates"
    assert (data["MTLS_CERT_FILE"], data["MTLS_KEY_FILE"], data["MTLS_CA_FILE"]) == (f"{D}/tls.crt", f"{D}/tls.key", f"{D}/ca.crt"), data
for svc, port in health.items():
    spec, c, data = pod(on, svc)
    assert data["HEALTH_PORT"] == str(port), (svc, data.get("HEALTH_PORT"))
    assert {"name": "health", "containerPort": port} in c["ports"], c["ports"]
    for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
        assert c[probe]["grpc"]["port"] == port, (svc, probe, c[probe])
    assert c["livenessProbe"]["grpc"]["service"] == "liveness", c["livenessProbe"]
for svc, port in (("gateway", 9100), ("mcp", 9101)):
    spec, c, data = pod(on, svc)
    assert "HEALTH_PORT" not in data, svc
    assert all(c[p]["httpGet"]["port"] == port for p in ("startupProbe", "livenessProbe", "readinessProbe")), svc
for svc in not_yet:
    spec, c, data = pod(on, svc)
    assert "mtls" not in {v["name"] for v in spec["volumes"]} and not any(k.startswith("MTLS_") for k in data), svc
# Off is the rc.7 pod: no mount, no variable, the probes on the service port.
for svc in list(health) + no_health_port + not_yet:
    spec, c, data = pod(off, svc)
    assert "mtls" not in {v["name"] for v in spec["volumes"]}, svc
    assert not any(k.startswith("MTLS_") or k == "HEALTH_PORT" for k in data), svc
    assert "health" not in {p["name"] for p in c["ports"]}, svc
for svc, port in (("identity", 9192), ("vault", 9091), ("sshbroker", 9096)):
    assert pod(off, svc)[1]["readinessProbe"]["grpc"]["port"] == port, svc
print("ok: with mTLS on, the pods mount their certificate, read it by variable and probe the health port; off is the rc.7 pod")
PY

step "guards and schema refusals"
must_fail "the umbrella without a vault root key" helm template ci charts/sneakers -n sneakers
must_fail "a service without its database DSN" helm template ci charts/vault -n sneakers
must_fail "an unknown log level" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.logLevel=verbose
must_fail "a writable root filesystem" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set gateway.securityContext.readOnlyRootFilesystem=false
must_fail "a misspelt service key" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set gateway.replica=3
must_fail "an ingress with no host" helm template ci charts/mcp -n sneakers -f test/ci/standalone/mcp.yaml --set ingress.enabled=true --set global.host=
must_fail "postgres without its Secret" helm template ci charts/postgres -n sneakers
must_fail "a token check with no callers" helm template ci charts/connector -n sneakers -f test/ci/standalone/connector.yaml --set-json 'workloadIdentity.callers=[]'
must_fail "an unknown caller" helm template ci charts/vault -n sneakers -f test/ci/standalone/vault.yaml --set 'workloadIdentity.callers={gateway,admin}'
must_fail "SSO without its client secret" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set sso.enabled=true --set sso.publicURL=https://sso.example.org
must_fail "SSO without its public URL" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set sso.enabled=true --set sso.clientSecret.secretName=polis
must_fail "a Polis URL with SSO off" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set env.POLIS_PUBLIC_URL=https://sso.example.org
must_fail "a projected token over the workload tokens" helm template ci charts/vault -n sneakers -f test/ci/standalone/vault.yaml --set projectedToken.enabled=true
must_fail "an mfaMaxAge that isn't a Go duration" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.mfaMaxAge=thirty-minutes
must_fail "certManager.enabled without ingress.enabled" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set certManager.enabled=true --set certManager.issuerRef.name=letsencrypt
must_fail "certManager.enabled without ingress.tlsSecretName" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set ingress.enabled=true --set ingress.host=sneakers.example.org --set certManager.enabled=true --set certManager.issuerRef.name=letsencrypt
must_fail "certManager.enabled without issuerRef.name" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set ingress.enabled=true --set ingress.host=sneakers.example.org --set ingress.tlsSecretName=sneakers-tls --set certManager.enabled=true

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

step "identity TOTP_ENC_KEY"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml >"$out/sneakers-totp-default.yaml"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set identity.secretEnv.TOTP_ENC_KEY.secretName=my-totp >"$out/sneakers-totp-named.yaml"
python3 - "$out/sneakers-totp-default.yaml" "$out/sneakers-totp-named.yaml" <<'PY'
import sys, yaml
def load(f):
    return [d for d in yaml.safe_load_all(open(f)) if d]
def totp_ref(docs):
    dep = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "sneakers-identity")
    env = {e["name"]: e for c in dep["spec"]["template"]["spec"]["containers"] for e in c.get("env", [])}
    assert "TOTP_ENC_KEY" in env, "identity: no TOTP_ENC_KEY, so authenticator-app MFA is unavailable"
    return env["TOTP_ENC_KEY"]["valueFrom"]["secretKeyRef"]
default = load(sys.argv[1])
ref = totp_ref(default)
assert ref == {"name": "sneakers-identity-generated", "key": "TOTP_ENC_KEY"}, ref
gen = next(d for d in default if d["kind"] == "Secret" and d["metadata"]["name"] == "sneakers-identity-generated")
assert gen["metadata"]["annotations"].get("helm.sh/resource-policy") == "keep", "the generated TOTP key must survive uninstall"
assert "TOTP_ENC_KEY" in gen["data"], gen["data"].keys()
named = load(sys.argv[2])
assert totp_ref(named)["name"] == "my-totp", totp_ref(named)
assert not any(d["kind"] == "Secret" and d["metadata"]["name"] == "sneakers-identity-generated" for d in named), "a named TOTP Secret still generated one"
print("ok: identity gets a generated TOTP_ENC_KEY by default, or the named Secret's")
PY

step "global.workloadIdentityIssuer"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml >"$out/sneakers-issuer-default.yaml"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.workloadIdentityIssuer=https://kubernetes.default.svc >"$out/sneakers-issuer-k0s.yaml"
python3 - "$out/sneakers-issuer-default.yaml" "$out/sneakers-issuer-k0s.yaml" <<'PY'
import sys, yaml

def issuers(path):
    out = {}
    for d in yaml.safe_load_all(open(path)):
        if not d or d["kind"] not in ("Deployment", "StatefulSet"):
            continue
        for c in d["spec"]["template"]["spec"]["containers"]:
            for e in c.get("env") or []:
                if e["name"] == "WORKLOAD_OIDC_ISSUER":
                    out[d["metadata"]["name"]] = e["value"]
    return out

default, k0s = issuers(sys.argv[1]), issuers(sys.argv[2])
assert default, "no service checks workload tokens"
assert set(default.values()) == {"https://kubernetes.default.svc.cluster.local"}, f"the default issuers: {default}"
assert set(k0s) == set(default) and set(k0s.values()) == {"https://kubernetes.default.svc"}, f"global.workloadIdentityIssuer didn't reach every verifier: {k0s}"
print(f"ok: global.workloadIdentityIssuer sets WORKLOAD_OIDC_ISSUER on all {len(k0s)} verifiers, and the default stays each chart's")
PY
must_fail "a workloadIdentityIssuer that isn't https" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.workloadIdentityIssuer=http://kubernetes.default.svc

step "global.imageTag"
# hydra on: every Sneakers image the chart can render, the Jobs included.
tag_args=(-f test/ci/values.yaml --set hydra.enabled=true)
helm template ci charts/sneakers -n sneakers "${tag_args[@]}" >"$out/tags-default.yaml"
helm template ci charts/sneakers -n sneakers "${tag_args[@]}" --set global.imageTag=0.1.0-rc.3 >"$out/tags-global.yaml"
helm template ci charts/sneakers -n sneakers "${tag_args[@]}" --set global.imageTag=0.1.0-rc.3 \
  --set vault.image.tag=pinned --set "audit.image.digest=sha256:$(printf 'a%.0s' {1..64})" >"$out/tags-override.yaml"
python3 - "$(awk '/^appVersion:/ { gsub(/"/, "", $2); print $2 }' charts/sneakers/Chart.yaml)" \
  "$out/tags-default.yaml" "$out/tags-global.yaml" "$out/tags-override.yaml" <<'PY'
import sys, yaml

def images(path):
    out = {}
    for d in yaml.safe_load_all(open(path)):
        if not d or d["kind"] not in ("Deployment", "StatefulSet", "Job", "Pod"):
            continue
        spec = d["spec"]["template"]["spec"] if d["kind"] != "Pod" else d["spec"]
        for c in spec.get("initContainers", []) + spec.get("containers", []):
            if c["image"].startswith("ghcr.io/sneakers-pam/sneakers-"):
                out[f'{d["kind"]}/{d["metadata"]["name"]}/{c["name"]}'] = c["image"]
    return out

app = sys.argv[1]
default, global_, override = (images(p) for p in sys.argv[2:])
assert len(default) >= 11, f"too few Sneakers images rendered: {default}"
bad = {k: v for k, v in default.items() if not v.endswith(f":{app}")}
assert not bad, f"the default tag isn't the appVersion {app}: {bad}"
assert set(global_) == set(default), f"global.imageTag changed which containers render: {set(global_) ^ set(default)}"
bad = {k: v for k, v in global_.items() if not v.endswith(":0.1.0-rc.3")}
assert not bad, f"global.imageTag didn't reach every Sneakers image: {bad}"
for k, v in override.items():
    if "/sneakers-vault/" in k:
        assert v.endswith("/sneakers-vault:pinned"), f"vault.image.tag didn't win over global.imageTag: {k} {v}"
    elif "/sneakers-audit/" in k:
        assert v.endswith("/sneakers-audit@sha256:" + "a" * 64), f"audit.image.digest didn't win over global.imageTag: {k} {v}"
    else:
        assert v.endswith(":0.1.0-rc.3"), f"{k}: {v}"
print(f"ok: global.imageTag sets all {len(global_)} Sneakers images, a service's own tag or digest wins, and the default is the appVersion {app}")
PY
must_fail "a global.imageTag that isn't an image tag" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.imageTag=0.1.0:latest

step "the gateway's product version"
# The value About and diagnostics show: the version the chart deploys, unless
# the installer names one, as the appliance's bundle build does.
digest="sha256:$(printf 'a%.0s' {1..64})"
version_case() {
  local want="$1"; shift
  local got
  helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml "$@" >"$out/version.yaml"
  got="$(python3 - "$out/version.yaml" <<'PY'
import re, sys, yaml

name = "SNEAKERS_PRODUCT_VERSION"
text = open(sys.argv[1]).read()
for doc in text.split("\n---\n"):
    d = yaml.safe_load(doc)
    if d and d["kind"] == "ConfigMap" and d["metadata"]["name"] == "sneakers-gateway":
        assert len(re.findall(rf"^\s*{name}:", doc, re.M)) <= 1, f"{name} is in the gateway's ConfigMap twice"
        print(d["data"].get(name, ""))
assert not any(
    e["name"] == name
    for d in yaml.safe_load_all(text)
    if d and d["kind"] == "Deployment"
    for c in d["spec"]["template"]["spec"]["containers"]
    for e in c.get("env") or []
), f"{name} is also in a container's env"
PY
  )"
  [ "$got" = "$want" ] || fail "product version with [$*]: got '$got', want '$want'"
  echo "ok: ${want:-(unset)} from [$*]"
}
app_version="$(awk '/^appVersion:/ { gsub(/"/, "", $2); print $2 }' charts/gateway/Chart.yaml)"
version_case "$app_version"
version_case 0.1.0-rc.3 --set global.imageTag=0.1.0-rc.3
version_case 0.1.0-rc.9 --set global.imageTag=0.1.0-rc.3 --set gateway.image.tag=0.1.0-rc.9
version_case 0.1.0-rc.9 --set gateway.image.tag=v0.1.0-rc.9
version_case 0.1.0-rc.9 --set "gateway.image.tag=0.1.0-rc.9@$digest"
version_case 0.1.0-rc.3 --set global.imageTag=0.1.0-rc.3 --set gateway.image.tag=pinned
version_case "$app_version" --set "gateway.image.digest=$digest"
version_case 9.9.9 --set global.imageTag=0.1.0-rc.3 --set-string gateway.env.SNEAKERS_PRODUCT_VERSION=9.9.9
version_case "" --set global.imageTag=0.1.0-rc.3 --set-string gateway.env.SNEAKERS_PRODUCT_VERSION=
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set global.imageTag=0.1.0-rc.3 >"$out/version-gateway.yaml"
grep -q 'SNEAKERS_PRODUCT_VERSION: "0.1.0-rc.3"' "$out/version-gateway.yaml" \
  || fail "the gateway chart on its own didn't set the product version"
echo "ok: the gateway chart on its own sets the product version"

step "global.arch"
# hydra on: every workload the umbrella can render. The third-party charts
# don't read global.arch, so their own nodeSelector keys carry the arch.
arch_args=(-f test/ci/values.yaml --set hydra.enabled=true)
arch_bundled=(--set-string 'valkey.nodeSelector.kubernetes\.io/arch=arm64'
  --set-string 'kratos.deployment.nodeSelector.kubernetes\.io/arch=arm64'
  --set-string 'hydra.deployment.nodeSelector.kubernetes\.io/arch=arm64')
helm template ci charts/sneakers -n sneakers "${arch_args[@]}" >"$out/arch-default.yaml"
helm template ci charts/sneakers -n sneakers "${arch_args[@]}" --set global.arch=arm64 "${arch_bundled[@]}" \
  --set-string 'vault.nodeSelector.disk=ssd' >"$out/arch-arm64.yaml"
helm template ci charts/postgres -n sneakers --set auth.existingSecret=ci --set global.arch=amd64 >"$out/arch-postgres.yaml"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set global.arch=amd64 >"$out/arch-gateway.yaml"
python3 - "$out/arch-default.yaml" "$out/arch-arm64.yaml" "$out/arch-postgres.yaml" "$out/arch-gateway.yaml" <<'PY'
import sys, yaml

# The third-party charts' own helm test pods have no scheduling values.
UNSET = {"sneakers-hydra-test-connection", "sneakers-kratos-test-connection", "sneakers-valkey-test-auth-existing"}

def selectors(path):
    out = {}
    for d in yaml.safe_load_all(open(path)):
        if not d or d["kind"] not in ("Deployment", "StatefulSet", "Job", "CronJob", "Pod"):
            continue
        spec = d["spec"]
        if d["kind"] == "CronJob":
            spec = spec["jobTemplate"]["spec"]
        if d["kind"] != "Pod":
            spec = spec["template"]["spec"]
        out[f'{d["kind"]}/{d["metadata"]["name"]}'] = spec.get("nodeSelector") or {}
    return out

default, arm, pg, gw = (selectors(p) for p in sys.argv[1:])
assert len(default) >= 15, f"too few workloads rendered: {sorted(default)}"
pinned = {k: v for k, v in default.items() if "kubernetes.io/arch" in v}
assert not pinned, f"the default install pins an arch: {pinned}"
assert set(arm) == set(default), f"global.arch changed which workloads render: {set(arm) ^ set(default)}"
for k, v in arm.items():
    if k.split("/", 1)[1] in UNSET:
        continue
    assert v.get("kubernetes.io/arch") == "arm64", f"global.arch didn't reach {k}: {v}"
assert arm["Deployment/sneakers-vault"] == {"disk": "ssd", "kubernetes.io/arch": "arm64"}, f"a service's own nodeSelector isn't kept: {arm['Deployment/sneakers-vault']}"
for name, chart in (("postgres", pg), ("gateway", gw)):
    assert chart and all(v.get("kubernetes.io/arch") == "amd64" for v in chart.values()), f"global.arch on the {name} chart alone: {chart}"
print(f"ok: global.arch pins all {len(arm) - len(UNSET)} workloads, keeps a service's own nodeSelector, works on a chart alone, and the default pins none")
PY
helm template ci charts/sneakers -n sneakers "${arch_args[@]}" --set global.arch=arm64 "${arch_bundled[@]}" \
  --set-string 'connector.nodeSelector.kubernetes\.io/arch=amd64' >"$out/arch-override.yaml"
python3 - "$out/arch-override.yaml" <<'PY'
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d["kind"] == "Deployment" and d["metadata"]["name"] == "sneakers-connector":
        sel = d["spec"]["template"]["spec"]["nodeSelector"]
        assert sel == {"kubernetes.io/arch": "amd64"}, f"a service's own arch didn't win over global.arch: {sel}"
        print("ok: a service's own kubernetes.io/arch wins over global.arch")
        break
else:
    raise SystemExit("no connector Deployment")
PY
must_fail "an unknown global.arch" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.arch=s390x
must_fail "an unknown global.arch on a chart alone" helm template ci charts/postgres -n sneakers --set auth.existingSecret=ci --set global.arch=x86_64
must_fail "global.arch without the Valkey arch" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.arch=arm64 \
  --set-string 'kratos.deployment.nodeSelector.kubernetes\.io/arch=arm64'
must_fail "global.arch without the Kratos arch" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.arch=arm64 \
  --set-string 'valkey.nodeSelector.kubernetes\.io/arch=arm64'
must_fail "global.arch with a different Kratos arch" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set global.arch=arm64 \
  --set-string 'valkey.nodeSelector.kubernetes\.io/arch=arm64' --set-string 'kratos.deployment.nodeSelector.kubernetes\.io/arch=amd64'
must_fail "global.arch without the Hydra arch" helm template ci charts/sneakers -n sneakers "${arch_args[@]}" --set global.arch=arm64 \
  --set-string 'valkey.nodeSelector.kubernetes\.io/arch=arm64' --set-string 'kratos.deployment.nodeSelector.kubernetes\.io/arch=arm64'

step "cert-manager"
# Rendered into its own subdirectory, out of kubeconform's "$out"/*.yaml glob:
# kubeconform has no schema for the cert-manager.io CRD kinds (the same reason
# the Hydra maester CRD stays off), and the fields the chart sets are checked
# below instead.
mkdir -p "$out/certtest"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml \
  --set ingress.enabled=true --set ingress.host=sneakers.example.org --set ingress.tlsSecretName=sneakers-tls \
  --set certManager.enabled=true --set certManager.issuerRef.name=letsencrypt >"$out/certtest/gateway-cert-on.yaml"
python3 - "$out/gateway.yaml" "$out/certtest/gateway-cert-on.yaml" <<'PY'
import sys, yaml
off_docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
assert not [d for d in off_docs if d["kind"] == "Certificate"], "certManager.enabled: false still renders a Certificate"
on_docs = [d for d in yaml.safe_load_all(open(sys.argv[2])) if d]
certs = [d for d in on_docs if d["kind"] == "Certificate"]
assert certs, "certManager.enabled: true renders no Certificate"
cert = certs[0]
assert cert["spec"]["issuerRef"] == {"name": "letsencrypt", "kind": "ClusterIssuer", "group": "cert-manager.io"}, cert["spec"]["issuerRef"]
assert cert["spec"]["secretName"] == "sneakers-tls", cert["spec"]["secretName"]
assert not [d for d in on_docs if d["kind"] in ("Issuer", "ClusterIssuer")], "the chart must never create an Issuer or a ClusterIssuer"
print("ok: certManager.enabled renders one Certificate at the configured issuer, off renders none, and the chart never creates an Issuer")
PY

step "service-account tokens"
python3 - "$out/sneakers.yaml" "$out/sneakers-small-box.yaml" <<'PY'
import sys, yaml
for path in sys.argv[1:]:
    docs = [d for d in yaml.safe_load_all(open(path)) if d]
    mounted = sorted(d["metadata"]["name"] for d in docs if d["kind"] == "Deployment" and d["spec"]["template"]["spec"].get("automountServiceAccountToken"))
    # The gateway reads the API server's /version for the diagnostics; its
    # service account has no role, and no other service mounts a token.
    assert mounted == ["sneakers-gateway"], f"{path}: Deployments with a mounted token: {mounted}"
    roles = [d["metadata"]["name"] for d in docs if d["kind"] in ("Role", "RoleBinding") and "gateway" in d["metadata"]["name"]]
    assert not roles, f"{path}: the gateway's service account has a role: {roles}"
print("ok: only the gateway mounts its service-account token, and it has no role")
PY

step "no cluster-scoped objects"
cluster_scoped=(CustomResourceDefinition ClusterRole ClusterRoleBinding MutatingWebhookConfiguration ValidatingWebhookConfiguration IngressClass StorageClass PriorityClass)
for f in "$out"/sneakers.yaml "$out"/sneakers-hydra.yaml "$out"/sneakers-small-box.yaml "$out"/sneakers-small-box-hydra.yaml "$out"/sneakers-large-box.yaml "$out"/sneakers-large-box-hydra.yaml; do
  for kind in "${cluster_scoped[@]}"; do
    if grep -qx "kind: ${kind}" "$f"; then fail "${f} renders a cluster-scoped ${kind}"; fi
  done
done
echo "ok: no render carries a cluster-scoped object"

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

step "envFromConfigMaps"
helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml \
  --set-json 'envFromConfigMaps=[{"name":"sneakers-mcp","optional":true}]' >"$out/gateway-cm-on.yaml"
python3 - "$out/gateway.yaml" "$out/gateway-cm-on.yaml" <<'PY'
import sys, yaml
def env_from(path):
    for d in yaml.safe_load_all(open(path)):
        if d and d["kind"] == "Deployment":
            return d["spec"]["template"]["spec"]["containers"][0]["envFrom"]
    raise SystemExit(f"{path}: no Deployment")
off, on = env_from(sys.argv[1]), env_from(sys.argv[2])
assert off == [{"configMapRef": {"name": "sneakers-gateway"}}], f"the default envFrom: {off}"
# Later envFrom sources win, so a listed ConfigMap overrides the chart's own settings.
assert on[0] == off[0] and on[-1] == {"configMapRef": {"name": "sneakers-mcp", "optional": True}}, f"envFromConfigMaps: {on}"
print("ok: envFromConfigMaps loads each ConfigMap after the chart's own, optional when asked, and the default adds none")
PY
must_fail "an envFromConfigMaps entry with no name" helm template ci charts/gateway -n sneakers -f test/ci/standalone/gateway.yaml --set-json 'envFromConfigMaps=[{"optional":true}]'

step "connector has no database setting"
# The connector holds no database, and its config loader no longer reads
# DATABASE_DSN, so the chart must not set a placeholder for it.
helm template ci charts/connector -n sneakers -f test/ci/standalone/connector.yaml >"$out/connector-nodsn.yaml"
if grep -q DATABASE_DSN "$out/connector-nodsn.yaml"; then
  fail "the connector chart still sets DATABASE_DSN"
fi
echo "ok: the connector chart sets no DATABASE_DSN"

step "web apps"
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml \
  --set gateway.ingress.enabled=true --set web-staff.ingress.enabled=true \
  --set web-admin.ingress.enabled=true --set global.sso.enabled=true >"$out/sneakers-web.yaml"
python3 scripts/check-web.py "$out/sneakers.yaml" "$out/sneakers-web.yaml"
# The gateway answers these itself, outside any sign-in, so the edge sends them
# past the staff app that owns / (its discovery document for the phone apps and
# the one-time share links). A path missing here falls through to the staff app
# and answers 404 on a box.
python3 - "$out/sneakers-web.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
ing = [d for d in docs if d["kind"] == "Ingress" and d["metadata"]["name"] == "sneakers-gateway"]
assert len(ing) == 1, f"want one gateway Ingress, got {len(ing)}"
rules = ing[0]["spec"]["rules"]
assert len(rules) == 1, f"the gateway Ingress has {len(rules)} rules"
got = {p["path"]: p["pathType"] for p in rules[0]["http"]["paths"]}
want = {p: "Prefix" for p in (
    "/graphql", "/machine", "/auth", "/setup", "/oauth2",
    "/.well-known/oauth-authorization-server",
    "/.well-known/sneakers", "/share",
)}
assert got == want, f"gateway Ingress paths: missing {sorted(set(want) - set(got))}, unexpected {sorted(set(got) - set(want))}"
print("ok: the gateway Ingress routes /.well-known/sneakers and /share, with its other paths, ahead of the staff app")
PY
must_fail "rehearsal mode without the API server address" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f migrate/deploy/migrate-callers-values.yaml -f test/migrate/rehearsal-values.yaml
for svc in connector sshbroker mcp; do
  must_fail "rehearsal mode with the ${svc} on" helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml -f migrate/deploy/migrate-callers-values.yaml -f test/migrate/rehearsal-values.yaml "${rehearsal_api[@]}" --set "${svc}.enabled=true"
done

step "sneakers-migrate Job manifests"
NAMESPACE=sneakers JOB_NAME=sneakers-migrate-import MIGRATE_IMAGE=ci.example.org/sneakers-migrate:ci \
  COMMAND_ARGS='["import", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key"]' \
  envsubst <migrate/deploy/import-job.yaml >"$out/migrate-import.yaml"
SOURCE_NAMESPACE=sneakers-old MIGRATE_IMAGE=ci.example.org/sneakers-migrate:ci HOLDER_IMAGE=ci.example.org/holder:ci \
  RECIPIENT=age1example SOURCE_NAME=old-box.example.org envsubst <migrate/deploy/export-job.yaml >"$out/migrate-export.yaml"
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
# cert-manager's Certificate and Issuer have no schema here; the mTLS step above checks them.
kubeconform -strict -summary -skip Certificate,Issuer -kubernetes-version "${KUBE_VERSION}" "$out"/*.yaml

step "production-safe defaults"
python3 scripts/check-defaults.py <"$out/sneakers.yaml"

step "probe timings"
# Probes fit a small box under boot load and never kill a process that is
# only waiting for a dependency (scripts/check-probes.py).
for f in "$out"/sneakers.yaml "$out"/sneakers-hydra.yaml "$out"/sneakers-small-box.yaml "$out"/sneakers-small-box-hydra.yaml "$out"/sneakers-large-box-hydra.yaml; do
  python3 scripts/check-probes.py <"$f"
done
helm template ci charts/sneakers -n sneakers -f test/ci/values.yaml --set audit.probes.timeoutSeconds=1 >"$out/probes-tight.yaml"
must_fail "a probe that waits 1 s" python3 scripts/check-probes.py <"$out/probes-tight.yaml"

step "PostgreSQL stops cleanly"
# Every stop is a fast shutdown with its checkpoint written before the kubelet
# would kill the server (scripts/check-shutdown.py).
for f in "$out"/sneakers.yaml "$out"/sneakers-small-box.yaml "$out"/sneakers-large-box.yaml "$out"/postgres.yaml; do
  python3 scripts/check-shutdown.py <"$f"
done
must_fail "a PostgreSQL grace period under 120 s" helm template ci charts/postgres -n sneakers --set auth.existingSecret=ci --set shutdown.terminationGracePeriodSeconds=60
python3 - "$out/postgres.yaml" <<'PY2'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
sts = [d for d in docs if d["kind"] == "StatefulSet"][0]
c = sts["spec"]["template"]["spec"]["containers"][0]
c["lifecycle"]["preStop"]["exec"]["command"] = ["pg_ctl", "stop", "-D", "/var/lib/postgresql/data/pgdata", "-m", "smart", "-W"]
yaml.safe_dump(sts, open(sys.argv[1] + ".smart", "w"))
PY2
must_fail "a smart shutdown" sh -c "python3 scripts/check-shutdown.py <'$out/postgres.yaml.smart'"

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

step "install docs"
# The install steps must build every chart's dependencies the way the script
# does: helm dependency build on the umbrella alone leaves the service charts
# without their library, and the render fails.
grep -q 'scripts/build-deps.sh' docs/install.md || fail "docs/install.md does not tell the reader to run scripts/build-deps.sh"
if grep -q '^helm dependency build charts/sneakers' docs/install.md; then
  fail "docs/install.md builds only the umbrella's dependencies"
fi
echo "ok: the install steps build every chart's dependencies"

step "release manifest"
python3 scripts/check-manifest.py
# Each service's build block: the source commit the appliance release builds
# its image from. A broken one is refused, as is an install test that builds
# a different commit, target or build argument.
bad_manifest() {
  python3 - "$out/bad-release.yaml" "$1" <<'PY'
import sys, yaml
out, what = sys.argv[1:3]
m = yaml.safe_load(open("manifest/release.yaml"))
svc = m["spec"]["services"]
if what == "no-build":
    del svc["vault"]["build"]
elif what == "short-commit":
    svc["vault"]["build"]["commit"] = svc["vault"]["build"]["commit"][:12]
elif what == "other-repo":
    svc["vault"]["build"]["repository"] = "Sneakers-PAM/sneakers-audit"
elif what == "no-dockerfile":
    svc["audit"]["build"]["dockerfile"] = ""
elif what == "other-commit":
    svc["web-admin"]["build"]["commit"] = "0" * 40
elif what == "other-target":
    svc["workflow"]["build"]["target"] = "seed"
elif what == "other-args":
    svc["web-staff"]["build"]["args"] = {"APP": "admin"}
elif what == "unknown-key":
    svc["mcp"]["build"]["ref"] = "main"
elif what == "no-migrate":
    del m["spec"]["jobs"]["migrate"]
elif what == "migrate-short-commit":
    m["spec"]["jobs"]["migrate"]["build"]["commit"] = "59056d5"
elif what == "migrate-other-repo":
    m["spec"]["jobs"]["migrate"]["build"]["repository"] = "Sneakers-PAM/sneakers-vault"
elif what == "no-postgres-ha":
    del m["spec"]["thirdParty"]["postgres-ha"]
elif what == "postgres-ha-no-digest":
    del m["spec"]["thirdParty"]["postgres-ha"]["chart"]["digest"]
elif what == "postgres-ha-other-agent":
    m["spec"]["thirdParty"]["postgres-ha"]["digest"] = "sha256:" + "0" * 64
elif what == "postgres-ha-pseudo-version":
    m["spec"]["thirdParty"]["postgres-ha"]["chart"]["version"] = "1.0.1-0.20261101"
elif what == "no-acmesolver":
    del m["spec"]["platform"]["cert-manager-acmesolver"]
elif what == "acmesolver-other-version":
    m["spec"]["platform"]["cert-manager-acmesolver"]["version"] = "v1.0.0"
yaml.safe_dump(m, open(out, "w"), sort_keys=False)
PY
  python3 scripts/check-manifest.py "$out/bad-release.yaml"
}
for what in no-build short-commit other-repo no-dockerfile other-commit other-target other-args unknown-key no-migrate migrate-short-commit migrate-other-repo no-postgres-ha postgres-ha-no-digest postgres-ha-other-agent postgres-ha-pseudo-version no-acmesolver acmesolver-other-version; do
  must_fail "a service build block: ${what}" bad_manifest "$what"
done

# Every image the bundle carries is an index with linux/amd64 and linux/arm64
# (appliance platform design, section 5.2). check-manifest.py --platforms reads
# each real digest's index from the registry; here the indexes come from
# fixtures in CHECK_MANIFEST_INDEX_DIR, one file per digest, so the check
# runs offline. A placeholder digest is skipped, as is the postgres-ha chart's.
step "release manifest: image platforms"
platform_fixtures() {
  python3 - "$out/index-$1" "$1" <<'PY'
import json, os, sys, yaml
dest, what = sys.argv[1:3]
os.makedirs(dest)
m = yaml.safe_load(open("manifest/release.yaml"))["spec"]
digests = []
def walk(o):
    if isinstance(o, dict):
        d = o.get("digest")
        if isinstance(o.get("image"), str) and isinstance(d, str) and d.startswith("sha256:") and "TBD" not in d:
            digests.append(d)
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)
walk(m)
def entry(os_, arch, variant=None):
    p = {"os": os_, "architecture": arch}
    if variant:
        p["variant"] = variant
    return {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "1" * 64, "size": 1, "platform": p}
def index(*entries, media="application/vnd.oci.image.index.v1+json"):
    return {"schemaVersion": 2, "mediaType": media, "manifests": list(entries)}
good = index(entry("linux", "amd64"), entry("linux", "arm64", "v8"), entry("unknown", "unknown"))
for i, d in enumerate(digests):
    body = good
    if i == 0:
        body = index(entry("linux", "amd64"), entry("linux", "arm64"), media="application/vnd.docker.distribution.manifest.list.v2+json")
    if i == 1:
        if what == "no-arm64":
            body = index(entry("linux", "amd64"), entry("linux", "arm", "v7"))
        elif what == "no-amd64":
            body = index(entry("linux", "arm64"))
        elif what == "single-platform":
            body = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {}, "layers": []}
        elif what == "wrong-os":
            body = index(entry("linux", "amd64"), entry("windows", "arm64"))
        elif what == "not-in-registry":
            continue
    json.dump(body, open(os.path.join(dest, d.split(":", 1)[1] + ".json"), "w"))
PY
}
platform_fixtures ok
CHECK_MANIFEST_INDEX_DIR="$out/index-ok" python3 scripts/check-manifest.py --platforms
bad_platforms() {
  platform_fixtures "$1"
  CHECK_MANIFEST_INDEX_DIR="$out/index-$1" python3 scripts/check-manifest.py --platforms
}
for what in no-arm64 no-amd64 single-platform wrong-os not-in-registry; do
  must_fail "an image without both platforms: ${what}" bad_platforms "$what"
done

echo
echo "all chart checks passed"
