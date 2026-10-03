#!/usr/bin/env bash
# The synthetic migration rehearsal (docs/migrate.md), against the current
# kubectl context (a throwaway kind cluster with the service images and the
# sneakers-migrate image already loaded):
#
#   1. the source: Postgres and Kratos containers with the original schema,
#      seeded with an invented dataset by migrate/test/synth;
#   2. the target: the umbrella chart in rehearsal mode (deny-all egress, no
#      automation);
#   3. keygen on the target side, export on the source side, the import Job,
#      a vault restart, the verify Job;
#   4. the negative tests: egress is blocked, automation is off, an import into
#      a target holding other data is refused, a tampered audit record fails
#      verify.
#
# Only counts and results are kept (in $WORK_DIR/results.txt); the source, its
# keys and the bundle are removed on exit unless KEEP=1.
set -euo pipefail
cd "$(dirname "$0")/../.."
root="$PWD"

ns="${NAMESPACE:-sneakers}"
release=sneakers
prefix="${SOURCE_PREFIX:-sneakers-migrate-src}"
image="${MIGRATE_IMAGE:-ci.example.org/sneakers-migrate:ci}"
schema_dir="${SOURCE_SCHEMA_DIR:-migrate/testdata/source-schema}"
timeout="${HELM_TIMEOUT:-15m}"
owner="owner@example.org"
pg_image="docker.io/library/postgres:18.6@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722"
kratos_image="oryd/kratos:v1.3.1@sha256:fe2428f103a6240c064b6ea77d3088610865c55fcebccb30355857eccdc25b4b"
work="${WORK_DIR:-$(mktemp -d)}"
mkdir -p "$work"
chmod 700 "$work"
results="$work/results.txt"
: >"$results"

step() { printf '\n== %s\n' "$*"; }
note() { echo "$*" | tee -a "$results"; }
fail() { echo "FAIL: $*" | tee -a "$results" >&2; exit 1; }

ctx="$(kubectl config current-context)"
case "$ctx" in
  kind-*) ;;
  *) fail "refusing to run against the kubectl context ${ctx}: the rehearsal needs a throwaway kind cluster" ;;
esac

cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then
    echo "KEEP=1: leaving the source containers and $work"
    return
  fi
  docker rm -f "$prefix-kratos" "$prefix-pg" >/dev/null 2>&1 || true
  docker network rm "$prefix-net" >/dev/null 2>&1 || true
  kubectl -n "$ns" delete secret sneakers-migrate-bundle sneakers-migrate-key --ignore-not-found >/dev/null 2>&1 || true
  find "$work" -mindepth 1 ! -name results.txt -delete 2>/dev/null || true
}
trap cleanup EXIT

src_pw="$(openssl rand -hex 16)"

step "source: Postgres and Kratos (original schema)"
docker network create "$prefix-net" >/dev/null
docker run -d --name "$prefix-pg" --network "$prefix-net" -e POSTGRES_PASSWORD="$src_pw" -p 127.0.0.1::5432 "$pg_image" >/dev/null
for _ in $(seq 60); do docker exec "$prefix-pg" pg_isready -U postgres -q 2>/dev/null && break; sleep 1; done
sleep 2
for d in src_identity src_vault src_workflow src_audit src_kratos; do
  docker exec "$prefix-pg" createdb -U postgres "$d"
done
mkdir -p "$work/kratos"
python3 - "$work/kratos" <<'PY'
import json, sys, yaml
values = yaml.safe_load(open("charts/sneakers/values.yaml"))
schema = values["kratos"]["kratos"]["identitySchemas"]["identity.default.schema.json"]
open(sys.argv[1] + "/identity.schema.json", "w").write(schema)
cfg = {
    "serve": {"public": {"base_url": "http://127.0.0.1:4433/"}, "admin": {"base_url": "http://127.0.0.1:4434/"}},
    "identity": {"default_schema_id": "default", "schemas": [{"id": "default", "url": "file:///etc/kratos/identity.schema.json"}]},
    "selfservice": {"default_browser_return_url": "https://source.example.org/", "methods": {"password": {"enabled": True}}},
    "courier": {"smtp": {"connection_uri": "smtp://smtp.example.org:25/"}},
}
open(sys.argv[1] + "/kratos.yml", "w").write(yaml.safe_dump(cfg))
PY
chmod 755 "$work/kratos"
chmod 644 "$work/kratos"/*
kdsn="postgres://postgres:${src_pw}@${prefix}-pg:5432/src_kratos?sslmode=disable"
docker run --rm --network "$prefix-net" -v "$work/kratos:/etc/kratos:ro" -e DSN="$kdsn" "$kratos_image" migrate sql -e --yes -c /etc/kratos/kratos.yml >/dev/null 2>&1
docker run -d --name "$prefix-kratos" --network "$prefix-net" -v "$work/kratos:/etc/kratos:ro" -e DSN="$kdsn" -p 127.0.0.1::4434 "$kratos_image" serve -c /etc/kratos/kratos.yml >/dev/null
pg_port="$(docker port "$prefix-pg" 5432/tcp | head -1 | cut -d: -f2)"
k_port="$(docker port "$prefix-kratos" 4434/tcp | head -1 | cut -d: -f2)"
for _ in $(seq 60); do curl -fs "http://127.0.0.1:${k_port}/admin/health/ready" >/dev/null && break; sleep 1; done

step "source: seed the synthetic dataset"
host_dsn() { echo "postgres://postgres:${src_pw}@127.0.0.1:${pg_port}/src_$1?sslmode=disable"; }
SOURCE_IDENTITY_DSN="$(host_dsn identity)" SOURCE_VAULT_DSN="$(host_dsn vault)" \
  SOURCE_WORKFLOW_DSN="$(host_dsn workflow)" SOURCE_AUDIT_DSN="$(host_dsn audit)" \
  SOURCE_KRATOS_ADMIN_URL="http://127.0.0.1:${k_port}" \
  go run ./migrate/test/synth -s "$schema_dir" -k "$work/source-keys.json" -o "$work/source-summary.json" -e "$owner"
python3 - "$work/source-summary.json" <<'PY' | tee -a "$results"
import json, sys
s = json.load(open(sys.argv[1]))
print("source seeded: %d Kratos identities, %d secrets, %d secret versions, %d users, %d audit records"
      % (s["Kratos"], s["Rows"]["vault.secrets"], s["Rows"]["vault.secret_versions"], s["Rows"]["identity.users"], s["Rows"]["audit.audit_records"]))
PY

step "target: the umbrella chart in rehearsal mode"
scripts/build-deps.sh >/dev/null
# The services that check caller tokens fetch the cluster's signing keys from
# the API server, the one address rehearsal mode lets them reach.
api_ips="$(kubectl get endpoints kubernetes -n default -o jsonpath='{range .subsets[*].addresses[*]}{.ip}/32,{end}')"
api_port="$(kubectl get endpoints kubernetes -n default -o jsonpath='{.subsets[0].ports[0].port}')"
[ -n "$api_ips" ] && [ -n "$api_port" ] || fail "could not read the API server endpoints"
helm install "$release" charts/sneakers -n "$ns" --create-namespace \
  -f test/kind/values.yaml -f migrate/deploy/migrate-callers-values.yaml -f test/migrate/rehearsal-values.yaml \
  --set "rehearsal.apiServer.addresses={${api_ips%,}}" --set "rehearsal.apiServer.port=${api_port}" \
  --wait --timeout "$timeout"
kubectl -n "$ns" get pods

step "target: the import key"
recipient="$(docker run --rm --user "$(id -u):$(id -g)" -v "$work:/work" "$image" keygen --out /work/import.key)"
kubectl -n "$ns" create secret generic sneakers-migrate-key --from-file=import.key="$work/import.key" >/dev/null
note "import recipient: ${recipient}"

step "source: export"
keys() { python3 -c "import json,sys; print(json.load(open('$work/source-keys.json'))[sys.argv[1]])" "$1"; }
net_dsn() { echo "postgres://postgres:${src_pw}@${prefix}-pg:5432/src_$1?sslmode=disable"; }
docker run --rm --network "$prefix-net" --user "$(id -u):$(id -g)" -v "$work:/work" \
  -e SOURCE_IDENTITY_DSN="$(net_dsn identity)" -e SOURCE_VAULT_DSN="$(net_dsn vault)" \
  -e SOURCE_WORKFLOW_DSN="$(net_dsn workflow)" -e SOURCE_AUDIT_DSN="$(net_dsn audit)" \
  -e SOURCE_KRATOS_ADMIN_URL="http://${prefix}-kratos:4434" \
  -e SOURCE_VAULT_ROOT_KEK="$(keys SOURCE_VAULT_ROOT_KEK)" -e SOURCE_DEV_KEK_SEED="$(keys SOURCE_DEV_KEK_SEED)" \
  -e SOURCE_TOTP_ENC_KEY="$(keys SOURCE_TOTP_ENC_KEY)" \
  "$image" export --recipient "$recipient" --out /work/bundle.age | tee "$work/export.txt"
note "bundle: $(stat -c %s "$work/bundle.age") bytes, encrypted"
kubectl -n "$ns" create secret generic sneakers-migrate-bundle --from-file=bundle.age="$work/bundle.age" >/dev/null

# run_job <name> <expected exit code> <command args as YAML flow items>
run_job() {
  local name="$1" want="$2" args="$3" code=""
  kubectl -n "$ns" delete job "$name" --ignore-not-found --wait >/dev/null
  NAMESPACE="$ns" JOB_NAME="$name" MIGRATE_IMAGE="$image" COMMAND_ARGS="[$args]" \
    envsubst '${NAMESPACE} ${JOB_NAME} ${MIGRATE_IMAGE} ${COMMAND_ARGS}' <migrate/deploy/import-job.yaml |
    sed 's/imagePullPolicy: IfNotPresent/imagePullPolicy: Never/' | kubectl apply -f - >/dev/null
  for _ in $(seq 300); do
    code="$(kubectl -n "$ns" get pods -l "job-name=$name" -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null || true)"
    [ -n "$code" ] && break
    sleep 2
  done
  # The rehearsal owner password line is shown once, on the terminal of a
  # real run; the CI log never carries it.
  kubectl -n "$ns" logs "job/$name" | grep -v "(shown once)" | tee "$work/$name.log"
  [ -n "$code" ] || fail "$name did not finish"
  [ "$code" = "$want" ] || fail "$name exited $code, want $want"
  note "$name: exit $code (as expected)"
}

psql_target() { # db sql
  kubectl -n "$ns" exec sneakers-postgres-0 -- sh -c "PGPASSWORD=\"\$POSTGRES_PASSWORD\" psql -U \"\$POSTGRES_USER\" -tA -d $1 -c \"$2\""
}

step "import (Job, rehearsal mode)"
run_job sneakers-migrate-import 0 '"import", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key", "--rehearsal", "--owner-email", "'"$owner"'"'
grep -q "^rehearsal sign-in for $owner" <(kubectl -n "$ns" logs job/sneakers-migrate-import) || fail "the owner password was not shown"
note "owner sign-in password: shown once, kept out of this log"

step "restart the vault so it loads the imported state"
kubectl -n "$ns" rollout restart deployment/sneakers-vault >/dev/null
kubectl -n "$ns" rollout status deployment/sneakers-vault --timeout 5m

step "verify (Job)"
run_job sneakers-migrate-verify 0 '"verify", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key"'
sed -n '/^verify /,$p' "$work/sneakers-migrate-verify.log" >>"$results"

step "negative: rehearsal mode blocks egress"
test_image="$(python3 - <<'PY'
import yaml
i = yaml.safe_load(open("charts/sneakers/values.yaml"))["tests"]["image"]
print("%s:%s@%s" % (i["repository"], i["tag"], i["digest"]))
PY
)"
# kindnet's policy engine only filters a pod once its IP is in its pod set and
# lets traffic through until then, so each probe waits before connecting.
probe() { # namespace name url [labels]: prints the curl exit code
  kubectl -n "$1" run "$2" --image="$test_image" --restart=Never --quiet --labels="${4:-app.kubernetes.io/part-of=sneakers}" \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}}}' \
    --command -- sh -c "sleep 10; curl -sk -m 5 -o /dev/null $3; echo \$?" >/dev/null
  kubectl -n "$1" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$2" --timeout=120s >/dev/null
  kubectl -n "$1" logs "$2" | tail -1
  kubectl -n "$1" delete pod "$2" --wait=false >/dev/null
}
outside_ns="${ns}-outside"
kubectl create namespace "$outside_ns" >/dev/null
api=https://kubernetes.default.svc/healthz
inside="$(probe "$ns" egress-rehearsal "$api")"
control="$(probe "$outside_ns" egress-control "$api")"
# Each service admits only its callers, so this probe is the migrate caller.
in_ns="$(probe "$ns" egress-in-namespace http://sneakers-vault:9091/ app.kubernetes.io/part-of=sneakers,app.kubernetes.io/component=migrate,app.kubernetes.io/instance=${release})"
kubectl delete namespace "$outside_ns" --wait=false >/dev/null
note "egress to the cluster API from the rehearsal namespace: curl exit ${inside} (28 = timed out)"
note "egress to the cluster API from another namespace (control): curl exit ${control}"
note "a service inside the rehearsal namespace: curl exit ${in_ns}"
[ "$inside" = 28 ] || fail "a rehearsal pod reached outside its namespace"
[ "$control" = 0 ] || fail "the control probe could not reach the cluster API (exit $control)"
[ "$in_ns" != 28 ] && [ "$in_ns" != 6 ] || fail "a rehearsal pod could not reach a service in its own namespace"

step "negative: rehearsal mode runs no automation"
for d in connector sshbroker mcp; do
  if kubectl -n "$ns" get deployment "sneakers-$d" >/dev/null 2>&1; then fail "sneakers-$d is deployed in rehearsal mode"; fi
done
claims="$(psql_target sneakers_vault "SELECT (SELECT count(*) FROM rotation_schedule WHERE claimed_until IS NOT NULL) + (SELECT count(*) FROM heartbeat_schedule WHERE claimed_until IS NOT NULL)")"
kek_days="$(psql_target sneakers_vault "SELECT coalesce(data->>'kekRotationDays', '0') FROM security_settings")"
note "connector, SSH broker and MCP not deployed; rotation and heartbeat claims after the run: ${claims}; KEK rotation days: ${kek_days}"
[ "$claims" = 0 ] || fail "rotation or heartbeat work was claimed in rehearsal mode"
[ "$kek_days" = 0 ] || fail "KEK rotation is on in rehearsal mode"

step "negative: an import into a target holding other data is refused"
psql_target sneakers_identity "INSERT INTO users (id, name, email) VALUES ('usr-foreign', 'Foreign User', 'foreign@example.org')" >/dev/null
run_job sneakers-migrate-import-foreign 3 '"import", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key", "--rehearsal"'
grep -q "already holds data that is not this bundle" "$work/sneakers-migrate-import-foreign.log" || fail "the refusal did not say why"
psql_target sneakers_identity "DELETE FROM users WHERE id = 'usr-foreign'" >/dev/null

step "negative: a tampered audit record fails verify"
psql_target sneakers_audit "UPDATE audit_records SET subject = 'tampered' WHERE seq = 500" >/dev/null
run_job sneakers-migrate-verify-tampered 4 '"verify", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key"'
grep -q "audit chain" "$work/sneakers-migrate-verify-tampered.log" || fail "verify did not name the audit chain"
note "tampered record: $(grep -m1 'FAIL\] audit chain' "$work/sneakers-migrate-verify-tampered.log" | sed 's/^ *//')"

step "results"
cat "$results"
echo
echo "migration rehearsal passed"
