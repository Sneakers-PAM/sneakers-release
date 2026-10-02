#!/usr/bin/env bash
# The install test, against the current kubectl context (a throwaway kind
# cluster): install the umbrella with the bundled pieces, upgrade it in place
# and check the generated secrets survive, run helm test, and check that the
# NetworkPolicies refuse a pod from outside the release.
set -euo pipefail
cd "$(dirname "$0")/../.."
ns="${NAMESPACE:-sneakers}"
release=sneakers
timeout="${HELM_TIMEOUT:-15m}"

secret_hashes() {
  for s in sneakers-bundled sneakers-kratos sneakers-vault-generated sneakers-identity-generated; do
    printf '%s %s\n' "$s" "$(kubectl -n "$ns" get secret "$s" -o jsonpath='{.data}' | sha256sum | cut -c1-16)"
  done
}

echo "== dependencies"
scripts/build-deps.sh

echo "== install"
helm install "$release" charts/sneakers -n "$ns" --create-namespace -f test/kind/values.yaml --wait --timeout "$timeout"
kubectl -n "$ns" get pods

echo "== upgrade in place"
before="$(secret_hashes)"
helm upgrade "$release" charts/sneakers -n "$ns" -f test/kind/values.yaml --wait --timeout "$timeout"
after="$(secret_hashes)"
if [ "$before" != "$after" ]; then
  echo "generated secrets changed on upgrade:" >&2
  diff <(echo "$before") <(echo "$after") >&2 || true
  exit 1
fi
echo "generated secrets unchanged"

echo "== helm test"
helm test "$release" -n "$ns" --timeout 10m --logs

echo "== NetworkPolicy"
test_image="$(python3 - <<'PY'
import yaml
i = yaml.safe_load(open("charts/sneakers/values.yaml"))["tests"]["image"]
print("%s:%s@%s" % (i["repository"], i["tag"], i["digest"]))
PY
)"
probe() { # name extra-label url: prints the curl exit code
  kubectl -n "$ns" run "$1" --image="$test_image" --restart=Never --quiet ${2:+--labels="$2"} \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}}}' \
    --command -- sh -c "curl -s -m 5 -o /dev/null $3; echo \$?" >/dev/null
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$1" --timeout=60s >/dev/null
  kubectl -n "$ns" logs "$1" | tail -1
  kubectl -n "$ns" delete pod "$1" --wait=false >/dev/null
}
outside="$(probe np-outside "" http://sneakers-vault:9091/)"
inside="$(probe np-inside app.kubernetes.io/part-of=sneakers http://sneakers-vault:9091/)"
echo "vault from outside the release: curl exit ${outside} (28 = timed out)"
echo "vault from inside the release: curl exit ${inside}"
[ "$outside" = 28 ] || { echo "the vault NetworkPolicy let an outside pod connect" >&2; exit 1; }
[ "$inside" != 28 ] || { echo "the vault NetworkPolicy blocked a pod of the release" >&2; exit 1; }

echo "install test passed"
