#!/usr/bin/env bash
# The install test, against the current kubectl context (a throwaway kind
# cluster): install the umbrella with the bundled pieces, upgrade it in place
# and check the generated secrets survive, run helm test (which checks both web
# apps' health), check that each service's port takes only the callers in the
# call graph and that the web apps reach only the gateway, that a callee
# refuses a caller with the wrong service account, and that both web apps
# render a page. BASE_VALUES names values files (space-separated) applied
# before test/kind/values.yaml, such as a sizing example; the test's own
# values (the images built in the job, Hydra on) still win.
set -euo pipefail
cd "$(dirname "$0")/../.."
ns="${NAMESPACE:-sneakers}"
release=sneakers
timeout="${HELM_TIMEOUT:-15m}"
values=()
for f in ${BASE_VALUES:-}; do values+=(-f "$f"); done
values+=(-f test/kind/values.yaml)

secret_hashes() {
  for s in sneakers-bundled sneakers-kratos sneakers-vault-generated sneakers-identity-generated; do
    printf '%s %s\n' "$s" "$(kubectl -n "$ns" get secret "$s" -o jsonpath='{.data}' | sha256sum | cut -c1-16)"
  done
}

echo "== dependencies"
scripts/build-deps.sh

echo "== install"
helm install "$release" charts/sneakers -n "$ns" --create-namespace "${values[@]}" --wait --timeout "$timeout"
kubectl -n "$ns" get pods

echo "== upgrade in place"
before="$(secret_hashes)"
helm upgrade "$release" charts/sneakers -n "$ns" "${values[@]}" --wait --timeout "$timeout"
after="$(secret_hashes)"
if [ "$before" != "$after" ]; then
  echo "generated secrets changed on upgrade:" >&2
  diff <(echo "$before") <(echo "$after") >&2 || true
  exit 1
fi
echo "generated secrets unchanged"

echo "== helm test"
helm test "$release" -n "$ns" --timeout 10m --logs

echo "== NetworkPolicies per edge"
test_image="$(python3 - <<'PY2'
import yaml
i = yaml.safe_load(open("charts/sneakers/values.yaml"))["tests"]["image"]
print("%s:%s@%s" % (i["repository"], i["tag"], i["digest"]))
PY2
)"

# callee: the services allowed on its gRPC port (scripts/check-edges.py has the
# same table for the rendered charts).
declare -A callers=(
  [vault]="gateway workflow sshbroker connector"
  [workflow]="gateway"
  [sshbroker]="gateway"
  [audit]="gateway vault sshbroker identity workflow"
  [notify]="vault gateway"
  [identity]="gateway notify"
  [connector]=""
)
declare -A grpc_port=([vault]=9091 [workflow]=9193 [sshbroker]=9096 [audit]=9194 [notify]=9195 [identity]=9192 [connector]=9196)
# The bundled pieces, by Service address: the services allowed to connect
# (scripts/check-edges.py has the same table).
declare -A bundled=(
  [sneakers-kratos-public:80]="gateway"
  [sneakers-kratos-admin:80]="identity gateway"
  [sneakers-hydra-admin:4445]=""
  [sneakers-valkey:6379]="gateway vault notify sshbroker"
  [sneakers-postgres:5432]="identity vault workflow audit"
)
edge_targets="sneakers-gateway:9100 sneakers-sshbroker:9097 sneakers-hydra-public:4444 sneakers-web-staff:3000 sneakers-web-admin:3000"
targets="$edge_targets"
for svc in "${!grpc_port[@]}"; do targets+=" sneakers-${svc}:${grpc_port[$svc]}"; done
for t in "${!bundled[@]}"; do targets+=" $t"; done

# pod <name> <component or -> <service account> <image> <script>: a one-shot
# pod. With a component it carries that service's component labels, which its
# callees' NetworkPolicies match, and a caller token with audience sneakers. It
# never carries the service's name label, so the service's own Service doesn't
# route to it; the MCP and staff app probes do, so their egress policies apply.
pod() {
  local name="$1" comp="$2" sa="$3" image="$4" script="$5" labels mounts="" volumes=""
  labels="edge-probe: \"$name\""
  if [ "$comp" != - ]; then
    labels+="
    app.kubernetes.io/part-of: sneakers
    app.kubernetes.io/instance: ${release}
    app.kubernetes.io/component: ${comp}"
    case "$comp" in mcp | web-staff) labels+="
    app.kubernetes.io/name: sneakers-${comp}" ;; esac
    mounts="volumeMounts: [{name: token, mountPath: /var/run/secrets/sneakers, readOnly: true}]"
    volumes="volumes: [{name: token, projected: {sources: [{serviceAccountToken: {audience: sneakers, expirationSeconds: 600, path: token}}]}}]"
  fi
  kubectl -n "$ns" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    ${labels}
spec:
  restartPolicy: Never
  serviceAccountName: ${sa}
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: ${image}
      command: [/bin/sh, -c]
      args: [$(printf '%s' "$script" | python3 -c 'import json, sys; print(json.dumps(sys.stdin.read()))')]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      ${mounts}
  ${volumes}
EOF
}
wait_logs() {
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$1" --timeout=180s >/dev/null
  kubectl -n "$ns" logs "$1"
  kubectl -n "$ns" delete pod "$1" --wait=false >/dev/null
}
want() { # <probe> <host:port>: open or refused
  local probe="$1" target="$2" svc port
  svc="${target%%:*}"; svc="${svc#sneakers-}"; port="${target#*:}"
  if [ "$probe" = web-staff ]; then
    [ "$target" = sneakers-gateway:9100 ] && echo open || echo refused
    return
  fi
  if [ "$probe" = mcp ]; then
    case "$target" in sneakers-gateway:9100 | sneakers-hydra-public:4444) echo open ;; *) echo refused ;; esac
    return
  fi
  case " $edge_targets " in *" $target "*) echo open; return ;; esac
  if [ -n "${bundled[$target]+set}" ]; then
    case " ${bundled[$target]} " in *" $probe "*) echo open ;; *) echo refused ;; esac
    return
  fi
  if [ "$port" = "${grpc_port[$svc]:-}" ]; then
    case " ${callers[$svc]} " in *" $probe "*) echo open; return ;; esac
  fi
  echo refused
}

connect_script="for t in ${targets}; do curl -s -m 3 -o /dev/null http://\$t/; echo \"\$t \$?\"; done"
probes="outside mcp web-staff gateway vault workflow sshbroker connector notify identity"
for p in $probes; do
  comp="$p"; [ "$p" = outside ] && comp=-
  pod "np-${p}" "$comp" default "$test_image" "$connect_script"
done

failed=0
for p in $probes; do
  results="$(wait_logs "np-${p}")"
  for t in $targets; do
    code="$(awk -v t="$t" '$1 == t {print $2}' <<<"$results")"
    got=open; [ "$code" = 28 ] && got=refused
    w="$(want "$p" "$t")"
    printf '%-9s -> %-26s %-8s (curl exit %s)\n' "$p" "$t" "$got" "$code"
    [ "$got" = "$w" ] || { echo "  want ${w}" >&2; failed=1; }
  done
done
[ "$failed" = 0 ] || { echo "a NetworkPolicy does not match the call graph" >&2; exit 1; }

echo "== callees check the caller's service account"
# Pods with a caller's labels pass the NetworkPolicies; the callee must still
# refuse a token from a service account it doesn't list (Unauthenticated), a
# listed caller on a method outside its allow-list (PermissionDenied), and a
# call with no token (Unauthenticated).
# call <service:port> <method> [token]: one unary gRPC call with an empty
# request, sent raw over HTTP/2 so the callee's check runs on the method itself
# (grpcurl's reflection lookup would be checked first). Prints grpc-status.
call() {
  local auth=""
  [ "${3:-}" = token ] && auth='-H "authorization: Bearer $(cat /var/run/secrets/sneakers/token)"'
  printf "printf '\\\\000\\\\000\\\\000\\\\000\\\\000' | curl -s -m 10 --http2-prior-knowledge -o /dev/null -D - -H 'content-type: application/grpc' -H 'te: trailers' %s --data-binary @- http://%s/%s | grep -i '^grpc-'" "$auth" "$1" "$2"
}
reveal=sneakers.vault.v1.VaultService/RevealSecretField
pod tok-wrong-vault gateway sneakers-mcp "$test_image" "$(call sneakers-vault:9091 "$reveal" token)"
pod tok-wrong-broker gateway sneakers-mcp "$test_image" "$(call sneakers-sshbroker:9096 sneakers.sshbroker.v1.SSHBrokerService/CreateSession token)"
pod tok-connector-vault connector sneakers-connector "$test_image" "$(call sneakers-vault:9091 "$reveal" token)"
pod tok-none-vault gateway sneakers-gateway "$test_image" "$(call sneakers-vault:9091 "$reveal")"
pod tok-right-vault gateway sneakers-gateway "$test_image" "$(call sneakers-vault:9091 "$reveal" token)"
# 16 is Unauthenticated, 7 PermissionDenied.
expect() { # <pod> <grpc-status pattern> <yes|no> <what>
  local out code
  out="$(wait_logs "$1")"
  code="$(awk -F': *' 'tolower($1) == "grpc-status" {gsub(/\r/, "", $2); print $2; exit}' <<<"$out")"
  echo "$1: grpc-status ${code:-none}"
  if [[ "$code" =~ ^($2)$ ]]; then [ "$3" = yes ] && return 0; else [ "$3" = no ] && return 0; fi
  echo "$4" >&2
  echo "$out" >&2
  failed=1
}
expect tok-wrong-vault 16 yes "the vault took a token from sneakers-mcp"
expect tok-wrong-broker 16 yes "the broker took a token from sneakers-mcp"
expect tok-connector-vault 7 yes "the vault let the connector call a user-facing method"
expect tok-none-vault 16 yes "the vault took a call with no token"
expect tok-right-vault '16|7|' no "the vault refused the gateway's token"
[ "$failed" = 0 ] || exit 1

echo "== web apps render"
# Each app renders a page (its sign-in, after redirects) through the live
# gateway: 200 after at most a few redirects.
page() { # name url: prints the final HTTP status
  kubectl -n "$ns" run "$1" --image="$test_image" --restart=Never --quiet \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}}}}' \
    --command -- curl -s -m 20 -L --max-redirs 5 -o /dev/null -w '%{http_code}' "$2" >/dev/null
  kubectl -n "$ns" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$1" --timeout=60s >/dev/null
  kubectl -n "$ns" logs "$1"
  kubectl -n "$ns" delete pod "$1" --wait=false >/dev/null
}
staff="$(page web-staff-page http://sneakers-web-staff:3000/)"
admin="$(page web-admin-page http://sneakers-web-admin:3000/admin/)"
echo "staff /: HTTP ${staff}; admin /admin/: HTTP ${admin}"
[ "$staff" = 200 ] || { echo "the staff app didn't render" >&2; exit 1; }
[ "$admin" = 200 ] || { echo "the admin app didn't render" >&2; exit 1; }

echo "install test passed"
