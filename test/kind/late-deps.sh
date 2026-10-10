#!/usr/bin/env bash
# Cold start with the databases late, against an installed release (run after
# run.sh): stop PostgreSQL, Kratos and Hydra, restart every other workload so
# it boots while they're gone, bring PostgreSQL back after LATE seconds
# (default 60) and Kratos and Hydra once it's ready, then check every pod
# reaches Ready without a single container restart. A service that exits
# while a dependency isn't up yet, or a probe that kills one that is only
# waiting, shows up here as a restart.
set -euo pipefail
ns="${NAMESPACE:-sneakers}"
late="${LATE:-60}"
timeout="${ROLLOUT_TIMEOUT:-600s}"
k() { kubectl -n "$ns" "$@"; }

ory=()
for d in sneakers-kratos sneakers-hydra; do
  k get deployment "$d" >/dev/null 2>&1 && ory+=("$d")
done

echo "== stop PostgreSQL and ${ory[*]}"
k scale statefulset/sneakers-postgres --replicas=0
for d in "${ory[@]}"; do k scale "deployment/$d" --replicas=0; done
k wait --for=delete pod -l app.kubernetes.io/component=postgres --timeout=120s || true
for d in "${ory[@]}"; do
  k wait --for=delete pod -l "app.kubernetes.io/name=${d#sneakers-}" --timeout=120s || true
done

echo "== restart every other workload while they're down"
others=()
while read -r d; do
  case " ${ory[*]} " in *" $d "*) continue ;; esac
  others+=("$d")
done < <(k get deployments -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
for d in "${others[@]}"; do k rollout restart "deployment/$d" >/dev/null; done
echo "restarted: ${others[*]}"

echo "== PostgreSQL comes back in ${late}s"
sleep "$late"
k get pods -o wide
k scale statefulset/sneakers-postgres --replicas=1
k rollout status statefulset/sneakers-postgres --timeout="$timeout"
for d in "${ory[@]}"; do
  k scale "deployment/$d" --replicas=1
done

echo "== everything ready"
for d in "${ory[@]}" "${others[@]}"; do k rollout status "deployment/$d" --timeout="$timeout"; done

echo "== no container restarted"
# Pods owned by a ReplicaSet or StatefulSet (the Job and test pods are left
# out): every container and init container must show restartCount 0.
report="$(k get pods -o json | python3 -c '
import json, sys
bad = 0
for p in json.load(sys.stdin)["items"]:
    owners = [o["kind"] for o in p["metadata"].get("ownerReferences", [])]
    if not set(owners) & {"ReplicaSet", "StatefulSet"} or p["metadata"].get("deletionTimestamp"):
        continue
    st = p["status"]
    statuses = st.get("initContainerStatuses", []) + st.get("containerStatuses", [])
    ready = any(c["type"] == "Ready" and c["status"] == "True" for c in st.get("conditions", []))
    for c in statuses:
        n = c["restartCount"]
        last = (c.get("lastState") or {}).get("terminated") or {}
        flag = "" if n == 0 and ready else "  <-- " + ("not ready" if n == 0 else "restarted (%s, exit %s)" % (last.get("reason"), last.get("exitCode")))
        bad += flag != ""
        print("%-45s %-22s restarts=%d%s" % (p["metadata"]["name"], c["name"], n, flag))
print("BAD=%d" % bad)
')"
echo "$report"
if ! grep -q '^BAD=0$' <<<"$report"; then
  echo "a pod restarted or isn't ready after a cold start with PostgreSQL ${late}s late" >&2
  k get events --sort-by=.lastTimestamp | tail -40 >&2
  exit 1
fi
echo "late-dependency cold start passed"
