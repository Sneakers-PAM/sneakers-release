#!/usr/bin/env bash
# PostgreSQL stops cleanly, against an installed release (run after run.sh):
# write rows, stop the server the way every stop does (a scale to 0 and a pod
# delete, each with the pod's own grace period), and after each check the old
# server wrote its shutdown checkpoint (the next start says "database system
# was shut down", not that it has to recover), the stop hook didn't fail, the
# server never needed the kubelet's kill, and every row is there.
set -euo pipefail
ns="${NAMESPACE:-sneakers}"
timeout="${ROLLOUT_TIMEOUT:-600s}"
pod=sneakers-postgres-0
k() { kubectl -n "$ns" "$@"; }
psql() { k exec "$pod" -c postgres -- psql -U postgres -d postgres -qtAX -v ON_ERROR_STOP=1 -c "$1"; }

k rollout status statefulset/sneakers-postgres --timeout="$timeout"
psql "CREATE TABLE IF NOT EXISTS clean_stop_rows (id bigserial PRIMARY KEY, v text NOT NULL)"
psql "INSERT INTO clean_stop_rows (v) SELECT md5(g::text) FROM generate_series(1, 5000) g"
want="$(psql "SELECT count(*) FROM clean_stop_rows")"
echo "rows written: $want"

# check <how>: the new server's start was a clean one, the old pod's stop hook
# didn't fail, and the rows are all there.
check() {
  local how="$1" log got
  k rollout status statefulset/sneakers-postgres --timeout="$timeout"
  k wait --for=condition=Ready "pod/$pod" --timeout="$timeout"
  log="$(k logs "$pod" -c postgres)"
  if grep -q 'not properly shut down\|database system was interrupted\|automatic recovery in progress' <<<"$log"; then
    echo "after $how: PostgreSQL started with a crash recovery: the stop didn't finish its shutdown checkpoint" >&2
    grep -n 'database system\|recovery\|redo' <<<"$log" >&2 || true
    exit 1
  fi
  if ! grep -q 'database system was shut down at' <<<"$log"; then
    echo "after $how: no clean start in the log" >&2
    head -40 <<<"$log" >&2
    exit 1
  fi
  if k get events --field-selector "involvedObject.name=$pod,reason=FailedPreStopHook" -o name | grep -q .; then
    echo "after $how: the stop hook failed" >&2
    k get events --field-selector "involvedObject.name=$pod,reason=FailedPreStopHook" >&2
    exit 1
  fi
  got="$(psql "SELECT count(*) FROM clean_stop_rows")"
  if [ "$got" != "$want" ]; then
    echo "after $how: $got rows, want $want" >&2
    exit 1
  fi
  echo "after $how: a clean start, $got of $want rows"
}

# stopped_within <seconds> <started>: the old server was gone well before the
# grace period ran out, so it exited by itself rather than by the kill.
stopped_within() {
  local took=$(( $(date +%s) - $2 ))
  echo "the old server was gone in ${took}s"
  if [ "$took" -ge "$1" ]; then
    echo "the stop took ${took}s, the whole grace period: the kubelet killed the server" >&2
    exit 1
  fi
}

grace="$(k get statefulset sneakers-postgres -o jsonpath='{.spec.template.spec.terminationGracePeriodSeconds}')"
echo "grace period: ${grace}s"

echo "== a scale to 0 and back"
start=$(date +%s)
k scale statefulset/sneakers-postgres --replicas=0
k wait --for=delete "pod/$pod" --timeout="$((grace + 60))s"
stopped_within "$grace" "$start"
k scale statefulset/sneakers-postgres --replicas=1
check "a scale to 0"

echo "== a pod delete"
start=$(date +%s)
k delete pod "$pod" --wait=true --timeout="$((grace + 60))s"
stopped_within "$grace" "$start"
check "a pod delete"

psql "DROP TABLE clean_stop_rows"
echo "clean stop passed"
