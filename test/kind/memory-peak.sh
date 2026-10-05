#!/usr/bin/env bash
# Print the peak memory of every pod in the namespace, read from the kind
# node's cgroups (memory.peak, cgroup v2), and their sum. With MEMORY_BUDGET
# set (a number of MiB), fail when the sum is over it. Run it after the
# install test, while the release's pods are still up.
set -euo pipefail
ns="${NAMESPACE:-sneakers}"
node="${KIND_CLUSTER:-sneakers}-control-plane"
budget="${MEMORY_BUDGET:-}"

total=0
missing=0
printf '%-48s %10s\n' pod "peak MiB"
while read -r name uid; do
  # The kubelet's systemd cgroup driver names the pod's slice after its UID,
  # with the dashes as underscores.
  dir="$(docker exec "$node" find /sys/fs/cgroup -maxdepth 5 -type d -name "*pod${uid//-/_}.slice" 2>/dev/null | head -n 1)"
  if [ -z "$dir" ]; then
    dir="$(docker exec "$node" find /sys/fs/cgroup -maxdepth 5 -type d -name "pod${uid}" 2>/dev/null | head -n 1)"
  fi
  if [ -z "$dir" ]; then
    echo "::warning::no cgroup found for pod ${name}"
    missing=$((missing + 1))
    continue
  fi
  bytes="$(docker exec "$node" cat "${dir}/memory.peak" 2>/dev/null || true)"
  if [ -z "$bytes" ]; then
    echo "::warning::${dir} has no memory.peak (kernel older than 5.19); using memory.current for ${name}"
    bytes="$(docker exec "$node" cat "${dir}/memory.current")"
  fi
  mib=$((bytes / 1048576))
  total=$((total + mib))
  printf '%-48s %10d\n' "$name" "$mib"
done < <(kubectl -n "$ns" get pods --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.uid}{"\n"}{end}')
printf '%-48s %10d\n' total "$total"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "Peak memory of the pods in ${ns}: ${total} MiB${budget:+ (budget ${budget} MiB)}" >>"$GITHUB_STEP_SUMMARY"
fi
[ "$missing" = 0 ] || { echo "could not read the memory of ${missing} pod(s)" >&2; exit 1; }
if [ -n "$budget" ] && [ "$total" -gt "$budget" ]; then
  echo "the pods peaked at ${total} MiB, over the budget of ${budget} MiB" >&2
  exit 1
fi
echo "ok: the pods peaked at ${total} MiB${budget:+, within ${budget} MiB}"
