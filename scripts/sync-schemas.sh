#!/usr/bin/env bash
# Every service chart validates its values with the one schema in
# charts/sneakers-lib/service.schema.json. This copies it into each chart, or
# with --check fails when a copy differs.
set -euo pipefail
cd "$(dirname "$0")/.."
src=charts/sneakers-lib/service.schema.json
services=(identity vault workflow audit notify connector sshbroker gateway mcp)
status=0
for svc in "${services[@]}"; do
  dst="charts/${svc}/values.schema.json"
  if [ "${1:-}" = "--check" ]; then
    if ! cmp -s "$src" "$dst"; then
      echo "out of date: ${dst} (run scripts/sync-schemas.sh)" >&2
      status=1
    fi
  else
    cp "$src" "$dst"
  fi
done
exit "$status"
