#!/usr/bin/env bash
# Hold the postgres-ha chart scripts/build-deps.sh fetched to the digest
# manifest/release.yaml pins. A chart version in an OCI registry can be pushed
# again, and a pull by digest can't give any other chart. PGHA_CHART is the
# packaged chart to check (default: the umbrella's); HELM is the helm binary.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
helm="${HELM:-helm}"
block="$(awk '/^    postgres-ha:$/ { on = 1; next } on && /^    [^ ]/ { on = 0 } on' "$here/manifest/release.yaml")"
repo="$(sed -n 's/^ *repository: //p' <<<"$block")"
version="$(sed -n '/^ *chart:/,/repository:/s/^ *version: //p' <<<"$block")"
digest="$(sed -n '/repository:/{n;s/^ *digest: //p;}' <<<"$block")"
[ -n "$repo" ] && [ -n "$version" ] && [ -n "$digest" ] || { echo "manifest/release.yaml pins no postgres-ha chart" >&2; exit 1; }
chart="${PGHA_CHART:-$here/charts/sneakers/charts/postgres-ha-$version.tgz}"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
"$helm" pull "$repo/postgres-ha@$digest" --destination "$dir" >/dev/null
cmp -s "$chart" "$dir"/*.tgz || { echo "$chart isn't the chart at $digest" >&2; exit 1; }
echo "ok: postgres-ha $version is the chart at $digest"
