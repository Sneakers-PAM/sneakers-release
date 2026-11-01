#!/usr/bin/env bash
# Fetch the postgres-ha chart at the digest manifest/release.yaml pins and unpack
# it into the directory given (default: a new one), printing the chart's path, for
# a render or an install. A pull by digest can't give any other chart. HELM is
# the helm binary.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
helm="${HELM:-helm}"
block="$(awk '/^    postgres-ha:$/ { on = 1; next } on && /^    [^ ]/ { on = 0 } on' "$here/manifest/release.yaml")"
repo="$(sed -n 's/^ *repository: //p' <<<"$block")"
digest="$(sed -n '/repository:/{n;s/^ *digest: //p;}' <<<"$block")"
[ -n "$repo" ] && [ -n "$digest" ] || { echo "manifest/release.yaml pins no postgres-ha chart" >&2; exit 1; }
dir="${1:-$(mktemp -d)}"
mkdir -p "$dir"
"$helm" pull "$repo/postgres-ha@$digest" --untar --untardir "$dir" >/dev/null
echo "$dir/postgres-ha"
