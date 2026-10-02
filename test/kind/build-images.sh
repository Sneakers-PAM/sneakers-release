#!/usr/bin/env bash
# Build every service image from its repository with the repository's own
# Dockerfile, load it into the kind cluster, and remove the local copy. Nothing
# is pushed anywhere. SERVICES_FROM_MAIN=true builds each repository's main
# instead of the ref pinned in services.txt.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cluster="${KIND_CLUSTER:-sneakers}"
from_main="${SERVICES_FROM_MAIN:-false}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

grep -v -E '^\s*(#|$)' "$here/services.txt" | while read -r image repo ref target buildargs; do
  [ "$from_main" = true ] && ref=main
  src="$work/${image}"
  echo "::group::${image} from ${repo}@${ref}"
  git init -q "$src"
  git -C "$src" fetch -q --depth 1 "https://github.com/${repo}.git" "$ref"
  git -C "$src" checkout -q FETCH_HEAD
  echo "commit $(git -C "$src" rev-parse HEAD)"
  args=(-t "ci.example.org/${image}:ci")
  [ "$target" = - ] || args+=(--target "$target")
  if [ -n "${buildargs:-}" ]; then
    IFS=, read -r -a pairs <<<"$buildargs"
    for kv in "${pairs[@]}"; do args+=(--build-arg "$kv"); done
  fi
  docker build -q "${args[@]}" "$src"
  kind load docker-image "ci.example.org/${image}:ci" --name "$cluster"
  docker rmi -f "ci.example.org/${image}:ci" >/dev/null
  rm -rf "$src"
  echo "::endgroup::"
done
