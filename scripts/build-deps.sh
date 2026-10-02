#!/usr/bin/env bash
# Resolve every chart's dependencies: the library into each service chart
# first, then the umbrella (which packages the service charts with it).
set -euo pipefail
cd "$(dirname "$0")/.."
helm repo add valkey https://valkey.io/valkey-helm/ --force-update >/dev/null
helm repo add ory https://k8s.ory.sh/helm/charts --force-update >/dev/null
for svc in identity vault workflow audit notify connector sshbroker gateway mcp web-staff web-admin; do
  helm dependency build "charts/${svc}" >/dev/null
done
helm dependency build charts/sneakers >/dev/null
echo "chart dependencies built"
