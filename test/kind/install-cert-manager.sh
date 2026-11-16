#!/usr/bin/env bash
# Installs cert-manager into the current kubectl context (a throwaway kind
# cluster) for the install test, which runs with global.internalTLS on: the chart
# issues one certificate per service from a CA it creates, so cert-manager's CRDs,
# controller, webhook and cainjector must be up before helm install. The manifest
# is upstream's static one, checked against the SHA-256 the appliance's box stack
# checks (build/product/cert-manager/upstream.sha256 in sneakers-appliance), at
# the version manifest/release.yaml pins. A different version needs its sum here.
set -euo pipefail
cd "$(dirname "$0")/../.."
CERT_MANAGER_VERSION="v1.21.2"
CERT_MANAGER_SHA256="e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f"
url="https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "== cert-manager ${CERT_MANAGER_VERSION}"
curl -fsSL --retry 3 -o "$tmp/cert-manager.yaml" "$url"
got="$(sha256sum "$tmp/cert-manager.yaml" | cut -d' ' -f1)"
if [ "$got" != "$CERT_MANAGER_SHA256" ]; then
  echo "cert-manager manifest sum ${got}, want ${CERT_MANAGER_SHA256}" >&2
  exit 1
fi
kubectl apply -f "$tmp/cert-manager.yaml" >/dev/null
# The webhook must answer, and the cainjector must have put its CA in the webhook configuration, before the first
# Issuer or Certificate is accepted.
kubectl -n cert-manager rollout status deploy/cert-manager deploy/cert-manager-webhook deploy/cert-manager-cainjector --timeout=180s
kubectl -n cert-manager get pods
