#!/usr/bin/env bash
# Install the pinned chart tools into a directory (default: ./bin), checking
# each download against its published SHA-256. Usage:
#   scripts/install-tools.sh [dir] [helm kubeconform kind kubectl]
set -euo pipefail
dir="${1:-bin}"
shift || true
tools=("$@")
[ "${#tools[@]}" -gt 0 ] || tools=(helm kubeconform)

HELM_VERSION=v4.3.0
HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
KUBECONFORM_VERSION=v0.8.0
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=v1.36.4
KUBECTL_SHA256=8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a

mkdir -p "$dir"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 file
  curl -fsSL --retry 3 -o "$work/$3" "$1"
  echo "$2  $work/$3" | sha256sum -c --quiet -
}

for tool in "${tools[@]}"; do
  case "$tool" in
    helm)
      fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" "$HELM_SHA256" helm.tgz
      tar -xzf "$work/helm.tgz" -C "$work" linux-amd64/helm
      install -m 0755 "$work/linux-amd64/helm" "$dir/helm" ;;
    kubeconform)
      fetch "https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/kubeconform-linux-amd64.tar.gz" "$KUBECONFORM_SHA256" kubeconform.tgz
      tar -xzf "$work/kubeconform.tgz" -C "$work" kubeconform
      install -m 0755 "$work/kubeconform" "$dir/kubeconform" ;;
    kind)
      fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-amd64" "$KIND_SHA256" kind
      install -m 0755 "$work/kind" "$dir/kind" ;;
    kubectl)
      fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" kubectl
      install -m 0755 "$work/kubectl" "$dir/kubectl" ;;
    *)
      echo "unknown tool: $tool" >&2; exit 2 ;;
  esac
  echo "installed $tool"
done
