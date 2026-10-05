#!/usr/bin/env bash
# Install the pinned chart tools into a directory (default: ./bin), checking
# each download against its published SHA-256, for the machine's architecture
# (amd64 or arm64). Usage:
#   scripts/install-tools.sh [dir] [helm kubeconform kind kubectl]
set -euo pipefail
dir="${1:-bin}"
shift || true
tools=("$@")
[ "${#tools[@]}" -gt 0 ] || tools=(helm kubeconform)

HELM_VERSION=v4.3.0
KUBECONFORM_VERSION=v0.8.0
KIND_VERSION=v0.33.0
KUBECTL_VERSION=v1.36.4

case "$(uname -m)" in
  x86_64 | amd64)
    arch=amd64
    HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb
    KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
    KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
    KUBECTL_SHA256=8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a ;;
  aarch64 | arm64)
    arch=arm64
    HELM_SHA256=31c5794dd55c66a51e6b7d2e2ac7a114ae8b1de41ff1d9ba51748ac973b06a08
    KUBECONFORM_SHA256=1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87
    KIND_SHA256=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2
    KUBECTL_SHA256=0ecf44450ee6063bf19dd166a103ee6df4a9034455c2abce626e6eea657d73fb ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2; exit 2 ;;
esac

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
      fetch "https://get.helm.sh/helm-${HELM_VERSION}-linux-${arch}.tar.gz" "$HELM_SHA256" helm.tgz
      tar -xzf "$work/helm.tgz" -C "$work" linux-${arch}/helm
      install -m 0755 "$work/linux-${arch}/helm" "$dir/helm" ;;
    kubeconform)
      fetch "https://github.com/yannh/kubeconform/releases/download/${KUBECONFORM_VERSION}/kubeconform-linux-${arch}.tar.gz" "$KUBECONFORM_SHA256" kubeconform.tgz
      tar -xzf "$work/kubeconform.tgz" -C "$work" kubeconform
      install -m 0755 "$work/kubeconform" "$dir/kubeconform" ;;
    kind)
      fetch "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-${arch}" "$KIND_SHA256" kind
      install -m 0755 "$work/kind" "$dir/kind" ;;
    kubectl)
      fetch "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" "$KUBECTL_SHA256" kubectl
      install -m 0755 "$work/kubectl" "$dir/kubectl" ;;
    *)
      echo "unknown tool: $tool" >&2; exit 2 ;;
  esac
  echo "installed $tool"
done
