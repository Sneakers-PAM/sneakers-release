#!/usr/bin/env python3
"""Fail when manifest/release.yaml and the charts pin different versions."""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
PLACEHOLDER = "sha256:TBD-at-release"
errors = []


def load(rel):
    return yaml.safe_load((ROOT / rel).read_text())


def expect(what, got, want):
    if got != want:
        errors.append(f"{what}: charts have {got!r}, the manifest has {want!r}")


manifest = load("manifest/release.yaml")
spec = manifest["spec"]
umbrella = load("charts/sneakers/Chart.yaml")
values = load("charts/sneakers/values.yaml")

expect("umbrella chart version", umbrella["version"], manifest["metadata"]["version"])
expect("spec.charts.sneakers.version", umbrella["version"], spec["charts"]["sneakers"]["version"])

deps = {d["name"]: d for d in umbrella["dependencies"]}
for name, svc in spec["services"].items():
    chart = load(f"charts/{name}/Chart.yaml")
    svc_values = load(f"charts/{name}/values.yaml")
    expect(f"{name} image", svc_values["image"]["repository"], svc["image"])
    expect(f"{name} appVersion", chart["appVersion"], svc["version"])
    expect(f"{name} chart in the umbrella", deps[name]["version"], chart["version"])
    if svc["digest"] != PLACEHOLDER and not DIGEST.match(svc["digest"]):
        errors.append(f"{name}: digest {svc['digest']!r} is neither a sha256 digest nor {PLACEHOLDER}")

for name, part in spec["thirdParty"].items():
    if not DIGEST.match(part["digest"]):
        errors.append(f"{name}: digest {part['digest']!r} is not a sha256 digest")
    expect(f"{name} chart version", deps[name]["version"], part["chart"]["version"])
    if part["chart"]["repository"].startswith("http"):
        expect(f"{name} chart repository", deps[name]["repository"], part["chart"]["repository"])
        expect(f"{name} image tag", values[name]["image"]["tag"], f"{part['version']}@{part['digest']}")
    else:
        local = load(f"charts/{name}/values.yaml")["image"]
        expect(f"{name} image", local["repository"], part["image"])
        expect(f"{name} image tag", local["tag"], str(part["version"]))
        expect(f"{name} image digest", local["digest"], part["digest"])

curl = spec["tools"]["curl"]
test_image = values["tests"]["image"]
expect("test image", test_image["repository"], curl["image"])
expect("test image tag", test_image["tag"], str(curl["version"]))
expect("test image digest", test_image["digest"], curl["digest"])

k0s = spec["kubernetes"]["k0s"]
if not re.match(r"^v\d+\.\d+\.\d+\+k0s\.\d+$", k0s["version"]):
    errors.append(f"k0s version {k0s['version']!r} is not a k0s release")
for arch, sha in k0s["sha256"].items():
    if not re.match(r"^[a-f0-9]{64}$", sha):
        errors.append(f"k0s {arch} checksum is not a sha256")
# k0s's own images (pause, kube-proxy, CoreDNS, kube-router and its CNI
# node image): an airgapped node, such as the appliance, loads them from the
# bundle instead of pulling them.
K0S_IMAGES = {"pause", "kube-proxy", "coredns", "kube-router", "cni-node"}
pinned = {}
for im in k0s.get("images") or []:
    pinned[im["image"].rsplit("/", 1)[-1]] = im
    if not DIGEST.match(im.get("digest", "")):
        errors.append(f"k0s image {im['image']}: digest {im.get('digest')!r} is not a sha256 digest")
for name in sorted(K0S_IMAGES - pinned.keys()):
    errors.append(f"spec.kubernetes.k0s.images pins no {name} image")

for e in errors:
    print(f"manifest: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
