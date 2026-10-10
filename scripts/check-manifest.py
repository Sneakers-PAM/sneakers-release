#!/usr/bin/env python3
"""Fail when manifest/release.yaml and the charts pin different versions.

Usage: check-manifest.py [release.yaml] (default manifest/release.yaml).
"""
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
BUILD_KEYS = {"repository", "commit", "dockerfile", "context", "target", "args"}
PLACEHOLDER = "sha256:TBD-at-release"
errors = []


def load(rel):
    return yaml.safe_load((ROOT / rel).read_text())


def expect(what, got, want):
    if got != want:
        errors.append(f"{what}: charts have {got!r}, the manifest has {want!r}")


manifest = yaml.safe_load(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "manifest/release.yaml").read_text())
spec = manifest["spec"]
umbrella = load("charts/sneakers/Chart.yaml")
values = load("charts/sneakers/values.yaml")

expect("umbrella chart version", umbrella["version"], manifest["metadata"]["version"])
expect("spec.charts.sneakers.version", umbrella["version"], spec["charts"]["sneakers"]["version"])

deps = {d["name"]: d for d in umbrella["dependencies"]}


def kind_services():
    """test/kind/services.txt: image name -> (repository, ref, target, args)."""
    out = {}
    for line in (ROOT / "test/kind/services.txt").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        f = line.split()
        args = dict(kv.split("=", 1) for kv in f[4].split(",")) if len(f) > 4 else {}
        out[f[0]] = (f[1], f[2], None if f[3] == "-" else f[3], args)
    return out


kind = kind_services()


def check_build(name, svc, kind_test=True):
    """The build block the appliance release builds the image from."""
    b = svc.get("build")
    if not isinstance(b, dict):
        errors.append(f"{name}: no build block (repository, commit, dockerfile, context)")
        return
    for k in sorted(set(b) - BUILD_KEYS):
        errors.append(f"{name}: build.{k} isn't a build key ({', '.join(sorted(BUILD_KEYS))})")
    repo = b.get("repository", "")
    if svc.get("source") != f"https://github.com/{repo}":
        errors.append(f"{name}: build.repository {repo!r} isn't the source {svc.get('source')!r}")
    if not COMMIT.match(str(b.get("commit", ""))):
        errors.append(f"{name}: build.commit {b.get('commit')!r} isn't a full commit")
    for k in ("dockerfile", "context"):
        if not isinstance(b.get(k), str) or not b[k] or b[k].startswith("/") or ".." in b[k].split("/"):
            errors.append(f"{name}: build.{k} {b.get(k)!r} isn't a path in the repository")
    args = b.get("args") or {}
    if not isinstance(args, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in args.items()):
        errors.append(f"{name}: build.args is a map of strings")
        args = {}
    if not kind_test:
        return
    image = svc["image"].rsplit("/", 1)[-1]
    if image not in kind:
        errors.append(f"{name}: test/kind/services.txt doesn't build {image}")
        return
    want = (repo, b.get("commit"), b.get("target"), args)
    if kind[image] != want:
        errors.append(f"{name}: test/kind/services.txt builds {kind[image]}, the manifest {want}")
for name, svc in spec["services"].items():
    chart = load(f"charts/{name}/Chart.yaml")
    svc_values = load(f"charts/{name}/values.yaml")
    expect(f"{name} image", svc_values["image"]["repository"], svc["image"])
    expect(f"{name} appVersion", chart["appVersion"], svc["version"])
    expect(f"{name} chart in the umbrella", deps[name]["version"], chart["version"])
    if svc["digest"] != PLACEHOLDER and not DIGEST.match(svc["digest"]):
        errors.append(f"{name}: digest {svc['digest']!r} is neither a sha256 digest nor {PLACEHOLDER}")
    check_build(name, svc)

# One-off Job images (sneakers-migrate): no chart pins them and the install
# test doesn't build them, but each has a build block, a version that is
# the release's, and a digest or the placeholder.
for name, job in (spec.get("jobs") or {}).items():
    check_build(f"jobs.{name}", job, kind_test=False)
    expect(f"jobs.{name} version", job.get("version"), manifest["metadata"]["version"])
    if job.get("digest") != PLACEHOLDER and not DIGEST.match(str(job.get("digest"))):
        errors.append(f"jobs.{name}: digest {job.get('digest')!r} is neither a sha256 digest nor {PLACEHOLDER}")
if "migrate" not in (spec.get("jobs") or {}):
    errors.append("spec.jobs pins no migrate image (the appliance's Import page runs it)")

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

# The platform the appliance runs under the charts: the bundle carries these
# images too, and the appliance's bundle check refuses one that's missing.
PLATFORM = {"traefik", "cert-manager-controller", "cert-manager-webhook", "cert-manager-cainjector"}
platform = spec.get("platform") or {}
missing = PLATFORM - set(platform)
if missing:
    errors.append(f"spec.platform has no pin for {', '.join(sorted(missing))}")
for name, part in platform.items():
    if not DIGEST.match(part.get("digest", "")):
        errors.append(f"platform {name}: digest {part.get('digest')!r} is not a sha256 digest")
    if not part.get("image") or not part.get("version"):
        errors.append(f"platform {name}: needs an image and a version")

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
