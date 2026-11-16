#!/usr/bin/env python3
"""Fail when manifest/release.yaml and the charts pin different versions.

Usage: check-manifest.py [--platforms | --migrations] [release.yaml] (default manifest/release.yaml).

--platforms also reads the index behind every image digest the manifest pins
and fails when it lacks linux/amd64 or linux/arm64, so the bundle runs on the
appliance's arm64 build as well as amd64. It needs the network: the indexes
come from each registry, anonymously, and the bytes are held to the pinned
digest. A digest still at the release placeholder is skipped. For tests,
CHECK_MANIFEST_INDEX_DIR names a folder of <digest hex>.json files that stand
in for the registries.

--migrations checks only that the sneakers-migrate image the manifest pins
writes the newest migration of every service at its pinned commit (the tool
refuses a database at any other version, code 2001): it reads each service's
migrations folder, and the tool's schema.go, at the pinned commits from GitHub
(GITHUB_TOKEN is used when set). For tests, CHECK_MANIFEST_MIGRATIONS_DIR names
a folder of <owner>__<repo>__<commit>.txt path lists and schema-<commit>.go.txt files
that stand in for GitHub.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
BUILD_KEYS = {"repository", "commit", "dockerfile", "context", "target", "args"}
PLACEHOLDER = "sha256:TBD-at-release"
errors = []
REQUIRED_PLATFORMS = (("linux", "amd64"), ("linux", "arm64"))
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)


def load(rel):
    return yaml.safe_load((ROOT / rel).read_text())


def expect(what, got, want):
    if got != want:
        errors.append(f"{what}: charts have {got!r}, the manifest has {want!r}")


args = [a for a in sys.argv[1:] if not a.startswith("--")]
flags = {a for a in sys.argv[1:] if a.startswith("--")}
if flags - {"--platforms", "--migrations"}:
    sys.exit(f"check-manifest.py: unknown option {', '.join(sorted(flags - {'--platforms', '--migrations'}))}")
manifest = yaml.safe_load(Path(args[0] if args else ROOT / "manifest/release.yaml").read_text())
spec = manifest["spec"]


# Each service's migrations folder in the repository it is built from, and the key of the
# tool's schema.TargetVersions it must be listed under.
MIGRATIONS = {
    "identity": "migrations/",
    "vault": "migrations/vault/",
    "workflow": "migrations/workflow/",
    "audit": "migrations/",
}
SCHEMA_PATH = "migrate/internal/schema/schema.go"


def github(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "check-manifest"})
    if os.environ.get("GITHUB_TOKEN") and url.startswith("https://api.github.com/"):
        req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def source_paths(repo, commit):
    """Every path in a repository at a commit."""
    fixtures = os.environ.get("CHECK_MANIFEST_MIGRATIONS_DIR")
    if fixtures:
        return (Path(fixtures) / f"{repo.replace('/', '__')}__{commit}.txt").read_text().split()
    tree = json.loads(github(f"https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1"))
    if tree.get("truncated"):
        raise RuntimeError("the repository tree is too large to list")
    return [e["path"] for e in tree["tree"]]


def source_schema(repo, commit):
    """The tool's schema.go at a commit."""
    fixtures = os.environ.get("CHECK_MANIFEST_MIGRATIONS_DIR")
    if fixtures:
        return (Path(fixtures) / f"schema-{commit}.go.txt").read_text()
    return github(f"https://raw.githubusercontent.com/{repo}/{commit}/{SCHEMA_PATH}")


def parse_target_versions(text):
    """schema.TargetVersions as {service: [versions]} from its Go source."""
    block = re.search(r"var TargetVersions = map\[Service\]\[\]int64\{(.*?)\n\}", text, re.S)
    if not block:
        raise ValueError("no TargetVersions map in schema.go")
    return {name.lower(): [int(v) for v in re.findall(r"\d+", nums)] for name, nums in re.findall(r"(\w+):\s*\{([\d,\s]*)\}", block.group(1))}


def check_migrations(spec):
    """The pinned sneakers-migrate writes the newest migration of every pinned service."""
    tool = spec["jobs"]["migrate"]["build"]
    try:
        writes = parse_target_versions(source_schema(tool["repository"], tool["commit"]))
    except (OSError, ValueError, urllib.error.URLError) as e:
        errors.append(f"jobs.migrate: can't read the tool's schema at {tool['commit'][:7]}: {e}")
        return
    for svc, folder in MIGRATIONS.items():
        build = spec["services"][svc]["build"]
        where = f"{svc} ({build['repository']}@{build['commit'][:7]})"
        try:
            paths = source_paths(build["repository"], build["commit"])
        except (OSError, ValueError, RuntimeError, urllib.error.URLError) as e:
            errors.append(f"{where}: can't list its migrations: {e}")
            continue
        found = [int(m.group(1)) for p in paths if p.startswith(folder) and p.endswith(".up.sql") and (m := re.match(r"(\d+)_", p.rsplit("/", 1)[-1]))]
        if not found:
            errors.append(f"{where}: no migrations under {folder}")
            continue
        newest = max(found)
        if newest not in writes.get(svc, []):
            errors.append(f"{where} ships migration {newest}, but the sneakers-migrate pinned at {tool['commit'][:7]} writes {svc} {writes.get(svc, [])}: pin a migrate commit whose schema.go lists {svc} {newest}")


if "--migrations" in flags:
    check_migrations(spec)
    for e in errors:
        print(f"manifest: {e}", file=sys.stderr)
    if not errors:
        print("ok: the pinned sneakers-migrate writes the newest migration of every pinned service")
    sys.exit(1 if errors else 0)

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
    if name == "postgres-ha":
        continue
    if part["chart"]["repository"].startswith("http"):
        expect(f"{name} chart repository", deps[name]["repository"], part["chart"]["repository"])
        expect(f"{name} image tag", values[name]["image"]["tag"], f"{part['version']}@{part['digest']}")
    else:
        local = load(f"charts/{name}/values.yaml")["image"]
        expect(f"{name} image", local["repository"], part["image"])
        expect(f"{name} image tag", local["tag"], str(part["version"]))
        expect(f"{name} image digest", local["digest"], part["digest"])

# postgres-ha is an OCI dependency of the umbrella, off by default. The manifest
# pins it by digest (scripts/check-chart-digest.sh holds the fetched chart to it).
# Its values pin the agent image above, and the PostgreSQL image charts/postgres
# pins, so the two clusters run one build.
pgha = spec["thirdParty"].get("postgres-ha")
if not pgha:
    errors.append("spec.thirdParty pins no postgres-ha")
else:
    expect("postgres-ha chart repository", deps["postgres-ha"]["repository"], pgha["chart"]["repository"])
    if not DIGEST.match(str(pgha["chart"].get("digest"))):
        errors.append(f"postgres-ha: chart digest {pgha['chart'].get('digest')!r} is not a sha256 digest")
    if not pgha["chart"]["repository"].startswith("oci://"):
        errors.append("postgres-ha: the chart comes from an OCI registry, pulled by its digest")
    if re.search(r"-|\+", str(pgha["chart"]["version"])):
        errors.append(f"postgres-ha: {pgha['chart']['version']} isn't a published release")
    pv = values["postgres-ha"]
    expect("postgres-ha agent image tag", pv["agent"]["image"]["tag"], pgha["version"])
    expect("postgres-ha agent image digest", pv["agent"]["image"]["digest"], pgha["digest"])
    pg = spec["thirdParty"]["postgres"]
    expect("postgres-ha PostgreSQL image", "docker.io/" + pv["image"]["repository"], pg["image"])
    expect("postgres-ha PostgreSQL image tag", pv["image"]["tag"], str(pg["version"]))
    expect("postgres-ha PostgreSQL image digest", pv["image"]["digest"], pg["digest"])

# The platform the appliance runs under the charts: the bundle carries these
# images too, and the appliance's bundle check refuses one that's missing.
PLATFORM = {"traefik", "cert-manager-controller", "cert-manager-webhook", "cert-manager-cainjector", "cert-manager-acmesolver"}
platform = spec.get("platform") or {}
missing = PLATFORM - set(platform)
if missing:
    errors.append(f"spec.platform has no pin for {', '.join(sorted(missing))}")
for name, part in platform.items():
    if not DIGEST.match(part.get("digest", "")):
        errors.append(f"platform {name}: digest {part.get('digest')!r} is not a sha256 digest")
    if not part.get("image") or not part.get("version"):
        errors.append(f"platform {name}: needs an image and a version")
# cert-manager's four images are one release: the controller starts the
# acmesolver pods, so a different version would run a solver it wasn't built for.
cm_versions = {n: str(p.get("version")) for n, p in platform.items() if n.startswith("cert-manager-")}
if len(set(cm_versions.values())) > 1:
    errors.append(f"platform cert-manager images pin different versions: {cm_versions}")

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

def pinned_images(node, path="spec"):
    """Every (where, image, digest) the manifest pins by a real digest.

    An image is a map with both `image` and `digest`. That leaves out the
    postgres-ha chart's digest (a Helm artifact, no `image`), the k0s binary
    checksums, and any digest still at the release placeholder.
    """
    if isinstance(node, dict):
        image, digest = node.get("image"), node.get("digest")
        if isinstance(image, str) and isinstance(digest, str) and DIGEST.match(digest):
            yield path, image, digest
        for key, value in node.items():
            yield from pinned_images(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from pinned_images(value, f"{path}[{i}]")


def registry_ref(image):
    """(host, repository) for an image name, Docker Hub's defaults included."""
    first, _, rest = image.partition("/")
    if "." in first or ":" in first or first == "localhost":
        host, repo = first, rest
    else:
        host, repo = "docker.io", image
    if host == "docker.io":
        host = "registry-1.docker.io"
        repo = repo if "/" in repo else f"library/{repo}"
    return host, repo


def fetch_manifest(image, digest):
    """The bytes of the manifest `image@digest`, held to the digest."""
    stub = os.environ.get("CHECK_MANIFEST_INDEX_DIR")
    if stub:
        return (Path(stub) / f"{digest.split(':', 1)[1]}.json").read_bytes()
    host, repo = registry_ref(image)
    url = f"https://{host}/v2/{repo}/manifests/{digest}"
    accept = ",".join(INDEX_TYPES + MANIFEST_TYPES)
    token = None
    for attempt in range(4):
        headers = {"Accept": accept}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:
                body = r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401 and not token:
                # Anonymous pull token, from the registry's own challenge.
                challenge = dict(re.findall(r'(\w+)="([^"]*)"', e.headers.get("WWW-Authenticate", "")))
                if "realm" not in challenge:
                    raise
                query = f"service={challenge.get('service', '')}&scope=repository:{repo}:pull"
                with urllib.request.urlopen(f"{challenge['realm']}?{query}", timeout=30) as t:
                    reply = json.load(t)
                token = reply.get("token") or reply.get("access_token")
                continue
            if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise
        except urllib.error.URLError:
            if attempt < 3:
                time.sleep(2 ** attempt)
                continue
            raise
        if "sha256:" + hashlib.sha256(body).hexdigest() != digest:
            raise ValueError("the registry's bytes don't hash to the pinned digest")
        return body
    raise RuntimeError("no manifest after retries")


def check_platforms(spec):
    """Each real image digest is an index holding linux/amd64 and linux/arm64."""
    for where, image, digest in pinned_images(spec):
        try:
            body = json.loads(fetch_manifest(image, digest))
        except (OSError, ValueError, urllib.error.URLError, RuntimeError) as e:
            errors.append(f"{where}: can't read {image}@{digest[:19]}: {e}")
            continue
        entries = body.get("manifests") if isinstance(body, dict) else None
        if not isinstance(entries, list):
            errors.append(f"{where}: {image}@{digest[:19]} is a single-platform manifest, not an index with {', '.join('/'.join(p) for p in REQUIRED_PLATFORMS)}")
            continue
        # os and architecture only: a variant (arm64/v8) doesn't matter, and
        # attestation entries (unknown/unknown) never count.
        have = {(m["platform"].get("os"), m["platform"].get("architecture")) for m in entries if isinstance(m.get("platform"), dict)}
        for plat in REQUIRED_PLATFORMS:
            if plat not in have:
                errors.append(f"{where}: {image}@{digest[:19]} has no {'/'.join(plat)} (it has {', '.join(sorted('/'.join(map(str, h)) for h in have)) or 'no platforms'})")

if "--platforms" in flags:
    check_platforms(spec)

for e in errors:
    print(f"manifest: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
