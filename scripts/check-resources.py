#!/usr/bin/env python3
"""Check that sizing stays in the user's hands, and the example values' budgets.

  check-resources.py templates
      Every container's resources, every memory-backed volume's size and every
      replica count in the chart templates comes from a value: no figure is
      written into a template, so a user can always size the release.

  check-resources.py budget <rendered.yaml> <max requests> <max limits>
      Every long-running container in the rendered release sets memory
      requests and limits, and their sums over all pods (replicas included)
      stay within the budgets, given as Kubernetes quantities (1536Mi, 3.5Gi).
      Helm hooks (the helm test pod) run only briefly and are left out.
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Templates that may keep a literal, with the reason.
ALLOWED = {
    ("charts/postgres/templates/statefulset.yaml", "replicas"): "the bundled PostgreSQL is one instance by design",
}

UNITS = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "k": 10**3, "M": 10**6, "G": 10**9}


def quantity(q):
    m = re.fullmatch(r"([0-9.]+)([A-Za-z]*)", str(q))
    if not m or (m.group(2) and m.group(2) not in UNITS):
        raise ValueError(f"not a memory quantity: {q}")
    return float(m.group(1)) * UNITS.get(m.group(2), 1)


def mib(b):
    return f"{b / 2**20:.0f}Mi"


def templates():
    errors = []
    files = sorted(p for p in (ROOT / "charts").glob("*/templates/**/*") if p.is_file())
    for path in files:
        rel = str(path.relative_to(ROOT))
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            m = re.match(r"\s*(resources|replicas|sizeLimit):\s*(.*)$", line)
            if m:
                key, rest = m.groups()
                if (rel, key) in ALLOWED:
                    continue
                if key == "resources":
                    indent = len(line) - len(line.lstrip())
                    block = []
                    for l in lines[i + 1:]:
                        if l.strip() and len(l) - len(l.lstrip()) <= indent:
                            break
                        block.append(l)
                    if any(re.match(r"\s*(cpu|memory|storage|ephemeral-storage):\s*[\"']?[0-9]", l) for l in block):
                        errors.append(f"{rel}:{i + 1}: resources written into the template, not read from a value")
                elif key == "replicas":
                    if ".Values" not in rest:
                        errors.append(f"{rel}:{i + 1}: replicas written into the template, not read from a value")
                elif "{{" not in rest and any("medium: Memory" in l for l in lines[max(0, i - 3):i]):
                    errors.append(f"{rel}:{i + 1}: a memory-backed volume's size written into the template, not read from a value")
            # dict-built volumes: a memory-backed one must not carry a literal size.
            if re.search(r'"medium"\s+"Memory"', line) and re.search(r'"sizeLimit"\s+"[0-9]', line):
                errors.append(f"{rel}:{i + 1}: a memory-backed volume's size written into the template, not read from a value")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        sys.exit(1)
    print(f"ok: {len(files)} templates read every resource, memory-backed volume size and replica count from a value")


def pod_memory(spec, kind, doc):
    """The pod's effective request and limit: the larger of the containers'
    sum and any one init container (init containers run one at a time)."""
    name = doc["metadata"]["name"]
    errors = []
    totals = {}
    for which in ("requests", "limits"):
        main = init = 0.0
        for group, containers in (("main", spec.get("containers", [])), ("init", spec.get("initContainers", []))):
            for c in containers:
                v = ((c.get("resources") or {}).get(which) or {}).get("memory")
                if not v:
                    errors.append(f"{kind}/{name}/{c['name']}: no memory {which}")
                    continue
                if group == "main":
                    main += quantity(v)
                else:
                    init = max(init, quantity(v))
        totals[which] = max(main, init)
    return totals, errors


def budget(rendered, max_requests, max_limits):
    docs = [d for d in yaml.safe_load_all(open(rendered)) if d]
    errors = []
    sums = {"requests": 0.0, "limits": 0.0}
    rows = []
    for doc in docs:
        kind = doc.get("kind")
        if kind not in ("Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"):
            continue
        if "helm.sh/hook" in (doc["metadata"].get("annotations") or {}):
            continue
        spec = doc["spec"] if kind == "Pod" else doc["spec"]["template"]["spec"]
        replicas = 1 if kind in ("Pod", "Job", "DaemonSet") else doc["spec"].get("replicas", 1)
        totals, errs = pod_memory(spec, kind, doc)
        errors += errs
        for k in sums:
            sums[k] += totals[k] * replicas
        rows.append((doc["metadata"]["name"], replicas, totals["requests"], totals["limits"]))
    for name, replicas, req, lim in sorted(rows):
        print(f"  {name:<28} x{replicas}  requests {mib(req):>7}  limits {mib(lim):>7}")
    print(f"  {'total':<28}     requests {mib(sums['requests']):>7}  limits {mib(sums['limits']):>7}")
    if not rows:
        errors.append("no workloads rendered")
    if sums["requests"] > quantity(max_requests):
        errors.append(f"memory requests {mib(sums['requests'])} exceed the budget of {max_requests}")
    if sums["limits"] > quantity(max_limits):
        errors.append(f"memory limits {mib(sums['limits'])} exceed the budget of {max_limits}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        sys.exit(1)
    print(f"ok: {rendered} fits {max_requests} of memory requests and {max_limits} of limits")


if __name__ == "__main__":
    if sys.argv[1:2] == ["templates"]:
        templates()
    elif sys.argv[1:2] == ["budget"] and len(sys.argv) == 5:
        budget(*sys.argv[2:])
    else:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
