#!/usr/bin/env python3
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
"""Build the per-service telemetry list in docs/telemetry.md.

Reads each service's internal/telemetry/telemetry.go at the commit
manifest/release.yaml pins for it (through `gh api`, so it needs a signed-in
gh and network) and takes from it the log field allow-list, the class-only log
fields, the trace and metric attributes and whether database spans are wired.
The metrics and spans themselves come from the shared instrumentation, which
docs/telemetry.md describes by hand.

  telemetry-list.py           print the generated block
  telemetry-list.py --write   replace the block in docs/telemetry.md
  telemetry-list.py --check   exit 1 when docs/telemetry.md is out of date
"""
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "telemetry.md"
BEGIN = "<!-- telemetry-list:begin -->"
END = "<!-- telemetry-list:end -->"
# The nine Go services, in the order the release manifest lists them. The web
# apps are not Go and carry no telemetry package.
SERVICES = ["identity", "vault", "workflow", "audit", "notify", "connector", "sshbroker", "gateway", "mcp"]
SLICE = re.compile(r"(?:var\s+)?(\w+)\s*=\s*\[\]string\{(.*?)\}", re.S)


def fetch(repo, commit):
    out = subprocess.run(
        ["gh", "api", f"repos/{repo}/contents/internal/telemetry/telemetry.go?ref={commit}",
         "-H", "Accept: application/vnd.github.raw"],
        capture_output=True, text=True, check=True)
    return out.stdout


def strings(body):
    body = re.sub(r"//[^\n]*", "", body)
    return re.findall(r'"([^"]+)"', body)


def parse(src):
    logs, class_only, trace, metric = [], [], [], []
    for name, body in SLICE.findall(src):
        vals = strings(body)
        low = name.lower()
        if "classonly" in low:
            class_only = vals
        elif "trace" in low:
            trace = vals
        elif "metric" in low or low in ("exportedattributes", "allowedrpcattributes"):
            metric = vals
            if low in ("exportedattributes", "allowedrpcattributes"):
                trace = vals
        elif "log" in low or "allow" in low:
            logs = vals
    # Some services pass the attributes inline instead of through a variable.
    for kind, call in (("trace", "WithTraceAllowAttributes"), ("metric", "WithMetricAllowAttributes")):
        for args in re.findall(call + r"\((.*?)\)", src, re.S):
            vals = strings(args)
            if vals and kind == "trace" and not trace:
                trace = vals
            if vals and kind == "metric" and not metric:
                metric = vals
    return {
        "logs": sorted(set(logs)),
        "class_only": class_only,
        "trace": trace,
        "metric": metric,
        "db": "otelpg" in src,
    }


def block():
    manifest = yaml.safe_load((ROOT / "manifest" / "release.yaml").read_text())["spec"]["services"]
    lines = [BEGIN, ""]
    for svc in SERVICES:
        b = manifest[svc]["build"]
        info = parse(fetch(b["repository"], b["commit"]))
        lines.append(f"### {svc}")
        lines.append("")
        lines.append(f"Source: `{b['repository']}` at `{b['commit'][:12]}`, `internal/telemetry/telemetry.go`.")
        lines.append("")
        lines.append(f"- Trace attributes: {', '.join(f'`{a}`' for a in info['trace']) or 'none set here'}.")
        lines.append(f"- Metric attributes: {', '.join(f'`{a}`' for a in info['metric']) or 'none set here'}.")
        lines.append(f"- Database spans: {'yes (`query <VERB>`)' if info['db'] else 'no'}.")
        if info["class_only"]:
            lines.append(f"- Class-only log fields (logged as a class, never the text): {', '.join(f'`{a}`' for a in info['class_only'])}.")
        lines.append(f"- Log fields that leave the process: {', '.join(f'`{a}`' for a in info['logs'])}.")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    new = block()
    if not mode:
        print(new)
        return 0
    text = DOC.read_text()
    m = re.search(re.escape(BEGIN) + ".*?" + re.escape(END), text, re.S)
    if not m:
        print(f"{DOC} has no {BEGIN} block", file=sys.stderr)
        return 1
    if mode == "--check":
        if m.group(0) != new:
            print("docs/telemetry.md is out of date: run scripts/telemetry-list.py --write", file=sys.stderr)
            return 1
        print("ok: docs/telemetry.md matches the pinned services")
        return 0
    if mode == "--write":
        DOC.write_text(text[: m.start()] + new + text[m.end():])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
