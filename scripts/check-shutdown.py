#!/usr/bin/env python3
"""Check the bundled PostgreSQL stops cleanly in a rendered chart.

Reads `helm template` output on stdin. A pod's stop (a scale to 0, a delete,
an update, a node drain) must end with PostgreSQL's shutdown checkpoint
written, never with the kubelet's SIGKILL at the end of the grace period:

- the postgres container has a preStop hook that runs
  `pg_ctl stop -m fast -W` on the pod's own data directory: a fast shutdown
  whatever signal the runtime sends (a smart one waits for the services'
  pooled sessions until the kill). It only asks: waiting (-w) in the hook is
  cut off when the server's exit ends the container, a failed hook every time;
- the pod's terminationGracePeriodSeconds, how long the kubelet waits for the
  server to exit before it kills it, is at least 120.
"""
import sys

import yaml

MIN_GRACE = 120

docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
errors = []
found = False

for doc in docs:
    if doc["kind"] != "StatefulSet":
        continue
    labels = doc.get("metadata", {}).get("labels") or {}
    if labels.get("app.kubernetes.io/component") != "postgres" and labels.get("app.kubernetes.io/name") != "postgres":
        continue
    found = True
    name = doc["metadata"]["name"]
    spec = doc["spec"]["template"]["spec"]
    grace = spec.get("terminationGracePeriodSeconds", 30)
    if grace < MIN_GRACE:
        errors.append(f"{name}: terminationGracePeriodSeconds {grace}, want at least {MIN_GRACE}")
    pg = [c for c in spec["containers"] if c["name"] == "postgres"]
    if not pg:
        errors.append(f"{name}: no postgres container")
        continue
    env = {e["name"]: e.get("value") for e in pg[0].get("env") or []}
    cmd = (((pg[0].get("lifecycle") or {}).get("preStop") or {}).get("exec") or {}).get("command") or []
    if not cmd or "pg_ctl" not in cmd[0]:
        errors.append(f"{name}: the postgres container has no preStop pg_ctl stop: {cmd}")
        continue
    args = cmd[1:]

    def opt(flag):
        return args[args.index(flag) + 1] if flag in args and args.index(flag) + 1 < len(args) else None

    if "stop" not in args:
        errors.append(f"{name}: the preStop doesn't stop the server: {cmd}")
    if opt("-m") != "fast":
        errors.append(f"{name}: the preStop shutdown mode is {opt('-m')}, want fast: {cmd}")
    if "-W" not in args or "-w" in args:
        errors.append(f"{name}: the preStop must only ask (-W); the kubelet's grace period is the wait: {cmd}")
    if opt("-D") != env.get("PGDATA"):
        errors.append(f"{name}: the preStop stops {opt('-D')}, not PGDATA {env.get('PGDATA')}")

if not found:
    errors.append("no PostgreSQL StatefulSet rendered")
for e in errors:
    print(f"shutdown: {e}", file=sys.stderr)
if not errors:
    print(f"ok: PostgreSQL stops with a fast shutdown and its checkpoint, with {grace}s before the kubelet kills it")
sys.exit(1 if errors else 0)
