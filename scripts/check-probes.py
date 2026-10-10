#!/usr/bin/env python3
"""Check the probe timings in a rendered umbrella chart.

Reads `helm template` output on stdin. Every container of every Sneakers
workload, and of the bundled PostgreSQL, Valkey, Kratos and Hydra, must have a
startup and a readiness probe, and a liveness probe unless it is one of the Ory
servers (whose charts run none). On a small box under boot load a probe must
not fail because the kubelet stopped waiting, nor kill a process that is only
waiting for a dependency:

- every probe waits at least 3 seconds for an answer (timeoutSeconds);
- the startup window (periodSeconds x failureThreshold) is at least 5 minutes;
- startup and liveness ask the process only: the gRPC health service
  "liveness", an HTTP liveness path (never a readiness one), or an exec
  check (pg_isready, valkey-cli ping) of the server itself.
"""
import sys

import yaml

SERVICES = {"identity", "vault", "workflow", "audit", "notify", "connector", "sshbroker", "gateway", "mcp", "web-staff", "web-admin"}
BUNDLED = {"postgres", "valkey", "kratos", "hydra"}
NO_LIVENESS = {"kratos", "hydra"}
MIN_TIMEOUT = 3
MIN_STARTUP_WINDOW = 300

docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
errors = []
seen = set()


def component(doc):
    labels = doc.get("metadata", {}).get("labels") or {}
    comp = labels.get("app.kubernetes.io/component")
    if comp in SERVICES or comp == "postgres":
        return comp
    name = labels.get("app.kubernetes.io/name")
    if name in BUNDLED:
        return name
    return None


def process_only(probe):
    if "grpc" in probe:
        return probe["grpc"].get("service") == "liveness"
    if "httpGet" in probe:
        path = probe["httpGet"].get("path", "/")
        return "ready" not in path
    return "exec" in probe or "tcpSocket" in probe


for doc in docs:
    if doc["kind"] not in ("Deployment", "StatefulSet"):
        continue
    comp = component(doc)
    if comp is None:
        continue
    seen.add(comp)
    name = doc["metadata"]["name"]
    for c in doc["spec"]["template"]["spec"]["containers"]:
        where = f"{name}/{c['name']}"
        kinds = ["startupProbe", "readinessProbe"] + ([] if comp in NO_LIVENESS else ["livenessProbe"])
        for kind in kinds:
            probe = c.get(kind)
            if not probe:
                errors.append(f"{where}: no {kind}")
                continue
            timeout = probe.get("timeoutSeconds", 1)
            if timeout < MIN_TIMEOUT:
                errors.append(f"{where}: {kind} waits {timeout}s, want at least {MIN_TIMEOUT}s")
            if kind != "readinessProbe" and not process_only(probe):
                errors.append(f"{where}: {kind} checks more than the process: {probe}")
        startup = c.get("startupProbe") or {}
        window = startup.get("periodSeconds", 10) * startup.get("failureThreshold", 3)
        if startup and window < MIN_STARTUP_WINDOW:
            errors.append(f"{where}: startup window {window}s, want at least {MIN_STARTUP_WINDOW}s")

missing = (SERVICES | {"postgres"}) - seen
if missing:
    errors.append(f"not rendered: {', '.join(sorted(missing))}")

for e in errors:
    print(f"probes: {e}", file=sys.stderr)
if not errors:
    print(f"ok: probe timings for {', '.join(sorted(seen))}")
sys.exit(1 if errors else 0)
