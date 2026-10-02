#!/usr/bin/env python3
"""Check the production-safe defaults in a rendered umbrella chart.

Reads `helm template` output on stdin. Every Sneakers workload must log JSON at
error level, set requests and limits, run as non-root on a read-only root
filesystem without privilege escalation, sit behind a NetworkPolicy, and have a
PodDisruptionBudget when it runs more than one pod.
"""
import sys

import yaml

SERVICES = {"identity", "vault", "workflow", "audit", "notify", "connector", "sshbroker", "gateway", "mcp", "web-staff", "web-admin"}
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
errors = []


def labels(doc):
    return doc.get("metadata", {}).get("labels") or {}


def ours(doc):
    return labels(doc).get("app.kubernetes.io/component") in SERVICES | {"postgres"}


def selects(selector, pod_labels):
    return all(pod_labels.get(k) == v for k, v in (selector.get("matchLabels") or {}).items())


policies = [d for d in docs if d["kind"] == "NetworkPolicy"]
budgets = [d for d in docs if d["kind"] == "PodDisruptionBudget"]
configs = {d["metadata"]["name"]: d for d in docs if d["kind"] == "ConfigMap"}
seen = set()

for doc in docs:
    if doc["kind"] not in ("Deployment", "StatefulSet") or not ours(doc):
        continue
    name = doc["metadata"]["name"]
    component = labels(doc)["app.kubernetes.io/component"]
    seen.add(component)
    pod = doc["spec"]["template"]
    pod_spec = pod["spec"]
    pod_labels = pod["metadata"]["labels"]
    if not (pod_spec.get("securityContext") or {}).get("runAsNonRoot"):
        errors.append(f"{name}: pod does not set runAsNonRoot")
    for c in pod_spec["containers"] + pod_spec.get("initContainers", []):
        sc = c.get("securityContext") or {}
        res = c.get("resources") or {}
        if sc.get("readOnlyRootFilesystem") is not True:
            errors.append(f"{name}/{c['name']}: root filesystem is writable")
        if sc.get("allowPrivilegeEscalation") is not False:
            errors.append(f"{name}/{c['name']}: privilege escalation is allowed")
        if "ALL" not in ((sc.get("capabilities") or {}).get("drop") or []):
            errors.append(f"{name}/{c['name']}: capabilities are not dropped")
        if not (res.get("requests") or {}).get("memory") or not (res.get("limits") or {}).get("memory"):
            errors.append(f"{name}/{c['name']}: memory requests or limits are missing")
    if not any(selects(p["spec"]["podSelector"], pod_labels) for p in policies):
        errors.append(f"{name}: no NetworkPolicy selects its pods")
    replicas = doc["spec"].get("replicas", 1)
    if replicas > 1 and not any(selects(b["spec"]["selector"], pod_labels) for b in budgets):
        errors.append(f"{name}: {replicas} replicas but no PodDisruptionBudget")
    if component in SERVICES:
        data = (configs.get(name) or {}).get("data") or {}
        if data.get("LOG_LEVEL") != "error" or data.get("LOG_FORMAT") != "json":
            errors.append(f"{name}: logs at {data.get('LOG_LEVEL')!r} in {data.get('LOG_FORMAT')!r}, want error in json")

missing = (SERVICES | {"postgres"}) - seen
if missing:
    errors.append(f"not rendered: {', '.join(sorted(missing))}")

for e in errors:
    print(f"defaults: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
