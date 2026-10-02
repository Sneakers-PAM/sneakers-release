#!/usr/bin/env python3
"""Check the service-to-service edges in a rendered umbrella chart.

Reads `helm template` output on stdin. For every service the NetworkPolicy on
its main port must admit exactly the callers in EDGES, the callee must verify
workload tokens from exactly those callers' service accounts, and every caller
must mount a projected token with audience `sneakers`. The MCP server's egress
must stop at the gateway.
"""
import sys

import yaml

# callee: the services allowed to call its main port.
EDGES = {
    "vault": {"gateway", "workflow", "sshbroker", "connector"},
    "workflow": {"gateway"},
    "sshbroker": {"gateway"},
    "audit": {"gateway", "vault", "sshbroker", "identity", "workflow"},
    "notify": {"vault", "gateway"},
    "identity": {"gateway", "notify"},
    "connector": set(),
    "gateway": {"mcp"},
    "mcp": set(),
}
# Ports open to any pod (the edge): service: port names.
EDGE_PORTS = {"gateway": {"http"}, "mcp": {"http"}, "sshbroker": {"http"}}
CALLERS = set().union(*EDGES.values()) - {"mcp"}
CALLER_TOKEN = "/var/run/secrets/sneakers/token"
VERIFIER_DIR = "/var/run/secrets/tokens"

docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
errors = []
namespace = None


def component(labels):
    return (labels or {}).get("app.kubernetes.io/component")


deployments = {
    component(d["metadata"].get("labels")): d
    for d in docs
    if d["kind"] == "Deployment" and component(d["metadata"].get("labels")) in EDGES
}
configs = {d["metadata"]["name"]: d.get("data") or {} for d in docs if d["kind"] == "ConfigMap"}
policies = {d["metadata"]["name"]: d for d in docs if d["kind"] == "NetworkPolicy"}


def port_names(rule):
    return {p.get("port") for p in rule.get("ports") or []}


def env_of(name, dep):
    out = dict(configs.get(name) or {})
    for c in dep["spec"]["template"]["spec"]["containers"]:
        for e in c.get("env") or []:
            if "value" in e:
                out[e["name"]] = e["value"]
    return out


def tokens(dep):
    """mountPath -> list of serviceAccountToken sources in that volume."""
    spec = dep["spec"]["template"]["spec"]
    by_volume = {}
    for v in spec.get("volumes") or []:
        srcs = (v.get("projected") or {}).get("sources") or []
        by_volume[v["name"]] = [s["serviceAccountToken"] for s in srcs if "serviceAccountToken" in s]
    out = {}
    for c in spec["containers"]:
        for m in c.get("volumeMounts") or []:
            if by_volume.get(m["name"]):
                out[m["mountPath"]] = by_volume[m["name"]]
    return out


for svc in sorted(EDGES):
    dep = deployments.get(svc)
    if dep is None:
        errors.append(f"{svc}: not rendered")
        continue
    name = dep["metadata"]["name"]
    pod_labels = dep["spec"]["template"]["metadata"]["labels"]
    sa = dep["spec"]["template"]["spec"].get("serviceAccountName")
    if sa != f"sneakers-{svc}":
        errors.append(f"{svc}: service account {sa!r}, want sneakers-{svc}")
    policy = policies.get(name)
    if policy is None:
        errors.append(f"{svc}: no NetworkPolicy")
        continue
    main_port = dep["spec"]["template"]["spec"]["containers"][0]["ports"][0]["name"]
    admitted = set()
    for rule in policy["spec"].get("ingress") or []:
        for peer in rule.get("from") or []:
            sel = (peer.get("podSelector") or {}).get("matchLabels") or {}
            if "namespaceSelector" in peer or not sel:
                for p in port_names(rule):
                    if p not in EDGE_PORTS.get(svc, set()):
                        errors.append(f"{svc}: port {p} is open to any pod")
                continue
            if set(sel) - {"app.kubernetes.io/part-of", "app.kubernetes.io/component", "app.kubernetes.io/instance"}:
                errors.append(f"{svc}: unexpected peer selector {sel}")
            caller = sel.get("app.kubernetes.io/component")
            if caller is None:
                errors.append(f"{svc}: a peer selects every pod of the release {sel}")
                continue
            if port_names(rule) != {main_port}:
                errors.append(f"{svc}: {caller} is admitted on {sorted(port_names(rule))}, want [{main_port}]")
            admitted.add(caller)
    if admitted != EDGES[svc]:
        errors.append(f"{svc}: NetworkPolicy admits {sorted(admitted)}, want {sorted(EDGES[svc])}")

    env = env_of(name, dep)
    mounts = tokens(dep)
    if svc in CALLERS:
        caller_tokens = mounts.get("/var/run/secrets/sneakers") or []
        if [t.get("audience") for t in caller_tokens] != ["sneakers"]:
            errors.append(f"{svc}: no caller token with audience sneakers at {CALLER_TOKEN}")
        if env.get("WORKLOAD_TOKEN_FILE") != CALLER_TOKEN:
            errors.append(f"{svc}: WORKLOAD_TOKEN_FILE is {env.get('WORKLOAD_TOKEN_FILE')!r}")
    elif "WORKLOAD_TOKEN_FILE" in env or "/var/run/secrets/sneakers" in mounts:
        errors.append(f"{svc}: mounts a caller token but calls no service")

    grpc_callers = EDGES[svc] - {"mcp"}
    if grpc_callers:
        ns = policy["metadata"].get("namespace") or "sneakers"
        want = {f"{ns}/sneakers-{c}" for c in grpc_callers}
        got = {s.strip() for s in env.get("WORKLOAD_ALLOWED_SERVICEACCOUNTS", "").split(",") if s.strip()}
        if got != want:
            errors.append(f"{svc}: WORKLOAD_ALLOWED_SERVICEACCOUNTS {sorted(got)}, want {sorted(want)}")
        if env.get("WORKLOAD_AUDIENCE") != "sneakers":
            errors.append(f"{svc}: WORKLOAD_AUDIENCE is {env.get('WORKLOAD_AUDIENCE')!r}, want sneakers")
        for key, value in {
            "WORKLOAD_OIDC_BEARER_FILE": f"{VERIFIER_DIR}/token",
            "WORKLOAD_OIDC_CA_FILE": f"{VERIFIER_DIR}/ca.crt",
        }.items():
            if env.get(key) != value:
                errors.append(f"{svc}: {key} is {env.get(key)!r}, want {value}")
        for key in ("WORKLOAD_OIDC_ISSUER", "WORKLOAD_OIDC_JWKS_URL"):
            if not env.get(key, "").startswith("https://"):
                errors.append(f"{svc}: {key} is not set to an https URL")
        api_tokens = mounts.get(VERIFIER_DIR) or []
        if len(api_tokens) != 1 or api_tokens[0].get("audience"):
            errors.append(f"{svc}: no API-audience token at {VERIFIER_DIR} for the JWKS fetch")
    elif any(k.startswith("WORKLOAD_OIDC_") or k == "WORKLOAD_ALLOWED_SERVICEACCOUNTS" for k in env):
        errors.append(f"{svc}: verifies workload tokens but has no callers")

mcp = policies.get("sneakers-mcp")
if mcp is not None:
    if "Egress" not in mcp["spec"].get("policyTypes", []):
        errors.append("mcp: no egress policy")
    targets = set()
    for rule in mcp["spec"].get("egress") or []:
        for peer in rule.get("to") or []:
            sel = (peer.get("podSelector") or {}).get("matchLabels") or {}
            if "namespaceSelector" in peer and not sel:
                if port_names(rule) - {53}:
                    errors.append(f"mcp: egress to any namespace on {sorted(port_names(rule))}")
                continue
            targets.add(sel.get("app.kubernetes.io/component") or sel.get("app.kubernetes.io/name"))
    if "gateway" not in targets:
        errors.append("mcp: egress does not reach the gateway")
    if targets - {"gateway", "hydra"}:
        errors.append(f"mcp: egress reaches {sorted(targets - {'gateway', 'hydra'})}")

for e in errors:
    print(f"edges: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
