#!/usr/bin/env python3
"""Check the web apps in two renders of the umbrella chart.

Usage: check-web.py <defaults render> <render with ingress and global.sso on>.
Both apps run as uid 1000 on port 3000 with their health checks, call the
gateway at GATEWAY_URL, and may reach only the gateway and DNS. With ingress
on, the staff app owns / and the admin app /admin on the gateway's host, and
SSO_ENABLED follows global.sso.enabled.
"""
import sys

import yaml

APPS = {
    "web-staff": {"health": "/healthz", "path": "/", "base": "/"},
    "web-admin": {"health": "/admin/healthz", "path": "/admin", "base": "/admin/"},
}
errors = []


def load(path):
    with open(path) as f:
        return [d for d in yaml.safe_load_all(f) if d]


def by_kind(docs, kind):
    return {d["metadata"]["name"]: d for d in docs if d["kind"] == kind}


def check(docs, sso, ingress):
    deps = by_kind(docs, "Deployment")
    configs = by_kind(docs, "ConfigMap")
    policies = by_kind(docs, "NetworkPolicy")
    ingresses = by_kind(docs, "Ingress")
    for app, want in APPS.items():
        name = f"sneakers-{app}"
        dep = deps.get(name)
        if dep is None:
            errors.append(f"{app}: not rendered")
            continue
        spec = dep["spec"]["template"]["spec"]
        c = spec["containers"][0]
        sc = spec.get("securityContext") or {}
        if sc.get("runAsUser") != 1000 or sc.get("runAsGroup") != 1000:
            errors.append(f"{app}: runs as {sc.get('runAsUser')}:{sc.get('runAsGroup')}, want 1000:1000")
        if (c.get("securityContext") or {}).get("readOnlyRootFilesystem") is not True:
            errors.append(f"{app}: root filesystem is writable")
        if [p["containerPort"] for p in c["ports"]] != [3000]:
            errors.append(f"{app}: ports {c['ports']}, want 3000")
        for probe in ("startupProbe", "livenessProbe", "readinessProbe"):
            got = (c.get(probe) or {}).get("httpGet") or {}
            if got.get("path") != want["health"] or got.get("port") != 3000:
                errors.append(f"{app}: {probe} {got}, want GET {want['health']} on 3000")
        env = configs.get(name, {}).get("data") or {}
        expect = {
            "PORT": "3000",
            "GATEWAY_URL": "http://sneakers-gateway:9100",
            "APP_ENV": "prod",
            "LOG_LEVEL": "error",
            "LOG_FORMAT": "json",
            "SSO_ENABLED": "true" if sso else "false",
            "STAFF_URL": "/",
            "ADMIN_URL": "/admin/",
            "TRUST_PROXY": "1",
        }
        for k, v in expect.items():
            if env.get(k) != v:
                errors.append(f"{app}: {k}={env.get(k)!r}, want {v!r}")
        policy = policies.get(name)
        if policy is None:
            errors.append(f"{app}: no NetworkPolicy")
        else:
            targets = set()
            for rule in policy["spec"].get("egress") or []:
                for peer in rule.get("to") or []:
                    sel = (peer.get("podSelector") or {}).get("matchLabels") or {}
                    ports = {p.get("port") for p in rule.get("ports") or []}
                    if not sel:
                        if ports - {53}:
                            errors.append(f"{app}: egress to any pod on {sorted(ports, key=str)}")
                        continue
                    targets.add((sel.get("app.kubernetes.io/component"), tuple(sorted(ports, key=str))))
            if targets != {("gateway", ("http",))}:
                errors.append(f"{app}: egress reaches {sorted(targets)}, want only the gateway's http port")
        if ingress:
            ing = ingresses.get(name)
            if ing is None:
                errors.append(f"{app}: no Ingress")
                continue
            rule = ing["spec"]["rules"][0]
            gw = ingresses.get("sneakers-gateway")
            if gw is None or gw["spec"]["rules"][0]["host"] != rule["host"]:
                errors.append(f"{app}: Ingress host {rule['host']!r} is not the gateway's")
            paths = [(p["path"], p["pathType"], p["backend"]["service"]["name"]) for p in rule["http"]["paths"]]
            if paths != [(want["path"], "Prefix", name)]:
                errors.append(f"{app}: Ingress paths {paths}, want [({want['path']!r}, 'Prefix', {name!r})]")


check(load(sys.argv[1]), sso=False, ingress=False)
check(load(sys.argv[2]), sso=True, ingress=True)
for e in errors:
    print(f"web: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
