#!/usr/bin/env python3
"""Check the gateway's SSO wiring in two renders of the gateway chart.

Usage: check-sso.py <render with SSO off> <render with SSO on>. With SSO off
the gateway gets no Polis URL and no client secret. With SSO on it gets
POLIS_PUBLIC_URL and POLIS_CLIENT_SECRET from the named Secret, which is
required (never optional).
"""
import sys

import yaml


def gateway_env(path):
    env = {}
    with open(path) as f:
        for d in yaml.safe_load_all(f):
            if not d:
                continue
            if d["kind"] == "ConfigMap":
                env.update(d.get("data") or {})
            if d["kind"] == "Deployment":
                for e in d["spec"]["template"]["spec"]["containers"][0].get("env") or []:
                    env[e["name"]] = e.get("value", e.get("valueFrom"))
    return env


off, on = gateway_env(sys.argv[1]), gateway_env(sys.argv[2])
errors = []
for key in ("POLIS_PUBLIC_URL", "POLIS_CLIENT_SECRET"):
    if key in off:
        errors.append(f"SSO off still sets {key}")
if on.get("POLIS_PUBLIC_URL") != "https://sso.example.org":
    errors.append(f"SSO on: POLIS_PUBLIC_URL is {on.get('POLIS_PUBLIC_URL')!r}")
ref = (on.get("POLIS_CLIENT_SECRET") or {}).get("secretKeyRef") if isinstance(on.get("POLIS_CLIENT_SECRET"), dict) else None
if not ref or ref.get("name") != "polis" or ref.get("key") != "POLIS_CLIENT_SECRET" or ref.get("optional"):
    errors.append(f"SSO on: POLIS_CLIENT_SECRET is not a required secretKeyRef to polis: {on.get('POLIS_CLIENT_SECRET')!r}")
for e in errors:
    print(f"sso: {e}", file=sys.stderr)
sys.exit(1 if errors else 0)
