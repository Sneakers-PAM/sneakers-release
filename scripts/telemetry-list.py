#!/usr/bin/env python3
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
"""Build the telemetry contract: docs/telemetry.md, docs/telemetry.json, docs/telemetry.ref.

Reads each Go service's source at the commit manifest/release.yaml pins for it
(one tarball per repository through `gh api`, so it needs a signed-in gh and
network) and takes from it the service.name, the resource attributes, the span
names and attributes its filter lets through, the metric attributes, the log
field allow-list, and whether it wires the gRPC server and client handlers,
the HTTP middleware, otelhttp and database spans. The instruments themselves
come from three libraries (go-otel, otelgrpc, otelhttp), read from their
sources at the versions in INSTRUMENTS; the script fails when a service's
go.mod names another version, so the table is read again before it is trusted.

The same data renders three files, and --check covers all of them:

  docs/telemetry.md    the generated block between the markers, for people
  docs/telemetry.json  the machine-readable contract the metrics-traces repo reads
  docs/telemetry.ref   one line: the release ref that repo reads (set by hand)

  telemetry-list.py           print the generated Markdown block
  telemetry-list.py --json    print docs/telemetry.json
  telemetry-list.py --write   rewrite the block and docs/telemetry.json
  telemetry-list.py --check   exit 1 when any of the three is out of date
"""
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "telemetry.md"
JSON_FILE = ROOT / "docs" / "telemetry.json"
REF_FILE = ROOT / "docs" / "telemetry.ref"
BEGIN = "<!-- telemetry-list:begin -->"
END = "<!-- telemetry-list:end -->"
# The nine Go services, in the order the release manifest lists them. The web
# apps are not Go and carry no telemetry package. The workflow service is built
# from the vault repository, from cmd/workflow.
SERVICES = ["identity", "vault", "workflow", "audit", "notify", "connector", "sshbroker", "gateway", "mcp"]
PLACEHOLDER = "[span]"
REF = re.compile(r"v\d+\.\d+\.\d+(-rc\.\d+)?")
SLICE = re.compile(r"(?:var\s+)?(\w+)\s*=\s*\[\]string\{(.*?)\}", re.S)

# The versions the INSTRUMENTS table was read from. A service whose go.mod names
# another version fails the run until the table is read again.
LIBRARIES = {
    "go-otel": ("github.com/Bugs5382/go-otel", "v1.6.0"),
    "otelgrpc": ("go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc", "v0.70.0"),
    "otelhttp": ("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", "v0.70.0"),
}
SCOPE_GO_OTEL = "github.com/Bugs5382/go-otel"
SCOPE_OTELGRPC = LIBRARIES["otelgrpc"][0]
SCOPE_OTELHTTP = LIBRARIES["otelhttp"][0]
RPC_ATTRS = ["rpc.method", "rpc.response.status_code"]
HTTP_ATTRS = ["http.request.method", "http.route", "http.response.status_code"]
SECONDS_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10]

# What the three libraries create, read from their sources at the versions above.
# "when" is the wiring that makes a service emit it, "attributes" the attributes
# the instrument can carry that a service's metric allow-list can keep.
#   otelgrpc stats_handler.go: rpcconv.NewServerCallDuration / NewClientCallDuration
#     (semconv v1.43.0, unit "s"), made in the default semantic-convention mode.
#     OTEL_SEMCONV_STABILITY_OPT_IN=rpc/dup or rpc would add or swap in the older
#     rpc.server.duration and rpc.client.duration (unit "ms"); no chart sets it.
#   otelhttp internal/semconv/server.go: httpconv.NewServerRequestDuration,
#     NewServerRequestBodySize, NewServerResponseBodySize.
#   go-otel metrics.go: Metrics() makes Histogram("http.server.request.duration",
#     unit "s") and Counter("http.server.request.count"), no unit.
INSTRUMENTS = [
    {"name": "rpc.server.call.duration", "type": "histogram", "unit": "s", "scope": SCOPE_OTELGRPC,
     "library": "otelgrpc", "standard": True, "when": "grpc_server", "attributes": RPC_ATTRS,
     "boundaries": SECONDS_BUCKETS, "description": "Duration of gRPC calls served."},
    {"name": "rpc.client.call.duration", "type": "histogram", "unit": "s", "scope": SCOPE_OTELGRPC,
     "library": "otelgrpc", "standard": True, "when": "grpc_client", "attributes": RPC_ATTRS,
     "boundaries": SECONDS_BUCKETS, "description": "Duration of gRPC calls made."},
    {"name": "http.server.request.duration", "type": "histogram", "unit": "s", "scope": SCOPE_GO_OTEL,
     "library": "go-otel", "standard": True, "when": "http_middleware", "attributes": HTTP_ATTRS,
     "boundaries": "sdk-default", "description": "Duration of inbound HTTP requests (go-otel Metrics)."},
    {"name": "http.server.request.count", "type": "counter", "unit": "", "scope": SCOPE_GO_OTEL,
     "library": "go-otel", "standard": False, "when": "http_middleware", "attributes": HTTP_ATTRS,
     "boundaries": None, "description": "Count of inbound HTTP requests (go-otel Metrics); monotonic."},
    {"name": "http.server.request.duration", "type": "histogram", "unit": "s", "scope": SCOPE_OTELHTTP,
     "library": "otelhttp", "standard": True, "when": "otelhttp", "attributes": HTTP_ATTRS,
     "boundaries": SECONDS_BUCKETS, "description": "Duration of inbound HTTP requests (otelhttp)."},
    {"name": "http.server.request.body.size", "type": "histogram", "unit": "By", "scope": SCOPE_OTELHTTP,
     "library": "otelhttp", "standard": True, "when": "otelhttp", "attributes": HTTP_ATTRS,
     "boundaries": "sdk-default", "description": "Size of inbound HTTP request bodies."},
    {"name": "http.server.response.body.size", "type": "histogram", "unit": "By", "scope": SCOPE_OTELHTTP,
     "library": "otelhttp", "standard": True, "when": "otelhttp", "attributes": HTTP_ATTRS,
     "boundaries": "sdk-default", "description": "Size of HTTP response bodies."},
]


# --- reading the sources ----------------------------------------------------

def strings(body):
    body = re.sub(r"//[^\n]*", "", body)
    return re.findall(r'"([^"]+)"', body)


def parse(src):
    """The filter settings of one internal/telemetry/telemetry.go."""
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
    filtered = "WithTelemetryFilter(true)" in src
    if filtered:
        resource = ["service.name"]
        for args in re.findall(r"WithResourceAllowAttributes\((.*?)\)", src, re.S):
            resource += [a for a in strings(args) if a not in resource]
    else:
        # Without the filter the SDK's default resource leaves, and so does
        # whatever OTEL_RESOURCE_ATTRIBUTES adds.
        resource = ["service.name", "telemetry.sdk.language", "telemetry.sdk.name", "telemetry.sdk.version"]
    return {
        "logs": sorted(set(logs)),
        "class_only": class_only,
        "trace": trace,
        "metric": metric,
        "db": "otelpgx" in src,
        "filtered": filtered,
        "resource": resource,
        "span_names": span_name_patterns(src),
    }


def span_name_patterns(src):
    """The regular expressions WithTraceAllowSpanNames lets through, in call order."""
    out = []
    for args in re.findall(r"WithTraceAllowSpanNames\((.*?)\)", src, re.S):
        for ident in [a.strip() for a in args.split(",") if a.strip()]:
            m = re.search(r"\b" + re.escape(ident) + r"\s*=\s*regexp\.MustCompile\(`([^`]*)`\)", src)
            if not m:
                raise SystemExit(f"span name pattern {ident!r} is not a raw-string regexp.MustCompile in the source")
            if m.group(1) not in out:
                out.append(m.group(1))
    return out


def scan(files, cmd):
    """What a service wires, from its non-test Go files (path -> text).

    Only cmd/<cmd>/ and internal/ count: the repository may hold other commands
    (the vault repository also builds the workflow service and seed tools).
    """
    mine = {p: re.sub(r"//[^\n]*", "", t) for p, t in files.items()
            if p.startswith(f"cmd/{cmd}/") or p.startswith("internal/")}
    joined = "\n".join(mine.values())
    main = mine.get(f"cmd/{cmd}/main.go", "")
    m = re.search(r"\bserviceName\s*=\s*\"([^\"]+)\"", main)
    client = False
    for text in mine.values():
        # The helper that wraps the client handler is a definition, not a use.
        text = re.sub(r"func ClientStatsHandler\(\)[^{]*\{.*?\n\}", "", text, flags=re.S)
        if re.search(r"NewClientHandler\(|GRPCClientStatsHandler\(|\bClientStatsHandler\(\)", text):
            client = True
    return {
        "service_name": m.group(1) if m else None,
        "grpc_server": bool(re.search(r"NewServerHandler\(|GRPCServerStatsHandler\(", joined)),
        "grpc_client": client,
        "http_middleware": bool(re.search(r"\b(?:otel|gootel|otelhelper)\.Metrics\(", joined)),
        "otelhttp": "otelhttp.NewHandler(" in joined,
    }


def version_problems(svc, gomod):
    out = []
    for lib, (path, want) in LIBRARIES.items():
        m = re.search(re.escape(path) + r"\s+(v[\w.\-+]+)", gomod)
        if m and m.group(1) != want:
            out.append(f"{svc}: go.mod has {lib} {m.group(1)}, the instrument table was read at {want}")
    return out


# --- building the data ------------------------------------------------------

def span_kind_entries(pattern, found, info):
    """The span entries one allowed name pattern stands for in this service."""
    if "query" in pattern:
        return [("CLIENT", "otelpgx")] if info["db"] else []
    if "GET" in pattern or "POST" in pattern:
        return [("SERVER", "otelhttp")] if found["otelhttp"] else []
    out = []
    if found["grpc_server"]:
        out.append(("SERVER", "otelgrpc"))
    if found["grpc_client"]:
        out.append(("CLIENT", "otelgrpc"))
    return out


def build_data(services, pins, sources, ref, version=None):
    """pins: service -> (repository, commit); sources: service -> {path: text}."""
    data = {
        "schema": 1,
        "release": {"ref": ref, "version": version},
        "libraries": {k: v[1] for k, v in LIBRARIES.items()},
        "export": {
            "endpoint_env": "OTEL_EXPORTER_OTLP_ENDPOINT",
            "protocol": "otlp/grpc",
            "signals": ["traces", "metrics", "logs"],
            "logs_enabled_env": "OTLP_LOGS_ENABLED",
        },
        "span_placeholder": PLACEHOLDER,
        "metrics": [],
        "services": {},
    }
    found_by, info_by = {}, {}
    for svc in services:
        files = sources[svc]
        cmd = svc
        info = parse(files["internal/telemetry/telemetry.go"])
        found = scan(files, cmd)
        found_by[svc], info_by[svc] = found, info
        names = []
        for pattern in info["span_names"]:
            for kind, source in span_kind_entries(pattern, found, info):
                names.append({"pattern": pattern, "kind": kind, "source": source})
        repo, commit = pins[svc]
        data["services"][svc] = {
            "service_name": found["service_name"] or svc,
            "source": {"repository": repo, "commit": commit, "file": "internal/telemetry/telemetry.go"},
            "resource": info["resource"],
            "resource_filtered": info["filtered"],
            "spans": {"placeholder": PLACEHOLDER, "names": names, "attributes": info["trace"]},
            "metrics": [],
            "metric_attributes": info["metric"],
            "database_spans": info["db"],
            "class_only_log_fields": info["class_only"],
            "log_fields": info["logs"],
        }
    for inst in INSTRUMENTS:
        per = {}
        for svc in services:
            if not found_by[svc][inst["when"]]:
                continue
            kept = [a for a in inst["attributes"] if a in info_by[svc]["metric"]]
            per[svc] = kept
            data["services"][svc]["metrics"].append({"name": inst["name"], "scope": inst["scope"]})
        data["metrics"].append({
            "name": inst["name"], "type": inst["type"], "unit": inst["unit"], "scope": inst["scope"],
            "library": inst["library"], "standard": inst["standard"], "boundaries": inst["boundaries"],
            "description": inst["description"], "services": per,
        })
    return data


# --- rendering --------------------------------------------------------------

def render_json(data):
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def code(items):
    return ", ".join(f"`{a}`" for a in items) or "none"


def render_block(data):
    lib = data["libraries"]
    lines = [BEGIN, "",
             f"Release ref: `{data['release']['ref']}` (`docs/telemetry.ref`). Read from the service sources at the "
             f"commits `manifest/release.yaml` pins, with go-otel {lib['go-otel']}, otelgrpc {lib['otelgrpc']} and "
             f"otelhttp {lib['otelhttp']}. The same data is in `docs/telemetry.json`.", "",
             "### Metric instruments", "",
             "| Metric | Type | Unit | Scope | Emitted by (labels kept) |", "|---|---|---|---|---|"]
    for m in data["metrics"]:
        who = "; ".join(f"{s} ({', '.join(f'`{a}`' for a in l) or 'no labels'})" for s, l in m["services"].items()) or "none"
        scope = m["scope"].rsplit("/", 1)[-1] if m["library"] != "go-otel" else "go-otel"
        lines.append(f"| `{m['name']}` | {m['type']} | {m['unit'] or 'none'} | {scope} | {who} |")
    lines += ["",
              "A service keeps a label only when its metric allow-list names it; the table shows the labels that "
              "can survive that filter.", ""]
    odd = [m for m in data["metrics"] if not m["standard"]]
    for m in odd:
        lines.append(f"- `{m['name']}` is a go-otel counter (monotonic, no unit), not a standard OpenTelemetry name: "
                     "the standard way to count requests is the count of the duration histogram.")
    lines.append("- The gateway records `http.server.request.duration` twice, once from go-otel's `Metrics` and "
                 "once from otelhttp, under two instrumentation scopes; read them by scope.")
    lines.append("- The go-otel histogram uses the SDK's default bucket boundaries, which are sized for "
                 "milliseconds although its unit is seconds.")
    lines.append("")
    for svc, s in data["services"].items():
        lines += [f"### {svc}", "",
                  f"Source: `{s['source']['repository']}` at `{s['source']['commit'][:12]}`, `{s['source']['file']}`.", "",
                  f"- Resource: `service.name` = `{s['service_name']}`; attributes that leave: {code(s['resource'])}"
                  f"{'' if s['resource_filtered'] else ' (the resource filter is off)'}."]
        if s["metrics"]:
            lines.append(f"- Metrics: {code([m['name'] for m in s['metrics']])}.")
        else:
            lines.append("- Metrics: none.")
        lines.append(f"- Metric attributes allowed: {code(s['metric_attributes'])}.")
        names = s["spans"]["names"]
        if names:
            lines.append("- Span names kept (any other name is exported as `[span]`): "
                         + "; ".join(f"`{n['pattern']}` ({n['kind'].lower()}, {n['source']})" for n in names) + ".")
        else:
            lines.append("- Span names: none, the service creates no spans.")
        lines.append(f"- Trace attributes allowed: {code(s['spans']['attributes'])}.")
        lines.append(f"- Database spans: {'yes (`query <VERB>`)' if s['database_spans'] else 'no'}.")
        if s["class_only_log_fields"]:
            lines.append("- Class-only log fields (logged as a class, never the text): "
                         + code(s["class_only_log_fields"]) + ".")
        lines.append(f"- Log fields that leave the process: {code(s['log_fields'])}.")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def problems(data, doc_text, json_text, ref_text):
    out = []
    m = re.search(re.escape(BEGIN) + ".*?" + re.escape(END), doc_text, re.S)
    if not m:
        out.append(f"docs/telemetry.md has no {BEGIN} block")
    elif m.group(0) != render_block(data):
        out.append("docs/telemetry.md is out of date: run scripts/telemetry-list.py --write")
    if json_text != render_json(data):
        out.append("docs/telemetry.json is out of date: run scripts/telemetry-list.py --write")
    ref = ref_text.rstrip("\n")
    if "\n" in ref or not REF.fullmatch(ref) or not ref_text.endswith("\n"):
        out.append("docs/telemetry.ref must be one line holding a release ref such as v0.1.0-rc.7")
    elif ref != data["release"]["ref"]:
        out.append(f"docs/telemetry.ref holds {ref} but the data was built for {data['release']['ref']}")
    return out


# --- fetching ---------------------------------------------------------------

_TARBALLS = {}


def fetch_files(repo, commit):
    """Every non-test .go file and go.mod of a repository at a commit: path -> text."""
    key = (repo, commit)
    if key not in _TARBALLS:
        raw = subprocess.run(["gh", "api", f"repos/{repo}/tarball/{commit}"], capture_output=True, check=True).stdout
        files = {}
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                if path == "go.mod" or (path.endswith(".go") and not path.endswith("_test.go")):
                    files[path] = tar.extractfile(member).read().decode("utf-8", "replace")
        _TARBALLS[key] = files
    return _TARBALLS[key]


def collect(ref):
    manifest = yaml.safe_load((ROOT / "manifest" / "release.yaml").read_text())
    svcs = manifest["spec"]["services"]
    pins = {s: (svcs[s]["build"]["repository"], svcs[s]["build"]["commit"]) for s in SERVICES}
    sources, bad = {}, []
    for s in SERVICES:
        files = fetch_files(*pins[s])
        bad += version_problems(s, files.get("go.mod", ""))
        sources[s] = {p: t for p, t in files.items() if p != "go.mod"}
    if bad:
        raise SystemExit("\n".join(bad))
    return build_data(SERVICES, pins, sources, ref, manifest["metadata"]["version"])


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("", "--json", "--write", "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    ref_text = REF_FILE.read_text() if REF_FILE.exists() else ""
    ref = ref_text.strip()
    if not REF.fullmatch(ref):
        print("docs/telemetry.ref must be one line holding a release ref such as v0.1.0-rc.7", file=sys.stderr)
        return 1
    data = collect(ref)
    if mode == "":
        print(render_block(data))
        return 0
    if mode == "--json":
        sys.stdout.write(render_json(data))
        return 0
    doc_text = DOC.read_text()
    if mode == "--check":
        found = problems(data, doc_text, JSON_FILE.read_text() if JSON_FILE.exists() else "", ref_text)
        for p in found:
            print(p, file=sys.stderr)
        if not found:
            print("ok: docs/telemetry.md, docs/telemetry.json and docs/telemetry.ref match the pinned services")
        return 1 if found else 0
    m = re.search(re.escape(BEGIN) + ".*?" + re.escape(END), doc_text, re.S)
    if not m:
        print(f"{DOC} has no {BEGIN} block", file=sys.stderr)
        return 1
    DOC.write_text(doc_text[: m.start()] + render_block(data) + doc_text[m.end():])
    JSON_FILE.write_text(render_json(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
