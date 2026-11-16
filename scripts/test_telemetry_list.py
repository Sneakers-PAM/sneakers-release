#!/usr/bin/env python3
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
"""Offline tests for telemetry-list.py: python3 scripts/test_telemetry_list.py

The fixtures are small Go sources shaped like the services' telemetry
packages, so the tests need neither network nor gh.
"""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("telemetry_list", HERE / "telemetry-list.py")
tl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tl)

TELEMETRY_GO = '''package telemetry

var rpcMethod = regexp.MustCompile(`^sneakers\\.[a-z]+\\.v1\\.[A-Za-z]+/[A-Za-z]+$`)
var postgresSpan = regexp.MustCompile(`^query [A-Z]+$`)
var allowedTraceAttributes = []string{"rpc.method", "rpc.response.status_code"}
var allowedMetricAttributes = []string{"rpc.method", "rpc.response.status_code"}
var allowedLogFields = []string{"attempt", "port"}

func Start() {
	gootel.InitWithOptions(ctx, service, s.Endpoint,
		gootel.WithTelemetryFilter(true),
		gootel.WithTraceAllowSpanNames(rpcMethod, postgresSpan),
		gootel.WithTraceAllowAttributes(allowedTraceAttributes...),
		gootel.WithMetricAllowAttributes(allowedMetricAttributes...),
	)
}
func Tracing() { otelpg.WithTracing(otelpgx.WithTrimSQLInSpanName()) }
'''

GATEWAY_GO = '''package telemetry

var rpcMethod = regexp.MustCompile(`^sneakers\\.[a-z]+\\.v1\\.[A-Za-z]+/[A-Za-z]+$`)
var httpSpanName = regexp.MustCompile(`^(GET|POST|OPTIONS) /`)

func Options() []otel.Option {
	return []otel.Option{
		otel.WithTelemetryFilter(true),
		otel.WithTraceAllowSpanNames(httpSpanName, rpcMethod),
		otel.WithTraceAllowAttributes("http.request.method", "rpc.method"),
		otel.WithMetricAllowAttributes("http.request.method", "http.route", "rpc.method"),
		otel.WithResourceAllowAttributes(),
	}
}
'''

SERVER_GRPC = ('grpc.StatsHandler(otelgrpc.NewServerHandler())\n\nfunc ClientStatsHandler() grpc.DialOption {\n'
               '\treturn grpc.WithStatsHandler(otelgrpc.NewClientHandler())\n}\n')
MAIN_NO_CLIENT = 'const serviceName = "connector"\n'
MAIN_CLIENT = 'const serviceName = "identity"\nconn := grpc.NewClient(a, grpc.WithStatsHandler(otelgrpc.NewClientHandler()))\n'
MAIN_GATEWAY = ('const serviceName = "gateway"\nh := otelhttp.NewHandler(withLogging(l, otel.Metrics(mux)), "gateway")\n'
                'grpc.WithStatsHandler(otel.GRPCClientStatsHandler())\n')
MAIN_MCP = 'const (\n\tserviceName = "mcp"\n)\nsrv := otel.Metrics(handler)\n'
MCP_GO = '''package telemetry
func InitOptions() []otelhelper.Option {
	return []otelhelper.Option{
		otelhelper.WithTelemetryFilter(true),
		otelhelper.WithMetricAllowAttributes(MetricAttributes...),
	}
}
var MetricAttributes = []string{"http.request.method", "http.route", "http.response.status_code"}
'''


class Parse(unittest.TestCase):
    def test_span_names_resolve_the_variables(self):
        info = tl.parse(TELEMETRY_GO)
        self.assertEqual(info["span_names"], [r"^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$", r"^query [A-Z]+$"])
        self.assertTrue(info["filtered"])
        self.assertTrue(info["db"])

    def test_resource_is_service_name_only_with_the_filter_on(self):
        self.assertEqual(tl.parse(TELEMETRY_GO)["resource"], ["service.name"])
        self.assertEqual(tl.parse(GATEWAY_GO)["resource"], ["service.name"])

    def test_resource_allow_list_is_added(self):
        src = GATEWAY_GO.replace("WithResourceAllowAttributes()", 'WithResourceAllowAttributes("k8s.pod.name")')
        self.assertEqual(tl.parse(src)["resource"], ["service.name", "k8s.pod.name"])

    def test_unfiltered_resource_names_the_sdk_defaults(self):
        res = tl.parse("package telemetry\n")["resource"]
        self.assertIn("telemetry.sdk.name", res)
        self.assertIn("service.name", res)


class Scan(unittest.TestCase):
    def test_a_definition_of_the_client_handler_is_not_a_use(self):
        found = tl.scan({"cmd/connector/main.go": MAIN_NO_CLIENT, "internal/server/grpc.go": SERVER_GRPC}, "connector")
        self.assertEqual(found["service_name"], "connector")
        self.assertTrue(found["grpc_server"])
        self.assertFalse(found["grpc_client"])

    def test_a_comment_naming_the_client_handler_is_not_a_use(self):
        main = MAIN_NO_CLIENT + "// conn, err := grpc.NewClient(target, server.ClientStatsHandler())\n"
        self.assertFalse(tl.scan({"cmd/connector/main.go": main, "internal/server/grpc.go": SERVER_GRPC}, "connector")["grpc_client"])

    def test_a_use_of_the_client_handler_is_found(self):
        found = tl.scan({"cmd/identity/main.go": MAIN_CLIENT, "internal/server/grpc.go": SERVER_GRPC}, "identity")
        self.assertTrue(found["grpc_client"])

    def test_gateway_has_http_spans_and_both_metric_sources(self):
        found = tl.scan({"cmd/gateway/main.go": MAIN_GATEWAY}, "gateway")
        self.assertTrue(found["otelhttp"])
        self.assertTrue(found["http_middleware"])
        self.assertTrue(found["grpc_client"])
        self.assertFalse(found["grpc_server"])

    def test_the_service_name_is_found_in_a_const_block(self):
        self.assertEqual(tl.scan({"cmd/mcp/main.go": MAIN_MCP}, "mcp")["service_name"], "mcp")


def sample():
    pins = {"identity": ("Sneakers-PAM/sneakers-identity", "a" * 40), "gateway": ("Sneakers-PAM/sneakers-gateway", "b" * 40),
            "mcp": ("Sneakers-PAM/sneakers-mcp", "c" * 40)}
    sources = {
        "identity": {"internal/telemetry/telemetry.go": TELEMETRY_GO, "cmd/identity/main.go": MAIN_CLIENT,
                     "internal/server/grpc.go": SERVER_GRPC},
        "gateway": {"internal/telemetry/telemetry.go": GATEWAY_GO, "cmd/gateway/main.go": MAIN_GATEWAY},
        "mcp": {"internal/telemetry/telemetry.go": MCP_GO, "cmd/mcp/main.go": MAIN_MCP},
    }
    return tl.build_data(["identity", "gateway", "mcp"], pins, sources, "v0.1.0-rc.7")


class Build(unittest.TestCase):
    def test_every_metric_has_a_type_a_unit_and_a_scope(self):
        data = sample()
        for m in data["metrics"]:
            self.assertIn(m["type"], ("histogram", "counter"))
            self.assertIsInstance(m["unit"], str)
            self.assertTrue(m["scope"])
        names = {m["name"]: m for m in data["metrics"]}
        self.assertEqual((names["rpc.server.call.duration"]["type"], names["rpc.server.call.duration"]["unit"]), ("histogram", "s"))
        self.assertEqual((names["http.server.request.count"]["type"], names["http.server.request.count"]["unit"]), ("counter", ""))
        self.assertFalse(names["http.server.request.count"]["standard"])

    def test_metrics_are_assigned_to_the_services_that_emit_them(self):
        by = {m["name"]: m["services"] for m in sample()["metrics"]}
        self.assertEqual(sorted(by["rpc.server.call.duration"]), ["identity"])
        self.assertEqual(sorted(by["rpc.client.call.duration"]), ["gateway", "identity"])
        self.assertEqual(sorted(by["http.server.request.count"]), ["gateway", "mcp"])
        self.assertEqual(sorted(by["http.server.request.body.size"]), ["gateway"])

    def test_labels_are_what_survives_the_service_filter(self):
        by = {m["name"]: m["services"] for m in sample()["metrics"]}
        self.assertEqual(by["rpc.server.call.duration"]["identity"], ["rpc.method", "rpc.response.status_code"])
        self.assertEqual(by["http.server.request.count"]["mcp"], ["http.request.method", "http.route", "http.response.status_code"])
        self.assertEqual(by["http.server.request.count"]["gateway"], ["http.request.method", "http.route"])

    def test_pgx_metrics_come_from_services_with_database_spans(self):
        by = {m["name"]: m for m in sample()["metrics"]}
        for name, kind in (("db.client.operation.duration", "histogram"), ("db.client.operation.errors", "counter")):
            self.assertEqual(by[name]["type"], kind)
            self.assertEqual(by[name]["scope"], "github.com/exaring/otelpgx")
            self.assertEqual(by[name]["library"], "otelpgx")
            self.assertEqual(sorted(by[name]["services"]), ["identity"])
        self.assertEqual(by["db.client.operation.duration"]["unit"], "s")
        names = {m["name"] for m in sample()["services"]["identity"]["metrics"]}
        self.assertIn("db.client.operation.duration", names)
        self.assertNotIn("db.client.operation.duration", {m["name"] for m in sample()["services"]["gateway"]["metrics"]})

    def test_pgx_labels_are_what_survives_the_service_filter(self):
        src = TELEMETRY_GO.replace('var allowedMetricAttributes = []string{"rpc.method", "rpc.response.status_code"}',
                                   'var allowedMetricAttributes = []string{"rpc.method", "db.system.name", "pgx.operation.type"}')
        data = tl.build_data(["identity"], {"identity": ("Sneakers-PAM/sneakers-identity", "a" * 40)},
                             {"identity": {"internal/telemetry/telemetry.go": src, "cmd/identity/main.go": MAIN_CLIENT}},
                             "v0.1.0-rc.7")
        by = {m["name"]: m["services"] for m in data["metrics"]}
        self.assertEqual(by["db.client.operation.duration"]["identity"], ["db.system.name", "pgx.operation.type"])

    def test_services_carry_service_name_spans_and_resource(self):
        svc = sample()["services"]
        self.assertEqual(svc["identity"]["service_name"], "identity")
        self.assertEqual(svc["identity"]["resource"], ["service.name"])
        self.assertEqual(svc["identity"]["spans"]["placeholder"], "[span]")
        kinds = {s["kind"] for s in svc["identity"]["spans"]["names"]}
        self.assertEqual(kinds, {"SERVER", "CLIENT"})
        self.assertEqual(svc["mcp"]["spans"]["names"], [])
        self.assertEqual(svc["mcp"]["spans"]["attributes"], [])

    def test_gateway_http_spans_use_the_allowed_pattern(self):
        names = {s["pattern"] for s in sample()["services"]["gateway"]["spans"]["names"]}
        self.assertIn(r"^(GET|POST|OPTIONS) /", names)


class Render(unittest.TestCase):
    def test_json_is_stable_and_round_trips(self):
        data = sample()
        text = tl.render_json(data)
        self.assertEqual(text, tl.render_json(json.loads(text)))
        self.assertTrue(text.endswith("\n"))

    def test_markdown_states_type_unit_and_the_nonstandard_name(self):
        md = tl.render_block(sample())
        self.assertIn("`http.server.request.count`", md)
        self.assertIn("not a standard OpenTelemetry name", md)
        self.assertIn("### identity", md)
        self.assertIn("`service.name` = `identity`", md)


class Check(unittest.TestCase):
    def doc(self, data):
        return "head\n" + tl.render_block(data) + "\ntail\n"

    def test_matching_files_pass(self):
        data = sample()
        self.assertEqual(tl.problems(data, self.doc(data), tl.render_json(data), "v0.1.0-rc.7\n"), [])

    def test_each_file_is_covered(self):
        data = sample()
        doc, js, ref = self.doc(data), tl.render_json(data), "v0.1.0-rc.7\n"
        self.assertTrue(any("telemetry.md" in p for p in tl.problems(data, doc.replace("identity", "idx"), js, ref)))
        self.assertTrue(any("telemetry.json" in p for p in tl.problems(data, doc, js + " ", ref)))
        self.assertTrue(any("telemetry.ref" in p for p in tl.problems(data, doc, js, "v0.1.0-rc.6\n")))

    def test_the_ref_must_be_one_release_ref_on_one_line(self):
        data = sample()
        for bad in ("main\n", "v0.1.0-rc.7\nv0.1.0-rc.8\n", ""):
            self.assertTrue(tl.problems(data, self.doc(data), tl.render_json(data), bad), bad)


class Versions(unittest.TestCase):
    PGX = "require " + "/".join(["github.com", "exaring", "otelpgx"]) + " "
    OK = "\tgithub.com/Bugs5382/go-otel v1.6.0\n\tgo.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.70.0\n"

    def test_the_read_versions_pass(self):
        self.assertEqual(tl.version_problems("identity", self.OK), [])

    def test_a_bumped_otelpgx_fails_until_the_table_is_reread(self):
        self.assertEqual(tl.version_problems("identity", self.PGX + "v0.11.1\n"), [])
        self.assertTrue(tl.version_problems("identity", self.PGX + "v0.12.0\n"))

    def test_a_bumped_library_fails_until_the_table_is_reread(self):
        bumped = self.OK.replace("v0.70.0", "v0.71.0")
        self.assertTrue(tl.version_problems("identity", bumped))


if __name__ == "__main__":
    unittest.main()
