# Telemetry each service emits

What the nine Go services (identity, vault, workflow, audit, notify, connector, sshbroker, gateway
and mcp) export over OTLP, for the metrics and traces starter repo
(Sneakers-PAM/sneakers-metrics-traces). The web apps are not Go and export nothing here.

Every service wires the same helper, `github.com/Bugs5382/go-otel`, in its own
`internal/telemetry/telemetry.go`, so the instruments are shared and the per-service part is a
set of filters. The workflow service is built from the vault repository (`cmd/workflow`) and uses
the vault's package.

## Switches

Export is off unless the endpoint is set. The chart sets `OTEL_EXPORTER_OTLP_ENDPOINT` from
`global.otlpEndpoint`; `OTLP_LOGS_ENABLED=true` adds log export, and `OTLP_INSECURE_SKIP_VERIFY=true`
is for a lab collector. With an endpoint set, the service's health check reports a failing export.

## Metrics

No service defines a metric of its own name. Every metric comes from three libraries, read from
their sources at the versions in the service `go.mod` files (`go-otel`, `otelgrpc`, `otelhttp`; the
versions are in the generated part below). The table there gives each metric's type, unit,
instrumentation scope and the labels each service keeps.

- gRPC: `rpc.server.call.duration` and `rpc.client.call.duration` are histograms in seconds
  from `otelgrpc`, in its default semantic-convention mode. The older `rpc.server.duration` and
  `rpc.client.duration` (milliseconds) appear only when `OTEL_SEMCONV_STABILITY_OPT_IN` is set to
  `rpc` or `rpc/dup`; no chart sets it. Only services that wire the server or the client handler
  emit them.
- HTTP, from go-otel's `Metrics` middleware (gateway and mcp): `http.server.request.duration` is a
  histogram in seconds, and `http.server.request.count` is a monotonic counter with no unit. The
  count is not a standard OpenTelemetry name. It is documented here as it is rather than renamed,
  because the services at the pinned commits emit it; the standard way to get a request count is
  the count of the duration histogram.
- HTTP, from `otelhttp` (gateway only): `http.server.request.duration` (seconds),
  `http.server.request.body.size` and `http.server.response.body.size` (bytes). The duration shares
  its name with the go-otel one, under a different instrumentation scope.

Metric labels pass the service's allow-list; anything else is dropped before export, and
`http.route` is `unmatched` and the method `_OTHER` for requests no route or standard method
matches.

## Traces

Spans are the gRPC server and client spans from `otelgrpc`, the HTTP server span of the gateway
from `otelhttp`, and, where "Database spans" says yes, one span per PostgreSQL query from
`otelpgx`. Span names pass an allow-list of patterns per service; a span whose name matches none
is still exported, named `[span]`. The names kept are:

- gRPC spans are named by `rpc.method`, `sneakers.<service>.v1.<Service>/<Method>` (the connector
  also keeps `grpc.health.v1.Health/Check` and `Watch`). The server span is kind SERVER, the call
  span kind CLIENT.
- The gateway's HTTP spans are named `<METHOD> <route pattern>` for GET, POST and OPTIONS.
- Database spans are named `query <VERB>`, with the statement text and attributes removed.

The span attributes each service lets through are in the generated part below. The mcp server
creates no spans: it has no gRPC and no `otelhttp` wiring, only the go-otel metrics middleware, so
it has no trace attributes either. Its tool calls appear as the log fields `tool` and
`tool_status`.

## Resource

Every service turns on go-otel's telemetry filter, so the only resource attribute that leaves is
`service.name`, whatever `OTEL_RESOURCE_ATTRIBUTES` says. The value is the service's own name, the
constant `serviceName` in its `cmd/<service>/main.go`: `identity`, `vault`, `workflow`, `audit`,
`notify`, `connector`, `sshbroker`, `gateway` and `mcp`. The workflow service is built from the
vault repository and reports as `workflow`.

## Log fields

Logs leave the process only when `OTLP_LOGS_ENABLED=true`, and only the fields on each service's
allow-list. They hold ids, counts, durations, classes, states and short enums; names, emails,
addresses, error text and secret values stay off. A "class-only" field is logged as a class, never
its text.

## Contract per service

The block below is generated from each service at the commit `manifest/release.yaml` pins. Do not
edit it by hand. `docs/telemetry.json` holds the same data for tools.

<!-- telemetry-list:begin -->

Release ref: `v0.1.0-rc.7` (`docs/telemetry.ref`). Read from the service sources at the commits `manifest/release.yaml` pins, with go-otel v1.6.0, otelgrpc v0.70.0, otelhttp v0.70.0 and otelpgx v0.11.1. The same data is in `docs/telemetry.json`.

### Metric instruments

| Metric | Type | Unit | Scope | Emitted by (labels kept) |
|---|---|---|---|---|
| `rpc.server.call.duration` | histogram | s | otelgrpc | identity (`rpc.method`, `rpc.response.status_code`); vault (`rpc.method`, `rpc.response.status_code`); workflow (`rpc.method`, `rpc.response.status_code`); audit (`rpc.method`, `rpc.response.status_code`); notify (`rpc.method`, `rpc.response.status_code`); connector (`rpc.method`, `rpc.response.status_code`); sshbroker (`rpc.method`, `rpc.response.status_code`) |
| `rpc.client.call.duration` | histogram | s | otelgrpc | identity (`rpc.method`, `rpc.response.status_code`); vault (`rpc.method`, `rpc.response.status_code`); workflow (`rpc.method`, `rpc.response.status_code`); notify (`rpc.method`, `rpc.response.status_code`); connector (`rpc.method`, `rpc.response.status_code`); sshbroker (`rpc.method`, `rpc.response.status_code`); gateway (`rpc.method`, `rpc.response.status_code`) |
| `http.server.request.duration` | histogram | s | go-otel | gateway (`http.request.method`, `http.route`, `http.response.status_code`); mcp (`http.request.method`, `http.route`, `http.response.status_code`) |
| `http.server.request.count` | counter | none | go-otel | gateway (`http.request.method`, `http.route`, `http.response.status_code`); mcp (`http.request.method`, `http.route`, `http.response.status_code`) |
| `http.server.request.duration` | histogram | s | otelhttp | gateway (`http.request.method`, `http.route`, `http.response.status_code`) |
| `http.server.request.body.size` | histogram | By | otelhttp | gateway (`http.request.method`, `http.route`, `http.response.status_code`) |
| `http.server.response.body.size` | histogram | By | otelhttp | gateway (`http.request.method`, `http.route`, `http.response.status_code`) |
| `db.client.operation.duration` | histogram | s | otelpgx | identity (no labels); vault (no labels); workflow (no labels); audit (no labels) |
| `db.client.operation.errors` | counter | none | otelpgx | identity (no labels); vault (no labels); workflow (no labels); audit (no labels) |

A service keeps a label only when its metric allow-list names it; the table shows the labels that can survive that filter.

- `http.server.request.count` is a go-otel counter (monotonic, no unit), not a standard OpenTelemetry name: the standard way to count requests is the count of the duration histogram.
- `db.client.operation.errors` is a go-otel counter (monotonic, no unit), not a standard OpenTelemetry name: the standard way to count requests is the count of the duration histogram.
- The gateway records `http.server.request.duration` twice, once from go-otel's `Metrics` and once from otelhttp, under two instrumentation scopes; read them by scope.
- The go-otel histogram uses the SDK's default bucket boundaries, which are sized for milliseconds although its unit is seconds.

### identity

Source: `Sneakers-PAM/sneakers-identity` at `574276214447`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `identity`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `rpc.client.call.duration`, `db.client.operation.duration`, `db.client.operation.errors`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc); `^query [A-Z]+$` (client, otelpgx).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `access`, `acting_admin`, `acting_user_id`, `action`, `attempt`, `attempts`, `auth`, `code`, `component`, `custom_ca`, `dependencies`, `dependency`, `disabled`, `duration_ms`, `error_class`, `force`, `from`, `granted`, `groups`, `kept_keys`, `keys`, `method`, `orphans`, `port`, `required`, `retry_in`, `retry_in_ms`, `revoked`, `service_account_id`, `tls_mode`, `to`, `token_id`, `user_id`, `verify`.

### vault

Source: `Sneakers-PAM/sneakers-vault` at `57255803af15`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `vault`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `rpc.client.call.duration`, `db.client.operation.duration`, `db.client.operation.errors`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc); `^query [A-Z]+$` (client, otelpgx).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `action`, `active_ref`, `actor`, `actor_user_id`, `allowed`, `attempt`, `caller`, `clamped`, `confirm`, `count`, `cutoff`, `decided_by`, `dependencies`, `dependency`, `dev_static_kek_loaded`, `end_reason`, `error_class`, `expires_at`, `folder_id`, `folders`, `found`, `from_target_id`, `from_type_id`, `heartbeat_opt_out`, `item`, `items`, `lease_id`, `method`, `mode`, `new_version_no`, `parent_id`, `port`, `principal_id`, `principal_kind`, `request_id`, `requested`, `result`, `retention_days`, `retry_in`, `reveals`, `rewrapped_records`, `rewrapped_versions`, `rotated_by`, `rotation_opt_out`, `rpc`, `run_id`, `secret_id`, `secrets`, `session_id`, `state`, `target_id`, `to_type_id`, `token_id`, `type_id`, `use_id`, `user_id`, `value_version`, `verb`, `version_no`, `worker_id`.

### workflow

Source: `Sneakers-PAM/sneakers-vault` at `57255803af15`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `workflow`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `rpc.client.call.duration`, `db.client.operation.duration`, `db.client.operation.errors`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc); `^query [A-Z]+$` (client, otelpgx).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `action`, `active_ref`, `actor`, `actor_user_id`, `allowed`, `attempt`, `caller`, `clamped`, `confirm`, `count`, `cutoff`, `decided_by`, `dependencies`, `dependency`, `dev_static_kek_loaded`, `end_reason`, `error_class`, `expires_at`, `folder_id`, `folders`, `found`, `from_target_id`, `from_type_id`, `heartbeat_opt_out`, `item`, `items`, `lease_id`, `method`, `mode`, `new_version_no`, `parent_id`, `port`, `principal_id`, `principal_kind`, `request_id`, `requested`, `result`, `retention_days`, `retry_in`, `reveals`, `rewrapped_records`, `rewrapped_versions`, `rotated_by`, `rotation_opt_out`, `rpc`, `run_id`, `secret_id`, `secrets`, `session_id`, `state`, `target_id`, `to_type_id`, `token_id`, `type_id`, `use_id`, `user_id`, `value_version`, `verb`, `version_no`, `worker_id`.

### audit

Source: `Sneakers-PAM/sneakers-audit` at `bca59c038358`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `audit`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `db.client.operation.duration`, `db.client.operation.errors`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^query [A-Z]+$` (client, otelpgx).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `attempt`, `attempts`, `bearer_file`, `ca_file`, `code`, `dependencies`, `dependency`, `duration_ms`, `error_class`, `from`, `jwks_override`, `kept_keys`, `keys`, `method`, `port`, `required`, `retry_in`, `to`.

### notify

Source: `Sneakers-PAM/sneakers-notify` at `06638da4cb8b`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `notify`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `rpc.client.call.duration`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Log fields that leave the process: `attempt`, `attempts`, `bearer_file`, `ca_file`, `code`, `component`, `dependencies`, `dependency`, `duration_ms`, `env`, `error_class`, `from`, `jwks_override`, `kept_keys`, `keys`, `method`, `otlp_insecure_skip_verify`, `otlp_logs`, `port`, `required`, `retry_in`, `retry_in_ms`, `to`.

### connector

Source: `Sneakers-PAM/sneakers-connector` at `4c1df9583d1d`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `connector`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `rpc.client.call.duration`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc); `^grpc\.health\.v1\.Health/(Check|Watch)$` (server, otelgrpc); `^grpc\.health\.v1\.Health/(Check|Watch)$` (client, otelgrpc).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Class-only log fields (logged as a class, never the text): `error`, `detail`, `reason`.
- Log fields that leave the process: `admin_count`, `backoff`, `builtin_administrator`, `dependency`, `detail`, `error`, `error_class`, `error_code`, `from`, `pinned_certificates`, `pinned_keys`, `port`, `reason`, `required`, `result`, `secret_id`, `to`.

### sshbroker

Source: `Sneakers-PAM/sneakers-sshbroker` at `de68e5156d22`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `sshbroker`; attributes that leave: `service.name`.
- Metrics: `rpc.server.call.duration`, `rpc.client.call.duration`.
- Metric attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (server, otelgrpc); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc).
- Trace attributes allowed: `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Class-only log fields (logged as a class, never the text): `error`, `reason`.
- Log fields that leave the process: `action`, `actor_user_id`, `attempt`, `attempts`, `caller`, `code`, `dependency`, `duration`, `duration_ms`, `elapsed`, `elapsed_ms`, `error`, `error_class`, `from`, `kept_keys`, `keys`, `method`, `pinned_keys`, `principal_kind`, `reason`, `reference`, `required`, `retry_in`, `secret_id`, `span_id`, `step`, `step_ms`, `target_id`, `to`, `took`, `trace_id`.

### gateway

Source: `Sneakers-PAM/sneakers-gateway` at `13cd05d8cbe6`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `gateway`; attributes that leave: `service.name`.
- Metrics: `rpc.client.call.duration`, `http.server.request.duration`, `http.server.request.count`, `http.server.request.duration`, `http.server.request.body.size`, `http.server.response.body.size`.
- Metric attributes allowed: `http.request.method`, `http.response.status_code`, `http.route`, `rpc.method`, `rpc.response.status_code`.
- Span names kept (any other name is exported as `[span]`): `^(GET|POST|OPTIONS) /` (server, otelhttp); `^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$` (client, otelgrpc).
- Trace attributes allowed: `http.request.method`, `http.response.status_code`, `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Log fields that leave the process: `action`, `actor`, `actor_user_id`, `age_ms`, `appliance_configmap`, `approval_run_links`, `auth_mode`, `caller`, `check`, `class`, `client_id`, `client_kind`, `code`, `confirmed`, `connection_id`, `cookie_secure`, `count`, `current`, `decided`, `decision`, `dependency`, `dur`, `duration`, `duration_ms`, `error_class`, `fallback`, `folders`, `from`, `host_keys`, `hydra_enabled`, `machine_api_enabled`, `maintenance_readonly`, `mcp_clients`, `mcp_enabled`, `ms`, `ok`, `refused`, `required`, `route`, `rule`, `run_id`, `secret_id`, `secrets`, `session_id`, `session_ttl`, `sso_reason`, `state`, `status`, `step`, `target_id`, `to`, `token_id`, `use_id`, `user_id`, `workload`.

### mcp

Source: `Sneakers-PAM/sneakers-mcp` at `528f52f483cb`, `internal/telemetry/telemetry.go`.

- Resource: `service.name` = `mcp`; attributes that leave: `service.name`.
- Metrics: `http.server.request.duration`, `http.server.request.count`.
- Metric attributes allowed: `http.request.method`, `http.route`, `http.response.status_code`.
- Span names: none, the service creates no spans.
- Trace attributes allowed: none.
- Database spans: no.
- Log fields that leave the process: `api_tokens`, `dependency`, `dur`, `error_class`, `from`, `hydra`, `required`, `status`, `to`, `tool`, `tool_status`.

<!-- telemetry-list:end -->

## Recording telemetry for acceptance

Two recordings come from the kind install test, with the chart and the service images at the
release ref named in `docs/telemetry.ref`. The values in step 3 were checked with `helm template`;
the collector and the full kind run with it were not run here, and the install test itself is what
`test/kind/run.sh` does today.

1. Check out the release ref, create the cluster the way `.github/workflows/install-test.yml` does
   (`kind create cluster`, the `KIND_NODE_IMAGE` there), and run `test/kind/build-images.sh`. It
   builds each service from the commits in `test/kind/services.txt`, which `scripts/check-manifest.py`
   keeps equal to the commits in `manifest/release.yaml`.
2. Create the namespace and run an OpenTelemetry Collector in it, with an OTLP gRPC receiver on
   4317 and the `file` exporter on its traces, metrics and logs pipelines, so every OTLP request is
   written as JSON lines to a volume.
3. Write a values file with `global.otlpEndpoint: http://<collector service>.<namespace>:4317`,
   `global.logLevel: info`, `OTLP_LOGS_ENABLED: "true"` in the services' `env`, and an egress rule
   on `mcp.networkPolicy.egress` for the collector's port (the mcp server's egress otherwise allows
   only DNS, the gateway and Hydra, so it could not export).
4. Real run: `BASE_VALUES=<that file> test/kind/run.sh`. The test installs, upgrades, runs
   `helm test` and calls every edge, so each service exports its metrics, spans and logs. Copy the
   collector's files out as the recording.
5. Stopped service: with the release installed and healthy, scale one service away
   (`kubectl -n <namespace> scale deploy/sneakers-<service> --replicas=0`), make its callers use it
   (the `helm test` hook, or a request through the gateway), wait one export interval (the SDK's
   default is 60 seconds), and copy the collector's files again. The callers' client spans end in an
   error status and their `rpc.client.call.duration` points carry a non-OK `rpc.response.status_code`;
   the callers' dependency-state log lines change to `down`.

Check a recording against `docs/telemetry.json`: every metric name, span name pattern and
`service.name` in it must be in the file, and nothing else.

## Keeping it current

`scripts/telemetry-list.py --write` rebuilds the generated block and `docs/telemetry.json` from the
pinned commits, and `--check` fails when either, or `docs/telemetry.ref`, no longer matches.
`docs/telemetry.ref` is set by hand to the release ref the metrics-traces repo reads. The script
reads GitHub through `gh`, so it runs when a release pin changes and as a release check, not on
every pull request. It also fails when a service's `go.mod` names another `go-otel`, `otelgrpc` or
`otelhttp` version than the one the instrument table in the script was read from: read the
library sources again, update the table and the versions, then run `--write`.
`python3 scripts/test_telemetry_list.py` tests the script offline.
