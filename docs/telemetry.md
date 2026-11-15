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

No service defines a metric of its own name. What exists comes from two shared instruments, read
from the versions in the service `go.mod` files (`go-otel` v1.6.0, `otelgrpc` v0.70.0):

| Metric | From | Services | Attributes kept |
|---|---|---|---|
| `rpc.server.call.duration` (and the older `rpc.server.duration`, per the OpenTelemetry semantic-convention opt-in) | `otelgrpc` server handler | every service with a gRPC port | `rpc.method`, `rpc.response.status_code` |
| `rpc.client.call.duration` (and `rpc.client.duration`) | `otelgrpc` client handler | every service that makes gRPC calls | `rpc.method`, `rpc.response.status_code` |
| `http.server.request.duration` and `http.server.request.count` | `go-otel` HTTP middleware | gateway, mcp | `http.request.method`, `http.route`, `http.response.status_code` |

The attribute lists below are what each service lets through its filter; anything else is
dropped before export.

## Traces

Spans are the gRPC server and client spans from `otelgrpc` (named by `rpc.method`, which each
service restricts to the shape `sneakers.<service>.v1.<Service>/<Method>`), the HTTP server spans
of the gateway and mcp, and, where "Database spans" says yes, one span per PostgreSQL query named
`query <VERB>` from `otelpgx`.

## Log fields

Logs leave the process only when `OTLP_LOGS_ENABLED=true`, and only the fields on each service's
allow-list. They hold ids, counts, durations, classes, states and short enums; names, emails,
addresses, error text and secret values stay off. A "class-only" field is logged as a class, never
its text.

## Per service

The block below is generated from each service at the commit `manifest/release.yaml` pins. Do not
edit it by hand.

<!-- telemetry-list:begin -->

### identity

Source: `Sneakers-PAM/sneakers-identity` at `d0617c688ebd`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `access`, `acting_admin`, `acting_user_id`, `action`, `attempt`, `attempts`, `auth`, `code`, `component`, `custom_ca`, `dependencies`, `dependency`, `disabled`, `duration_ms`, `error_class`, `force`, `from`, `granted`, `groups`, `kept_keys`, `keys`, `method`, `orphans`, `port`, `required`, `retry_in`, `retry_in_ms`, `revoked`, `service_account_id`, `tls_mode`, `to`, `token_id`, `user_id`, `verify`.

### vault

Source: `Sneakers-PAM/sneakers-vault` at `d68f3e0e9375`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `action`, `active_ref`, `actor`, `actor_user_id`, `allowed`, `attempt`, `caller`, `clamped`, `confirm`, `count`, `cutoff`, `decided_by`, `dependencies`, `dependency`, `dev_static_kek_loaded`, `end_reason`, `error_class`, `expires_at`, `folder_id`, `folders`, `found`, `from_target_id`, `from_type_id`, `heartbeat_opt_out`, `item`, `items`, `lease_id`, `method`, `mode`, `new_version_no`, `parent_id`, `port`, `principal_id`, `principal_kind`, `request_id`, `requested`, `result`, `retention_days`, `retry_in`, `reveals`, `rewrapped_records`, `rewrapped_versions`, `rotated_by`, `rotation_opt_out`, `rpc`, `run_id`, `secret_id`, `secrets`, `session_id`, `state`, `target_id`, `to_type_id`, `token_id`, `type_id`, `use_id`, `user_id`, `value_version`, `verb`, `version_no`, `worker_id`.

### workflow

Source: `Sneakers-PAM/sneakers-vault` at `d68f3e0e9375`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `action`, `active_ref`, `actor`, `actor_user_id`, `allowed`, `attempt`, `caller`, `clamped`, `confirm`, `count`, `cutoff`, `decided_by`, `dependencies`, `dependency`, `dev_static_kek_loaded`, `end_reason`, `error_class`, `expires_at`, `folder_id`, `folders`, `found`, `from_target_id`, `from_type_id`, `heartbeat_opt_out`, `item`, `items`, `lease_id`, `method`, `mode`, `new_version_no`, `parent_id`, `port`, `principal_id`, `principal_kind`, `request_id`, `requested`, `result`, `retention_days`, `retry_in`, `reveals`, `rewrapped_records`, `rewrapped_versions`, `rotated_by`, `rotation_opt_out`, `rpc`, `run_id`, `secret_id`, `secrets`, `session_id`, `state`, `target_id`, `to_type_id`, `token_id`, `type_id`, `use_id`, `user_id`, `value_version`, `verb`, `version_no`, `worker_id`.

### audit

Source: `Sneakers-PAM/sneakers-audit` at `2db54060db2a`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: yes (`query <VERB>`).
- Log fields that leave the process: `attempt`, `attempts`, `bearer_file`, `ca_file`, `code`, `dependencies`, `dependency`, `duration_ms`, `error_class`, `from`, `jwks_override`, `kept_keys`, `keys`, `method`, `port`, `required`, `retry_in`, `to`.

### notify

Source: `Sneakers-PAM/sneakers-notify` at `4ef7d2aee989`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Log fields that leave the process: `attempt`, `attempts`, `bearer_file`, `ca_file`, `code`, `component`, `dependencies`, `dependency`, `duration_ms`, `env`, `error_class`, `from`, `jwks_override`, `kept_keys`, `keys`, `method`, `otlp_insecure_skip_verify`, `otlp_logs`, `port`, `required`, `retry_in`, `retry_in_ms`, `to`.

### connector

Source: `Sneakers-PAM/sneakers-connector` at `641581e27e46`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Class-only log fields (logged as a class, never the text): `error`, `detail`, `reason`.
- Log fields that leave the process: `admin_count`, `backoff`, `builtin_administrator`, `dependency`, `detail`, `error`, `error_class`, `error_code`, `from`, `pinned_certificates`, `pinned_keys`, `port`, `reason`, `required`, `result`, `secret_id`, `to`.

### sshbroker

Source: `Sneakers-PAM/sneakers-sshbroker` at `8c86b9e05391`, `internal/telemetry/telemetry.go`.

- Trace attributes: `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Class-only log fields (logged as a class, never the text): `error`, `reason`.
- Log fields that leave the process: `action`, `actor_user_id`, `attempt`, `attempts`, `caller`, `code`, `dependency`, `duration`, `duration_ms`, `elapsed`, `elapsed_ms`, `error`, `error_class`, `from`, `kept_keys`, `keys`, `method`, `pinned_keys`, `principal_kind`, `reason`, `reference`, `required`, `retry_in`, `secret_id`, `span_id`, `step`, `step_ms`, `target_id`, `to`, `took`, `trace_id`.

### gateway

Source: `Sneakers-PAM/sneakers-gateway` at `07f50f5d0dbb`, `internal/telemetry/telemetry.go`.

- Trace attributes: `http.request.method`, `http.response.status_code`, `rpc.method`, `rpc.response.status_code`.
- Metric attributes: `http.request.method`, `http.response.status_code`, `http.route`, `rpc.method`, `rpc.response.status_code`.
- Database spans: no.
- Log fields that leave the process: `action`, `actor`, `actor_user_id`, `age_ms`, `appliance_configmap`, `approval_run_links`, `auth_mode`, `caller`, `check`, `class`, `client_id`, `client_kind`, `code`, `confirmed`, `connection_id`, `cookie_secure`, `count`, `current`, `decided`, `decision`, `dependency`, `dur`, `duration`, `duration_ms`, `error_class`, `fallback`, `folders`, `from`, `host_keys`, `hydra_enabled`, `machine_api_enabled`, `maintenance_readonly`, `mcp_clients`, `mcp_enabled`, `ms`, `ok`, `refused`, `required`, `route`, `rule`, `run_id`, `secret_id`, `secrets`, `session_id`, `session_ttl`, `sso_reason`, `state`, `status`, `step`, `target_id`, `to`, `token_id`, `use_id`, `user_id`, `workload`.

### mcp

Source: `Sneakers-PAM/sneakers-mcp` at `f431e377b824`, `internal/telemetry/telemetry.go`.

- Trace attributes: none set here.
- Metric attributes: `http.request.method`, `http.route`, `http.response.status_code`.
- Database spans: no.
- Log fields that leave the process: `api_tokens`, `dependency`, `dur`, `error_class`, `from`, `hydra`, `required`, `status`, `to`, `tool`, `tool_status`.

<!-- telemetry-list:end -->

## Keeping it current

`scripts/telemetry-list.py --write` rebuilds the block from the pinned commits, and `--check`
fails when `docs/telemetry.md` no longer matches them. It reads GitHub through `gh`, so it runs
when a release pin changes and as a release check, not on every pull request. The hand-written
parts above change only when a service changes how it exports, which `go-otel` and `otelgrpc`
bumps can do.
