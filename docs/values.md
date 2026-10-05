# Values

Every chart validates its values against its `values.schema.json`, so a misspelt key or a value of
the wrong type stops `helm install` and `helm template` with the path that's wrong. The service
charts share one schema, kept in `charts/sneakers-lib/service.schema.json` and copied into each
chart by `scripts/sync-schemas.sh`.

## The umbrella (`charts/sneakers`)

| Value | Default | Meaning |
|---|---|---|
| `global.host` | `sneakers.example.org` | The public host name. Feeds the passkey relying party, the OAuth and MCP URLs, the SSH WebSocket URL, the Kratos return URLs and the Ingress hosts. |
| `global.environment` | `production` | `ENVIRONMENT` for every service. `prod` or `production` turn on the production checks: no dev worker token and no dev keys. |
| `global.logLevel` | `error` | `LOG_LEVEL` for every service: `trace`, `debug`, `info`, `warn`, `error`. |
| `global.logFormat` | `json` | `LOG_FORMAT` for every service. Clusters log `json`. |
| `global.otlpEndpoint` | (empty) | OTLP gRPC collector (`host:port`) for traces and metrics. |
| `bundledSecrets.enabled` | `true` | Create the Secrets the bundled pieces share (below). |
| `<service>.enabled` | `true` | Install that service: `identity`, `vault`, `workflow`, `audit`, `notify`, `connector`, `sshbroker`, `gateway`, `mcp`, `web-staff`, `web-admin`. |
| `rehearsal.enabled` | `false` | Migration rehearsal mode ([migrate.md](migrate.md)): a deny-all egress NetworkPolicy for the namespace (other pods in it and the cluster DNS only), and the chart refuses to render with `connector`, `sshbroker` or `mcp` enabled. Never on for production. |
| `rehearsal.dnsNamespace` | `kube-system` | The namespace of the cluster DNS the rehearsal policy still allows. |
| `rehearsal.apiServer.addresses` | `[]` | The Kubernetes API server's endpoint addresses as CIDRs (`kubectl get endpoints kubernetes -n default`). Only the services that check caller tokens may reach them, to fetch the cluster's signing keys. Required with rehearsal mode on. |
| `rehearsal.apiServer.port` | `6443` | The API server endpoint port. |
| `gateway.env.MCP_HEALTH_URL` | `http://sneakers-mcp:9101/livez` | Where the gateway's diagnostics query reads the MCP server's build (its `Sneakers-Version` and `Sneakers-Commit` headers). Set it to `""` with `mcp.enabled: false`, so mcp shows as not configured. |
| `global.sso.enabled` | `false` | `SSO_ENABLED` for both web apps: shows the single sign-on button. Turn it on with the gateway's SSO settings. |
| `<service>.*` | | That service chart's values (next section). The umbrella sets each database DSN and points each `secretEnv` at the bundled Secrets. |
| `postgres.enabled` | `true` | The bundled PostgreSQL (`charts/postgres`). |
| `valkey.enabled` | `true` | The bundled Valkey ([valkey-helm](https://github.com/valkey-io/valkey-helm)); its values pass through. |
| `kratos.enabled` | `true` | The bundled Ory Kratos ([ory/k8s](https://github.com/ory/k8s)); its values pass through. |
| `hydra.enabled` | `false` | The bundled Ory Hydra ([ory/k8s](https://github.com/ory/k8s)); its values pass through. |
| `bundledNetworkPolicies.enabled` | `true` | NetworkPolicies for the bundled Kratos and Hydra, whose charts ship none. See [install.md](install.md#service-to-service-traffic). |
| `bundledNetworkPolicies.kratosPublicFrom` | `[]` | More peers for Kratos's public port, besides the gateway. |
| `bundledNetworkPolicies.kratosAdminFrom` | `[]` | Extra peers (NetworkPolicy `from` entries) admitted to the Kratos admin port, besides the identity service, the gateway and Kratos itself. A migration adds the `sneakers-migrate` Jobs ([migrate.md](migrate.md)). |
| `bundledNetworkPolicies.hydraPublicFrom` | any pod | More peers for Hydra's public port, besides the gateway and mcp: the edge OAuth clients come through. |
| `tests.image` | curl, pinned | The image of the `helm test` pod. |
| `tests.resources` | 10m and 16Mi requested, 200m and 64Mi limit | The `helm test` pod's requests and limits. |

The one value with no default is the vault root key:
`vault.secretEnv.VAULT_ROOT_KEK.secretName` (or `generate: true`). See [install.md](install.md).

### The bundled Secrets

Created when `bundledSecrets.enabled` is true. Every value is generated on the first install, read
back on every upgrade, and kept on uninstall.

| Secret | Keys | Used by |
|---|---|---|
| `sneakers-bundled` | `password`, `postgres-password` | PostgreSQL (the `sneakers` role and the superuser); `PGPASSWORD` for the services |
| `sneakers-bundled` | `valkey-password`, `redis-url` | Valkey; `REDIS_URL` for the vault, notify, sshbroker and gateway |
| `sneakers-kratos` | `dsn`, `secretsDefault`, `secretsCookie`, `secretsCipher`, `smtpConnectionURI` | Kratos, when Kratos and PostgreSQL are both bundled |
| `sneakers-hydra` | `dsn`, `secretsSystem`, `secretsCookie` | Hydra, when Hydra and PostgreSQL are both bundled |

## A service chart (`charts/<service>`)

All nine service charts take the same values. Each one also works on its own, outside the umbrella.

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/sneakers-pam/sneakers-<service>` | The image. |
| `image.tag` | (the chart's appVersion) | The tag. |
| `image.digest` | (empty) | `sha256:...`. When set it wins over the tag. |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `fullnameOverride` | (empty: `sneakers-<service>`) | The name of every resource. The other services' defaults expect the fixed names. |
| `replicas` | `2` (`1` for audit) | Pods, when autoscaling is off. The audit service is the single writer of its hash chain: keep it at one. |
| `strategy` | `RollingUpdate` (`Recreate` for audit) | The Deployment strategy. |
| `autoscaling.*` | off | A CPU HorizontalPodAutoscaler: `enabled`, `minReplicas`, `maxReplicas`, `targetCPUUtilizationPercentage`. |
| `podDisruptionBudget.enabled` | `true` | A budget for services with more than one pod. |
| `podDisruptionBudget.minAvailable` | `1` | Or set `maxUnavailable`. |
| `logLevel`, `logFormat` | (empty: the global values) | Per-service overrides. |
| `service.port`, `service.portName` | the service's port, `grpc` or `http` | The main port. |
| `service.extraPorts` | `[]` (`http` 9097 for sshbroker) | More ports, each `{name, port}`. |
| `probes.*` | gRPC health, or HTTP `/livez` and `/readyz` | Startup, liveness and readiness probes: `type`, `port`, `startupFailureThreshold`. Liveness (and startup) checks the process only: gRPC health service `livenessService` (`liveness`), or HTTP `livenessPath`. Readiness follows the service's required dependencies: the default gRPC health service, or HTTP `readinessPath`. Unset, both use `path` or the default gRPC service. |
| `env` | per service | Non-secret settings, rendered into the ConfigMap. Values go through `tpl` (so `{{ .Values.global.host }}` works); an empty value is left out so the service uses its own default. The settings are in each service's `docs/configuration.md`. |
| `requiredEnv` | `[DATABASE_DSN]` where there is a database | Keys of `env` that must not be empty. |
| `secretEnv.<VAR>` | per service | A setting read from a Secret: `secretName`, `key` (default: the variable name), `required`. With `generate: true` and no `secretName` the chart creates the value once (`bytes` random bytes, base64) in `sneakers-<service>-generated`, kept on upgrade and uninstall. |
| `envFromSecrets` | `[]` | Secrets loaded whole as environment variables. |
| `extraEnv` | `[]` | More container env, in Kubernetes form. |
| `resources` | 50m and 64Mi requested, 1 CPU and 512Mi limit | Requests and limits; both are required. |
| `podSecurityContext` | non-root (65532), `RuntimeDefault` seccomp | `runAsNonRoot` must stay true. |
| `securityContext` | read-only root filesystem, no privilege escalation, all capabilities dropped | `readOnlyRootFilesystem` must stay true and `allowPrivilegeEscalation` false. |
| `serviceAccount.*` | one per service, no token mounted | `create`, `name`, `automountToken`. |
| `projectedToken.*` | off | An extra kubelet-rotated ServiceAccount token: `audience`, `expirationSeconds`, `mountPath`, `path`, `clusterCA` (also mount the cluster CA), `envName` (a variable set to the token's path). It can't use the workload identity paths below. |
| `workloadIdentity.caller` | on for every service that makes gRPC calls | Mount a token with audience `workloadIdentity.audience` at `/var/run/secrets/sneakers/token` and set `WORKLOAD_TOKEN_FILE` to it. The service sends it on every gRPC call. |
| `workloadIdentity.callers` | the service's callers ([install.md](install.md#service-to-service-traffic)) | The services allowed to call this one's main port. The NetworkPolicy admits only their pods there. `migrate` is the `sneakers-migrate` Jobs, listed on the vault and audit only for a migration ([migrate.md](migrate.md)). |
| `workloadIdentity.verify` | on for vault, workflow, sshbroker, audit, notify and identity | Check the callers' tokens: sets `WORKLOAD_OIDC_ISSUER`, `WORKLOAD_OIDC_JWKS_URL`, `WORKLOAD_OIDC_CA_FILE`, `WORKLOAD_OIDC_BEARER_FILE`, `WORKLOAD_AUDIENCE` and `WORKLOAD_ALLOWED_SERVICEACCOUNTS` (`<namespace>/sneakers-<caller>` for each caller), and mounts an API token and the cluster CA at `/var/run/secrets/tokens` for the key fetch. Needs `callers`. |
| `workloadIdentity.audience`, `expirationSeconds` | `sneakers`, `3600` | The caller token's audience and lifetime. |
| `workloadIdentity.issuer`, `jwksURL` | the in-cluster issuer and JWKS | Where a callee checks the tokens. Both must be https. |
| `sso.enabled` | `false` | Gateway only. SAML single sign-on through your Ory Polis: sets `POLIS_PUBLIC_URL` and `POLIS_CLIENT_SECRET`. Requires `sso.publicURL` and `sso.clientSecret.secretName`. Setting `env.POLIS_PUBLIC_URL` without it is refused. |
| `sso.publicURL` | (empty) | `POLIS_PUBLIC_URL`, the Polis URL the browser is sent to. |
| `sso.clientSecret.secretName`, `key` | (empty), `POLIS_CLIENT_SECRET` | The Secret and key holding `POLIS_CLIENT_SECRET`: the `CLIENT_SECRET_VERIFIER` your Polis runs with. There is no default value; the gateway refuses to start with Polis's development value. |
| `caBundle.*` | off | One key of a ConfigMap with a PEM bundle, pointed to by `envName` (`SSL_CERT_FILE`). The bundle replaces the system roots, so it must hold every root the service needs. |
| `extraVolumes`, `extraVolumeMounts` | `[]` | |
| `networkPolicy.enabled` | `true` | Ingress on the main port only from the services in `workloadIdentity.callers`; nothing else from the release. |
| `networkPolicy.ingressFrom`, `networkPolicy.ingressPorts` | any pod in the cluster, on `http`, for gateway, mcp, sshbroker and the web apps; none for the rest | More peers, for the ingress controller. |
| `networkPolicy.egress` | `[]` (DNS, the gateway and Hydra for mcp) | Egress rules. Empty means no egress policy. |
| `ingress.*` | off | `enabled`, `className`, `host` (default `global.host` for the edge services), `annotations`, `tlsSecretName`, `paths` (each `{path, pathType, portName}`). |
| `migrations.job.*` | off | A pre-upgrade Job running the image with `args`. Off until the services have a migrate-only command; they migrate at start today. |
| `podLabels`, `podAnnotations`, `priorityClassName`, `terminationGracePeriodSeconds`, `nodeSelector`, `tolerations`, `affinity` | | Pod placement and metadata. |
| `topologySpreadConstraints` | spread over nodes, best effort | Values go through `tpl`. |

### Per-service settings the umbrella and the defaults set

| Service | Port | Database | Secrets (`secretEnv`) | Notes |
|---|---|---|---|---|
| identity | 9192 | `sneakers_identity` | `PGPASSWORD`, `TOTP_ENC_KEY` (optional), `SMTP_PASS` (optional) | Set `SMTP_HOST` to send email. Without `TOTP_ENC_KEY` the TOTP second factor is unavailable; changing it makes stored TOTP secrets unreadable. |
| vault | 9091 | `sneakers_vault` | `PGPASSWORD`, `VAULT_ROOT_KEK` (required), `REDIS_URL` | Checks the connector's projected token against the cluster's ServiceAccount issuer, `https://kubernetes.default.svc.cluster.local` by default. Read yours with `kubectl get --raw /.well-known/openid-configuration` and set `env.WORKLOAD_OIDC_ISSUER`. |
| workflow | 9193 | `sneakers_workflow` | `PGPASSWORD` | |
| audit | 9194 | `sneakers_audit` | `PGPASSWORD` | One replica, `Recreate`. |
| notify | 9195 | | `REDIS_URL` (required) | The inboxes live in Valkey or Redis. |
| connector | 9196 (health) | | | Sends a projected token with audience `sneakers-vault`. Mount a CA bundle with `caBundle` for LDAPS to a private CA. |
| sshbroker | 9096, 9097 | | `REDIS_URL` | Without Redis the tickets stay in memory: run one replica. |
| gateway | 9100 | | `REDIS_URL` (required), `SETUP_TOKEN`, `POLIS_API_KEY`, `POLIS_CLIENT_SECRET` (with `sso.enabled`) | `AUTH_MODE=real`, secure cookies, MFA enforced. |
| mcp | 9101 | | | Accepts service-account and personal tokens; Hydra JWTs once `HYDRA_ISSUER` is set. |
| web-staff | 3000 | | | The staff app at `/`. Runs as uid 1000. Health: `GET /healthz`. Settings: `GATEWAY_URL` (required), `APP_ENV` (`prod`), `SSO_ENABLED` (from `global.sso.enabled`), `STAFF_URL` (`/`), `ADMIN_URL` (`/admin/`), `TRUST_PROXY` (`1`: the proxies whose `X-Forwarded-*` headers the app trusts, as a hop count or the ingress's address range; leave it empty wherever clients reach the pod directly). Egress: the gateway and DNS only. `caBundle.envName` is `NODE_EXTRA_CA_CERTS`. |
| web-admin | 3000 | | | The admin app at `/admin/`, same settings as web-staff. Health: `GET /admin/healthz`. |

## The bundled PostgreSQL (`charts/postgres`)

| Value | Default | Meaning |
|---|---|---|
| `image.*` | `postgres:18.6`, pinned by digest | |
| `auth.existingSecret` | (required; the umbrella sets `sneakers-bundled`) | The Secret with both passwords. |
| `auth.username` | `sneakers` | The role that owns the databases. |
| `auth.passwordKey`, `auth.superuserPasswordKey` | `password`, `postgres-password` | Keys in that Secret. |
| `databases` | one per service, plus Kratos and Hydra | Created on the first start only. |
| `persistence.size`, `persistence.storageClass`, `persistence.accessModes` | `10Gi`, the default class, `ReadWriteOnce` | The data volume, kept when the release is deleted. |
| `resources` | 100m and 256Mi requested, 2 CPUs and 1Gi limit | |
| `parameters` | `{}` (the image's defaults) | Server settings, each passed as `-c <name>=<value>`: `shared_buffers`, `work_mem`, `maintenance_work_mem`, `max_connections` and any other. |
| `shm.sizeLimit` | `256Mi` | The memory-backed `/dev/shm`, used by parallel query workers. It counts against the pod's memory. |
| `networkPolicy.enabled` | `true` | Only this release's pods may connect. |

## Sizing examples

Sizing is yours. The chart has no profiles and doesn't look at the hardware: the defaults are
the same everywhere, and every request, limit, replica count, PostgreSQL setting and volume size is
a value you set. Two example files show what a small and a larger install might use. Nothing in
the chart or the appliance loads them; copy what you want into your own values file, or pass one
with `-f` ahead of your own.

| File | For | Memory (all pods) |
|---|---|---|
| [`charts/sneakers/examples/values-small-box.yaml`](../charts/sneakers/examples/values-small-box.yaml) | One node with 4 to 8 GB: a Raspberry Pi 4 or 5, or a small VM, on k3s, k0s or kind | under 1 GiB requested, under 3 GiB of limits |
| [`charts/sneakers/examples/values-large-box.yaml`](../charts/sneakers/examples/values-large-box.yaml) | Three or more nodes with 16 GB or more | about 9 GiB requested |

The small box runs one pod per service, a PostgreSQL with `shared_buffers` 64MB, `work_mem` 2MB,
`maintenance_work_mem` 32MB and `max_connections` 50, a Valkey capped at 64mb, and Hydra off (it
only serves machine callers of the MCP server). The larger box runs three pods for most services
(audit always runs one), Kratos on three, and a PostgreSQL with `shared_buffers` 2GB.

Each Go service keeps its own connection pool of up to the larger of 4 and the node's CPU count,
so `max_connections` has to cover every service pod's pool plus Kratos and Hydra. The PostgreSQL
blocks in both files use the current bundled chart (`charts/postgres`); they change when
sneakers-release#44 replaces it with helm-postgres-ha, which adds PgBouncer pooling.

`scripts/check-resources.py` (run by `scripts/check-charts.sh`) keeps this honest: it fails if a
chart template writes in a resource figure, a memory-backed volume size or a replica count instead
of reading a value, and it renders both examples and fails if the small one's memory requests pass
1 GiB or its limits 3 GiB, with Hydra on or off.
