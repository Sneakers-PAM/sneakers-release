# Installing Sneakers with Helm

The appliance is the recommended way to run Sneakers: a single-node k0s image built from an
org-signed release, with a maintenance screen, scheduled automatic updates, a database snapshot
before every upgrade and automatic rollback. See the `sneakers-appliance` repository.

Helm on your own Kubernetes is the supported alternative. It installs the same services from the
same pinned release, but some things the appliance does for you become yours:

| | Appliance | Helm |
|---|---|---|
| Upgrades | Scheduled window, maintenance screen, automatic rollback | `helm upgrade`, when you run it |
| Database snapshot before an upgrade | Automatic | Yours to take |
| Backups | Scheduled and encrypted to the backup key | Yours: PostgreSQL and the Secrets listed below |
| Kubernetes | k0s, pinned in the release | Your cluster |
| TLS and the public edge | Built in | Your ingress controller and certificates |

## Requirements

- Kubernetes 1.36 or newer, the version the release is tested on (`manifest/release.yaml` pins
  the k0s version the appliance uses).
- A CNI that enforces NetworkPolicies, or the policies the chart creates do nothing.
- A default StorageClass, or `postgres.persistence.storageClass` and
  `valkey.dataStorage.className` set, for the bundled PostgreSQL and Valkey.
- Helm 3.14 or newer, or Helm 4.
- An ingress controller (or another edge) that terminates TLS for your public host.
- Memory for the pods you run. The defaults run two pods of most services; for one small node (a
  Raspberry Pi 4 or 5, or a small VM) start from the small-box example in
  [values.md](values.md#sizing-examples).

## Install

The charts aren't published to a registry yet; install from a checkout of this repository.

```bash
helm repo add valkey https://valkey.io/valkey-helm/
helm repo add ory https://k8s.ory.sh/helm/charts
helm dependency build charts/sneakers
```

Create the vault root key first. It's 32 random bytes, base64-encoded, and it is permanent for the
database: without it no stored secret can be opened. Keep a copy in your secret store.

```bash
kubectl create namespace sneakers
kubectl -n sneakers create secret generic sneakers-vault-root-key \
  --from-literal=VAULT_ROOT_KEK="$(openssl rand -base64 32)"
```

Then install, with your public host:

```bash
helm install sneakers charts/sneakers -n sneakers \
  --set global.host=sneakers.example.org \
  --set vault.secretEnv.VAULT_ROOT_KEK.secretName=sneakers-vault-root-key
helm test sneakers -n sneakers
```

Without a root key the install stops with an error that names the value to set. For a throwaway
install you can let the chart generate one instead
(`--set vault.secretEnv.VAULT_ROOT_KEK.generate=true`); it is written to the
`sneakers-vault-generated` Secret and kept on uninstall.

Install one release per namespace: the services find each other by fixed names
(`sneakers-vault`, `sneakers-gateway` and so on).

### First start

On the first start the services can restart once or twice while PostgreSQL initialises; each one
applies its own database migrations at start, under an advisory lock, so this is safe.

The gateway's first-run setup (`/setup/bootstrap`) is off until you give it a setup token. Put one
in a Secret, point `gateway.secretEnv.SETUP_TOKEN.secretName` at it, run the setup, then remove
the value again.

## The public edge

The two web apps, the gateway, the MCP server and the SSH broker are the only services reached
from outside. Each chart can render an Ingress; they are off by default:

```yaml
web-staff:
  ingress:
    enabled: true
    className: nginx
    tlsSecretName: sneakers-tls
web-admin:
  ingress:
    enabled: true
    className: nginx
    tlsSecretName: sneakers-tls
gateway:
  ingress:
    enabled: true
    className: nginx
    tlsSecretName: sneakers-tls
mcp:
  ingress:
    enabled: true
    className: nginx
    tlsSecretName: sneakers-tls
sshbroker:
  ingress:
    enabled: true
    className: nginx
    tlsSecretName: sneakers-tls
```

They all use `global.host`, each with its own paths: the staff web app serves `/` and the admin web
app `/admin` (the path is passed on unchanged: each app's base is fixed when its image is built),
and the more specific paths go to the other services. The gateway serves `/graphql`, `/machine`,
`/auth`, `/setup`, `/oauth2` and `/.well-known/oauth-authorization-server`; the MCP server `/mcp`
and `/.well-known/oauth-protected-resource`; the SSH broker `/ssh` (a WebSocket). The edge
services' NetworkPolicies let any pod in the cluster reach their HTTP port; set
`<service>.networkPolicy.ingressFrom` to your ingress controller's namespace to narrow that.

The web apps render on the server and make every gateway call from there, at
`http://sneakers-gateway:9100`; their egress policy allows only that and DNS. The browser talks
to the gateway only for the single sign-on redirect. Your ingress must pass
`X-Forwarded-Proto: https` through, so the apps (`TRUST_PROXY`, one hop by default) and the gateway
see the request as secure.
With single sign-on, set `global.sso.enabled: true` as well as the gateway's SSO settings: it
shows the SSO sign-in in both apps.

## Service-to-service traffic

Every gRPC call between the services carries the caller's projected ServiceAccount token
(audience `sneakers`), and the callee checks it against the cluster's issuer and refuses a
service account that isn't one of its callers. Each service runs as its own service account,
`sneakers-<service>`. The NetworkPolicies admit, on each service's main port, only the callers
below; any other pod, including the other pods of the release, can't connect.

| Service | Callers |
|---|---|
| vault | gateway, workflow, sshbroker, connector |
| workflow | gateway |
| sshbroker (gRPC) | gateway. Its WebSocket port is open to the edge. |
| audit | gateway, vault, sshbroker, identity, workflow |
| notify | vault, gateway |
| identity | gateway, notify |
| connector | none (health probes only) |
| gateway (HTTP) | the edge (any pod in the cluster, which takes in the web apps) and mcp |
| mcp (HTTP) | the edge |

The MCP server's own egress allows only DNS, the gateway's HTTP port and the bundled Hydra's
public port. With an external Hydra or an OTLP collector, add a rule to
`mcp.networkPolicy.egress`.

The bundled pieces take only the services that use them:

| Piece | Port | Callers |
|---|---|---|
| Kratos public | 4433 | gateway, plus `bundledNetworkPolicies.kratosPublicFrom` |
| Kratos admin | 4434 | identity, gateway, and Kratos's own pods (its chart's `helm test` pod) |
| Hydra public | 4444 | gateway, mcp, plus `bundledNetworkPolicies.hydraPublicFrom` (default: any pod, for OAuth clients coming through the edge) |
| Hydra admin | 4445 | only Hydra's own pods (its chart's `helm test` pod). No service calls it; manage its clients with `kubectl port-forward`. |
| Valkey | 6379 | gateway, vault, notify, sshbroker |
| PostgreSQL | 5432 | identity, vault, workflow, audit, Kratos, Hydra |

If you expose Kratos's public API through your ingress, add the ingress controller to
`bundledNetworkPolicies.kratosPublicFrom`.

The callees fetch the cluster's signing keys from `https://kubernetes.default.svc/openid/v1/jwks`
with their own API token. If your cluster's issuer differs (check with
`kubectl get --raw /.well-known/openid-configuration`), set
`<service>.workloadIdentity.issuer` and `jwksURL` on vault, workflow, sshbroker, audit, notify and
identity.

## Bring your own

Each bundled piece can be turned off and replaced with your own. The services take every address
from their `env` values and every credential from a Secret named in their `secretEnv` values.

### PostgreSQL

The identity, vault, workflow and audit services each need their own database. Set
`postgres.enabled=false` and give each service its DSN and password Secret. Keep the password out
of the DSN; the services read it from `PGPASSWORD`.

```yaml
postgres:
  enabled: false
vault:
  env:
    DATABASE_DSN: postgres://sneakers_vault@db.example.org:5432/sneakers_vault?sslmode=require
  secretEnv:
    PGPASSWORD:
      secretName: sneakers-vault-db
      key: password
```

Repeat for `identity`, `workflow` and `audit`. If the runtime DSN goes through a
transaction-pooling proxy, also set `env.MIGRATE_DSN` to a direct connection. With
`postgres.enabled=false` the chart doesn't create the Kratos or Hydra DSN either: see below.

### Valkey or Redis

Set `valkey.enabled=false` and point `REDIS_URL` at your own, from a Secret, for the vault,
notify, sshbroker and gateway:

```yaml
valkey:
  enabled: false
gateway:
  secretEnv:
    REDIS_URL:
      secretName: sneakers-redis
      key: redis-url
```

### Ory Kratos

Set `kratos.enabled=false` and point the identity service (`env.KRATOS_ADMIN_URL`) and the gateway
(`env.KRATOS_PUBLIC_URL`, `env.KRATOS_ADMIN_URL`) at your Kratos. To keep the bundled Kratos with
your own PostgreSQL, create the `sneakers-kratos` Secret yourself with the keys `dsn`,
`secretsDefault`, `secretsCookie`, `secretsCipher` (32 characters each) and `smtpConnectionURI`.

### Ory Hydra

Hydra is off by default. It issues client-credentials tokens for machine callers of the MCP server;
without it, the MCP server accepts service-account and personal tokens, which the gateway checks.
To turn it on, set `hydra.enabled=true` and `hydra.hydra.config.urls.self.issuer`, then on the
gateway `HYDRA_ENABLED: "true"` and `HYDRA_ISSUER`, and on mcp `HYDRA_ISSUER` and
`MCP_RESOURCE_URL`.

### Single sign-on

SAML single sign-on goes through Ory Polis, which isn't bundled. Put the client secret your Polis
checks (its `CLIENT_SECRET_VERIFIER`) in a Secret, then turn SSO on:

```yaml
gateway:
  sso:
    enabled: true
    publicURL: https://sso.example.org
    clientSecret:
      secretName: sneakers-polis
  env:
    POLIS_ISSUER_URL: http://polis.polis.svc:5225
    POLIS_TENANT: example.org
```

The gateway refuses to start with SSO on and no client secret, or Polis's development value. The
other `POLIS_*` settings are in the gateway's configuration docs.

## Upgrades

Run `helm upgrade` with the new release's chart and your values file. The generated passwords and
keys are read back from their Secrets, so an upgrade never changes them. Take a database backup
first: the services migrate their schemas when the new pods start, and a schema change is not
rolled back by `helm rollback`.

Each service chart also has a pre-upgrade migration Job (`migrations.job.enabled`). It stays off
until the service images have a migrate-only command.

## Backups

Back up together:

- the PostgreSQL databases (or the bundled PostgreSQL volume);
- the vault root key Secret;
- `sneakers-bundled`, `sneakers-kratos` and `sneakers-hydra` when the bundled pieces are used;
- any `sneakers-<service>-generated` Secret.

## Uninstall

```bash
helm uninstall sneakers -n sneakers
```

The bundled PostgreSQL volume and the Secrets above are kept, so a reinstall with the same release
name finds the same data and keys. Delete them by hand to remove everything.

## Logs and telemetry

Every service logs JSON at `error` by default (`global.logLevel`, `global.logFormat`, or per
service `logLevel`). Set `global.otlpEndpoint` to an OTLP gRPC collector for traces and metrics.
With no collector set, the services still try their default `localhost:4317` and print a plain-text
export error to stderr every few seconds; that is noise, not a fault.
