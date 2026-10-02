# Migrating to Sneakers-PAM with sneakers-migrate

`sneakers-migrate` moves an install of the original Sneakers system to Sneakers-PAM without losing
anything: secrets with every version, folders and access rules, users and groups with their sign-in
and second factor, targets, connections and schedules, and the audit chain, which still verifies.
The first target is a Helm install of the umbrella chart; the appliance uses the same tool later.

One binary, four commands:

| Command | Runs | Does |
|---|---|---|
| `keygen` | target side | makes the import key pair (an age X25519 identity) and prints its public recipient |
| `export` | next to the original system | reads it and writes one bundle encrypted to the recipient |
| `import` | next to the new install | loads the bundle into a fresh, empty install |
| `verify` | next to the new install | checks the install against the bundle |

The tool is in `migrate/` (Go, cobra) and is built as an image from `migrate/Dockerfile`:

```bash
docker build -f migrate/Dockerfile -t sneakers-migrate .
```

## How it works

### Export

- Reads each service database (identity, vault, workflow, audit) in one read-only, repeatable-read
  snapshot. Give it a read-only database role; it never writes to the source.
- Refuses a source it doesn't know: each database must be at the migration version of the source
  profile it reads (`original-v1`: identity 10, vault 6, workflow 1, audit 1), and not dirty. The
  workflow service's version is in `workflow_schema_migrations`; `schema_migrations` there belongs
  to the go-saga engine.
- Opens every sealed secret version with the source key ring in memory: the vault root key unwraps
  each working key in `kek_keyring`, and each record's data key opens under its `KeyRef`. Records
  sealed under the legacy `dev-static-v1` key need the source's `DEV_KEK_SEED`. TOTP secrets open
  under the source identity's `TOTP_ENC_KEY`.
- Reads every Kratos identity through the admin API with its password hash
  (`include_credential=password`).
- Checks the audit chain from genesis to head and stops if it doesn't verify.
- Picks the sample secrets (`--sample-secret`, or `--samples` picked evenly among active shared
  secrets) and records a keyed hash (HMAC-SHA256, under a random per-bundle key) of each sensitive
  value, current and every version. Verify reveals the current values; import checks the older
  versions before sealing them.
- Writes one bundle and never plaintext: the bundle is built in memory and written only encrypted.

### The bundle

A gzipped tar, encrypted with age to the import recipient. Holding it without the target's import
identity reveals nothing.

- `manifest.json`: the format version, the bundle id, the source profile and versions (Kratos
  included), per-table row counts and SHA-256 checksums, the audit chain head, the sample hashes and
  their key, and the list of what isn't carried and why.
- `streams/<service>.<table>.ndjson`: one stream per table, newline-delimited JSON, ids kept. Sealed
  values travel opened (inside the encryption), so the target can re-seal them.

Import refuses a bundle of another major format version, and any stream that doesn't match its
checksum or count.

### Import

- Refuses a target that already holds data that isn't this bundle's. "Empty" means no users,
  groups, service accounts, secrets, secret versions, folders, targets, approval requests, leases
  or audit records, and no Kratos identities. A production install is empty until its first-run
  setup, so import before setup: the bundle brings the root user, the built-in types and settings.
- Checks every target database is at baseline version 1.
- Creates each Kratos identity with its traits, state, addresses and password hash, so people keep
  their password. Kratos assigns new ids; the identity service's `subject` follows them.
- Maps the old layout to the new one (below), then has the target vault re-seal every secret
  version through its `SealForImport` RPC, so the target root key never leaves the vault. TOTP
  secrets are re-encrypted under the target identity's `TOTP_ENC_KEY`. WebAuthn credentials are
  public keys and carry over as they are.
- Writes each service database in one transaction, in dependency order, through the baseline
  layout. The vault transaction holds the vault's write lock. Seed rows the vault may hold (types,
  catalogue, policies, settings, connections) are replaced by the source's.
- Inserts the audit chain first, record for record with its stored hashes, never recomputed, so
  every entry the import causes lands after the source head: the vault's `vault.import.seal`
  entries for each re-seal call, then the migration's own entries appended through the audit
  service, which hashes them onto the chain: one per item closed by the migration and one
  `migration.import` summary.
- Checks every older-version sample against the opened value it is about to seal, before anything
  is written, and stops if one doesn't match (exit code 5: the bundle doesn't match its manifest).
  The count of matched samples goes into the report and the `migration.import` summary
  (`version_samples_matched`), so it is on the audit chain. Values are never printed.
- Reviews the security settings: the report lists each imported setting next to the target's
  default (API access to super-sensitive fields, MFA for sensitive check-out, step-up before a
  reveal and the folder overrides, retention, session lifetime, working-key rotation, the default
  password policy). The original system stored the sensitive-data switches but didn't enforce
  them; the target does. So the report warns, with counts, on each one that will now restrict
  something, for example tokens losing super-sensitive fields while API access is off, or check-outs
  needing a fresh MFA. Change those settings before the cutover if the old behaviour is needed.
- Is resumable: a service whose tables already hold exactly the bundle's rows is skipped, Kratos
  identities that already exist are reused, and migration audit entries are never appended twice.
  A failed service transaction leaves that service empty, so a re-run picks it up.
- Restart the vault afterwards (`kubectl rollout restart deployment/sneakers-vault`): it holds its
  state in memory and loads the imported rows on start.

### Mapping, old to new

| Area | Change |
|---|---|
| Identity | `users.keycloak_subject` becomes `subject`, remapped to the new Kratos id. A user without a Kratos identity gets an empty subject and is listed in the report. |
| Identity | Pending email codes and WebAuthn ceremony state are transient and left behind (counted in the report). The source keeps no lldap group-sync state; the report says so. |
| Vault | The source key ring isn't carried: every value is re-sealed under the target's own. |
| Vault | Security settings import as stored, but the target enforces them: API access to super-sensitive fields, MFA for sensitive check-out and step-up before a reveal. The report warns on each one that now restricts something. |
| Vault | `target_ssh_host_keys` is new and stays empty: brokered SSH to those targets is refused until an admin pins the keys. The report lists every SSH target that needs pins. |
| Vault | Pending or approved uses without reveal end as expired; in-flight rotation and heartbeat claims are cleared, and a rotation that was running is marked failed ("interrupted by migration"). |
| Workflow | Open approval requests close as denied by the migration, with a comment "Expired by migration."; open check-outs are returned. Each gets an audit entry, so force check-outs back before a cutover. |
| Kratos | Only password hashes import. Any other Kratos credential type is counted in the report; second factors live in the identity service. |

### Verify

Any mismatch fails the run (exit code 4):

- **Counts:** every table holds the manifest's rows (plus the comments import adds), the audit
  table holds the source records up to the source head, and Kratos holds every identity.
- **Audit chain:** the audit service's `VerifyChain` and an independent walk both verify from
  genesis to head, and the record at the source head seq still has the source head hash.
- **Sample reveals:** every sample's current value, revealed through the vault, matches its keyed
  hash. Values are never printed or stored. These prove the re-seal opens.
- **Versions:** older versions are never revealed, so verify doesn't need the vault's recovery-gated
  `RevealSecretVersionField`. Instead every secret's versions in the target match the bundle by
  version number and timestamp, each is sealed with the bundle's field names, and the import's
  `migration.import` audit summary records that every older-version sample matched before sealing.
- **Targets (dry run):** every target resolves to its connection, and every connection's
  privileged secret resolves. Nothing is contacted: a rehearsal denies egress.

Verify reveals and lists as a root actor named for the tool (`MIGRATE_PRINCIPAL`), so those reads
are audited as the tool's, not a person's.

## Guardrails

- **Rehearsal mode:**
  - The umbrella chart's `rehearsal.enabled` renders a deny-all egress NetworkPolicy for the
    namespace (other pods in it and the cluster DNS only), and the chart refuses to render with the
    connector (rotation, heartbeats), the SSH broker (brokered sessions) or the MCP server (agent
    access) on. `test/migrate/rehearsal-values.yaml` is that layer. For an install that isn't the
    umbrella chart, apply `migrate/deploy/rehearsal-egress.yaml`.
  - `import --rehearsal` also turns KEK rotation off and is the only mode that allows
    `--wipe-target` and `--owner-email`.
- **One account changed:** `--owner-email` gives that account a new random password, shown once on
  the terminal and never in the report or the log. Every other account is imported as it is.
- **No values in output:** logs and reports carry ids and counts only; never a value, a hash of a
  value, a password hash or a token.
- **Keys:** secrets come from the environment only (a Job fills it from Kubernetes Secrets), never
  from flags.

## Configuration

| Variable | Used by | Meaning |
|---|---|---|
| `SOURCE_IDENTITY_DSN`, `SOURCE_VAULT_DSN`, `SOURCE_WORKFLOW_DSN`, `SOURCE_AUDIT_DSN` | export | the source databases (a read-only role) |
| `SOURCE_KRATOS_ADMIN_URL` | export | the source Kratos admin API |
| `SOURCE_VAULT_ROOT_KEK` | export | the source vault's root key (base64, 32 bytes) |
| `SOURCE_DEV_KEK_SEED` | export | the source's `DEV_KEK_SEED`, when records still use `dev-static-v1` |
| `SOURCE_TOTP_ENC_KEY` | export | the source identity's `TOTP_ENC_KEY`, when users have TOTP |
| `TARGET_IDENTITY_DSN`, `TARGET_VAULT_DSN`, `TARGET_WORKFLOW_DSN`, `TARGET_AUDIT_DSN` | import, verify | the target databases |
| `TARGET_KRATOS_ADMIN_URL` | import, verify | the target Kratos admin API |
| `TARGET_VAULT_ADDR`, `TARGET_AUDIT_ADDR` | import, verify | the target vault and audit gRPC addresses |
| `TARGET_TOTP_ENC_KEY` | import | the target identity's `TOTP_ENC_KEY` |
| `MIGRATE_PRINCIPAL` | import, verify | the workload principal and audit actor (default `system:sneakers-migrate`) |
| `WORKLOAD_TOKEN_FILE` | import, verify | the projected ServiceAccount token sent as the caller's workload identity |
| `LOG_LEVEL`, `LOG_FORMAT` | all | logging (console format unless `LOG_FORMAT` says otherwise; `-v` is trace) |

The target vault must list the principal in `VAULT_IMPORT_PRINCIPALS` for the import
(`vault.env.VAULT_IMPORT_PRINCIPALS`); take it out after the cutover.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | any other error (a connection, a file, a service) |
| 2 | a bad flag, argument or missing setting |
| 3 | refused: the source or target version, a target holding other data, a rehearsal-only flag, a missing key |
| 4 | verify found a mismatch |
| 5 | the bundle won't open with this identity, is damaged, or is from another major version |

## The synthetic rehearsal

The same flow runs in CI (the Migrate Rehearsal workflow) and on a build box, with invented data:

```bash
kind create cluster --name sneakers --image kindest/node:v1.36.4
test/kind/build-images.sh                                  # the service images
docker build -f migrate/Dockerfile -t ci.example.org/sneakers-migrate:ci .
kind load docker-image ci.example.org/sneakers-migrate:ci --name sneakers
test/migrate/rehearsal.sh
```

`test/migrate/rehearsal.sh` refuses any kubectl context that isn't a kind cluster. It:

1. starts a source Postgres and Kratos in containers, applies the source schema
   (`migrate/testdata/source-schema`, or `SOURCE_SCHEMA_DIR`) and seeds it with
   `migrate/test/synth`: 30 users with passwords and TOTP, groups, folders and rules, 200 secrets
   with several versions sealed under an invented key ring (older generations and the legacy key
   included), SSH and AD targets, schedules, open approvals, check-outs and uses, and 1,000 chained
   audit records;
2. installs the umbrella chart in rehearsal mode;
3. runs `keygen`, `export`, the import Job (`--rehearsal --owner-email`), a vault restart and the
   verify Job;
4. runs the negative tests: a rehearsal pod can't reach the cluster API while a pod in another
   namespace can, the connector, SSH broker and MCP server aren't deployed and no rotation or
   heartbeat work is claimed, an import into a target holding another user is refused (exit 3), and
   a tampered audit record fails verify (exit 4).

Only counts and results are kept, in `$WORK_DIR/results.txt`; the source, its keys and the bundle
are removed when it ends. The source-schema fixture is the Sneakers-PAM baselines plus the two
mapped differences; it was checked against the original migration chains with a
`pg_dump --schema-only` diff.

## The real-data rehearsal: QA on the production cluster

Real data is proved once, after the v0.1.0 tag, as a separate QA install on the production cluster
in rehearsal mode. Every production step needs the owner's explicit yes at the time.

1. **Install QA.** Deploy the tagged release as its own namespace with rehearsal mode on, and the
   import principal on the vault:

   ```bash
   helm install sneakers charts/sneakers -n sneakers-qa --create-namespace \
     -f <the install's values> -f test/migrate/rehearsal-values.yaml
   ```

   Don't run first-run setup: the import brings the root user.
2. **Import key, QA side.** Run `keygen` locally into an encrypted path, store the identity as the
   Secret `sneakers-migrate-key` (key `import.key`) in the QA namespace, and keep the recipient.
3. **Export, original side.** In the original system's namespace, create the Secret
   `sneakers-migrate-source` with the `SOURCE_*` settings: read-only DSNs for the four databases,
   the in-cluster Kratos admin URL, and the key ring material (the vault's `VAULT_ROOT_KEK`, its
   `DEV_KEK_SEED` if the vault's KEK report still shows `dev-static-v1` rows, and identity's
   `TOTP_ENC_KEY`). Let the export pod reach the four databases and the Kratos admin port (its
   pods are labelled `app.kubernetes.io/name: sneakers-migrate`). Then:

   ```bash
   SOURCE_NAMESPACE=<original namespace> MIGRATE_IMAGE=<image@digest> HOLDER_IMAGE=<busybox@digest> \
     RECIPIENT=<age1...> envsubst <migrate/deploy/export-job.yaml | kubectl apply -f -
   kubectl -n <original namespace> wait --for=condition=ready pod -l job-name=sneakers-migrate-export
   kubectl -n <original namespace> cp -c holder <pod>:/bundle/bundle.age ./bundle.age
   kubectl -n <original namespace> delete job sneakers-migrate-export
   ```

4. **Import, QA side.** Store the bundle as the Secret `sneakers-migrate-bundle` (key
   `bundle.age`; a bundle over 1 MiB goes on a volume instead), then:

   ```bash
   NAMESPACE=sneakers-qa JOB_NAME=sneakers-migrate-import MIGRATE_IMAGE=<image@digest> \
     COMMAND_ARGS='["import", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key", "--rehearsal", "--owner-email", "<owner address>"]' \
     envsubst <migrate/deploy/import-job.yaml | kubectl apply -f -
   kubectl -n sneakers-qa logs -f job/sneakers-migrate-import
   kubectl -n sneakers-qa rollout restart deployment/sneakers-vault
   ```

   The owner's new password is in that log once; delete the Job when it's read.
5. **Verify**, the same manifest with `JOB_NAME=sneakers-migrate-verify` and
   `COMMAND_ARGS='["verify", "--bundle", "/bundle/bundle.age", "--identity", "/key/import.key"]'`,
   then the owner's own checks in the QA install.
6. **Wipe.** Remove the QA namespace, its volumes, the bundle and the import identity. Keep only the
   import and verify reports (counts and results).

`migrate/deploy/import-job.yaml` assumes the umbrella chart's names for a release called
`sneakers` with the bundled PostgreSQL and Kratos; change the DSNs and addresses for anything else.

## Cutover

Only after the v0.1.0 tag, on the adopter's own Kubernetes:

1. **Free the space.** Shut down the original system's dev and QA deployments.
2. **QA on the production cluster.** The real-data rehearsal above.
3. **Take the original production down.** Freeze it to read-only, force open check-outs back, take
   the final export, then stop it.
4. **Production.** Deploy Sneakers-PAM as production with `vault.env.VAULT_IMPORT_PRINCIPALS` set
   and without rehearsal mode, import the final export (no `--rehearsal`, so no wipe and no owner
   password), restart the vault, verify, turn automation on (the connector, SSH broker and MCP
   server) after verify, pin the SSH host keys the report lists, take `VAULT_IMPORT_PRINCIPALS`
   out, then switch the address over.
5. **Clean up.** Remove the QA install. The original system's data stays read-only until the owner
   signs off, then it's retired.

## Error codes

| Code | Area | Cause |
| --- | --- | --- |
| 1001 | source | the source database is at a version this tool does not read, or a migration is dirty |
| 1002 | source | the source audit chain does not verify |
| 1003 | source | a source value does not open with the given keys |
| 2001 | target | the target database is not at the baseline this tool writes |
| 2002 | target | the target already holds data that is not this bundle's |
| 2003 | mode | the flag is only allowed in rehearsal mode |
| 2004 | target | a target key the import needs is missing or invalid |
| 3001 | verify | the target does not match the bundle |
| 4001 | bundle | the bundle is damaged or does not match its manifest |
| 4002 | bundle | the bundle does not open with the given identity |
| 4003 | bundle | the bundle is from another major version |
