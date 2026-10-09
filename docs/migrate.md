# Migrating to Sneakers-PAM with sneakers-migrate

`sneakers-migrate` moves an install of the original Sneakers system to Sneakers-PAM: secrets,
folders and access rules, users and groups, targets, connections and schedules, personal and API
tokens, and the audit chain, which still verifies. By default it carries everything, every secret
version and every sign-in included. For a move onto the appliance it can instead carry each
secret's current value only, reset every sign-in (each user sets a new password and enrols a
second factor again), and re-map folders, names and types from a mapping file the owner approves.
[Moving onto the appliance](migrate-appliance.md) is the step-by-step guide for that.

One binary, six commands:

| Command | Runs | Does |
|---|---|---|
| `keygen` | target side | makes the import key pair (an age X25519 identity) and prints its public recipient |
| `export` | next to the original system | reads it and writes one bundle encrypted to the recipient; `--inventory` counts only |
| `review` | anywhere with the import key | lists the bundle's secrets by folder, name and type and writes a mapping template |
| `mapping` | anywhere with the import key | converts a proposal sheet into a mapping file, or checks one, against the bundle |
| `import` | next to the new install | loads the bundle into a fresh, empty install, applying the mapping file |
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
- Counts folders, secrets, types, users, targets and connections in the source, inside the same
  snapshot, and prints them next to the bundle's (the parity report). A difference stops the export
  (exit code 4, error 3002).

Options that change what travels:

- `--current-only`: each secret carries its current version only. Older and staged versions stay
  behind and are listed under "not carried" as `vault.secret_versions.history`.
- `--reset-sign-in`: no password hash, TOTP seed or passkey travels. Kratos identities carry their
  traits and addresses only, `identity.user_totp` and `identity.user_webauthn_credentials` travel
  empty, and `SOURCE_TOTP_ENC_KEY` isn't needed. On the target every user sets a new password
  (the sign-in page's "Forgot password", which needs the product's email set up) and enrols a
  second factor at first sign-in. Personal and API tokens still carry over.
- `--sanitise`: a lab dry-run bundle. It keeps every id, name, folder, rule, type, target, user and
  schedule, replaces every secret value, token hash and target address with a generated fake of the
  same length, and implies `--reset-sign-in`. The sample hashes are taken over the fakes, so verify
  still works. The audit chain travels as it is (ids, actions and client addresses, never values).
  The manifest says `sanitised`, and import takes a sanitised bundle in rehearsal mode only.
- `--inventory`: counts and names only, with no key and no bundle: rows per table, secrets per
  folder and per type, unused types, users per role, personal tokens by id (active or not), the
  rotation and heartbeat schedules, and the Kratos identity count. It needs only the four
  `SOURCE_*_DSN` settings (and `SOURCE_KRATOS_ADMIN_URL` for the identity count). `--out` writes it
  as JSON.

### The bundle

A gzipped tar, encrypted with age to the import recipient. Holding it without the target's import
identity reveals nothing.

- `manifest.json`: the format version, the bundle id, the source profile and versions (Kratos
  included), per-table row counts and SHA-256 checksums, the audit chain head, the sample hashes and
  their key, the list of what isn't carried and why, the parity counts, and whether the bundle is
  current-only, sign-in reset or sanitised.
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
  their password (with a sign-in reset bundle, without any credential). Kratos assigns new ids; the
  identity service's `subject` follows them.
- Applies the mapping file (`--mapping`, below) after the old-to-new mapping, before anything is
  written. A mapping that doesn't fit the bundle stops the import with nothing written (exit code 3,
  error 2005). Outside rehearsal mode the mapping file is required; one that keeps everything is
  three lines.
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
- Prints a parity table for folders, secrets, types, users, targets and connections: the source
  count, what the mapping dropped and created, what the target should hold and what it holds. Any
  difference fails the import loudly (exit code 4, error 3002) after the report is printed; fix the
  cause and re-import with `--wipe-target`.
- Is resumable: a service whose tables already hold exactly the bundle's rows is skipped, Kratos
  identities that already exist are reused (found by email, so identities without credentials are
  found too), and migration audit entries are never appended twice. A failed service transaction
  leaves that service empty, so a re-run picks it up.
- Records on the audit chain, in its `migration.import` summary, the mapping file's SHA-256 and
  what it changed, and whether the bundle was current-only or a sign-in reset. Each secret the
  mapping drops gets a `secret.dropped_by_migration` entry.
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

### The mapping file

The mapping file is the owner's decisions, written down: which folders move or are renamed, which
secrets get a new folder, name or type, and which are left behind. It names things only, never a
value. Import and verify both read it, and verify checks that the import applied the same file (by
its SHA-256 on the audit chain).

```json
{
  "format": "sneakers-migrate-mapping",
  "version": 1,
  "unlisted": "keep",
  "folders": [
    {"from": ["Infrastructure", "Certs/PKI"], "to": "Infrastructure/PKI"},
    {"from": "Old stuff", "drop": true}
  ],
  "types": [
    {"from": "Windows Domain Account", "to": "Active Directory Account",
     "fields": {"user": "username", "pass": "password"}, "drop_fields": ["comment"]}
  ],
  "secrets": [
    {"id": "sec-0001", "from": {"folder": "Infrastructure/ESXI", "name": "esx01 root", "type": "Web Password"},
     "to": {"folder": "Infrastructure/Virtualisation/ESXi", "name": "esx01 - root (lab)"}},
    {"from": {"folder": "Personal", "owner": "user@example.org", "name": "old laptop"}, "drop": true}
  ]
}
```

- **Paths** run from the root, as a string split on `/` or, for a name that holds a `/`, a list of
  names. `from` always names the bundle's own tree; `to` names the tree as the rules leave it.
  Personal folders share a path (each user's is called the same), so `owner` (an email) picks one.
- **`unlisted`** is required: `keep` leaves every secret the file doesn't name where and as it is
  (other users' personal folders, say), `refuse` stops the import if any secret isn't named.
- **Folder rules** run first, in order. A move or rename keeps the folder's id, so its access rules
  and everything in it come along. Missing parents are created as shared folders, with ids derived
  from their path, so import and verify make the same ones. A personal folder can't move into a
  shared one, and a folder can't move inside itself. `drop` removes a folder once the secret rules
  have emptied it; one still holding a secret or a folder is refused.
- **Secret rules** match by `id` (and the `from` names, when given, must agree) or by `from`'s
  folder, name, type and owner, which must match exactly one secret. A secret may be named once.
  `to` changes any of folder (created when missing), name and type; an empty one is unchanged.
  `drop` leaves the secret behind, with its value, versions, schedules, uses, grants, check-outs and
  approval requests. Dropping a connection's privileged secret is refused.
- **Type changes** map each field to the new type's keys: `types` gives the mapping for a pair, and a
  field without one keeps its key. A non-empty field with no place in the new type is refused unless
  it's in `drop_fields`. A rotation or heartbeat schedule the new type can't run is removed.
- A folder that gains or loses secrets has its order renumbered, keeping the secrets' order. Two
  secrets with one name in one folder is a warning in the report, not an error.

`review --template` writes a mapping file that keeps everything, one entry per secret with its id,
to edit. `mapping --tsv` converts a proposal sheet: one row per secret with `current_folder`,
`current_name`, `current_type`, `new_folder`, `new_name`, `new_type` and `action` (`carry` or
`drop`), and an optional `id`. Folders in the sheet are named on their own (not by path): a name
resolves to the one shared folder with that name, and `Personal` to the personal folder of the
account named by `--personal`. A new folder name is created under `--new-folder-parent`, and a folder
whose secrets all move to one new name is renamed instead, so it keeps its access rules. The sheet
has no field mappings, so give them with `--types` (a JSON list of type rules). Either command, and
`mapping --check`, applies the result to the bundle in memory and prints what would change.

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
- **Mapping:** the import's audit summary records the same mapping file verify is given
  (`--mapping`), or neither has one.
- **Parity:** the import's parity table, again: the source, less what the mapping dropped, plus the
  folders it created, is what the target holds.
- **Sign-in reset** (a sign-in reset bundle only): no TOTP seed or passkey is on the target, and at
  most one identity (the first admin's, from `--owner-email`) has a password.
- **Personal tokens:** every active personal (MCP) token in the bundle still authenticates on the
  target, checked by id and never with the token: the same stored hash, not revoked or expired, and
  its user present, enabled and linked to a sign-in identity. A token of a disabled user is skipped.

sneakers-migrate calls the vault as itself and sends no actor: the vault refuses one from it and
acts as its own `system:migrate` actor, so the seals, reveals and lists are audited as the tool's,
not a person's. The vault admits it to `SealForImport`, `RevealSecretField`, `GetSecret`,
`ListTargets` and `ListConnections` only, and only with workload authentication on: with
`WORKLOAD_AUTH=disabled` it refuses `SealForImport`.

## Guardrails

- **Rehearsal mode:**
  - The umbrella chart's `rehearsal.enabled` renders a deny-all egress NetworkPolicy for the
    namespace (other pods in it and the cluster DNS only), and the chart refuses to render with the
    connector (rotation, heartbeats), the SSH broker (brokered sessions) or the MCP server (agent
    access) on. The one exception is the Kubernetes API server, from the services that check caller
    tokens only: they fetch the cluster's signing keys there and refuse every call without them.
    Name its endpoint in `rehearsal.apiServer` (`kubectl get endpoints kubernetes -n default`); the
    chart refuses rehearsal mode without it. `test/migrate/rehearsal-values.yaml` is that layer,
    applied with the migrate callers below. For an install that isn't the umbrella chart, apply
    `migrate/deploy/rehearsal-egress.yaml`.
  - `import --rehearsal` also turns KEK rotation off and makes the mapping file optional.
- **Re-import, never a rollback:** there is no rollback path. If something is wrong after an import,
  fix it and import again with `--wipe-target`, which empties the target (every table this tool
  writes, and Kratos) first. In rehearsal mode it empties any target; outside it, only one an
  earlier import filled (the audit chain holds a `migration.import` summary). A target holding data
  that didn't come from an import is refused, with a message: factory-reset it instead. Without
  `--wipe-target` a target holding other data is always refused.
- **One account changed:** `--owner-email` gives that account a new random password, shown once on
  the terminal and never in the report or the log: in rehearsal mode, or for a sign-in reset bundle,
  where it's the first admin's way in (they change it and enrol a second factor at first sign-in).
  Every other account is imported as it is.
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
| `SOURCE_TOTP_ENC_KEY` | export | the source identity's `TOTP_ENC_KEY`, when users have TOTP (not with `--reset-sign-in`) |
| `TARGET_IDENTITY_DSN`, `TARGET_VAULT_DSN`, `TARGET_WORKFLOW_DSN`, `TARGET_AUDIT_DSN` | import, verify | the target databases |
| `TARGET_KRATOS_ADMIN_URL` | import, verify | the target Kratos admin API |
| `TARGET_VAULT_ADDR`, `TARGET_AUDIT_ADDR` | import, verify | the target vault and audit gRPC addresses |
| `TARGET_TOTP_ENC_KEY` | import | the target identity's `TOTP_ENC_KEY` |
| `MIGRATE_PRINCIPAL` | import | the actor on the migration's own audit entries (default `system:sneakers-migrate`) |
| `WORKLOAD_TOKEN_FILE` | import, verify | the projected ServiceAccount token sent as the caller's workload identity |
| `LOG_LEVEL`, `LOG_FORMAT` | all | logging (console format unless `LOG_FORMAT` says otherwise; `-v` is trace) |

### The migrate callers

For the import and verify Jobs' lifetime, in a rehearsal and a cutover alike, the vault and audit must list `migrate` as a caller
(`vault.workloadIdentity.callers` and `audit.workloadIdentity.callers`, their defaults plus
`migrate`). That puts `<namespace>/sneakers-migrate` in their `WORKLOAD_ALLOWED_SERVICEACCOUNTS` and
admits the Jobs through their NetworkPolicy. The Jobs also read and write the target databases
and the Kratos admin API directly, so the bundled PostgreSQL and Kratos must admit them too:
`postgres.networkPolicy.from` (its default plus the `migrate` component) and
`bundledNetworkPolicies.kratosAdminFrom`. The Jobs run as the `sneakers-migrate` ServiceAccount
with the `migrate` component label of release `sneakers`.

`migrate/deploy/migrate-callers-values.yaml` sets all four. Layer it over the install's values
for the Jobs' lifetime only, then upgrade without it to take every `migrate` entry out again;
`scripts/check-charts.sh` checks each list is its chart default plus `migrate`. A cutover isn't in
rehearsal mode, so nothing denies egress and the token-checking services reach the API server as
usual: `rehearsal.apiServer` is for rehearsals only.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | done |
| 1 | any other error (a connection, a file, a service) |
| 2 | a bad flag, argument or missing setting |
| 3 | refused: the source or target version, a target holding other data, a mode or flag refused, a missing key, a mapping file that doesn't fit |
| 4 | verify found a mismatch, or an export or import parity check failed |
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

## The real-data rehearsal and cutover

The appliance is the target: [Moving onto the appliance](migrate-appliance.md) has the inventory,
the lab dry run with a sanitised bundle, the review and the mapping file, the rehearsal on the
target appliance, the cutover, and what to do when something is wrong (fix and re-import; there is
no rollback). For a Helm install of the umbrella chart the steps are the same, with the Jobs in
`migrate/deploy/` in place of the appliance's Import page:

- `export-job.yaml` runs the export next to the original system, from a Secret
  `sneakers-migrate-source` holding the `SOURCE_*` settings (read-only DSNs, the Kratos admin URL,
  and the key ring material). Copy the bundle out of its holder container, then delete the Job.
- `import-job.yaml` runs `import` (with `COMMAND_ARGS`, the mapping file mounted beside the bundle)
  and then `verify` in the new install, from the Secrets `sneakers-migrate-key` (`import.key`) and
  `sneakers-migrate-bundle` (`bundle.age`). It assumes the umbrella chart's names for a release
  called `sneakers` with the bundled PostgreSQL and Kratos; change the DSNs and addresses for
  anything else.
- Layer `migrate/deploy/migrate-callers-values.yaml` for the Jobs' lifetime only, restart the vault
  after the import, and upgrade without it afterwards.

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
| 2005 | mapping | the mapping file is invalid or does not fit the bundle |
| 3001 | verify | the target does not match the bundle |
| 3002 | parity | the counts after an export or an import do not match the source |
| 4001 | bundle | the bundle is damaged or does not match its manifest |
| 4002 | bundle | the bundle does not open with the given identity |
| 4003 | bundle | the bundle is from another major version |
