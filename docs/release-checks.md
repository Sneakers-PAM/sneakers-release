# Manual checks for a release

The install test covers what a machine can check: the charts install, upgrade and pass
`helm test`, the NetworkPolicies refuse the pods they should, and a cold start with PostgreSQL,
Kratos and Hydra 60 s late reaches Ready without a single container restart
(`test/kind/late-deps.sh`). The checks below need a person,
a browser or a running connector. Run them on a test install of the release candidate before it's
tagged, and record the result of each one in the release's tracking issue.

**A check that fails gets a Bug issue** in the repository that owns the behaviour, linked from
the tracking issue. The release waits until it's fixed or the owner moves it out of the release.

## Setup

- The umbrella installed from the release candidate (`manifest/release.yaml` at the candidate
  commit), with the bundled pieces, behind an ingress with TLS for `global.host`. See
  [install.md](install.md).
- A first admin from the setup flow, with MFA enrolled, and a second user with no access to the
  test secrets.
- A connector reaching a test directory or SSH host made for the run. Every account, host and
  password in the run is generated for it; never point a test install at a real system.
- An MCP client signed in to the MCP server with a personal token for the first admin.
- A desktop browser, and its developer tools for throttling the network.

## 1. Every image reports its release version

- [ ] **MCP server:** the `initialize` response's `serverInfo.version` is the release tag (for
  example `v0.1.0`), not `dev`. Leave `SERVICE_VERSION` unset for the check: it overrides the
  stamped version.
- [ ] **Every other Go service** (identity, vault, workflow, audit, notify, connector, sshbroker,
  gateway) reports the release tag wherever it reports its version. Set
  `<service>.logLevel: info` for the check if the install logs at `error`.

Pass when no image reports `dev`, an empty version or a commit hash in place of the tag. A
service that reports no version at all fails the check.

## 2. MCP: test a secret with a running connector

1. Create a password secret on the test target with the right password, and another with a wrong
   one.
2. Call `sneakers_test_secret` on each.

- [ ] The right password answers `result: ok`.
- [ ] The wrong password answers `result: failed` with a `detail` saying why (for example a
  refused sign-in), and the detail holds no secret value.

## 3. MCP: organise secrets

1. `sneakers_create_folder` creates `Personal`, then `SSH Keys` inside it (`parentId` from
   `sneakers_list_folders`).
2. `sneakers_move_secret` moves a test secret into `Personal/SSH Keys`.
3. `sneakers_rename_secret` renames it.

- [ ] `sneakers_list_folders` shows `Personal/SSH Keys`, and `sneakers_find_secrets` finds the
  secret there under its new name.

## 4. Web: long values on approvals and grants

With a command, a secret name and a label each longer than its column (at least 200 characters):

- [ ] On the approvals list and the grants list each one is cut with an ellipsis, not wrapped or
  spilling over the next column.
- [ ] Hovering shows the full value in a tooltip.
- [ ] Expanding the row shows the full value, and it can be selected and copied.

Check in a real browser at a desktop width and at a narrow window.

## 5. Web: the Type column never shows a slug

- [ ] With the network throttled to a slow 3G profile, the secrets table shows each secret's
  type name (or a placeholder while it loads), never its slug.
- [ ] Watching the table across several 10 second refreshes, no row flips to a slug and back.

## 6. Web: a plain username copy button

- [ ] On the secret page, every secret type with a username has a button that copies the
  username.
- [ ] Each row of the secrets table has the same button, for every type.
- [ ] The copied text is the plain username and nothing else.
