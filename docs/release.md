# Releases and the GitHub environments

A release of this repository is the pinned `manifest/release.yaml` and the charts at one `v*` tag.
The owner creates the tag and the GitHub Release by hand; nothing in CI tags or publishes.

## The environments

Only a job that signs a release may name an environment, and no signing key is ever a repository or
organization secret.

| Environment | Used by | Protection | Secrets |
|---|---|---|---|
| `production` | the release signing job of a `v*` tag run, once it exists | required reviewer Bugs5382; deployments from `v*` tags only (a custom tag policy); no admin bypass | none yet |

- The service images are built by the appliance's release workflow, not here. Each service in
  `manifest/release.yaml` has a `build` block, which pins its source:

  ```yaml
  web-staff:
    image: ghcr.io/sneakers-pam/sneakers-web-staff
    source: https://github.com/Sneakers-PAM/sneakers-web
    version: 0.1.0
    digest: sha256:TBD-at-release
    build:
      repository: Sneakers-PAM/sneakers-web   # the source's owner/name
      commit: <full 40-character commit>
      dockerfile: Dockerfile                  # in the repository
      context: .
      target: <Dockerfile target>             # optional
      args:                                   # optional build args
        APP: staff
  ```

  `spec.jobs` holds the images a product runs as one-off Jobs rather than as a chart's workload:
  today `migrate`, the sneakers-migrate image the appliance's Import page runs. Its build block
  points at this repository's `migrate/Dockerfile` at a commit of this repository's own `main`
  (bump it when `migrate/` changes); it isn't in `test/kind/services.txt`.

  The appliance's release builds each image from that commit with the repository's own
  Dockerfile, pushes it to GHCR by digest, and writes the digest in place of
  `sha256:TBD-at-release` in the release.yaml it ships and countersigns. The digests stay
  placeholders in git. To ship newer service code, bump the commits here (and the same refs in
  `test/kind/services.txt`; `scripts/check-manifest.py` refuses a mismatch) and pin the new
  sneakers-release commit in the appliance.
- No workflow here signs a release. The appliance takes `manifest/release.yaml` from this
  repository at a full commit it pins (its `build/release/pins.env`), not from a release asset,
  and its own release job countersigns that file and every image it pins with the appliance's
  release key, then publishes the signatures on the appliance's Release. A signing workflow added
  here later runs its signing job in `production` and lists the secret names it reads in this
  table; the owner sets their values, and nothing in CI writes, reads back or copies them.
- Self-review stays allowed: the owner pushes the tag and is the only reviewer, so blocking
  self-review would leave a release no one can approve. Admins can't bypass the review.
- There's no `lab` environment: no lab build here runs in Actions with keys of its own. The
  install test builds every image in the job and pushes nothing.

The settings applied:

```bash
gh api -X PUT repos/Sneakers-PAM/sneakers-release/environments/production --input - <<'JSON'
{"wait_timer": 0, "prevent_self_review": false, "reviewers": [{"type": "User", "id": 12115015}],
 "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true},
 "can_admins_bypass": false}
JSON
gh api -X POST repos/Sneakers-PAM/sneakers-release/environments/production/deployment-branch-policies -f name='v*' -f type=tag
```

`12115015` is the user id of Bugs5382.
