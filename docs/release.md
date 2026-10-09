# Releases and the GitHub environments

A release of this repository is the pinned `manifest/release.yaml` and the charts at one `v*` tag.
The owner creates the tag and the GitHub Release by hand; nothing in CI tags or publishes.

## The environments

Only a job that signs a release may name an environment, and no signing key is ever a repository or
organization secret.

| Environment | Used by | Protection | Secrets |
|---|---|---|---|
| `production` | the release signing job of a `v*` tag run, once it exists | required reviewer Bugs5382; deployments from `v*` tags only (a custom tag policy); no admin bypass | none yet |

- No workflow here signs a release yet: the `release.yaml` signature and the image
  countersignatures the appliance build reads (`release.yaml.sigstore.json` and one
  `<digest>.sigstore.json` per image) are still to be published. The workflow that signs them
  will run its signing job in `production` and list the secret names it reads in this table; the
  owner sets their values, and nothing in CI writes, reads back or copies them.
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
