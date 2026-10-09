# Moving onto the appliance

This guide moves an install of the original Sneakers system (the earlier Kubernetes deployment)
onto a Sneakers-PAM appliance with `sneakers-migrate` ([how the tool works](migrate.md)). It is a
one-off move: the source is read once more at the cutover and then retired.

What comes across, and what doesn't:

- **Secrets:** every secret with its **current value only**; older versions stay behind
  (`export --current-only`).
- **Structure:** folders, names and types are **re-mapped** from a mapping file the owner approves
  ([the mapping file](migrate.md#the-mapping-file)). Personal folders come across too; items the
  owner retires are dropped by the mapping.
- **Users:** every user, group, role, service account, API token and personal (MCP) token comes
  across, but **every sign-in is reset** (`export --reset-sign-in`): no password and no second
  factor travels. Each user sets a new password with "Forgot password" on the sign-in page and
  enrols a second factor at first sign-in. One account, the first admin, gets a one-time password
  from the import (`--owner-email`), so someone can get in before the product's email is set up.
- **The audit chain** comes across record for record and still verifies.

There is **no rollback**. If something is wrong after an import, fix the cause and import again
with `--wipe-target`; on the appliance, the Import page's **Re-import** does that.

## Before you start

- The appliance is installed, its key ceremony is done (setup code, the appliance admin, the
  recovery keys, network, protection; see the appliance's own docs), and the Sneakers product is
  installed from Updates. **Don't run the product's own first-run setup** (`/admin/setup`): the
  import brings the users, and the box goes into imported-users mode.
- The recovery escrow holds the vault and TOTP keys once the product is installed. Download it and
  store the recovery keys as the appliance docs say. **Keys on disk are a starting point, not a
  resting place:** move them into the new Sneakers once it's up, and keep an offline copy.
- Tell everyone with an account: the date, that the old system goes read-only at the freeze, and
  that they'll set a new password and second factor on the new one.
- Pick the person who will be the first admin, by their email in the old system.

## 1. Inventory

On the original system, with read-only database roles:

```bash
sneakers-migrate export --inventory --out inventory.json
```

It needs only the four `SOURCE_*_DSN` settings (and `SOURCE_KRATOS_ADMIN_URL` for the identity
count) and no key. It prints the counts per table, folder, type and role, the personal tokens by
id, and the schedules. Nothing in it is a value.

## 2. Lab dry run (sanitised)

On a lab appliance, in rehearsal mode:

1. On the lab box's Import page, make the import key; copy its recipient (`age1...`).
2. On the original system:

   ```bash
   sneakers-migrate export --sanitise --current-only --recipient age1... --out lab.age
   ```

   Every value, token hash and target address in it is a fake of the same length.
3. On the lab box: upload `lab.age`, run **Review**, upload a mapping file, then **Import** with
   **Rehearsal** on and **Verify**. Each step's report stays on the page.

A sanitised bundle is refused anywhere but rehearsal mode. When the dry run is done, move the lab
bundle and the lab import key out of use.

## 3. The review and the mapping file

On the target appliance's Import page, make its import key, then export a real bundle to it:

```bash
sneakers-migrate export --current-only --reset-sign-in --recipient age1... --out real.age
```

Upload `real.age` and run **Review**: it lists every secret by folder, name and type (personal
folders with their owner) and offers a mapping template, one entry per secret. Neither carries a
value. Decide the new structure from it, then write the mapping file:

- by editing the template, or
- from a proposal sheet (one row per secret: current and new folder, name and type, and `carry` or
  `drop`) with `mapping --tsv`, giving the type changes' field mappings with `--types`.

Upload the mapping file and run **Check mapping**: it applies the file to the bundle in memory and
lists what would move, be renamed, retyped, created or dropped, or names the rule that doesn't fit.
The file is keyed to the bundle it was made from (`bundle_id`), so keep the approved sheet or
template edits: at the cutover they are converted again against the final bundle.

## 4. Rehearsal on the target appliance

Run **Import** with **Rehearsal** on, then **Verify**, and check the product yourself: sign in as the
first admin with the one-time password, reveal a secret, check a second user sees only their
folders. Every report has a parity table: folders, secrets, types, users, targets and connections,
counted in the source, less what the mapping dropped, against what the box holds. Then
**Re-import** clears the box for the cutover.

## 5. Cutover

1. **Freeze** the original system: read-only for everyone, open check-outs forced back, rotation
   and heartbeats stopped.
2. **Final export** from the frozen system, to the target's import key:
   `export --current-only --reset-sign-in`. Compare its parity report with the inventory.
3. Upload it, run **Review** again: only items that changed since the mapping was approved need a
   new decision. Convert the approved sheet against this bundle and **Check mapping**.
4. **Import** (no rehearsal) with the mapping file and the first admin's email. The import prints the
   first admin's one-time password once; it is never stored. A parity mismatch fails the import:
   fix the cause and re-import.
5. **Verify** must pass. The page restarts the vault after the import.
6. **Switch**: point the product's name at the box. Personal tokens keep working (verify checked
   each by id). Turn on the MCP and the SSH broker once the SSH host keys the report lists are
   pinned; leave rotation off until the owner signs off.
7. The first admin sets up the product's email, so everyone else can use "Forgot password".

## If something is wrong

There is no rollback to the original system. Fix the cause (the mapping file, a setting, a new
build) and import again with **Re-import** (`--wipe-target`), which empties the box's product data
and Kratos before it imports. Outside rehearsal mode a re-import only replaces an earlier import:
a box holding data that didn't come from one is refused; factory-reset it instead.
