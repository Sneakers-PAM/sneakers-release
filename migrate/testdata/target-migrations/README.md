# Target migrations after the baselines

Test fixture: the service migrations that follow each Sneakers-PAM baseline
(identity 0002, vault 0002 and 0003), copied from the service repositories,
so the import is tested against the newest target layout as well as the
baselines. Add the next one here when a service adds a migration, together
with its entry in `schema.TargetVersions`.
