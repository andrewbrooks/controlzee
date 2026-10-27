# Changelog

Versions are `0.x`: output formats (schemas) may change between releases.

## Unreleased

- `controlzee scope`, `timeline`, `plan` and `report`: IOC seeding, taint propagation, coverage, timeline, exposure,
  response plan and report; local, S3 and CloudTrail event-history sources.
- `controlzee respond dry-run` / `execute`: permission-checked, human-approved remediation. `execute` takes `--scope`,
  rebuilds the plan and refuses a dry run whose steps are not what that plan gives.
- Session revocation cutoffs come from AWS's clock; dry runs warn about clock skew.
- `scope` exits 3 when none of its input files could be read.
