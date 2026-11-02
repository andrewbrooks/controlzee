# Changelog

Versions are `0.x`: output formats (schemas) may change between releases.

## Unreleased

- Tactics for removals and writes (`iam:Delete*`, `Detach*`, secret and parameter changes) are `impact`; a service's
  `AssumeRole` is `execution`, not `lateral-movement`.
- The plan has one step for a bulk read of secrets or parameters, and one undo step per change however many times it was made.
- `controlzee.sanitize` and `tests/captured/`: real CloudTrail from Stratus Red Team runs, identifiers replaced.

- `controlzee scope`, `timeline`, `plan` and `report`: IOC seeding, taint propagation, coverage, timeline, exposure,
  response plan and report; local, S3 and CloudTrail event-history sources.
- `controlzee respond dry-run` / `execute`: permission-checked, human-approved remediation. `execute` takes `--scope`,
  rebuilds the plan and refuses a dry run whose steps are not what that plan gives.
- Session revocation cutoffs come from AWS's clock; dry runs warn about clock skew.
- `scope` exits 3 when none of its input files could be read.
