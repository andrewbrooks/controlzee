# Changelog

Versions are `0.x`: output formats (schemas) may change between releases.

## Unreleased

- The exposure, report and plan flag an instance's role credentials used from more than one address: an instance calls
  from its own address, so another address holds a copy. The plan has an investigate step (and checks IMDSv2).

- `respond` can delete a Lambda function the attacker created (`delete_lambda_function`) and a bucket the attacker created
  (`delete_bucket`), both disruptive. A bucket that is not empty fails the dry run, and a bucket filled after the dry run
  stops `execute`: controlzee never empties a bucket.
- The plan has a step for a bucket the attacker created.
- Fix: the permission check now gives the IAM policy simulator the region of each step (`aws:RequestedRegion`). Before, an
  organization policy that allows only some regions made every regional step fail the dry run. Found on a real account.
- `ec2:ModifyInstanceAttribute` with `userData` is `execution`; `ec2:StopInstances` is `impact`.
- `tests/captured/`: three EC2 captures (instance credentials, enumeration from an instance, user data).

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
