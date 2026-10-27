# Security policy

controlzee is an alpha proof of concept. `controlzee respond` can change IAM and other AWS resources, and only part of
it has been run against a real account (see "What has been tested" in the README). Use a sandbox account first, review
every dry run, and do not rely on it as the only control in an incident.

## Reporting a vulnerability

Please report security problems privately, not in a public issue: use GitHub's
[private vulnerability reporting](https://github.com/andrewbrooks/controlzee/security/advisories/new) for this
repository. Include what you did, what you expected and what happened. This is a one-person project, so expect a reply
within about a week, not hours.

Of particular interest:

- a way for log content (CloudTrail records are attacker-controlled) to reach a command, an AWS call, the terminal or the
  Markdown report without being validated or escaped;
- a way to make `respond execute` do something its approved dry run did not list;
- a path that writes outside the requested output file, or overwrites without `--force`.

## Supported versions

Only the latest commit on `main`.
