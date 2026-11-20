# Changelog

Versions are `0.x`: output formats (schemas) may change between releases.

## Unreleased

- The dry run's check for activity after the scope reads the window in slices, earliest first, and says how far it read
  (`activity_check.slices_read`, `slices_total`, `last_time_read`; the warning reads "through T of ..."). Under a cap this
  keeps the activity nearest the scope's end, which is the question the check asks, where it used to keep the newest.
  Regions where the attacker was seen are read first. It also fixes a bug found in review: a cap that cut partway through
  the service's last page of events still reported the check as complete (`LookupInput.fetch` now uses botocore's
  `resume_token`; confirmed on a real account, where 252 of 254+ events read was called complete).

- The dry run's check for activity after the scope no longer asks CloudTrail for a window that ends before it starts
  (found on a real account: a scope whose `--window` end was still in the future made event history answer
  `InvalidTimeRangeException`). It now skips the check, saying that the scope's period ends at or after now.

- `respond dry-run` warns when the attacker acted after the scope was built. It reads CloudTrail event history from the
  scope's `period_end` to now in every log region and the home region, and looks for calls by the scope's tainted
  identities (keys, principal ids, roles, instances, functions) and its strong seed indicators. Calls found are listed in
  `new_activity` (first 100; `activity_check` says what was read, what failed and whether it was complete) and printed in
  bold. It only warns: it never fails the dry run or blocks a step, and says when it could not run or stopped at the cap.
  New option `--activity-check-max-events` (default 50,000; 0 skips) and permission `cloudtrail:LookupEvents`.
  `dryrun.json` gains `new_activity` and `activity_check`; `LookupInput` can be capped.

- `respond execute` writes a step journal, `response.<dry run hash>.journal.jsonl`, next to `--out`: a header, then for
  each step a `starting` line (written and `fsync`ed before the change is made) and a result line. A killed run leaves a
  `starting` line with no result, so the step that may be partly made is known. The journal also stops a dry run being
  executed twice from one folder (refused before any AWS call, and `--force` does not override it); it is not shared
  between machines. `response.json` gains `journal_sha256`. New schema `schemas/journal.schema.json`.

- `respond` stops if a target is no longer the resource the dry run checked: each dry-run step records the target's
  identity (user, role and group ids and creation dates, a Lambda function's ARN, code hash and last change, a bucket's
  creation date), and execute compares it again before the change. A user deleted and made again under the same name
  gives the new result `drifted`, nothing is changed and later steps are not run. Deleting a bucket now also needs
  `s3:ListAllMyBuckets`. Schema version 0.3: `DryRunStep.identity`, `ExecutedStep.result` may be `drifted`; a 0.2 dry run
  or scope must be made again.

- `controlzee report --format html` writes `report.html`: the same report as one self-contained page (no network, no library).
  It adds a diagram of how the attacker moved and a swimlane timeline (plain SVG; zoom with the buttons, Ctrl+wheel or a double click, drag to pan or use the scroll bar, click a dot to jump to its row in the call table), click to copy event ids and commands, a
  filter on the call table, a checklist that remembers what was done, expand all, and a light or dark theme. The page
  carries a Content Security Policy that allows only its own stylesheet and script, by hash, and a test checks every tag
  and attribute against an allowlist, including on a page built from hostile log content.

- Each evidence table has a folded "Full event IDs" block (one id per line, so GitHub's copy button or a triple click gets
  exactly one) next to the shortened codes.
- A plan step's evidence is a table (when, who, call, target, result, short event id), with repeated calls as one row
  ("x3"), not a row of event ids.
- `report.md` folds its long parts (the timeline, big tables, each plan step's commands and evidence, the appendix) in
  collapsible `<details>` blocks that GitHub and VS Code draw, and has a "Jump to" line. A new "Identities" section has one
  collapsible block per identity: who it is, how it came about (the call that created it, with the request parameters that
  were logged, so "what was `exfil-fn`" is answered: runtime, handler, role) and what it did. Secrets are never shown and
  environment variables show their names only.
- `report.md` has an "At a glance" block (how big, what stands out, what to do first), a diagram of how the attacker moved
  (Mermaid, drawn by GitHub; one arrow per credential an identity created or obtained for another), and the plan as a task
  list, so a ticket that holds the report shows tick boxes.

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
