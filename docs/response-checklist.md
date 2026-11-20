# Checklist: simulating an attack and reversing it

For whoever runs a simulation in a sandbox account, and, with the cautions marked, for a real response. It follows the order
of the commands. Everything here was run on a real account (see [field-testing.md](field-testing.md)) except where a line
says it was not. controlzee is a proof of concept: a dry run that is reviewed by a person is the safety, not the tool.

Tick the boxes as you go. If a box cannot be ticked, stop and read why before going on.

## 0. Before anything

- [ ] **The account is the right one.** Run `aws sts get-caller-identity --profile <profile>` and compare the account id with
      the one you mean. A sandbox in an organization still obeys the organization's service control policies (SCPs). Ours
      was a **region rule**: in two regions only global-style services (IAM, STS, Config, KMS and a few more) were
      allowed, and one region was open. A service that looks blocked may be blocked only in the region you tried, so
      probe the same read-only call in every region the SCP allows before deciding that something is denied, and
      build the defenses, buckets and functions of a simulation in the open region. An SCP denial shows in the error as
      "explicit deny in a service control policy". Do not edit an SCP to get around it: it is usually attached to the whole
      organization.
- [ ] **Two separate principals, both narrow.** An *intruder* (stands in for the leaked credential) and a *responder* (a role
      assumed for the response). Limit what each can touch to a naming prefix such as `ft-*`, and allow the intruder to
      attach only ReadOnlyAccess. An inline policy can grant anything, so do not let the intruder write one.
- [ ] **The responder can read what the tool reads.** `iam:SimulatePrincipalPolicy`, `iam:GetRole`, `iam:Get*`, `iam:List*`,
      `cloudtrail:LookupEvents` (the activity check and event history), `cloudtrail:GetTrailStatus`, `ec2:Describe*`, and
      `s3:ListAllMyBuckets`, `s3:ListBucket`, `lambda:GetFunction` for buckets and functions. Plus the change calls for the
      steps you will run, on your own prefix only. The intruder cannot run `scope` (it has no `LookupEvents`): run it as
      the responder.
- [ ] **Credentials stay out of the chat, the repo and the terminal output.** Use `--aws-profile`, never keys on a command
      line. Set `AWS_PAGER=""` so the CLI does not page output.
- [ ] **Nothing real goes in a public repo.** No account id, key id, address, organization id or ARN of a real account in a
      commit, test, doc or PR. Fake key ids use the `AKIAIOSFODNN7EXAMPLE` form (CI's secret scan flags others). Real
      captures go through `controlzee.sanitize` first.
- [ ] **A scratch folder outside the repo** for `scope.json`, `dryrun.json`, `response*.json` and the journal files.

## 1. Make the incident (simulation only)

- [ ] Run the attacker's calls as the intruder: create something, attach something, make a key, use it. Keep every name
      inside the prefix. Note the start time.
- [ ] **Wait for event history, and poll for it.** In our runs a call showed up 80 seconds to about two and a half minutes later. The tool's
      own warning allows about 15 minutes. Poll `aws cloudtrail lookup-events --start-time <start>` filtered by the access
      key until the count reaches what you made.
- [ ] After changing a key's status or adding a policy, **wait about 20 seconds before using it**. IAM takes a moment:
      `InvalidClientTokenId`, `InvalidAccessKeyId` or `AccessDenied` right after a change is usually that.

## 2. Scope (what did the attacker do?)

- [ ] `controlzee scope --lookup-events <region> --window <start> <end> --access-key <the leaked key> --aws-profile <responder>`
      (or `--logs` for a trail's files). Use every region the attacker may have touched.
- [ ] **The window's end is in the past.** If it is at or after now, the later activity check has nothing to look at and
      says so. Give `--window` an end a minute or two after the last call, once that time has passed.
- [ ] Read the summary: events in scope; how many credentials were followed; how many events were found *only* by following
      them (that is the tool working).
- [ ] Open `report.md` (`controlzee report scope.json`). Every call you made is in scope. The plan names the right users,
      keys, roles and instances. Look at the near misses and coverage gaps: they say what the logs cannot show.
- [ ] Nothing in the scope is a surprise. If it is, stop: that is a finding about the incident, or about the tool.

## 3. Dry run (nothing changes)

- [ ] `controlzee respond dry-run scope.json --aws-profile <responder> -o dryrun.json`. Add `--allow-disruptive` only
      when you mean to delete or stop things. Use `--steps A01,A02` to run part of the plan.
- [ ] **It passed** (exit 0, "Dry run passed"). A failed dry run exits 4 and cannot be executed. Fix what it names (a
      permission, an unreadable target, a clock more than 5 minutes off AWS's when a session revocation is in the plan)
      and run it again. Never edit `dryrun.json`.
- [ ] **Read every step**: what it will do, the target's state now, its identity (ids and creation dates) and the
      permission checks. "already done" means nothing to do; "CANNOT RUN" has a reason underneath.
- [ ] **Read what is not included**: manual steps (a trust policy the logs do not show, a secret to rotate) are yours;
      disruptive steps need `--allow-disruptive`; "runs only when named with `--steps`" are the lifts of a session
      revocation.
- [ ] **Read the warnings.** The one that matters most is *"tainted identities acted after this scope was built"*. It lists
      the calls. Go to section 4 first: contain, then scope again, before removing anything the attacker made. "Could
      not check" and "incomplete" mean the check did not see everything; look at CloudTrail yourself. An incomplete
      check says how far it read ("through T of ..."): activity after T was not looked at. Raise
      `--activity-check-max-events`, or look at CloudTrail from T onward.
- [ ] A step that would cut off the responder's own credentials fails the dry run. Run the response as a different role, or
      leave that step out.
- [ ] Note the dry run's sha256 (printed at the end). That hash is your approval.

## 4. Contain first

- [ ] If the attacker is still active, run containment on its own: `--steps` with only the deactivate-key and
      revoke-session steps. Then scope again with a later window and dry-run again.
- [ ] A **session revocation** denies every credential issued before now (from AWS's clock). It also ends legitimate
      sessions of an existing role until they sign in again. It stays until a person names its lift step with `--steps`.
- [ ] A **key deactivation** stops the key's owner too if the owner is legitimate. Check the plan's caution line.

## 5. Approve and execute

- [ ] `controlzee respond execute dryrun.json --scope scope.json --approve <sha256> --aws-profile <responder> -o response.json`.
      Same `--scope` as the dry run. The dry run must be less than 60 minutes old (`--max-age-minutes`).
- [ ] The journal is written first: `response.<first 16 of the dry run's hash>.journal.jsonl`, next to `--out`. A dry run is
      executed **once** from a folder: a second execute is refused (exit 2) before any call. `--force` does not override
      it. The guard is per folder, not shared between machines.
- [ ] Watch each step: `done`, `already done`, `failed` (stops the run), `drifted` (the target is not the resource the dry
      run checked, e.g. a user deleted and made again under the same name: nothing was changed, the run stops).
- [ ] **Exit 0 is done; exit 5 means a step failed or drifted and later steps did not run.** Read the step's detail.

## 6. If the run stopped, or was killed

- [ ] Read the journal. A `starting` line with **no** result line is a step that was in flight when the process died: its
      change may be partly made. Look at that target with the AWS CLI. (In our kill test the change had not been applied,
      and the journal could not have said so.)
- [ ] Do not execute the same dry run again. Run a **new dry run**: its probes report what is already done. Review it, then
      execute that one.
- [ ] If a step `drifted`, find out who changed the target before running anything else on it.

## 7. Verify

- [ ] A new dry run of the same plan reports every step already done (apart from steps you chose not to run). A lifted
      revocation is correctly "to do" again.
- [ ] Check the account yourself, not only through the tool: `aws iam list-access-keys`, `list-attached-user-policies`,
      `get-user`, and so on, for each thing the plan touched.
- [ ] `response.json` cites the journal's hash. Keep the dry run, the response and the journal together: they are the
      record of what was reviewed and what was done.

## 8. Eradicate and recover

- [ ] Eradicate steps (deleting users, roles, functions, buckets) are disruptive and need `--allow-disruptive`. A bucket is
      deleted only if it is empty: a full one fails the dry run, because what is in it may be evidence.
- [ ] **Keep evidence first.** There is a step that snapshots an instance's volumes, but the tool does not copy logs, a
      function's code or a bucket's contents. Check where the snapshot step falls against any stop or terminate step in
      the dry run, and export what you need before deleting.
- [ ] Groups are not deleted by any step. Remove leftovers by hand and list them: `aws iam list-groups`.
- [ ] Recover steps (turn logging, Config recording, GuardDuty or Security Hub back on) are **not tested on a real
      account**. Treat the printed AWS CLI commands as the way to do it and check the result.
- [ ] Lift session revocations when the incident is over, by naming their steps with `--steps`.

## 9. After a simulation

- [ ] Delete what the run created, through the tool where there is a step, by hand where there is not.
- [ ] Deactivate the intruder's key (or delete the intruder). A live "attacker" credential should not sit in a profile.
- [ ] List what is left: `aws iam list-users`, `list-roles`, `list-groups`, and the buckets, functions and instances you
      allowed. Write down anything you leave on purpose.

## What has not been run on a real account

If the response needs one of these, expect to finish by hand and read the dry run twice.

| not run | why it matters |
|---|---|
| `delete_user_policy`, `delete_role_policy`, `delete_group_policy` | the intruder would need to write inline policies, which can grant anything |
| `delete_access_key` | no plan contains this step, so a dry run cannot include it |
| bucket and Lambda function identity (creation date; ARN, code hash, last modified) | not yet run: they need a bucket and a function made in the open region (their deletion has run on another account) |
| roles used through Identity Center, and the coverage heuristics on real logs | no run produced them |

Failures show up as a stopped step, not a silent change: a dry run that cannot read a target or is not allowed fails, a
failed or drifted step stops the run, and the journal says what was in flight. That is how the design is meant to work and
what the live runs showed, not a guarantee.
