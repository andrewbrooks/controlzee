# Validation against Stratus Red Team

controlzee's rules were written from the CloudTrail documentation and tested on generated logs. This page records a first
check against real CloudTrail: attack techniques from [Stratus Red Team](https://github.com/DataDog/stratus-red-team)
(Datadog, Apache-2.0) were run in a sandbox AWS account, and controlzee was pointed at the resulting event history.

It is a proof-of-concept check, not a benchmark: one run per technique, one account, one operator.

## Method

For each technique, the harness ran Stratus `warmup`, `detonate` and `cleanup` with the credentials of a dedicated IAM
user, then waited for the events to appear in CloudTrail event history (it lags by a few minutes), and ran
`controlzee scope --lookup-events` seeded with that user's access key, then `timeline`, `plan` and `report`. It compared the
result with what the technique is documented to do:

- are the detonation's API calls in scope?
- does the timeline carry the tactic Stratus tags the technique with, or one that fits?
- does the plan contain the operations a responder would expect, and does the exposure list what was read?

## Results

Stratus v2.37.2; the sandbox is in the organization's `us-east-2` (EC2 calls elsewhere are denied by an SCP), with
event history read from `us-east-1` and `us-east-2`.

| technique | ran | detonation in scope | tactic | plan | notes |
|---|---|---|---|---|---|
| `persistence.iam-create-admin-user` | yes | yes | persistence, privilege-escalation | deactivate key, undo policy, delete user | exposure says full admin access was granted |
| `persistence.iam-backdoor-user` | yes | yes | persistence | deactivate keys, delete user | |
| `persistence.iam-create-backdoor-role` | yes | yes | persistence, privilege-escalation | revoke sessions, detach policy, delete role | |
| `persistence.iam-backdoor-role` | yes | yes | persistence, privilege-escalation | as above, plus manual trust-policy steps | duplicate steps (see 4) |
| `persistence.lambda-overwrite-code` | yes | yes (`UpdateFunctionCode20150331v2`) | persistence | revoke role sessions, delete role | first real-event check of the Lambda rule |
| `persistence.sts-federation-token` | yes | yes | persistence | deactivate keys, undo policy, delete user | the federation token's key was followed (`sts:GetFederationToken` rule) |
| `credential-access.secretsmanager-retrieve-secrets` | yes | yes | credential-access | one rotate step per secret | all 20 secrets listed as read; see 3 |
| `credential-access.ssm-retrieve-securestring-parameters` | yes | yes | credential-access | one "change a parameter" step per parameter (26) | see 3 |
| `persistence.iam-create-user-login-profile` | blocked | the denied call is in scope | n/a | n/a | an SCP denies `iam:CreateLoginProfile` in this account |

Every technique that could run was found, tagged with a fitting tactic, and given the plan operations expected of it.
The expectations were written from the Stratus documentation, partly after looking at the first two runs.

## What it showed, and what changed

The first run found five things. The first four are fixed, with regression tests that run on the captured logs
(`tests/captured/`, identifiers replaced by `controlzee.sanitize`); the fifth is open.

| # | finding | before | after |
|---|---|---|---|
| 1 | many calls had no tactic: `iam:Delete*`, `Detach*`, `UpdateAccessKey`, Secrets Manager and SSM writes and deletes, `lambda:DeleteFunction` were all `other` | 2 to 84 `other` entries per run | removing an identity, credential or permission, and changing or deleting a secret, parameter or function, are `impact` (ATT&CK "account access removal" and data manipulation or destruction); 0 for five of seven runs. Still `other`: `s3:CreateBucket`, `PutBucketTagging`, `secretsmanager:CreateSecret` |
| 2 | a call made by an AWS service was called lateral movement: Lambda assuming the attacker's role | `lateral-movement` | `execution` |
| 3 | a mass read became a wall of steps | 20 secrets: 20 steps; 42 parameters: 42 steps | one step each, naming the first three and carrying every command ("Rotate the 20 secrets the attacker read") |
| 4 | repeated changes to one target gave repeated steps | two identical "Undo a permission change" for one trust policy | one step citing both calls |
| 5 | some attacker-created things have no plan step: a bucket has none, and a created Lambda function has a step but no operation, so `respond` cannot carry it out | | open: needs new `respond` operations |

The tactic for removals is a judgement call: an attacker cleaning up its own traces looks the same as one locking
defenders out, so both are `impact`. The tactics are per call and deliberately simple (see `classify.py`).

How it was measured, and its limits:

- The attacker's key also ran Stratus's own set-up and clean-up, so a lot of in-scope events are that noise. The
  precision of the scope was not measured.
- A scope built too early misses late events: the harness stopped waiting once the technique's own call appeared, and
  the first SSM scope saw 26 parameter reads where the full history has 42. Counts in the table are from the captured,
  complete logs.
- Event history holds management events only, so nothing here tests data-event coverage. The coverage note about data
  events appeared on every run, as it should.
- Cleanup of IAM users failed in this account (an SCP denies `iam:DeleteLoginProfile`, which Terraform's destroy
  needs); leftovers were removed by hand.

## Not covered

EC2 techniques (instance credentials, user data), anything needing a CloudTrail trail or an S3 bucket policy, and
techniques that are only visible as data events. The `respond` operations were not exercised by these runs.
