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

Stratus v2.37.2; round one ran eight techniques and round two three more. The sandbox is in the organization's `us-east-2` (EC2 calls elsewhere are denied by an SCP), with
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
| `credential-access.ec2-steal-instance-credentials` | yes | yes | execution, credential-access | cut the instance off its role, stop, snapshot, terminate; revoke the role's sessions | the instance-profile rule fired (`instance_id` identity, 4 events acting as it); the stolen credentials' `DescribeInstances` call is followed; round 2 |
| `discovery.ec2-enumerate-from-instance` | yes | yes | execution, discovery | as above | the instance's own role calls (`GetCallerIdentity`, `ListBuckets`, `ListUsers`, `GetAccountAuthorizationDetails`...) are followed; round 2 |
| `execution.ec2-user-data` | yes | yes | execution (new user data), impact (stop) | as above | round 2; see 6 |
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
| 5 | some attacker-created things have no plan step: a bucket has none, and a created Lambda function has a step but no operation, so `respond` cannot carry it out | no step for a bucket; a manual step for a function | fixed: `delete_bucket` (only if the bucket is empty) and `delete_lambda_function`, both disruptive. Run on a real function and bucket, see below |
| 6 | changing an instance's user data (`ModifyInstanceAttribute` with `userData`) and stopping an instance had no tactic | `other` | `execution` and `impact` |
| 7 | the report did not say when an instance's role credentials were used from another address, the clearest sign of theft in the steal-credentials run | not flagged | flagged in the exposure (a table of each address, its calls and first use), a note, and an investigate step (check and require IMDSv2). Only a session whose name is an instance id, seen from two or more real addresses |

**Round two (EC2, and the new operations on a real account).** Three EC2 techniques showed the instance-profile rule
working on a real instance, which the first round could not (in these runs the attacker also created the role, so the role
rule overlaps; the `instance_id` identity still had its own events). The new operations were tried on the Lambda
technique's real function and bucket:

- The first dry run **failed on a bucket that was not empty** (it held `lambda.zip`), as designed: "controlzee only
  deletes empty buckets". A person emptied it and ran the dry run again.
- It also **failed on a permission it had**, and that was a bug in controlzee. The organization's policy allows only one
  region, and the IAM policy simulator, which evaluates organization policies, denies every regional action unless it is
  told the region (`aws:RequestedRegion`). Fixed: the simulator is now given each step's region (the step's own, else the
  one in the ARN, else the home region for global services). Before, the dry run could not pass for any regional step in
  an account with a region-restricting policy, a very common setup.
- With that fixed, the dry run passed, `execute` deleted the function and the bucket, and a second dry run showed both
  "already done".

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

**Round three (the instance operations on a real account).** A throwaway IAM user launched one `t3.micro` with an instance
profile, and controlzee scoped it from event history seeded by that user's key. The plan had five runnable steps. The dry
run passed all five (the real state of each resource, and the policy simulator allowing each action on the right resource)
and `execute` carried them out: the key went inactive, the profile association was removed, the instance was stopped, one
snapshot was started and the instance was terminated. A second dry run reported every step as already done. Everything the
test created was deleted afterwards and the account was checked for leftovers. The responder was an administrator, so the
simulator was not exercised against a narrowly scoped role on EC2.

## Not covered

Anything needing a CloudTrail trail or an S3 bucket policy, and techniques that are only visible as data events. Of the
`respond` operations, deactivating a key, revoking and lifting a role's sessions, deleting a function, deleting a bucket
and the instance operations (remove the instance profile, stop, snapshot, terminate) have run on a real account; logging
and detection restoration has not, though its steps appear in the plans above.

**Why logging and detection restoration is untested.** `start_logging`, `start_config_recorder`, `enable_guardduty` and
`enable_security_hub` only turn things on, and they share the probe, permission check, apply and "already done" machinery
that the tested operations use, but they have not run against a real account. None of the attack techniques run here
tamper with logging or detection, so no scope produced one of these steps. Testing `start_logging` needs a throwaway trail
and bucket, because stopping the sandbox's own trail would blind the logs every other test reads. Testing the other three
means enabling a Config recorder, GuardDuty or Security Hub, which cost money and, in an organization, can clash with
settings the organization manages. Treat all four as untested until they have been run on a real account.
