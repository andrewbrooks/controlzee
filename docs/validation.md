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

## What it showed

Things worth fixing, in rough order of value:

1. **Many calls have no tactic.** `iam:DeleteRole`, `DetachRolePolicy`, `DeleteAccessKey`, `DeleteUser`,
   `DeleteLoginProfile`, `UpdateAccessKey`, `DeleteUserPolicy`, `secretsmanager:CreateSecret` / `PutSecretValue` /
   `DeleteSecret`, `ssm:PutParameter` / `DeleteParameter`, and `s3:CreateBucket` / `PutBucketTagging` are classified
   `other`.
2. **A call made by an AWS service is called lateral movement.** When Lambda assumes the attacker's role
   (`sts:AssumeRole` with an `AWSService` caller), the timeline tags it `lateral-movement`.
3. **A mass read becomes a wall of steps.** Reading 20 secrets gives 20 identical "Rotate a secret the attacker read"
   steps (the SSM run gave 26 "change a parameter" steps). One step listing every target would be easier to act on.
4. **Repeated changes to one target give repeated steps.** Two `UpdateAssumeRolePolicy` events on one role gave two
   identical manual "Undo a permission change" steps.
5. **Some attacker-created things have no plan step.** A bucket created by the attacker has none, and a created Lambda
   function has a step but no operation, so `respond` cannot carry it out.

Worth knowing about how it was measured:

- The attacker's key also ran Stratus's own set-up and clean-up, so a lot of in-scope events are that noise. The
  precision of the scope was not measured.
- Event history holds management events only, so nothing here tests data-event coverage. The coverage note about data
  events appeared on every run, as it should.
- Cleanup of IAM users failed in this account (an SCP denies `iam:DeleteLoginProfile`, which Terraform's destroy
  needs); leftovers were removed by hand.

## Not covered

EC2 techniques (instance credentials, user data), anything needing a CloudTrail trail or an S3 bucket policy, and
techniques that are only visible as data events. The `respond` operations were not exercised by these runs.
