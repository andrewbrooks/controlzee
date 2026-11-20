# Field testing

The test suite runs on generated CloudTrail and an in-memory AWS account. Both follow the AWS documentation, not live
captures, so the first runs against a real account are where shape mismatches will show up. This guide is for those
runs. Use a dedicated sandbox account: nothing here should touch production.

## 1. Set up the sandbox

- A sandbox AWS account with a CloudTrail trail (multi-region, management events, read and write) delivering to S3.
  If the account cannot have one (an organization's region rule denying `s3:CreateBucket` in your region, for example), skip it: CloudTrail
  event history keeps 90 days of management events in every account, and `--lookup-events` reads it. Use the
  event-history command in step 3 instead of the S3 one.
- Two principals:
  - **`test-intruder`**: an IAM user with an access key, standing in for the leaked credential. Give it a deliberately
    narrow policy that allows only the calls in step 2.
  - **`IncidentResponder`**: an IAM role you assume for the response. It needs `sts:GetCallerIdentity`,
    `iam:SimulatePrincipalPolicy`, `iam:GetRole`, the read calls (`iam:Get*`, `iam:List*`, `cloudtrail:GetTrailStatus`,
    `cloudtrail:LookupEvents` for the activity check, `ec2:Describe*`, and `s3:ListAllMyBuckets`, `s3:ListBucket` and
    `lambda:GetFunction` if you will delete a bucket or function) and the change calls for the steps you will run.

## 2. Make some activity

Using the `test-intruder` key from a known IP, run a short, harmless sequence that exercises the taint rules:

```
aws sts get-caller-identity
aws iam create-user --user-name ft-created-user
aws iam attach-user-policy --user-name ft-created-user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam create-access-key --user-name ft-created-user      # note the new key id
# with the new key:
aws s3 ls
```

Optionally also: `sts assume-role` into a test role, then a read call with that session; launch a `t3.micro` (free-tier eligible; terminate it afterwards) with an
instance profile and let it make one read call; create a Lambda function with a role and invoke it once.

Wait 15 minutes for CloudTrail to deliver the files.

## 3. Run the analysis

```
controlzee scope --logs s3://<trail-bucket>/AWSLogs/<account>/CloudTrail/ --access-key <test-intruder key> \
  --aws-profile sandbox -o scope.json
controlzee report scope.json -o report.md
controlzee scope --lookup-events us-east-1 --window <start> <end> --access-key <test-intruder key> \
  --aws-profile sandbox -o scope-history.json --force
```

Check in the report:

- every call from step 2 is in scope, and the new key's `s3 ls` arrives as **followed** (via the new key)
- the optional assumed-role, instance and Lambda calls are followed too
- the plan's steps name the right user, key, role and instance
- the event-history run finds the same management events as the trail run

## 4. Respond

```
controlzee respond dry-run scope.json --aws-profile responder
```

- Every step should show `ok`, the real state ("key ... is Active") and allowed permissions.
- Remove one permission from `IncidentResponder` and run it again: the dry run must fail, naming that permission.
- Run it as `test-intruder` (or any role the plan revokes): the dry run must refuse the step that would revoke itself.

Then execute it and check the account:

```
controlzee respond execute dryrun.json --scope scope.json --approve <sha256 from the dry run> --aws-profile responder
aws iam list-access-keys --user-name ft-created-user     # Inactive
```

Run the dry run again: every step should now be "already done".

To check the activity warning, make one more call with the `test-intruder` key after the scope was built, wait for it to
show in event history (it took one to two minutes in the second real run), and run the dry run again: it must warn and
list the call. Give `scope` a `--window` that has ended, since a window ending at or after now leaves nothing to check.

## 5. Clean up

Delete `ft-created-user` (or run the eradicate steps with `--allow-disruptive`), the test role's deny policy (the lift
steps, named with `--steps`), the instance, the function and `test-intruder`'s key.

## What to compare against real events

Each of these is read from a documented field. If a real event differs, note it and add a sanitized copy of the record
as a regression fixture.

| where | field the code reads |
|---|---|
| `taint/rules.py` CreateAccessKey | `responseElements.accessKey.accessKeyId` |
| CreateUser / CreateRole | `responseElements.user.userId`, `responseElements.role.roleId` |
| AssumeRole, GetSessionToken, GetFederationToken | `responseElements.credentials.accessKeyId`, `responseElements.assumedRoleUser.assumedRoleId` |
| RunInstances | `requestParameters.iamInstanceProfile`, `responseElements.instancesSet.items[].instanceId` |
| Lambda CreateFunction / UpdateFunctionCode / UpdateFunctionConfiguration | event names with API-version suffixes (`CreateFunction20150331`); `requestParameters.functionName`, which may be an ARN with a qualifier, else `responseElements.functionName` |
| Identity Center sessions | role `AWSReservedSSO_<permission set>_<id>`, session name = the user name (so `--principal-id <user name>` seeds them); there is no taint rule because the response fields of its admin calls have not been checked against real events |
| instance role sessions | session name = instance id (`principalId` "AROA...:i-...") |
| Lambda role sessions | session name = function name |
| `coverage.py` | `eventCategory` "Data" for data events; `readOnly` |
| `respond/ops.py` | `iam:GetRolePolicy` returning the document decoded (the code also accepts URL-encoded text) |

## Results of the first real run

Run in a member account of the author's own organization, on CloudTrail event history (an SCP denied `s3:CreateBucket`,
so there was no trail). A `test-intruder` user created `ft-created-user`, attached ReadOnlyAccess and made a key; the new
key listed buckets.

- Passed: event-history ingest of real records; the two calls made with the created key were found only by taint; the
  plan named the right users and keys; the dry run read real state and passed the IAM policy simulator checks; execute
  deactivated both keys; a second dry run reported them "already done".
- Found and fixed: calls in the same second were listed out of order (CloudTrail times have one-second precision), and an
  SCP that denied `iam:GetLoginProfile` made `delete_user` fail its dry run with no way forward.
- Still unchecked on real events: assumed roles, instance profiles, Lambda, Identity Center and the coverage heuristics.

## Results of the second real run (identity, journal, activity check)

Run in a dedicated sandbox account that is a member of an organization. A service control policy there was a region
rule: in `us-east-1` it allowed only global-style services (so `cloudtrail:DescribeTrails` was denied and
`LookupEvents` was allowed), and `us-east-2` was open. This run worked in `us-east-1` with no trail, so everything used
event history. Two
principals as in step 1, with narrow policies (the intruder could only make `ft-*` users, keys and ReadOnlyAccess
attachments; the responder could only change `ft-*` users and the intruder).

- Passed: the dry run recorded the real ids and creation dates of each user (`user_id` and `user_create_date`). A user
  deleted and made again under the same name between a dry run and an execute gave `drifted`, exit 5, with the new user
  untouched. The journal held a header and a result line, and no `starting` line, since the change was never attempted.
- Passed: a normal execute wrote its journal with mode 0600, the journal's result lines equalled the response's steps and
  `journal_sha256` equalled the file's hash. Executing the same dry run again was refused (exit 2) before any call to AWS.
- Passed: a run killed with SIGKILL at the moment its journal ended in a `starting` line left no `response.json`, and the
  journal said which step was in flight. That change had not been applied, which the journal cannot tell you (hence
  "check the target"); a new dry run reported all three steps still to do, and its execute finished them. The kill was
  timed by a small script that polled the journal and sent the signal when its last line was `starting`.
- Passed: `delete_user` on a user with a key, through the tool.
- Passed: the activity check. With no new calls it read the events of its window and said none were found. After the
  intruder made another call it listed exactly that call (and, later, the calls that recreated a user), printed the
  warning and still passed the dry run. With `cloudtrail:LookupEvents` removed from the role by a session policy it
  warned that it could not run and the dry run still passed. Event history showed a call after 80 seconds to two
  minutes, well inside the "about 15 minutes" the warning allows for.
- Passed, in a later run: the activity check read in slices and said how far it read. A real window with 254 events and a
  cap of 252, which cuts partway through the service's last page of four events, was reported complete by the version
  that took the end of the last page as the truncation signal and is now reported incomplete (the same dry run, run from
  the earlier code and the new). With a first hour of more events than the cap, nothing beyond the scope is claimed.
- Found and fixed: a scope whose `--window` ended in the future made the check ask for a window that ends before it
  starts, and event history answered `InvalidTimeRangeException`. The check now says there is nothing after the scope to
  look at yet.
- Not checked in that run: roles, instance profiles, a Lambda function, and a bucket's creation date through
  `list_buckets`. The region used (`us-east-1`) denied creating a bucket and a function; the open region was not used
  for them in this run.

### The same account, plain IAM operations

A second pass made the attacker create a user with a console password and a managed policy, a group with the user in it
and a managed policy, a role with a managed policy, and use a session of that role and temporary credentials of its own
user (all named `ft-cov-*`, with the intruder's extra permissions limited to those names and to ReadOnlyAccess).

- Passed: the plan had a step for each, and the dry run read the real state and the policy simulator allowed each one.
  Executing all ten steps worked on real IAM: a user's and a role's session revocation (`controlzee-revoke-older-sessions`,
  a `Deny` with an `aws:TokenIssueTime` cutoff), removing the console password, detaching a policy from a user, a group
  and a role, removing the user from the group, deleting the user (a compound delete) and deleting the role. Naming the
  lift step removed the user's revocation. A new dry run then reported every step already done except the lifted
  revocation.
- Passed: the role and group identity facts (`role_id` with its creation date, `group_id` with its creation date). A role
  and a group deleted and made again under the same names between a dry run and its execute both gave `drifted`, exit 5,
  and the new objects kept their policies.
- Not run in that pass: `delete_user_policy`, `delete_role_policy` and `delete_group_policy`, because the intruder would
  need permission to write inline policies, which can grant anything (run later, with a permissions boundary: below).
- A gotcha: a key that was just re-enabled, or a policy that was just added, can take a few seconds to take effect
  (`InvalidClientTokenId`, `AccessDenied`). Wait and try again before suspecting the tool.

### The same account, the logging and detection restores

An organization region rule had made the services look blocked: the earlier attempts were all in `us-east-1`. In the open
region, `us-east-2`, the admin made a trail with its log bucket, an AWS Config recorder limited to IAM roles (to keep it
nearly free) with a delivery channel and bucket, a GuardDuty detector, and Security Hub without the default standards,
all named `ft-*` (about forty lines of CLI; a teardown removes them and the buckets). The intruder stopped the trail and
the recorder, deleted the detector and disabled the hub (five calls in three seconds). Event history in `us-east-2` showed
them after about two minutes, and the scope took both regions.

- Passed: the plan had a restore step for each, and the dry run read the real state of each ("not recording", "not
  logging", "no GuardDuty detector", "not enabled") with every permission allowed. Executing worked: the recorder was
  started, the trail was logging, a detector was created (the old one's id and findings are gone, as the plan says) and
  Security Hub was enabled. The account, read directly, agreed, and a second dry run reported every step already done.
- Gotchas: an IAM user's inline policies share a 2,048 character budget, so a policy for the intruder went in as a
  customer-managed policy; `securityhub describe-hub` answers `InvalidAccessException` when the hub is simply not
  enabled (the tool treats that as "not enabled"); the services' own service-linked roles are created on first use;
  GuardDuty and Security Hub have free trials and Config charges for what it records, so tear it all down after.

### Deleting a key the attacker made on an existing user

`delete_access_key` was in the operation list but no plan emitted it. The plan now deletes, in the eradicate phase, a key
the attacker made on a user they did not make (after deactivating it in contain). On the sandbox the admin made a user,
the intruder made a key on it, and the scope's plan had the deactivate step and the new delete step; the simulator
allowed `iam:DeleteAccessKey` on the user, execute ran both, the user had no keys when read directly, and a second dry
run found everything already done. A key on an attacker-made user is left to the delete-user step, and a key the attacker
only used is not deleted (its owner needs a replacement first).

### The inline-policy deletes, with a permissions boundary

Testing `delete_user_policy`, `delete_role_policy` and `delete_group_policy` needs the intruder to write inline policies,
and an inline policy can contain `"Action": "*"`. The sandbox made that safe with three IAM policies:

- **A low boundary** that allows only harmless reads (`sts:GetCallerIdentity`, `iam:ListUsers`, `iam:ListRoles`,
  `s3:ListAllMyBuckets`). Every user and role the intruder creates carries it, so an admin inline policy on one of them is
  worth nothing.
- **An intruder boundary** on the intruder itself, built from its exact current permissions plus `iam:Put*Policy` on `ft-*`
  names, with resources and conditions kept. Whatever policy it writes, however broad, cannot exceed this.
- **A guard policy** the intruder is granted: `Put*Policy` on `ft-*` names, an explicit deny on creating a user or role
  that does not carry the low boundary, and an explicit deny on changing a boundary or the boundary policies.

(Groups cannot carry a boundary, but their members do: the intruder is capped by its own, the users it makes by the low one.)
Before applying anything, 31 cases were run through the IAM policy simulator (`iam simulate-custom-policy`, read-only) with
the real policies: what must still work, what must be denied (creating a user without the boundary, editing a boundary,
writing a policy on itself or the responder, attaching AdministratorAccess, assuming the responder), what happens if the
attacker had admin on its own identity (it still cannot assume the responder, launch anything or drop its boundary), and
what a capped `ft-` user with an admin inline policy can do (ask who it is). None came out wrong.

- Passed: the intruder made a user, a group and a role, each with an admin inline policy, and tried to use the admin. The
  user (admin inline policy and admin group policy, capped by the low boundary) tried `iam:CreateUser` and was refused; the
  scope's failed calls show it. The plan had the three steps, the simulator allowed them, execute deleted the three inline
  policies (and the user and the role), the account read directly agreed, and a second dry run found everything done.
- Gotchas: IAM requires policy statement IDs to be alphanumeric and unique, but the policy simulator accepts invalid ones,
  so a generated policy passed the simulator and was rejected by `create-policy`; check generated policies with
  `aws accessanalyzer validate-policy` before applying them. `delete-policy` fails while a policy has non-default
  versions: delete those first. With the guard in place the intruder must pass `--permissions-boundary <the low boundary>` to
  `create-user` and `create-role`, so the earlier commands in this guide need that flag.

## Real samples as fixtures

Committed fixtures are generated (see `tests/builders/`). Real records are welcome as an addition, not a replacement:
strip account ids, ARNs, IPs, user agents and names (replace them consistently), keep the field structure exactly, and
add them with a test that checks what the code extracts from them.
