# Field testing

The test suite runs on generated CloudTrail and an in-memory AWS account. Both follow the AWS documentation, not live
captures, so the first runs against a real account are where shape mismatches will show up. This guide is for those
runs. Use a dedicated sandbox account: nothing here should touch production.

## 1. Set up the sandbox

- A sandbox AWS account with a CloudTrail trail (multi-region, management events, read and write) delivering to S3.
  If the account cannot have one (an organization's SCP denying `s3:CreateBucket`, for example), skip it: CloudTrail
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

Run in a dedicated sandbox account that is a member of an organization. A service control policy there denied
`cloudtrail:DescribeTrails` but not `LookupEvents`, so there was no trail and everything used event history. Two
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
- Found and fixed: a scope whose `--window` ended in the future made the check ask for a window that ends before it
  starts, and event history answered `InvalidTimeRangeException`. The check now says there is nothing after the scope to
  look at yet.
- Not checked: roles, instance profiles, a Lambda function, and a bucket's creation date through `list_buckets` (the
  account had no bucket or function).

## Real samples as fixtures

Committed fixtures are generated (see `tests/builders/`). Real records are welcome as an addition, not a replacement:
strip account ids, ARNs, IPs, user agents and names (replace them consistently), keep the field structure exactly, and
add them with a test that checks what the code extracts from them.
