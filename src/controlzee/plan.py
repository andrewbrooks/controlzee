"""Build `plan.json` from a scope: contain, investigate, eradicate, recover.

Each step names its target, why (with the events that justify it), its confidence, and either operations or manual
commands. An operation (see `respond.ops`) is something `controlzee respond` can carry out after a dry run and an
approval; its AWS CLI text is generated from it, for people who prefer to run it themselves. Manual steps need judgement
(a new secret value, a trust policy the logs do not show) and only ever have text.

Values taken from the logs are attacker-influenced, so a value becomes an operation argument or part of a command only
if it has the documented shape for its kind (IAM name, access key id, instance id, region...); anything else turns the
step manual, with the reason. Building a plan never calls AWS.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from controlzee import canonical
from controlzee.model.common import Confidence, tool_info
from controlzee.model.event import Event
from controlzee.model.plan import Operation, Phase, Plan, PlanAction
from controlzee.model.scope import Scope, ScopedEvent
from controlzee.respond.ops import OPS, Unsafe, q, validate
from controlzee.timeline import exposure

LISTED_EVIDENCE = 10
PHASES: tuple[Phase, ...] = ("contain", "investigate", "eradicate", "recover")

Op = tuple[str, dict[str, Any], str | None]  # (operation, arguments, region)


@dataclass
class _Draft:
    phase: Phase
    title: str
    target: str
    why: str
    evidence: list[ScopedEvent]
    account: str | None = None
    caution: str | None = None
    commands: list[str] = field(default_factory=list)
    operations: list[Operation] = field(default_factory=list)


def _confidence(evidence: Iterable[ScopedEvent]) -> Confidence:
    return Confidence.STRONG if any(s.confidence is Confidence.STRONG for s in evidence) else Confidence.WEAK


def _role_name(ev: Event) -> str | None:
    ui = ev.user_identity
    if ui.session_issuer and ui.session_issuer.user_name:
        return ui.session_issuer.user_name
    if ui.arn and ":assumed-role/" in ui.arn:
        return ui.arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    return None


def _user_name(ev: Event) -> str | None:
    ui = ev.user_identity
    if ui.user_name:
        return ui.user_name
    if ui.arn and ":user/" in ui.arn:
        return ui.arn.rsplit("/", 1)[1]
    return None


def _req(ev: Event, key: str) -> Any:
    return (ev.request_parameters or {}).get(key)


def _account(ev: Event) -> str:
    return ev.user_identity.account_id or ev.recipient_account_id


class _Builder:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self.by_id = {s.event.event_id: s for s in scope.events}
        self.drafts: list[_Draft] = []
        self.created_users: dict[str, ScopedEvent] = {}  # user name -> CreateUser event
        self.created_roles: dict[str, ScopedEvent] = {}
        self.created_keys: dict[str, tuple[str, ScopedEvent]] = {}  # key -> (user name, CreateAccessKey event)
        self.instances: dict[str, ScopedEvent] = {}  # instance id -> RunInstances event
        for t in scope.taint.identities:
            s = self.by_id.get(t.issued_by)
            if s is None:
                continue
            if t.rule == "iam:CreateUser" and isinstance(name := _req(s.event, "userName"), str):
                self.created_users[name] = s
            elif t.rule == "iam:CreateRole" and isinstance(name := _req(s.event, "roleName"), str):
                self.created_roles[name] = s
            elif t.rule == "iam:CreateAccessKey":
                owner = _req(s.event, "userName") or _user_name(s.event)
                if isinstance(owner, str):
                    self.created_keys[t.value] = (owner, s)
            elif t.rule == "ec2:RunInstances":
                self.instances[t.value] = s

    def _manual(self, draft: _Draft, kind: str) -> None:
        note = f"a {kind} value from the logs does not have the expected form, so nothing is given to run: check the target by hand"
        draft.caution = f"{draft.caution} {note}" if draft.caution else note
        draft.commands, draft.operations = [], []

    def run(self, draft: _Draft, ops: list[Op]) -> None:
        """Add a step that `controlzee respond` can carry out."""
        try:
            for op, args, region in ops:
                validate(op, args, region)
            draft.operations = [Operation(op=op, args=args, region=region) for op, args, region in ops]
            draft.commands = [c for op, args, region in ops for c in OPS[op].cli(args, region)]
        except Unsafe as e:
            self._manual(draft, str(e))
        self.drafts.append(draft)

    def manual(self, draft: _Draft, build: Callable[..., list[str]] | None = None) -> None:
        """Add a step for a person; `build` gives its commands and may raise Unsafe."""
        try:
            draft.commands = build() if build else []
        except Unsafe as e:
            self._manual(draft, str(e))
        self.drafts.append(draft)

    # ---- contain

    def contain(self) -> None:
        long_term: dict[tuple[str, str, str], list[ScopedEvent]] = defaultdict(list)
        user_sessions: dict[tuple[str, str], list[ScopedEvent]] = defaultdict(list)
        role_sessions: dict[tuple[str, str], list[ScopedEvent]] = defaultdict(list)
        for s in self.scope.events:
            ui, key = s.event.user_identity, s.event.user_identity.access_key_id
            if ui.type == "IAMUser" and key and (user := _user_name(s.event)):
                (long_term[(_account(s.event), user, key)] if key.startswith("AKIA")
                 else user_sessions[(_account(s.event), user)]).append(s)
            elif ui.type == "AssumedRole" and (role := _role_name(s.event)):
                role_sessions[(_account(s.event), role)].append(s)

        for (account, user, key), evs in sorted(long_term.items()):
            legit_owner = user not in self.created_users
            self.run(_Draft("contain", "Deactivate an access key the attacker used", f"access key {key} of user {user} (account {account})",
                            f"{len(evs)} in-scope call(s) were made with it", evs, account,
                            caution="the key's legitimate owner will stop working until it has a replacement (see the recover steps)"
                            if legit_owner else None),
                     [("deactivate_access_key", {"user": user, "key": key}, None)])
        for key, (user, s) in sorted(self.created_keys.items()):
            if any(k == key for _, _, k in long_term):
                continue
            self.run(_Draft("contain", "Deactivate an access key the attacker created", f"access key {key} of user {user}",
                            "created by an in-scope call; it was not seen in use, which the logs may simply not show", [s],
                            s.event.recipient_account_id),
                     [("deactivate_access_key", {"user": user, "key": key}, None)])
        for (account, user), evs in sorted(user_sessions.items()):
            self.run(_Draft("contain", "Revoke the user's temporary credentials", f"session tokens of user {user} (account {account})",
                            "in-scope calls used temporary credentials of this user (GetSessionToken, federation or a console "
                            "session); deactivating the user's keys does not end them", evs, account,
                            caution="denies everything to credentials issued before now; remove the policy once the incident is over"),
                     [("revoke_user_sessions", {"user": user}, None)])
        for (account, role), evs in sorted(role_sessions.items()):
            created = role in self.created_roles
            self.run(_Draft("contain", "Revoke the role's active sessions", f"role {role} (account {account})",
                            f"{len(evs)} in-scope call(s) were made with sessions of this role"
                            + ("; the attacker created it" if created else ""), evs, account,
                            caution=None if created else "this also ends legitimate sessions of the role; they can assume it again"),
                     [("revoke_role_sessions", {"role": role}, None)])
        for name, s in sorted(self.created_roles.items()):
            if any(r == name for _, r in role_sessions):
                continue
            self.run(_Draft("contain", "Revoke sessions of a role the attacker created", f"role {name}",
                            "created by an in-scope call; no session of it was seen, which the logs may not show", [s],
                            s.event.recipient_account_id),
                     [("revoke_role_sessions", {"role": name}, None)])
        for user, s in sorted(self.created_users.items()):
            if any(e.event.event_name in ("CreateLoginProfile", "UpdateLoginProfile") and _req(e.event, "userName") == user
                   for e in self.scope.events):
                self.run(_Draft("contain", "Remove the console password of a user the attacker created", f"user {user}",
                                "an in-scope call gave it a console password", [s], s.event.recipient_account_id),
                         [("delete_login_profile", {"user": user}, None)])
        for instance, s in sorted(self.instances.items()):
            r, account = s.event.aws_region, s.event.recipient_account_id
            self.run(_Draft("contain", "Cut an attacker's instance off from its role", f"instance {instance} ({r})",
                            "launched by an in-scope call with an instance profile; it keeps fetching new role credentials "
                            "until the profile is removed", [s], account),
                     [("disassociate_instance_profile", {"instance": instance}, r)])
            self.run(_Draft("contain", "Stop an attacker's instance", f"instance {instance} ({r})",
                            "it may still run the attacker's code", [s], account,
                            caution="stopping loses its memory; capture it first if you need it, and snapshot the disks "
                                    "(see the investigate steps)"),
                     [("stop_instance", {"instance": instance}, r)])

    # ---- investigate

    def investigate(self) -> None:
        cov = self.scope.coverage
        for u in cov.unlogged_accounts:
            evs = [self.by_id[e] for e in u.event_ids if e in self.by_id]
            keys = sorted(t.value for t in self.scope.taint.identities if t.issued_by in u.event_ids and t.kind == "access_key_id")
            self.manual(_Draft("investigate", "Get the logs of an account the attacker reached", f"account {u.account}",
                               f"in-scope calls assumed {', '.join(u.role_arns)} there, and no logs from it were given", evs, u.account,
                               caution="the attacker may hold credentials there that this plan cannot revoke"),
                        lambda ks=keys: [f"controlzee scope --logs THAT_ACCOUNTS_LOGS --access-key {q('key', k)} -o scope-{k}.json"
                                         for k in ks])
        for g in cov.gaps:
            evs = [self.by_id[g.possible_cause]] if g.possible_cause in self.by_id else []
            self.manual(_Draft("investigate", "Fill a gap in the logs from CloudTrail event history",
                               f"{g.region} in account {g.account}, {g.start} to {g.end}",
                               f"the logs are silent for {g.minutes} minutes during the incident; event history keeps 90 days of "
                               "management events whatever happened to the trail", evs, g.account,
                               caution="event history can only be read from inside the account, with credentials for it"),
                        lambda g=g: [f"controlzee scope --lookup-events {q('region', g.region)} --window {g.start} {g.end} "
                                     "--iocs YOUR_IOC_FILE -o scope-gap.json"])
        if any(n.startswith("no data events") for n in cov.notes):
            self.manual(_Draft("investigate", "Look for object-level access elsewhere", "S3 and other data-plane activity",
                               "the inputs have no data events, so reads of objects, secrets in Lambda and the like are invisible here",
                               [], caution="sources: S3 server access logs, CloudTrail data events on another trail, VPC flow logs"))
        for instance, s in sorted(self.instances.items()):
            r = s.event.aws_region
            self.run(_Draft("investigate", "Preserve an attacker's instance for analysis", f"instance {instance} ({r})",
                            "snapshot its disks before it is terminated", [s], s.event.recipient_account_id),
                     [("snapshot_instance", {"instance": instance}, r)])

    # ---- eradicate

    def eradicate(self) -> None:
        changes = [(pc, self.by_id[pc.event_id]) for pc in exposure(self.scope).privilege_changes
                   if pc.outcome == "ok" and pc.event_id in self.by_id]
        for name, s in sorted(self.created_users.items()):
            self.run(_Draft("eradicate", "Delete a user the attacker created", f"user {name}", "created by an in-scope call", [s],
                            s.event.recipient_account_id,
                            caution="removes its keys, password, policies, groups and MFA devices first; respond does this, "
                                    "by hand repeat each list-then-delete pair until the lists are empty"),
                     [("delete_user", {"user": name}, None)])
        for name, s in sorted(self.created_roles.items()):
            self.run(_Draft("eradicate", "Delete a role the attacker created", f"role {name}", "created by an in-scope call", [s],
                            s.event.recipient_account_id),
                     [("delete_role", {"role": name}, None)])
        for pc, s in changes:
            kind, _, who = pc.principal.partition(" ")
            if (kind == "user" and who in self.created_users) or (kind == "role" and who in self.created_roles):
                continue  # deleted with the principal
            self._undo(pc.action, kind, who, pc.policy, s)
        for instance, s in sorted(self.instances.items()):
            r = s.event.aws_region
            self.run(_Draft("eradicate", "Terminate an attacker's instance", f"instance {instance} ({r})",
                            "launched by an in-scope call", [s], s.event.recipient_account_id, caution="only after its disks are preserved"),
                     [("terminate_instance", {"instance": instance}, r)])

    _UNDO = {"iam:AttachUserPolicy": ("detach_user_policy", "user", "policy_arn"),
             "iam:AttachRolePolicy": ("detach_role_policy", "role", "policy_arn"),
             "iam:AttachGroupPolicy": ("detach_group_policy", "group", "policy_arn"),
             "iam:PutUserPolicy": ("delete_user_policy", "user", "policy"), "iam:PutRolePolicy": ("delete_role_policy", "role", "policy"),
             "iam:PutGroupPolicy": ("delete_group_policy", "group", "policy"),
             "iam:AddUserToGroup": ("remove_user_from_group", "user", "group")}

    def _undo(self, act: str, kind: str, who: str, policy: str | None, s: ScopedEvent) -> None:
        draft = _Draft("eradicate", "Undo a permission change", f"{kind} {who}",
                       f"{act} by an in-scope call" + (f" ({policy})" if policy else ""), [s], _account(s.event))
        if act in self._UNDO:
            op, principal_arg, other_arg = self._UNDO[act]
            self.run(draft, [(op, {principal_arg: who, other_arg: policy}, None)])
            return
        draft.caution = ("restore the role's previous trust policy by hand: the logs show the new one, not the old"
                         if act == "iam:UpdateAssumeRolePolicy" else
                         "restore the previous version by hand: the logs show the change but not what it replaced")
        self.manual(draft)

    # ---- recover

    _RESTORE: dict[str, tuple[str, str, str | None, str | None]] = {  # event -> (title, op, request parameter, caution)
        "StopLogging": ("Turn the trail back on", "start_logging", "name",
                        "someone may have turned it back on already; respond checks first, and starting it again does no harm"),
        "StopConfigurationRecorder": ("Restart AWS Config recording", "start_config_recorder", "configurationRecorderName", None),
        "DeleteDetector": ("Re-enable GuardDuty", "enable_guardduty", None, "the old detector's findings and settings are gone; reapply them"),
        "DisableSecurityHub": ("Re-enable Security Hub", "enable_security_hub", None, "re-enable the standards you used"),
    }
    _ARG = {"start_logging": "trail", "start_config_recorder": "recorder"}

    def recover(self) -> None:
        for t in self.scope.coverage.tampering:
            if not (t.in_scope and t.error_code is None and t.event_id in self.by_id):
                continue
            s = self.by_id[t.event_id]
            target = f"{t.event_source.split('.', 1)[0]} in {t.region} (account {t.account})"
            if t.event_name not in self._RESTORE:
                self.manual(_Draft("recover", f"Review and restore: {t.effect}", target, f"an in-scope {t.event_name} {t.effect}", [s],
                                   t.account, caution="the logs show the change but not the previous settings; restore them by hand"))
                continue
            title, op, param, caution = self._RESTORE[t.event_name]
            args = {self._ARG[op]: _req(s.event, param)} if param else {}
            if op == "start_logging" and not args["trail"]:
                args["trail"] = _req(s.event, "trailName")
            self.run(_Draft("recover", title, target, f"an in-scope {t.event_name} {t.effect}", [s], t.account, caution=caution),
                     [(op, args, t.region)])
        for item in exposure(self.scope).credentials_read:
            kind, _, name = item.partition(" ")
            readers = [s for s in self.scope.events if s.event.error_code is None and name in
                       (_req(s.event, "secretId"), _req(s.event, "name"), _req(s.event, "path"))]
            r = readers[0].event.aws_region if readers else "us-east-1"
            account = readers[0].event.recipient_account_id if readers else None
            if kind == "secret":
                self.manual(_Draft("recover", "Rotate a secret the attacker read", item, "read by an in-scope call", readers, account,
                                   caution="rotation needs a rotation function; otherwise set a new value and update its users"),
                            lambda n=name, r=r: [f"aws secretsmanager rotate-secret --region {q('region', r)} --secret-id {q('secret', n)}"])
            else:
                self.manual(_Draft("recover", "Change a parameter the attacker read", item, "read by an in-scope call", readers, account,
                                   caution="the value is a credential only if it is one; check before changing it"),
                            lambda n=name, r=r: [f"aws ssm put-parameter --region {q('region', r)} --name {q('parameter', n)} "
                                                 "--type SecureString --overwrite --value NEW_VALUE"])
        replaced: set[str] = set()
        for s in self.scope.events:
            ui = s.event.user_identity
            user = _user_name(s.event)
            key = ui.access_key_id
            if ui.type == "IAMUser" and key and key.startswith("AKIA") and user and user not in self.created_users and key not in replaced:
                replaced.add(key)
                self.manual(_Draft("recover", "Give the key's owner a new key, then delete the old one", f"user {user}, replacing {key}",
                                   "its key was deactivated in the contain steps",
                                   [x for x in self.scope.events if x.event.user_identity.access_key_id == key], _account(s.event),
                                   caution="the new secret is shown once: create it where the owner's secret store can take it, "
                                           "and find out how the old one leaked"),
                            lambda u=user, k=key: [f"aws iam create-access-key --user-name {q('iam', u)}",
                                                   f"aws iam delete-access-key --user-name {q('iam', u)} --access-key-id {q('key', k)}"])

    def actions(self) -> list[PlanAction]:
        out: list[PlanAction] = []
        for phase in PHASES:
            for d in (d for d in self.drafts if d.phase == phase):
                ev = sorted(d.evidence, key=lambda s: (s.event.event_time, s.event.event_id))
                out.append(PlanAction(
                    id=f"A{len(out) + 1:02d}", phase=d.phase, title=d.title, target=d.target, why=d.why, account=d.account,
                    confidence=_confidence(ev) if ev else Confidence.STRONG, commands=d.commands, operations=d.operations,
                    disruptive=any(OPS[o.op].disruptive for o in d.operations), caution=d.caution,
                    evidence=[s.event.event_id for s in ev][:LISTED_EVIDENCE]))
        return out


def build_plan(scope: Scope) -> dict[str, Any]:
    """The sealed plan document, ready for canonical.dumps."""
    b = _Builder(scope)
    b.contain()
    b.investigate()
    b.eradicate()
    b.recover()
    actions = b.actions()
    notes = ["steps with operations can be carried out by `controlzee respond` after a dry run and your approval; "
             "the others are for a person. Either way, review each one first",
             "work through the phases in order; within contain, act quickly, since the attacker may notice"]
    if any(a.confidence is Confidence.WEAK for a in actions):
        notes.append("steps marked weak rest on weak evidence (IP, user agent or ARN matches): confirm them before acting")
    if not scope.taint.enabled:
        notes.append("the scope was built with --no-propagate, so credentials the attacker created are not in this plan")
    plan = Plan(tool=tool_info(), scope_sha256=scope.scope_sha256, actions=actions, notes=notes)
    return canonical.seal(plan.model_dump(mode="json"), "plan_sha256")
