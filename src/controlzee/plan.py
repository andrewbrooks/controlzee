"""Build `plan.json` from a scope: contain, investigate, eradicate, recover.

Each step names its target, why (with the events that justify it), its confidence, and AWS CLI commands. The commands
are text for a person; nothing here calls AWS. Values taken from the logs are attacker-influenced, so a value goes into a
command only if it has the documented shape for its kind (IAM name, access key id, instance id, region...) and is
shell-quoted besides; anything else becomes a manual step that says why.

Revoking temporary credentials uses an inline deny on aws:TokenIssueTime, which is what the IAM console's "Revoke active
sessions" does. The time is left to the shell (`$(date -u ...)`) so the plan itself has no clock in it.
"""
from __future__ import annotations

import re
import shlex
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from controlzee import canonical
from controlzee.model.common import Confidence, tool_info
from controlzee.model.event import Event
from controlzee.model.plan import Phase, Plan, PlanAction
from controlzee.model.scope import Scope, ScopedEvent
from controlzee.timeline import exposure

LISTED_EVIDENCE = 10
PHASES: tuple[Phase, ...] = ("contain", "investigate", "eradicate", "recover")
REVOKE_POLICY = "controlzee-revoke-older-sessions"
_SHAPES = {
    "iam": re.compile(r"^[\w+=,.@-]{1,128}$"),  # user, role, group and policy names
    "key": re.compile(r"^(AKIA|ASIA)[A-Z0-9]{12,124}$"),
    "instance": re.compile(r"^i-[0-9a-f]{8,32}$"),
    "region": re.compile(r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$"),
    "policy_arn": re.compile(r"^arn:aws[\w-]*:iam::(aws|\d{12}):policy/[\w+=,.@/-]{1,512}$"),
    "trail": re.compile(r"^(arn:aws[\w-]*:cloudtrail:[a-z0-9-]+:\d{12}:trail/)?[\w.-]{3,128}$"),
    "recorder": re.compile(r"^[\w.-]{1,256}$"),
    "secret": re.compile(r"^[\w/+=.@:-]{1,2048}$"),
    "parameter": re.compile(r"^[\w/.-]{1,2048}$"),
}
_REVOKE_DOC = ('{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",'
               '"Condition":{"DateLessThan":{"aws:TokenIssueTime":"\'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"\'"}}}]}')


class _Unsafe(Exception):
    pass


def _q(kind: str, value: Any) -> str:
    """Shell-quoted `value` if it has the shape of `kind`; raises _Unsafe otherwise."""
    if not isinstance(value, str) or not _SHAPES[kind].match(value):
        raise _Unsafe(kind)
    return shlex.quote(value)


@dataclass
class _Draft:
    phase: Phase
    title: str
    target: str
    why: str
    evidence: list[ScopedEvent]
    commands: list[str] = field(default_factory=list)
    caution: str | None = None


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

    def add(self, draft: _Draft, build: Any = None) -> None:
        """Add `draft`; `build` fills its commands and may raise _Unsafe, which turns it into a manual step."""
        if build is not None:
            try:
                draft.commands = build()
            except _Unsafe as e:
                draft.commands = []
                note = (f"a {e.args[0]} value from the logs does not have the expected form, so no command is given: "
                        "check the target by hand")
                draft.caution = f"{draft.caution} {note}" if draft.caution else note
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
            self.add(_Draft("contain", "Deactivate an access key the attacker used", f"access key {key} of user {user} (account {account})",
                            f"{len(evs)} in-scope call(s) were made with it", evs,
                            caution="the key's legitimate owner will stop working until it has a replacement (see the recover steps)"
                            if legit_owner else None),
                     lambda u=user, k=key: [f"aws iam update-access-key --user-name {_q('iam', u)} --access-key-id {_q('key', k)} --status Inactive"])
        for key, (user, s) in sorted(self.created_keys.items()):
            if any(k == key for _, _, k in long_term):
                continue
            self.add(_Draft("contain", "Deactivate an access key the attacker created", f"access key {key} of user {user}",
                            "created by an in-scope call; it was not seen in use, which the logs may simply not show", [s]),
                     lambda u=user, k=key: [f"aws iam update-access-key --user-name {_q('iam', u)} --access-key-id {_q('key', k)} --status Inactive"])
        for (account, user), evs in sorted(user_sessions.items()):
            self.add(_Draft("contain", "Revoke the user's temporary credentials", f"session tokens of user {user} (account {account})",
                            "in-scope calls used temporary credentials of this user (GetSessionToken or federation); "
                            "deactivating the user's keys does not end them", evs,
                            caution="denies everything to credentials issued before now; remove the policy once the incident is over"),
                     lambda u=user: [f"aws iam put-user-policy --user-name {_q('iam', u)} --policy-name {REVOKE_POLICY} "
                                     f"--policy-document '{_REVOKE_DOC}'"])
        for (account, role), evs in sorted(role_sessions.items()):
            created = role in self.created_roles
            self.add(_Draft("contain", "Revoke the role's active sessions", f"role {role} (account {account})",
                            f"{len(evs)} in-scope call(s) were made with sessions of this role"
                            + ("; the attacker created it" if created else ""), evs,
                            caution=None if created else "this also ends legitimate sessions of the role; they can assume it again"),
                     lambda r=role: [f"aws iam put-role-policy --role-name {_q('iam', r)} --policy-name {REVOKE_POLICY} "
                                     f"--policy-document '{_REVOKE_DOC}'"])
        for name, s in sorted(self.created_roles.items()):
            if any(r == name for _, r in role_sessions):
                continue
            self.add(_Draft("contain", "Revoke sessions of a role the attacker created", f"role {name}",
                            "created by an in-scope call; no session of it was seen, which the logs may not show", [s]),
                     lambda r=name: [f"aws iam put-role-policy --role-name {_q('iam', r)} --policy-name {REVOKE_POLICY} "
                                     f"--policy-document '{_REVOKE_DOC}'"])
        for user, s in sorted(self.created_users.items()):
            console = any(e.event.event_name in ("CreateLoginProfile", "UpdateLoginProfile") and _req(e.event, "userName") == user
                          for e in self.scope.events)
            if console:
                self.add(_Draft("contain", "Remove the console password of a user the attacker created", f"user {user}",
                                "an in-scope call gave it a console password", [s]),
                         lambda u=user: [f"aws iam delete-login-profile --user-name {_q('iam', u)}"])
        for instance, s in sorted(self.instances.items()):
            region = s.event.aws_region
            self.add(_Draft("contain", "Cut an attacker's instance off from its role", f"instance {instance} ({region})",
                            "launched by an in-scope call with an instance profile; it keeps fetching new role credentials "
                            "until the profile is removed", [s],
                            caution="stopping the instance loses its memory; capture it first if you need it"),
                     lambda i=instance, r=region: [
                         f"aws ec2 describe-iam-instance-profile-associations --region {_q('region', r)} "
                         f"--filters Name=instance-id,Values={_q('instance', i)} --query 'IamInstanceProfileAssociations[].AssociationId'",
                         f"aws ec2 disassociate-iam-instance-profile --region {_q('region', r)} --association-id ASSOCIATION_ID_FROM_ABOVE",
                         f"aws ec2 stop-instances --region {_q('region', r)} --instance-ids {_q('instance', i)}"])

    # ---- investigate

    def investigate(self) -> None:
        cov = self.scope.coverage
        for u in cov.unlogged_accounts:
            evs = [self.by_id[e] for e in u.event_ids if e in self.by_id]
            keys = sorted(t.value for t in self.scope.taint.identities if t.issued_by in u.event_ids and t.kind == "access_key_id")
            self.add(_Draft("investigate", "Get the logs of an account the attacker reached", f"account {u.account}",
                            f"in-scope calls assumed {', '.join(u.role_arns)} there, and no logs from it were given", evs,
                            caution="the attacker may hold credentials there that this plan cannot revoke"),
                     lambda ks=keys: [f"controlzee scope --logs THAT_ACCOUNTS_LOGS --access-key {_q('key', k)} -o scope-{k}.json" for k in ks])
        for g in cov.gaps:
            evs = [self.by_id[g.possible_cause]] if g.possible_cause in self.by_id else []
            self.add(_Draft("investigate", "Fill a gap in the logs from CloudTrail event history",
                            f"{g.region} in account {g.account}, {g.start} to {g.end}",
                            f"the logs are silent for {g.minutes} minutes during the incident; event history keeps 90 days of "
                            "management events whatever happened to the trail", evs,
                            caution="event history can only be read from inside the account, with credentials for it"),
                     lambda g=g: [f"controlzee scope --lookup-events {_q('region', g.region)} --window {g.start} {g.end} "
                                  "--iocs YOUR_IOC_FILE -o scope-gap.json"])
        if any(n.startswith("no data events") for n in cov.notes):
            self.add(_Draft("investigate", "Look for object-level access elsewhere", "S3 and other data-plane activity",
                            "the inputs have no data events, so reads of objects, secrets in Lambda and the like are invisible here",
                            [], caution="sources: S3 server access logs, CloudTrail data events on another trail, VPC flow logs"))
        for instance, s in sorted(self.instances.items()):
            r = s.event.aws_region
            self.add(_Draft("investigate", "Preserve an attacker's instance for analysis", f"instance {instance} ({r})",
                            "snapshot its disks before it is terminated", [s]),
                     lambda i=instance, r=r: [
                         f"aws ec2 describe-instances --region {_q('region', r)} --instance-ids {_q('instance', i)} "
                         "--query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId'",
                         f"aws ec2 create-snapshot --region {_q('region', r)} --volume-id VOLUME_ID_FROM_ABOVE "
                         f"--description {shlex.quote('controlzee: evidence from ' + i)}"])

    # ---- eradicate

    def eradicate(self) -> None:
        changes = [(pc, self.by_id[pc.event_id]) for pc in exposure(self.scope).privilege_changes
                   if pc.outcome == "ok" and pc.event_id in self.by_id]
        for name, s in sorted(self.created_users.items()):
            keys = sorted(k for k, (u, _) in self.created_keys.items() if u == name)
            policies = sorted({pc.policy for pc, _ in changes if pc.principal == f"user {name}" and pc.policy
                               and pc.action == "iam:AttachUserPolicy"})

            def build(u: str = name, ks: list[str] = keys, ps: list[str] = policies) -> list[str]:
                user = _q("iam", u)
                return ([f"aws iam detach-user-policy --user-name {user} --policy-arn {_q('policy_arn', p)}" for p in ps]
                        + [f"aws iam delete-access-key --user-name {user} --access-key-id {_q('key', k)}" for k in ks]
                        + [f"aws iam delete-login-profile --user-name {user}",
                           f"aws iam list-attached-user-policies --user-name {user}",
                           f"aws iam list-user-policies --user-name {user}", f"aws iam list-groups-for-user --user-name {user}",
                           f"aws iam delete-user --user-name {user}"])
            self.add(_Draft("eradicate", "Delete a user the attacker created", f"user {name}", "created by an in-scope call", [s],
                            caution="delete-user fails while policies, keys, groups or MFA devices remain; the list commands "
                                    "show what is left, and delete-login-profile fails harmlessly if it has no password"), build)
        for name, s in sorted(self.created_roles.items()):
            policies = sorted({pc.policy for pc, _ in changes if pc.principal == f"role {name}" and pc.policy
                               and pc.action == "iam:AttachRolePolicy"})

            def build_role(r: str = name, ps: list[str] = policies) -> list[str]:
                role = _q("iam", r)
                return ([f"aws iam detach-role-policy --role-name {role} --policy-arn {_q('policy_arn', p)}" for p in ps]
                        + [f"aws iam delete-role-policy --role-name {role} --policy-name {REVOKE_POLICY}",
                           f"aws iam list-attached-role-policies --role-name {role}", f"aws iam list-role-policies --role-name {role}",
                           f"aws iam delete-role --role-name {role}"])
            self.add(_Draft("eradicate", "Delete a role the attacker created", f"role {name}", "created by an in-scope call", [s],
                            caution="delete-role fails while policies or instance profiles remain"), build_role)
        for pc, s in changes:
            kind, _, who = pc.principal.partition(" ")
            if (kind == "user" and who in self.created_users) or (kind == "role" and who in self.created_roles):
                continue  # deleted with the principal
            self.add(*self._undo(pc.action, kind, who, pc.policy, s))
        for instance, s in sorted(self.instances.items()):
            r = s.event.aws_region
            self.add(_Draft("eradicate", "Terminate an attacker's instance", f"instance {instance} ({r})",
                            "launched by an in-scope call", [s], caution="only after its disks are preserved"),
                     lambda i=instance, r=r: [f"aws ec2 terminate-instances --region {_q('region', r)} --instance-ids {_q('instance', i)}"])

    def _undo(self, act: str, kind: str, who: str, policy: str | None, s: ScopedEvent) -> tuple[_Draft, Any]:
        draft = _Draft("eradicate", "Undo a permission change", f"{kind} {who}",
                       f"{act} by an in-scope call" + (f" ({policy})" if policy else ""), [s])
        commands = {
            "iam:AttachUserPolicy": lambda: [f"aws iam detach-user-policy --user-name {_q('iam', who)} --policy-arn {_q('policy_arn', policy)}"],
            "iam:AttachRolePolicy": lambda: [f"aws iam detach-role-policy --role-name {_q('iam', who)} --policy-arn {_q('policy_arn', policy)}"],
            "iam:AttachGroupPolicy": lambda: [f"aws iam detach-group-policy --group-name {_q('iam', who)} --policy-arn {_q('policy_arn', policy)}"],
            "iam:PutUserPolicy": lambda: [f"aws iam delete-user-policy --user-name {_q('iam', who)} --policy-name {_q('iam', policy)}"],
            "iam:PutRolePolicy": lambda: [f"aws iam delete-role-policy --role-name {_q('iam', who)} --policy-name {_q('iam', policy)}"],
            "iam:PutGroupPolicy": lambda: [f"aws iam delete-group-policy --group-name {_q('iam', who)} --policy-name {_q('iam', policy)}"],
            "iam:AddUserToGroup": lambda: [f"aws iam remove-user-from-group --user-name {_q('iam', who)} --group-name {_q('iam', policy)}"],
        }.get(act)
        if commands is None:
            draft.caution = ("restore the previous version by hand: the logs show the change but not what it replaced"
                             if act != "iam:UpdateAssumeRolePolicy" else
                             "restore the role's previous trust policy by hand: the logs show the new one, not the old")
        return draft, commands

    # ---- recover

    def recover(self) -> None:
        for t in self.scope.coverage.tampering:
            if t.in_scope and t.error_code is None and t.event_id in self.by_id:
                title, build, caution = self._restore(t.event_name, t.effect, t.region, self.by_id[t.event_id].event)
                self.add(_Draft("recover", title, f"{t.event_source.split('.', 1)[0]} in {t.region} (account {t.account})",
                                f"an in-scope {t.event_name} {t.effect}", [self.by_id[t.event_id]], caution=caution), build)
        for item in exposure(self.scope).credentials_read:
            kind, _, name = item.partition(" ")
            readers = [s for s in self.scope.events if s.event.error_code is None and name in
                       (_req(s.event, "secretId"), _req(s.event, "name"), _req(s.event, "path"))]
            r = readers[0].event.aws_region if readers else "us-east-1"
            if kind == "secret":
                self.add(_Draft("recover", "Rotate a secret the attacker read", item, "read by an in-scope call", readers,
                                caution="rotation needs a rotation function; otherwise set a new value and update its users"),
                         lambda n=name, r=r: [f"aws secretsmanager rotate-secret --region {_q('region', r)} --secret-id {_q('secret', n)}"])
            else:
                self.add(_Draft("recover", "Change a parameter the attacker read", item, "read by an in-scope call", readers,
                                caution="the value is a credential only if it is one; check before changing it"),
                         lambda n=name, r=r: [f"aws ssm put-parameter --region {_q('region', r)} --name {_q('parameter', n)} "
                                              "--type SecureString --overwrite --value NEW_VALUE"])
        replaced: set[str] = set()
        for s in self.scope.events:
            ui = s.event.user_identity
            user = _user_name(s.event)
            if (ui.type == "IAMUser" and ui.access_key_id and ui.access_key_id.startswith("AKIA") and user
                    and user not in self.created_users and ui.access_key_id not in replaced):
                replaced.add(ui.access_key_id)
                self.add(_Draft("recover", "Give the key's owner a new key, then delete the old one",
                                f"user {user}, replacing {ui.access_key_id}", "its key was deactivated in the contain steps",
                                [x for x in self.scope.events if x.event.user_identity.access_key_id == ui.access_key_id],
                                caution="store the new secret where the owner reads it from, and find out how the old one leaked"),
                         lambda u=user, k=ui.access_key_id: [f"aws iam create-access-key --user-name {_q('iam', u)}",
                                                             f"aws iam delete-access-key --user-name {_q('iam', u)} --access-key-id {_q('key', k)}"])

    @staticmethod
    def _restore(name: str, effect: str, r: str, ev: Event) -> tuple[str, Any, str | None]:
        """(title, command builder or None, caution) for undoing one logging or detection change."""
        if name == "StopLogging":
            trail = _req(ev, "name") or _req(ev, "trailName")
            return "Turn the trail back on", lambda: [
                f"aws cloudtrail get-trail-status --region {_q('region', r)} --name {_q('trail', trail)} --query IsLogging",
                f"aws cloudtrail start-logging --region {_q('region', r)} --name {_q('trail', trail)}"], \
                "someone may have turned it back on already (the status shows it); starting it again does no harm"
        if name == "StopConfigurationRecorder":
            recorder = _req(ev, "configurationRecorderName")
            return "Restart AWS Config recording", lambda: [
                f"aws configservice start-configuration-recorder --region {_q('region', r)} "
                f"--configuration-recorder-name {_q('recorder', recorder)}"], None
        if name == "DeleteDetector":
            return "Re-enable GuardDuty", lambda: [f"aws guardduty create-detector --region {_q('region', r)} --enable"], \
                "the old detector's findings and settings are gone; reapply them"
        if name == "DisableSecurityHub":
            return "Re-enable Security Hub", lambda: [f"aws securityhub enable-security-hub --region {_q('region', r)}"], \
                "re-enable the standards you used"
        return f"Review and restore: {effect}", None, "the logs show the change but not the previous settings; restore them by hand"

    def actions(self) -> list[PlanAction]:
        out: list[PlanAction] = []
        for phase in PHASES:
            for d in (d for d in self.drafts if d.phase == phase):
                ev = sorted(d.evidence, key=lambda s: (s.event.event_time, s.event.event_id))
                out.append(PlanAction(id=f"A{len(out) + 1:02d}", phase=d.phase, title=d.title, target=d.target, why=d.why,
                                      confidence=_confidence(ev) if ev else Confidence.STRONG, commands=d.commands, caution=d.caution,
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
    notes = ["controlzee does not run these commands: review each one, then run it with credentials for the account named in "
             "its target",
             "work through the phases in order; within contain, act quickly, since the attacker may notice"]
    if any(a.confidence is Confidence.WEAK for a in actions):
        notes.append("steps marked weak rest on weak evidence (IP, user agent or ARN matches): confirm them before acting")
    if not scope.taint.enabled:
        notes.append("the scope was built with --no-propagate, so credentials the attacker created are not in this plan")
    plan = Plan(tool=tool_info(), scope_sha256=scope.scope_sha256, actions=actions, notes=notes)
    return canonical.seal(plan.model_dump(mode="json"), "plan_sha256")
