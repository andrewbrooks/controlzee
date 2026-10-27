"""Turn a raw CloudTrail record into an `Event`. Tolerant by design: CloudTrail omits fields freely."""
from __future__ import annotations

from typing import Any

from controlzee.model.event import Event, SessionIssuer, SourceRef, UserIdentity


def _dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value != "" else None


def session_name(identity_type: str | None, arn: str | None) -> str | None:
    """The session name of an assumed-role or federated-user ARN (the last path segment)."""
    if arn and identity_type in ("AssumedRole", "FederatedUser") and "/" in arn:
        return arn.rsplit("/", 1)[1]
    return None


def identity_from_record(ui: dict[str, Any]) -> UserIdentity:
    sc = _dict(ui.get("sessionContext")) or {}
    iss = _dict(sc.get("sessionIssuer"))
    attrs = _dict(sc.get("attributes")) or {}
    mfa = attrs.get("mfaAuthenticated")
    typ, arn = _str(ui.get("type")), _str(ui.get("arn"))
    return UserIdentity(
        type=typ,
        arn=arn,
        principal_id=_str(ui.get("principalId")),
        account_id=_str(ui.get("accountId")),
        access_key_id=_str(ui.get("accessKeyId")),
        user_name=_str(ui.get("userName")),
        session_name=session_name(typ, arn),
        session_issuer=SessionIssuer(
            type=_str(iss.get("type")), arn=_str(iss.get("arn")), principal_id=_str(iss.get("principalId")),
            account_id=_str(iss.get("accountId")), user_name=_str(iss.get("userName")),
        ) if iss else None,
        source_identity=_str(ui.get("sourceIdentity")),
        invoked_by=_str(ui.get("invokedBy")),
        mfa_authenticated=(mfa == "true") if isinstance(mfa, str) else (mfa if isinstance(mfa, bool) else None),
    )


def event_from_record(rec: dict[str, Any], source: SourceRef, *, embed_raw: bool = False) -> Event:
    ui = _dict(rec.get("userIdentity")) or {}
    identity = identity_from_record(ui)
    resources = rec.get("resources")
    return Event(
        event_id=str(rec["eventID"]),
        event_time=str(rec["eventTime"]),
        event_source=str(rec["eventSource"]),
        event_name=str(rec["eventName"]),
        aws_region=str(rec.get("awsRegion") or ""),
        recipient_account_id=str(rec.get("recipientAccountId") or identity.account_id or ""),
        read_only=rec.get("readOnly") if isinstance(rec.get("readOnly"), bool) else None,
        source_ip=_str(rec.get("sourceIPAddress")),
        user_agent=_str(rec.get("userAgent")),
        user_identity=identity,
        request_parameters=_dict(rec.get("requestParameters")),
        response_elements=_dict(rec.get("responseElements")),
        resources=[r for r in resources if isinstance(r, dict)] if isinstance(resources, list) else [],
        error_code=_str(rec.get("errorCode")),
        error_message=_str(rec.get("errorMessage")),
        shared_event_id=_str(rec.get("sharedEventID")),
        vpc_endpoint_id=_str(rec.get("vpcEndpointId")),
        source=source,
        raw=rec if embed_raw else None,
    )
