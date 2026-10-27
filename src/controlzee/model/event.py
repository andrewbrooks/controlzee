"""A normalized CloudTrail event."""
from __future__ import annotations

from typing import Any

from controlzee.model.common import Model


class SessionIssuer(Model):
    type: str | None = None
    arn: str | None = None
    principal_id: str | None = None
    account_id: str | None = None
    user_name: str | None = None


class UserIdentity(Model):
    type: str | None = None
    arn: str | None = None
    principal_id: str | None = None
    account_id: str | None = None
    access_key_id: str | None = None
    user_name: str | None = None
    session_name: str | None = None
    session_issuer: SessionIssuer | None = None
    source_identity: str | None = None
    invoked_by: str | None = None
    mfa_authenticated: bool | None = None


class SourceRef(Model):
    """Where the record came from, so the raw record can be fetched again without storing it in every artifact."""

    input: str
    record: int


class Event(Model):
    event_id: str
    event_time: str
    event_source: str
    event_name: str
    aws_region: str
    recipient_account_id: str
    read_only: bool | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    user_identity: UserIdentity
    request_parameters: dict[str, Any] | None = None
    response_elements: dict[str, Any] | None = None
    resources: list[dict[str, Any]] = []
    error_code: str | None = None
    error_message: str | None = None
    shared_event_id: str | None = None
    vpc_endpoint_id: str | None = None
    source: SourceRef
    raw: dict[str, Any] | None = None  # only present when the scope was built with --embed-raw
