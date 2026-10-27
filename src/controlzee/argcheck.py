"""Checks for command-line arguments that reach AWS or select what runs.

Each value is matched against the narrowest pattern its kind allows before it is used, and refused with a message
otherwise. Nothing controlzee does goes through a shell: AWS is called through boto3 with typed parameters, so these
checks are about getting exactly the intended target (no surprise region, profile, bucket or step), not about quoting.
"""
from __future__ import annotations

import re
from typing import Final

from controlzee.respond.ops import SHAPES

PROFILE: Final = re.compile(r"^[\w.+@-]{1,64}$")
BUCKET: Final = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PREFIX: Final = re.compile(r"^[\w!\-.*'()/=+@,;:&$ ]{0,1024}$")  # S3's "safe" key characters, plus a few common ones
ACTION_ID: Final = re.compile(r"^A\d{2,4}$")
APPROVAL: Final = re.compile(r"^[0-9a-f]{12,64}$")


class ArgError(ValueError):
    """A command-line value does not have the form its option needs."""


def profile(value: str | None) -> str | None:
    if value is not None and not PROFILE.match(value):
        raise ArgError("--aws-profile must be a profile name (letters, digits and . _ + @ -, at most 64)")
    return value


def region(value: str, option: str) -> str:
    if not SHAPES["region"].match(value):
        raise ArgError(f"{option} must be an AWS region such as us-east-1")
    return value


def s3_url(value: str) -> str:
    bucket, _, prefix = value[5:].partition("/")
    if not BUCKET.match(bucket) or ".." in bucket:
        raise ArgError("an s3:// URL must name a valid bucket: s3://bucket/prefix")
    if not PREFIX.match(prefix):
        raise ArgError("the S3 prefix contains characters controlzee does not accept")
    return value


def steps(value: str | None) -> set[str] | None:
    """--steps A01,A03 as a set of action ids."""
    if value is None:
        return None
    ids = [s.strip() for s in value.split(",") if s.strip()]
    if not ids or any(not ACTION_ID.match(i) for i in ids):
        raise ArgError("--steps takes plan step ids separated by commas, such as A01,A03")
    return set(ids)


def approval(value: str) -> str:
    v = value.strip().lower()
    if not APPROVAL.match(v):
        raise ArgError("--approve takes the dry run's sha256 (at least its first 12 hex characters), as printed by the dry run")
    return v
