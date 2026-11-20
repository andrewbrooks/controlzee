"""A trailing newline must not pass any command-line value check."""

import pytest

from controlzee import argcheck


@pytest.mark.parametrize(
    "call",
    [
        lambda: argcheck.profile("prod\n"),
        lambda: argcheck.region("us-east-1\n", "--region"),
        lambda: argcheck.s3_url("s3://my-bucket\n/prefix"),
    ],
)
def test_trailing_newline_is_refused(call) -> None:
    with pytest.raises(argcheck.ArgError):
        call()


def test_non_ascii_look_alikes_are_refused() -> None:
    with pytest.raises(argcheck.ArgError):
        argcheck.profile("prпfile")
    with pytest.raises(argcheck.ArgError):
        argcheck.s3_url("s3://my-bucket/café")
