"""The argument shapes of respond operations: ASCII only, and provider ARNs name a known partition."""

from __future__ import annotations

import re

import pytest

from controlzee.respond.ops import SHAPES, Unsafe, validate

NON_ASCII_DIGIT = "١"  # ARABIC-INDIC DIGIT ONE: `\d` matches it without re.ASCII
NON_ASCII_LETTER = "é"  # e with acute: `\w` matches it without re.ASCII
OIDC = "arn:{p}:iam::111122223333:oidc-provider/idp.example.com"
SAML = "arn:{p}:iam::111122223333:saml-provider/AttackerIdP"


@pytest.mark.parametrize(
    "op,arn",
    [
        ("delete_oidc_provider", f"arn:aws:iam::{NON_ASCII_DIGIT * 12}:oidc-provider/idp.example.com"),
        ("delete_saml_provider", f"arn:aws:iam::{NON_ASCII_DIGIT * 12}:saml-provider/AttackerIdP"),
        ("delete_oidc_provider", f"arn:aws:iam::111122223333:oidc-provider/idp{NON_ASCII_LETTER}.com"),
        ("delete_saml_provider", f"arn:aws:iam::111122223333:saml-provider/Attacker{NON_ASCII_LETTER}"),
        ("delete_oidc_provider", OIDC.format(p="aws") + "\n"),
        ("delete_saml_provider", SAML.format(p="aws") + "\n"),
        ("delete_oidc_provider", OIDC.format(p="aws-iso")),
        ("delete_saml_provider", SAML.format(p="awsx")),
        ("delete_saml_provider", SAML.format(p="aws-cn-x")),
        ("delete_oidc_provider", OIDC.format(p="aws-")),
    ],
)
def test_provider_arns_must_be_ascii_with_a_known_partition(op, arn):
    with pytest.raises(Unsafe):
        validate(op, {"provider_arn": arn}, None)


@pytest.mark.parametrize("partition", ["aws", "aws-cn", "aws-us-gov"])
def test_the_three_partitions_are_accepted(partition):
    validate("delete_oidc_provider", {"provider_arn": OIDC.format(p=partition)}, None)
    validate("delete_saml_provider", {"provider_arn": SAML.format(p=partition)}, None)


@pytest.mark.parametrize(
    "op,args",
    [
        ("delete_user", {"user": f"al{NON_ASCII_LETTER}ce"}),
        ("delete_role", {"role": f"r{NON_ASCII_LETTER}le"}),
        ("delete_lambda_function", {"function": f"f{NON_ASCII_LETTER}"}),
        ("start_config_recorder", {"recorder": f"r{NON_ASCII_LETTER}"}),
        ("detach_user_policy", {"user": "u", "policy_arn": f"arn:aws:iam::{NON_ASCII_DIGIT * 12}:policy/p"}),
    ],
)
def test_other_shapes_refuse_non_ascii_letters_and_digits(op, args):
    region = "us-east-1" if op in ("delete_lambda_function", "start_config_recorder") else None
    with pytest.raises(Unsafe):
        validate(op, args, region)


def test_every_shape_is_compiled_ascii_only():
    for kind, shape in SHAPES.items():
        assert shape.flags & re.ASCII, kind
