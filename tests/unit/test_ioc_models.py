import pytest
from pydantic import ValidationError

from controlzee.model.common import Confidence
from controlzee.model.ioc import Indicator, IndicatorKind, SeedSpec


def ind(kind="access_key_id", value="AKIAEXAMPLE", name="x", **kw):
    return Indicator(name=name, kind=kind, value=value, **kw)


@pytest.mark.parametrize("kind,strength", [
    ("access_key_id", Confidence.STRONG), ("principal_id", Confidence.STRONG), ("source_identity", Confidence.STRONG),
    ("principal_arn", Confidence.WEAK), ("source_ip", Confidence.WEAK), ("user_agent", Confidence.WEAK),
])
def test_strength_by_kind(kind, strength):
    value = {"source_ip": "192.0.2.1"}.get(kind, "something")
    assert ind(kind, value).strength is strength


@pytest.mark.parametrize("name", ["", "1abc", "a b", "a.b", "and", "OR", "Not", "x" * 65, "ünï"])
def test_bad_names(name):
    with pytest.raises(ValidationError):
        ind(name=name)


@pytest.mark.parametrize("value", ["", "x" * 2049, "has\nnewline", "has\x1bescape"])
def test_bad_values(value):
    with pytest.raises(ValidationError):
        ind(value=value)


def test_user_agent_defaults_to_substring_and_validates_regex():
    assert ind("user_agent", "curl/").match == "substring"
    assert ind("user_agent", "curl/.*", match="regex").match == "regex"
    with pytest.raises(ValidationError, match="invalid regular expression"):
        ind("user_agent", "([", match="regex")


@pytest.mark.parametrize("kind", ["access_key_id", "principal_id", "source_identity", "principal_arn", "source_ip"])
def test_only_user_agents_can_be_fuzzy(kind):
    value = "192.0.2.1" if kind == "source_ip" else "x"
    with pytest.raises(ValidationError, match="only support exact"):
        ind(kind, value, match="substring")


@pytest.mark.parametrize("value", ["192.0.2.1", "192.0.2.0/24", "2001:db8::1", "2001:db8::/32"])
def test_ip_indicators_accept_addresses_and_ranges(value):
    assert ind("source_ip", value).value == value


@pytest.mark.parametrize("value", ["not-an-ip", "192.0.2.300", "192.0.2.0/99", "ec2.amazonaws.com"])
def test_ip_indicators_reject_everything_else(value):
    with pytest.raises(ValidationError, match="not an IP address"):
        ind("source_ip", value)


def test_models_are_frozen_and_reject_unknown_fields():
    i = ind()
    with pytest.raises(ValidationError):
        i.value = "other"
    with pytest.raises(ValidationError):
        Indicator(name="x", kind=IndicatorKind.ACCESS_KEY_ID, value="v", surprise=1)


def test_seed_spec_rejects_duplicate_names():
    with pytest.raises(ValidationError, match="unique"):
        SeedSpec(indicators=(ind(name="a"), ind(name="a", value="other")), expression="a")
