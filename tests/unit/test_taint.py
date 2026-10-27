import pytest

from controlzee.ingest.index import EventIndex
from controlzee.model.common import Confidence
from controlzee.seed.match import SeedHit
from controlzee.taint.propagate import propagate, seeds_only
from controlzee.taint.rules import issued_by, rule_name
from controlzee.timeutil import parse_time_us
from tests.helpers import make_row

T0 = parse_time_us("2026-10-20T12:00:00Z")
STRONG, WEAK = Confidence.STRONG, Confidence.WEAK


def index(*rows):
    return EventIndex(rows=sorted(rows, key=lambda r: (r[1], r[0])), files=[])


def seed(idx, event_id, confidence=STRONG):
    return SeedHit(next(n for n, r in enumerate(idx.rows) if r[0] == event_id), confidence, ("ioc",))


def marks_by_id(idx, prop):
    return {idx.rows[n][0]: m for n, m in prop.marks.items()}


# ---- rules

@pytest.mark.parametrize("source,name,request_,response,expected", [
    ("iam.amazonaws.com", "CreateAccessKey", {}, {"accessKey": {"accessKeyId": "AKIANEW"}}, (("access_key_id", "AKIANEW"),)),
    ("iam.amazonaws.com", "CreateUser", {}, {"user": {"userId": "AIDANEW"}}, (("principal_id", "AIDANEW"),)),
    ("iam.amazonaws.com", "CreateRole", {}, {"role": {"roleId": "AROANEW"}}, (("role_id", "AROANEW"),)),
    ("sts.amazonaws.com", "GetSessionToken", {}, {"credentials": {"accessKeyId": "ASIANEW"}}, (("access_key_id", "ASIANEW"),)),
    ("sts.amazonaws.com", "AssumeRole", {}, {"credentials": {"accessKeyId": "ASIANEW"}, "assumedRoleUser": {"assumedRoleId": "AROAR:s"}},
     (("access_key_id", "ASIANEW"), ("assumes_role", "AROAR"))),
    ("ec2.amazonaws.com", "RunInstances", {"iamInstanceProfile": {"name": "p"}},
     {"instancesSet": {"items": [{"instanceId": "i-2"}, {"instanceId": "i-1"}, {"nope": 1}]}}, (("instance_id", "i-1"), ("instance_id", "i-2"))),
])
def test_rules_read_what_each_call_hands_over(source, name, request_, response, expected):
    assert issued_by({"requestParameters": request_, "responseElements": response}, source, name) == expected


@pytest.mark.parametrize("rec,source,name", [
    ({"errorCode": "AccessDenied", "responseElements": {"accessKey": {"accessKeyId": "AKIANEW"}}}, "iam.amazonaws.com", "CreateAccessKey"),
    ({"requestParameters": {}, "responseElements": {"instancesSet": {"items": [{"instanceId": "i-1"}]}}}, "ec2.amazonaws.com", "RunInstances"),
    ({"responseElements": {"accessKey": "garbage"}}, "iam.amazonaws.com", "CreateAccessKey"),
    ({"responseElements": None}, "sts.amazonaws.com", "AssumeRole"),
    ({"responseElements": {"accessKey": {"accessKeyId": "AKIANEW"}}}, "iam.amazonaws.com", "ListUsers"),
])
def test_failed_unrelated_or_odd_calls_hand_over_nothing(rec, source, name):
    # a failed call, an instance without a profile (no credentials), bad shapes, and any other call
    assert issued_by(rec, source, name) is None


def test_rule_name():
    assert rule_name("iam.amazonaws.com", "CreateAccessKey") == "iam:CreateAccessKey"


# ---- propagation

def test_chains_grow_one_hop_at_a_time():
    idx = index(make_row(id="seed", ts=T0, issued=(("access_key_id", "AK2"),)),
                make_row(id="hop1", ts=T0 + 1, ak="AK2", issued=(("access_key_id", "AK3"),)),
                make_row(id="hop2", ts=T0 + 2, ak="AK3"), make_row(id="other", ts=T0 + 3, ak="AKX"))
    m = marks_by_id(idx, propagate(idx, [seed(idx, "seed")]))
    assert sorted(m) == ["hop1", "hop2", "seed"]
    assert m["hop1"].chain == ("seed",) and m["hop2"].chain == ("seed", "hop1")
    assert m["hop2"].via is not None and m["hop2"].via.value == "AK3"


def test_an_identity_cannot_act_before_it_was_issued():
    idx = index(make_row(id="early", ts=T0 - 1, ak="AK2"), make_row(id="seed", ts=T0, issued=(("access_key_id", "AK2"),)),
                make_row(id="same-second", ts=T0, ak="AK2"))
    assert sorted(marks_by_id(idx, propagate(idx, [seed(idx, "seed")]))) == ["same-second", "seed"]


def test_strong_wins_over_an_earlier_weak_path():
    idx = index(make_row(id="weak-seed", ts=T0, issued=(("access_key_id", "AK2"),)),
                make_row(id="strong-seed", ts=T0 + 1, issued=(("access_key_id", "AK2"),)), make_row(id="use", ts=T0 + 2, ak="AK2"))
    prop = propagate(idx, [seed(idx, "weak-seed", WEAK), seed(idx, "strong-seed")])
    m = marks_by_id(idx, prop)
    assert m["use"].confidence is STRONG and m["use"].chain == ("strong-seed",)
    assert m["weak-seed"].confidence is WEAK and [t.confidence for t in prop.identities] == [STRONG]


def test_a_weak_seed_acting_as_a_strong_identity_becomes_strong():
    idx = index(make_row(id="strong-seed", ts=T0, issued=(("access_key_id", "AK2"),)), make_row(id="weak-seed", ts=T0 + 1, ak="AK2"))
    m = marks_by_id(idx, propagate(idx, [seed(idx, "strong-seed"), seed(idx, "weak-seed", WEAK)]))
    assert m["weak-seed"].confidence is STRONG and m["weak-seed"].chain == ("strong-seed",)


def test_roles_instances_and_users_are_matched_by_principal_id():
    idx = index(make_row(id="seed", ts=T0, issued=(("role_id", "AROANEW"), ("instance_id", "i-1"), ("principal_id", "AIDANEW"))),
                make_row(id="role-session", ts=T0 + 1, ak="ASIA1", pid="AROANEW:any", uitype="AssumedRole"),
                make_row(id="instance-session", ts=T0 + 2, ak="ASIA2", pid="AROAAPP:i-1", uitype="AssumedRole"),
                make_row(id="user", ts=T0 + 3, ak=None, pid="AIDANEW"),
                make_row(id="not-a-session", ts=T0 + 4, ak="AKIA9", pid="AIDAX:i-1", uitype="IAMUser"),
                make_row(id="other-role", ts=T0 + 5, ak="ASIA3", pid="AROAOLD:any", uitype="AssumedRole"))
    m = marks_by_id(idx, propagate(idx, [seed(idx, "seed")]))
    assert sorted(m) == ["instance-session", "role-session", "seed", "user"]


def test_assuming_a_tainted_role_is_acting_as_it_even_without_a_tainted_caller():
    idx = index(make_row(id="create-role", ts=T0, issued=(("role_id", "AROANEW"),)),
                make_row(id="outside-assume", ts=T0 + 1, ak=None, pid="AIDAOUTSIDE", uitype="AWSAccount",
                         issued=(("access_key_id", "ASIANEW"), ("assumes_role", "AROANEW"))),
                make_row(id="assume-other", ts=T0 + 2, ak=None, pid="AIDAOUTSIDE", issued=(("assumes_role", "AROAOLD"),)))
    prop = propagate(idx, [seed(idx, "create-role")])
    assert sorted(marks_by_id(idx, prop)) == ["create-role", "outside-assume"]
    assert [(t.kind, t.value) for t in prop.identities] == [("role_id", "AROANEW"), ("access_key_id", "ASIANEW")]  # never "assumes_role"


def test_seeds_only_and_no_seeds():
    idx = index(make_row(id="seed", ts=T0, issued=(("access_key_id", "AK2"),)), make_row(id="use", ts=T0 + 1, ak="AK2"))
    assert sorted(marks_by_id(idx, seeds_only([seed(idx, "seed")]))) == ["seed"]
    empty = propagate(idx, [])
    assert empty.marks == {} and empty.identities == []
