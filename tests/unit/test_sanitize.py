"""Sanitizing CloudTrail records: identifiers are replaced consistently, nothing original survives, output is stable."""
import json

from controlzee.sanitize import Sanitizer

RECORD = {
    "eventID": "0f1e2d3c-4b5a-4968-8776-655443322110",
    "recipientAccountId": "123456789012",
    "sourceIPAddress": "93.184.216.34",
    "userIdentity": {"accessKeyId": "AKIAQWERTYUIOPASDFGH", "principalId": "AIDAQWERTYUIOPASDFGHJ",
                     "arn": "arn:aws:iam::123456789012:user/stratus-attacker"},
    "errorMessage": "User: arn:aws:iam::123456789012:user/x is not authorized with an explicit deny in a service control "
                    "policy: arn:aws:organizations::210987654321:policy/o-a1b2c3d4e5/service_control_policy/p-q9w8e7r6",
    "userAgent": "aws-sdk-go-v2 contact me@corp.example.org",
}


def test_every_identifier_is_replaced_and_nothing_original_is_left():
    s = Sanitizer()
    text = json.dumps(s.clean(RECORD))
    for original in ("123456789012", "210987654321", "93.184.216.34", "AKIAQWERTYUIOPASDFGH", "AIDAQWERTYUIOPASDFGHJ",
                     "o-a1b2c3d4e5", "p-q9w8e7r6", "0f1e2d3c-4b5a-4968-8776-655443322110", "me@corp.example.org"):
        assert original not in text
    assert s.leaks(text) == []


def test_the_same_original_always_gets_the_same_replacement_and_relations_survive():
    s = Sanitizer()
    a, b = s.clean(RECORD), s.clean({**RECORD, "eventID": "00000000-0000-4000-8000-000000000000"})
    assert a["userIdentity"] == b["userIdentity"] and a["recipientAccountId"] == b["recipientAccountId"]
    assert a["eventID"] != b["eventID"]
    assert a["userIdentity"]["arn"].split(":")[4] == a["recipientAccountId"]  # the account in the ARN is the account field
    assert a["userIdentity"]["accessKeyId"].startswith("AKIA") and len(a["userIdentity"]["accessKeyId"]) == len("AKIAQWERTYUIOPASDFGH")
    assert len(a["userIdentity"]["principalId"]) == len("AIDAQWERTYUIOPASDFGHJ")


def test_output_is_reproducible_for_the_same_input_order():
    assert json.dumps(Sanitizer().clean([RECORD, RECORD])) == json.dumps(Sanitizer().clean([RECORD, RECORD]))


def test_documentation_addresses_and_the_example_key_are_left_alone():
    s = Sanitizer()
    out = s.clean({"ip": "203.0.113.9", "key": "AKIAIOSFODNN7EXAMPLE"})
    assert out == {"ip": "203.0.113.9", "key": "AKIAIOSFODNN7EXAMPLE"}
    assert s.leaks(json.dumps(out)) == []


def test_leaks_finds_what_the_sanitizer_never_saw():
    s = Sanitizer()
    s.clean(RECORD)
    leaked = s.leaks('{"a": "999988887777", "b": "8.8.4.4", "c": "AKIAABCDEFGHIJKLMNOP", "d": "x@y.org", "e": "93.184.216.34"}')
    assert set(leaked) == {"999988887777", "8.8.4.4", "AKIAABCDEFGHIJKLMNOP", "x@y.org", "93.184.216.34"}
    assert s.leaks("{}") == []


def test_a_uuid_made_only_of_digits_is_not_taken_for_an_account_id():
    s = Sanitizer()
    out = s.clean({"requestID": "28ce572f-dea1-595f-90ed-297174385245", "other": "12345678-1234-4234-8234-123456789012"})
    assert s.leaks(json.dumps(out)) == []
    assert out["other"].count("-") == 4 and not out["other"][-12:].isdigit()
    assert s.clean("12345678-1234-4234-8234-123456789012") == out["other"]
