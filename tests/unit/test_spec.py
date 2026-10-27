import pytest

from controlzee.model.ioc import IndicatorKind, Window
from controlzee.seed.guardduty import from_guardduty, load_guardduty_file
from controlzee.seed.spec import SpecError, SpecParts, assemble, from_flags, load_iocs_file, make_window

YAML = """\
version: 1
indicators:
  leaked_key: {type: access_key_id, value: AKIA1}
  nat: {type: source_ip, value: 203.0.113.0/24}
  tool: {type: user_agent, value: curl/, match: substring}
expression: leaked_key OR (nat AND tool)
window: {start: 2026-10-20T12:00:00Z, end: 2026-10-20T14:00:00Z}
"""


def write(tmp_path, text, name="iocs.yaml"):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_ioc_file_round_trip(tmp_path):
    parts = load_iocs_file(write(tmp_path, YAML))
    assert {i.name: (i.kind, i.value, i.match) for i in parts.indicators} == {
        "leaked_key": (IndicatorKind.ACCESS_KEY_ID, "AKIA1", "exact"),
        "nat": (IndicatorKind.SOURCE_IP, "203.0.113.0/24", "exact"),
        "tool": (IndicatorKind.USER_AGENT, "curl/", "substring")}
    assert parts.expression == "leaked_key OR (nat AND tool)"
    assert parts.window == Window(start="2026-10-20T12:00:00Z", end="2026-10-20T14:00:00Z")


def test_yaml_dates_are_normalised_to_utc_strings(tmp_path):
    # unquoted YAML timestamps load as datetimes
    parts = load_iocs_file(write(tmp_path, "indicators: {k: {type: access_key_id, value: A}}\nwindow: {start: 2026-10-20 12:00:00, end: 2026-10-20T15:00:00+01:00}\n"))
    assert parts.window == Window(start="2026-10-20T12:00:00Z", end="2026-10-20T14:00:00Z")


@pytest.mark.parametrize("text,message", [
    ("- just\n- a list\n", "must be a mapping"),
    ("indicators: [", "not valid YAML"),
    ("version: 2\nindicators: {k: {type: access_key_id, value: A}}\n", "unsupported IOC file version"),
    ("indicators: {k: {type: nonsense, value: A}}\n", "indicators.k.type"),
    ("indicators: {k: {type: access_key_id, value: A, surprise: 1}}\n", "surprise"),
    ("indicators: {k: {type: source_ip, value: nope}}\n", "not an IP address"),
    ("indicators: {k: {type: access_key_id, value: A}}\nwindow: {start: 2026-10-20T00:00:00Z, until: x}\n", "only takes 'start' and 'end'"),
    ("indicators: {k: {type: access_key_id, value: A}}\nwindow: {start: not-a-time}\n", "time"),
])
def test_ioc_file_errors_name_the_problem(tmp_path, text, message):
    with pytest.raises(SpecError, match=message):
        load_iocs_file(write(tmp_path, text))


def test_ioc_file_missing_or_huge(tmp_path):
    with pytest.raises(SpecError, match="cannot read IOC file"):
        load_iocs_file(tmp_path / "absent.yaml")
    with pytest.raises(SpecError, match="larger than"):
        load_iocs_file(write(tmp_path, "#" * ((1 << 20) + 1)))


def test_yaml_tags_cannot_construct_objects(tmp_path):
    with pytest.raises(SpecError, match="not valid YAML"):
        load_iocs_file(write(tmp_path, "indicators: !!python/object/apply:os.system ['true']\n"))


def test_make_window():
    assert make_window(None) is None and make_window({}) is None
    assert make_window({"end": "2026-10-20T14:00:00Z"}) == Window(start=None, end="2026-10-20T14:00:00Z")


def test_flags_are_named_in_order():
    inds = from_flags(access_keys=["A1", "A2"], ips=["192.0.2.1"], user_agents=["curl"], user_agent_regexes=["^x"], arns=["arn:a"])
    assert [(i.name, i.kind.value, i.match) for i in inds] == [
        ("access_key_1", "access_key_id", "exact"), ("access_key_2", "access_key_id", "exact"), ("arn_1", "principal_arn", "exact"),
        ("ip_1", "source_ip", "exact"), ("ua_1", "user_agent", "substring"), ("ua_regex_1", "user_agent", "regex")]


def test_bad_flag_values_become_spec_errors():
    with pytest.raises(SpecError, match="not an IP address"):
        from_flags(ips=["999.1.1.1"])


def test_assemble_defaults_expression_to_or_of_everything():
    spec = assemble([SpecParts(from_flags(access_keys=["A"], ips=["192.0.2.1"]))])
    assert spec.expression == "access_key_1 OR ip_1"
    assert [i.name for i in spec.indicators] == ["access_key_1", "ip_1"]


def test_assemble_precedence_cli_over_file_over_guardduty(tmp_path):
    gd = from_guardduty(FINDING)
    file = load_iocs_file(write(tmp_path, YAML))
    # the file beats GuardDuty (the file comes later in the parts list)
    spec = assemble([gd, file])
    assert spec.expression == "leaked_key OR (nat AND tool)" and spec.window and spec.window.start == "2026-10-20T12:00:00Z"
    # GuardDuty alone supplies the window; the default expression ORs everything
    only_gd = assemble([gd])
    assert only_gd.window == gd.window and only_gd.expression == "gd_access_key_1 OR gd_ip_1 OR gd_principal_id_1"
    # the command line beats both
    cli_window = Window(start="2026-10-21T00:00:00Z", end="2026-10-22T00:00:00Z")
    spec = assemble([gd, file], expression="gd_access_key_1 OR leaked_key", window=cli_window)
    assert spec.expression == "gd_access_key_1 OR leaked_key" and spec.window == cli_window


def test_assemble_rejects_nothing_and_duplicates():
    with pytest.raises(SpecError, match="no indicators"):
        assemble([SpecParts()])
    with pytest.raises(SpecError, match="used twice: access_key_1"):
        assemble([SpecParts(from_flags(access_keys=["A"])), SpecParts(from_flags(access_keys=["B"]))])


FINDING = {
    "Id": "f1", "Resource": {"AccessKeyDetails": {"AccessKeyId": "AKIAGD", "PrincipalId": "AIDAGD", "UserName": "alice"}},
    "Service": {"EventFirstSeen": "2026-10-20T12:00:00.000Z", "EventLastSeen": "2026-10-20T13:30:00Z",
                "Action": {"AwsApiCallAction": {"RemoteIpDetails": {"IpAddressV4": "198.51.100.7"}}}},
}


def test_guardduty_finding_yields_key_principal_ip_and_window():
    p = from_guardduty(FINDING)
    assert [(i.name, i.kind.value, i.value) for i in p.indicators] == [
        ("gd_access_key_1", "access_key_id", "AKIAGD"), ("gd_principal_id_1", "principal_id", "AIDAGD"), ("gd_ip_1", "source_ip", "198.51.100.7")]
    assert p.window == Window(start="2026-10-20T12:00:00Z", end="2026-10-20T13:30:00Z")
    assert any("imported access key AKIAGD" in n for n in p.notes)


def test_guardduty_accepts_wrapped_and_listed_findings_and_dedupes():
    other = {"Id": "f2", "Resource": {"AccessKeyDetails": {"AccessKeyId": "AKIAGD"}},
             "Service": {"EventFirstSeen": "2026-10-19T00:00:00Z", "EventLastSeen": "2026-10-21T00:00:00Z"}}
    for doc in ({"Findings": [FINDING, other]}, [FINDING, other]):
        p = from_guardduty(doc)
        assert len([i for i in p.indicators if i.kind is IndicatorKind.ACCESS_KEY_ID]) == 1
        assert p.window == Window(start="2026-10-19T00:00:00Z", end="2026-10-21T00:00:00Z")  # widest span across findings
        assert any("finding f2: no new indicators" in n for n in p.notes)


def test_guardduty_skips_what_it_cannot_use():
    p = from_guardduty({"Id": "f3", "Resource": {}, "Service": {"EventFirstSeen": "garbage", "EventLastSeen": "2026-10-21T00:00:00Z",
                                                                "Action": {"AwsApiCallAction": {"RemoteIpDetails": {"IpAddressV4": "not-an-ip"}}}}})
    assert p.indicators == [] and p.window is None
    assert any("unreadable EventFirstSeen" in n for n in p.notes)


def test_guardduty_rejects_other_json(tmp_path):
    with pytest.raises(SpecError, match="not a GuardDuty finding"):
        from_guardduty({"hello": "world"})
    bad = tmp_path / "f.json"
    bad.write_text("{nope")
    with pytest.raises(SpecError, match="not valid JSON"):
        load_guardduty_file(bad)
    with pytest.raises(SpecError, match="cannot read"):
        load_guardduty_file(tmp_path / "absent.json")
