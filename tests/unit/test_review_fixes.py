"""Regression tests for what the review of the HTML report branch found."""
import re
from pathlib import Path

from controlzee import facts, story
from controlzee._html_static import JS
from controlzee.diagrams import NAME_CHARS, _name_lines, _short
from controlzee.facts import SECRET_KINDS, reads_secret
from controlzee.html_report import _step, build_html
from controlzee.model.plan import Operation, Plan, PlanAction
from controlzee.model.timeline import Actor, Timeline
from controlzee.plan import build_plan
from controlzee.planlink import steps_by_actor
from controlzee.story import Moment, _group
from controlzee.timeline import build_timeline
from controlzee.visual import build_graph
from tests.unit.test_respond import scope_of

ROOT = Path(__file__).parents[2]


def moment(n: int, **kw) -> Moment:
    base = {"kind": "issued", "title": "New access key", "detail": "iam:CreateAccessKey", "actor": "user/x", "time": "2026-10-20T10:00:00Z",
            "t_us": n * 1_000_000, "end_us": n * 1_000_000, "count": 1, "event_id": f"e{n}", "hot": False, "event_ids": (f"e{n}",)}
    return Moment(**{**base, **kw})


# ---- an ARN keeps its name

def test_an_arn_whose_resource_is_type_colon_name_keeps_the_name():
    for arn, short in [("arn:aws:secretsmanager:us-east-1:111122223333:secret:prod-db-AbCdEf", "prod-db-AbCdEf"),
                       ("arn:aws:logs:us-east-1:111122223333:log-group:app-logs:*", "app-logs"),
                       ("arn:aws:lambda:us-east-1:111122223333:function:billing-report:$LATEST", "billing-report"),
                       ("arn:aws:iam::aws:policy/ReadOnlyAccess", "ReadOnlyAccess"),
                       ("arn:aws:iam::111122223333:role/path/to/ops-admin", "ops-admin"),
                       ("arn:aws:s3:::my-bucket", "my-bucket")]:
        assert _short(arn) == short, arn


def test_two_different_secrets_do_not_both_read_secret():
    assert _short("arn:aws:secretsmanager:us-east-1:111122223333:secret:a-AbCdEf") != _short("arn:aws:secretsmanager:us-east-1:111122223333:secret:b-AbCdEf")


# ---- the README matches the page

def test_the_readme_does_not_promise_a_dark_theme_the_page_no_longer_has():
    text = (ROOT / "README.md").read_text().lower()
    assert "dark theme" not in text and "light only" in text
    assert "dark" not in (ROOT / "src/controlzee/diagrams.py").read_text().split('"""')[1].lower()


# ---- the first call that matched an indicator is not lost in a burst

def test_a_burst_keeps_the_marker_of_the_call_that_matched_the_indicator():
    got = _group([moment(0), moment(5, first=True), moment(9)])
    assert len(got) == 1 and got[0].count == 3 and got[0].first and got[0].event_ids == ("e0", "e5", "e9")


def test_a_burst_without_the_marker_does_not_invent_it_and_a_late_repeat_is_its_own_moment():
    got = _group([moment(0), moment(5), moment(100)])
    assert [g.count for g in got] == [2, 1] and not any(g.first for g in got)


# ---- a long name stays inside its node

def test_the_head_of_a_long_name_is_cut_too():
    for name in ("arn:aws:sts::111122223333:federated-user/bob", "assumed-role/" + "r" * 80 + "/s" * 30, "x" * 90 + "/y"):
        lines = _name_lines(name)
        assert len(lines) <= 2 and all(len(x) <= NAME_CHARS for x in lines), (name, lines)


# ---- work done only where it is used

def test_the_graph_does_not_work_out_what_was_touched_unless_asked(fixtures):
    scope = scope_of(fixtures, "02_role_chain")
    assert all(not n.touched for n in build_graph(scope).nodes)
    assert any(n.touched for n in build_graph(scope, with_touched=True).nodes)
    assert b"changed role support-audit" in build_html(scope)  # the page asks


# ---- one idea of reading a secret

def test_the_graph_and_the_sequence_share_one_idea_of_reading_a_secret(fixtures):
    assert not hasattr(story, "_SECRET_KINDS") and not hasattr(facts, "_SECRET_KINDS") and SECRET_KINDS == ("secret", "parameter", "parameter path")
    scope = scope_of(fixtures, "06_lambda")
    marked = {s.event.event_id for s in scope.events if reads_secret(s.event)}
    moments = story._raw(scope, Timeline.model_validate(build_timeline(scope)))
    assert marked and {e for m in moments if m.kind == "secrets" for e in m.event_ids} == marked


# ---- the zoom of the graph

def test_the_graph_zoom_never_uses_a_width_measured_earlier():
    assert "function fit()" in JS and "getBoundingClientRect().width, z = 1" not in JS and "fit = svg" not in JS


# ---- plan steps name an identity by what the operation says

def actor(label: str, keys=()) -> Actor:
    return Actor.model_construct(label=label, access_keys=list(keys), arn=None)


def step(sid: str, op: str, **args: str) -> PlanAction:
    return PlanAction.model_construct(id=sid, operations=[Operation(op=op, args=args, region=None)])


def test_a_user_and_a_role_session_with_the_same_name_are_not_taken_for_each_other():
    plan = Plan.model_construct(actions=[step("A01", "delete_login_profile", user="maint")])
    actors = [actor("assumed-role/ops-admin/maint"), actor("user/maint")]
    assert steps_by_actor(plan, actors) == {"A01": ["user/maint"]}


def test_each_kind_of_argument_names_its_own_kind_of_identity():
    actors = [actor("user/jenkins", ["AKIAIOSFODNN7EXAMPLE"]), actor("assumed-role/ops-admin/maint"), actor("assumed-role/app-role/i-0a1b2c3d4e5f60718"),
              actor("assumed-role/lambda-exec/exfil-fn")]
    plan = Plan.model_construct(actions=[
        step("A01", "x", key="AKIAIOSFODNN7EXAMPLE"), step("A02", "x", role="ops-admin"), step("A03", "x", instance="i-0a1b2c3d4e5f60718"),
        step("A04", "x", function="exfil-fn"), step("A05", "x", role="maint"), step("A06", "x", policy_arn="arn:aws:iam::aws:policy/ReadOnlyAccess")])
    assert steps_by_actor(plan, actors) == {"A01": ["user/jenkins"], "A02": ["assumed-role/ops-admin/maint"], "A03": ["assumed-role/app-role/i-0a1b2c3d4e5f60718"],
                                            "A04": ["assumed-role/lambda-exec/exfil-fn"]}  # a role named like a session name, and a policy, name no identity


# ---- only drawn identities are lit

def test_a_step_lights_only_the_identities_the_graph_draws_and_still_links_the_others(fixtures):
    scope = scope_of(fixtures, "02_role_chain")
    a = next(x for x in Plan.model_validate(build_plan(scope)).actions if x.id == "A03")
    both = {"assumed-role/ops-admin/maint": "identity-1", "user/not-drawn": "identity-9"}
    out = _step(a, scope, both, {"assumed-role/ops-admin/maint"})
    assert 'data-nodes="identity-1"' in out and "identity-9" not in out.split("data-nodes=")[1].split(">")[0]
    assert out.count("(in the picture above)") == 1 and 'href="#identity-9"' in out  # the other one keeps its link to its details
    none = _step(a, scope, both, set())
    assert "data-nodes" not in none and "(in the picture above)" not in none and 'href="#identity-1"' in none


def test_the_page_never_lights_an_identity_that_is_not_there(fixtures):
    for name in ("02_role_chain", "03_instance_role", "06_lambda", "04_log_tampering"):
        page = build_html(scope_of(fixtures, name)).decode()
        nodes = set(re.findall(r'<g class="node[^"]*"[^>]* data-node="([^"]+)"', page))
        for ids in re.findall(r'data-nodes="([^"]+)"', page):
            assert set(ids.split()) <= nodes, name
