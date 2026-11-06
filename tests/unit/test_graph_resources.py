"""What each identity touched, drawn on the graph; and the account that was reached without logs."""
import pytest

from controlzee.diagrams import _mid, _short, attack_svg, touch_text
from controlzee.facts import MAX_TOUCHED, Touch, touched_by_actor
from controlzee.html_report import build_html
from controlzee.visual import Graph, Node, build_graph
from tests.unit.test_captured import load
from tests.unit.test_html_report import _hostile_scope, audit, check_inert
from tests.unit.test_respond import scope_of


def touch(kind="role", access="write", count=1, names=("x",), flag="") -> Touch:
    return Touch(kind, access, count, names, flag)


def graph(*nodes: Node, edges=((0, 1, "AssumeRole"),), ghosts=()) -> Graph:
    return Graph(nodes=list(nodes), edges=list(edges), unused=[], hidden=0, ghosts=tuple(ghosts))


def test_each_identity_lists_what_it_changed_and_role_assumptions_are_left_to_the_arrows(fixtures):
    got = touched_by_actor(scope_of(fixtures, "02_role_chain"))
    assert [(t.kind, t.access, t.names) for t in got["assumed-role/ops-admin/maint"]] == [
        ("policy", "write", ("arn:aws:iam::aws:policy/ReadOnlyAccess",)), ("role", "write", ("support-audit",))]
    assert "user/jenkins" not in got  # it only assumed roles and made read calls without a named resource


def test_full_control_and_secrets_read_are_flagged_and_listed_first(fixtures):
    admin = touched_by_actor(scope_of(fixtures, "01_leaked_key"))["user/ci-deploy"]
    assert [(t.kind, t.flag) for t in admin] == [("user", "admin"), ("policy", "")]
    secret = touched_by_actor(scope_of(fixtures, "03_instance_role"))["assumed-role/app-role/i-0a1b2c3d4e5f60718"]
    assert [(t.kind, t.access, t.flag) for t in secret] == [("secret", "read", "secret")]


def test_a_failed_call_is_not_something_the_identity_touched(fixtures):
    from controlzee.model.scope import Scope
    scope = scope_of(fixtures, "01_leaked_key")
    failed = [s for s in scope.events if s.event.error_code]
    assert not failed or all(t.count for v in touched_by_actor(scope).values() for t in v)
    assert isinstance(scope, Scope)


def test_the_chips_are_drawn_inside_the_identity_and_mark_what_needs_attention(fixtures):
    page = build_html(scope_of(fixtures, "01_leaked_key")).decode()
    assert page.count('<g class="rc hot">') == 1 and "▲ changed user backdoor-svc" in page
    assert "changed policy AdministratorAccess" in page  # the ARN by its last part; the tooltip has the rest


def test_a_graph_with_one_identity_and_nothing_issued_has_no_chips_at_all(fixtures):
    for name in ("04_log_tampering",):
        page = build_html(scope_of(fixtures, name)).decode()
        assert 'class="graph"' not in page and 'class="rc' not in page
    ssm = build_html(load("ssm-retrieve-securestring-parameters")[0]).decode()
    assert 'class="graph"' not in ssm  # 126 resources, one identity: the Exposure table is the place for them


def test_an_identity_with_nothing_touched_has_no_chip_block(fixtures):
    svg = attack_svg(graph(Node("user/a", 3, True), Node("user/b", 1, False, (touch(),))), {})
    assert svg.count('<g class="rc') == 1 and "more kinds" not in svg


def test_at_most_four_kinds_are_drawn_and_the_rest_counted():
    many = tuple(touch(kind=f"kind{n}", names=(f"n{n}",)) for n in range(MAX_TOUCHED + 3))
    svg = attack_svg(graph(Node("user/a", 3, True, many), Node("user/b", 1, False)), {})
    assert svg.count('<g class="rc') == MAX_TOUCHED and "+3 more kinds of resource" in svg
    assert "kind6" in svg  # the tooltip still names every one


def test_a_kind_with_many_resources_is_a_count_not_a_list():
    assert touch_text(touch(kind="secret", access="read", count=40, names=("a", "b"), flag="secret")) == "★ read secret ×40"
    assert touch_text(touch(count=2, names=("a", "b"))) == "changed role a, b"


@pytest.mark.parametrize(("arn", "short"), [("arn:aws:iam::aws:policy/ReadOnlyAccess", "ReadOnlyAccess"),
                                            ("arn:aws:lambda:us-east-1:111122223333:function:billing-report:$LATEST", "billing-report"),
                                            ("prod/db", "prod/db"), ("arn:broken", "arn:broken")])
def test_an_arn_is_shown_by_its_last_part(arn, short):
    assert _short(arn) == short


def test_an_account_reached_without_logs_is_drawn_so_the_chain_does_not_seem_to_end(fixtures):
    scope = scope_of(fixtures, "02_role_chain")
    assert [g[1] for g in build_graph(scope).ghosts] == ["account 444455556666"]
    page = build_html(scope).decode()
    assert 'class="node ghost"' in page and "reached, but no logs: unknown" in page and "1 account reached without logs" in page
    assert 'class="node ghost"' not in build_html(scope_of(fixtures, "01_leaked_key")).decode()


def test_the_picture_says_in_its_label_what_it_holds():
    svg = attack_svg(graph(Node("user/a", 3, True, (touch(),)), Node("user/b", 1, False, (touch(), touch(kind="secret")))), {})
    assert 'aria-label="How the attacker moved: 2 identities, 3 kinds of resource touched"' in svg and 'role="img"' in svg


HOSTILE = ['"><script>alert(1)</script>', "' onmouseover='alert(1)", "<img src=x onerror=alert(1)>", "A" * 5000]


@pytest.mark.parametrize("evil", HOSTILE)
def test_hostile_resource_and_account_names_are_inert(evil):
    nodes = (Node(evil, 3, True, (touch(kind=evil, names=(evil, evil), count=2, flag="admin"),)), Node("user/b", 1, False))
    svg = attack_svg(graph(*nodes, ghosts=((0, f"account {evil}", "AssumeRole"),)), {evil: "identity-0"})
    parsed = audit(svg.encode())  # what the browser would make of it: only our own tags, and no attribute that runs anything
    assert set(parsed.tags) <= {"svg", "defs", "marker", "path", "rect", "text", "g", "title"}
    assert not [k for _t, k, _v in parsed.attrs if k.startswith("on") or k == "style"]
    assert len(svg) < 20_000  # long text is cut, not copied whole


def test_the_whole_page_stays_inert_with_hostile_names_on_the_graph(tmp_path):
    page = build_html(_hostile_scope(tmp_path))
    check_inert(page)  # no extra tag, attribute, style or script
    assert b'class="rc' in page


def test_the_graph_is_the_same_bytes_every_time(fixtures):
    scope = scope_of(fixtures, "02_role_chain")
    assert build_html(scope) == build_html(scope)


def test_a_long_name_is_cut_from_the_middle_so_similar_names_stay_apart():
    a, b = _mid("changed bucket stratus-red-team-olc-2f39ab", 30), _mid("changed bucket stratus-red-team-olc-77cd01", 30)
    assert len(a) == 30 and a != b and a.endswith("2f39ab") and a.startswith("changed bucket")
    assert _mid("short", 30) == "short"
