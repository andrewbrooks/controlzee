"""A command laid out over lines must run exactly as the command it came from."""
import json
import re
import subprocess
from pathlib import Path

import pytest

from controlzee.plan import build_plan
from controlzee.shellwrap import LONG, collapse, wrap
from tests.unit.test_captured import CAPTURED
from tests.unit.test_html_report import SCENARIOS
from tests.unit.test_respond import scope_of

REVOKE = ('aws iam put-role-policy --role-name ops-admin --policy-name controlzee-revoke-older-sessions --policy-document '
          '\'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":'
          '{"aws:TokenIssueTime":"\'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"\'"}}}]}\'')


def argv(command: str) -> list[object]:
    """The arguments the shell hands to the program, found by really running the shell with the program stubbed out. Nothing but a
    stub runs: `aws`, `controlzee` and `date` are functions here, and a JSON argument is compared as JSON, not as text."""
    script = "aws() { printf '%s\\0' \"$@\"; }; controlzee() { aws \"$@\"; }; date() { echo NOW; }\n" + command
    out = subprocess.run(["bash", "-c", script], capture_output=True, check=True).stdout.decode().split("\0")[:-1]

    def norm(a: str) -> object:
        try:
            return json.loads(a) if a[:1] in "{[" else a
        except ValueError:
            return a
    return [norm(a) for a in out]


def all_commands() -> list[str]:
    cmds: list[str] = []
    for r in sorted(CAPTURED.iterdir()):
        from tests.unit.test_captured import load
        cmds += [c for a in build_plan(load(r.name)[0])["actions"] for c in a["commands"]]
    return sorted(set(cmds))


def test_a_short_command_is_left_as_it_is():
    assert wrap("aws iam list-users") == "aws iam list-users" and len("aws iam update-access-key --user-name a") < LONG


def test_a_long_command_gets_one_flag_to_a_line():
    cmd = "aws iam update-access-key --user-name backdoor-svc --access-key-id AKIAIOSFODNN7BKDOOR --status Inactive"
    assert wrap(cmd) == "aws iam update-access-key \\\n  --user-name backdoor-svc \\\n  --access-key-id AKIAIOSFODNN7BKDOOR \\\n  --status Inactive"


def test_the_json_policy_is_indented_and_the_date_it_carries_is_still_computed_by_the_shell():
    out = wrap(REVOKE)
    assert "\n  --policy-document '{\n  \"Version\": \"2012-10-17\"," in out
    assert "'\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"'" in out  # the expansion is exactly as written, between two single-quoted parts
    assert argv(out) == argv(REVOKE)
    assert out.count("\\\n") == 3


@pytest.mark.parametrize("cmd", [
    "aws s3 ls --bucket $BUCKET --region us-east-1 --profile incident --output json --query something",  # a variable
    "aws iam list-users --output json --query 'Users[].UserName' --region us-east-1 --profile incident | head",  # a pipe
    "aws s3 ls --bucket logs-* --region us-east-1 --profile incident --output json --query something",  # a glob
    "aws iam get-user --user-name a\\ b --region us-east-1 --profile incident --output json --query x",  # a backslash
    "aws iam get-user --user-name \"$(whoami)\" --region us-east-1 --profile incident --output json --query x",  # an expansion, not in JSON
    "aws iam get-user --user-name 'unterminated --region us-east-1 --profile incident --output json --query x",  # broken quoting
])
def test_anything_the_shell_would_treat_specially_is_left_exactly_as_it_came(cmd):
    assert wrap(cmd) == cmd


def test_collapsing_the_continuations_gives_back_the_words():
    cmd = "aws iam update-access-key --user-name backdoor-svc --access-key-id AKIAIOSFODNN7BKDOOR --status Inactive"
    assert collapse(wrap(cmd)) == "aws iam update-access-key   --user-name backdoor-svc   --access-key-id AKIAIOSFODNN7BKDOOR   --status Inactive"


def test_every_command_of_every_plan_runs_exactly_as_it_did_before_being_laid_out():
    commands = all_commands()
    assert len(commands) > 40 and any(c != wrap(c) for c in commands)  # there is something to check, and some of it was laid out
    for c in commands:
        assert argv(wrap(c)) == argv(c), c


def test_the_fixture_plans_too(fixtures):
    for name in SCENARIOS:
        for a in build_plan(scope_of(fixtures, name))["actions"]:
            for c in a["commands"]:
                assert argv(wrap(c)) == argv(c), c


def test_no_wrapped_line_outside_a_json_argument_is_longer_than_the_page_can_show():
    for c in all_commands():
        for line in wrap(c).split("\n"):
            assert len(line) < 160 or "arn:" in line, line  # a very long ARN is the one thing that cannot be cut


def test_the_script_never_runs_anything_but_the_stubs():
    assert re.search(r"date\(\) \{ echo NOW", Path(__file__).read_text())
