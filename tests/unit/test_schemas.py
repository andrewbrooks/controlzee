import json
from pathlib import Path

import jsonschema
import pytest

from controlzee.model.scope import InputsManifest
from controlzee.schemas import SCHEMAS, schema_bytes, schema_for
from tests.builders.build_fixtures import SCENARIOS

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_committed_schema_is_current(name):
    committed = SCHEMA_DIR / f"{name}.schema.json"
    assert committed.exists(), "run: uv run python -m controlzee.schemas"
    assert committed.read_bytes() == schema_bytes(name), f"{committed.name} is stale; run: uv run python -m controlzee.schemas"


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_goldens_validate_against_the_schemas(fixtures, scenario):
    expected = fixtures / scenario / "expected"
    for name, file in (("scope", "scope.json"), ("inputs", "scope.inputs.json"), ("timeline", "timeline.json"), ("plan", "plan.json")):
        jsonschema.validate(json.loads((expected / file).read_text()), schema_for(name))


def test_inputs_manifest_model_accepts_what_scope_writes(fixtures):
    InputsManifest.model_validate_json((fixtures / "01_leaked_key/expected/scope.inputs.json").read_bytes())


def test_schemas_reject_a_document_with_the_wrong_shape(fixtures):
    doc = json.loads((fixtures / "01_leaked_key/expected/scope.json").read_text())
    doc["summary"]["events_in_scope"] = "nine"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, schema_for("scope"))
