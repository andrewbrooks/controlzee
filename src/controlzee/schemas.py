"""JSON Schemas for the files controlzee writes. Committed under schemas/ and checked for drift by the tests."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from controlzee import canonical
from controlzee.model.common import SCHEMA_VERSION
from controlzee.model.plan import Plan
from controlzee.model.respond import DryRun, ResponseRecord
from controlzee.model.scope import InputsManifest, Scope
from controlzee.model.timeline import Timeline

SCHEMAS: dict[str, type[BaseModel]] = {"scope": Scope, "inputs": InputsManifest, "timeline": Timeline, "plan": Plan, "dryrun": DryRun, "response": ResponseRecord}


def schema_for(name: str) -> dict[str, Any]:
    schema: dict[str, Any] = SCHEMAS[name].model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://controlzee.invalid/schemas/{name}-{SCHEMA_VERSION}.json"
    return schema


def schema_bytes(name: str) -> bytes:
    return canonical.dumps(schema_for(name))


def write_all(directory: Path) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in sorted(SCHEMAS):
        path = directory / f"{name}.schema.json"
        path.write_bytes(schema_bytes(name))
        paths.append(path)
    return paths


if __name__ == "__main__":  # uv run python -m controlzee.schemas [directory]
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("schemas")
    for p in write_all(target):
        print(f"wrote {p}")
