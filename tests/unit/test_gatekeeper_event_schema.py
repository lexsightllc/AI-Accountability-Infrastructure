import json
from pathlib import Path

import jsonschema
import pytest

SCHEMA_PATH = Path("schemas/gatekeeper.event.v1.json")


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_valid_event_passes_schema_validation():
    schema = load_json(SCHEMA_PATH)
    event = load_json("tests/data/events/valid_event.json")
    jsonschema.validate(instance=event, schema=schema)


def test_invalid_event_fails_schema_validation():
    schema = load_json(SCHEMA_PATH)
    bad_event = load_json("tests/data/events/invalid_event.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=bad_event, schema=schema)

