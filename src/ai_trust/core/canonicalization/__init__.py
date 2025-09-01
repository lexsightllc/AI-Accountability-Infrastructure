"""Canonicalization of data for consistent hashing and signing."""
import json
import unicodedata
from typing import Any


def canonicalize(data: Any) -> str:
    """Convert data to a canonical JSON string with NFC normalization.

    Args:
        data: The data to canonicalize (must be JSON-serializable)

    Returns:
        str: Canonical JSON string with NFC normalization
    """

    def _canonicalize_value(value: Any) -> Any:
        if isinstance(value, str):
            return unicodedata.normalize("NFC", value)
        if isinstance(value, dict):
            return {k: _canonicalize_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [_canonicalize_value(v) for v in value]
        return value

    canonical_data = _canonicalize_value(data)
    return json.dumps(
        canonical_data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
