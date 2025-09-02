"""
Deterministic JSON canonicalization (RFC 8785) implementation.

This module provides functions to convert Python objects to canonical JSON format
suitable for cryptographic operations where byte-for-byte consistency is required.
"""

import json
import math
import re
from decimal import Decimal
from typing import Any, Dict, List, Union, cast

from pydantic import BaseModel, AnyHttpUrl


class CanonicalizationError(ValueError):
    """Raised when canonicalization fails due to invalid input."""

    pass


def _is_finite_number(value: float) -> bool:
    """Check if a number is finite and not NaN or infinite."""
    return not (math.isnan(value) or math.isinf(value))


def _canonicalize_value(value: Any) -> str:
    """Recursively convert a Python value to its canonical JSON string representation."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        if not _is_finite_number(value):
            raise CanonicalizationError(f"Non-finite number: {value}")
        # Handle integers and floats in a way that preserves precision
        if isinstance(value, int) or value.is_integer():
            return str(int(value))
        # Use Decimal for precise floating-point representation
        return format(Decimal(str(value)).normalize(), "f").rstrip("0").rstrip(".")
    if isinstance(value, str):
        # Escape special characters and wrap in quotes
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        items = [_canonicalize_value(item) for item in value]
        return f"[{','.join(items)}]"
    if isinstance(value, dict):
        return _canonicalize_object(value)
    if isinstance(value, BaseModel):
        return _canonicalize_object(value.dict(by_alias=True, exclude_unset=True))
    if isinstance(value, AnyHttpUrl):
        return json.dumps(str(value))
    if hasattr(value, 'isoformat'):
        # Handle datetime objects
        return json.dumps(value.isoformat())
    
    raise CanonicalizationError(f"Unsupported type for canonicalization: {type(value)}")


def _canonicalize_object(obj: Dict[str, Any]) -> str:
    """Convert a dictionary to a canonical JSON object string."""
    if not isinstance(obj, dict):
        raise CanonicalizationError(f"Expected dict, got {type(obj).__name__}")
    
    # Sort keys by Unicode code point order
    items = []
    for key, value in sorted(obj.items(), key=lambda x: x[0]):
        if not isinstance(key, str):
            raise CanonicalizationError(f"Dictionary keys must be strings, got {type(key).__name__}")
        items.append(f"{json.dumps(key)}:{_canonicalize_value(value)}")
    
    return "{" + ",".join(items) + "}"


def canonicalize(data: Any) -> bytes:
    """
    Convert a Python object to canonical JSON bytes.
    
    Args:
        data: The Python object to canonicalize (dict, list, or primitive)
        
    Returns:
        bytes: The canonical JSON representation as UTF-8 bytes
        
    Raises:
        CanonicalizationError: If the input cannot be canonicalized
    """
    try:
        return _canonicalize_value(data).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise CanonicalizationError(f"Failed to canonicalize data: {e}") from e


def canonical_json_dumps(data: Any, **kwargs) -> str:
    """
    Convert a Python object to a canonical JSON string.
    
    This is a convenience wrapper around canonicalize() that returns a string.
    """
    return canonicalize(data).decode("utf-8")


def verify_canonical_equivalence(a: Any, b: Any) -> bool:
    """
    Check if two Python objects have equivalent canonical JSON representations.
    
    This is useful for testing and verification purposes.
    """
    return canonicalize(a) == canonicalize(b)
