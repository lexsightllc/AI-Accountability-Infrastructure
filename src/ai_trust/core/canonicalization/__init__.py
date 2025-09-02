"""
Deterministic JSON canonicalization (minimal JCS-compatible subset).

This module provides byte-stable serialization for signing and verification.
It follows RFC 8785 principles: sorted object keys by code point, UTF-8 without BOM,
lowercase booleans, null literal, arrays preserve order, no NaN/Infinity, and
a deterministic rendering of numbers. For floats we use the shortest round-trippable
decimal via Python's repr which is IEEE-754 aware on CPython 3.11+. If your threat
model requires strict RFC 8785 number formatting, replace _render_number accordingly.
"""
from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

def _render_number(x: int | float | Decimal) -> str:
    if isinstance(x, bool):
        return "true" if x else "false"
    if isinstance(x, int):
        return str(x)
    if isinstance(x, Decimal):
        if not x.is_finite():
            raise ValueError("Non-finite Decimal not allowed")
        s = format(x, 'f').rstrip('0').rstrip('.')
        return s if s else "0"
    if isinstance(x, float):
        if math.isnan(x) or math.isinf(x):
            raise ValueError("NaN/Infinity not allowed")
        # Python 3.11+ float repr is shortest-roundtrip; remove trailing .0 for integers
        s = repr(x)
        if 'e' in s or 'E' in s:
            # normalize exponent to uppercase E and strip + and leading zeros
            mantissa, exp = s.lower().split('e')
            sign = '-' if exp.startswith('-') else ''
            exp_digits = exp.lstrip('+-').lstrip('0') or '0'
            return f"{mantissa}E{sign}{exp_digits}"
        if s.endswith('.0'):
            return s[:-2]
        return s
    raise TypeError(f"Unsupported number type: {type(x)}")

def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, Decimal)):
        return _render_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if isinstance(value, list):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(json.dumps(k, ensure_ascii=False, separators=(',', ':')) + ":" + _canon(v)
                              for k, v in items) + "}"
    raise TypeError(f"Unsupported type in canonicalization: {type(value)}")

def canonical_json_dumps(obj: Any) -> str:
    return _canon(obj)

def canonicalize(obj: Any) -> bytes:
    return canonical_json_dumps(obj).encode('utf-8')

class CanonicalizationError(Exception):
    pass

def verify_canonical_equivalence(a: Any, b: Any) -> bool:
    """
    Check if two Python objects have equivalent canonical JSON representations.
    
    This is useful for testing and verification purposes.
    """
    try:
        return canonicalize(a) == canonicalize(b)
    except Exception:
        return False
