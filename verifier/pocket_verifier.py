"""
Pocket verifier for AI receipts (v0).

Validates: schema subset, canonical JSON signature with Ed25519, body_sha256 binding.
Log proofs are optional in this minimal build.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

def b64url_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('_', '/')
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s + pad)

def canonical_json(obj: Any) -> bytes:
    def _canon(v):
        if v is None: return "null"
        if v is True: return "true"
        if v is False: return "false"
        if isinstance(v, (int, float)):
            if isinstance(v, float) and (v != v or v in (float('inf'), float('-inf'))):
                raise ValueError("non-finite number")
            s = repr(v)
            if s.endswith('.0'): s = s[:-2]
            return s
        if isinstance(v, str): return json.dumps(v, ensure_ascii=False, separators=(',', ':'))
        if isinstance(v, list): return "[" + ",".join(_canon(x) for x in v) + "]"
        if isinstance(v, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False, separators=(',', ':')) + ":" + _canon(v[k]) for k in sorted(v)) + "}"
        raise TypeError(f"unsupported type {type(v)}")
    return _canon(obj).encode('utf-8')

def verify_signature(receipt: dict, body_bytes: bytes) -> tuple[bool, str]:
    sig_block = receipt.get("signature") or {}
    alg = sig_block.get("alg")
    kid = sig_block.get("kid")
    sig_b64 = sig_block.get("sig")
    if alg != "Ed25519" or not sig_b64 or not kid:
        return False, "signature block missing required fields"
    to_sign = dict(receipt)
    to_sign.pop("signature", None)
    msg = b"AI-Receipt-v0\n" + canonical_json(to_sign)
    sig = b64url_decode(sig_b64)
    # Minimal key resolution for demo: expect debug_public_key_b64url at top-level
    pk_b64 = receipt.get("debug_public_key_b64url")
    if not pk_b64:
        return False, "no key resolution in demo; include debug_public_key_b64url"
    if not HAVE_CRYPTO:
        return False, "cryptography not available"
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64url_decode(pk_b64))
        pk.verify(sig, msg)
    except InvalidSignature:
        return False, "invalid signature"
    return True, "ok"

def verify_body_hash(receipt: dict, body_bytes: bytes) -> tuple[bool, str]:
    out = receipt.get("output") or {}
    h = out.get("body_sha256")
    if not h: return False, "missing output.body_sha256"
    calc = hashlib.sha256(body_bytes).hexdigest()
    if calc != h: return False, f"body hash mismatch: expected {h}, got {calc}"
    return True, "ok"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--receipt", required=True)
    p.add_argument("--body-file", required=True)
    args = p.parse_args()
    rcpt = json.load(open(args.receipt, "r", encoding="utf-8"))
    body = open(args.body_file, "rb").read()
    ok, why = verify_body_hash(rcpt, body)
    if not ok:
        print(json.dumps({"ok": False, "stage": "body_hash", "reason": why}, ensure_ascii=False)); sys.exit(2)
    ok, why = verify_signature(rcpt, body)
    if not ok:
        print(json.dumps({"ok": False, "stage": "signature", "reason": why}, ensure_ascii=False)); sys.exit(3)
    print(json.dumps({"ok": True}, ensure_ascii=False))

if __name__ == "__main__":
    main()
