"""
AI Trust - Cryptographic receipts for AI accountability.

This package provides tools for creating, signing, and verifying cryptographic receipts
for AI model outputs, enabling transparency and accountability in AI systems.
"""

from importlib.metadata import version

# Set up version
__version__ = "0.1.0"

try:
    __version__ = version("ai-trust")
except Exception:
    pass

# Core components
from ai_trust.core.canonicalization import (
    canonicalize,
    canonical_json_dumps,
    verify_canonical_equivalence,
)
from ai_trust.core.crypto import KeyPair, KeyStore, sign_receipt, verify_receipt, hash_sha256, compute_hmac_sha256
from ai_trust.core.models import (
    ExecutionID,
    InputCommitment,
    LogEntry,
    ModelInfo,
    OutputCommitment,
    Receipt,
    ReceiptVersion,
    Signature,
    WitnessSignature,
)

__all__ = [
    # Core functionality
    "canonicalize",
    "canonical_json_dumps",
    "verify_canonical_equivalence",
    "KeyPair",
    "KeyStore",
    "generate_keypair",
    "sign_receipt",
    "verify_receipt",
    # Models
    "ExecutionID",
    "InputCommitment",
    "LogEntry",
    "ModelInfo",
    "OutputCommitment",
    "Receipt",
    "ReceiptVersion",
    "Signature",
    "WitnessSignature",
]
