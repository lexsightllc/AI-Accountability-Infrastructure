"""
AI Accountability Transparency Log

This package provides an append-only transparency log for AI accountability receipts,
including Merkle tree-based verification and a REST API for interaction.
"""

__version__ = "1.0.0"

from .server import create_app, TransparencyLog, LogEntry, InclusionProof

__all__ = ["create_app", "TransparencyLog", "LogEntry", "InclusionProof"]
