"""
AI Trust Command Line Interface.

This package provides command-line tools for managing AI accountability receipts,
including creating, signing, verifying receipts, and interacting with transparency logs.
"""

__version__ = "0.1.0"

# Import the main CLI entry point
from .main import cli

# Re-export for easier imports
__all__ = [
    'cli',
]
