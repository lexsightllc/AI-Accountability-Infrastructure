"""
API module for the AI Accountability Infrastructure.

This package provides the REST API endpoints for interacting with the
AI Accountability system, including endpoints for managing logs, generating
proofs, and verifying data integrity.
"""

from fastapi import APIRouter

router = APIRouter()

__all__ = ['router']
