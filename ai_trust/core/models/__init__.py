"""Core data models for AI Trust receipts and related structures."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    Field,
    HttpUrl,
    field_validator,
    StringConstraints,
)
from typing_extensions import Annotated

# Type aliases
ExecutionID = Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9._-]{8,128}$')]
KeyID = str
Algorithm = Literal["EdDSA", "RS256", "ES256"]
HashAlgorithm = Literal["SHA-256"]


class ReceiptVersion(str, Enum):
    """Supported receipt versions."""
    V1 = "1.0"


class ModelInfo(BaseModel):
    """Information about the AI model that generated the output."""
    name: str = Field(
        ...,
        description="Name of the AI model (e.g., 'gpt-4', 'claude-2')."
    )
    version: Optional[str] = Field(
        None,
        description="Version identifier for the model."
    )
    commit_sha256: Optional[Annotated[str, StringConstraints(pattern=r'^[a-f0-9]{64}$')]] = Field(
        None,
        description="SHA-256 hash of the model's source code or weights commit."
    )
    parameters: Optional[Dict[str, Any]] = Field(
        None,
        description="Key parameters used during model inference."
    )


class Signature(BaseModel):
    """Cryptographic signature of the receipt."""
    alg: Algorithm = Field(
        ...,
        description="Signature algorithm used."
    )
    kid: KeyID = Field(
        ...,
        description="Key identifier for the public key that can verify this signature."
    )
    sig: Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]+$')] = Field(
        ...,
        description="Base64url-encoded signature without padding."
    )
    issued_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the signature was created (RFC 3339)."
    )


class InputCommitment(BaseModel):
    """Commitment to input data for privacy preservation."""
    hmac: Annotated[str, StringConstraints(pattern=r'^[a-f0-9]{64}$')] = Field(
        ...,
        description="HMAC-SHA256 of the input data."
    )
    salt_id: str = Field(
        ...,
        description="Identifier for the salt used in the HMAC calculation."
    )
    algorithm: HashAlgorithm = Field(
        "SHA-256",
        description="Hash algorithm used for the HMAC."
    )


class OutputCommitment(BaseModel):
    """Commitment to the model's output."""
    body_sha256: Annotated[str, StringConstraints(pattern=r'^[a-f0-9]{64}$')] = Field(
        ...,
        description="SHA-256 hash of the response body (after decoding any content encoding)."
    )
    content_type: Optional[str] = Field(
        None,
        description="MIME type of the response body."
    )


class LogEntry(BaseModel):
    """Reference to a transparency log entry."""
    log_id: str = Field(
        ...,
        description="Unique identifier for the log."
    )
    leaf_index: int = Field(
        ...,
        ge=0,
        description="Index of the leaf in the Merkle tree."
    )
    inclusion_proof: List[str] = Field(
        ...,
        min_items=1,
        description="Merkle audit path from the leaf to the root."
    )
    tree_size: int = Field(
        ...,
        ge=1,
        description="Size of the tree when this entry was included."
    )
    timestamp: datetime = Field(
        ...,
        description="When the entry was added to the log."
    )


class WitnessSignature(BaseModel):
    """Witness signature of a log's signed tree head."""
    log_id: str = Field(
        ...,
        description="ID of the log being witnessed."
    )
    witness_id: str = Field(
        ...,
        description="ID of the witness providing the signature."
    )
    signature: Annotated[str, StringConstraints(pattern=r'^[A-Za-z0-9_-]+$')] = Field(
        ...,
        description="Base64url-encoded Ed25519 signature without padding."
    )
    timestamp: datetime = Field(
        ...,
        description="When the signature was created."
    )


class Receipt(BaseModel):
    """Core receipt structure containing all verifiable claims."""
    # Required fields
    receipt_version: ReceiptVersion = Field(
        ReceiptVersion.V1,
        description="Version of the receipt schema."
    )
    execution_id: ExecutionID = Field(
        ...,
        description="Unique identifier for this execution."
    )
    issued_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the receipt was issued (RFC 3339)."
    )
    issuer: AnyHttpUrl = Field(
        ...,
        description="Base URL of the issuing service's well-known endpoint."
    )
    model: ModelInfo = Field(
        ...,
        description="Information about the AI model used."
    )
    output: OutputCommitment = Field(
        ...,
        description="Commitment to the model's output."
    )
    signature: Optional[Signature] = Field(
        None,
        description="Signature over the receipt contents."
    )
    
    # Optional fields
    inputs: Optional[List[InputCommitment]] = Field(
        None,
        description="Commitments to input data."
    )
    log_entries: Optional[List[LogEntry]] = Field(
        None,
        description="Transparency log entries for this receipt."
    )
    witness_signatures: Optional[List[WitnessSignature]] = Field(
        None,
        description="Witness signatures for log entries."
    )
    policy: Optional[Dict[str, Any]] = Field(
        None,
        description="Policy applied to this execution."
    )
    extensions: Optional[Dict[str, Any]] = Field(
        None,
        description="Extension fields for forward compatibility."
    )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + 'Z'
        }
    
    @field_validator('issuer')
    @classmethod
    def validate_issuer_url(cls, v):
        """Ensure the issuer URL is well-formed and uses HTTPS."""
        url_str = str(v)
        if not url_str.startswith('https://'):
            raise ValueError('Issuer URL must use HTTPS')
        # Remove trailing slash for consistency
        if url_str.endswith('/'):
            return AnyHttpUrl(url_str.rstrip('/'))
        return v
