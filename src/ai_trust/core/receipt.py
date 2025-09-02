"""
Enhanced Receipt model with validation, serialization, and helper methods.
"""

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from pydantic import BaseModel, Field, field_validator, model_validator

from ai_trust.core.canonicalization import canonicalize
from ai_trust.core.crypto import KeyPair, hash_sha256
from ai_trust.core.models import (
    ExecutionID,
    InputCommitment,
    LogEntry,
    ModelInfo,
    OutputCommitment,
    Receipt as BaseReceipt,
    ReceiptVersion,
    Signature,
    WitnessSignature,
)


class Receipt(BaseReceipt):
    """Enhanced Receipt model with additional validation and helper methods."""

    @field_validator('execution_id')
    @classmethod
    def validate_execution_id(cls, v: str) -> str:
        """Validate execution ID format."""
        if not v or len(v) < 8 or len(v) > 128:
            raise ValueError('execution_id must be between 8 and 128 characters')
        if not all(c.isalnum() or c in '._-' for c in v):
            raise ValueError('execution_id can only contain alphanumerics, ., _, and -')
        return v

    @field_validator('issued_at')
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        """Ensure datetime is timezone-aware and in UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @model_validator(mode='after')
    def validate_receipt(self) -> 'Receipt':
        """Cross-field validation."""
        # Validate signature if present
        if self.signature and self.signature.alg != 'EdDSA':
            raise ValueError('Only EdDSA signatures are supported')
        
        # Ensure issued_at is timezone-aware
        if self.issued_at.tzinfo is None:
            self.issued_at = self.issued_at.replace(tzinfo=timezone.utc)
            
        # Validate timestamps
        now = datetime.now(timezone.utc)
        if self.issued_at > now:
            raise ValueError('issued_at cannot be in the future')
            
        return self
    
    def to_canonical_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary in a canonical form for signing."""
        # Create a dict with only the fields that should be signed
        data = {
            'receipt_version': self.receipt_version,
            'execution_id': self.execution_id,
            'issued_at': self.issued_at.isoformat().replace('+00:00', 'Z'),
            'issuer': str(self.issuer),
            'model': {
                'name': self.model.name,
                'version': self.model.version,
                'commit_sha256': self.model.commit_sha256,
                'parameters': self.model.parameters or {},
            },
            'output': {
                'body_sha256': self.output.body_sha256,
                'content_type': self.output.content_type or '',
            },
        }
        
        # Add optional fields if present
        if self.inputs:
            data['inputs'] = [
                {
                    'hmac': i.hmac,
                    'salt_id': i.salt_id,
                    'algorithm': i.algorithm,
                }
                for i in self.inputs
            ]
            
        if self.policy:
            data['policy'] = self.policy
            
        if self.extensions:
            data['extensions'] = self.extensions
            
        return data
    
    def to_canonical_json(self) -> bytes:
        """Convert to canonical JSON bytes for signing."""
        return canonicalize(self.to_canonical_dict())
    
    def compute_digest(self) -> str:
        """Compute the SHA-256 digest of the canonical JSON."""
        return hash_sha256(self.to_canonical_json())
    
    def sign(self, key_pair: KeyPair) -> 'Receipt':
        """Sign the receipt with the provided key pair."""
        if not key_pair.private_key_obj:
            raise ValueError('Private key is required for signing')
            
        # Create signature
        sig = key_pair.sign(self.to_canonical_json())
        
        # Update receipt with signature
        self.signature = Signature(
            alg='EdDSA',
            kid=key_pair.kid,
            sig=key_pair.encode_signature(sig),
            issued_at=datetime.now(timezone.utc)
        )
        
        return self
    
    def verify_signature(self, public_key: bytes) -> bool:
        """Verify the receipt's signature."""
        if not self.signature:
            return False
            
        try:
            # Create a public key object from the raw bytes
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            
            # Get the signature bytes from base64url
            signature_bytes = base64.urlsafe_b64decode(self.signature.sig + '===')
            
            # Add domain separation
            context = b"AI-Receipt-v0\n"
            message = context + self.to_canonical_json()
            
            # Verify the signature
            public_key_obj.verify(signature_bytes, message)
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}", file=sys.stderr)
            return False
    
    def add_log_entry(self, log_id: str, leaf_index: int, tree_size: int, root_hash: str, witness_id: str) -> 'Receipt':
        """Add a log entry to the receipt.
        
        Args:
            log_id: ID of the log where this entry is stored
            leaf_index: Index of the entry in the log's Merkle tree
            tree_size: Total number of entries in the log when this entry was added
            root_hash: Hex-encoded root hash of the Merkle tree
            witness_id: ID of the witness providing the signature
            
        Returns:
            The updated receipt with the new log entry
        """
        if not self.log_entries:
            self.log_entries = []
            
        self.log_entries.append(LogEntry(
            log_id=log_id,
            leaf_index=leaf_index,
            tree_size=tree_size,
            root_hash=root_hash,
            witness_id=witness_id,
            timestamp=datetime.now(timezone.utc)
        ))
        
        return self
    
    def add_witness_signature(self, log_id: str, witness_id: str, signature: str) -> 'Receipt':
        """Add a witness signature to the receipt."""
        if not self.witness_signatures:
            self.witness_signatures = []
            
        self.witness_signatures.append(WitnessSignature(
            log_id=log_id,
            witness_id=witness_id,
            signature=signature,
            timestamp=datetime.now(timezone.utc)
        ))
        
        return self
    
    @classmethod
    def create(
        cls,
        execution_id: str,
        issuer: str,
        model_name: str,
        body_sha256: str,
        content_type: Optional[str] = None,
        model_version: Optional[str] = None,
        model_commit: Optional[str] = None,
        model_params: Optional[Dict[str, Any]] = None,
        inputs: Optional[List[Dict[str, str]]] = None,
        policy: Optional[Dict[str, Any]] = None,
        extensions: Optional[Dict[str, Any]] = None,
    ) -> 'Receipt':
        """Create a new receipt with the provided information."""
        # Create model info
        model = ModelInfo(
            name=model_name,
            version=model_version,
            commit_sha256=model_commit,
            parameters=model_params or {}
        )
        
        # Create output commitment
        output = OutputCommitment(
            body_sha256=body_sha256,
            content_type=content_type
        )
        
        # Create input commitments if provided
        input_commitments = None
        if inputs:
            input_commitments = [
                InputCommitment(**i) for i in inputs
                if 'hmac' in i and 'salt_id' in i
            ]
        
        return cls(
            receipt_version=ReceiptVersion.V1,
            execution_id=execution_id,
            issuer=issuer,
            model=model,
            output=output,
            inputs=input_commitments,
            policy=policy,
            extensions=extensions
        )
