"""
Cryptographic primitives for AI Trust.

This module provides cryptographic operations for signing, verification, and key management.
"""

import base64
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from pydantic import BaseModel, Field, HttpUrl, field_validator

from ai_trust.core.canonicalization import canonicalize
from ai_trust.core.models import KeyID, Receipt


class KeyPair(BaseModel):
    """A cryptographic key pair with metadata."""
    
    kid: KeyID
    public_key: bytes
    private_key: Optional[bytes] = None
    algorithm: str = "Ed25519"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    metadata: Dict[str, str] = {}

    model_config = {
        "arbitrary_types_allowed": True,
        "json_encoders": {
            datetime: lambda v: v.isoformat() + 'Z',
            bytes: lambda v: v.hex() if v else None
        }
    }
    
    @classmethod
    def generate(cls, kid: str, **kwargs) -> 'KeyPair':
        """Generate a new Ed25519 key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        return cls(
            kid=kid,
            private_key=private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ),
            public_key=public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ),
            **kwargs
        )
    
    @property
    def private_key_obj(self) -> Optional[ed25519.Ed25519PrivateKey]:
        """Get the private key as a cryptography object."""
        if not self.private_key:
            return None
        return ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key)
    
    @property
    def public_key_obj(self) -> ed25519.Ed25519PublicKey:
        """Get the public key as a cryptography object."""
        return ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
    
    def sign(self, data: bytes) -> bytes:
        """Sign data with the private key."""
        if not self.private_key_obj:
            raise ValueError("Private key not available for signing")
        
        # Add domain separation
        context = b"AI-Receipt-v0\n"
        message = context + data
        return self.private_key_obj.sign(message)
    
    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature with the public key."""
        try:
            # Add domain separation
            context = b"AI-Receipt-v0\n"
            message = context + data
            self.public_key_obj.verify(signature, message)
            return True
        except Exception:
            return False
    
    def to_jwk(self, private: bool = False) -> Dict:
        """Convert the key pair to a JWK (JSON Web Key)."""
        jwk = {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "x": base64.urlsafe_b64encode(self.public_key).decode('ascii').rstrip("="),
            "alg": "EdDSA",
            "use": "sig",
            "key_ops": ["verify"],
            "created": int(self.created_at.timestamp()),
        }
        
        if private and self.private_key:
            jwk.update({
                "d": base64.urlsafe_b64encode(self.private_key).decode('ascii').rstrip("="),
                "key_ops": ["sign", "verify"],
            })
        
        if self.not_before:
            jwk["nbf"] = int(self.not_before.timestamp())
        if self.not_after:
            jwk["exp"] = int(self.not_after.timestamp())
        
        return jwk
    
    @classmethod
    def from_jwk(cls, jwk: Dict) -> 'KeyPair':
        """Create a KeyPair from a JWK."""
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise ValueError("Only Ed25519 keys are supported")
        
        # Decode public key
        x = base64.urlsafe_b64decode(jwk["x"] + '==='[:len(jwk["x"]) % 4])
        
        # Decode private key if present
        private_key = None
        if "d" in jwk:
            private_key = base64.urlsafe_b64decode(jwk["d"] + '==='[:len(jwk["d"]) % 4])
        
        # Parse timestamps
        created_at = datetime.fromtimestamp(jwk.get("created", datetime.utcnow().timestamp()), tz=timezone.utc)
        not_before = datetime.fromtimestamp(jwk["nbf"], tz=timezone.utc) if "nbf" in jwk else None
        not_after = datetime.fromtimestamp(jwk["exp"], tz=timezone.utc) if "exp" in jwk else None
        
        return cls(
            kid=jwk["kid"],
            public_key=x,
            private_key=private_key,
            created_at=created_at,
            not_before=not_before,
            not_after=not_after,
        )


def hash_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of data and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def compute_hmac_sha256(key: bytes, data: bytes) -> str:
    """Compute HMAC-SHA256 of data with the given key."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def prepare_receipt_dict(receipt: Receipt) -> dict:
    """Convert a receipt to a dictionary with all fields serialized."""
    # Create a copy of the receipt without the signature
    receipt_dict = receipt.model_dump(exclude={"signature"}, exclude_unset=True, exclude_none=True)
    
    # Function to recursively convert objects to JSON-serializable types
    def convert_to_serializable(obj):
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif hasattr(obj, 'isoformat'):
            # Convert datetime to ISO format string
            return obj.isoformat()
        elif hasattr(obj, '__str__'):
            # Handle URL objects and other string-like objects
            return str(obj)
        elif hasattr(obj, 'model_dump'):
            # Handle Pydantic models
            return convert_to_serializable(obj.model_dump())
        elif hasattr(obj, 'model_dump_json'):
            # Handle Pydantic models with JSON serialization
            return json.loads(obj.model_dump_json())
        elif hasattr(obj, '__dict__'):
            # Handle other objects with __dict__
            return convert_to_serializable(obj.__dict__)
        elif isinstance(obj, dict):
            # Handle dictionaries
            return {str(k): convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple, set)):
            # Handle sequences
            return [convert_to_serializable(v) for v in obj]
        else:
            # Fallback to string representation
            return str(obj)
    
    # Convert all fields to serializable types
    serialized = convert_to_serializable(receipt_dict)
    
    # Ensure we have a clean dictionary with string keys
    if not isinstance(serialized, dict):
        raise ValueError(f"Expected dictionary after serialization, got {type(serialized).__name__}")
    
    return serialized

def prepare_receipt_for_signing(receipt: Receipt) -> bytes:
    """Prepare a receipt for signing by creating a canonical representation."""
    # Get the serialized receipt as a dictionary
    receipt_dict = prepare_receipt_dict(receipt)
    
    # Canonicalize the receipt
    canonical_data = canonicalize(receipt_dict)
    
    return canonical_data

def sign_receipt(receipt: Receipt, key_pair: KeyPair) -> str:
    """Sign a receipt and return the signature as base64url."""
    # Create a dictionary with only the fields we want to sign
    receipt_data = {
        'receipt_version': str(receipt.receipt_version.value),
        'execution_id': receipt.execution_id,
        'issued_at': receipt.issued_at.isoformat(),
        'issuer': str(receipt.issuer),
        'model': {
            'name': receipt.model.name,
            'version': receipt.model.version,
            'commit_sha256': receipt.model.commit_sha256,
        },
        'output': {
            'body_sha256': receipt.output.body_sha256,
            'content_type': receipt.output.content_type,
        }
    }
    
    # Convert to JSON with consistent formatting
    receipt_json = json.dumps(receipt_data, sort_keys=True, separators=(',', ':'))
    
    # Sign the JSON string (KeyPair.sign will add the domain separation prefix)
    signature = key_pair.sign(receipt_json.encode('utf-8'))
    
    # Return base64url-encoded signature without padding
    return base64.urlsafe_b64encode(signature).decode('ascii').rstrip("=")


def verify_receipt(receipt: Receipt, public_key: bytes, debug: bool = False) -> bool:
    """Verify a receipt's signature.
    
    Args:
        receipt: The receipt to verify
        public_key: The public key to use for verification (raw bytes)
        debug: If True, print debug information
        
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    if not receipt.signature or not receipt.signature.sig:
        if debug:
            print("No signature found in receipt", file=sys.stderr)
        return False
    
    try:
        # Get the public key object
        public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        
        # Recreate the exact data structure used for signing
        receipt_data = {
            'receipt_version': str(receipt.receipt_version.value),
            'execution_id': receipt.execution_id,
            'issued_at': receipt.issued_at.isoformat(),
            'issuer': str(receipt.issuer),
            'model': {
                'name': receipt.model.name,
                'version': receipt.model.version,
                'commit_sha256': receipt.model.commit_sha256,
            },
            'output': {
                'body_sha256': receipt.output.body_sha256,
                'content_type': receipt.output.content_type,
            }
        }
        
        # Convert to JSON with consistent formatting (same as in sign_receipt)
        receipt_json = json.dumps(receipt_data, sort_keys=True, separators=(',', ':'))
        
        if debug:
            print("\nReceipt data being verified:", file=sys.stderr)
            print(receipt_json, file=sys.stderr)
        
        # Decode the signature
        signature = base64.urlsafe_b64decode(receipt.signature.sig + '==='[:len(receipt.signature.sig) % 4])
        
        if debug:
            print(f"\nSignature (base64): {receipt.signature.sig}", file=sys.stderr)
            print(f"Signature (hex): {signature.hex()}", file=sys.stderr)
            print(f"Public key (hex): {public_key.hex()}", file=sys.stderr)
        
        # Create a temporary KeyPair for verification (KeyPair.verify will add the domain separation prefix)
        temp_keypair = KeyPair(kid="temp", public_key=public_key)
        return temp_keypair.verify(signature, receipt_json.encode('utf-8'))
        
    except Exception as e:
        if debug:
            import traceback
            print(f"\nVerification error: {e}", file=sys.stderr)
            print("\nStack trace:", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        return False


class KeyStore:
    """In-memory key store for managing cryptographic keys."""
    
    def __init__(self):
        self._keys: Dict[KeyID, KeyPair] = {}
    
    def add_key(self, key_pair: KeyPair) -> None:
        """Add a key pair to the store."""
        self._keys[key_pair.kid] = key_pair
    
    def get_key(self, kid: KeyID) -> Optional[KeyPair]:
        """Get a key pair by ID."""
        return self._keys.get(kid)
    
    def remove_key(self, kid: KeyID) -> None:
        """Remove a key pair from the store."""
        self._keys.pop(kid, None)
    
    def get_jwks(self, private: bool = False) -> Dict:
        """Get all public keys as a JWK Set."""
        return {
            "keys": [key.to_jwk(private=private) for key in self._keys.values()]
        }
