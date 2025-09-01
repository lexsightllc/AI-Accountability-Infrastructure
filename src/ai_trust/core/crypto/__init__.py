"""Cryptographic operations for AI Trust."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import ClassVar, Optional, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


@dataclass
class KeyPair:
    """Represents a public/private key pair."""

    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey

    DOMAIN: ClassVar[bytes] = b"ai-trust-v1"

    @classmethod
    def generate(cls) -> "KeyPair":
        """Generate a new key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key=private_key, public_key=private_key.public_key())

    def sign(self, data: bytes, timestamp: Optional[float] = None) -> bytes:
        """Sign data with the private key."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).timestamp()
        timestamp_int = int(timestamp)
        signed_data = self.DOMAIN + timestamp_int.to_bytes(8, "big") + data
        return cast(bytes, self.private_key.sign(signed_data))

    def verify(
        self,
        data: bytes,
        signature: bytes,
        timestamp: Optional[float] = None,
        max_age_seconds: float = 300,
    ) -> bool:
        """Verify a signature."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).timestamp()
        if abs(datetime.now(timezone.utc).timestamp() - timestamp) > max_age_seconds:
            return False
        try:
            timestamp_int = int(timestamp)
            signed_data = self.DOMAIN + timestamp_int.to_bytes(8, "big") + data
            self.public_key.verify(signature, signed_data)
        except Exception:
            return False
        else:
            return True

    def public_bytes(self) -> bytes:
        """Get the public key as bytes."""
        return cast(
            bytes,
            self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    @classmethod
    def from_private_bytes(cls, private_bytes: bytes) -> "KeyPair":
        """Create a KeyPair from private key bytes."""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        return cls(private_key=private_key, public_key=private_key.public_key())


def create_keypair() -> KeyPair:
    """Generate a new key pair."""
    return KeyPair.generate()


def sign(key_pair: KeyPair, data: bytes, timestamp: Optional[float] = None) -> bytes:
    """Sign data with the provided key pair."""
    return key_pair.sign(data, timestamp)


def verify_signature(
    key_pair: KeyPair,
    data: bytes,
    signature: bytes,
    timestamp: Optional[float] = None,
    max_age_seconds: float = 300,
) -> bool:
    """Verify a signature using the provided key pair."""
    return key_pair.verify(data, signature, timestamp, max_age_seconds)
