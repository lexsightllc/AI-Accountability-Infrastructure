"""Unit tests for core functionality."""

from ai_trust.core import KeyPair, canonicalize, create_receipt, verify_receipt


def test_canonicalization() -> None:
    """Test that canonicalization produces consistent output."""
    data = {"b": 2, "a": 1, "c": [3, 1, 2]}
    expected = '{"a":1,"b":2,"c":[3,1,2]}'
    assert canonicalize(data) == expected


def test_keypair_generation() -> None:
    """Test key pair generation and signing."""
    key_pair = KeyPair.generate()
    data = b"test data"
    signature = key_pair.sign(data)

    assert key_pair.verify(data, signature)
    assert not key_pair.verify(b"different data", signature)


def test_receipt_creation_and_verification() -> None:
    """Test receipt creation and verification."""
    key_pair = KeyPair.generate()
    data = {"model": "test", "input": "test", "output": "test"}

    receipt = create_receipt(data, key_pair)
    assert receipt.status == "verified"

    assert verify_receipt(receipt, key_pair.public_bytes())
