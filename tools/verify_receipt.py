#!/usr/bin/env python3
"""
Verify an AI accountability receipt.

This script verifies the signature and structure of an AI accountability receipt
using the verifier module.
"""

import json
import sys
import argparse
from pathlib import Path

# Add the parent directory to the path so we can import the verifier
sys.path.insert(0, str(Path(__file__).parent.parent))

from verifier.verify import AIReceiptVerifier, VerificationResult

def load_receipt(receipt_path: str) -> dict:
    """Load a receipt from a JSON file."""
    try:
        with open(receipt_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in receipt file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading receipt file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Verify an AI accountability receipt')
    parser.add_argument('receipt_file', help='Path to the receipt JSON file')
    parser.add_argument('--public-key', '-k', help='Path to the public key file (PEM or base64)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Load the receipt
    receipt = load_receipt(args.receipt_file)
    
    # Initialize the verifier
    verifier = AIReceiptVerifier()
    
    # Load the public key if provided
    if args.public_key:
        try:
            with open(args.public_key, 'r') as f:
                public_key_data = f.read().strip()
            
            # Try to determine if it's PEM or base64
            if '-----BEGIN PUBLIC KEY-----' in public_key_data:
                verifier.load_public_key(public_key_data, format='pem')
            else:
                verifier.load_public_key(public_key_data, format='base64')
                
            print(f"Loaded public key from: {args.public_key}")
        except Exception as e:
            print(f"Error loading public key: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Verify the receipt
    print(f"Verifying receipt: {args.receipt_file}")
    result = verifier.verify(receipt, verbose=args.verbose)
    
    # Print the result
    print("\nVerification Result:")
    print(f"  Valid: {'✅' if result.is_valid else '❌'}")
    
    if not result.is_valid:
        print("\nValidation Errors:")
        for error in result.errors:
            print(f"  - {error}")
    
    if result.warnings:
        print("\nValidation Warnings:")
        for warning in result.warnings:
            print(f"  - ⚠️ {warning}")
    
    if result.is_valid:
        print("\nReceipt is valid and verified!")
        if 'attestation' in receipt and 'pubkey_id' in receipt['attestation']:
            print(f"  Signed by: {receipt['attestation']['pubkey_id']}")
        if 'issued_at' in receipt:
            print(f"  Issued at: {receipt['issued_at']}")
        if 'model_hash' in receipt:
            print(f"  Model: {receipt['model_hash']}")
    
    sys.exit(0 if result.is_valid else 1)

if __name__ == "__main__":
    main()
