"""
AI Trust Command Line Interface

Provides commands for managing keys, signing receipts, and verifying them.
"""

import json
import os
import sys
from typing import List, Optional

import click

from ai_trust.cli.commands import (
    create_receipt,
    generate_keypair,
    init_log_db,
    load_keypair,
    load_receipt,
    save_keypair,
    save_receipt,
    show_key,
    submit_to_log,
    verify_inclusion,
    verify_receipt,
)

# Configure click
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

# Command groups
@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    """AI Trust - Cryptographic receipts for AI accountability."""
    pass

# Key management commands
@cli.group()
def keys():
    """Manage cryptographic keys."""
    pass

@keys.command('generate')
@click.option('--output', '-o', required=True, help='Output file for the key pair')
@click.option('--kid', help='Key ID (default: auto-generated)')
def generate_key(output: str, kid: Optional[str] = None):
    """Generate a new Ed25519 key pair."""
    generate_keypair(output, kid)

@keys.command('show')
@click.argument('key_file', type=click.Path(exists=True))
def show_key_cmd(key_file: str):
    """Show information about a key pair."""
    show_key(key_file)

# Receipt commands
@cli.group()
def receipt():
    """Create and verify receipts."""
    pass

@receipt.command('create')
@click.option('--key', '-k', 'key_file', required=True, help='Path to the key file')
@click.option('--output', '-o', required=True, help='Output file for the receipt')
@click.option('--issuer', '-i', required=True, help='Issuer URL (must be HTTPS)')
@click.option('--model', '-m', 'model_name', required=True, help='Name of the AI model')
@click.option('--model-version', help='Version of the AI model')
@click.option('--model-commit', help='Git commit hash of the model')
@click.option('--body-sha256', required=True, help='SHA-256 hash of the response body')
@click.option('--content-type', help='Content type of the response')
@click.option('--input', '-I', 'inputs', multiple=True, help='Input commitment (format: hmac:salt_id)')
@click.option('--policy-json', help='Path to a JSON file containing policy information')
@click.option('--extensions-json', help='Path to a JSON file containing extension fields')
def create_receipt_cmd(
    key_file: str,
    output: str,
    issuer: str,
    model_name: str,
    body_sha256: str,
    content_type: Optional[str],
    model_version: Optional[str],
    model_commit: Optional[str],
    inputs: List[str],
    policy_json: Optional[str],
    extensions_json: Optional[str],
):
    """Create and sign a new receipt."""
    # Parse inputs
    input_commitments = []
    for input_str in inputs:
        if ':' not in input_str:
            click.echo(f"Invalid input format: {input_str}. Expected 'hmac:salt_id'", err=True)
            sys.exit(1)
        hmac, salt_id = input_str.split(':', 1)
        input_commitments.append({'hmac': hmac, 'salt_id': salt_id, 'algorithm': 'SHA-256'})
    
    # Load policy if provided
    policy = None
    if policy_json:
        try:
            with open(policy_json, 'r') as f:
                policy = json.load(f)
        except Exception as e:
            click.echo(f"Error loading policy: {e}", err=True)
            sys.exit(1)
    
    # Load extensions if provided
    extensions = None
    if extensions_json:
        try:
            with open(extensions_json, 'r') as f:
                extensions = json.load(f)
        except Exception as e:
            click.echo(f"Error loading extensions: {e}", err=True)
            sys.exit(1)
    
    # Create the receipt
    create_receipt(
        key_file=key_file,
        output=output,
        issuer=issuer,
        model_name=model_name,
        body_sha256=body_sha256,
        content_type=content_type,
        model_version=model_version,
        model_commit=model_commit,
        inputs=input_commitments if input_commitments else None,
        policy=policy,
        extensions=extensions
    )

@receipt.command('verify')
@click.argument('receipt_file', type=click.Path(exists=True))
@click.option('--key', '-k', 'key_file', help='Path to the public key file')
@click.option('--public-key', '-p', help='Public key as a hex string')
def verify_receipt_cmd(receipt_file: str, key_file: Optional[str], public_key: Optional[str]):
    """Verify a receipt's signature and contents."""
    if not key_file and not public_key:
        click.echo("Error: Either --key or --public-key must be provided", err=True)
        sys.exit(1)
    
    verify_receipt(receipt_file, key_file, public_key)

# Log commands
@cli.group()
def log():
    """Interact with transparency logs."""
    pass

@log.command('submit')
@click.option('--db', 'db_path', default='trust_log.db', help='Path to the log database')
@click.argument('receipt_file', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file for the updated receipt')
def submit_to_log_cmd(db_path: str, receipt_file: str, output: Optional[str]):
    """Submit a receipt to a transparency log."""
    submit_to_log(db_path, receipt_file, output)

@log.command('verify')
@click.option('--db', 'db_path', default='trust_log.db', help='Path to the log database')
@click.argument('receipt_file', type=click.Path(exists=True))
def verify_inclusion_cmd(db_path: str, receipt_file: str):
    """Verify that a receipt is included in the log."""
    if not verify_inclusion(db_path, receipt_file):
        sys.exit(1)

# Initialize command
@cli.command('init')
@click.option('--db', 'db_path', default='trust_log.db', help='Path to the log database')
def init_db(db_path: str):
    """Initialize a new log database."""
    try:
        db = init_log_db(db_path)
        click.echo(f"Initialized log database at {db_path}")
    except Exception as e:
        click.echo(f"Error initializing database: {e}", err=True)
        sys.exit(1)
    pass

# Key management commands
@cli.group()
def keys():
    """Manage cryptographic keys."""
    pass

@keys.command()
@click.option('--output', '-o', required=True, help='Output file for the key pair')
@click.option('--kid', help='Key ID (default: auto-generated)')
def generate(output: str, kid: Optional[str] = None):
    """Generate a new Ed25519 key pair."""
    if not kid:
        kid = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    
    key_pair = KeyPair.generate(kid)
    save_keypair(key_pair, output)
    click.echo(f"Generated key pair with ID: {kid}")

@keys.command()
@click.argument('key_file', type=click.Path(exists=True))
def show(key_file: str):
    """Show information about a key pair."""
    key_pair = load_keypair(key_file)
    
    click.echo(f"Key ID: {key_pair.kid}")
    click.echo(f"Algorithm: {key_pair.algorithm}")
    click.echo(f"Created: {key_pair.created_at.isoformat()}")
    
    if key_pair.not_before:
        click.echo(f"Not before: {key_pair.not_before.isoformat()}")
    if key_pair.not_after:
        click.echo(f"Not after: {key_pair.not_after.isoformat()}")
    
    click.echo("\nPublic key (JWK):")
    click.echo(json.dumps(key_pair.to_jwk(), indent=2))

# Receipt commands
@cli.group()
def receipt():
    """Create and verify receipts."""
    pass

@receipt.command()
@click.option('--key', '-k', required=True, help='Path to private key file')
@click.option('--output', '-o', required=True, help='Output file for the receipt')
@click.option('--issuer', '-i', required=True, help='Base URL of the issuing service')
@click.option('--model', '-m', required=True, help='Name of the AI model')
@click.option('--model-version', help='Version of the AI model')
@click.option('--model-commit', help='Git commit hash of the model')
@click.option('--body', help='Path to the response body file')
@click.option('--content-type', default='application/json', help='Content type of the response')
@click.option('--input', multiple=True, help='Input commitment in the format HMAC:SALT_ID')
def sign(key: str, output: str, issuer: str, model: str, model_version: Optional[str],
        model_commit: Optional[str], body: Optional[str], content_type: str,
        input: List[str]):
    """Create and sign a new receipt."""
    # Load the key pair
    key_pair = load_keypair(key)
    
    # Generate a unique execution ID
    execution_id = f"ex-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{os.urandom(4).hex()}"
    
    # Process input commitments
    input_commitments = []
    for inp in input:
        try:
            hmac, salt_id = inp.split(':', 1)
            input_commitments.append(InputCommitment(hmac=hmac, salt_id=salt_id))
        except ValueError:
            click.echo(f"Invalid input format: {inp}. Expected HMAC:SALT_ID", err=True)
            sys.exit(1)
    
    # Process output commitment
    body_sha256 = None
    if body:
        try:
            with open(body, 'rb') as f:
                body_data = f.read()
            body_sha256 = hashlib.sha256(body_data).hexdigest()
        except Exception as e:
            click.echo(f"Error reading response body: {e}", err=True)
            sys.exit(1)
    else:
        # If no body is provided, use a default hash of an empty string
        body_sha256 = hashlib.sha256(b'').hexdigest()
    
    # Create the receipt without signature first
    receipt_data = {
        "receipt_version": ReceiptVersion.V1,
        "execution_id": execution_id,
        "issuer": issuer,
        "model": {
            "name": model,
            "version": model_version,
            "commit_sha256": model_commit
        },
        "output": {
            "body_sha256": body_sha256 or "",
            "content_type": content_type if body_sha256 else None
        },
        "inputs": [ic.dict() for ic in input_commitments] if input_commitments else None
    }
    
    # Create a temporary receipt for signing
    temp_receipt = Receipt(**receipt_data)
    
    # Sign the receipt
    sig = sign_receipt(temp_receipt, key_pair)
    
    # Add the signature to the receipt data
    receipt_data["signature"] = {
        "alg": "EdDSA",
        "kid": key_pair.kid,
        "sig": sig,
        "issued_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Create the final receipt with signature
    receipt = Receipt(**receipt_data)
    
    # Save the receipt
    save_receipt(receipt, output)

@receipt.command()
@click.argument('receipt_file', type=click.Path(exists=True))
@click.option('--public-key', help='Public key to verify against (if not in the receipt)')
@click.option('--issuer', help='Expected issuer URL')
@click.option('--model', help='Expected model name')
def verify(receipt_file: str, public_key: Optional[str], issuer: Optional[str], model: Optional[str]):
    """Verify a receipt's signature and contents."""
    # Load the receipt
    receipt = load_receipt(receipt_file)
    
    # Verify the receipt version
    if receipt.receipt_version != ReceiptVersion.V1:
        click.echo(f"Unsupported receipt version: {receipt.receipt_version}", err=True)
        sys.exit(1)
    
    # Verify the issuer if provided
    if issuer and str(receipt.issuer) != issuer:
        click.echo(f"Issuer mismatch: expected {issuer}, got {receipt.issuer}", err=True)
        sys.exit(1)
    
    # Verify the model if provided
    if model and receipt.model.name != model:
        click.echo(f"Model mismatch: expected {model}, got {receipt.model.name}", err=True)
        sys.exit(1)
    
    # Get the public key
    pub_key = None
    if public_key:
        try:
            with open(public_key, 'r') as f:
                key_data = json.load(f)
            key_pair = KeyPair.from_jwk(key_data)
            pub_key = key_pair.public_key
        except Exception as e:
            click.echo(f"Error loading public key: {e}", err=True)
            sys.exit(1)
    
    # Verify the signature
    if not pub_key:
        click.echo("No public key provided and none found in the receipt", err=True)
        sys.exit(1)
    
    if verify_receipt(receipt, pub_key):
        click.echo("✅ Receipt signature is valid")
        sys.exit(0)
    else:
        click.echo("❌ Invalid receipt signature", err=True)
        sys.exit(1)

# Log commands
@cli.group()
def log():
    """Interact with transparency logs."""
    pass

@log.command()
@click.argument('url')
@click.option('--output', '-o', help='Output file for the log entry')
def submit(url: str, output: Optional[str]):
    """Submit a receipt to a transparency log."""
    click.echo(f"Submitting receipt to log at {url}...")
    # TODO: Implement log submission
    click.echo("Not implemented yet")

@log.command()
@click.argument('log_url')
@click.argument('index', type=int)
def get_entry(log_url: str, index: int):
    """Get an entry from a transparency log."""
    click.echo(f"Getting entry {index} from log at {log_url}...")
    # TODO: Implement log entry retrieval
    click.echo("Not implemented yet")

# Main entry point
if __name__ == '__main__':
    cli()
