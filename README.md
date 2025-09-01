# AI Accountability Infrastructure

**The HTTPS moment for AI accountability starts now.**

A minimal, extensible standard for cryptographically verifiable AI system accountability. This repository provides the three core components needed to make AI systems auditable: a receipt schema, a verifier, and a transparency log.

## The Trinity

### 1. **Receipt Schema** (`schema/`)
- Minimal JSON schema defining accountability receipts
- Privacy-preserving input/output commitments
- Extensible policy framework
- Cryptographic attestation structure

### 2. **Pocket Verifier** (`verifier/`)
- Single Python file (<200 lines)
- Ed25519 signature verification
- Timestamp and hash validation
- Policy compliance checking
- Human-readable output

### 3. **Transparency Log** (`log/`)
- Append-only Merkle tree implementation
- REST API for receipt submission and proof generation
- Public read access with inclusion proofs
- Tamper-evident storage

## Documentation

For detailed documentation and examples, check out the [Claude AI Artifact](https://claude.ai/public/artifacts/6f841464-05b3-4f27-99c8-18b752f82798).

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Verify a receipt
python verifier/verify.py examples/sample_receipt.json

# Start transparency log server
python log/server.py

# Run tests
pytest tests/
```

## Example Receipt

```json
{
  "receipt_version": "1.0",
  "issued_at": "2025-09-01T19:07:00Z",
  "task_hash": "sha256:1a2b3c...",
  "model_hash": "sha256:4d5e6f...", 
  "input_commitment": "sha256:7g8h9i...",
  "output_commitment": "sha256:0j1k2l...",
  "policies": {
    "satisfied": ["P_SAFE_001", "P_PRIV_007"],
    "relaxed": []
  },
  "costs": {
    "latency_ms": 4210,
    "energy_j": 7.3,
    "tokens": 1284
  },
  "attestation": {
    "signature": "ed25519:XYZ123...",
    "pubkey_id": "key_2025_q3"
  }
}
```

## Cryptographic Design

- **Ed25519** signatures for fast verification and small size
- **SHA-256** commitments for privacy-preserving auditability
- **RFC 3339** timestamps with microsecond precision
- **Canonical JSON** (RFC 8785) for signature stability

## Architecture Principles

### Privacy by Design
- Log cryptographic commitments, not raw content
- Field-level encryption with separate keys
- Format-preserving tokens for PII
- Configurable retention with verified deletion

### Graceful Degradation
- Tiered compliance levels (A/B/C)
- Policy relaxation with expiry timestamps
- Sampling-based attestation for cost optimization
- Asynchronous heavy verification

### Verifiable Trust
- Open receipt format and validators
- Public transparency log
- Third-party audit capability
- No vendor lock-in

## Strategic Impact

Once this infrastructure exists, **every AI company faces a choice**: participate in verifiable accountability or explain why they don't.

### Immediate Effects
- Researchers can verify benchmark claims
- Enterprises can audit AI vendors  
- Regulators get machine-readable compliance
- Users can demand receipts from any AI service

### Network Effects
- Low technical barrier → no excuse not to implement
- High governance impact → can't ignore
- Open standard → no competitive moat
- First mover advantage → standard setter wins

## Contributing

We welcome contributions from:
- **AI Companies** implementing the standard
- **Researchers** extending the schema
- **Auditors** building verification tools
- **Regulators** defining compliance requirements

## License

MIT License - see [LICENSE](LICENSE) for details.
