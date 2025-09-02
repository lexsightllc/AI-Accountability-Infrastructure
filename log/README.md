# AI Accountability Transparency Log

An append-only transparency log for AI accountability receipts, providing cryptographic proof of inclusion for all logged receipts.

## Features

- Append-only Merkle tree implementation
- REST API for receipt submission and verification
- SQLite storage for persistence
- Merkle inclusion proofs
- Tamper-evident logging
- Simple integration with existing systems

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Starting the Server

```bash
# Start the server on default port (5000)
python -m log.server

# Custom host and port
python -m log.server --host 0.0.0.0 --port 8080

# Enable debug mode
python -m log.server --debug
```

### API Endpoints

#### `POST /receipts`

Submit a new receipt to the log.

**Request:**
```http
POST /receipts
Content-Type: application/json

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
    "signature": "ed25519:VGVzdFNpZ25hdHVyZQ==",
    "pubkey_id": "test_key_2025"
  }
}
```

**Response (201 Created):**
```json
{
  "status": "success",
  "index": 0,
  "receipt_hash": "1a2b3c...",
  "merkle_root": "4d5e6f...",
  "timestamp": "2025-09-01T19:07:00Z"
}
```

#### `GET /receipts/<receipt_id>`

Retrieve a receipt by its index or hash.

**Request:**
```http
GET /receipts/0
```

**Response (200 OK):**
```json
{
  "index": 0,
  "timestamp": 1733166420.0,
  "receipt_hash": "1a2b3c...",
  "receipt": {
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
      "signature": "ed25519:VGVzdFNpZ25hdHVyZQ==",
      "pubkey_id": "test_key_2025"
    }
  },
  "merkle_leaf_hash": "2b3c4d..."
}
```

#### `GET /proofs/<receipt_id>`

Get the inclusion proof for a receipt.

**Request:**
```http
GET /proofs/0
```

**Response (200 OK):**
```json
{
  "index": 0,
  "tree_size": 1,
  "leaf_hash": "1a2b3c...",
  "audit_path": [],
  "merkle_root": "4d5e6f..."
}
```

#### `GET /tree/root`

Get the current Merkle root hash.

**Request:**
```http
GET /tree/root
```

**Response (200 OK):**
```json
{
  "tree_size": 1,
  "root_hash": "4d5e6f..."
}
```

#### `GET /tree/size`

Get the current number of entries in the log.

**Request:**
```http
GET /tree/size
```

**Response (200 OK):**
```json
{
  "tree_size": 1
}
```

#### `GET /health`

Check the health status of the server.

**Request:**
```http
GET /health
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2025-09-01T19:07:00Z",
  "tree_size": 1,
  "merkle_root": "4d5e6f..."
}
```

## Python API

### `TransparencyLog`

Main class for interacting with the transparency log.

```python
from log.server import TransparencyLog

# Initialize with custom storage directory
log = TransparencyLog(storage_dir="./data")

# Add a receipt to the log
with open('receipt.json', 'r') as f:
    receipt_json = f.read()

index, receipt_hash = log.append_receipt(receipt_json)
print(f"Added receipt with index {index} and hash {receipt_hash}")

# Get a receipt
entry = log.get_receipt(index)  # or log.get_receipt(receipt_hash)
print(f"Retrieved receipt: {entry.receipt}")

# Get inclusion proof
proof = log.get_inclusion_proof(index)
print(f"Inclusion proof: {proof}")

# Get current Merkle root
root_hash = log.get_merkle_root()
print(f"Current Merkle root: {root_hash}")

# Get tree size
size = log.get_tree_size()
print(f"Tree size: {size}")
```

### `MerkleTree`

Merkle tree implementation used by the transparency log.

```python
from log.server import MerkleTree

# Create a new Merkle tree
tree = MerkleTree()

# Add leaves
index1 = tree.add_leaf("hash1")
index2 = tree.add_leaf("hash2")

# Get Merkle root
root = tree.root_hash

# Get inclusion proof
proof = tree.get_proof(index1)

# Verify proof
is_valid = tree.verify_proof(proof)
print(f"Proof is valid: {is_valid}")
```

## Testing

Run the test suite with pytest:

```bash
pytest tests/test_log.py -v
```

## License

MIT
