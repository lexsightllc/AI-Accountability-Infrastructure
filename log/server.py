"""
AI Accountability Transparency Log Server
=========================================

A minimal implementation of an append-only transparency log for AI receipts.
Provides REST API for receipt submission, retrieval, and inclusion proofs.
"""

import os
import json
import hashlib
import sqlite3
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

# Flask import
# Flask imports
FLASK_AVAILABLE = True

# Import Flask and related modules
try:
    from flask import Flask, request, jsonify, Response, abort, make_response
    from flask.typing import ResponseReturnValue
    from werkzeug.exceptions import HTTPException, BadRequest, NotFound
    from werkzeug.serving import run_simple
    from typing_extensions import TypedDict
    from typing import Callable
    from functools import wraps
except ImportError:
    FLASK_AVAILABLE = False
    # Provide dummy Flask class when not available
    class Flask:
        def __init__(self, *args, **kwargs):
            raise ImportError("Flask is not installed. Please install it with 'pip install flask'")
    
    class ResponseReturnValue:
        pass
    
    class HTTPException(Exception):
        pass
    
    class BadRequest(Exception):
        pass
    
    class NotFound(Exception):
        pass
    
    def run_simple(*args, **kwargs):
        raise ImportError("Werkzeug is not installed. Please install it with 'pip install werkzeug'")
    
    class TypedDict(dict):
        __annotations__ = {}
    
    def wraps(f):
        return lambda x: x


@dataclass
class LogEntry:
    """Represents an entry in the transparency log."""
    index: int
    timestamp: float
    receipt_hash: str
    receipt: str
    merkle_leaf_hash: str


@dataclass
class InclusionProof:
    """Merkle inclusion proof for a log entry."""
    index: int
    tree_size: int
    leaf_hash: str
    audit_path: List[str]


class MerkleTree:
    """Simple Merkle tree implementation for the transparency log."""
    
    def __init__(self, leaves: List[str] = None):
        self.leaves = leaves or []
        self.tree = []
        self._build_tree()
    
    @property
    def size(self) -> int:
        """Get the number of leaves in the tree."""
        return len(self.leaves)
    
    @property
    def root_hash(self) -> str:
        """Get the Merkle root hash."""
        if not self.tree:
            return "0" * 64  # Empty tree root
        return self.tree[0][0]
    
    def add_leaf(self, leaf_hash: str) -> int:
        """Add a new leaf and return its index."""
        if not self._is_hex_sha256(leaf_hash):
            raise ValueError("Leaf hash must be a valid SHA-256 hex string")
            
        index = len(self.leaves)
        self.leaves.append(leaf_hash)
        self._build_tree()
        return index
    
    def get_proof(self, leaf_index: int) -> Optional[InclusionProof]:
        """Generate inclusion proof for a leaf at given index."""
        if leaf_index >= len(self.leaves):
            return None
            
        leaf_hash = self.leaves[leaf_index]
        audit_path = self._get_audit_path(leaf_index)
        
        return InclusionProof(
            index=leaf_index,
            tree_size=len(self.leaves),
            leaf_hash=leaf_hash,
            audit_path=audit_path
        )
    
    def verify_proof(self, proof: InclusionProof) -> bool:
        """Verify an inclusion proof against current tree."""
        if proof.tree_size != len(self.leaves):
            return False
            
        if proof.index >= proof.tree_size:
            return False
            
        # Reconstruct root from proof
        current_hash = proof.leaf_hash
        index = proof.index
        
        for sibling_hash in proof.audit_path:
            if index % 2 == 0:  # Left child
                current_hash = self._hash_pair(current_hash, sibling_hash)
            else:  # Right child
                current_hash = self._hash_pair(sibling_hash, current_hash)
            index //= 2
            
        return current_hash == self.root_hash
    
    def _build_tree(self):
        """Build the complete Merkle tree."""
        if not self.leaves:
            self.tree = []
            return
            
        # Start with leaves
        current_level = self.leaves.copy()
        self.tree = [current_level]
        
        # Build up the tree
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                parent = self._hash_pair(left, right)
                next_level.append(parent)
            
            current_level = next_level
            self.tree.insert(0, current_level)
    
    def _get_audit_path(self, leaf_index: int) -> List[str]:
        """Get audit path for inclusion proof."""
        audit_path = []
        index = leaf_index
        
        # Traverse from leaves to root (skip the root level)
        for level in self.tree[1:]:
            sibling_index = index ^ 1  # XOR with 1 to get sibling
            if sibling_index < len(level):
                audit_path.append(level[sibling_index])
            else:
                audit_path.append(level[index])  # Use same node if no sibling
            index //= 2
            
        return audit_path
    
    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """Hash a pair of nodes."""
        return hashlib.sha256(f"{left}:{right}".encode()).hexdigest()
    
    @staticmethod
    def _is_hex_sha256(s: str) -> bool:
        """Check if string is a valid SHA-256 hex digest."""
        if not isinstance(s, str) or len(s) != 64:
            return False
        try:
            int(s, 16)
            return True
        except ValueError:
            return False


class TransparencyLog:
    """Transparency log implementation with SQLite storage."""
    
    def __init__(self, storage_dir: str = "./data"):
        """Initialize the transparency log.
        
        Args:
            storage_dir: Directory to store the database and other files
        """
        self.storage_dir = os.path.abspath(storage_dir)
        os.makedirs(self.storage_dir, exist_ok=True)
        
        # Initialize database
        self.db_path = os.path.join(self.storage_dir, 'transparency_log.db')
        self._init_database()
        
        # Initialize Merkle tree with existing entries
        self.merkle_tree = MerkleTree()
        self._load_existing_entries()
    
    def _init_database(self):
        """Initialize SQLite database schema."""
        with sqlite3.connect(self.db_path) as conn:
            # Enable foreign keys
            conn.execute('PRAGMA foreign_keys = ON')
            
            # Create log_entries table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS log_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    index_num INTEGER UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    receipt TEXT NOT NULL,
                    merkle_leaf_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_receipt_hash 
                ON log_entries(receipt_hash)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_index_num 
                ON log_entries(index_num)
            ''')
    
    def _load_existing_entries(self):
        """Load existing entries from database into Merkle tree."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT merkle_leaf_hash 
                FROM log_entries 
                ORDER BY index_num
            ''')
            
            for row in cursor:
                self.merkle_tree.add_leaf(row[0])
    
    def append_receipt(self, receipt: str) -> Tuple[int, str]:
        """Append a receipt to the log.
        
        Args:
            receipt: JSON string of the receipt to append
            
        Returns:
            Tuple of (index, receipt_hash)
            
        Raises:
            ValueError: If receipt is invalid or already exists
        """
        try:
            # Validate JSON
            json.loads(receipt)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        
        # Calculate receipt hash
        receipt_hash = hashlib.sha256(receipt.encode()).hexdigest()
        
        # Check if receipt already exists
        existing_index = self._find_receipt_index(receipt_hash)
        if existing_index is not None:
            return existing_index, receipt_hash
        
        # Create log entry
        timestamp = time.time()
        index = self.merkle_tree.size
        
        # Create Merkle leaf hash (hash of the log entry)
        entry_data = f"{index}:{timestamp}:{receipt_hash}"
        merkle_leaf_hash = hashlib.sha256(entry_data.encode()).hexdigest()
        
        # Add to Merkle tree
        self.merkle_tree.add_leaf(merkle_leaf_hash)
        
        # Store in database
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO log_entries 
                (index_num, timestamp, receipt_hash, receipt, merkle_leaf_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (index, timestamp, receipt_hash, receipt, merkle_leaf_hash))
        
        return index, receipt_hash
    
    def get_receipt(self, receipt_id: str) -> Optional[LogEntry]:
        """Get receipt by ID (either index or hash)."""
        with sqlite3.connect(self.db_path) as conn:
            # Try by index
            if receipt_id.isdigit():
                cursor = conn.execute('''
                    SELECT index_num, timestamp, receipt_hash, receipt, merkle_leaf_hash
                    FROM log_entries 
                    WHERE index_num = ?
                ''', (int(receipt_id),))
            else:
                # Try by hash
                cursor = conn.execute('''
                    SELECT index_num, timestamp, receipt_hash, receipt, merkle_leaf_hash
                    FROM log_entries 
                    WHERE receipt_hash = ?
                ''', (receipt_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
                
            return LogEntry(
                index=row[0],
                timestamp=row[1],
                receipt_hash=row[2],
                receipt=row[3],
                merkle_leaf_hash=row[4]
            )
    
    def get_inclusion_proof(self, receipt_id: str) -> Optional[InclusionProof]:
        """Get inclusion proof for a receipt by ID."""
        entry = self.get_receipt(receipt_id)
        if not entry:
            return None
            
        return self.merkle_tree.get_proof(entry.index)
    
    def get_merkle_root(self) -> str:
        """Get the current Merkle root hash."""
        return self.merkle_tree.root_hash
    
    def get_tree_size(self) -> int:
        """Get the current number of entries in the log."""
        return self.merkle_tree.size
    
    def _find_receipt_index(self, receipt_hash: str) -> Optional[int]:
        """Find receipt index by hash."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT index_num 
                FROM log_entries 
                WHERE receipt_hash = ?
            ''', (receipt_hash,))
            
            row = cursor.fetchone()
            return row[0] if row else None


def create_app(test_config=None) -> Flask:
    """Create and configure the Flask application.
    
    Args:
        test_config: Optional test configuration
        
    Returns:
        Configured Flask application
    """
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask is required to create the web application")
    
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.urandom(24),
        DATABASE=os.path.join(app.instance_path, 'transparency_log.db'),
        STORAGE_DIR=os.path.join(app.instance_path, 'data'),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max upload
    )
    
    # Apply test config if provided
    if test_config is not None:
        app.config.update(test_config)
    
    # Ensure instance folder exists
    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config['STORAGE_DIR'], exist_ok=True)
    
    # Initialize transparency log
    transparency_log = TransparencyLog(storage_dir=app.config['STORAGE_DIR'])
    
    # Register routes
    @app.route('/health', methods=['GET'])
    def health() -> ResponseReturnValue:
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'tree_size': transparency_log.get_tree_size(),
            'merkle_root': transparency_log.get_merkle_root()
        })
    
    @app.route('/receipts', methods=['POST'])
    def submit_receipt() -> ResponseReturnValue:
        """Submit a new receipt to the log."""
        if not request.is_json:
            raise BadRequest("Content-Type must be application/json")
            
        receipt = request.get_data(as_text=True)
        
        try:
            index, receipt_hash = transparency_log.append_receipt(receipt)
            return jsonify({
                'status': 'success',
                'index': index,
                'receipt_hash': receipt_hash,
                'merkle_root': transparency_log.get_merkle_root(),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }), 201
        except ValueError as e:
            raise BadRequest(str(e))
    
    @app.route('/receipts/<receipt_id>', methods=['GET'])
    def get_receipt(receipt_id: str) -> ResponseReturnValue:
        """Get a receipt by ID or hash."""
        entry = transparency_log.get_receipt(receipt_id)
        if not entry:
            raise NotFound(f"Receipt not found: {receipt_id}")
            
        return jsonify({
            'index': entry.index,
            'timestamp': entry.timestamp,
            'receipt_hash': entry.receipt_hash,
            'receipt': json.loads(entry.receipt),
            'merkle_leaf_hash': entry.merkle_leaf_hash
        })
    
    @app.route('/proofs/<receipt_id>', methods=['GET'])
    def get_inclusion_proof(receipt_id: str) -> ResponseReturnValue:
        """Get inclusion proof for a receipt."""
        proof = transparency_log.get_inclusion_proof(receipt_id)
        if not proof:
            raise NotFound(f"Proof not found for receipt: {receipt_id}")
            
        return jsonify({
            'index': proof.index,
            'tree_size': proof.tree_size,
            'leaf_hash': proof.leaf_hash,
            'audit_path': proof.audit_path,
            'merkle_root': transparency_log.get_merkle_root()
        })
    
    @app.route('/tree/root', methods=['GET'])
    def get_merkle_root() -> ResponseReturnValue:
        """Get the current Merkle root hash."""
        return jsonify({
            'tree_size': transparency_log.get_tree_size(),
            'root_hash': transparency_log.get_merkle_root()
        })
    
    @app.route('/tree/size', methods=['GET'])
    def get_tree_size() -> ResponseReturnValue:
        """Get the current number of entries in the log."""
        return jsonify({
            'tree_size': transparency_log.get_tree_size()
        })
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(error: HTTPException) -> ResponseReturnValue:
        return jsonify({
            'error': 'bad_request',
            'message': str(error)
        }), 400
    
    @app.errorhandler(404)
    def not_found(error: HTTPException) -> ResponseReturnValue:
        return jsonify({
            'error': 'not_found',
            'message': str(error)
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error: HTTPException) -> ResponseReturnValue:
        return jsonify({
            'error': 'internal_server_error',
            'message': 'An internal server error occurred'
        }), 500
    
    return app


def run_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
    """Run the transparency log server.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        debug: Enable debug mode
    """
    if not FLASK_AVAILABLE:
        print("Error: Flask is required to run the server")
        print("Install with: pip install flask")
        sys.exit(1)
    
    app = create_app()
    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Accountability Transparency Log Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print(f"Starting transparency log server on {args.host}:{args.port}")
    print(f"Merkle root: {TransparencyLog().get_merkle_root()}")
    print("Press Ctrl+C to stop")
    
    run_server(host=args.host, port=args.port, debug=args.debug)
