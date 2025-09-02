"""
Database module for the transparency log using SQLite.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel

from ai_trust.core.merkle import MerkleTree

logger = logging.getLogger(__name__)

# Database schema version
SCHEMA_VERSION = 1

# SQL statements for schema creation
SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS log_entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        leaf_hash BLOB NOT NULL,
        data BLOB NOT NULL,
        receipt_id TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(receipt_id)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_log_entries_receipt_id ON log_entries(receipt_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS tree_nodes (
        node_hash BLOB PRIMARY KEY,
        left_hash BLOB,
        right_hash BLOB,
        data BLOB,
        is_leaf BOOLEAN NOT NULL,
        leaf_index INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tree_roots (
        tree_size INTEGER PRIMARY KEY,
        root_hash BLOB NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY,
        receipt_data BLOB NOT NULL,
        status TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS update_receipt_timestamp
    AFTER UPDATE ON receipts
    FOR EACH ROW
    BEGIN
        UPDATE receipts SET updated_at = CURRENT_TIMESTAMP WHERE receipt_id = NEW.receipt_id;
    END;
    """
]


class LogEntry(BaseModel):
    """A log entry in the transparency log."""
    receipt_id: str
    leaf_hash: bytes
    data: bytes
    timestamp: datetime
    leaf_index: Optional[int] = None


class LogDB:
    """SQLite database for the transparency log."""
    
    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        """Initialize the database.
        
        Args:
            db_path: Path to the SQLite database file, or ":memory:" for in-memory DB.
        """
        self.db_path = str(db_path)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_connection() as conn:
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON")
            
            # Create tables
            for stmt in SCHEMA:
                conn.execute(stmt)
            
            # Set schema version if not set
            cursor = conn.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            )
            if not cursor.fetchone():
                conn.execute(
                    "INSERT INTO metadata (key, value) VALUES (?, ?)",
                    ("schema_version", str(SCHEMA_VERSION))
                )
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Get a database connection with proper transaction handling."""
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def add_log_entry(self, receipt_id: str, data: bytes) -> LogEntry:
        """Add a new log entry.
        
        Args:
            receipt_id: The ID of the receipt being logged.
            data: The receipt data to log.
            
        Returns:
            The created log entry.
        """
        # Calculate leaf hash
        merkle = MerkleTree()
        leaf_hash = merkle._hash_leaf(data)
        
        with self._get_connection() as conn:
            # Check if receipt already exists
            cursor = conn.execute(
                "SELECT id FROM log_entries WHERE receipt_id = ?",
                (receipt_id,)
            )
            if cursor.fetchone():
                raise ValueError(f"Receipt {receipt_id} already exists in the log")
            
            # Insert the log entry
            cursor = conn.execute(
                """
                INSERT INTO log_entries (leaf_hash, data, receipt_id)
                VALUES (?, ?, ?)
                RETURNING id, timestamp
                """,
                (leaf_hash, data, receipt_id)
            )
            
            result = cursor.fetchone()
            if not result:
                raise RuntimeError("Failed to insert log entry")
            
            # Update the Merkle tree
            self._update_merkle_tree(conn)
            
            # Get the leaf index
            cursor = conn.execute(
                """
                SELECT COUNT(*) as count 
                FROM log_entries 
                WHERE id <= ?
                """,
                (result["id"],)
            )
            leaf_index = cursor.fetchone()["count"] - 1
            
            # Update the log entry with the leaf index
            conn.execute(
                """
                UPDATE log_entries 
                SET leaf_index = ? 
                WHERE id = ?
                """,
                (leaf_index, result["id"])
            )
            
            # Store the receipt
            self._store_receipt(conn, receipt_id, data)
            
            conn.commit()
            
            return LogEntry(
                receipt_id=receipt_id,
                leaf_hash=leaf_hash,
                data=data,
                timestamp=datetime.fromisoformat(result["timestamp"]),
                leaf_index=leaf_index
            )
    
    def get_log_entry(self, receipt_id: str) -> Optional[LogEntry]:
        """Get a log entry by receipt ID.
        
        Args:
            receipt_id: The ID of the receipt to look up.
            
        Returns:
            The log entry if found, None otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, leaf_hash, data, timestamp, leaf_index
                FROM log_entries
                WHERE receipt_id = ?
                """,
                (receipt_id,)
            )
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return LogEntry(
                receipt_id=receipt_id,
                leaf_hash=row["leaf_hash"],
                data=row["data"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                leaf_index=row["leaf_index"]
            )
    
    def get_log_entries(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> Tuple[List[LogEntry], int]:
        """Get a paginated list of log entries.
        
        Args:
            limit: Maximum number of entries to return.
            offset: Number of entries to skip.
            
        Returns:
            A tuple of (entries, total_count).
        """
        with self._get_connection() as conn:
            # Get total count
            cursor = conn.execute("SELECT COUNT(*) as count FROM log_entries")
            total_count = cursor.fetchone()["count"]
            
            # Get paginated results
            cursor = conn.execute(
                """
                SELECT receipt_id, leaf_hash, data, timestamp, leaf_index
                FROM log_entries
                ORDER BY id ASC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
            
            entries = [
                LogEntry(
                    receipt_id=row["receipt_id"],
                    leaf_hash=row["leaf_hash"],
                    data=row["data"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    leaf_index=row["leaf_index"]
                )
                for row in cursor.fetchall()
            ]
            
            return entries, total_count
    
    def get_latest_root(self) -> Optional[bytes]:
        """Get the latest root hash of the Merkle tree.
        
        Returns:
            The root hash as bytes, or None if the tree is empty.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT root_hash
                FROM tree_roots
                ORDER BY tree_size DESC
                LIMIT 1
                """
            )
            
            row = cursor.fetchone()
            return row["root_hash"] if row else None
    
    def get_inclusion_proof(
        self,
        receipt_id: str,
        tree_size: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """Get an inclusion proof for a receipt.
        
        Args:
            receipt_id: The ID of the receipt to prove inclusion for.
            tree_size: The size of the tree to generate the proof against.
                      If None, uses the latest tree size.
            
        Returns:
            A dictionary with the proof data, or None if the receipt is not found.
        """
        with self._get_connection() as conn:
            # Get the log entry
            entry = self.get_log_entry(receipt_id)
            if not entry or entry.leaf_index is None:
                return None
            
            # Get the tree size if not specified
            if tree_size is None:
                cursor = conn.execute(
                    "SELECT MAX(tree_size) as max_size FROM tree_roots"
                )
                tree_size = cursor.fetchone()["max_size"]
                if not tree_size:
                    return None
            
            # Get the root hash for the specified tree size
            cursor = conn.execute(
                """
                SELECT root_hash
                FROM tree_roots
                WHERE tree_size = ?
                """,
                (tree_size,)
            )
            
            root_row = cursor.fetchone()
            if not root_row:
                return None
            
            # Get the inclusion proof
            proof_hashes = self._get_inclusion_proof_hashes(
                conn, entry.leaf_index, tree_size
            )
            
            if proof_hashes is None:
                return None
            
            return {
                "leaf_index": entry.leaf_index,
                "tree_size": tree_size,
                "root_hash": root_row["root_hash"],
                "proof_hashes": proof_hashes
            }
    
    def _get_inclusion_proof_hashes(
        self,
        conn: sqlite3.Connection,
        leaf_index: int,
        tree_size: int
    ) -> Optional[List[bytes]]:
        """Get the inclusion proof hashes for a leaf."""
        # This is a simplified implementation that rebuilds the proof from the tree
        # In a production system, you'd want to store the proof hashes in the DB
        
        # Get all leaves up to tree_size
        cursor = conn.execute(
            """
            SELECT leaf_hash
            FROM log_entries
            WHERE leaf_index < ?
            ORDER BY leaf_index ASC
            """,
            (tree_size,)
        )
        
        leaves = [row["leaf_hash"] for row in cursor.fetchall()]
        
        # Build the Merkle tree and get the proof
        merkle = MerkleTree(leaves)
        proof = merkle.get_inclusion_proof(leaf_index, tree_size)
        
        return proof
    
    def _update_merkle_tree(self, conn: sqlite3.Connection) -> None:
        """Update the Merkle tree with new entries."""
        # Get all leaf hashes
        cursor = conn.execute(
            "SELECT leaf_hash FROM log_entries ORDER BY id ASC"
        )
        
        leaves = [row["leaf_hash"] for row in cursor.fetchall()]
        if not leaves:
            return
        
        # Build the Merkle tree
        merkle = MerkleTree(leaves)
        root_hash = merkle.get_root_hash()
        
        if not root_hash:
            return
        
        # Store the new root
        tree_size = len(leaves)
        conn.execute(
            """
            INSERT OR REPLACE INTO tree_roots (tree_size, root_hash)
            VALUES (?, ?)
            """,
            (tree_size, root_hash)
        )
    
    def _store_receipt(
        self,
        conn: sqlite3.Connection,
        receipt_id: str,
        data: bytes
    ) -> None:
        """Store a receipt in the database."""
        conn.execute(
            """
            INSERT INTO receipts (receipt_id, receipt_data, status)
            VALUES (?, ?, 'PENDING')
            ON CONFLICT(receipt_id) DO UPDATE SET
                receipt_data = excluded.receipt_data,
                status = 'UPDATED'
            """,
            (receipt_id, data)
        )
    
    def get_receipt(self, receipt_id: str) -> Optional[bytes]:
        """Get a receipt by ID.
        
        Args:
            receipt_id: The ID of the receipt to retrieve.
            
        Returns:
            The receipt data as bytes, or None if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT receipt_data
                FROM receipts
                WHERE receipt_id = ?
                """,
                (receipt_id,)
            )
            
            row = cursor.fetchone()
            return row["receipt_data"] if row else None
    
    def update_receipt_status(
        self,
        receipt_id: str,
        status: str
    ) -> bool:
        """Update the status of a receipt.
        
        Args:
            receipt_id: The ID of the receipt to update.
            status: The new status.
            
        Returns:
            True if the receipt was updated, False otherwise.
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE receipts
                SET status = ?
                WHERE receipt_id = ?
                RETURNING 1
                """,
                (status, receipt_id)
            )
            
            return cursor.fetchone() is not None
