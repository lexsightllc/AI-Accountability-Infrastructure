"""
Core functionality for the AI Accountability Infrastructure.

This package contains the core components and utilities for the AI Accountability system,
including the Merkle tree implementation, proof generation, and verification logic.
"""

from .merkle import MerkleTree, Node, MerkleTreeProof, ConsistencyProof

__all__ = ['MerkleTree', 'Node', 'MerkleTreeProof', 'ConsistencyProof']
