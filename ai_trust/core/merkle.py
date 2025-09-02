"""
Merkle Tree implementation for the transparency log.
"""

import hashlib
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple, Union

from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Domain separation tags for Merkle tree hashing
LEAF_NODE_PREFIX = b'\x00'  # Prefix for leaf nodes
INTERNAL_NODE_PREFIX = b'\x01'  # Prefix for internal nodes


@dataclass
class Node:
    """A node in the Merkle tree."""
    hash: bytes
    left: Optional['Node'] = None
    right: Optional['Node'] = None
    leaf_index: Optional[int] = None


class MerkleTree:
    """
    A binary Merkle tree for efficient membership and consistency proofs.
    
    This implementation follows RFC 6962 (Certificate Transparency) for hashing
    and proof generation.
    """
    
    def __init__(self, leaves: Optional[List[bytes]] = None):
        """Initialize a new Merkle tree with the given leaves."""
        self.leaves: List[bytes] = leaves or []
        self.root: Optional[Node] = None
        self.tree_size: int = 0
        self._build_tree()
    
    def _hash_leaf(self, data: bytes) -> bytes:
        """Hash a leaf node with domain separation."""
        return hashlib.sha256(LEAF_NODE_PREFIX + data).digest()
    
    def _hash_internal(self, left: bytes, right: bytes) -> bytes:
        """Hash an internal node with domain separation."""
        return hashlib.sha256(INTERNAL_NODE_PREFIX + left + right).digest()
    
    def _build_tree(self) -> None:
        """Build or rebuild the Merkle tree from the current leaves."""
        if not self.leaves:
            self.root = None
            self.tree_size = 0
            return
        
        # Hash all leaves
        nodes = [
            Node(hash=self._hash_leaf(leaf), leaf_index=i)
            for i, leaf in enumerate(self.leaves)
        ]
        self.tree_size = len(nodes)
        
        # Build the tree from the leaves up
        while len(nodes) > 1:
            # If odd number of nodes, duplicate the last one
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            
            # Pair up nodes and hash them together
            new_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i+1]
                parent = Node(
                    hash=self._hash_internal(left.hash, right.hash),
                    left=left,
                    right=right
                )
                new_level.append(parent)
            
            nodes = new_level
        
        self.root = nodes[0] if nodes else None
    
    def add_leaf(self, data: bytes) -> int:
        """Add a new leaf to the tree and return its index."""
        index = len(self.leaves)
        self.leaves.append(data)
        self._build_tree()  # Rebuild the tree
        return index
    
    def get_root_hash(self) -> Optional[bytes]:
        """Get the root hash of the tree."""
        return self.root.hash if self.root else None
    
    def get_leaf_hash(self, index: int) -> Optional[bytes]:
        """Get the hash of a leaf node by its index."""
        if index < 0 or index >= len(self.leaves):
            return None
        return self._hash_leaf(self.leaves[index])
    
    def get_inclusion_proof(
        self,
        leaf_index: int,
        tree_size: Optional[int] = None
    ) -> Optional[List[bytes]]:
        """
        Generate a Merkle inclusion proof for a leaf.
        
        Args:
            leaf_index: The index of the leaf to prove inclusion for.
            tree_size: The size of the tree to generate the proof against.
                      If None, uses the current tree size.
                      
        Returns:
            A list of sibling hashes from leaf to root, or None if the proof
            cannot be generated.
        """
        if tree_size is None:
            tree_size = self.tree_size
        
        if leaf_index < 0 or leaf_index >= tree_size:
            return None
        
        if tree_size > self.tree_size:
            # Requesting a proof for a future tree size is not supported
            return None
        
        proof = []
        node = self.root
        node_size = self.tree_size
        
        # Find the path to the leaf
        while node and node.leaf_index is None:  # Not a leaf node
            left_size = self._count_leaves(node.left) if node.left else 0
            
            if leaf_index < left_size:
                # Leaf is in the left subtree
                if node.right:
                    proof.append(node.right.hash)
                node = node.left
            else:
                # Leaf is in the right subtree
                if node.left:
                    proof.append(node.left.hash)
                node = node.right
                leaf_index -= left_size
        
        return proof
    
    def verify_inclusion_proof(
        self,
        leaf_hash: bytes,
        proof: List[bytes],
        leaf_index: int,
        tree_size: int,
        root_hash: bytes
    ) -> bool:
        """
        Verify a Merkle inclusion proof.
        
        Args:
            leaf_hash: The hash of the leaf to verify.
            proof: List of sibling hashes from leaf to root.
            leaf_index: The index of the leaf.
            tree_size: The size of the tree when the proof was generated.
            root_hash: The expected root hash of the tree.
            
        Returns:
            True if the proof is valid, False otherwise.
        """
        if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
            return False
        
        # Special case: empty tree or single node
        if tree_size == 1:
            return len(proof) == 0 and leaf_hash == root_hash
        
        # Calculate the node indices along the path from leaf to root
        path = []
        idx = leaf_index
        size = tree_size
        
        while size > 1:
            if size == 0:
                return False
            
            # Determine if we're a right or left child
            is_right = idx % 2
            sibling_idx = idx - 1 if is_right else idx + 1
            
            # Add the sibling to the path if it exists
            if sibling_idx < size - 1 or (sibling_idx == size - 1 and size % 2 == 1):
                # Sibling exists in this level
                path.append((is_right, sibling_idx < size - 1))
            
            # Move up the tree
            idx = idx // 2
            size = (size + 1) // 2
        
        # Rebuild the root hash from the leaf and proof
        computed_hash = leaf_hash
        proof_idx = 0
        
        for is_right, has_sibling in path:
            if not has_sibling and proof_idx < len(proof):
                # This should not happen with a valid proof
                return False
            
            if has_sibling:
                if proof_idx >= len(proof):
                    return False
                
                sibling_hash = proof[proof_idx]
                proof_idx += 1
                
                if is_right:
                    computed_hash = self._hash_internal(sibling_hash, computed_hash)
                else:
                    computed_hash = self._hash_internal(computed_hash, sibling_hash)
        
        # Verify we used all proof hashes
        if proof_idx != len(proof):
            return False
        
        return computed_hash == root_hash
    
    def get_consistency_proof(
        self,
        first: int,
        second: int
    ) -> Optional[List[bytes]]:
        """
        Generate a consistency proof between two tree states.
        
        Args:
            first: The size of the first tree.
            second: The size of the second tree (must be >= first).
            
        Returns:
            A list of hashes that can be used to verify consistency, or None
            if the proof cannot be generated.
        """
        if first < 0 or second < first or second > self.tree_size:
            return None
        
        if first == 0:
            # A consistency proof from size 0 is always valid
            return []
        
        if first == second:
            # Empty proof for identical tree sizes
            return []
        
        # Find the nodes that are on the right boundary of the first tree
        proof = []
        node = self.root
        node_size = self.tree_size
        
        # Traverse the tree to find the consistency proof
        while node and node_size > 1:
            left_size = self._count_leaves(node.left) if node.left else 0
            
            if first <= left_size:
                # The split is in the left subtree
                if node.right:
                    proof.append(node.right.hash)
                node = node.left
                node_size = left_size
            else:
                # The split is in the right subtree
                node = node.right
                first -= left_size
                node_size -= left_size
        
        return proof
    
    @staticmethod
    def verify_consistency_proof(
        first_root: bytes,
        second_root: bytes,
        first_size: int,
        second_size: int,
        proof: List[bytes]
    ) -> bool:
        """
        Verify a consistency proof between two tree states.
        
        Args:
            first_root: The root hash of the first tree.
            second_root: The root hash of the second tree.
            first_size: The size of the first tree.
            second_size: The size of the second tree.
            proof: The consistency proof.
            
        Returns:
            True if the proof is valid, False otherwise.
        """
        if first_size < 0 or second_size < first_size:
            return False
        
        if first_size == 0:
            # Empty tree is consistent with any tree
            return True
        
        if first_size == second_size:
            # Trees are identical
            return first_root == second_root
        
        # Verify the proof
        tree = MerkleTree()
        proof_idx = 0
        
        # Reconstruct the first root
        first_node = tree._build_subtree(first_size, 0, first_size - 1, proof, proof_idx)
        if not first_node or first_node.hash != first_root:
            return False
        
        # Reconstruct the second root
        second_node = tree._build_subtree(second_size, 0, second_size - 1, proof, proof_idx)
        if not second_node or second_node.hash != second_root:
            return False
        
        return True
    
    def _build_subtree(
        self,
        size: int,
        start: int,
        end: int,
        proof: List[bytes],
        proof_idx: int
    ) -> Optional[Node]:
        """Recursively build a subtree from a consistency proof."""
        if start > end or start >= size or end >= size:
            return None
        
        if start == end:
            # Leaf node
            return Node(hash=self._hash_leaf(self.leaves[start]), leaf_index=start)
        
        # Find the largest power of 2 less than size
        split = 1 << (size.bit_length() - 1)
        if split * 2 <= size:
            split *= 2
        
        if end < split:
            # Entire range is in the left subtree
            return self._build_subtree(split, start, end, proof, proof_idx)
        elif start >= split:
            # Entire range is in the right subtree
            return self._build_subtree(size - split, start - split, end - split, proof, proof_idx)
        else:
            # Range spans both subtrees
            left = self._build_subtree(split, start, split - 1, proof, proof_idx)
            right = self._build_subtree(size - split, 0, end - split, proof, proof_idx)
            
            if not left or not right:
                return None
            
            return Node(
                hash=self._hash_internal(left.hash, right.hash),
                left=left,
                right=right
            )
    
    def _count_leaves(self, node: Optional[Node]) -> int:
        """Count the number of leaves under a node."""
        if not node:
            return 0
        if node.leaf_index is not None:
            return 1
        return self._count_leaves(node.left) + self._count_leaves(node.right)


class MerkleTreeProof(BaseModel):
    """A Merkle tree proof (inclusion or consistency)."""
    leaf_index: int
    tree_size: int
    root_hash: str
    proof_hashes: List[str]
    
    class Config:
        json_encoders = {
            bytes: lambda v: v.hex() if v else None
        }


class ConsistencyProof(BaseModel):
    """A consistency proof between two tree states."""
    first_size: int
    second_size: int
    first_root: str
    second_root: str
    proof_hashes: List[str]
    
    class Config:
        json_encoders = {
            bytes: lambda v: v.hex() if v else None
        }
