#!/usr/bin/env python3
"""
Visualize the Merkle Tree of the Transparency Log

This script generates a visualization of the Merkle tree used in the transparency log,
showing the structure and hashes of the tree nodes. This can be useful for debugging
and understanding how the log works.
"""

import argparse
import hashlib
import json
import math
import os
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class MerkleTreeVisualizer:
    """Class for visualizing the Merkle tree of the transparency log."""
    
    def __init__(self, db_path: str):
        """Initialize the visualizer with the path to the database."""
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database file not found: {self.db_path}")
        
        # Tree visualization settings
        self.node_width = 20  # Width of each node in characters
        self.max_depth = 10   # Maximum depth to visualize
        self.max_width = 120  # Maximum width of the visualization
    
    def get_tree_data(self) -> Dict[str, Any]:
        """
        Retrieve the Merkle tree data from the database.
        
        Returns:
            A dictionary containing the tree data.
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get the tree size
        cursor.execute("SELECT COUNT(*) as count FROM receipts;")
        tree_size = cursor.fetchone()['count']
        
        # Get the Merkle root
        cursor.execute("SELECT root_hash FROM tree_state WHERE id = 1;")
        root_hash = cursor.fetchone()['root_hash']
        
        # Get all nodes in the tree
        cursor.execute("SELECT * FROM tree_nodes ORDER BY level, node_index;")
        nodes = [dict(row) for row in cursor.fetchall()]
        
        # Get all receipts
        cursor.execute("SELECT * FROM receipts ORDER BY id;")
        receipts = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'tree_size': tree_size,
            'root_hash': root_hash,
            'nodes': nodes,
            'receipts': receipts
        }
    
    def build_tree_structure(self, tree_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a hierarchical structure of the Merkle tree.
        
        Args:
            tree_data: The tree data from get_tree_data().
            
        Returns:
            A hierarchical dictionary representing the tree.
        """
        # Group nodes by level
        nodes_by_level = {}
        for node in tree_data['nodes']:
            level = node['level']
            if level not in nodes_by_level:
                nodes_by_level[level] = []
            nodes_by_level[level].append(node)
        
        # Sort each level by node index
        for level in nodes_by_level:
            nodes_by_level[level].sort(key=lambda x: x['node_index'])
        
        # Build the tree recursively
        def build_node(level: int, index: int) -> Dict[str, Any]:
            """Recursively build a node and its children."""
            if level not in nodes_by_level or index >= len(nodes_by_level[level]):
                return None
                
            node_data = nodes_by_level[level][index]
            node = {
                'hash': node_data['hash'],
                'is_leaf': level == 0,
                'index': node_data['node_index'],
                'level': level,
                'left': None,
                'right': None
            }
            
            # If this is a leaf node, add receipt info
            if level == 0 and node_data.get('receipt_id'):
                receipt = next(
                    (r for r in tree_data['receipts'] if r['id'] == node_data['receipt_id']), 
                    None
                )
                if receipt:
                    node['receipt'] = {
                        'id': receipt['id'],
                        'timestamp': receipt.get('timestamp'),
                        'task_id': receipt.get('task_id', '')
                    }
            
            # Recursively build children for non-leaf nodes
            if level > 0:
                left_child = build_node(level - 1, index * 2)
                right_child = build_node(level - 1, index * 2 + 1)
                
                node['left'] = left_child
                node['right'] = right_child
            
            return node
        
        # Calculate the depth of the tree
        depth = max(nodes_by_level.keys()) if nodes_by_level else 0
        
        # Build the tree starting from the root
        root = build_node(depth, 0) if depth >= 0 else None
        
        return {
            'root': root,
            'depth': depth,
            'size': tree_data['tree_size']
        }
    
    def visualize_tree(self, tree_structure: Dict[str, Any]) -> str:
        """
        Generate a text-based visualization of the Merkle tree.
        
        Args:
            tree_structure: The tree structure from build_tree_structure().
            
        Returns:
            A string containing the visualization.
        """
        if not tree_structure or not tree_structure['root']:
            return "Empty tree"
        
        lines = []
        
        # Add header
        lines.append(f"{Colors.HEADER}{Colors.BOLD}Merkle Tree Visualization{Colors.ENDC}")
        lines.append(f"Size: {tree_structure['size']} receipts")
        lines.append(f"Depth: {tree_structure['depth']} levels")
        lines.append(f"Root: {self._short_hash(tree_structure['root']['hash'])}")
        lines.append("")
        
        # Calculate the maximum depth to display
        max_display_depth = min(tree_structure['depth'], self.max_depth)
        
        # Generate the tree visualization level by level
        for level in range(max_display_depth + 1):
            level_nodes = self._get_nodes_at_level(tree_structure['root'], level, 0, max_display_depth)
            
            # Skip empty levels
            if not level_nodes:
                continue
            
            # Add level header
            if level == 0:
                level_name = "Leaf Nodes (Receipts)"
            elif level == tree_structure['depth']:
                level_name = f"Root (Level {level})"
            else:
                level_name = f"Level {level}"
            
            lines.append(f"\n{Colors.UNDERLINE}{level_name}{Colors.ENDC}")
            
            # Add nodes at this level
            for node in level_nodes:
                if node is None:
                    continue
                
                # Format the node
                if node['is_leaf'] and 'receipt' in node:
                    receipt = node['receipt']
                    node_str = (
                        f"Receipt #{receipt['id']} | "
                        f"{receipt.get('task_id', '')[:20]}... | "
                        f"{self._short_hash(node['hash'])}"
                    )
                else:
                    node_str = self._short_hash(node['hash'])
                
                # Add indentation based on the node's position
                indent = ' ' * (node['pos'] * (self.node_width + 2))
                lines.append(f"{indent}{node_str}")
                
                # Add connection lines for non-leaf nodes
                if not node['is_leaf']:
                    conn_indent = ' ' * (node['pos'] * (self.node_width + 2) + 3)
                    conn_line = '|'.ljust(self.node_width - 4, '-')
                    lines.append(f"{conn_indent}/{conn_line}\\ ")
        
        # Add a note if the tree was truncated
        if tree_structure['depth'] > max_display_depth:
            lines.append(
                f"\n{Colors.WARNING}Note: Tree truncated at depth {max_display_depth} "
                f"(total depth: {tree_structure['depth']}){Colors.ENDC}"
            )
        
        return '\n'.join(lines)
    
    def _get_nodes_at_level(self, node: Dict[str, Any], target_level: int, 
                          current_level: int, max_level: int) -> List[Optional[Dict]]:
        """
        Get all nodes at a specific level of the tree.
        
        Args:
            node: The current node.
            target_level: The level to collect nodes from.
            current_level: The level of the current node.
            max_level: Maximum level to traverse.
            
        Returns:
            A list of nodes at the target level, with their positions.
        """
        if current_level > max_level:
            return []
        
        if current_level == target_level:
            # Calculate position based on the node's index at its level
            pos = node['index'] * (2 ** (max_level - current_level))
            return [{'hash': node['hash'], 
                    'is_leaf': node['is_leaf'],
                    'pos': pos,
                    'receipt': node.get('receipt')}]
        
        if current_level < target_level:
            left_nodes = []
            right_nodes = []
            
            if node['left']:
                left_nodes = self._get_nodes_at_level(
                    node['left'], target_level, current_level + 1, max_level
                )
            
            if node['right']:
                right_nodes = self._get_nodes_at_level(
                    node['right'], target_level, current_level + 1, max_level
                )
            
            return left_nodes + right_nodes
        
        return []
    
    @staticmethod
    def _short_hash(hash_str: str, length: int = 8) -> str:
        """Shorten a hash string for display."""
        if not hash_str:
            return ""
        
        if len(hash_str) <= length + 2:
            return hash_str
        
        return f"{hash_str[:length//2]}...{hash_str[-length//2:]}"

def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(description='Visualize the Merkle tree of the transparency log')
    parser.add_argument('--db', default='data/transparency_log.db',
                      help='Path to the transparency log database')
    parser.add_argument('--max-depth', type=int, default=4,
                      help='Maximum depth to visualize (default: 4)')
    parser.add_argument('--output', '-o',
                      help='Output file (default: print to console)')
    
    args = parser.parse_args()
    
    try:
        # Create the visualizer
        visualizer = MerkleTreeVisualizer(args.db)
        visualizer.max_depth = args.max_depth
        
        # Get the tree data
        tree_data = visualizer.get_tree_data()
        
        # Build the tree structure
        tree_structure = visualizer.build_tree_structure(tree_data)
        
        # Generate the visualization
        visualization = visualizer.visualize_tree(tree_structure)
        
        # Output the result
        if args.output:
            with open(args.output, 'w') as f:
                # Strip ANSI color codes when writing to file
                import re
                clean_visualization = re.sub(r'\x1b\[[0-9;]*[mK]', '', visualization)
                f.write(clean_visualization)
            print(f"Visualization saved to {args.output}")
        else:
            print(visualization)
        
        return 0
        
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
