#!/usr/bin/env python3
"""
VEX Generation Script for Jenkins SLSA Pipeline
Generates VEX documents with vulnerability analysis
"""

import json
import sys
import uuid
from datetime import datetime
import argparse

def generate_vex_document(output_file, metadata=None):
    """Generate a VEX document structure"""
    if metadata is None:
        metadata = {}
    
    vex = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/{uuid.uuid4()}",
        "author": metadata.get('author', 'Jenkins SLSA Pipeline'),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": 1,
        "statements": []
    }
    
    # Add sample VEX statement (placeholder)
    sample_statement = {
        "vulnerability": {
            "name": "CVE-PLACEHOLDER",
            "description": "Placeholder vulnerability for VEX template"
        },
        "products": [
            {
                "component": metadata.get('component', 'unknown'),
                "version": metadata.get('version', '1.0.0')
            }
        ],
        "status": "not_affected",
        "justification": "component_not_present"
    }
    
    vex["statements"].append(sample_statement)
    
    with open(output_file, 'w') as f:
        json.dump(vex, f, indent=2)
    
    print(f"Generated VEX document: {output_file}")
    return vex

def main():
    parser = argparse.ArgumentParser(description='Generate VEX document for SLSA pipeline')
    parser.add_argument('--output', '-o', default='vex.json', help='Output file path')
    parser.add_argument('--component', help='Component name')
    parser.add_argument('--version', default='1.0.0', help='Component version')
    parser.add_argument('--author', default='Jenkins SLSA Pipeline', help='VEX author')
    
    args = parser.parse_args()
    
    metadata = {
        'component': args.component or 'jenkins-build',
        'version': args.version,
        'author': args.author
    }
    
    # Generate VEX document
    vex = generate_vex_document(args.output, metadata)
    
    print(f"VEX document generated successfully: {args.output}")
    print(f"Statements: {len(vex.get('statements', []))}")

if __name__ == "__main__":
    main()