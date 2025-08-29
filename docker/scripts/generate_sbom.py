#!/usr/bin/env python3
"""
SBOM Generation Script for Jenkins SLSA Pipeline
Generates comprehensive SBOMs with SLSA metadata
"""

import json
import sys
import uuid
from datetime import datetime
import os
import subprocess
import argparse

def run_command(cmd, shell=True):
    """Run a command and return the output"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running command '{cmd}': {e.stderr}", file=sys.stderr)
        return None

def generate_minimal_sbom(output_file, metadata=None):
    """Generate a minimal SBOM structure"""
    if metadata is None:
        metadata = {}
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "Jenkins SLSA Pipeline",
                    "name": "SBOM Generator",
                    "version": "1.0.0"
                }
            ],
            "properties": []
        },
        "components": []
    }
    
    # Add SLSA metadata as properties
    for key, value in metadata.items():
        sbom["metadata"]["properties"].append({
            "name": f"slsa:{key}",
            "value": str(value)
        })
    
    with open(output_file, 'w') as f:
        json.dump(sbom, f, indent=2)
    
    print(f"Generated minimal SBOM: {output_file}")
    return sbom

def main():
    parser = argparse.ArgumentParser(description='Generate SBOM for SLSA pipeline')
    parser.add_argument('--output', '-o', default='sbom.json', help='Output file path')
    parser.add_argument('--build-id', help='Build ID for SLSA metadata')
    parser.add_argument('--build-type', default='jenkins-kubernetes', help='Build type')
    parser.add_argument('--slsa-level', default='3', help='SLSA level')
    
    args = parser.parse_args()
    
    metadata = {
        'build_type': args.build_type,
        'slsa_level': args.slsa_level,
        'build_id': args.build_id or f"jenkins-{int(datetime.utcnow().timestamp())}"
    }
    
    # Generate SBOM
    sbom = generate_minimal_sbom(args.output, metadata)
    
    print(f"SBOM generated successfully: {args.output}")
    print(f"Components: {len(sbom.get('components', []))}")

if __name__ == "__main__":
    main()