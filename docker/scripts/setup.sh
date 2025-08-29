#!/bin/bash
# Setup script for Jenkins SLSA security agent

set -euo pipefail

echo "=== Jenkins SLSA Security Agent Setup ==="

# Create necessary directories
mkdir -p /tmp/slsa-work
mkdir -p /home/jenkins/.cache
mkdir -p /home/jenkins/.config

# Set proper permissions
chown -R jenkins:jenkins /home/jenkins/.cache
chown -R jenkins:jenkins /home/jenkins/.config

# Initialize tool caches
echo "Initializing tool caches..."
trivy image --download-db-only || echo "Trivy DB initialization skipped"

echo "=== Setup completed successfully ==="