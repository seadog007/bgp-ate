#!/bin/bash

# Exit on error
set -e

# Create GoBGP directory in current path
GOBGP_DIR="$(pwd)/gobgpbin"
mkdir -p "$GOBGP_DIR"
cd "$GOBGP_DIR"

# Download and install GoBGP v3.37.0
wget https://github.com/osrg/gobgp/releases/download/v3.37.0/gobgp_3.37.0_linux_amd64.tar.gz
tar xzf gobgp_3.37.0_linux_amd64.tar.gz
rm gobgp_3.37.0_linux_amd64.tar.gz

# Verify installation
echo "Verifying GoBGP installation..."
"$GOBGP_DIR/gobgpd" --version
"$GOBGP_DIR/gobgp" --version

echo "GoBGP v3.37.0 has been installed successfully in $GOBGP_DIR"
echo "To use GoBGP, run the binaries directly from $GOBGP_DIR or add it to your PATH" 