#!/bin/bash
# Setup script for zcert tab completion in Replit environment
# This script enables bash completion and generates the completion files

echo "Setting up zcert tab completion..."

# Check if zcert binary exists
if [ ! -f "./zcert" ]; then
    echo "Error: zcert binary not found in current directory"
    echo "Please run: go build -o zcert main.go"
    exit 1
fi

# Enable programmable completion
shopt -s progcomp

# Generate and load zcert completion
./zcert config completion --shell bash > zcert-completion.bash
source zcert-completion.bash

echo "✓ Tab completion enabled for zcert and ./zcert"
echo "✓ Try typing: zcert <TAB> or ./zcert enroll --<TAB>"
echo
echo "To enable completion in new shell sessions, run:"
echo "source setup-completion.sh"
