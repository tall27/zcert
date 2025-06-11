#!/bin/bash
# zcert Tab Completion Setup Script for Replit
# This script sets up tab completion for the current shell session

echo "Setting up zcert tab completion..."

# Enable bash completion
if [ -f /usr/share/bash-completion/bash_completion ]; then
    source /usr/share/bash-completion/bash_completion
fi

# Enable programmable completion
shopt -s progcomp

# Generate and load zcert completion
./zcert config completion --shell bash > zcert-completion.bash
source zcert-completion.bash

echo "✓ Tab completion enabled for zcert"
echo "✓ Try typing: zcert <TAB> or zcert enroll --<TAB>"
echo
echo "To enable completion in new shell sessions, run:"
echo "source setup-completion.sh"