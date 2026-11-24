#!/bin/bash
set -euo pipefail

cd "${CLAUDE_PROJECT_DIR:-.}"

# Point the Understand-Anything skills at the plugin copy in this repository.
# The skills look for the plugin root at $HOME/.understand-anything-plugin.
# Idempotent: ln -sfn replaces an existing link.
PLUGIN_DIR="$PWD/understand-anything/understand-anything-plugin"
if [ -f "$PLUGIN_DIR/pnpm-workspace.yaml" ]; then
  ln -sfn "$PLUGIN_DIR" "$HOME/.understand-anything-plugin"
fi
