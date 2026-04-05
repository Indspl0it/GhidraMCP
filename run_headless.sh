#!/bin/bash
# GhidraMCP Headless Server Launcher
# Usage: ./run_headless.sh <binary_path> [port] [project_dir]
# Example: ./run_headless.sh /path/to/firmware.bin 8080
#
# This script imports a binary into a Ghidra project and starts
# the GhidraMCP HTTP server in headless mode (no GUI required).
#
# Arguments:
#   binary_path  - Path to the binary to analyze (required)
#   port         - HTTP server port (default: 8080)
#   project_dir  - Ghidra project directory (default: /tmp/ghidra_projects)
#
# The server provides the same REST API as the GUI plugin.
# Connect your MCP client to http://localhost:<port>

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <binary_path> [port] [project_dir]"
    echo "Example: $0 /path/to/firmware.bin 8080"
    exit 1
fi

BINARY="$1"
PORT="${2:-8080}"
PROJECT_DIR="${3:-/tmp/ghidra_projects}"
PROJECT_NAME="HeadlessMCP"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)/ghidra_scripts"

# Find Ghidra's analyzeHeadless
if [ -n "$GHIDRA_INSTALL_DIR" ]; then
    ANALYZE_HEADLESS="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
elif [ -x "/usr/share/ghidra/support/analyzeHeadless" ]; then
    ANALYZE_HEADLESS="/usr/share/ghidra/support/analyzeHeadless"
elif command -v analyzeHeadless &> /dev/null; then
    ANALYZE_HEADLESS="analyzeHeadless"
else
    echo "Error: Cannot find analyzeHeadless. Set GHIDRA_INSTALL_DIR or add Ghidra to PATH."
    exit 1
fi

# Create project directory if needed
mkdir -p "$PROJECT_DIR"

echo "GhidraMCP Headless Server"
echo "========================="
echo "Binary:    $BINARY"
echo "Port:      $PORT"
echo "Project:   $PROJECT_DIR/$PROJECT_NAME"
echo "Script:    $SCRIPT_DIR/GhidraMCPServerScript.java"
echo ""

"$ANALYZE_HEADLESS" "$PROJECT_DIR" "$PROJECT_NAME" \
    -import "$BINARY" \
    -postScript GhidraMCPServerScript.java "$PORT" \
    -scriptPath "$SCRIPT_DIR" \
    -overwrite
