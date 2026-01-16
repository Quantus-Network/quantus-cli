#!/bin/bash

# Block Scanner Script
# This script continuously scans blocks for events, starting from a specified block number.
# It increments the block number by 1 each time and queries events from each block.

# Default values
START_BLOCK=${1:-448332}  # Use first argument as start block, default to 448332
NODE_URL=${NODE_URL:-"wss://matcha-latte.quantus.com:443"}  # Allow override via environment variable

DELAY=${DELAY:-1}  # Delay in seconds between requests (default 1 second)

# Set this to your binary path
if [ -f "./target/release/quantus" ]; then
    QUANTUS_CMD="./target/release/quantus"
elif [ -f "./target/debug/quantus" ]; then
    QUANTUS_CMD="./target/debug/quantus"
else
    echo "❌ Error: Could not find quantus binary in target/release or target/debug"
    echo "💡 Please build the project first with: cargo build --release"
    exit 1
fi

echo "🔮 Quantus Block Scanner"
echo "📍 Starting block: $START_BLOCK"
echo "🔗 Node URL: $NODE_URL"
echo "⏱️  Delay between requests: ${DELAY}s"
echo "🎯 Command: $QUANTUS_CMD events --block <block_number> --node-url $NODE_URL"
echo ""

# Check if we can connect to the node first
echo "🔍 Testing connection to node..."
if $QUANTUS_CMD --node-url "$NODE_URL" system --runtime > /dev/null 2>&1; then
    echo "✅ Successfully connected to node"
    echo ""
else
    echo "❌ Failed to connect to node at $NODE_URL"
    echo "💡 Make sure the node is running and accessible"
    exit 1
fi

# Main scanning loop
CURRENT_BLOCK=$START_BLOCK
BLOCKS_SCANNED=0

echo "🚀 Starting block scan..."
echo "Press Ctrl+C to stop scanning"
echo ""

while true; do
    echo "🔍 Scanning block $CURRENT_BLOCK..."

    # Run the events command
    if $QUANTUS_CMD --node-url "$NODE_URL" events --block "$CURRENT_BLOCK" 2>/dev/null; then
        BLOCKS_SCANNED=$((BLOCKS_SCANNED + 1))
        echo "✅ Block $CURRENT_BLOCK scanned successfully ($BLOCKS_SCANNED total)"
    else
        echo "⚠️  Failed to scan block $CURRENT_BLOCK (may not exist yet)"
    fi

    echo ""

    # Increment block number
    CURRENT_BLOCK=$((CURRENT_BLOCK + 1))

    # Add delay between requests
    if [ "$DELAY" -gt 0 ]; then
        sleep "$DELAY"
    fi
done