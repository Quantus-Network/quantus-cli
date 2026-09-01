#!/bin/bash
set -euo pipefail

# Default node URL
NODE_URL="ws://127.0.0.1:9944"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --node-url)
            NODE_URL="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--node-url <URL>]"
            echo "  --node-url <URL>  Node endpoint URL (default: ws://127.0.0.1:9944)"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

echo "Using node URL: $NODE_URL"
echo "Updating metadata file at src/quantus_metadata.scale..."
subxt metadata --url "$NODE_URL" > src/quantus_metadata.scale

echo "Generating SubXT types to src/chain/quantus_subxt.rs..."
# `multisig.execute` carries a RuntimeCall, and the CLI decodes the proposal's stored
# bytes back into one and re-encodes it, so the call surface needs codec's Decode and
# Encode alongside DecodeAsType/EncodeAsType.
subxt codegen --url "$NODE_URL" \
    --derive-for-type quantus_runtime::RuntimeCall=codec::Decode,recursive \
    --derive-for-type quantus_runtime::RuntimeCall=codec::Encode,recursive \
    > src/chain/quantus_subxt.rs

echo "Formatting generated code..."
# Generated SubXT code may require nightly rustfmt.
cargo +nightly fmt -- src/chain/quantus_subxt.rs

echo "Reminder: update src/config/mod.rs with the new compatible spec/transaction version pair."
echo "Done!"
