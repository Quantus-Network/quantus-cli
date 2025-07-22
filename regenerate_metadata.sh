echo "Updating metadata file at src/quantus_metadata.scale..."
subxt metadata --url ws://127.0.0.1:9944 > src/quantus_metadata.scale

echo "Generating SubXT types to src/chain/quantus_subxt.rs..."
subxt codegen --url ws://127.0.0.1:9944 > src/chain/quantus_subxt.rs

echo "Formatting generated code..."
cargo fmt -- src/chain/quantus_subxt.rs

echo "Done!"