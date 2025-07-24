echo "Updating metadata file at src/quantus_metadata.scale..."
subxt metadata --url wss://a.t.res.fm:443 > src/quantus_metadata.scale

echo "Generating SubXT types to src/chain/quantus_subxt.rs..."
subxt codegen --url wss://a.t.res.fm:443 > src/chain/quantus_subxt.rs

echo "Formatting generated code..."
cargo fmt -- src/chain/quantus_subxt.rs

echo "Done!"