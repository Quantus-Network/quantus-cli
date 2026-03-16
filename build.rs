//! Build script for quantus-cli.
//!
//! Generates circuit binaries (prover, verifier, aggregator) at build time.
//! This ensures the binaries are always consistent with the circuit crate version
//! and eliminates the need to manually run `quantus developer build-circuits`.

use std::{env, path::Path, time::Instant};

fn main() {
	let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
	let output_dir = Path::new(&manifest_dir).join("generated-bins");

	let num_leaf_proofs: usize = env::var("QP_NUM_LEAF_PROOFS")
		.unwrap_or_else(|_| "16".to_string())
		.parse()
		.expect("QP_NUM_LEAF_PROOFS must be a valid usize");

	// Rerun if the circuit builder crate changes
	println!("cargo:rerun-if-changed=build.rs");

	println!(
		"cargo:warning=[quantus-cli] Generating ZK circuit binaries (num_leaf_proofs={})...",
		num_leaf_proofs
	);

	let start = Instant::now();

	// Create the output directory if it doesn't exist
	std::fs::create_dir_all(&output_dir).expect("Failed to create generated-bins directory");

	// Generate all circuit binaries (leaf + aggregated, WITH prover)
	qp_wormhole_circuit_builder::generate_all_circuit_binaries(
		&output_dir,
		true, // include_prover = true (CLI needs prover for proof generation)
		num_leaf_proofs,
		None, // num_layer0_proofs - no layer-1 aggregation
	)
	.expect("Failed to generate circuit binaries");

	let elapsed = start.elapsed();
	println!(
		"cargo:warning=[quantus-cli] ZK circuit binaries generated in {:.2}s",
		elapsed.as_secs_f64()
	);
}
