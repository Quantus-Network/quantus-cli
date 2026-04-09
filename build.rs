//! Build script for quantus-cli.
//!
//! Generates circuit binaries (prover, verifier, aggregator) at build time.
//! This ensures the binaries are always consistent with the circuit crate version
//! and eliminates the need to manually run `quantus developer build-circuits`.
//!
//! Outputs are written to `OUT_DIR` (required by cargo) and then copied to
//! `generated-bins/` in the project root for runtime access — but only during
//! normal builds, **not** during `cargo publish` verification where modifying the
//! source directory is forbidden.

use std::{env, path::Path, time::Instant};

fn main() {
	let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
	let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

	let build_output_dir = Path::new(&out_dir).join("generated-bins");

	let num_leaf_proofs: usize = env::var("QP_NUM_LEAF_PROOFS")
		.unwrap_or_else(|_| "16".to_string())
		.parse()
		.expect("QP_NUM_LEAF_PROOFS must be a valid usize");

	println!("cargo:rerun-if-changed=build.rs");

	println!(
		"cargo:warning=[quantus-cli] Generating ZK circuit binaries (num_leaf_proofs={})...",
		num_leaf_proofs
	);

	let start = Instant::now();

	std::fs::create_dir_all(&build_output_dir)
		.expect("Failed to create generated-bins directory in OUT_DIR");

	qp_wormhole_circuit_builder::generate_all_circuit_binaries(
		&build_output_dir,
		true,
		num_leaf_proofs,
		None,
	)
	.expect("Failed to generate circuit binaries");

	let elapsed = start.elapsed();
	println!(
		"cargo:warning=[quantus-cli] ZK circuit binaries generated in {:.2}s",
		elapsed.as_secs_f64()
	);

	// Copy bins to project root for runtime access, but NOT during `cargo publish`
	// verification (manifest_dir is inside target/package/ in that case).
	let project_bins = Path::new(&manifest_dir).join("generated-bins");
	if !manifest_dir.contains("target/package/") {
		// Prefer a symlink to avoid copying large prover binaries on every build.
		// If symlink creation fails (e.g. on filesystems without symlink support),
		// fall back to copying and surface errors.
		#[cfg(unix)]
		{
			use std::os::unix::fs::symlink;
			// Remove any existing dir/file/symlink at destination.
			if let Ok(meta) = std::fs::symlink_metadata(&project_bins) {
				if meta.is_dir() {
					std::fs::remove_dir_all(&project_bins)
						.expect("Failed to remove existing generated-bins directory");
				} else {
					std::fs::remove_file(&project_bins)
						.expect("Failed to remove existing generated-bins file/symlink");
				}
			}
			if let Err(e) = symlink(&build_output_dir, &project_bins) {
				println!(
					"cargo:warning=[quantus-cli] Failed to symlink generated-bins ({}). Falling back to copy...",
					e
				);
			} else {
				// Symlink created successfully; we're done.
				return;
			}
		}

		std::fs::create_dir_all(&project_bins).expect("Failed to create generated-bins directory");
		let entries = std::fs::read_dir(&build_output_dir)
			.expect("Failed to read generated-bins directory in OUT_DIR");
		for entry in entries {
			let entry = entry.expect("Failed to read generated-bins entry");
			let dest = project_bins.join(entry.file_name());
			std::fs::copy(entry.path(), dest).expect("Failed to copy generated-bins file");
		}
	}
}
