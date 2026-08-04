//! Build script for quantus-cli.
//!
//! Generates circuit binaries (leaf verifier/common + private/public-batch
//! prover/verifier artifacts) at build time. The leaf circuit has no
//! `prover.bin` — proving uses an in-process fresh build. This keeps the
//! binaries consistent with the circuit crate version and eliminates the need
//! to manually run `quantus developer build-circuits`.
//!
//! Outputs are written to `OUT_DIR` (required by cargo) and, during local source
//! builds only, atomically published to `generated-bins/` in the project root.
//! When the crate is consumed via `cargo install` or `cargo publish` verification,
//! the manifest lives under `~/.cargo/registry/src/` or `target/package/`
//! respectively — locations the installed binary cannot reach — so the project
//! copy is skipped. Installed binaries regenerate the files on first run via
//! `crate::bins::ensure_bins_dir()`.
//!
//! Set `SKIP_CIRCUIT_BUILD=1` to skip circuit generation (useful for CI jobs
//! that don't need the circuits, like clippy/doc checks).

use sha2::{Digest, Sha256};
use std::{env, time::Instant};

include!("src/bins_consts.rs");
include!("src/bins_fs.rs");

/// Compute Poseidon2 hash of bytes and return hex string
fn poseidon_hex(data: &[u8]) -> String {
	let hash = qp_poseidon_core::hash_bytes(data);
	hex::encode(&hash[..16]) // first 16 bytes for shorter display
}

/// Print hash of a generated binary file
fn print_bin_hash(dir: &Path, filename: &str) {
	let path = dir.join(filename);
	if let Ok(data) = std::fs::read(&path) {
		println!(
			"cargo:warning=  {}: {} bytes, hash: {}",
			filename,
			data.len(),
			poseidon_hex(&data)
		);
	}
}

const MANIFESTED_FILES: &[&str] = &[
	"verifier.bin",
	"common.bin",
	"private_batch_prover.bin",
	"private_batch_verifier.bin",
	"private_batch_common.bin",
	"public_batch_prover.bin",
	"public_batch_verifier.bin",
	"public_batch_common.bin",
	"dummy_proof.bin",
	"dummy_private_batch_proof.bin",
	"config.json",
	VERSION_MARKER,
];

fn file_sha256_hex(dir: &Path, filename: &str) -> String {
	let data =
		std::fs::read(dir.join(filename)).expect("Failed to read generated artifact for manifest");
	let mut hasher = Sha256::new();
	hasher.update(&data);
	hex::encode(hasher.finalize())
}

fn json_escape(s: &str) -> String {
	s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn write_manifest(
	dir: &Path,
	pkg_version: &str,
	num_leaf_proofs: usize,
	num_private_batch_proofs: usize,
) {
	let mut content = String::new();
	content.push_str("{\n");
	content.push_str("  \"manifest_version\": 1,\n");
	content.push_str(&format!("  \"package_version\": \"{}\",\n", json_escape(pkg_version)));
	content.push_str(&format!("  \"num_leaf_proofs\": {},\n", num_leaf_proofs));
	content.push_str(&format!("  \"num_private_batch_proofs\": {},\n", num_private_batch_proofs));
	content.push_str("  \"files\": {\n");
	for (idx, filename) in MANIFESTED_FILES.iter().enumerate() {
		let comma = if idx + 1 == MANIFESTED_FILES.len() { "" } else { "," };
		content.push_str(&format!(
			"    \"{}\": \"{}\"{}\n",
			json_escape(filename),
			file_sha256_hex(dir, filename),
			comma
		));
	}
	content.push_str("  }\n}\n");
	std::fs::write(dir.join(MANIFEST_FILE), content).expect("Failed to write artifact manifest");
}

fn main() {
	// Allow skipping circuit generation for CI jobs that don't need it
	if env::var("SKIP_CIRCUIT_BUILD").is_ok() {
		println!(
			"cargo:warning=[quantus-cli] Skipping circuit generation (SKIP_CIRCUIT_BUILD is set)"
		);
		return;
	}

	let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
	let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

	let build_output_dir = Path::new(&out_dir).join("generated-bins");

	let num_leaf_proofs: usize = env::var("QP_NUM_LEAF_PROOFS")
		.map(|v| v.parse().expect("QP_NUM_LEAF_PROOFS must be a valid usize"))
		.unwrap_or(DEFAULT_NUM_LEAF_PROOFS);

	let num_private_batch_proofs: usize = env::var("QP_NUM_PRIVATE_BATCH_PROOFS")
		.map(|v| v.parse().expect("QP_NUM_PRIVATE_BATCH_PROOFS must be a valid usize"))
		.unwrap_or(DEFAULT_NUM_PRIVATE_BATCH_PROOFS);

	// Re-run when QP_NUM_LEAF_PROOFS env var changes. Note: emitting any `rerun-if-*`
	// directive opts out of Cargo's default "re-run when any package file changes"
	// behavior. However, the important cases still work:
	// - Editing DEFAULT_NUM_LEAF_PROOFS in bins_consts.rs triggers a rebuild because
	//   `include!("src/bins_consts.rs")` above creates a dependency on that file.
	// - Circuit crate version bumps (qp-wormhole-circuit-builder) recompile the build script, which
	//   re-runs it.
	// For installed binaries, runtime detection in bins.rs `is_ready()` handles leaf
	// count mismatches by regenerating on first use.
	println!("cargo:rerun-if-env-changed=QP_NUM_LEAF_PROOFS");
	println!("cargo:rerun-if-env-changed=QP_NUM_PRIVATE_BATCH_PROOFS");

	println!(
		"cargo:warning=[quantus-cli] Generating ZK circuit binaries (num_leaf_proofs={}, num_private_batch_proofs={})...",
		num_leaf_proofs, num_private_batch_proofs
	);

	let start = Instant::now();

	std::fs::create_dir_all(&build_output_dir)
		.expect("Failed to create generated-bins directory in OUT_DIR");

	qp_wormhole_circuit_builder::generate_all_circuit_binaries(
		&build_output_dir,
		true,
		num_leaf_proofs,
		Some(num_private_batch_proofs),
	)
	.expect("Failed to generate circuit binaries");

	let pkg_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set");
	std::fs::write(build_output_dir.join(VERSION_MARKER), &pkg_version)
		.expect("Failed to write version marker");
	write_manifest(&build_output_dir, &pkg_version, num_leaf_proofs, num_private_batch_proofs);

	let elapsed = start.elapsed();
	println!(
		"cargo:warning=[quantus-cli] ZK circuit binaries generated in {:.2}s",
		elapsed.as_secs_f64()
	);

	// Print hashes of generated binaries
	print_bin_hash(&build_output_dir, "common.bin");
	print_bin_hash(&build_output_dir, "verifier.bin");
	print_bin_hash(&build_output_dir, "dummy_proof.bin");
	print_bin_hash(&build_output_dir, "private_batch_common.bin");
	print_bin_hash(&build_output_dir, "private_batch_verifier.bin");
	print_bin_hash(&build_output_dir, "private_batch_prover.bin");
	print_bin_hash(&build_output_dir, "public_batch_common.bin");
	print_bin_hash(&build_output_dir, "public_batch_verifier.bin");
	print_bin_hash(&build_output_dir, "public_batch_prover.bin");

	// Atomically publish a real directory (not a symlink) for runtime access.
	// Symlinks are refused by runtime `ensure_bins_dir` (#160699), and the old
	// check/remove/symlink/copy sequence was racy (#160700).
	let project_bins = Path::new(&manifest_dir).join("generated-bins");
	let is_source_build =
		!manifest_dir.contains("target/package/") && !manifest_dir.contains(".cargo/registry/src");
	if is_source_build {
		publish_dir_atomically(&build_output_dir, &project_bins)
			.unwrap_or_else(|e| panic!("Failed to publish generated-bins: {e}"));
	}
}
