//! Circuit binaries path resolution and lazy generation.
//!
//! The CLI needs access to several large ZK-circuit files (`prover.bin`,
//! `verifier.bin`, `aggregated_*.bin`, etc.). During `cargo build`/`cargo install`
//! these are produced by `build.rs` into `$OUT_DIR/generated-bins/`, but
//! `cargo install` does not copy build-script outputs alongside the installed
//! executable. To make installed binaries self-sufficient, this module resolves
//! a persistent storage location and regenerates the binaries there on demand.
//!
//! Resolution order:
//! 1. `QUANTUS_BINS_DIR` env var (explicit override).
//! 2. `./generated-bins/` in the current directory (local dev).
//! 3. `~/.quantus/generated-bins/` (default for installed binaries).

use crate::{
	error::{QuantusError, Result},
	log_print, log_success,
};
use std::path::{Path, PathBuf};

include!("bins_consts.rs");

/// Environment variable used to override the bins directory.
pub const BINS_DIR_ENV: &str = "QUANTUS_BINS_DIR";

/// Files that must be present for all wormhole operations to succeed.
const REQUIRED_FILES: &[&str] = &[
	"prover.bin",
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
];

/// Resolve the path where circuit binaries should live.
///
/// This never generates anything; see [`ensure_bins_dir`] for the full
/// resolve-and-generate flow.
pub fn resolve_bins_dir() -> PathBuf {
	if let Ok(dir) = std::env::var(BINS_DIR_ENV) {
		return PathBuf::from(dir);
	}

	let cwd_dir = PathBuf::from("generated-bins");
	if cwd_dir.join("config.json").exists() {
		return cwd_dir;
	}

	user_bins_dir()
}

/// Location used for auto-generated binaries on installed systems.
fn user_bins_dir() -> PathBuf {
	dirs::home_dir()
		.expect("Could not determine home directory for ~/.quantus/generated-bins")
		.join(".quantus")
		.join("generated-bins")
}

/// Resolve the bins directory and generate any missing circuit binaries.
///
/// Safe to call multiple times; regeneration only happens when the target is
/// empty, partially populated, or was produced by a different CLI version.
pub fn ensure_bins_dir() -> Result<PathBuf> {
	let dir = resolve_bins_dir();

	if is_ready(&dir) {
		return Ok(dir);
	}

	let num_leaf_proofs = env_num_leaf_proofs();
	let num_private_batch_proofs = env_num_private_batch_proofs();
	generate(&dir, num_leaf_proofs, num_private_batch_proofs)?;
	Ok(dir)
}

fn is_ready(dir: &Path) -> bool {
	if !REQUIRED_FILES.iter().all(|f| dir.join(f).exists()) {
		return false;
	}
	// Check CLI version matches
	let version_ok = match std::fs::read_to_string(dir.join(VERSION_MARKER)) {
		Ok(v) => v.trim() == env!("CARGO_PKG_VERSION"),
		Err(_) => return false,
	};
	if !version_ok {
		return false;
	}
	// Check circuit sizing in config.json matches current settings
	let config_path = dir.join("config.json");
	match std::fs::read_to_string(&config_path) {
		Ok(content) => {
			// Parse just the sizing fields to avoid pulling in full config dependency
			#[derive(serde::Deserialize)]
			struct ConfigCheck {
				num_leaf_proofs: usize,
				#[serde(default, alias = "num_layer0_proofs")]
				num_private_batch_proofs: Option<usize>,
			}
			match serde_json::from_str::<ConfigCheck>(&content) {
				Ok(config) =>
					config.num_leaf_proofs == env_num_leaf_proofs() &&
						config.num_private_batch_proofs == Some(env_num_private_batch_proofs()),
				Err(_) => false,
			}
		},
		Err(_) => false,
	}
}

fn env_num_leaf_proofs() -> usize {
	std::env::var("QP_NUM_LEAF_PROOFS")
		.ok()
		.and_then(|v| v.parse().ok())
		.unwrap_or(DEFAULT_NUM_LEAF_PROOFS)
}

fn env_num_private_batch_proofs() -> usize {
	std::env::var("QP_NUM_PRIVATE_BATCH_PROOFS")
		.ok()
		.and_then(|v| v.parse().ok())
		.unwrap_or(DEFAULT_NUM_PRIVATE_BATCH_PROOFS)
}

fn generate(dir: &Path, num_leaf_proofs: usize, num_private_batch_proofs: usize) -> Result<()> {
	std::fs::create_dir_all(dir).map_err(|e| {
		QuantusError::Generic(format!("Failed to create bins directory {}: {}", dir.display(), e))
	})?;

	log_print!("");
	log_print!("🛠️  Generating ZK circuit binaries (first-time setup, ~30s)...");
	log_print!("   Target: {}", dir.display());
	log_print!("   num_leaf_proofs: {}", num_leaf_proofs);
	log_print!("   num_private_batch_proofs: {}", num_private_batch_proofs);

	let start = std::time::Instant::now();
	qp_wormhole_circuit_builder::generate_all_circuit_binaries(
		dir,
		true,
		num_leaf_proofs,
		Some(num_private_batch_proofs),
	)
	.map_err(|e| QuantusError::Generic(format!("Failed to generate circuit binaries: {}", e)))?;

	std::fs::write(dir.join(VERSION_MARKER), env!("CARGO_PKG_VERSION"))
		.map_err(|e| QuantusError::Generic(format!("Failed to write version marker: {}", e)))?;

	let elapsed = start.elapsed();
	log_success!("Circuit binaries ready in {:.1}s", elapsed.as_secs_f64());
	log_print!("");
	Ok(())
}
