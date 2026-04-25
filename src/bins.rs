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

	let num_leaf_proofs = env_num_leaf_proofs()?;
	generate(&dir, num_leaf_proofs)?;
	Ok(dir)
}

fn is_ready(dir: &Path) -> bool {
	if !REQUIRED_BIN_FILES.iter().all(|f| dir.join(f).exists()) {
		return false;
	}
	match std::fs::read_to_string(dir.join(VERSION_MARKER)) {
		Ok(v) => v.trim() == env!("CARGO_PKG_VERSION"),
		Err(_) => false,
	}
}

fn env_num_leaf_proofs() -> Result<usize> {
	let num_leaf_proofs = std::env::var("QP_NUM_LEAF_PROOFS")
		.ok()
		.and_then(|v| v.parse().ok())
		.unwrap_or(DEFAULT_NUM_LEAF_PROOFS);
	if num_leaf_proofs != DEFAULT_NUM_LEAF_PROOFS {
		return Err(QuantusError::Generic(
			"PR #129 shipping layer-0 aggregation is fixed at 16 leaves. Set QP_NUM_LEAF_PROOFS=16 or unset it.".to_string(),
		));
	}
	Ok(num_leaf_proofs)
}

fn remove_existing_path(path: &Path) -> Result<()> {
	if let Ok(metadata) = std::fs::symlink_metadata(path) {
		if metadata.file_type().is_symlink() || !metadata.is_dir() {
			std::fs::remove_file(path).map_err(|e| {
				QuantusError::Generic(format!(
					"Failed to remove existing bins file {}: {}",
					path.display(),
					e
				))
			})?;
		} else {
			std::fs::remove_dir_all(path).map_err(|e| {
				QuantusError::Generic(format!(
					"Failed to remove existing bins directory {}: {}",
					path.display(),
					e
				))
			})?;
		}
	}
	Ok(())
}

fn generate(dir: &Path, num_leaf_proofs: usize) -> Result<()> {
	remove_existing_path(dir)?;
	std::fs::create_dir_all(dir).map_err(|e| {
		QuantusError::Generic(format!("Failed to create bins directory {}: {}", dir.display(), e))
	})?;

	log_print!("");
	log_print!("🛠️  Generating ZK circuit binaries (first-time setup, ~30s)...");
	log_print!("   Target: {}", dir.display());
	log_print!("   num_leaf_proofs: {}", num_leaf_proofs);

	let start = std::time::Instant::now();
	qp_wormhole_circuit_builder::generate_all_circuit_binaries(
		dir,
		true,
		DEFAULT_NUM_LEAF_PROOFS,
		None,
	)
	.map_err(|e| QuantusError::Generic(format!("Failed to generate circuit binaries: {}", e)))?;

	std::fs::write(dir.join(VERSION_MARKER), env!("CARGO_PKG_VERSION"))
		.map_err(|e| QuantusError::Generic(format!("Failed to write version marker: {}", e)))?;

	let elapsed = start.elapsed();
	log_success!("Circuit binaries ready in {:.1}s", elapsed.as_secs_f64());
	log_print!("");
	Ok(())
}
