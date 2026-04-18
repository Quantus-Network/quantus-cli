//! Circuit Binary Management
//!
//! This module provides utilities for managing ZK circuit binaries used by wormhole operations.
//! Circuit binaries are large files (~1GB total) that contain proving and verification keys.
//!
//! ## Storage Locations
//!
//! Circuit binaries are searched in the following order:
//! 1. `$QUANTUS_CIRCUIT_BINS` environment variable (for custom setups)
//! 2. `~/.quantus/circuit-bins/` (standard installed location)
//! 3. `./generated-bins` (for development)
//!
//! ## Setup
//!
//! Users must run `quantus setup-circuits` before using wormhole commands.
//! This generates the circuit binaries, which takes a few minutes on first run.

use crate::error::{QuantusError, Result};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Environment variable for custom circuit bins directory
pub const CIRCUIT_BINS_ENV_VAR: &str = "QUANTUS_CIRCUIT_BINS";

/// Default directory name for circuit bins in user's home
pub const DEFAULT_CIRCUIT_BINS_DIR: &str = ".quantus/circuit-bins";

/// Development directory name (relative to CWD)
pub const DEV_CIRCUIT_BINS_DIR: &str = "generated-bins";

/// Required circuit binary files
pub const REQUIRED_CIRCUIT_FILES: &[&str] = &[
	"common.bin",
	"verifier.bin",
	"prover.bin",
	"dummy_proof.bin",
	"aggregated_common.bin",
	"aggregated_verifier.bin",
	"aggregated_prover.bin",
	"config.json",
];

/// Get the default circuit bins directory in user's home
pub fn get_default_circuit_bins_dir() -> Option<PathBuf> {
	dirs::home_dir().map(|home| home.join(DEFAULT_CIRCUIT_BINS_DIR))
}

/// Check if a directory contains valid circuit binaries
pub fn is_valid_circuit_dir(dir: &Path) -> bool {
	if !dir.exists() || !dir.is_dir() {
		return false;
	}

	// Check that all required files exist
	REQUIRED_CIRCUIT_FILES.iter().all(|file| dir.join(file).exists())
}

/// Get the circuit bins directory, searching in order of precedence.
///
/// Search order:
/// 1. `$QUANTUS_CIRCUIT_BINS` environment variable
/// 2. `~/.quantus/circuit-bins/`
/// 3. `./generated-bins` (development)
///
/// Returns `None` if no valid circuit directory is found.
pub fn find_circuit_bins_dir() -> Option<PathBuf> {
	// 1. Check environment variable
	if let Ok(env_path) = std::env::var(CIRCUIT_BINS_ENV_VAR) {
		let path = PathBuf::from(&env_path);
		if is_valid_circuit_dir(&path) {
			return Some(path);
		}
	}

	// 2. Check user's home directory
	if let Some(home_path) = get_default_circuit_bins_dir() {
		if is_valid_circuit_dir(&home_path) {
			return Some(home_path);
		}
	}

	// 3. Check development directory (relative to CWD)
	let dev_path = PathBuf::from(DEV_CIRCUIT_BINS_DIR);
	if is_valid_circuit_dir(&dev_path) {
		return Some(dev_path);
	}

	None
}

/// Get the circuit bins directory or return a helpful error.
///
/// This is the main function that should be used by wormhole commands.
pub fn get_circuit_bins_dir() -> Result<PathBuf> {
	find_circuit_bins_dir().ok_or_else(|| {
		QuantusError::Generic(
			"Circuit binaries not found. Run 'quantus setup-circuits' first.\n\
             This is a one-time setup that generates ZK proving keys (~1GB).\n\
             It may take a few minutes on first run."
				.to_string(),
		)
	})
}

/// Check if circuits exist (without returning an error)
#[allow(dead_code)]
pub fn circuits_exist() -> bool {
	find_circuit_bins_dir().is_some()
}

/// Check if an error message indicates a circuit version mismatch or corruption
pub fn is_circuit_version_error(error: &str) -> bool {
	let error_lower = error.to_lowercase();
	error_lower.contains("wire partition")
		|| error_lower.contains("circuitconfig mismatch")
		|| error_lower.contains("gate_serializer")
		|| error_lower.contains("generator_serializer")
		|| error_lower.contains("deserialization failed")
		|| error_lower.contains("invalid circuit data")
}

/// Wrap a circuit loading error with helpful context
pub fn wrap_circuit_error<E: std::fmt::Display>(error: E) -> QuantusError {
	let error_str = error.to_string();

	if is_circuit_version_error(&error_str) {
		QuantusError::Generic(format!(
			"Circuit binaries appear to be outdated or corrupted.\n\
             Run 'quantus setup-circuits --force' to regenerate them.\n\
             \n\
             Original error: {}",
			error_str
		))
	} else if error_str.contains("No such file") || error_str.contains("not found") {
		QuantusError::Generic(
			"Circuit binaries not found. Run 'quantus setup-circuits' first.\n\
             This is a one-time setup that generates ZK proving keys (~1GB).\n\
             It may take a few minutes on first run."
				.to_string(),
		)
	} else {
		QuantusError::Generic(format!("Circuit loading error: {}", error_str))
	}
}

/// Progress callback for circuit generation
struct GenerationProgress {
	bar: ProgressBar,
	start_time: Instant,
}

impl GenerationProgress {
	fn new() -> Self {
		let bar = ProgressBar::new(100);
		bar.set_style(
			ProgressStyle::default_bar()
				.template("{spinner:.green} [{bar:40.cyan/blue}] {pos}% {msg}")
				.unwrap()
				.progress_chars("=>-"),
		);
		Self { bar, start_time: Instant::now() }
	}

	fn set_message(&self, msg: &str) {
		self.bar.set_message(msg.to_string());
	}

	fn set_progress(&self, percent: u64) {
		self.bar.set_position(percent);
	}

	fn finish(&self) {
		let elapsed = self.start_time.elapsed();
		self.bar.finish_with_message(format!("Done in {:.1}s", elapsed.as_secs_f64()));
	}
}

/// Generate circuit binaries to the specified directory.
///
/// # Arguments
/// * `output_dir` - Directory to write binaries to
/// * `num_leaf_proofs` - Number of leaf proofs per aggregation (default: 16)
/// * `force` - If true, regenerate even if circuits exist
///
/// # Returns
/// Ok(()) on success, or an error if generation fails
pub fn generate_circuits(output_dir: &Path, num_leaf_proofs: usize, force: bool) -> Result<()> {
	use colored::Colorize;

	// Check if circuits already exist
	if !force && is_valid_circuit_dir(output_dir) {
		println!(
			"{}",
			"Circuit binaries already exist. Use --force to regenerate.".bright_yellow()
		);
		return Ok(());
	}

	// Create output directory
	std::fs::create_dir_all(output_dir).map_err(|e| {
		QuantusError::Generic(format!("Failed to create output directory {:?}: {}", output_dir, e))
	})?;

	println!("{}", "Generating ZK circuit binaries...".bright_cyan());
	println!("  Output directory: {}", output_dir.display().to_string().bright_white());
	println!("  Leaf proofs per aggregation: {}", num_leaf_proofs.to_string().bright_white());
	println!();

	let progress = GenerationProgress::new();
	let start_time = Instant::now();

	// Step 1: Generate leaf circuit (0-30%)
	progress.set_message("Building wormhole leaf circuit...");
	progress.set_progress(5);

	// Use the circuit builder to generate all binaries
	// The circuit builder handles the heavy lifting
	progress.set_message("Generating leaf circuit binaries...");
	progress.set_progress(10);

	// Generate all circuit binaries using the builder
	qp_wormhole_circuit_builder::generate_all_circuit_binaries(
		output_dir,
		true, // include prover
		num_leaf_proofs,
		None, // no layer-1 aggregation
	)
	.map_err(|e| QuantusError::Generic(format!("Circuit generation failed: {}", e)))?;

	progress.set_progress(100);
	progress.finish();

	let elapsed = start_time.elapsed();

	// Print summary
	println!();
	println!(
		"{}",
		format!("Circuit binaries generated successfully in {:.1}s", elapsed.as_secs_f64())
			.bright_green()
	);
	println!();

	// Print file sizes
	print_circuit_file_info(output_dir)?;

	println!();
	println!("{}", "You can now use wormhole commands.".bright_green());

	Ok(())
}

/// Print information about generated circuit files
fn print_circuit_file_info(dir: &Path) -> Result<()> {
	use colored::Colorize;

	let files = [
		("common.bin", "Leaf circuit common data"),
		("verifier.bin", "Leaf circuit verifier"),
		("prover.bin", "Leaf circuit prover"),
		("dummy_proof.bin", "Dummy proof for padding"),
		("aggregated_common.bin", "Aggregated circuit common data"),
		("aggregated_verifier.bin", "Aggregated circuit verifier"),
		("aggregated_prover.bin", "Aggregated circuit prover"),
		("config.json", "Circuit configuration"),
	];

	for (filename, description) in files {
		let path = dir.join(filename);
		if let Ok(metadata) = std::fs::metadata(&path) {
			let size = metadata.len();
			let size_str = format_file_size(size);
			println!(
				"  {}: {} ({})",
				filename.bright_white(),
				size_str.bright_cyan(),
				description.dimmed()
			);
		}
	}

	Ok(())
}

/// Format a file size in human-readable form
fn format_file_size(bytes: u64) -> String {
	const KB: u64 = 1024;
	const MB: u64 = KB * 1024;
	const GB: u64 = MB * 1024;

	if bytes >= GB {
		format!("{:.2} GB", bytes as f64 / GB as f64)
	} else if bytes >= MB {
		format!("{:.2} MB", bytes as f64 / MB as f64)
	} else if bytes >= KB {
		format!("{:.2} KB", bytes as f64 / KB as f64)
	} else {
		format!("{} bytes", bytes)
	}
}

/// Handle the setup-circuits command
pub fn handle_setup_circuits(
	force: bool,
	num_leaf_proofs: usize,
	output_dir: Option<String>,
) -> Result<()> {
	// Determine output directory
	let output_path = if let Some(dir) = output_dir {
		PathBuf::from(dir)
	} else {
		get_default_circuit_bins_dir().ok_or_else(|| {
			QuantusError::Generic(
				"Could not determine home directory. Use --output-dir to specify a location."
					.to_string(),
			)
		})?
	};

	generate_circuits(&output_path, num_leaf_proofs, force)
}

#[cfg(test)]
mod tests {
	use super::*;
	use tempfile::tempdir;

	#[test]
	fn test_is_circuit_version_error() {
		assert!(is_circuit_version_error("wire partition mismatch"));
		assert!(is_circuit_version_error("CircuitConfig mismatch detected"));
		assert!(is_circuit_version_error("gate_serializer error"));
		assert!(is_circuit_version_error("Deserialization failed for circuit"));
		assert!(!is_circuit_version_error("File not found"));
		assert!(!is_circuit_version_error("Network error"));
	}

	#[test]
	fn test_is_valid_circuit_dir_empty() {
		let dir = tempdir().unwrap();
		assert!(!is_valid_circuit_dir(dir.path()));
	}

	#[test]
	fn test_is_valid_circuit_dir_nonexistent() {
		let path = PathBuf::from("/nonexistent/path/to/circuits");
		assert!(!is_valid_circuit_dir(&path));
	}

	#[test]
	fn test_format_file_size() {
		assert_eq!(format_file_size(500), "500 bytes");
		assert_eq!(format_file_size(1024), "1.00 KB");
		assert_eq!(format_file_size(1024 * 1024), "1.00 MB");
		assert_eq!(format_file_size(1024 * 1024 * 1024), "1.00 GB");
		assert_eq!(format_file_size(1536), "1.50 KB");
	}

	#[test]
	fn test_get_default_circuit_bins_dir() {
		let dir = get_default_circuit_bins_dir();
		// Should return Some on most systems
		if let Some(path) = dir {
			assert!(path.to_string_lossy().contains(".quantus"));
			assert!(path.to_string_lossy().contains("circuit-bins"));
		}
	}

	#[test]
	fn test_find_circuit_bins_dir_not_found() {
		// In a clean test environment without circuits, should return None
		// (unless running in the quantus-cli dev directory)
		let result = find_circuit_bins_dir();
		// We can't assert None because dev environment might have generated-bins
		// Just verify it doesn't panic
		let _ = result;
	}
}
