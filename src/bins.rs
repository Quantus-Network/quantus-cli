//! Circuit binaries path resolution and lazy generation.
//!
//! The CLI needs access to ZK-circuit artifacts (`verifier.bin`, `common.bin`,
//! `private_batch_*.bin`, `public_batch_*.bin`, dummy proofs, etc.). The leaf
//! circuit no longer ships a `prover.bin` — `WormholeProver` builds fresh at
//! prove time. During `cargo build`/`cargo install` the remaining files are
//! produced by `build.rs` into `$OUT_DIR/generated-bins/`, but `cargo install`
//! does not copy build-script outputs alongside the installed executable. To
//! make installed binaries self-sufficient, this module resolves a persistent
//! storage location and regenerates the binaries there on demand.
//!
//! Resolution order:
//! 1. `QUANTUS_BINS_DIR` env var (explicit override).
//! 2. `./generated-bins/` in the current directory (local dev).
//! 3. `~/.quantus/generated-bins/` (default for installed binaries).

use crate::{
	error::{QuantusError, Result},
	log_print, log_success,
};
use sha2::{Digest, Sha256};
use std::{
	fs,
	io::Write,
	path::{Path, PathBuf},
};

include!("bins_consts.rs");

mod fs_helpers {
	#![allow(dead_code)] // publish_dir_atomically is used by build.rs and tests
	include!("bins_fs.rs");
}
use fs_helpers::remove_path_nofollow;

/// Environment variable used to override the bins directory.
pub const BINS_DIR_ENV: &str = "QUANTUS_BINS_DIR";

/// Files that must be present for all wormhole operations to succeed.
///
/// Note: there is no leaf `prover.bin` — qp-wormhole-circuit-builder 3.1.0+ does
/// not emit one; leaf proofs use `qp_wormhole_prover::build_fresh()`.
const REQUIRED_FILES: &[&str] = &[
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

#[derive(serde::Deserialize, serde::Serialize)]
struct ArtifactManifest {
	manifest_version: u32,
	package_version: String,
	num_leaf_proofs: usize,
	num_private_batch_proofs: usize,
	files: std::collections::BTreeMap<String, String>,
}

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
/// Safe to call multiple times. A directory attributable to a different CLI
/// version or sizing configuration (via its manifest or version marker) is
/// quarantined and regenerated, so upgrades recover automatically. A
/// same-version directory that fails authentication is rejected rather than
/// overwritten.
pub fn ensure_bins_dir() -> Result<PathBuf> {
	let dir = resolve_bins_dir();
	ensure_safe_bins_dir(&dir)?;

	if is_ready(&dir) {
		return Ok(dir);
	}

	if REQUIRED_FILES.iter().any(|f| dir.join(f).exists()) {
		match stale_artifact_provenance(&dir) {
			Some(provenance) => {
				log_print!(
					"♻️  Replacing circuit artifacts in {} ({}; current CLI is {})",
					dir.display(),
					provenance,
					env!("CARGO_PKG_VERSION")
				);
				remove_path_nofollow(&dir).map_err(QuantusError::Generic)?;
			},
			None => {
				return Err(QuantusError::Generic(format!(
					"Circuit artifact directory {} is incomplete or failed authentication; remove the directory and rerun this command to regenerate trusted artifacts",
					dir.display()
				)));
			},
		}
	}

	let num_leaf_proofs = env_num_leaf_proofs();
	let num_private_batch_proofs = env_num_private_batch_proofs();
	generate(&dir, num_leaf_proofs, num_private_batch_proofs)?;
	Ok(dir)
}

/// Best-effort attribution of an artifact directory to a different CLI version
/// or sizing configuration, so upgrades can quarantine-and-regenerate instead
/// of bricking wormhole commands.
///
/// Returns a description of the stale provenance, or `None` when the directory
/// claims to belong to the current version/sizing (in which case a failed
/// manifest check means tampering or corruption and must stay a hard error).
fn stale_artifact_provenance(dir: &Path) -> Option<String> {
	// Prefer the manifest: it records the producing package version and sizing.
	if let Ok(content) = fs::read_to_string(dir.join(MANIFEST_FILE)) {
		if let Ok(manifest) = serde_json::from_str::<ArtifactManifest>(&content) {
			if manifest.package_version != env!("CARGO_PKG_VERSION") {
				return Some(format!("built by quantus-cli {}", manifest.package_version));
			}
			if manifest.num_leaf_proofs != env_num_leaf_proofs() ||
				manifest.num_private_batch_proofs != env_num_private_batch_proofs()
			{
				return Some(format!(
					"sized for num_leaf_proofs={}, num_private_batch_proofs={}",
					manifest.num_leaf_proofs, manifest.num_private_batch_proofs
				));
			}
			return None;
		}
	}

	// Pre-manifest layouts from older releases only carry the version marker.
	if let Ok(marker) = fs::read_to_string(dir.join(VERSION_MARKER)) {
		let marker = marker.trim();
		if !marker.is_empty() && marker != env!("CARGO_PKG_VERSION") {
			return Some(format!("built by quantus-cli {marker}"));
		}
	}

	None
}

fn ensure_safe_bins_dir(dir: &Path) -> Result<()> {
	match fs::symlink_metadata(dir) {
		Ok(meta) => {
			if meta.file_type().is_symlink() {
				return Err(QuantusError::Generic(format!(
					"Refusing to use symlinked bins directory {}",
					dir.display()
				)));
			}
			if !meta.is_dir() {
				return Err(QuantusError::Generic(format!(
					"Bins path {} is not a directory",
					dir.display()
				)));
			}
		},
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
		Err(e) => {
			return Err(QuantusError::Generic(format!(
				"Failed to inspect bins directory {}: {}",
				dir.display(),
				e
			)));
		},
	}
	Ok(())
}

fn ensure_regular_file(path: &Path) -> Result<()> {
	let meta = fs::symlink_metadata(path).map_err(|e| {
		QuantusError::Generic(format!("Failed to inspect circuit artifact {}: {e}", path.display()))
	})?;
	if meta.file_type().is_symlink() {
		return Err(QuantusError::Generic(format!(
			"Refusing to use symlinked circuit artifact {}",
			path.display()
		)));
	}
	if !meta.is_file() {
		return Err(QuantusError::Generic(format!(
			"Circuit artifact {} is not a regular file",
			path.display()
		)));
	}
	Ok(())
}

fn is_ready(dir: &Path) -> bool {
	REQUIRED_FILES.iter().all(|f| dir.join(f).exists()) && verify_manifest(dir).is_ok()
}

/// Authenticate a circuit-artifact directory against its SHA-256 manifest.
pub(crate) fn verify_manifest(dir: &Path) -> Result<()> {
	ensure_safe_bins_dir(dir)?;
	ensure_regular_file(&dir.join(MANIFEST_FILE))?;
	let content = std::fs::read_to_string(dir.join(MANIFEST_FILE)).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to read circuit artifact manifest {}: {e}",
			dir.join(MANIFEST_FILE).display()
		))
	})?;
	let manifest: ArtifactManifest = serde_json::from_str(&content).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to parse circuit artifact manifest {}: {e}",
			dir.join(MANIFEST_FILE).display()
		))
	})?;
	validate_manifest(dir, &manifest)
}

fn validate_manifest(dir: &Path, manifest: &ArtifactManifest) -> Result<()> {
	if manifest.manifest_version != 1 {
		return Err(QuantusError::Generic(format!(
			"Unsupported circuit artifact manifest version {}",
			manifest.manifest_version
		)));
	}
	if manifest.package_version != env!("CARGO_PKG_VERSION") {
		return Err(QuantusError::Generic(
			"Circuit artifact manifest package version mismatch".to_string(),
		));
	}
	if manifest.num_leaf_proofs != env_num_leaf_proofs() ||
		manifest.num_private_batch_proofs != env_num_private_batch_proofs()
	{
		return Err(QuantusError::Generic(
			"Circuit artifact manifest sizing does not match current settings".to_string(),
		));
	}
	if manifest.files.len() != MANIFESTED_FILES.len() {
		return Err(QuantusError::Generic(
			"Circuit artifact manifest file set mismatch".to_string(),
		));
	}
	for filename in MANIFESTED_FILES {
		let expected = manifest.files.get(*filename).ok_or_else(|| {
			QuantusError::Generic(format!("Circuit artifact manifest lacks {filename}"))
		})?;
		let path = dir.join(filename);
		ensure_regular_file(&path)?;
		let actual = file_sha256_hex(&path)?;
		if &actual != expected {
			return Err(QuantusError::Generic(format!(
				"Circuit artifact hash mismatch for {filename}"
			)));
		}
	}
	Ok(())
}

fn write_manifest(
	dir: &Path,
	num_leaf_proofs: usize,
	num_private_batch_proofs: usize,
) -> Result<()> {
	let mut files = std::collections::BTreeMap::new();
	for filename in MANIFESTED_FILES {
		ensure_regular_file(&dir.join(filename))?;
		files.insert((*filename).to_string(), file_sha256_hex(&dir.join(filename))?);
	}
	let manifest = ArtifactManifest {
		manifest_version: 1,
		package_version: env!("CARGO_PKG_VERSION").to_string(),
		num_leaf_proofs,
		num_private_batch_proofs,
		files,
	};
	let content = serde_json::to_string_pretty(&manifest).map_err(|e| {
		QuantusError::Generic(format!("Failed to serialize circuit artifact manifest: {e}"))
	})?;
	atomic_write_new_file(&dir.join(MANIFEST_FILE), content.as_bytes())
}

fn file_sha256_hex(path: &Path) -> Result<String> {
	let data = std::fs::read(path).map_err(|e| {
		QuantusError::Generic(format!("Failed to read circuit artifact {}: {e}", path.display()))
	})?;
	let mut hasher = Sha256::new();
	hasher.update(&data);
	Ok(hex::encode(hasher.finalize()))
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

fn atomic_write_new_file(path: &Path, contents: &[u8]) -> Result<()> {
	let parent = path.parent().unwrap_or_else(|| Path::new("."));
	let file_name = path
		.file_name()
		.and_then(|s| s.to_str())
		.ok_or_else(|| QuantusError::Generic("Invalid artifact filename".to_string()))?;
	let temp_path = parent.join(format!("{}.tmp-{}", file_name, std::process::id()));

	if let Ok(meta) = fs::symlink_metadata(path) {
		if meta.file_type().is_symlink() {
			return Err(QuantusError::Generic(format!(
				"Refusing to overwrite symlinked artifact {}",
				path.display()
			)));
		}
	}
	if let Ok(meta) = fs::symlink_metadata(&temp_path) {
		if meta.file_type().is_symlink() {
			return Err(QuantusError::Generic(format!(
				"Refusing to overwrite symlinked temporary artifact {}",
				temp_path.display()
			)));
		}
		if meta.is_file() {
			let _ = fs::remove_file(&temp_path);
		}
	}

	let mut file =
		fs::OpenOptions::new()
			.write(true)
			.create_new(true)
			.open(&temp_path)
			.map_err(|e| {
				QuantusError::Generic(format!("Failed to create {}: {}", path.display(), e))
			})?;
	file.write_all(contents)
		.and_then(|_| file.sync_all())
		.map_err(|e| QuantusError::Generic(format!("Failed to write {}: {}", path.display(), e)))?;
	drop(file);

	fs::rename(&temp_path, path).map_err(|e| {
		let _ = fs::remove_file(&temp_path);
		QuantusError::Generic(format!("Failed to publish {}: {}", path.display(), e))
	})?;
	Ok(())
}

fn write_version_marker_safely(dir: &Path) -> Result<()> {
	atomic_write_new_file(&dir.join(VERSION_MARKER), env!("CARGO_PKG_VERSION").as_bytes())
}

fn generate(dir: &Path, num_leaf_proofs: usize, num_private_batch_proofs: usize) -> Result<()> {
	std::fs::create_dir_all(dir).map_err(|e| {
		QuantusError::Generic(format!("Failed to create bins directory {}: {}", dir.display(), e))
	})?;
	ensure_safe_bins_dir(dir)?;

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
	ensure_safe_bins_dir(dir)?;

	write_version_marker_safely(dir)?;
	write_manifest(dir, num_leaf_proofs, num_private_batch_proofs)?;

	let elapsed = start.elapsed();
	log_success!("Circuit binaries ready in {:.1}s", elapsed.as_secs_f64());
	log_print!("");
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use serial_test::serial;
	use std::os::unix::fs::symlink;
	use tempfile::TempDir;

	fn seed_required_files(dir: &Path) {
		for name in REQUIRED_FILES {
			fs::write(dir.join(name), format!("contents-of-{name}")).unwrap();
		}
		fs::write(dir.join(VERSION_MARKER), env!("CARGO_PKG_VERSION")).unwrap();
	}

	fn write_valid_manifest_for_dir(dir: &Path) {
		write_manifest(dir, env_num_leaf_proofs(), env_num_private_batch_proofs()).unwrap();
	}

	#[test]
	fn verify_manifest_rejects_tampered_artifact() {
		// #160697: readiness/load must authenticate artifact bytes, not just names.
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path();
		seed_required_files(dir);
		write_valid_manifest_for_dir(dir);
		assert!(verify_manifest(dir).is_ok());

		fs::write(dir.join("private_batch_verifier.bin"), b"attacker-substituted-circuit").unwrap();
		let err = verify_manifest(dir).expect_err("tampered verifier must fail authentication");
		assert!(err.to_string().contains("hash mismatch"), "unexpected error: {err}");
		assert!(!is_ready(dir));
	}

	#[test]
	#[serial]
	fn ensure_bins_dir_rejects_incomplete_unauthenticated_directory() {
		// #160697: do not regenerate over an existing unverified artifact set.
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path().join("generated-bins");
		fs::create_dir_all(&dir).unwrap();
		seed_required_files(&dir);
		// No manifest.json

		std::env::set_var(BINS_DIR_ENV, &dir);
		let result = ensure_bins_dir();
		std::env::remove_var(BINS_DIR_ENV);

		let err = result.expect_err("incomplete/unauthenticated dir must be rejected");
		assert!(err.to_string().contains("failed authentication"), "unexpected error: {err}");
	}

	#[test]
	#[serial]
	fn ensure_bins_dir_rejects_symlinked_directory() {
		// #160699: artifact directory must not be a symlink redirect.
		let tmp = TempDir::new().unwrap();
		let real = tmp.path().join("real-bins");
		let link = tmp.path().join("generated-bins");
		fs::create_dir_all(&real).unwrap();
		seed_required_files(&real);
		write_valid_manifest_for_dir(&real);
		symlink(&real, &link).unwrap();

		std::env::set_var(BINS_DIR_ENV, &link);
		let result = ensure_bins_dir();
		std::env::remove_var(BINS_DIR_ENV);

		let err = result.expect_err("symlinked bins dir must be rejected");
		assert!(err.to_string().contains("symlinked bins directory"), "unexpected error: {err}");
	}

	#[test]
	fn version_marker_write_refuses_existing_symlink() {
		// #160699: marker publication must not follow a pre-existing symlink.
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path();
		fs::create_dir_all(dir).unwrap();
		let victim = tmp.path().join("victim.txt");
		fs::write(&victim, b"do-not-overwrite").unwrap();
		symlink(&victim, dir.join(VERSION_MARKER)).unwrap();

		let err = write_version_marker_safely(dir).expect_err("must refuse symlink marker");
		assert!(err.to_string().contains("symlinked"), "unexpected error: {err}");
		assert_eq!(fs::read_to_string(&victim).unwrap(), "do-not-overwrite");
	}

	#[test]
	fn verify_manifest_rejects_symlinked_artifact_file() {
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path();
		seed_required_files(dir);
		write_valid_manifest_for_dir(dir);

		let evil = tmp.path().join("evil-verifier.bin");
		fs::write(&evil, b"redirected").unwrap();
		fs::remove_file(dir.join("verifier.bin")).unwrap();
		symlink(&evil, dir.join("verifier.bin")).unwrap();

		let err = verify_manifest(dir).expect_err("symlinked artifact must be rejected");
		assert!(err.to_string().contains("symlinked"), "unexpected error: {err}");
	}

	// Shared publish helpers from build.rs (#160700).
	use super::fs_helpers::publish_dir_atomically;

	#[test]
	fn publish_dir_atomically_replaces_destination_symlink_without_following() {
		// #160700: publishing must not write through a swapped destination symlink.
		let tmp = TempDir::new().unwrap();
		let src = tmp.path().join("src");
		let dest = tmp.path().join("generated-bins");
		let victim_dir = tmp.path().join("victim-dir");
		fs::create_dir_all(&src).unwrap();
		fs::create_dir_all(&victim_dir).unwrap();
		fs::write(src.join("config.json"), b"{\"ok\":true}").unwrap();
		fs::write(src.join("verifier.bin"), b"trusted").unwrap();
		fs::write(victim_dir.join("keep-me.txt"), b"safe").unwrap();
		symlink(&victim_dir, &dest).unwrap();

		publish_dir_atomically(&src, &dest).expect("publish must succeed");

		assert!(dest.is_dir());
		assert!(!fs::symlink_metadata(&dest).unwrap().file_type().is_symlink());
		assert_eq!(fs::read(dest.join("verifier.bin")).unwrap(), b"trusted");
		assert_eq!(fs::read(victim_dir.join("keep-me.txt")).unwrap(), b"safe");
		assert!(!victim_dir.join("config.json").exists());
	}

	#[test]
	fn remove_path_nofollow_removes_symlink_without_deleting_target() {
		let tmp = TempDir::new().unwrap();
		let target = tmp.path().join("target-dir");
		let link = tmp.path().join("link-dir");
		fs::create_dir_all(&target).unwrap();
		fs::write(target.join("keep.txt"), b"keep").unwrap();
		symlink(&target, &link).unwrap();

		remove_path_nofollow(&link).expect("remove symlink");
		assert!(!link.exists());
		assert!(target.join("keep.txt").exists());
	}

	/// Upgrades must not brick wormhole: artifacts attributable to another CLI
	/// version are stale and eligible for quarantine-and-regenerate.
	#[test]
	fn artifacts_from_an_older_cli_version_are_stale() {
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path();
		seed_required_files(dir);
		write_valid_manifest_for_dir(dir);

		// Same version and sizing: not stale (a failed check must stay a hard error).
		assert_eq!(stale_artifact_provenance(dir), None);

		// Rewrite the manifest as if produced by an older release.
		let content = fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
		let mut manifest: ArtifactManifest = serde_json::from_str(&content).unwrap();
		manifest.package_version = "0.0.1-old".to_string();
		fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(&manifest).unwrap()).unwrap();

		let provenance = stale_artifact_provenance(dir).expect("older version is stale");
		assert!(provenance.contains("0.0.1-old"), "unexpected provenance: {provenance}");
	}

	/// Pre-manifest layouts (older releases) are attributed via the version marker.
	#[test]
	fn pre_manifest_artifacts_with_old_version_marker_are_stale() {
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path();
		seed_required_files(dir);
		// No manifest.json at all; marker from an older release.
		fs::write(dir.join(VERSION_MARKER), "0.0.1-old").unwrap();

		let provenance = stale_artifact_provenance(dir).expect("old marker is stale");
		assert!(provenance.contains("0.0.1-old"), "unexpected provenance: {provenance}");

		// Marker matching the current version without a manifest is NOT stale:
		// that directory claims to be ours but cannot be authenticated.
		fs::write(dir.join(VERSION_MARKER), env!("CARGO_PKG_VERSION")).unwrap();
		assert_eq!(stale_artifact_provenance(dir), None);
	}

	/// A same-version directory with mismatched sizing regenerates instead of erroring.
	#[test]
	fn artifacts_with_different_sizing_are_stale() {
		let tmp = TempDir::new().unwrap();
		let dir = tmp.path();
		seed_required_files(dir);
		write_valid_manifest_for_dir(dir);

		let content = fs::read_to_string(dir.join(MANIFEST_FILE)).unwrap();
		let mut manifest: ArtifactManifest = serde_json::from_str(&content).unwrap();
		manifest.num_leaf_proofs += 1;
		fs::write(dir.join(MANIFEST_FILE), serde_json::to_string(&manifest).unwrap()).unwrap();

		let provenance = stale_artifact_provenance(dir).expect("different sizing is stale");
		assert!(provenance.contains("num_leaf_proofs"), "unexpected provenance: {provenance}");
	}
}
