// Filesystem helpers for publishing circuit artifact directories.
// Included by `build.rs` (no crate prelude) and by `crate::bins` tests.

use std::fs;
#[allow(unused_imports)] // Path is provided by build.rs when included there
use std::path::{Path, PathBuf};

/// Remove a path without following a destination that was swapped to a symlink
/// between inspection and deletion.
pub(crate) fn remove_path_nofollow(path: &Path) -> std::result::Result<(), String> {
	match fs::symlink_metadata(path) {
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
		Err(e) => Err(format!("Failed to inspect {}: {}", path.display(), e)),
		Ok(meta) if meta.file_type().is_symlink() || meta.is_file() => {
			fs::remove_file(path).map_err(|e| format!("Failed to remove {}: {}", path.display(), e))
		},
		Ok(meta) if meta.is_dir() => {
			// Rename aside first so a TOCTOU swap to a symlink cannot redirect
			// remove_dir_all onto an attacker-chosen directory.
			let trash = path.with_file_name(format!(
				".{}.trash-{}",
				path.file_name().and_then(|s| s.to_str()).unwrap_or("path"),
				std::process::id()
			));
			if trash.exists() || fs::symlink_metadata(&trash).is_ok() {
				remove_path_nofollow(&trash)?;
			}
			fs::rename(path, &trash)
				.map_err(|e| format!("Failed to quarantine {}: {}", path.display(), e))?;
			match fs::symlink_metadata(&trash) {
				Ok(m) if m.file_type().is_symlink() || m.is_file() => fs::remove_file(&trash)
					.map_err(|e| {
						format!("Failed to remove quarantined path {}: {}", trash.display(), e)
					}),
				Ok(m) if m.is_dir() => fs::remove_dir_all(&trash).map_err(|e| {
					format!("Failed to remove quarantined dir {}: {}", trash.display(), e)
				}),
				Ok(_) => Err(format!("Unexpected quarantined path type at {}", trash.display())),
				Err(e) => Err(format!(
					"Failed to inspect quarantined path {}: {}",
					trash.display(),
					e
				)),
			}
		},
		Ok(_) => Err(format!("Unexpected path type at {}", path.display())),
	}
}

/// Atomically publish `src` directory contents to `dest` via a staging directory
/// and rename, refusing symlink destinations at each step.
pub(crate) fn publish_dir_atomically(src: &Path, dest: &Path) -> std::result::Result<(), String> {
	let parent = dest
		.parent()
		.ok_or_else(|| "destination must have a parent directory".to_string())?;
	let staging: PathBuf =
		parent.join(format!(".generated-bins.staging-{}", std::process::id()));

	remove_path_nofollow(&staging)?;
	fs::create_dir_all(&staging)
		.map_err(|e| format!("Failed to create staging directory {}: {}", staging.display(), e))?;
	if fs::symlink_metadata(&staging)
		.map(|m| m.file_type().is_symlink())
		.unwrap_or(false)
	{
		return Err(format!("Staging path {} unexpectedly became a symlink", staging.display()));
	}

	let entries = fs::read_dir(src)
		.map_err(|e| format!("Failed to read source directory {}: {}", src.display(), e))?;
	for entry in entries {
		let entry =
			entry.map_err(|e| format!("Failed to read source directory entry: {}", e))?;
		let dest_file = staging.join(entry.file_name());
		if let Ok(meta) = fs::symlink_metadata(&dest_file) {
			if meta.file_type().is_symlink() {
				return Err(format!(
					"Refusing to copy onto symlinked staging artifact {}",
					dest_file.display()
				));
			}
		}
		fs::copy(entry.path(), &dest_file).map_err(|e| {
			format!(
				"Failed to copy {} -> {}: {}",
				entry.path().display(),
				dest_file.display(),
				e
			)
		})?;
	}

	remove_path_nofollow(dest)?;
	if let Err(e) = fs::rename(&staging, dest) {
		let _ = fs::remove_dir_all(&staging);
		return Err(format!(
			"Failed to publish directory to {}: {}",
			dest.display(),
			e
		));
	}
	Ok(())
}
