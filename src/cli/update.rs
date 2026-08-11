//! Self-update command.
//!
//! Downloads the appropriate release archive from GitHub for the current
//! platform and replaces the running `quantus` binary in place. Cross-platform
//! binary replacement (including the Windows "can't overwrite a running exe"
//! case) is handled by the `self_update` crate.
//!
//! Before installing, the downloaded archive is verified against the sibling
//! `sha256sums-*.txt` asset published by the release workflow.
//!
//! Threat model: this is same-origin integrity, not authenticity. The checksum
//! is a sibling asset of the same GitHub release fetched over the same TLS
//! channel, so it defends against corruption and single-object substitution,
//! but not against an attacker who can write release assets or MITM TLS (they
//! control both files). Cryptographic release signing (e.g. the `self_update`
//! crate's zipsign/ed25519 `signatures` feature, with the public key embedded
//! here) would be required for that, and needs the release pipeline to sign
//! assets first.

use crate::{error::QuantusError, log_print, log_success};
use colored::Colorize;
use sha2::{Digest, Sha256};
use std::{
	fs,
	io::{self, Write},
	path::Path,
};

const REPO_OWNER: &str = "Quantus-Network";
const REPO_NAME: &str = "quantus-cli";
const BIN_NAME: &str = "quantus";

/// Identifier used to disambiguate the archive asset from the sibling
/// `sha256sums-*.txt` asset (both contain the target triple in their name).
#[cfg(target_os = "windows")]
const ASSET_IDENTIFIER: &str = ".zip";
#[cfg(not(target_os = "windows"))]
const ASSET_IDENTIFIER: &str = ".tar.gz";

/// Run the self-update flow.
///
/// * `check_only` - only report whether a newer version exists, don't install.
/// * `yes` - skip the interactive confirmation prompt.
/// * `version` - optional specific version to install (tag, with or without `v`).
pub async fn handle_update_command(
	check_only: bool,
	yes: bool,
	version: Option<String>,
) -> crate::error::Result<()> {
	let current = env!("CARGO_PKG_VERSION");

	log_print!("🔄 {}", "Quantus CLI Self-Update".bright_cyan().bold());
	log_print!("   Current version: {}", current.bright_yellow());

	// `self_update` is synchronous and does blocking I/O, so run it off the
	// async runtime's worker threads.
	let status = tokio::task::spawn_blocking(move || run_update(check_only, yes, version))
		.await
		.map_err(|e| QuantusError::Generic(format!("Update task failed to run: {e}")))??;

	match status {
		UpdateOutcome::AlreadyLatest(v) => {
			log_success!("You are already on the latest version ({}).", v.bright_green());
		},
		UpdateOutcome::UpdateAvailable(v) => {
			// `check_only` path: report and exit without installing.
			log_print!("");
			log_print!(
				"{} A newer version is available: {} → {}",
				"⬆️".bright_yellow(),
				current.dimmed(),
				v.bright_green().bold()
			);
			log_print!("   Run {} to install it.", "quantus update".bright_cyan());
		},
		UpdateOutcome::Updated(v) => {
			log_print!("");
			log_success!("Updated to version {} 🎉", v.bright_green().bold());
			log_print!("   Restart any running sessions to use the new version.");
		},
	}

	Ok(())
}

/// Result of an update attempt.
enum UpdateOutcome {
	/// Already running the newest release.
	AlreadyLatest(String),
	/// A newer release exists (returned only in `check_only` mode).
	UpdateAvailable(String),
	/// The binary was replaced with this version.
	Updated(String),
}

/// Build the shared `self_update` updater configuration.
///
/// This is the single source of truth for how we talk to GitHub: both the
/// install flow and [`latest_stable_version`] derive from it, so the version a
/// check advertises can never disagree with the version an install resolves
/// (they both follow GitHub's `/releases/latest` semantics).
fn configure_updater() -> self_update::backends::github::UpdateBuilder {
	let mut builder = self_update::backends::github::Update::configure();
	builder
		.repo_owner(REPO_OWNER)
		.repo_name(REPO_NAME)
		.bin_name(BIN_NAME)
		// Archives extract to `quantus-cli-v{version}-{target}/quantus`.
		// `{{ version }}` is substituted without the leading `v`, so it is
		// added back as a literal here.
		.bin_path_in_archive("quantus-cli-v{{ version }}-{{ target }}/{{ bin }}")
		.asset_identifier(ASSET_IDENTIFIER)
		.current_version(env!("CARGO_PKG_VERSION"));
	builder
}

/// Resolve the latest *stable* release version from GitHub (without a leading
/// `v`), using the same `/releases/latest` resolution as the install path.
///
/// Blocking: `self_update` performs synchronous I/O, so call this off the async
/// runtime's worker threads (e.g. via `spawn_blocking`).
pub fn latest_stable_version() -> crate::error::Result<String> {
	let releases = configure_updater()
		.build()
		.map_err(map_self_update_err)?
		.get_latest_release()
		.map_err(map_self_update_err)?;
	let release = releases.latest().ok_or_else(|| {
		QuantusError::Generic("No GitHub releases found for Quantus CLI".to_string())
	})?;
	Ok(release.version().trim_start_matches('v').to_string())
}

/// Semver comparison that surfaces unparseable release tags as errors instead
/// of silently reporting "already latest" (`unwrap_or(false)` previously
/// swallowed a non-semver `latest` tag).
fn version_is_newer(current: &str, latest: &str) -> crate::error::Result<bool> {
	self_update::version::bump_is_greater(current, latest).map_err(|e| {
		QuantusError::Generic(format!(
			"Cannot compare current version `{current}` with latest release tag `{latest}`: {e}"
		))
	})
}

/// Verify `data` matches the expected SHA-256 hex digest (case-insensitive).
///
/// Used to bind a downloaded release archive to the published `sha256sums`
/// digest before the archive is extracted or the running binary is replaced.
fn verify_sha256(data: &[u8], expected_hex: &str) -> crate::error::Result<()> {
	let expected = expected_hex.trim().to_ascii_lowercase();
	if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
		return Err(QuantusError::Generic(format!(
			"Invalid SHA-256 digest (expected 64 hex chars): {expected_hex}"
		)));
	}

	let actual = hex::encode(Sha256::digest(data));
	if actual != expected {
		return Err(QuantusError::Generic(format!(
			"Release archive SHA-256 mismatch: expected {expected}, got {actual}. \
			 Refusing to install."
		)));
	}
	Ok(())
}

/// Parse the expected SHA-256 hex for `asset_name` from a `sha256sums` file body.
///
/// Accepts the GNU/`shasum -a 256` line format: `<hex>  <filename>` (one or more
/// spaces; optional `*` binary-mode prefix on the filename).
fn expected_hash_from_sha256sums(
	sums_text: &str,
	asset_name: &str,
) -> crate::error::Result<String> {
	for line in sums_text.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let mut parts = line.split_whitespace();
		let Some(hash) = parts.next() else {
			continue;
		};
		let Some(name) = parts.next() else {
			continue;
		};
		let name = name.strip_prefix('*').unwrap_or(name);
		if name == asset_name ||
			Path::new(name).file_name().and_then(|n| n.to_str()) == Some(asset_name)
		{
			if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
				return Err(QuantusError::Generic(format!(
					"Malformed SHA-256 digest for {asset_name} in sha256sums file"
				)));
			}
			return Ok(hash.to_ascii_lowercase());
		}
	}
	Err(QuantusError::Generic(format!(
		"No SHA-256 digest found for asset `{asset_name}` in release sha256sums file"
	)))
}

/// Blocking implementation that talks to GitHub and replaces the binary.
fn run_update(
	check_only: bool,
	yes: bool,
	version: Option<String>,
) -> crate::error::Result<UpdateOutcome> {
	let current = env!("CARGO_PKG_VERSION");

	// In check-only mode we just look up the latest release and compare. This
	// uses the exact same resolution as the install path below, so a reported
	// upgrade is always one that `quantus update` can actually install.
	if check_only {
		let latest = latest_stable_version()?;
		if version_is_newer(current, &latest)? {
			return Ok(UpdateOutcome::UpdateAvailable(latest));
		}
		return Ok(UpdateOutcome::AlreadyLatest(current.to_string()));
	}

	let mut builder = configure_updater();
	builder.show_download_progress(true).no_confirm(yes);

	let target_tag = version.map(|v| if v.starts_with('v') { v } else { format!("v{v}") });
	if let Some(ref tag) = target_tag {
		builder.release_tag(tag);
	}

	let updater = builder.build().map_err(map_self_update_err)?;
	let release = if let Some(ref tag) = target_tag {
		updater.get_release_version(tag).map_err(map_self_update_err)?
	} else {
		let releases = updater.get_latest_release().map_err(map_self_update_err)?;
		let latest = releases.latest().cloned().ok_or_else(|| {
			QuantusError::Generic("No GitHub releases found for Quantus CLI".to_string())
		})?;
		if !version_is_newer(current, latest.version())? {
			return Ok(UpdateOutcome::AlreadyLatest(latest.version().to_string()));
		}
		latest
	};

	install_verified_release(&updater, &release, yes)?;
	Ok(UpdateOutcome::Updated(release.version().to_string()))
}

/// Download the release archive and its published sha256sums, verify integrity,
/// then extract and replace the running binary.
fn install_verified_release(
	updater: &impl self_update::update::ReleaseUpdate,
	release: &self_update::update::Release,
	yes: bool,
) -> crate::error::Result<()> {
	let target = updater.target();
	let archive_asset = release.asset_for(target, Some(ASSET_IDENTIFIER)).ok_or_else(|| {
		QuantusError::Generic(format!(
			"No release archive found for target `{target}` (looking for {ASSET_IDENTIFIER})"
		))
	})?;
	let sums_asset = release
		.assets()
		.iter()
		.find(|a| a.name().contains("sha256sums") && a.name().contains(target))
		.cloned()
		.ok_or_else(|| {
			QuantusError::Generic(format!(
				"No sha256sums asset found for target `{target}` in release v{}",
				release.version()
			))
		})?;

	log_print!("");
	log_print!("{} release status:", BIN_NAME);
	log_print!("  * Current exe: {:?}", updater.bin_install_path());
	log_print!("  * New exe release: {}", archive_asset.name());
	log_print!("  * Checksum file: {}", sums_asset.name());
	log_print!(
		"\nThe new release will be downloaded, SHA-256 verified, extracted, and the existing binary will be replaced."
	);

	if !yes {
		confirm_update()?;
	}

	log_print!("Downloading checksums...");
	let mut sums_bytes = Vec::new();
	download_asset(sums_asset.download_url(), &mut sums_bytes, MAX_SUMS_ASSET_BYTES, false)?;
	let sums_text = std::str::from_utf8(&sums_bytes).map_err(|e| {
		QuantusError::Generic(format!("Release sha256sums file is not valid UTF-8: {e}"))
	})?;
	let expected_hex = expected_hash_from_sha256sums(sums_text, archive_asset.name())?;

	let tmp_dir = tempfile::TempDir::new()
		.map_err(|e| QuantusError::Generic(format!("Failed to create temp dir for update: {e}")))?;
	let archive_path = tmp_dir.path().join(archive_asset.name());

	log_print!("Downloading...");
	{
		let mut archive_file = fs::File::create(&archive_path).map_err(|e| {
			QuantusError::Generic(format!("Failed to create temp archive file: {e}"))
		})?;
		download_asset(
			archive_asset.download_url(),
			&mut archive_file,
			MAX_ARCHIVE_ASSET_BYTES,
			true,
		)?;
		archive_file
			.flush()
			.map_err(|e| QuantusError::Generic(format!("Failed to flush archive download: {e}")))?;
	}

	log_print!("Verifying SHA-256...");
	let archive_bytes = fs::read(&archive_path)
		.map_err(|e| QuantusError::Generic(format!("Failed to read downloaded archive: {e}")))?;
	verify_sha256(&archive_bytes, &expected_hex)?;
	log_print!("   Checksum OK.");

	let bin_path = substitute_bin_path(
		updater.bin_path_in_archive(),
		release.version(),
		target,
		updater.bin_name(),
	);

	log_print!("Extracting archive...");
	self_update::Extract::from_source(&archive_path)
		.extract_file(tmp_dir.path(), &bin_path)
		.map_err(map_self_update_err)?;

	let new_exe = tmp_dir.path().join(&bin_path);
	let install_path = updater.bin_install_path();

	log_print!("Replacing binary file...");
	let current_exe = std::env::current_exe().map_err(|e| {
		QuantusError::Generic(format!("Failed to resolve current executable path: {e}"))
	})?;
	if install_path == current_exe {
		self_replace::self_replace(&new_exe)
			.map_err(|e| QuantusError::Generic(format!("Failed to replace running binary: {e}")))?;
	} else {
		self_update::Move::from_source(&new_exe)
			.to_dest(install_path)
			.map_err(map_self_update_err)?;
	}

	Ok(())
}

fn substitute_bin_path(template: &str, version: &str, target: &str, bin: &str) -> String {
	template
		.replace("{{ version }}", version)
		.replace("{{version}}", version)
		.replace("{{ target }}", target)
		.replace("{{target}}", target)
		.replace("{{ bin }}", bin)
		.replace("{{bin}}", bin)
}

/// Upper bound for the sha256sums text asset (a handful of lines).
const MAX_SUMS_ASSET_BYTES: u64 = 64 * 1024;
/// Upper bound for the release archive. Real archives are tens of MB; this
/// exists so a rogue release asset cannot exhaust disk/memory before the
/// checksum is ever consulted.
const MAX_ARCHIVE_ASSET_BYTES: u64 = 512 * 1024 * 1024;

/// Writer adapter that fails once more than `limit` bytes have been written.
struct LimitedWriter<W> {
	inner: W,
	remaining: u64,
	limit: u64,
}

impl<W> LimitedWriter<W> {
	fn new(inner: W, limit: u64) -> Self {
		Self { inner, remaining: limit, limit }
	}
}

impl<W: Write> Write for LimitedWriter<W> {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		if buf.len() as u64 > self.remaining {
			return Err(io::Error::other(format!(
				"download exceeds the maximum allowed size of {} bytes",
				self.limit
			)));
		}
		let written = self.inner.write(buf)?;
		self.remaining -= written as u64;
		Ok(written)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.inner.flush()
	}
}

fn download_asset(
	url: &str,
	dest: &mut impl Write,
	max_bytes: u64,
	show_progress: bool,
) -> crate::error::Result<()> {
	let mut limited = LimitedWriter::new(dest, max_bytes);
	let mut download = self_update::Download::from_url(url);
	download
		.request_header(reqwest::header::ACCEPT, "application/octet-stream")
		.show_download_progress(show_progress);
	download.download_to(&mut limited).map_err(map_self_update_err)
}

fn confirm_update() -> crate::error::Result<()> {
	print!("Do you want to continue? [Y/n] ");
	io::stdout()
		.flush()
		.map_err(|e| QuantusError::Generic(format!("Failed to flush confirmation prompt: {e}")))?;
	let mut response = String::new();
	io::stdin()
		.read_line(&mut response)
		.map_err(|e| QuantusError::Generic(format!("Failed to read confirmation: {e}")))?;
	let response = response.trim().to_lowercase();
	if !response.is_empty() && response != "y" && response != "yes" {
		return Err(QuantusError::Generic("Update aborted".to_string()));
	}
	Ok(())
}

/// Convert a `self_update` error into a `QuantusError` with a friendly hint for
/// the common permission-denied case (e.g. binary installed under a path that
/// requires elevated privileges).
fn map_self_update_err(err: self_update::errors::Error) -> QuantusError {
	let msg = err.to_string();
	if msg.contains("Permission denied") || msg.contains("Access is denied") {
		QuantusError::Generic(format!(
			"{msg}\n💡 The CLI binary is in a protected location. Re-run with elevated \
			 privileges (e.g. `sudo quantus update`) or reinstall manually from \
			 https://github.com/Quantus-Network/quantus-cli/releases"
		))
	} else {
		QuantusError::Generic(format!("Self-update failed: {msg}"))
	}
}

#[cfg(test)]
mod tests {
	use super::{expected_hash_from_sha256sums, verify_sha256, version_is_newer, LimitedWriter};
	use sha2::{Digest, Sha256};
	use std::io::Write;

	#[test]
	fn limited_writer_enforces_download_cap() {
		let mut sink = Vec::new();
		let mut limited = LimitedWriter::new(&mut sink, 8);
		limited.write_all(b"12345678").expect("within limit");
		let err = limited.write_all(b"9").expect_err("over limit must fail");
		assert!(err.to_string().contains("maximum allowed size"), "unexpected error: {err}");
		assert_eq!(sink, b"12345678");
	}

	#[test]
	fn non_semver_latest_tag_is_an_error_not_already_latest() {
		assert!(version_is_newer("1.6.0", "1.7.0").expect("semver compares"));
		assert!(!version_is_newer("1.6.0", "1.6.0").expect("semver compares"));
		let err = version_is_newer("1.6.0", "nightly-build")
			.expect_err("non-semver tag must surface an error");
		assert!(err.to_string().contains("nightly-build"), "unexpected error: {err}");
	}

	#[test]
	fn verify_sha256_match_accepts_mismatch_refuses() {
		let data = b"quantus-release-archive-fixture";
		let matching = hex::encode(Sha256::digest(data));
		assert!(
			verify_sha256(data, &matching).is_ok(),
			"matching digest must accept the archive bytes"
		);
		assert!(
			verify_sha256(data, &matching.to_ascii_uppercase()).is_ok(),
			"hex comparison must be case-insensitive"
		);

		let mismatched = "0".repeat(64);
		let err = verify_sha256(data, &mismatched).expect_err("mismatch must refuse install");
		let msg = err.to_string();
		assert!(
			msg.contains("SHA-256 mismatch") && msg.contains("Refusing to install"),
			"expected refusal message, got: {msg}"
		);
	}

	#[test]
	fn expected_hash_from_sha256sums_parses_asset_line() {
		let asset = "quantus-cli-v1.6.0-aarch64-apple-darwin.tar.gz";
		let hash = "a".repeat(64);
		let sums = format!("{hash}  {asset}\n");
		assert_eq!(expected_hash_from_sha256sums(&sums, asset).unwrap(), hash);

		let other = "b".repeat(64);
		let sums_multi = format!("{other}  other-asset.tar.gz\n{hash} *{asset}\n");
		assert_eq!(expected_hash_from_sha256sums(&sums_multi, asset).unwrap(), hash);

		assert!(expected_hash_from_sha256sums(&sums, "missing.tar.gz").is_err());
	}
}
