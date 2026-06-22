//! Self-update command.
//!
//! Downloads the appropriate release archive from GitHub for the current
//! platform and replaces the running `quantus` binary in place. Cross-platform
//! binary replacement (including the Windows "can't overwrite a running exe"
//! case) is handled by the `self_update` crate.

use crate::{error::QuantusError, log_print, log_success};
use colored::Colorize;

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

/// Blocking implementation that talks to GitHub and replaces the binary.
fn run_update(
	check_only: bool,
	yes: bool,
	version: Option<String>,
) -> crate::error::Result<UpdateOutcome> {
	let current = env!("CARGO_PKG_VERSION");

	// In check-only mode we just look up the latest release and compare.
	if check_only {
		let release = self_update::backends::github::ReleaseList::configure()
			.repo_owner(REPO_OWNER)
			.repo_name(REPO_NAME)
			.build()
			.and_then(|list| list.fetch())
			.map_err(map_self_update_err)?;

		let latest = release
			.first()
			.ok_or_else(|| QuantusError::Generic("No releases found on GitHub.".to_string()))?;

		let latest_version = latest.version.trim_start_matches('v');
		if self_update::version::bump_is_greater(current, latest_version).unwrap_or(false) {
			return Ok(UpdateOutcome::UpdateAvailable(latest_version.to_string()));
		}
		return Ok(UpdateOutcome::AlreadyLatest(current.to_string()));
	}

	let mut builder = self_update::backends::github::Update::configure();
	builder
		.repo_owner(REPO_OWNER)
		.repo_name(REPO_NAME)
		.bin_name(BIN_NAME)
		// Archives extract to `quantus-cli-v{version}-{target}/quantus`.
		// `{{ version }}` is substituted without the leading `v`, so it is
		// added back as a literal here.
		.bin_path_in_archive("quantus-cli-v{{ version }}-{{ target }}/{{ bin }}")
		.identifier(ASSET_IDENTIFIER)
		.show_download_progress(true)
		.no_confirm(yes)
		.current_version(current);

	if let Some(version) = version {
		// Accept both `1.5.0` and `v1.5.0`; the release tags include the `v`.
		let tag =
			if version.starts_with('v') { version.clone() } else { format!("v{version}") };
		builder.target_version_tag(&tag);
	}

	let status = builder
		.build()
		.map_err(map_self_update_err)?
		.update()
		.map_err(map_self_update_err)?;

	if status.updated() {
		Ok(UpdateOutcome::Updated(status.version().to_string()))
	} else {
		Ok(UpdateOutcome::AlreadyLatest(status.version().to_string()))
	}
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
