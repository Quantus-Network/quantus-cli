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
		.identifier(ASSET_IDENTIFIER)
		.current_version(env!("CARGO_PKG_VERSION"));
	builder
}

/// Resolve the latest *stable* release version from GitHub (without a leading
/// `v`), using the same `/releases/latest` resolution as the install path.
///
/// Blocking: `self_update` performs synchronous I/O, so call this off the async
/// runtime's worker threads (e.g. via `spawn_blocking`).
pub fn latest_stable_version() -> crate::error::Result<String> {
	let release = configure_updater()
		.build()
		.map_err(map_self_update_err)?
		.get_latest_release()
		.map_err(map_self_update_err)?;
	Ok(release.version.trim_start_matches('v').to_string())
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
		if self_update::version::bump_is_greater(current, &latest).unwrap_or(false) {
			return Ok(UpdateOutcome::UpdateAvailable(latest));
		}
		return Ok(UpdateOutcome::AlreadyLatest(current.to_string()));
	}

	let mut builder = configure_updater();
	builder.show_download_progress(true).no_confirm(yes);

	if let Some(version) = version {
		// Accept both `1.5.0` and `v1.5.0`; the release tags include the `v`.
		let tag = if version.starts_with('v') { version } else { format!("v{version}") };
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
