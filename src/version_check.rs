//! Update notification module.
//!
//! Checks GitHub for the latest published release of the CLI and notifies the
//! user when a newer version is available. The result is cached on disk for a
//! short period so we don't query GitHub on every invocation (avoids latency
//! and API rate-limiting).
//!
//! The check is strictly best-effort: any network, parsing or filesystem error
//! can never interfere with the actual command. To stay aligned with the
//! "fail early / always log" rule, these errors are not silenced outright —
//! they are downgraded to `log_verbose!` so `-v` surfaces exactly what happened
//! without spamming normal output.
//!
//! To avoid adding latency, the network fetch never blocks the command. The
//! latest version is resolved from an on-disk cache via [`refresh_cache_in_background`]
//! (spawned to run concurrently with the command), while [`notify_if_update_available`]
//! only consults that cache and prints instantly. The first run with a cold
//! cache shows nothing; a later run (once the cache is warm) shows the notice.

use crate::{log_print, log_verbose};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};

/// GitHub API endpoint returning the latest (non-prerelease) release.
const LATEST_RELEASE_URL: &str =
	"https://api.github.com/repos/Quantus-Network/quantus-cli/releases/latest";

/// Page users can visit to download a new release.
const RELEASES_PAGE_URL: &str = "https://github.com/Quantus-Network/quantus-cli/releases";

/// How long a cached result is considered fresh before we query GitHub again.
const CACHE_TTL: Duration = Duration::from_secs(60 * 60 * 4); // 4 hours

/// Maximum time we allow the network request to take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Environment variable that, when set to any value, disables the update check.
const DISABLE_ENV: &str = "QUANTUS_NO_UPDATE_CHECK";

/// On-disk cache of the last update check.
#[derive(Debug, Serialize, Deserialize)]
struct UpdateCache {
	/// Unix timestamp (seconds) of when the check was last performed.
	last_checked: u64,
	/// Latest version tag observed from GitHub (without a leading `v`).
	latest_version: String,
}

/// Minimal shape of the GitHub release response we care about.
#[derive(Debug, Deserialize)]
struct GithubRelease {
	tag_name: String,
}

/// Location of the cache file: `~/.quantus/update_check.json`.
fn cache_path() -> Option<PathBuf> {
	dirs::home_dir().map(|home| home.join(".quantus").join("update_check.json"))
}

/// Current unix time in seconds.
fn now_secs() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0)
}

/// Strip a leading `v`/`V` from a version tag, returning the bare version.
fn normalize(version: &str) -> &str {
	version.trim().strip_prefix(['v', 'V']).unwrap_or(version.trim())
}

/// Parse a semver-ish string into numeric `(major, minor, patch)` components.
/// Any pre-release/build suffix (after `-` or `+`) is ignored.
fn parse_version(version: &str) -> Option<(u64, u64, u64)> {
	let core = normalize(version);
	let core = core.split(['-', '+']).next().unwrap_or(core);
	let mut parts = core.split('.');
	let major = parts.next()?.parse().ok()?;
	let minor = parts.next().unwrap_or("0").parse().ok()?;
	let patch = parts.next().unwrap_or("0").parse().ok()?;
	Some((major, minor, patch))
}

/// Returns `true` if `latest` is strictly newer than `current`.
fn is_newer(current: &str, latest: &str) -> bool {
	match (parse_version(current), parse_version(latest)) {
		(Some(c), Some(l)) => l > c,
		// If we can't parse, fall back to a conservative string inequality so we
		// don't nag users with a malformed comparison.
		_ => false,
	}
}

/// Read the cache file if it exists and is well-formed.
///
/// A missing cache file is expected (e.g. on first run) and not logged. Any
/// other read/parse failure is surfaced via `log_verbose!`.
fn read_cache() -> Option<UpdateCache> {
	let path = cache_path()?;
	let contents = match std::fs::read_to_string(&path) {
		Ok(contents) => contents,
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
		Err(e) => {
			log_verbose!("update check: failed to read cache {}: {e}", path.display());
			return None;
		},
	};
	match serde_json::from_str(&contents) {
		Ok(cache) => Some(cache),
		Err(e) => {
			log_verbose!("update check: failed to parse cache {}: {e}", path.display());
			None
		},
	}
}

/// Persist the cache file, creating the parent directory if needed.
fn write_cache(cache: &UpdateCache) {
	let Some(path) = cache_path() else {
		log_verbose!("update check: could not determine cache path; skipping cache write");
		return;
	};
	if let Some(parent) = path.parent() {
		if let Err(e) = std::fs::create_dir_all(parent) {
			log_verbose!(
				"update check: failed to create cache dir {}: {e}",
				parent.display()
			);
			return;
		}
	}
	match serde_json::to_string_pretty(cache) {
		Ok(contents) => {
			if let Err(e) = std::fs::write(&path, contents) {
				log_verbose!("update check: failed to write cache {}: {e}", path.display());
			}
		},
		Err(e) => log_verbose!("update check: failed to serialize cache: {e}"),
	}
}

/// Query GitHub for the latest release tag (without a leading `v`).
async fn fetch_latest_version() -> Option<String> {
	let client = match reqwest::Client::builder()
		.timeout(REQUEST_TIMEOUT)
		// GitHub requires a User-Agent header on all API requests.
		.user_agent(concat!("quantus-cli/", env!("CARGO_PKG_VERSION")))
		.build()
	{
		Ok(client) => client,
		Err(e) => {
			log_verbose!("update check: failed to build HTTP client: {e}");
			return None;
		},
	};

	let response = match client
		.get(LATEST_RELEASE_URL)
		.header("Accept", "application/vnd.github+json")
		.send()
		.await
	{
		Ok(response) => response,
		Err(e) => {
			log_verbose!("update check: request to GitHub failed: {e}");
			return None;
		},
	};

	let response = match response.error_for_status() {
		Ok(response) => response,
		Err(e) => {
			log_verbose!("update check: GitHub returned an error status: {e}");
			return None;
		},
	};

	match response.json::<GithubRelease>().await {
		Ok(release) => Some(normalize(&release.tag_name).to_string()),
		Err(e) => {
			log_verbose!("update check: failed to parse GitHub response: {e}");
			None
		},
	}
}

/// Print an update notice when a *fresh* cached result already says a newer
/// version exists.
///
/// This never performs network I/O — it only consults the on-disk cache — so it
/// is effectively instant and adds no latency to the command. The cache is
/// populated by [`refresh_cache_in_background`], which runs concurrently with
/// the command. When the cache is cold or stale we print nothing; a later
/// invocation (once the cache is warm) shows the notice. Honors the
/// `QUANTUS_NO_UPDATE_CHECK` opt-out.
pub fn notify_if_update_available() {
	if std::env::var_os(DISABLE_ENV).is_some() {
		return;
	}

	let Some(cache) = read_cache() else {
		log_verbose!("update check: no cached result yet; nothing to show");
		return;
	};

	if now_secs().saturating_sub(cache.last_checked) >= CACHE_TTL.as_secs() {
		log_verbose!("update check: cached result is stale; refreshing in background");
		return;
	}

	let current = env!("CARGO_PKG_VERSION");
	if is_newer(current, &cache.latest_version) {
		log_print!("");
		log_print!(
			"{} A new version of Quantus CLI is available: {} → {}",
			"⬆️".bright_yellow(),
			current.dimmed(),
			cache.latest_version.bright_green().bold()
		);
		log_print!("   Download it from {}", RELEASES_PAGE_URL.bright_cyan());
	}
}

/// Refresh the cached latest-version from GitHub when the cache is missing or
/// stale.
///
/// Best-effort and designed to never block the command: it is meant to be
/// spawned and left to run concurrently so the *next* invocation has a warm
/// cache to display. Honors the `QUANTUS_NO_UPDATE_CHECK` opt-out.
pub async fn refresh_cache_in_background() {
	if std::env::var_os(DISABLE_ENV).is_some() {
		return;
	}

	if let Some(cache) = read_cache() {
		if now_secs().saturating_sub(cache.last_checked) < CACHE_TTL.as_secs() {
			log_verbose!("update check: cache is fresh; skipping refresh");
			return;
		}
	}

	match fetch_latest_version().await {
		Some(latest) => {
			write_cache(&UpdateCache { last_checked: now_secs(), latest_version: latest });
			log_verbose!("update check: refreshed cached latest version");
		},
		None => log_verbose!("update check: could not refresh latest version"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn normalize_strips_v_prefix() {
		assert_eq!(normalize("v1.5.0"), "1.5.0");
		assert_eq!(normalize("V1.5.0"), "1.5.0");
		assert_eq!(normalize("1.5.0"), "1.5.0");
		assert_eq!(normalize("  v1.5.0  "), "1.5.0");
	}

	#[test]
	fn parse_version_handles_suffixes() {
		assert_eq!(parse_version("v1.5.0"), Some((1, 5, 0)));
		assert_eq!(parse_version("1.5"), Some((1, 5, 0)));
		assert_eq!(parse_version("2"), Some((2, 0, 0)));
		assert_eq!(parse_version("1.5.0-beta.1"), Some((1, 5, 0)));
		assert_eq!(parse_version("1.5.0+build"), Some((1, 5, 0)));
		assert_eq!(parse_version("not-a-version"), None);
	}

	#[test]
	fn is_newer_compares_correctly() {
		assert!(is_newer("1.4.0", "1.5.0"));
		assert!(is_newer("1.5.0", "1.5.1"));
		assert!(is_newer("1.5.0", "2.0.0"));
		assert!(is_newer("1.5.0", "v1.6.0"));
		assert!(!is_newer("1.5.0", "1.5.0"));
		assert!(!is_newer("1.5.0", "1.4.9"));
		assert!(!is_newer("1.5.0", "garbage"));
	}
}
