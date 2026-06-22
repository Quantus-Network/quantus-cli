//! Update notification module.
//!
//! Checks GitHub for the latest published release of the CLI and notifies the
//! user when a newer version is available. The result is cached on disk for a
//! short period so we don't query GitHub on every invocation (avoids latency
//! and API rate-limiting).
//!
//! The check is strictly best-effort: any network, parsing or filesystem error
//! is swallowed silently so it can never interfere with the actual command.

use crate::log_print;
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
fn read_cache() -> Option<UpdateCache> {
	let path = cache_path()?;
	let contents = std::fs::read_to_string(path).ok()?;
	serde_json::from_str(&contents).ok()
}

/// Persist the cache file, creating the parent directory if needed.
fn write_cache(cache: &UpdateCache) {
	let Some(path) = cache_path() else { return };
	if let Some(parent) = path.parent() {
		let _ = std::fs::create_dir_all(parent);
	}
	if let Ok(contents) = serde_json::to_string_pretty(cache) {
		let _ = std::fs::write(path, contents);
	}
}

/// Query GitHub for the latest release tag (without a leading `v`).
async fn fetch_latest_version() -> Option<String> {
	let client = reqwest::Client::builder()
		.timeout(REQUEST_TIMEOUT)
		// GitHub requires a User-Agent header on all API requests.
		.user_agent(concat!("quantus-cli/", env!("CARGO_PKG_VERSION")))
		.build()
		.ok()?;

	let release = client
		.get(LATEST_RELEASE_URL)
		.header("Accept", "application/vnd.github+json")
		.send()
		.await
		.ok()?
		.error_for_status()
		.ok()?
		.json::<GithubRelease>()
		.await
		.ok()?;

	Some(normalize(&release.tag_name).to_string())
}

/// Resolve the latest known version, using the cache when it is still fresh and
/// otherwise querying GitHub and refreshing the cache.
async fn latest_version() -> Option<String> {
	if let Some(cache) = read_cache() {
		if now_secs().saturating_sub(cache.last_checked) < CACHE_TTL.as_secs() {
			return Some(cache.latest_version);
		}
	}

	let latest = fetch_latest_version().await?;
	write_cache(&UpdateCache { last_checked: now_secs(), latest_version: latest.clone() });
	Some(latest)
}

/// Perform the update check and print a notice when a newer version exists.
///
/// This is best-effort and never returns an error: it is safe to call from any
/// command path. Honors the `QUANTUS_NO_UPDATE_CHECK` opt-out.
pub async fn notify_if_update_available() {
	if std::env::var_os(DISABLE_ENV).is_some() {
		return;
	}

	let current = env!("CARGO_PKG_VERSION");
	let Some(latest) = latest_version().await else { return };

	if is_newer(current, &latest) {
		log_print!("");
		log_print!(
			"{} A new version of Quantus CLI is available: {} → {}",
			"⬆️".bright_yellow(),
			current.dimmed(),
			latest.bright_green().bold()
		);
		log_print!("   Download it from {}", RELEASES_PAGE_URL.bright_cyan());
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
