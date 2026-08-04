use crate::{error::Result, log_print, log_verbose, wallet::WalletManager};
use colored::Colorize;

/// Ensure a password file is a regular file owned by the current user with
/// no group/other access bits set before reading its contents.
#[cfg(unix)]
fn validate_password_file_permissions(file_path: &str) -> Result<()> {
	use std::os::unix::fs::MetadataExt;

	unsafe extern "C" {
		fn geteuid() -> u32;
	}

	let metadata = std::fs::metadata(file_path).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to inspect password file '{file_path}': {e}"
		))
	})?;

	if !metadata.is_file() {
		return Err(crate::error::QuantusError::Generic(format!(
			"Password file '{file_path}' is not a regular file"
		)));
	}

	// SAFETY: geteuid is a POSIX libc function with no preconditions.
	let effective_uid = unsafe { geteuid() };
	if metadata.uid() != effective_uid {
		return Err(crate::error::QuantusError::Generic(format!(
			"Password file '{file_path}' must be owned by the current user"
		)));
	}

	let mode = metadata.mode() & 0o777;
	if mode & 0o077 != 0 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Password file '{file_path}' must not be accessible by group or other users (mode {mode:o})"
		)));
	}

	Ok(())
}

#[cfg(not(unix))]
fn validate_password_file_permissions(_file_path: &str) -> Result<()> {
	Ok(())
}

fn reject_raw_cli_password(password: &Option<String>) -> Result<()> {
	if password.is_some() {
		return Err(crate::error::QuantusError::Generic(
			"Passing wallet passwords with --password/-p is not supported; use --password-file, QUANTUS_WALLET_PASSWORD, or the interactive prompt".to_string(),
		));
	}
	Ok(())
}

fn read_password_file(file_path: &str) -> Result<String> {
	log_verbose!("🔑 Reading password from file: {}", file_path);
	validate_password_file_permissions(file_path)?;
	let pwd = std::fs::read_to_string(file_path)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Failed to read password file '{file_path}': {e}"
			))
		})?
		.trim()
		.to_string();
	Ok(pwd)
}

fn password_from_env(wallet_name: &str) -> Option<String> {
	if let Ok(env_password) = std::env::var("QUANTUS_WALLET_PASSWORD") {
		log_verbose!("🔑 Using password from QUANTUS_WALLET_PASSWORD environment variable");
		return Some(env_password);
	}

	let wallet_env_var = format!("QUANTUS_WALLET_PASSWORD_{}", wallet_name.to_uppercase());
	if let Ok(env_password) = std::env::var(&wallet_env_var) {
		log_verbose!("🔑 Using password from {} environment variable", wallet_env_var);
		return Some(env_password);
	}

	None
}

/// Reject empty passwords unless explicitly allowed for development wallets.
pub fn ensure_password_allowed(password: String, allow_empty: bool) -> Result<String> {
	if password.is_empty() && !allow_empty {
		return Err(crate::error::QuantusError::Generic(
			"Empty wallet passwords are not allowed; provide a password via --password-file, QUANTUS_WALLET_PASSWORD, or the interactive prompt (use --allow-empty-password only for development wallets)".to_string(),
		));
	}
	Ok(password)
}

/// Confirm that two newly entered passwords match.
pub fn confirm_new_password(first: &str, second: &str) -> Result<String> {
	if first != second {
		return Err(crate::error::QuantusError::Generic("Passwords do not match".to_string()));
	}
	Ok(first.to_string())
}

/// Get wallet password with convenience options
pub fn get_wallet_password(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<String> {
	// Raw passwords passed through command-line arguments are visible in process
	// listings and command logs. Use --password-file, QUANTUS_WALLET_PASSWORD,
	// wallet-specific environment variables, or the masked prompt instead.
	reject_raw_cli_password(&password)?;

	if let Some(file_path) = password_file {
		return read_password_file(&file_path);
	}

	if let Some(env_password) = password_from_env(wallet_name) {
		return Ok(env_password);
	}

	// Try empty password first (for development wallets)
	log_verbose!("🔑 Trying empty password first...");
	let wallet_manager = WalletManager::new()?;
	if wallet_manager.load_wallet(wallet_name, "").is_ok() {
		log_verbose!("✅ Empty password works for wallet '{}'", wallet_name);
		return Ok("".to_string());
	}

	get_password_from_user(&format!("Enter password for wallet '{wallet_name}'"))
}

/// Obtain a password for creating a new wallet.
///
/// Unlike [`get_wallet_password`], this never silently defaults to an empty
/// password. Empty passwords require `allow_empty`. Interactive entry is confirmed.
pub fn get_new_wallet_password(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
	allow_empty: bool,
) -> Result<String> {
	reject_raw_cli_password(&password)?;

	if let Some(file_path) = password_file {
		return ensure_password_allowed(read_password_file(&file_path)?, allow_empty);
	}

	if let Some(env_password) = password_from_env(wallet_name) {
		return ensure_password_allowed(env_password, allow_empty);
	}

	if allow_empty {
		log_verbose!("🔑 Creating wallet with explicitly allowed empty password");
		return Ok(String::new());
	}

	let first =
		get_password_from_user(&format!("Enter a password for new wallet '{wallet_name}'"))?;
	let second = get_password_from_user("Confirm password")?;
	let confirmed = confirm_new_password(&first, &second)?;
	ensure_password_allowed(confirmed, allow_empty)
}

/// Get mnemonic phrase from user
pub fn get_mnemonic_from_user() -> Result<String> {
	log_print!("{}", "Please enter or paste your secret phrase:".bright_yellow());
	let mut mnemonic = rpassword::read_password().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read secret phrase: {e}"))
	})?;
	let trimmed = mnemonic.trim().to_string();
	crate::wallet::keystore::zeroize_string(&mut mnemonic);
	Ok(trimmed)
}

/// Get password from user securely
pub fn get_password_from_user(prompt: &str) -> Result<String> {
	log_print!("{}", prompt.bright_yellow());
	let password = rpassword::read_password().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read password: {e}"))
	})?;
	Ok(password)
}

#[cfg(test)]
mod tests {
	use super::*;
	use serial_test::serial;

	#[test]
	fn get_wallet_password_rejects_cli_password_flag() {
		let err = get_wallet_password("w", Some("secret".into()), None).unwrap_err();
		let msg = err.to_string();
		assert!(msg.contains("--password"), "expected unsupported --password message, got: {msg}");
	}

	#[test]
	fn get_new_wallet_password_rejects_cli_password_flag() {
		let err = get_new_wallet_password("w", Some("secret".into()), None, false).unwrap_err();
		assert!(err.to_string().contains("--password"));
	}

	#[test]
	fn ensure_password_allowed_rejects_empty_without_opt_in() {
		let err = ensure_password_allowed(String::new(), false).unwrap_err();
		assert!(err.to_string().contains("--allow-empty-password"));
	}

	#[test]
	fn ensure_password_allowed_accepts_empty_with_opt_in() {
		assert_eq!(ensure_password_allowed(String::new(), true).unwrap(), "");
	}

	#[test]
	fn confirm_new_password_requires_match() {
		assert!(confirm_new_password("a", "b").is_err());
		assert_eq!(confirm_new_password("same", "same").unwrap(), "same");
	}

	#[test]
	fn get_new_wallet_password_allow_empty_without_other_sources() {
		let pwd = get_new_wallet_password("brand-new-wallet", None, None, true).unwrap();
		assert_eq!(pwd, "");
	}

	#[test]
	#[serial]
	fn get_new_wallet_password_uses_env_and_rejects_empty_env_without_opt_in() {
		// SAFETY: serial_test isolates this from other env-mutating tests.
		unsafe {
			std::env::remove_var("QUANTUS_WALLET_PASSWORD");
			std::env::remove_var("QUANTUS_WALLET_PASSWORD_ENVWALLET");
			std::env::set_var("QUANTUS_WALLET_PASSWORD", "env-secret");
		}
		let pwd = get_new_wallet_password("envwallet", None, None, false).unwrap();
		assert_eq!(pwd, "env-secret");

		unsafe {
			std::env::set_var("QUANTUS_WALLET_PASSWORD", "");
		}
		let err = get_new_wallet_password("envwallet", None, None, false).unwrap_err();
		assert!(err.to_string().contains("--allow-empty-password"));

		unsafe {
			std::env::remove_var("QUANTUS_WALLET_PASSWORD");
		}
	}

	#[cfg(unix)]
	mod password_file_permissions {
		use super::*;
		use std::{fs, os::unix::fs::PermissionsExt};

		fn write_password_file(mode: u32) -> (tempfile::TempDir, String) {
			let dir = tempfile::tempdir().expect("temp dir");
			let path = dir.path().join("wallet-password.txt");
			fs::write(&path, "correct horse battery staple\n").expect("write password file");
			fs::set_permissions(&path, fs::Permissions::from_mode(mode))
				.expect("set password file mode");
			let path_str = path.to_string_lossy().into_owned();
			(dir, path_str)
		}

		#[test]
		fn rejects_group_or_world_readable_password_file() {
			let (_dir, path) = write_password_file(0o644);
			let err = validate_password_file_permissions(&path).unwrap_err();
			let msg = err.to_string();
			assert!(
				msg.contains("must not be accessible by group or other"),
				"expected restrictive-mode rejection, got: {msg}"
			);
		}

		#[test]
		fn accepts_owner_only_password_file() {
			let (_dir, path) = write_password_file(0o600);
			validate_password_file_permissions(&path)
				.expect("owner-only password file owned by self should be accepted");
		}
	}
}
