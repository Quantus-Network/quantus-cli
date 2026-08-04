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

/// Get wallet password with convenience options
pub fn get_wallet_password(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<String> {
	// Raw passwords passed through command-line arguments are visible in process
	// listings and command logs. Use --password-file, QUANTUS_WALLET_PASSWORD,
	// wallet-specific environment variables, or the masked prompt instead.
	if password.is_some() {
		return Err(crate::error::QuantusError::Generic(
			"Passing wallet passwords with --password/-p is not supported; use --password-file, QUANTUS_WALLET_PASSWORD, or the interactive prompt".to_string(),
		));
	}

	// Option 2: Read password from file if provided
	if let Some(file_path) = password_file {
		log_verbose!("🔑 Reading password from file: {}", file_path);
		validate_password_file_permissions(&file_path)?;
		let pwd = std::fs::read_to_string(&file_path)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to read password file '{file_path}': {e}"
				))
			})?
			.trim()
			.to_string();
		return Ok(pwd);
	}

	// Option 3: Check environment variable
	if let Ok(env_password) = std::env::var("QUANTUS_WALLET_PASSWORD") {
		log_verbose!("🔑 Using password from QUANTUS_WALLET_PASSWORD environment variable");
		return Ok(env_password);
	}

	// Option 4: Check for wallet-specific environment variable
	let wallet_env_var = format!("QUANTUS_WALLET_PASSWORD_{}", wallet_name.to_uppercase());
	if let Ok(env_password) = std::env::var(&wallet_env_var) {
		log_verbose!("🔑 Using password from {} environment variable", wallet_env_var);
		return Ok(env_password);
	}

	// Option 5: Try empty password first (for development wallets)
	log_verbose!("🔑 Trying empty password first...");
	let wallet_manager = WalletManager::new()?;
	if wallet_manager.load_wallet(wallet_name, "").is_ok() {
		log_verbose!("✅ Empty password works for wallet '{}'", wallet_name);
		return Ok("".to_string());
	}

	// Option 6: Prompt user for password
	get_password_from_user(&format!("Enter password for wallet '{wallet_name}'"))
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

/// Reject raw `--password`/`-p` values for handlers that bypass [`get_wallet_password`].
pub fn reject_cli_password(password: &Option<String>) -> Result<()> {
	if password.is_some() {
		return Err(crate::error::QuantusError::Generic(
			"Passing wallet passwords with --password/-p is not supported; use an interactive prompt or a supported non-argv secret source".to_string(),
		));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_wallet_password_rejects_cli_password_flag() {
		let err = get_wallet_password("w", Some("secret".into()), None).unwrap_err();
		let msg = err.to_string();
		assert!(
			msg.contains("--password"),
			"expected unsupported --password message, got: {msg}"
		);
	}

	#[test]
	fn wallet_create_rejects_cli_password() {
		let err = reject_cli_password(&Some("secret".into())).unwrap_err();
		let msg = err.to_string();
		assert!(
			msg.contains("--password"),
			"expected unsupported --password message, got: {msg}"
		);
	}

	#[cfg(unix)]
	mod password_file_permissions {
		use super::*;
		use std::fs;
		use std::os::unix::fs::PermissionsExt;

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
