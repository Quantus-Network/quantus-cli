use crate::{error::Result, log_print, log_verbose, wallet::WalletManager};
use colored::Colorize;

/// Ensure an already-opened secret file is a regular file owned by the current
/// user with no group/other access bits set. Checking the handle (fstat) rather
/// than the path avoids validating a different file than the one read.
#[cfg(unix)]
fn validate_owner_only_file(file: &std::fs::File, file_path: &str, kind: &str) -> Result<()> {
	use std::os::unix::fs::MetadataExt;

	let metadata = file.metadata().map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to inspect {kind} file '{file_path}': {e}"
		))
	})?;

	if !metadata.is_file() {
		return Err(crate::error::QuantusError::Generic(format!(
			"🔒 Refusing to read {kind} file '{file_path}': it is not a regular file.\n\
			 Secret files must be plain files owned by you with permissions 600 \
			 (FIFOs, devices, and process substitution are not accepted)."
		)));
	}

	// SAFETY: geteuid is a POSIX libc function with no preconditions.
	let effective_uid = unsafe { libc::geteuid() };
	if metadata.uid() != effective_uid {
		let quoted = shell_quote(file_path);
		return Err(crate::error::QuantusError::Generic(format!(
			"🔒 Refusing to read {kind} file '{file_path}': it is not owned by the current user.\n\
			 Secret files must belong to the user running quantus. Fix it with:\n\
			 \n\
			 \tchown $(id -un) -- {quoted}"
		)));
	}

	let mode = metadata.mode() & 0o777;
	if mode & 0o077 != 0 {
		let quoted = shell_quote(file_path);
		return Err(crate::error::QuantusError::Generic(format!(
			"🔒 Refusing to read {kind} file '{file_path}': it is accessible by other users (permissions {mode:o}).\n\
			 Secret files must be readable only by you. Fix it with:\n\
			 \n\
			 \tchmod 600 -- {quoted}"
		)));
	}

	Ok(())
}

/// Quote a path for safe copy/paste into a POSIX shell command.
#[cfg(unix)]
fn shell_quote(path: &str) -> String {
	format!("'{}'", path.replace('\'', r"'\''"))
}

#[cfg(not(unix))]
fn validate_owner_only_file(_file: &std::fs::File, _file_path: &str, _kind: &str) -> Result<()> {
	Ok(())
}

/// Open without blocking: a plain `File::open` on a FIFO with no writer hangs
/// forever, before the regular-file check ever runs. O_NONBLOCK is a no-op for
/// regular files, and non-regular files are rejected right after fstat.
#[cfg(unix)]
fn open_secret_file(file_path: &str) -> std::io::Result<std::fs::File> {
	use std::os::unix::fs::OpenOptionsExt;
	std::fs::OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NONBLOCK)
		.open(file_path)
}

#[cfg(not(unix))]
fn open_secret_file(file_path: &str) -> std::io::Result<std::fs::File> {
	std::fs::File::open(file_path)
}

/// Read a trimmed secret from a file, requiring (on Unix) a regular file owned
/// by the current user with no group/other access bits.
pub(crate) fn read_secret_file(file_path: &str, kind: &str) -> Result<String> {
	use std::io::Read;

	log_verbose!("🔑 Reading {kind} from file: {file_path}");
	let mut file = open_secret_file(file_path).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to open {kind} file '{file_path}': {e}"
		))
	})?;
	validate_owner_only_file(&file, file_path, kind)?;
	let mut raw = String::new();
	file.read_to_string(&mut raw).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to read {kind} file '{file_path}': {e}"
		))
	})?;
	let value = raw.trim().to_string();
	crate::wallet::keystore::zeroize_string(&mut raw);
	Ok(value)
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
	read_secret_file(file_path, "password")
}

/// Read a mnemonic phrase from a file (never from argv).
///
/// On Unix the file must be a regular file owned by the current user with no
/// group/other access bits, matching `--password-file`. A leading UTF-8 BOM is
/// stripped and interior whitespace (e.g. one word per line) is normalized to
/// single spaces so the stored phrase is a single line.
pub fn read_mnemonic_file(file_path: &str) -> Result<String> {
	let mut raw = read_secret_file(file_path, "mnemonic")?;
	let mnemonic = raw
		.trim_start_matches('\u{feff}')
		.split_whitespace()
		.collect::<Vec<_>>()
		.join(" ");
	crate::wallet::keystore::zeroize_string(&mut raw);
	if mnemonic.is_empty() {
		return Err(crate::error::QuantusError::Generic(format!(
			"Mnemonic file '{file_path}' is empty"
		)));
	}
	Ok(mnemonic)
}

/// Look up a wallet password from the environment without prompting.
pub fn env_wallet_password(wallet_name: &str) -> Option<String> {
	password_from_env(wallet_name)
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

	fn write_secret_file(contents: &str) -> (tempfile::TempDir, String) {
		let dir = tempfile::tempdir().expect("temp dir");
		let path = dir.path().join("secret.txt");
		std::fs::write(&path, contents).expect("write secret file");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
				.expect("set secret file mode");
		}
		let path_str = path.to_string_lossy().into_owned();
		(dir, path_str)
	}

	#[test]
	fn read_mnemonic_file_rejects_empty() {
		let (_dir, path) = write_secret_file("   \n");
		let err = read_mnemonic_file(&path).unwrap_err();
		assert!(err.to_string().contains("is empty"), "expected empty-file rejection, got: {err}");
	}

	#[test]
	fn read_mnemonic_file_reads_phrase() {
		let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		let (_dir, path) = write_secret_file(&format!("{phrase}\n"));
		assert_eq!(read_mnemonic_file(&path).expect("mnemonic file"), phrase);
	}

	#[test]
	fn read_mnemonic_file_normalizes_interior_whitespace() {
		let (_dir, path) = write_secret_file("word1\nword2\r\n  word3\tword4\n");
		assert_eq!(read_mnemonic_file(&path).unwrap(), "word1 word2 word3 word4");
	}

	#[test]
	fn read_mnemonic_file_strips_utf8_bom() {
		let (_dir, path) = write_secret_file("\u{feff}word1 word2\n");
		assert_eq!(read_mnemonic_file(&path).unwrap(), "word1 word2");
	}

	#[cfg(unix)]
	mod secret_file_permissions {
		use super::*;
		use std::{fs, os::unix::fs::PermissionsExt};

		fn write_secret_file_with_mode(contents: &str, mode: u32) -> (tempfile::TempDir, String) {
			let (dir, path) = super::write_secret_file(contents);
			fs::set_permissions(&path, fs::Permissions::from_mode(mode))
				.expect("set secret file mode");
			(dir, path)
		}

		#[test]
		fn rejects_group_or_world_readable_password_file() {
			let (_dir, path) = write_secret_file_with_mode("correct horse battery staple\n", 0o644);
			let err = read_password_file(&path).unwrap_err();
			let msg = err.to_string();
			assert!(
				msg.contains("accessible by other users") && msg.contains("chmod 600"),
				"expected restrictive-mode rejection with fix hint, got: {msg}"
			);
		}

		#[test]
		fn accepts_owner_only_password_file() {
			let (_dir, path) = write_secret_file_with_mode("correct horse battery staple\n", 0o600);
			assert_eq!(
				read_password_file(&path).expect("owner-only password file"),
				"correct horse battery staple"
			);
		}

		#[test]
		fn read_secret_file_rejects_fifo_without_blocking() {
			let dir = tempfile::tempdir().expect("temp dir");
			let path = dir.path().join("secret.fifo");
			let c_path = std::ffi::CString::new(path.to_str().expect("utf-8 path")).unwrap();
			// SAFETY: c_path is a valid NUL-terminated path.
			let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
			assert_eq!(rc, 0, "mkfifo failed");
			let err = read_secret_file(path.to_str().unwrap(), "secret").unwrap_err();
			assert!(
				err.to_string().contains("not a regular file"),
				"expected non-regular-file rejection, got: {err}"
			);
		}

		#[test]
		fn fix_hints_shell_quote_hostile_paths() {
			let dir = tempfile::tempdir().expect("temp dir");
			let path = dir.path().join("owner'; touch pwned;'.txt");
			fs::write(&path, "secret\n").expect("write secret file");
			fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
				.expect("set secret file mode");
			let err = read_secret_file(path.to_str().unwrap(), "secret").unwrap_err();
			let msg = err.to_string();
			assert!(
				msg.contains(r"chmod 600 -- ") && msg.contains(r"owner'\''; touch pwned;'\''.txt"),
				"expected shell-quoted fix hint, got: {msg}"
			);
		}

		#[test]
		fn read_mnemonic_file_rejects_group_or_world_readable() {
			let phrase = "abandon abandon about";
			let (_dir, path) = write_secret_file_with_mode(&format!("{phrase}\n"), 0o644);
			let err = read_mnemonic_file(&path).unwrap_err();
			let msg = err.to_string();
			assert!(
				msg.contains("accessible by other users") && msg.contains("chmod 600"),
				"expected restrictive-mode rejection with fix hint, got: {msg}"
			);
		}
	}
}
