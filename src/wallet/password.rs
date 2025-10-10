use crate::{error::Result, log_print, log_verbose, wallet::WalletManager};
use colored::Colorize;

/// Get wallet password with convenience options
pub fn get_wallet_password(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<String> {
	// Option 1: Use CLI password flag if provided
	if let Some(pwd) = password {
		log_verbose!("🔑 Using password from --password flag");
		return Ok(pwd);
	}

	// Option 2: Read password from file if provided
	if let Some(file_path) = password_file {
		log_verbose!("🔑 Reading password from file: {}", file_path);
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
	let mnemonic = rpassword::read_password().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read secret phrase: {e}"))
	})?;
	Ok(mnemonic.trim().to_string())
}

/// Get password from user securely
pub fn get_password_from_user(prompt: &str) -> Result<String> {
	log_print!("{}", prompt.bright_yellow());
	let password = rpassword::read_password().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read password: {e}"))
	})?;
	Ok(password)
}
