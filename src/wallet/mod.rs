/// Wallet management module
///
/// This module provides functionality for:
/// - Creating quantum-safe wallets using Dilithium keys
/// - Importing/exporting wallets with mnemonic phrases
/// - Encrypting/decrypting wallet data
/// - Managing multiple wallets
pub mod keystore;
pub mod password;

use crate::error::{QuantusError, Result, WalletError};
pub use keystore::{Keystore, QuantumKeyPair, WalletData};
use qp_dilithium_crypto::DilithiumPair;
use qp_rusty_crystals_hdwallet::{
	derive_key_from_mnemonic, generate_mnemonic, mnemonic_to_seed, SensitiveBytes32,
};
use rand::{rng, RngCore};
use serde::{Deserialize, Serialize};

/// Default derivation path for Quantus wallets: m/44'/189189'/0'/0'/0'
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/189189'/0'/0'/0'";

/// Wallet information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
	pub name: String,
	pub address: String,
	pub created_at: chrono::DateTime<chrono::Utc>,
	pub key_type: String,
	pub derivation_path: String,
}

/// Main wallet manager
pub struct WalletManager {
	wallets_dir: std::path::PathBuf,
}

#[cfg(unix)]
fn ensure_dir_owner_only(path: &std::path::Path) -> Result<()> {
	use std::os::unix::fs::PermissionsExt;

	let mut perms = std::fs::metadata(path)?.permissions();
	perms.set_mode(0o700);
	std::fs::set_permissions(path, perms)?;
	Ok(())
}

impl WalletManager {
	/// Create a new wallet manager
	pub fn new() -> Result<Self> {
		let wallets_dir = dirs::home_dir()
			.ok_or(WalletError::KeyGeneration)?
			.join(".quantus")
			.join("wallets");

		Self::from_wallets_dir(wallets_dir)
	}

	/// Create a wallet manager rooted at `wallets_dir`, creating it if needed.
	fn from_wallets_dir(wallets_dir: std::path::PathBuf) -> Result<Self> {
		// Create directory if it doesn't exist
		std::fs::create_dir_all(&wallets_dir)?;
		#[cfg(unix)]
		ensure_dir_owner_only(&wallets_dir)?;

		Ok(Self { wallets_dir })
	}

	/// Create a new wallet
	pub async fn create_wallet(&self, name: &str, password: Option<&str>) -> Result<WalletInfo> {
		self.create_wallet_with_derivation_path(name, password, DEFAULT_DERIVATION_PATH)
			.await
	}

	/// Create a new wallet with custom derivation path
	pub async fn create_wallet_with_derivation_path(
		&self,
		name: &str,
		password: Option<&str>,
		derivation_path: &str,
	) -> Result<WalletInfo> {
		let keystore = Keystore::new(&self.wallets_dir);
		let _create_guard = keystore.lock_wallet_create(name)?;
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Generate a new Dilithium keypair using derivation path
		let mut seed = [0u8; 32];
		rng().fill_bytes(&mut seed);
		let sensitive_seed = SensitiveBytes32::from(&mut seed);
		let mnemonic = generate_mnemonic(sensitive_seed).map_err(|_| WalletError::KeyGeneration)?;
		keystore::zeroize_bytes(&mut seed);
		let dilithium_keypair = derive_key_from_mnemonic(&mnemonic, None, derivation_path)
			.map_err(|_| WalletError::KeyGeneration)?;
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("derivation_path".to_string(), derivation_path.to_string());
		let address = quantum_keypair.try_to_account_id_ss58check()?;

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: Some(mnemonic.clone()),
			derivation_path: derivation_path.to_string(),
			metadata,
		};

		// Encrypt and save the wallet
		let password = password.unwrap_or(""); // Use empty password if none provided
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, password)?;
		keystore.save_new_wallet(&encrypted_wallet)?;

		Ok(WalletInfo {
			name: name.to_string(),
			address,
			created_at: encrypted_wallet.created_at,
			key_type: "Dilithium ML-DSA-87".to_string(),
			derivation_path: derivation_path.to_string(),
		})
	}

	/// Create a new developer wallet
	pub async fn create_developer_wallet(&self, name: &str) -> Result<WalletInfo> {
		let keystore = Keystore::new(&self.wallets_dir);
		let _create_guard = keystore.lock_wallet_create(name)?;
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Generate the appropriate test keypair
		let resonance_pair = match name {
			"crystal_alice" => qp_dilithium_crypto::crystal_alice(),
			"crystal_bob" => qp_dilithium_crypto::dilithium_bob(),
			"crystal_charlie" => qp_dilithium_crypto::crystal_charlie(),
			_ => return Err(WalletError::KeyGeneration.into()),
		};

		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&resonance_pair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("test_wallet".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.try_to_account_id_ss58check()?;

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: None,                    // Test wallets don't have mnemonics
			derivation_path: "m/".to_string(), // Developer wallets use root path
			metadata,
		};

		// Empty password is intentional for crystal_* developer wallets: these are
		// well-known genesis test keys for local development, not custody material.
		// File permissions remain owner-only (0600) via Keystore::save_new_wallet.
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, "")?;
		keystore.save_new_wallet(&encrypted_wallet)?;

		Ok(WalletInfo {
			name: name.to_string(),
			address,
			created_at: encrypted_wallet.created_at,
			key_type: "Dilithium ML-DSA-87".to_string(),
			derivation_path: "m/".to_string(),
		})
	}

	/// Export a wallet's mnemonic phrase
	pub fn export_mnemonic(&self, name: &str, password: Option<&str>) -> Result<String> {
		let final_password = password::get_wallet_password(name, password.map(String::from), None)?;

		let wallet_data = self.load_wallet(name, &final_password)?;

		// Clone before Drop zeroizes the in-memory mnemonic on wallet_data drop.
		wallet_data
			.mnemonic
			.as_ref()
			.cloned()
			.ok_or_else(|| WalletError::MnemonicNotAvailable.into())
	}

	/// List all wallets
	pub fn list_wallets(&self) -> Result<Vec<WalletInfo>> {
		let keystore = Keystore::new(&self.wallets_dir);
		let wallet_names = keystore.list_wallets()?;

		let mut wallets = Vec::new();
		for name in wallet_names {
			let Some(encrypted_wallet) = (match keystore.load_wallet(&name) {
				Ok(wallet) => wallet,
				Err(_) => continue,
			}) else {
				continue;
			};

			// Only expose an address when it can be authenticated via empty-password
			// decrypt (developer / no-password wallets). Never trust the plaintext
			// envelope address for password-protected wallets.
			let wallet_info = match keystore.decrypt_wallet_data(&encrypted_wallet, "") {
				Ok(wallet_data) => WalletInfo {
					name: wallet_data.name.clone(),
					address: wallet_data.keypair.try_to_account_id_ss58check()?,
					created_at: encrypted_wallet.created_at,
					key_type: "Dilithium ML-DSA-87".to_string(),
					derivation_path: "[Encrypted]".to_string(),
				},
				Err(crate::error::QuantusError::Wallet(
					WalletError::InvalidPassword | WalletError::Integrity(_),
				)) => WalletInfo {
					name,
					address: "[Encrypted]".to_string(),
					created_at: encrypted_wallet.created_at,
					key_type: "Dilithium ML-DSA-87".to_string(),
					derivation_path: "[Encrypted]".to_string(),
				},
				Err(_) => continue,
			};
			wallets.push(wallet_info);
		}

		// Sort by creation date (newest first)
		wallets.sort_by_key(|k| std::cmp::Reverse(k.created_at));
		Ok(wallets)
	}

	/// Import wallet from mnemonic phrase
	pub async fn import_wallet(
		&self,
		name: &str,
		mnemonic: &str,
		password: Option<&str>,
	) -> Result<WalletInfo> {
		self.import_wallet_with_derivation_path(name, mnemonic, password, DEFAULT_DERIVATION_PATH)
			.await
	}

	/// Create wallet from mnemonic without derivation (master seed)
	pub async fn create_wallet_no_derivation(
		&self,
		name: &str,
		password: Option<&str>,
	) -> Result<WalletInfo> {
		let keystore = Keystore::new(&self.wallets_dir);
		let _create_guard = keystore.lock_wallet_create(name)?;
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		let mut seed = [0u8; 32];
		rng().fill_bytes(&mut seed);
		let sensitive_seed = SensitiveBytes32::from(&mut seed);
		let mnemonic = generate_mnemonic(sensitive_seed).map_err(|_| WalletError::KeyGeneration)?;
		keystore::zeroize_bytes(&mut seed);
		let mut seed64 =
			mnemonic_to_seed(mnemonic.clone(), None).map_err(|_| WalletError::KeyGeneration)?;
		let dilithium_pair = DilithiumPair::from_seed(&seed64);
		keystore::zeroize_bytes(&mut seed64);
		let dilithium_pair = dilithium_pair.map_err(|_| WalletError::KeyGeneration)?;
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&dilithium_pair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("no_derivation".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.try_to_account_id_ss58check()?;

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: Some(mnemonic),
			derivation_path: "master".to_string(),
			metadata,
		};

		// Encrypt and save the wallet
		let password = password.unwrap_or(""); // Use empty password if none provided
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, password)?;
		keystore.save_new_wallet(&encrypted_wallet)?;

		Ok(WalletInfo {
			name: name.to_string(),
			address,
			created_at: chrono::Utc::now(),
			key_type: "Dilithium ML-DSA-87".to_string(),
			derivation_path: "master".to_string(),
		})
	}

	/// Import wallet from mnemonic without derivation (master seed)
	pub async fn import_wallet_no_derivation(
		&self,
		name: &str,
		mnemonic: &str,
		password: Option<&str>,
	) -> Result<WalletInfo> {
		let keystore = Keystore::new(&self.wallets_dir);
		let _create_guard = keystore.lock_wallet_create(name)?;
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// No derivation path - get the seed and create a key from the seed
		let seed64 = mnemonic_to_seed(mnemonic.to_string(), None)
			.map_err(|_| WalletError::InvalidMnemonic)?;
		let dilithium_pair =
			DilithiumPair::from_seed(&seed64).map_err(|_| WalletError::KeyGeneration)?;
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&dilithium_pair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("imported".to_string(), "true".to_string());
		metadata.insert("no_derivation".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.try_to_account_id_ss58check()?;

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: Some(mnemonic.to_string()),
			derivation_path: "master".to_string(),
			metadata,
		};

		// Encrypt and save the wallet
		let password = password.unwrap_or(""); // Use empty password if none provided
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, password)?;
		keystore.save_new_wallet(&encrypted_wallet)?;

		Ok(WalletInfo {
			name: name.to_string(),
			address,
			created_at: chrono::Utc::now(),
			key_type: "Dilithium ML-DSA-87".to_string(),
			derivation_path: "master".to_string(),
		})
	}

	/// Import wallet from mnemonic phrase with custom derivation path
	pub async fn import_wallet_with_derivation_path(
		&self,
		name: &str,
		mnemonic: &str,
		password: Option<&str>,
		derivation_path: &str,
	) -> Result<WalletInfo> {
		let keystore = Keystore::new(&self.wallets_dir);
		let _create_guard = keystore.lock_wallet_create(name)?;
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		let dilithium_pair = derive_key_from_mnemonic(mnemonic, None, derivation_path)
			.map_err(|_| WalletError::InvalidMnemonic)?;
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_pair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("imported".to_string(), "true".to_string());
		metadata.insert("derivation_path".to_string(), derivation_path.to_string());

		// Generate address from public key
		let address = quantum_keypair.try_to_account_id_ss58check()?;

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: Some(mnemonic.to_string()),
			derivation_path: derivation_path.to_string(),
			metadata,
		};

		// Encrypt and save the wallet
		let password = password.unwrap_or(""); // Use empty password if none provided
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, password)?;
		keystore.save_new_wallet(&encrypted_wallet)?;

		Ok(WalletInfo {
			name: name.to_string(),
			address,
			created_at: encrypted_wallet.created_at,
			key_type: "Dilithium ML-DSA-87".to_string(),
			derivation_path: derivation_path.to_string(),
		})
	}

	/// Create wallet from 32-byte seed
	pub async fn create_wallet_from_seed(
		&self,
		name: &str,
		seed: &str,
		password: Option<&str>,
	) -> Result<WalletInfo> {
		let keystore = Keystore::new(&self.wallets_dir);
		let _create_guard = keystore.lock_wallet_create(name)?;
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Validate seed hex format (should be 64 hex characters for 32 bytes)
		if seed.len() != 64 {
			return Err(WalletError::InvalidMnemonic.into()); // Reusing error type
		}

		// Convert hex to bytes
		let mut seed_bytes = hex::decode(seed).map_err(|_| WalletError::InvalidMnemonic)?;
		if seed_bytes.len() != 32 {
			keystore::zeroize_bytes(&mut seed_bytes);
			return Err(WalletError::InvalidMnemonic.into());
		}

		// Create DilithiumPair from seed; wipe both copies of the seed after use.
		let mut seed_bytes_32: [u8; 32] =
			seed_bytes.as_slice().try_into().map_err(|_| WalletError::InvalidMnemonic)?;
		keystore::zeroize_bytes(&mut seed_bytes);

		let dilithium_pair = qp_dilithium_crypto::types::DilithiumPair::from_seed(&seed_bytes_32);
		keystore::zeroize_bytes(&mut seed_bytes_32);
		let dilithium_pair = dilithium_pair.map_err(|_| WalletError::InvalidMnemonic)?;

		// Convert to QuantumKeyPair
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&dilithium_pair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("from_seed".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.try_to_account_id_ss58check()?;

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: None,                    // No mnemonic for seed-based wallets
			derivation_path: "m/".to_string(), // Seed-based wallets use root path
			metadata,
		};

		// Encrypt and save the wallet
		let password = password.unwrap_or(""); // Use empty password if none provided
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, password)?;
		keystore.save_new_wallet(&encrypted_wallet)?;

		Ok(WalletInfo {
			name: name.to_string(),
			address,
			created_at: encrypted_wallet.created_at,
			key_type: "Dilithium ML-DSA-87".to_string(),
			derivation_path: "m/".to_string(),
		})
	}

	/// Get wallet by name with password for decryption
	pub fn get_wallet(&self, name: &str, password: Option<&str>) -> Result<Option<WalletInfo>> {
		let keystore = Keystore::new(&self.wallets_dir);

		if let Some(encrypted_wallet) = keystore.load_wallet(name)? {
			if let Some(pwd) = password {
				// Decrypt and show full details
				match keystore.decrypt_wallet_data(&encrypted_wallet, pwd) {
					Ok(wallet_data) => {
						let address = wallet_data.keypair.try_to_account_id_ss58check()?;
						Ok(Some(WalletInfo {
							name: wallet_data.name.clone(),
							address,
							created_at: encrypted_wallet.created_at,
							key_type: "Dilithium ML-DSA-87".to_string(),
							derivation_path: wallet_data.derivation_path.clone(),
						}))
					},
					Err(crate::error::QuantusError::Wallet(WalletError::InvalidPassword)) => {
						// Wrong password, return basic info without trusting envelope metadata
						Ok(Some(WalletInfo {
							name: name.to_string(),
							address: "[Wrong password]".to_string(),
							created_at: encrypted_wallet.created_at,
							key_type: "Dilithium ML-DSA-87".to_string(),
							derivation_path: "[Wrong password]".to_string(),
						}))
					},
					Err(e) => Err(e),
				}
			} else {
				match keystore.decrypt_wallet_data(&encrypted_wallet, "") {
					Ok(wallet_data) => {
						let address = wallet_data.keypair.try_to_account_id_ss58check()?;
						Ok(Some(WalletInfo {
							name: wallet_data.name.clone(),
							address,
							created_at: encrypted_wallet.created_at,
							key_type: "Dilithium ML-DSA-87".to_string(),
							derivation_path: "[Encrypted]".to_string(),
						}))
					},
					Err(crate::error::QuantusError::Wallet(
						WalletError::InvalidPassword | WalletError::Integrity(_),
					)) => Ok(Some(WalletInfo {
						name: name.to_string(),
						address: "[Encrypted]".to_string(),
						created_at: encrypted_wallet.created_at,
						key_type: "Dilithium ML-DSA-87".to_string(),
						derivation_path: "[Encrypted]".to_string(),
					})),
					Err(e) => Err(e),
				}
			}
		} else {
			Ok(None)
		}
	}

	/// Load a wallet from disk and decrypt it with the provided password
	pub fn load_wallet(&self, name: &str, password: &str) -> Result<WalletData> {
		let keystore = Keystore::new(&self.wallets_dir);

		// Load the encrypted wallet
		let encrypted_wallet = keystore.load_wallet(name)?.ok_or(WalletError::NotFound)?;

		// Decrypt the wallet data using the provided password
		let wallet_data = keystore.decrypt_wallet_data(&encrypted_wallet, password)?;

		// Transparent migration: legacy wallet files embed the Argon2 digest (which
		// determines the AES key) in `argon2_params`. Re-encrypt without it on unlock.
		// Note: once migrated, the file can no longer be opened by older CLI
		// versions (they fail with "invalid password").
		// Fail closed on migration save failure: returning Ok would leave a
		// password-bypassable wallet file on disk.
		if Keystore::has_embedded_key_material(&encrypted_wallet) {
			let migrated = keystore.encrypt_wallet_data(&wallet_data, password)?;
			if !keystore.save_wallet_if_current(&migrated, &encrypted_wallet)? {
				return Err(QuantusError::Generic(
					"wallet changed during legacy migration".to_string(),
				));
			}
		}

		Ok(wallet_data)
	}

	/// Delete a wallet
	pub fn delete_wallet(&self, name: &str) -> Result<bool> {
		let keystore = Keystore::new(&self.wallets_dir);
		keystore.delete_wallet(name)
	}

	/// Find wallet by name and return its authenticated address when available without a password
	pub fn find_wallet_address(&self, name: &str) -> Result<WalletAddressLookup> {
		let keystore = Keystore::new(&self.wallets_dir);

		if let Some(encrypted_wallet) = keystore.load_wallet(name)? {
			// Wallet-name resolution must not trust the plaintext envelope address.
			// Only empty-password wallets can be authenticated without prompting.
			match keystore.decrypt_wallet_data(&encrypted_wallet, "") {
				Ok(wallet_data) => Ok(WalletAddressLookup::Address(
					wallet_data.keypair.try_to_account_id_ss58check()?,
				)),
				Err(crate::error::QuantusError::Wallet(
					WalletError::InvalidPassword | WalletError::Integrity(_),
				)) => Ok(WalletAddressLookup::Protected),
				Err(e) => Err(e),
			}
		} else {
			Ok(WalletAddressLookup::NotFound)
		}
	}
}

/// Result of resolving a wallet name to an address without a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletAddressLookup {
	/// No wallet with that name exists.
	NotFound,
	/// The wallet exists but its address cannot be authenticated without its password.
	Protected,
	/// The wallet's authenticated address.
	Address(String),
}

impl WalletAddressLookup {
	/// The authenticated address, if one was resolved without a password.
	#[allow(dead_code)] // SDK/examples convenience; unused by the CLI binary
	pub fn address(self) -> Option<String> {
		match self {
			WalletAddressLookup::Address(address) => Some(address),
			_ => None,
		}
	}
}

pub fn load_keypair_from_wallet(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<QuantumKeyPair> {
	let wallet_manager = WalletManager::new()?;
	let wallet_password = password::get_wallet_password(wallet_name, password, password_file)?;
	let mut wallet_data = wallet_manager.load_wallet(wallet_name, &wallet_password)?;
	Ok(wallet_data.take_keypair())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use tempfile::TempDir;

	async fn create_test_wallet_manager() -> (WalletManager, TempDir) {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let wallets_dir = temp_dir.path().join("wallets");
		let wallet_manager = WalletManager::from_wallets_dir(wallets_dir)
			.expect("Failed to create wallets directory");

		(wallet_manager, temp_dir)
	}

	#[cfg(unix)]
	#[test]
	fn test_wallet_storage_uses_owner_only_permissions() {
		use std::os::unix::fs::PermissionsExt;

		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let wallets_dir = temp_dir.path().join("wallets");

		// Exercise WalletManager::new's directory creation path
		let wallet_manager = WalletManager::from_wallets_dir(wallets_dir)
			.expect("Failed to create wallets directory");

		let dir_mode = fs::metadata(&wallet_manager.wallets_dir)
			.expect("stat wallets dir")
			.permissions()
			.mode() & 0o777;
		assert_eq!(dir_mode, 0o700, "wallets directory must be owner-only (0700)");

		let keystore = Keystore::new(&wallet_manager.wallets_dir);
		let mut entropy = [9u8; 32];
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(
			qp_rusty_crystals_hdwallet::SensitiveBytes32::from(&mut entropy),
		);
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);
		let wallet_data = WalletData {
			name: "perm-test-wallet".to_string(),
			keypair: quantum_keypair,
			mnemonic: None,
			derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
			metadata: std::collections::HashMap::new(),
		};
		let encrypted = keystore
			.encrypt_wallet_data(&wallet_data, "perm-test-password")
			.expect("encrypt wallet");
		keystore.save_wallet(&encrypted).expect("save wallet");

		let wallet_file = wallet_manager.wallets_dir.join("perm-test-wallet.json");
		let file_mode =
			fs::metadata(&wallet_file).expect("stat wallet file").permissions().mode() & 0o777;
		assert_eq!(file_mode, 0o600, "wallet file must be owner-read/write (0600)");
	}

	#[tokio::test]
	async fn test_wallet_creation() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Test wallet creation
		let wallet_info = wallet_manager
			.create_wallet("test-wallet", Some("test-password"))
			.await
			.expect("Failed to create wallet");

		// Verify wallet info
		assert_eq!(wallet_info.name, "test-wallet");
		assert!(wallet_info.address.starts_with("qz")); // SS58 addresses start with 5
		assert_eq!(wallet_info.key_type, "Dilithium ML-DSA-87");
		assert!(wallet_info.created_at <= chrono::Utc::now());
	}

	#[tokio::test]
	async fn test_wallet_already_exists() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Create first wallet
		wallet_manager
			.create_wallet("duplicate-wallet", None)
			.await
			.expect("Failed to create first wallet");

		// Try to create wallet with same name
		let result = wallet_manager.create_wallet("duplicate-wallet", None).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			crate::error::QuantusError::Wallet(WalletError::AlreadyExists) => {},
			_ => panic!("Expected AlreadyExists error"),
		}
	}

	#[tokio::test]
	async fn test_developer_wallet_duplicate_rejected() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		let wallet_info = wallet_manager
			.create_developer_wallet("crystal_alice")
			.await
			.expect("Failed to create developer wallet");
		assert_eq!(wallet_info.name, "crystal_alice");

		let result = wallet_manager.create_developer_wallet("crystal_alice").await;
		assert!(matches!(
			result,
			Err(crate::error::QuantusError::Wallet(WalletError::AlreadyExists))
		));
	}

	#[tokio::test]
	#[cfg(unix)]
	async fn developer_wallet_empty_password_is_intentional_and_owner_only() {
		// #159457: empty password remains intentional for crystal_*; world-readable
		// file perms are not — save path must enforce 0600.
		use std::os::unix::fs::PermissionsExt;

		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;
		wallet_manager
			.create_developer_wallet("crystal_bob")
			.await
			.expect("create developer wallet");

		wallet_manager
			.load_wallet("crystal_bob", "")
			.expect("empty password must unlock crystal_* developer wallets");

		let wallet_file = wallet_manager.wallets_dir.join("crystal_bob.json");
		let mode = fs::metadata(&wallet_file).expect("stat wallet").permissions().mode() & 0o777;
		assert_eq!(mode, 0o600, "developer wallet file must be owner-read/write only");
	}

	#[tokio::test]
	async fn test_wallet_file_creation() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Create wallet
		let _ = wallet_manager
			.create_wallet("file-test-wallet", Some("password123"))
			.await
			.expect("Failed to create wallet");

		// Check if wallet file exists
		let wallet_file = wallet_manager.wallets_dir.join("file-test-wallet.json");
		assert!(wallet_file.exists(), "Wallet file should exist");

		// Verify file is not empty
		let file_size = fs::metadata(&wallet_file).expect("Failed to get file metadata").len();
		assert!(file_size > 0, "Wallet file should not be empty");
	}

	#[tokio::test]
	async fn test_keystore_encryption_decryption() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = keystore::Keystore::new(temp_dir.path());

		// Create test wallet data
		let mut entropy = [1u8; 32]; // Use fixed entropy for deterministic tests
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(
			SensitiveBytes32::from(&mut entropy),
		);
		let quantum_keypair = keystore::QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		let mut metadata = std::collections::HashMap::new();
		metadata.insert("test_key".to_string(), "test_value".to_string());

		let original_wallet_data = keystore::WalletData {
			name: "test-wallet".to_string(),
			keypair: quantum_keypair,
			mnemonic: Some(
				"test mnemonic phrase with twenty four words here for testing purposes only"
					.to_string(),
			),
			derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
			metadata,
		};

		// Test encryption
		let encrypted_wallet = keystore
			.encrypt_wallet_data(&original_wallet_data, "test-password")
			.expect("Failed to encrypt wallet data");

		assert_eq!(encrypted_wallet.name, "test-wallet");
		assert!(!encrypted_wallet.encrypted_data.is_empty());
		assert!(!encrypted_wallet.argon2_salt.is_empty());
		assert!(!encrypted_wallet.aes_nonce.is_empty());

		// Test decryption
		let decrypted_wallet_data = keystore
			.decrypt_wallet_data(&encrypted_wallet, "test-password")
			.expect("Failed to decrypt wallet data");

		// Verify decrypted data matches original
		assert_eq!(decrypted_wallet_data.name, original_wallet_data.name);
		assert_eq!(decrypted_wallet_data.mnemonic, original_wallet_data.mnemonic);
		assert_eq!(decrypted_wallet_data.metadata, original_wallet_data.metadata);
		assert_eq!(
			decrypted_wallet_data.keypair.public_key,
			original_wallet_data.keypair.public_key
		);
		assert_eq!(
			decrypted_wallet_data.keypair.private_key,
			original_wallet_data.keypair.private_key
		);
	}

	#[tokio::test]
	async fn test_quantum_keypair_address_generation() {
		// Generate keypair
		let mut entropy = [2u8; 32]; // Use different entropy for variety
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(
			SensitiveBytes32::from(&mut entropy),
		);
		let quantum_keypair = keystore::QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Test address generation
		let account_id = quantum_keypair.try_to_account_id_32().expect("valid keypair");
		let ss58_address = quantum_keypair.try_to_account_id_ss58check().expect("valid keypair");

		// Verify SS58 address format
		assert!(ss58_address.starts_with("qz"), "SS58 address should start with 5");
		assert!(ss58_address.len() >= 47, "SS58 address should be at least 47 characters");

		// Test round-trip conversion
		let converted_account_bytes = keystore::QuantumKeyPair::ss58_to_account_id(&ss58_address)
			.expect("valid SS58 should decode");
		let account_bytes: &[u8] = account_id.as_ref();
		assert_eq!(converted_account_bytes, account_bytes);
	}

	#[tokio::test]
	async fn test_keystore_save_and_load() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = keystore::Keystore::new(temp_dir.path());

		// Create and encrypt wallet data
		let mut entropy = [3u8; 32]; // Use different entropy for each test
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(
			SensitiveBytes32::from(&mut entropy),
		);
		let quantum_keypair = keystore::QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		let wallet_data = keystore::WalletData {
			name: "save-load-test".to_string(),
			keypair: quantum_keypair,
			mnemonic: Some("save load test mnemonic phrase".to_string()),
			derivation_path: DEFAULT_DERIVATION_PATH.to_string(),
			metadata: std::collections::HashMap::new(),
		};

		let encrypted_wallet = keystore
			.encrypt_wallet_data(&wallet_data, "save-load-password")
			.expect("Failed to encrypt wallet");

		// Save wallet
		keystore.save_wallet(&encrypted_wallet).expect("Failed to save wallet");

		// Load wallet
		let loaded_wallet = keystore
			.load_wallet("save-load-test")
			.expect("Failed to load wallet")
			.expect("Wallet should exist");

		// Verify loaded wallet matches saved wallet
		assert_eq!(loaded_wallet.name, encrypted_wallet.name);
		assert_eq!(loaded_wallet.encrypted_data, encrypted_wallet.encrypted_data);
		assert_eq!(loaded_wallet.argon2_salt, encrypted_wallet.argon2_salt);
		assert_eq!(loaded_wallet.aes_nonce, encrypted_wallet.aes_nonce);

		// Test loading non-existent wallet
		let non_existent = keystore
			.load_wallet("non-existent-wallet")
			.expect("Load should succeed but return None");
		assert!(non_existent.is_none());
	}

	#[tokio::test]
	async fn test_mnemonic_generation_and_key_derivation() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Create multiple wallets to test mnemonic uniqueness
		let wallet1 = wallet_manager
			.create_wallet("mnemonic-test-1", None)
			.await
			.expect("Failed to create wallet 1");

		let wallet2 = wallet_manager
			.create_wallet("mnemonic-test-2", None)
			.await
			.expect("Failed to create wallet 2");

		// Addresses should be different (extremely unlikely to be the same)
		assert_ne!(wallet1.address, wallet2.address);

		// Both should be valid SS58 addresses
		assert!(wallet1.address.starts_with("qz"));
		assert!(wallet2.address.starts_with("qz"));
	}

	#[tokio::test]
	async fn test_wallet_import() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Test mnemonic phrase (24 words)
		let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

		// Import wallet
		let imported_wallet = wallet_manager
			.import_wallet("imported-test-wallet", test_mnemonic, Some("import-password"))
			.await
			.expect("Failed to import wallet");

		// Verify wallet info
		assert_eq!(imported_wallet.name, "imported-test-wallet");
		assert!(imported_wallet.address.starts_with("qz"));
		assert_eq!(imported_wallet.key_type, "Dilithium ML-DSA-87");

		// Import the same mnemonic again should create the same address
		let imported_wallet2 = wallet_manager
			.import_wallet("imported-test-wallet-2", test_mnemonic, None)
			.await
			.expect("Failed to import wallet again");

		assert_eq!(imported_wallet.address, imported_wallet2.address);
	}

	#[tokio::test]
	async fn test_known_values() {
		sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));

		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;
		let test_mnemonic = "orchard answer curve patient visual flower maze noise retreat penalty cage small earth domain scan pitch bottom crunch theme club client swap slice raven";
		let expected_address_no_derive = "qzmTAz3UUw1WGUuVh8nbFmPwcftomduwy6twq6NDR6y9qqtEs";
		let expected_address_hd_0 = "qzm5QCox8Dp5A3oSXZZYHD8YoYgPz7enykZb6RPUropdCyN5h";

		let imported_wallet = wallet_manager
			.import_wallet("imported-test-wallet", test_mnemonic, Some("import-password"))
			.await
			.expect("Failed to import wallet");

		let imported_wallet_no_derive = wallet_manager
			.import_wallet_no_derivation(
				"imported-test-wallet_no_derive",
				test_mnemonic,
				Some("import-password"),
			)
			.await
			.expect("Failed to import wallet");

		assert_eq!(imported_wallet.address, expected_address_hd_0, "address at index 0 is wrong");
		assert_eq!(
			imported_wallet_no_derive.address, expected_address_no_derive,
			"no-derivation address is wrong"
		);
	}

	#[tokio::test]
	async fn test_wallet_import_invalid_mnemonic() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Test with invalid mnemonic
		let invalid_mnemonic = "invalid mnemonic phrase that should not work";

		let result = wallet_manager.import_wallet("invalid-wallet", invalid_mnemonic, None).await;

		assert!(result.is_err());
		match result.unwrap_err() {
			crate::error::QuantusError::Wallet(WalletError::InvalidMnemonic) => {},
			_ => panic!("Expected InvalidMnemonic error"),
		}
	}

	#[tokio::test]
	async fn test_wallet_import_already_exists() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

		// Import first wallet
		wallet_manager
			.import_wallet("duplicate-import-wallet", test_mnemonic, None)
			.await
			.expect("Failed to import first wallet");

		// Try to import with same name
		let result = wallet_manager
			.import_wallet("duplicate-import-wallet", test_mnemonic, None)
			.await;

		assert!(result.is_err());
		match result.unwrap_err() {
			crate::error::QuantusError::Wallet(WalletError::AlreadyExists) => {},
			_ => panic!("Expected AlreadyExists error"),
		}
	}

	#[tokio::test]
	async fn test_wallet_creation_from_seed() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;
		let seed = "0101010101010101010101010101010101010101010101010101010101010101";

		let wallet_info = wallet_manager
			.create_wallet_from_seed("seed-based-wallet", seed, Some("probe-password"))
			.await
			.expect("Failed to create seed wallet");

		assert_eq!(wallet_info.name, "seed-based-wallet");
		assert!(wallet_info.address.starts_with("qz"));
		assert_eq!(wallet_info.derivation_path, "m/");

		let wallet_data = wallet_manager
			.load_wallet("seed-based-wallet", "probe-password")
			.expect("Failed to load seed wallet");
		assert!(wallet_data.mnemonic.is_none());
		assert_eq!(wallet_data.derivation_path, "m/");
		assert_eq!(wallet_data.metadata.get("from_seed").map(String::as_str), Some("true"));
	}

	#[tokio::test]
	async fn test_list_wallets() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Initially should be empty
		let wallets = wallet_manager.list_wallets().expect("Failed to list wallets");
		assert_eq!(wallets.len(), 0);

		// Create some wallets
		wallet_manager
			.create_wallet("wallet-1", Some("password1"))
			.await
			.expect("Failed to create wallet 1");

		wallet_manager
			.create_wallet("wallet-2", None)
			.await
			.expect("Failed to create wallet 2");

		let test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
		wallet_manager
			.import_wallet("imported-wallet", test_mnemonic, Some("password3"))
			.await
			.expect("Failed to import wallet");

		// List wallets
		let wallets = wallet_manager.list_wallets().expect("Failed to list wallets");

		assert_eq!(wallets.len(), 3);

		// Check that all wallet names are present
		let wallet_names: Vec<&String> = wallets.iter().map(|w| &w.name).collect();
		assert!(wallet_names.contains(&&"wallet-1".to_string()));
		assert!(wallet_names.contains(&&"wallet-2".to_string()));
		assert!(wallet_names.contains(&&"imported-wallet".to_string()));

		// Empty-password wallets expose authenticated addresses; password-protected
		// wallets must not leak the unauthenticated envelope address.
		for wallet in &wallets {
			assert_eq!(wallet.key_type, "Dilithium ML-DSA-87");
			if wallet.name == "wallet-2" {
				assert!(wallet.address.starts_with("qz"));
			} else {
				assert_eq!(wallet.address, "[Encrypted]");
			}
		}

		// Check sorting (newest first)
		assert!(wallets[0].created_at >= wallets[1].created_at);
		assert!(wallets[1].created_at >= wallets[2].created_at);
	}

	#[tokio::test]
	async fn test_get_wallet() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		// Create a wallet
		let created_wallet = wallet_manager
			.create_wallet("test-get-wallet", Some("test-password"))
			.await
			.expect("Failed to create wallet");

		// Passwordless view must not trust the unauthenticated envelope address
		let wallet_info = wallet_manager
			.get_wallet("test-get-wallet", None)
			.expect("Failed to get wallet")
			.expect("Wallet should exist");

		assert_eq!(wallet_info.name, "test-get-wallet");
		assert_eq!(wallet_info.address, "[Encrypted]");

		// Test getting wallet with wrong password
		// Now with real quantum-safe encryption, wrong password should be detected
		let wallet_info = wallet_manager
			.get_wallet("test-get-wallet", Some("wrong-password"))
			.expect("Failed to get wallet")
			.expect("Wallet should exist");

		assert_eq!(wallet_info.name, "test-get-wallet");
		// With real encryption, wrong password returns placeholder text
		assert_eq!(wallet_info.address, "[Wrong password]");

		// Test getting wallet with correct password
		let wallet_info = wallet_manager
			.get_wallet("test-get-wallet", Some("test-password"))
			.expect("Failed to get wallet")
			.expect("Wallet should exist");

		assert_eq!(wallet_info.name, "test-get-wallet");
		assert_eq!(wallet_info.address, created_wallet.address);
		assert!(wallet_info.address.starts_with("qz"));

		// Test getting non-existent wallet
		let result = wallet_manager
			.get_wallet("non-existent-wallet", None)
			.expect("Should not error on non-existent wallet");

		assert!(result.is_none());
	}

	/// Corrupt wallet files must remain deletable: delete works on the file
	/// itself and must not require the JSON to parse.
	#[tokio::test]
	async fn delete_wallet_removes_corrupt_wallet_file() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		wallet_manager.create_wallet("corrupt_me", None).await.expect("create wallet");
		let wallet_file = wallet_manager.wallets_dir.join("corrupt_me.json");
		fs::write(&wallet_file, b"{ not valid json").expect("corrupt the file");

		// The pre-check path fails to parse it...
		assert!(wallet_manager.get_wallet("corrupt_me", None).is_err());

		// ...but deletion must still succeed.
		let deleted = wallet_manager.delete_wallet("corrupt_me").expect("delete must not error");
		assert!(deleted, "corrupt wallet file must be deleted");
		assert!(!wallet_file.exists());
	}

	/// find_wallet_address must distinguish "no such wallet" from "wallet exists
	/// but needs its password", so callers can report an honest error or unlock.
	#[tokio::test]
	async fn find_wallet_address_distinguishes_missing_protected_and_open_wallets() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		assert_eq!(
			wallet_manager.find_wallet_address("nope").unwrap(),
			WalletAddressLookup::NotFound
		);

		let open = wallet_manager.create_wallet("open_wallet", None).await.expect("open wallet");
		assert_eq!(
			wallet_manager.find_wallet_address("open_wallet").unwrap(),
			WalletAddressLookup::Address(open.address)
		);

		wallet_manager
			.create_wallet("locked_wallet", Some("hunter2 but longer"))
			.await
			.expect("locked wallet");
		assert_eq!(
			wallet_manager.find_wallet_address("locked_wallet").unwrap(),
			WalletAddressLookup::Protected
		);
	}

	#[tokio::test]
	async fn passwordless_paths_do_not_trust_tampered_envelope_address() {
		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;

		let victim = wallet_manager
			.create_wallet("victim_alias", Some("correct horse battery staple"))
			.await
			.expect("victim wallet");
		let attacker = wallet_manager
			.create_wallet("attacker_wallet", Some("attacker password"))
			.await
			.expect("attacker wallet");
		assert_ne!(victim.address, attacker.address);

		let keystore = Keystore::new(&wallet_manager.wallets_dir);
		let mut tampered =
			keystore.load_wallet("victim_alias").expect("load").expect("victim exists");
		tampered.address = attacker.address.clone();
		keystore.save_wallet(&tampered).expect("persist tampered envelope");

		let decrypt_result =
			wallet_manager.load_wallet("victim_alias", "correct horse battery staple");
		assert!(
			matches!(
				decrypt_result,
				Err(crate::error::QuantusError::Wallet(WalletError::Integrity(_)))
			),
			"correct-password decrypt must reject envelope/keypair mismatch, got: {decrypt_result:?}"
		);

		let lookup = wallet_manager
			.find_wallet_address("victim_alias")
			.expect("passwordless resolution must not panic");
		assert_eq!(
			lookup,
			WalletAddressLookup::Protected,
			"password-protected wallets must refuse unauthenticated wallet-name resolution"
		);

		let listed = wallet_manager
			.list_wallets()
			.expect("list")
			.into_iter()
			.find(|w| w.name == "victim_alias")
			.expect("victim should still be listed");
		assert_ne!(
			listed.address, attacker.address,
			"list_wallets must not display the attacker-substituted envelope address"
		);
		assert!(
			listed.address.contains('['),
			"password-protected wallets must use a placeholder without authenticated decrypt"
		);

		let viewed = wallet_manager
			.get_wallet("victim_alias", None)
			.expect("view")
			.expect("victim exists");
		assert_ne!(
			viewed.address, attacker.address,
			"passwordless get_wallet must not display the attacker-substituted envelope address"
		);
		assert!(
			viewed.address.contains('['),
			"passwordless view of a password-protected wallet must use a placeholder"
		);
	}

	#[tokio::test]
	async fn list_wallets_skips_malformed_files_and_rejects_invalid_addresses() {
		use sp_core::crypto::{AccountId32, Ss58Codec};

		let (wallet_manager, _temp_dir) = create_test_wallet_manager().await;
		let created = wallet_manager
			.create_developer_wallet("crystal_alice")
			.await
			.expect("developer wallet creation should succeed");

		let corrupt_path = wallet_manager.wallets_dir.join("corrupt.json");
		fs::write(&corrupt_path, b"{\"name\":").expect("write malformed wallet file");

		let listed = wallet_manager
			.list_wallets()
			.expect("listing must skip one malformed wallet file and still return valid wallets");
		assert!(
			listed.iter().any(|w| w.name == created.name),
			"valid wallet must remain listable despite a malformed sibling file"
		);

		fs::remove_file(&corrupt_path).expect("remove malformed file");

		let keystore = Keystore::new(&wallet_manager.wallets_dir);
		let mut forged = keystore
			.load_wallet("crystal_alice")
			.expect("valid wallet load")
			.expect("valid wallet exists");
		forged.name = "forged_address_wallet".to_string();
		forged.address = "not a Quantus SS58 account".to_string();
		keystore.save_wallet(&forged).expect("save forged-address wallet JSON");

		assert!(
			matches!(
				keystore.load_wallet("forged_address_wallet"),
				Err(crate::error::QuantusError::Wallet(WalletError::InvalidAddress))
			),
			"load boundary must reject non-canonical wallet addresses"
		);

		let listed_after = wallet_manager.list_wallets().expect("listing after forgery");
		assert!(
			listed_after.iter().any(|w| w.name == created.name),
			"valid wallet must remain listable"
		);
		assert!(
			listed_after.iter().all(|w| {
				w.address == "[Encrypted]" ||
					AccountId32::from_ss58check_with_version(&w.address).is_ok()
			}),
			"listing must not return addresses the SS58 parser rejects"
		);
		assert!(
			listed_after.iter().all(|w| w.name != "forged_address_wallet"),
			"forged-address wallet must be omitted from listing"
		);
	}
}
