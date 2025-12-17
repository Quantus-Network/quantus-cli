/// Wallet management module
///
/// This module provides functionality for:
/// - Creating quantum-safe wallets using Dilithium keys
/// - Importing/exporting wallets with mnemonic phrases
/// - Encrypting/decrypting wallet data
/// - Managing multiple wallets
pub mod keystore;
pub mod password;

use crate::error::{Result, WalletError};
pub use keystore::{Keystore, QuantumKeyPair, WalletData};
use qp_rusty_crystals_hdwallet::{generate_mnemonic, HDLattice};
use rand::{rng, RngCore};
use serde::{Deserialize, Serialize};
use sp_runtime::traits::IdentifyAccount;

/// Default derivation path for Quantus wallets: m/44'/189189'/0'/0/0
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/189189'/0'/0/0";

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

impl WalletManager {
	/// Create a new wallet manager
	pub fn new() -> Result<Self> {
		let wallets_dir = dirs::home_dir()
			.ok_or(WalletError::KeyGeneration)?
			.join(".quantus")
			.join("wallets");

		// Create directory if it doesn't exist
		std::fs::create_dir_all(&wallets_dir)?;

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
		// Check if wallet already exists
		let keystore = Keystore::new(&self.wallets_dir);
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Generate a new Dilithium keypair using derivation path
		let mut seed = [0u8; 32];
		rng().fill_bytes(&mut seed);
		let mnemonic = generate_mnemonic(24, seed).map_err(|_| WalletError::KeyGeneration)?;
		let lattice =
			HDLattice::from_mnemonic(&mnemonic, None).expect("Failed to generate lattice");
		let dilithium_keypair = lattice
			.generate_derived_keys(derivation_path)
			.map_err(|_| WalletError::KeyGeneration)?;
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("derivation_path".to_string(), derivation_path.to_string());

		// Generate address from public key (simplified version)
		let address = quantum_keypair.to_account_id_ss58check();

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
		keystore.save_wallet(&encrypted_wallet)?;

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
		// Check if wallet already exists
		let keystore = Keystore::new(&self.wallets_dir);

		// Generate the appropriate test keypair
		let resonance_pair = match name {
			"crystal_alice" => qp_dilithium_crypto::crystal_alice(),
			"crystal_bob" => qp_dilithium_crypto::dilithium_bob(),
			"crystal_charlie" => qp_dilithium_crypto::crystal_charlie(),
			_ => return Err(WalletError::KeyGeneration.into()),
		};

		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&resonance_pair);

		// Format addresses with SS58 version 189 (Quantus format)
		use sp_core::crypto::Ss58Codec;
		let resonance_addr = resonance_pair
			.public()
			.into_account()
			.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));
		println!("🔑 Resonance pair: {:?}", resonance_addr);
		println!("🔑 Quantum keypair: {:?}", quantum_keypair.to_account_id_ss58check());

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("test_wallet".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.to_account_id_ss58check();

		let wallet_data = WalletData {
			name: name.to_string(),
			keypair: quantum_keypair,
			mnemonic: None,                    // Test wallets don't have mnemonics
			derivation_path: "m/".to_string(), // Developer wallets use root path
			metadata,
		};

		// Encrypt and save the wallet with empty password for test wallets
		let encrypted_wallet = keystore.encrypt_wallet_data(&wallet_data, "")?;
		keystore.save_wallet(&encrypted_wallet)?;

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

		wallet_data.mnemonic.ok_or_else(|| WalletError::MnemonicNotAvailable.into())
	}

	/// List all wallets
	pub fn list_wallets(&self) -> Result<Vec<WalletInfo>> {
		let keystore = Keystore::new(&self.wallets_dir);
		let wallet_names = keystore.list_wallets()?;

		let mut wallets = Vec::new();
		for name in wallet_names {
			if let Some(encrypted_wallet) = keystore.load_wallet(&name)? {
				// Create wallet info using stored public address
				let wallet_info = WalletInfo {
					name: encrypted_wallet.name,
					address: encrypted_wallet.address, // Address is stored unencrypted
					created_at: encrypted_wallet.created_at,
					key_type: "Dilithium ML-DSA-87".to_string(),
					derivation_path: "[Encrypted]".to_string(), // Derivation path is encrypted
				};
				wallets.push(wallet_info);
			}
		}

		// Sort by creation date (newest first)
		wallets.sort_by(|a, b| b.created_at.cmp(&a.created_at));
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
		// Check if wallet already exists
		let keystore = Keystore::new(&self.wallets_dir);
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Generate new mnemonic and use master seed directly
		let mut seed = [0u8; 32];
		rng().fill_bytes(&mut seed);
		let mnemonic = generate_mnemonic(24, seed).map_err(|_| WalletError::KeyGeneration)?;
		let lattice =
			HDLattice::from_mnemonic(&mnemonic, None).map_err(|_| WalletError::KeyGeneration)?;
		let dilithium_keypair = lattice.generate_keys();
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("no_derivation".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.to_account_id_ss58check();

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
		keystore.save_wallet(&encrypted_wallet)?;

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
		// Check if wallet already exists
		let keystore = Keystore::new(&self.wallets_dir);
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Use mnemonic to generate master seed directly
		let lattice =
			HDLattice::from_mnemonic(mnemonic, None).map_err(|_| WalletError::InvalidMnemonic)?;
		let dilithium_keypair = lattice.generate_keys();
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("imported".to_string(), "true".to_string());
		metadata.insert("no_derivation".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.to_account_id_ss58check();

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
		keystore.save_wallet(&encrypted_wallet)?;

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
		// Check if wallet already exists
		let keystore = Keystore::new(&self.wallets_dir);
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Validate and import from mnemonic using derivation path
		let lattice =
			HDLattice::from_mnemonic(mnemonic, None).map_err(|_| WalletError::InvalidMnemonic)?;
		let dilithium_keypair = lattice
			.generate_derived_keys(derivation_path)
			.map_err(|_| WalletError::KeyGeneration)?;
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("imported".to_string(), "true".to_string());
		metadata.insert("derivation_path".to_string(), derivation_path.to_string());

		// Generate address from public key
		let address = quantum_keypair.to_account_id_ss58check();

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
		keystore.save_wallet(&encrypted_wallet)?;

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
		seed_hex: &str,
		password: Option<&str>,
	) -> Result<WalletInfo> {
		// Check if wallet already exists
		let keystore = Keystore::new(&self.wallets_dir);
		if keystore.load_wallet(name)?.is_some() {
			return Err(WalletError::AlreadyExists.into());
		}

		// Validate seed hex format (should be 64 hex characters for 32 bytes)
		if seed_hex.len() != 64 {
			return Err(WalletError::InvalidMnemonic.into()); // Reusing error type
		}

		// Convert hex to bytes
		let seed_bytes = hex::decode(seed_hex).map_err(|_| WalletError::InvalidMnemonic)?;
		if seed_bytes.len() != 32 {
			return Err(WalletError::InvalidMnemonic.into());
		}

		// Create DilithiumPair from seed
		let seed_array: [u8; 32] =
			seed_bytes.try_into().map_err(|_| WalletError::InvalidMnemonic)?;

		println!("Debug: seed_array length: {}", seed_array.len());
		println!("Debug: seed_hex: {}", seed_hex);
		println!("Debug: calling DilithiumPair::from_seed");

		let dilithium_pair = qp_dilithium_crypto::types::DilithiumPair::from_seed(&seed_array)
			.map_err(|e| {
				println!("Debug: DilithiumPair::from_seed failed with error: {:?}", e);
				WalletError::InvalidMnemonic
			})?;

		println!("Debug: DilithiumPair created successfully");

		// Convert to QuantumKeyPair
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&dilithium_pair);

		// Create wallet data
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("from_seed".to_string(), "true".to_string());

		// Generate address from public key
		let address = quantum_keypair.to_account_id_ss58check();

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
		keystore.save_wallet(&encrypted_wallet)?;

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
						let address = wallet_data.keypair.to_account_id_ss58check();
						Ok(Some(WalletInfo {
							name: wallet_data.name,
							address,
							created_at: encrypted_wallet.created_at,
							key_type: "Dilithium ML-DSA-87".to_string(),
							derivation_path: wallet_data.derivation_path,
						}))
					},
					Err(_) => {
						// Wrong password, return basic info
						Ok(Some(WalletInfo {
							name: encrypted_wallet.name,
							address: "[Wrong password]".to_string(),
							created_at: encrypted_wallet.created_at,
							key_type: "Dilithium ML-DSA-87".to_string(),
							derivation_path: "[Wrong password]".to_string(),
						}))
					},
				}
			} else {
				// No password provided, return basic info with public address
				Ok(Some(WalletInfo {
					name: encrypted_wallet.name,
					address: encrypted_wallet.address, // Address is public
					created_at: encrypted_wallet.created_at,
					key_type: "Dilithium ML-DSA-87".to_string(),
					derivation_path: "[Encrypted]".to_string(), // Derivation path is encrypted
				}))
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

		Ok(wallet_data)
	}

	/// Delete a wallet
	pub fn delete_wallet(&self, name: &str) -> Result<bool> {
		let keystore = Keystore::new(&self.wallets_dir);
		keystore.delete_wallet(name)
	}

	/// Find wallet by name and return its address
	pub fn find_wallet_address(&self, name: &str) -> Result<Option<String>> {
		let keystore = Keystore::new(&self.wallets_dir);

		if let Some(encrypted_wallet) = keystore.load_wallet(name)? {
			// Return the stored address (it's stored unencrypted)
			Ok(Some(encrypted_wallet.address))
		} else {
			Ok(None)
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
	let wallet_data = wallet_manager.load_wallet(wallet_name, &wallet_password)?;
	let keypair = wallet_data.keypair;
	Ok(keypair)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use tempfile::TempDir;

	async fn create_test_wallet_manager() -> (WalletManager, TempDir) {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let wallets_dir = temp_dir.path().join("wallets");
		fs::create_dir_all(&wallets_dir).expect("Failed to create wallets directory");

		let wallet_manager = WalletManager { wallets_dir };

		(wallet_manager, temp_dir)
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
		let entropy = [1u8; 32]; // Use fixed entropy for deterministic tests
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(&entropy);
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
		let entropy = [2u8; 32]; // Use different entropy for variety
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(&entropy);
		let quantum_keypair = keystore::QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Test address generation
		let account_id = quantum_keypair.to_account_id_32();
		let ss58_address = quantum_keypair.to_account_id_ss58check();

		// Verify SS58 address format
		assert!(ss58_address.starts_with("qz"), "SS58 address should start with 5");
		assert!(ss58_address.len() >= 47, "SS58 address should be at least 47 characters");

		// Test round-trip conversion
		let converted_account_bytes = keystore::QuantumKeyPair::ss58_to_account_id(&ss58_address);
		let account_bytes: &[u8] = account_id.as_ref();
		assert_eq!(converted_account_bytes, account_bytes);
	}

	#[tokio::test]
	async fn test_keystore_save_and_load() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = keystore::Keystore::new(temp_dir.path());

		// Create and encrypt wallet data
		let entropy = [3u8; 32]; // Use different entropy for each test
		let dilithium_keypair = qp_rusty_crystals_dilithium::ml_dsa_87::Keypair::generate(&entropy);
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
		let expected_address = "qznMJss7Ls1SWBhvvL2CSHVbgTxEfnL9GgpvMTq5CWMEwfCoe"; // default derivation path index 0
		let expected_address_no_derive = "qznBvupPsA9T8VJDuTDokKPiNUe88zMMUtHGA1AsGc8fXKSSA";

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

		assert_eq!(imported_wallet.address, expected_address, "address at index 0 is wrong");
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

		// Check that addresses are real addresses (now stored unencrypted)
		for wallet in &wallets {
			assert!(wallet.address.starts_with("qz")); // Real SS58 addresses start with 5
			assert_eq!(wallet.key_type, "Dilithium ML-DSA-87");
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

		// Test getting wallet without password
		let wallet_info = wallet_manager
			.get_wallet("test-get-wallet", None)
			.expect("Failed to get wallet")
			.expect("Wallet should exist");

		assert_eq!(wallet_info.name, "test-get-wallet");
		assert_eq!(wallet_info.address, created_wallet.address); // Now returns real address

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
}
