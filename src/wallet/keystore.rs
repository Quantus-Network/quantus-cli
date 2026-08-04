/// Quantum-safe keystore for wallet data
///
/// This module handles:
/// - Quantum-safe encrypting and storing wallet data using Argon2 + AES-256-GCM
/// - Loading and decrypting wallet data with post-quantum cryptography
/// - Managing wallet files on disk with quantum-resistant security
use crate::error::{QuantusError, Result, WalletError};
use qp_rusty_crystals_dilithium::ml_dsa_87::{Keypair, PublicKey, SecretKey};
#[cfg(test)]
use qp_rusty_crystals_hdwallet::SensitiveBytes32;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sp_core::crypto::Ss58AddressFormat;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	ByteArray,
};
// Quantum-safe encryption imports
use aes_gcm::{
	aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
	Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, Version};
use rand::{rng, RngCore};

use std::{
	collections::HashSet,
	fs::{self, File, OpenOptions},
	io::{ErrorKind, Read, Write},
	path::{Path, PathBuf},
	sync::{Condvar, Mutex, OnceLock},
};

use qp_dilithium_crypto::types::{DilithiumPair, DilithiumPublic};
use sp_runtime::traits::IdentifyAccount;

fn keystore_lock() -> &'static Mutex<()> {
	static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
	LOCK.get_or_init(|| Mutex::new(()))
}

fn wallet_filename(name: &str) -> Result<String> {
	if name.is_empty() ||
		name.contains('/') ||
		name.contains('\\') ||
		name == "." ||
		name == ".."
	{
		return Err(WalletError::InvalidName.into());
	}
	Ok(format!("{name}.json"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_no_follow(options: &mut OpenOptions) {
	use std::os::unix::fs::OpenOptionsExt;
	const O_NOFOLLOW: i32 = 0o400000;
	options.custom_flags(O_NOFOLLOW);
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_no_follow(_options: &mut OpenOptions) {}

fn open_wallet_for_read(path: &Path) -> std::io::Result<File> {
	let mut options = OpenOptions::new();
	options.read(true);
	set_no_follow(&mut options);
	options.open(path)
}

/// Exclusively create a random temporary file in the wallet directory.
/// `create_new` / O_EXCL refuses an existing path (including a pre-positioned symlink).
fn create_unique_temp(storage_path: &Path, name: &str) -> std::io::Result<(PathBuf, File)> {
	for _ in 0..32 {
		let mut nonce = [0u8; 16];
		rng().fill_bytes(&mut nonce);
		let tmp_path = storage_path.join(format!(".{name}.{}.tmp", hex::encode(nonce)));
		let mut options = OpenOptions::new();
		options.write(true).create_new(true);
		set_no_follow(&mut options);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			options.mode(0o600);
		}
		match options.open(&tmp_path) {
			Ok(file) => return Ok((tmp_path, file)),
			Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
			Err(e) => return Err(e),
		}
	}
	Err(std::io::Error::new(
		ErrorKind::AlreadyExists,
		"could not create unique wallet temporary file",
	))
}

fn write_temp_wallet_bytes(storage_path: &Path, name: &str, data: &[u8]) -> Result<PathBuf> {
	let (tmp_path, mut file) = create_unique_temp(storage_path, name)?;
	let result = (|| -> Result<()> {
		file.write_all(data)?;
		file.sync_all()?;
		Ok(())
	})();
	if let Err(e) = result {
		let _ = fs::remove_file(&tmp_path);
		return Err(e);
	}
	drop(file);

	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mut perms = fs::metadata(&tmp_path)?.permissions();
		perms.set_mode(0o600);
		fs::set_permissions(&tmp_path, perms)?;
	}

	Ok(tmp_path)
}

#[cfg(unix)]
fn same_file_metadata(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
	use std::os::unix::fs::MetadataExt;
	a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file_metadata(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
	a.len() == b.len() && a.modified().ok() == b.modified().ok()
}

struct WalletCreateLocks {
	active: Mutex<HashSet<PathBuf>>,
	available: Condvar,
}

static WALLET_CREATE_LOCKS: OnceLock<WalletCreateLocks> = OnceLock::new();

pub(crate) struct WalletCreateGuard {
	path: PathBuf,
	locks: &'static WalletCreateLocks,
}

impl WalletCreateLocks {
	fn lock(path: PathBuf) -> WalletCreateGuard {
		let locks = WALLET_CREATE_LOCKS.get_or_init(|| WalletCreateLocks {
			active: Mutex::new(HashSet::new()),
			available: Condvar::new(),
		});
		let mut active = locks.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		while active.contains(&path) {
			active =
				locks.available.wait(active).unwrap_or_else(|poisoned| poisoned.into_inner());
		}
		active.insert(path.clone());
		WalletCreateGuard { path, locks }
	}
}

impl Drop for WalletCreateGuard {
	fn drop(&mut self) {
		let mut active =
			self.locks.active.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		active.remove(&self.path);
		self.locks.available.notify_all();
	}
}

/// Quantum-safe key pair using Dilithium post-quantum signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumKeyPair {
	pub public_key: Vec<u8>,
	pub private_key: Vec<u8>,
}

impl QuantumKeyPair {
	/// Create from rusty-crystals Keypair
	pub fn from_dilithium_keypair(keypair: &Keypair) -> Self {
		Self {
			public_key: keypair.public.to_bytes().to_vec(),
			private_key: keypair.secret.to_bytes().to_vec(),
		}
	}

	/// Convert to rusty-crystals Keypair
	#[allow(dead_code)]
	pub fn to_dilithium_keypair(&self) -> Result<Keypair> {
		// TODO: Implement conversion from bytes back to Keypair
		// For now, generate a new one as placeholder
		// This function should properly reconstruct the Keypair from stored bytes
		Ok(Keypair {
			public: PublicKey::from_bytes(&self.public_key).expect("Failed to parse public key"),
			secret: SecretKey::from_bytes(&self.private_key).expect("Failed to parse private key"),
		})
	}

	/// Convert to DilithiumPair for use with substrate-api-client
	pub fn to_resonance_pair(&self) -> Result<DilithiumPair> {
		// Convert our QuantumKeyPair to DilithiumPair using from_raw
		Ok(DilithiumPair::from_raw(&self.public_key, &self.private_key)
			.map_err(|_| crate::error::WalletError::KeyGeneration)?)
	}

	pub fn from_resonance_pair(keypair: &DilithiumPair) -> Self {
		use sp_core::Pair;
		Self {
			public_key: keypair.public().as_ref().to_vec(),
			private_key: keypair.secret_bytes().to_vec(),
		}
	}

	pub fn to_account_id_32(&self) -> AccountId32 {
		// Use the DilithiumPublic's into_account method for correct address generation
		let resonance_public =
			DilithiumPublic::from_slice(&self.public_key).expect("Invalid public key");
		resonance_public.into_account()
	}

	pub fn to_account_id_ss58check(&self) -> String {
		use crate::cli::address_format::quantus_ss58_format;
		let account = self.to_account_id_32();
		account.to_ss58check_with_version(quantus_ss58_format())
	}

	/// Convert to subxt Signer for use
	pub fn to_subxt_signer(&self) -> Result<qp_dilithium_crypto::types::DilithiumPair> {
		// Convert to DilithiumPair first - now it implements subxt::tx::Signer<ChainConfig>
		let resonance_pair = self.to_resonance_pair()?;

		Ok(resonance_pair)
	}

	#[allow(dead_code)]
	pub fn ss58_to_account_id(s: &str) -> Vec<u8> {
		// from_ss58check returns a Result, we unwrap it to panic on invalid input.
		// We then convert the AccountId32 struct to a Vec<u8> to be compatible with Polkadart's
		// typedef.
		AsRef::<[u8]>::as_ref(&AccountId32::from_ss58check_with_version(s).unwrap().0).to_vec()
	}
}

/// Quantum-safe encrypted wallet data structure
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedWallet {
	pub name: String,
	pub address: String, // SS58-encoded address (public, not encrypted)
	pub encrypted_data: Vec<u8>,
	pub kyber_ciphertext: Vec<u8>, // Reserved for future ML-KEM implementation
	pub kyber_public_key: Vec<u8>, // Reserved for future ML-KEM implementation
	pub argon2_salt: Vec<u8>,      // Salt for password-based key derivation
	/// Argon2 params as a PHC string WITHOUT the digest (the digest determines the
	/// AES key and must never be stored)
	pub argon2_params: String,
	pub aes_nonce: Vec<u8>,      // AES-GCM nonce
	pub encryption_version: u32, // Version for future crypto upgrades
	pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Wallet data structure (before encryption)
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletData {
	pub name: String,
	pub keypair: QuantumKeyPair,
	pub mnemonic: Option<String>,
	pub derivation_path: String,
	pub metadata: std::collections::HashMap<String, String>,
}

/// Keystore manager for handling encrypted wallet storage
pub struct Keystore {
	storage_path: std::path::PathBuf,
}

impl Keystore {
	/// Create a new keystore instance
	pub fn new<P: AsRef<Path>>(storage_path: P) -> Self {
		Self { storage_path: storage_path.as_ref().to_path_buf() }
	}

	/// Acquire the per-wallet-name create lock for check-then-save creation flows.
	pub(crate) fn lock_wallet_create(&self, name: &str) -> Result<WalletCreateGuard> {
		let file_name = wallet_filename(name)?;
		Ok(WalletCreateLocks::lock(self.storage_path.join(file_name)))
	}

	/// Save an encrypted wallet to disk (may replace an existing wallet file).
	pub fn save_wallet(&self, wallet: &EncryptedWallet) -> Result<()> {
		let _guard = keystore_lock()
			.lock()
			.map_err(|_| QuantusError::Generic("keystore lock poisoned".to_string()))?;
		self.save_wallet_unlocked(wallet)
	}

	/// Save a newly-created wallet only if no wallet with this name exists.
	pub fn save_new_wallet(&self, wallet: &EncryptedWallet) -> Result<()> {
		let _guard = keystore_lock()
			.lock()
			.map_err(|_| QuantusError::Generic("keystore lock poisoned".to_string()))?;
		let file_name = wallet_filename(&wallet.name)?;
		let wallet_file = self.storage_path.join(&file_name);
		let wallet_json = serde_json::to_string_pretty(wallet)?;
		let tmp_file = write_temp_wallet_bytes(&self.storage_path, &wallet.name, wallet_json.as_bytes())?;

		// Atomically create the destination without replacing an existing wallet.
		// hard_link fails with AlreadyExists when the final name is taken.
		match fs::hard_link(&tmp_file, &wallet_file) {
			Ok(()) => {
				let _ = fs::remove_file(&tmp_file);
				#[cfg(unix)]
				{
					use std::os::unix::fs::PermissionsExt;
					let mut perms = fs::metadata(&wallet_file)?.permissions();
					perms.set_mode(0o600);
					fs::set_permissions(&wallet_file, perms)?;
				}
				Ok(())
			},
			Err(e) if e.kind() == ErrorKind::AlreadyExists => {
				let _ = fs::remove_file(&tmp_file);
				Err(WalletError::AlreadyExists.into())
			},
			Err(e) => {
				let _ = fs::remove_file(&tmp_file);
				Err(e.into())
			},
		}
	}

	/// Save a replacement only if the stored wallet still matches the caller's snapshot.
	pub fn save_wallet_if_current(
		&self,
		wallet: &EncryptedWallet,
		expected: &EncryptedWallet,
	) -> Result<bool> {
		let _guard = keystore_lock()
			.lock()
			.map_err(|_| QuantusError::Generic("keystore lock poisoned".to_string()))?;
		match self.load_wallet_unlocked(&expected.name)? {
			Some(current) if current == *expected => {
				self.save_wallet_unlocked(wallet)?;
				Ok(true)
			},
			_ => Ok(false),
		}
	}

	fn save_wallet_unlocked(&self, wallet: &EncryptedWallet) -> Result<()> {
		let file_name = wallet_filename(&wallet.name)?;
		let wallet_file = self.storage_path.join(&file_name);
		let wallet_json = serde_json::to_string_pretty(wallet)?;
		// Unpredictable, exclusively-created temp so attackers cannot pre-position a
		// symlink at a deterministic path. rename replaces the directory entry only.
		let tmp_file = write_temp_wallet_bytes(&self.storage_path, &wallet.name, wallet_json.as_bytes())?;
		match fs::rename(&tmp_file, &wallet_file) {
			Ok(()) => {
				#[cfg(unix)]
				{
					use std::os::unix::fs::PermissionsExt;
					let mut perms = fs::metadata(&wallet_file)?.permissions();
					perms.set_mode(0o600);
					fs::set_permissions(&wallet_file, perms)?;
				}
				Ok(())
			},
			Err(e) => {
				let _ = fs::remove_file(&tmp_file);
				Err(e.into())
			},
		}
	}

	/// Load an encrypted wallet from disk
	pub fn load_wallet(&self, name: &str) -> Result<Option<EncryptedWallet>> {
		let _guard = keystore_lock()
			.lock()
			.map_err(|_| QuantusError::Generic("keystore lock poisoned".to_string()))?;
		self.load_wallet_unlocked(name)
	}

	fn load_wallet_unlocked(&self, name: &str) -> Result<Option<EncryptedWallet>> {
		let wallet_file = self.storage_path.join(wallet_filename(name)?);
		let mut file = match open_wallet_for_read(&wallet_file) {
			Ok(file) => file,
			Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
			Err(e) => return Err(e.into()),
		};
		if !file.metadata()?.file_type().is_file() {
			return Err(QuantusError::Generic("wallet path is not a regular file".to_string()));
		}
		let mut wallet_json = String::new();
		file.read_to_string(&mut wallet_json)?;
		let wallet: EncryptedWallet = serde_json::from_str(&wallet_json)?;
		Self::validate_wallet_address(&wallet.address)?;
		Ok(Some(wallet))
	}

	fn validate_wallet_address(address: &str) -> Result<()> {
		use crate::cli::address_format::quantus_ss58_format;

		let (account_id, format) = AccountId32::from_ss58check_with_version(address)
			.map_err(|_| WalletError::InvalidAddress)?;
		if format != quantus_ss58_format()
			|| account_id.to_ss58check_with_version(quantus_ss58_format()) != address
		{
			return Err(WalletError::InvalidAddress.into());
		}
		Ok(())
	}

	/// List all wallet files
	pub fn list_wallets(&self) -> Result<Vec<String>> {
		let mut wallets = Vec::new();

		if !self.storage_path.exists() {
			return Ok(wallets);
		}

		for entry in std::fs::read_dir(&self.storage_path)? {
			let entry = entry?;
			let path = entry.path();

			if path.extension().and_then(|s| s.to_str()) == Some("json") {
				if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
					if wallet_filename(name).is_ok() {
						wallets.push(name.to_string());
					}
				}
			}
		}

		Ok(wallets)
	}

	/// Delete a wallet file
	pub fn delete_wallet(&self, name: &str) -> Result<bool> {
		let _guard = keystore_lock()
			.lock()
			.map_err(|_| QuantusError::Generic("keystore lock poisoned".to_string()))?;
		let wallet_file = self.storage_path.join(wallet_filename(name)?);
		let before = match fs::symlink_metadata(&wallet_file) {
			Ok(metadata) => metadata,
			Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
			Err(e) => return Err(e.into()),
		};
		if !before.file_type().is_file() {
			return Err(QuantusError::Generic(
				"refusing to delete non-regular wallet file".to_string(),
			));
		}

		let (tombstone, tombstone_file) = create_unique_temp(&self.storage_path, name)?;
		drop(tombstone_file);
		fs::remove_file(&tombstone)?;
		match fs::rename(&wallet_file, &tombstone) {
			Ok(()) => {},
			Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
			Err(e) => return Err(e.into()),
		}

		let after = fs::symlink_metadata(&tombstone)?;
		if !after.file_type().is_file() || !same_file_metadata(&before, &after) {
			let _ = fs::rename(&tombstone, &wallet_file);
			return Err(QuantusError::Generic("wallet changed during delete".to_string()));
		}
		fs::remove_file(tombstone)?;
		Ok(true)
	}

	/// Encrypt wallet data using quantum-safe Argon2 + AES-256-GCM
	/// This provides quantum-safe symmetric encryption with strong password derivation
	pub fn encrypt_wallet_data(
		&self,
		data: &WalletData,
		password: &str,
	) -> Result<EncryptedWallet> {
		// 1. Generate salt for Argon2
		let mut argon2_salt = [0u8; 16];
		rng().fill_bytes(&mut argon2_salt);

		// 2. Derive encryption key from password using Argon2 (quantum-safe)
		let argon2 = Argon2::default();
		let salt_string = argon2::password_hash::SaltString::encode_b64(&argon2_salt)
			.map_err(|e| WalletError::Encryption(e.to_string()))?;
		let password_hash = argon2
			.hash_password(password.as_bytes(), &salt_string)
			.map_err(|e| WalletError::Encryption(e.to_string()))?;

		// 3. Use password hash as AES-256 key (quantum-safe with 256-bit key)
		let hash_bytes = password_hash.hash.as_ref().unwrap().as_bytes();
		let aes_key = Key::<Aes256Gcm>::from(<[u8; 32]>::try_from(&hash_bytes[..32]).unwrap());
		let cipher = Aes256Gcm::new(&aes_key);

		// 4. Generate nonce and encrypt the wallet data
		let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
		let serialized_data = serde_json::to_vec(data)?;
		let encrypted_data = cipher
			.encrypt(&nonce, serialized_data.as_ref())
			.map_err(|e| WalletError::Encryption(e.to_string()))?;

		// 5. Store the Argon2 parameters WITHOUT the digest. The digest determines
		// the AES key, so persisting it next to the ciphertext would let anyone
		// reading the wallet file decrypt it without the password. Only salt and
		// cost parameters are persisted; the key is re-derived from the password
		// at decrypt time.
		let mut password_hash = password_hash;
		password_hash.hash = None;

		Ok(EncryptedWallet {
			name: data.name.clone(),
			address: data.keypair.to_account_id_ss58check(), // Store public address
			encrypted_data,
			kyber_ciphertext: vec![], // Reserved for future ML-KEM implementation
			kyber_public_key: vec![], // Reserved for future ML-KEM implementation
			argon2_salt: argon2_salt.to_vec(),
			argon2_params: password_hash.to_string(),
			aes_nonce: nonce.to_vec(),
			encryption_version: 2, // Version 2: Argon2 params+salt only (no digest) + AES-256-GCM
			created_at: chrono::Utc::now(),
		})
	}

	/// Decrypt wallet data using quantum-safe decryption
	pub fn decrypt_wallet_data(
		&self,
		encrypted: &EncryptedWallet,
		password: &str,
	) -> Result<WalletData> {
		// 1. Re-derive the AES key from the password and the stored salt + params.
		// The key itself is never stored in the wallet file.
		let aes_key = Self::derive_aes_key(encrypted, password)?;
		let cipher = Aes256Gcm::new(&aes_key);

		// 2. Decrypt the data. An AES-GCM authentication failure means the password
		// was wrong (or the file was tampered with) - this is the password check.
		let nonce = Nonce::from(<[u8; 12]>::try_from(&encrypted.aes_nonce[..]).unwrap());
		let decrypted_data = cipher
			.decrypt(&nonce, encrypted.encrypted_data.as_ref())
			.map_err(|_| WalletError::InvalidPassword)?;

		// 3. Deserialize the wallet data
		let wallet_data: WalletData = serde_json::from_slice(&decrypted_data)?;

		// 4. The plaintext envelope address is not AEAD-authenticated, so it must
		// match the address derived from the decrypted key material before the
		// wallet file is accepted as intact.
		let derived_address = wallet_data.keypair.to_account_id_ss58check();
		if encrypted.address != derived_address {
			return Err(WalletError::Integrity(
				"stored address does not match decrypted keypair".to_string(),
			)
			.into());
		}

		Ok(wallet_data)
	}

	/// Derive the AES-256 key from a password and the wallet's stored Argon2 salt
	/// and parameters. Works for both the current format (params only) and legacy
	/// files (params + digest); the embedded digest of legacy files is ignored.
	fn derive_aes_key(encrypted: &EncryptedWallet, password: &str) -> Result<Key<Aes256Gcm>> {
		// The cost parameters come from the wallet file, so cap them: a crafted
		// file could otherwise request an enormous m_cost and force a huge
		// allocation. Limits are far above anything we ever write (defaults are
		// m=19456 KiB, t=2, p=1).
		const MAX_M_COST: u32 = 1 << 20; // 1 GiB (in KiB)
		const MAX_T_COST: u32 = 64;
		const MAX_P_COST: u32 = 16;

		let parsed =
			PasswordHash::new(&encrypted.argon2_params).map_err(|_| WalletError::Decryption)?;

		let algorithm =
			Algorithm::new(parsed.algorithm.as_str()).map_err(|_| WalletError::Decryption)?;
		let version = Version::try_from(parsed.version.unwrap_or(Version::V0x13 as u32))
			.map_err(|_| WalletError::Decryption)?;
		let m_cost = parsed.params.get_decimal("m").unwrap_or(Params::DEFAULT_M_COST);
		let t_cost = parsed.params.get_decimal("t").unwrap_or(Params::DEFAULT_T_COST);
		let p_cost = parsed.params.get_decimal("p").unwrap_or(Params::DEFAULT_P_COST);
		if m_cost > MAX_M_COST || t_cost > MAX_T_COST || p_cost > MAX_P_COST {
			return Err(WalletError::Decryption.into());
		}
		let params =
			Params::new(m_cost, t_cost, p_cost, None).map_err(|_| WalletError::Decryption)?;
		let argon2 = Argon2::new(algorithm, version, params);

		let mut key = [0u8; 32];
		argon2
			.hash_password_into(password.as_bytes(), &encrypted.argon2_salt, &mut key)
			.map_err(|_| WalletError::Decryption)?;

		Ok(Key::<Aes256Gcm>::from(key))
	}

	/// Returns true if the wallet embeds the Argon2 digest in `argon2_params`
	/// (legacy format, `encryption_version` 1). Since the digest determines the AES
	/// key, such files allow decryption without the password and must be
	/// re-encrypted (done transparently on unlock in `WalletManager::load_wallet`).
	pub fn has_embedded_key_material(encrypted: &EncryptedWallet) -> bool {
		PasswordHash::new(&encrypted.argon2_params)
			.map(|h| h.hash.is_some())
			.unwrap_or(false)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use qp_dilithium_crypto::{crystal_alice, crystal_charlie, dilithium_bob};
	use qp_rusty_crystals_dilithium::ml_dsa_87::Keypair;
	use sp_core::Pair;
	use tempfile::TempDir;

	#[test]
	fn test_quantum_keypair_from_dilithium_keypair() {
		// Generate a test keypair
		let mut entropy = [1u8; 32];
		let dilithium_keypair = Keypair::generate(SensitiveBytes32::from(&mut entropy));

		// Convert to QuantumKeyPair
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

		// Verify the conversion
		assert_eq!(quantum_keypair.public_key, dilithium_keypair.public.to_bytes().to_vec());
		assert_eq!(quantum_keypair.private_key, dilithium_keypair.secret.to_bytes().to_vec());
	}

	#[test]
	fn test_quantum_keypair_to_dilithium_keypair_roundtrip() {
		// Generate a test keypair
		let mut entropy = [2u8; 32];
		let original_keypair = Keypair::generate(SensitiveBytes32::from(&mut entropy));

		// Convert to QuantumKeyPair and back
		let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&original_keypair);
		let converted_keypair =
			quantum_keypair.to_dilithium_keypair().expect("Conversion should succeed");

		// Verify round-trip conversion preserves data
		assert_eq!(original_keypair.public.to_bytes(), converted_keypair.public.to_bytes());
		assert_eq!(original_keypair.secret.to_bytes(), converted_keypair.secret.to_bytes());
	}

	#[test]
	fn test_quantum_keypair_from_resonance_pair() {
		// Test with crystal_alice
		let resonance_pair = crystal_alice();
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&resonance_pair);

		// Verify the conversion
		assert_eq!(quantum_keypair.public_key, resonance_pair.public().as_ref().to_vec());
		assert_eq!(quantum_keypair.private_key.as_slice(), resonance_pair.secret_bytes());
	}

	#[test]
	fn test_quantum_keypair_to_resonance_pair_roundtrip() {
		// Test with crystal_bob
		let original_pair = dilithium_bob();
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&original_pair);
		let converted_pair =
			quantum_keypair.to_resonance_pair().expect("Conversion should succeed");

		// Verify round-trip conversion preserves data
		assert_eq!(original_pair.public().as_ref(), converted_pair.public().as_ref());
		assert_eq!(original_pair.secret_bytes(), converted_pair.secret_bytes());
	}

	/// Wallet address must match chain: same AccountId (Poseidon hash of Dilithium public)
	/// and same SS58 prefix (189, "qz") as in chain runtime and genesis.
	#[test]
	fn test_quantum_keypair_address_generation() {
		sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));
		// Same test keypairs as chain genesis (crystal_alice, dilithium_bob, crystal_charlie)
		let test_pairs = vec![
			("crystal_alice", crystal_alice()),
			("crystal_bob", dilithium_bob()),
			("crystal_charlie", crystal_charlie()),
		];

		for (name, resonance_pair) in test_pairs {
			let quantum_keypair = QuantumKeyPair::from_resonance_pair(&resonance_pair);

			// Generate address using both methods
			let account_id = quantum_keypair.to_account_id_32();
			let ss58_address = quantum_keypair.to_account_id_ss58check();

			// Verify address format (Quantus SS58 prefix 189 = "qz")
			assert!(
				ss58_address.starts_with("qz"),
				"SS58 address for {name} should start with qz (Quantus prefix 189)"
			);
			assert!(
				ss58_address.len() >= 47,
				"SS58 address for {name} should be at least 47 characters"
			);

			// Verify consistency between methods
			use crate::cli::address_format::quantus_ss58_format;
			assert_eq!(
				account_id.to_ss58check_with_version(quantus_ss58_format()),
				ss58_address,
				"Address methods should be consistent for {name}"
			);

			// Must match chain: chain uses same qp_dilithium_crypto IdentifyAccount (into_account)
			// and SS58 189 in genesis_config_presets and runtime config
			let chain_expected_address = resonance_pair
				.public()
				.into_account()
				.to_ss58check_with_version(quantus_ss58_format());
			assert_eq!(
				ss58_address, chain_expected_address,
				"Wallet address for {name} must match chain dev account (same derivation and SS58 189)"
			);
		}
	}

	#[test]
	fn test_ss58_to_account_id_conversion() {
		sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));
		// Test with known addresses
		use crate::cli::address_format::quantus_ss58_format;
		let test_cases = vec![
			crystal_alice()
				.public()
				.into_account()
				.to_ss58check_with_version(quantus_ss58_format()),
			dilithium_bob()
				.public()
				.into_account()
				.to_ss58check_with_version(quantus_ss58_format()),
			crystal_charlie()
				.public()
				.into_account()
				.to_ss58check_with_version(quantus_ss58_format()),
		];

		for ss58_address in test_cases {
			// Convert SS58 to account ID bytes
			let account_bytes = QuantumKeyPair::ss58_to_account_id(&ss58_address);

			// Verify length (AccountId32 should be 32 bytes)
			assert_eq!(account_bytes.len(), 32, "Account ID should be 32 bytes");

			// Convert back to SS58 and verify round-trip
			let account_id =
				AccountId32::from_slice(&account_bytes).expect("Should create valid AccountId32");
			let round_trip_address =
				account_id.to_ss58check_with_version(Ss58AddressFormat::custom(189));
			assert_eq!(
				ss58_address, round_trip_address,
				"Round-trip conversion should preserve address"
			);
		}
	}

	#[test]
	fn test_address_consistency_across_conversions() {
		// Start with a Dilithium keypair
		sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));

		let mut entropy = [3u8; 32];
		let dilithium_keypair = Keypair::generate(SensitiveBytes32::from(&mut entropy));

		// Convert through different paths
		let quantum_from_dilithium = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);
		let resonance_from_quantum =
			quantum_from_dilithium.to_resonance_pair().expect("Should convert");
		let quantum_from_resonance = QuantumKeyPair::from_resonance_pair(&resonance_from_quantum);

		// All should generate the same address
		let addr1 = quantum_from_dilithium.to_account_id_ss58check();
		let addr2 = quantum_from_resonance.to_account_id_ss58check();
		let addr3 = resonance_from_quantum
			.public()
			.into_account()
			.to_ss58check_with_version(Ss58AddressFormat::custom(189));

		assert_eq!(addr1, addr2, "Addresses should be consistent across conversion paths");
		assert_eq!(addr2, addr3, "Address should match direct DilithiumPair calculation");
	}

	#[test]
	fn test_known_test_wallet_addresses() {
		// Test that our test wallets generate expected addresses
		sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));
		let alice_pair = crystal_alice();
		let bob_pair = dilithium_bob();
		let charlie_pair = crystal_charlie();

		let alice_quantum = QuantumKeyPair::from_resonance_pair(&alice_pair);
		let bob_quantum = QuantumKeyPair::from_resonance_pair(&bob_pair);
		let charlie_quantum = QuantumKeyPair::from_resonance_pair(&charlie_pair);

		let alice_addr = alice_quantum.to_account_id_ss58check();
		let bob_addr = bob_quantum.to_account_id_ss58check();
		let charlie_addr = charlie_quantum.to_account_id_ss58check();

		// Addresses should be different
		assert_ne!(alice_addr, bob_addr, "Alice and Bob should have different addresses");
		assert_ne!(bob_addr, charlie_addr, "Bob and Charlie should have different addresses");
		assert_ne!(alice_addr, charlie_addr, "Alice and Charlie should have different addresses");

		// All should be valid SS58 addresses
		assert!(alice_addr.starts_with("qz"), "Alice address should be valid SS58");
		assert!(bob_addr.starts_with("qz"), "Bob address should be valid SS58");
		assert!(charlie_addr.starts_with("qz"), "Charlie address should be valid SS58");

		println!("Test wallet addresses:");
		println!("  Alice:   {alice_addr}");
		println!("  Bob:     {bob_addr}");
		println!("  Charlie: {charlie_addr}");
	}

	#[test]
	fn test_invalid_ss58_address_handling() {
		// Test with invalid SS58 addresses
		let invalid_addresses = vec![
			"invalid",
			"5",          // Too short
			"1234567890", // Wrong format
			"",           // Empty
		];

		for invalid_addr in invalid_addresses {
			let result =
				std::panic::catch_unwind(|| QuantumKeyPair::ss58_to_account_id(invalid_addr));
			assert!(result.is_err(), "Should panic on invalid address: {invalid_addr}");
		}
	}

	#[test]
	fn test_stored_wallet_address_generation() {
		sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));

		// This test reproduces the error that occurs when loading a wallet from disk
		// and trying to generate its address - simulating the real-world scenario

		// Create a test wallet like the developer wallets
		let alice_pair = crystal_alice();
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&alice_pair);

		// Create wallet data like what gets stored
		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("test_wallet".to_string(), "true".to_string());

		let wallet_data = WalletData {
			name: "test_crystal_alice".to_string(),
			keypair: quantum_keypair.clone(),
			mnemonic: None,
			derivation_path: "m/".to_string(),
			metadata,
		};

		// Test that we can generate address from the stored keypair
		let result = std::panic::catch_unwind(|| wallet_data.keypair.to_account_id_ss58check());

		match result {
			Ok(address) => {
				println!("✅ Address generation successful: {address}");
				// Verify it matches the expected address
				let expected = alice_pair
					.public()
					.into_account()
					.to_ss58check_with_version(Ss58AddressFormat::custom(189));
				assert_eq!(address, expected, "Stored wallet should generate correct address");
			},
			Err(_) => {
				panic!("❌ Address generation failed - this is the bug we need to fix!");
			},
		}
	}

	#[test]
	fn test_encrypted_wallet_address_generation() {
		// This test simulates the full encryption/decryption cycle that happens
		// when creating a developer wallet and then trying to use it for sending

		let temp_dir = tempfile::TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());

		// Create a developer wallet like crystal_alice
		let alice_pair = crystal_alice();
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&alice_pair);

		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("test_wallet".to_string(), "true".to_string());

		let wallet_data = WalletData {
			name: "test_crystal_alice".to_string(),
			keypair: quantum_keypair,
			mnemonic: None,
			derivation_path: "m/".to_string(),
			metadata,
		};

		// Encrypt the wallet (like developer wallets use empty password)
		let encrypted_wallet = keystore
			.encrypt_wallet_data(&wallet_data, "")
			.expect("Encryption should succeed");

		// Save and reload the wallet
		keystore.save_wallet(&encrypted_wallet).expect("Save should succeed");
		let loaded_wallet = keystore
			.load_wallet("test_crystal_alice")
			.expect("Load should succeed")
			.expect("Wallet should exist");

		// Decrypt the wallet (this is where the send command would decrypt it)
		let decrypted_data = keystore
			.decrypt_wallet_data(&loaded_wallet, "")
			.expect("Decryption should succeed");

		// Test that we can generate address from the decrypted keypair
		let result = std::panic::catch_unwind(|| decrypted_data.keypair.to_account_id_ss58check());

		match result {
			Ok(address) => {
				println!("✅ Encrypted wallet address generation successful: {address}");
				// Verify it matches the expected address
				let expected = alice_pair
					.public()
					.into_account()
					.to_ss58check_with_version(Ss58AddressFormat::custom(189));
				assert_eq!(address, expected, "Decrypted wallet should generate correct address");
			},
			Err(_) => {
				panic!("❌ Encrypted wallet address generation failed - this reproduces the send command bug!");
			},
		}
	}

	#[test]
	fn test_send_command_wallet_loading_flow() {
		// This test reproduces the exact bug in the send command
		// The send command calls wallet_manager.load_wallet() which returns dummy data
		// then tries to generate an address from that dummy data, causing the panic

		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());

		// Create and save a developer wallet like crystal_alice
		let alice_pair = crystal_alice();
		let quantum_keypair = QuantumKeyPair::from_resonance_pair(&alice_pair);

		let mut metadata = std::collections::HashMap::new();
		metadata.insert("version".to_string(), "1.0.0".to_string());
		metadata.insert("algorithm".to_string(), "ML-DSA-87".to_string());
		metadata.insert("test_wallet".to_string(), "true".to_string());

		let wallet_data = WalletData {
			name: "crystal_alice".to_string(),
			keypair: quantum_keypair,
			mnemonic: None,
			derivation_path: "m/".to_string(),
			metadata,
		};

		// Encrypt and save the wallet (like developer wallets use empty password)
		let encrypted_wallet = keystore
			.encrypt_wallet_data(&wallet_data, "")
			.expect("Encryption should succeed");
		keystore.save_wallet(&encrypted_wallet).expect("Save should succeed");

		// Now simulate what the send command does:
		// 1. Create a WalletManager and load the wallet with password
		use crate::wallet::WalletManager;
		let wallet_manager = WalletManager { wallets_dir: temp_dir.path().to_path_buf() };
		let loaded_wallet_data =
			wallet_manager.load_wallet("crystal_alice", "").expect("Should load wallet");

		// 2. Try to generate address from the loaded keypair (should work now)
		let result = std::panic::catch_unwind(|| {
			// The keypair is already decrypted, so we can use it directly
			loaded_wallet_data.keypair.to_account_id_ss58check()
		});

		match result {
			Ok(address) => {
				println!("✅ Send command flow works: {address}");
				// If this passes, the bug is fixed
				let expected = alice_pair
					.public()
					.into_account()
					.to_ss58check_with_version(Ss58AddressFormat::custom(189));
				assert_eq!(address, expected, "Loaded wallet should generate correct address");
			},
			Err(_) => {
				println!("❌ Send command flow failed - this reproduces the bug!");
				// This test should fail initially, proving we found the bug
				panic!(
					"This test reproduces the send command bug - load_wallet returns dummy data!"
				);
			},
		}
	}

	#[test]
	fn test_keypair_data_integrity() {
		// Generate multiple keypairs and verify they maintain data integrity
		for i in 0..5 {
			let mut entropy = [i as u8; 32];
			let dilithium_keypair = Keypair::generate(SensitiveBytes32::from(&mut entropy));
			let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

			// Print actual key sizes for debugging (first iteration only)
			if i == 0 {
				println!("Actual public key size: {}", quantum_keypair.public_key.len());
				println!("Actual private key size: {}", quantum_keypair.private_key.len());
			}

			// Verify key sizes are consistent and reasonable
			assert!(
				quantum_keypair.public_key.len() > 1000,
				"Public key should be reasonably large (actual: {})",
				quantum_keypair.public_key.len()
			);
			assert!(
				quantum_keypair.private_key.len() > 2000,
				"Private key should be reasonably large (actual: {})",
				quantum_keypair.private_key.len()
			);

			// Verify keys are not all zeros
			assert!(
				quantum_keypair.public_key.iter().any(|&b| b != 0),
				"Public key should not be all zeros"
			);
			assert!(
				quantum_keypair.private_key.iter().any(|&b| b != 0),
				"Private key should not be all zeros"
			);
		}
	}

	fn make_test_wallet_data(name: &str, entropy_byte: u8) -> WalletData {
		let mut entropy = [entropy_byte; 32];
		let dilithium_keypair = Keypair::generate(SensitiveBytes32::from(&mut entropy));
		let keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);
		WalletData {
			name: name.to_string(),
			keypair,
			mnemonic: Some("test mnemonic phrase".to_string()),
			derivation_path: "m/".to_string(),
			metadata: std::collections::HashMap::new(),
		}
	}

	/// Replicates the legacy (v1) encryption logic, which stored the full Argon2
	/// PHC string including the digest that determines the AES key.
	fn encrypt_legacy(data: &WalletData, password: &str) -> EncryptedWallet {
		let mut argon2_salt = [0u8; 16];
		rng().fill_bytes(&mut argon2_salt);
		let argon2 = Argon2::default();
		let salt_string = argon2::password_hash::SaltString::encode_b64(&argon2_salt).unwrap();
		let password_hash = argon2.hash_password(password.as_bytes(), &salt_string).unwrap();
		let hash_bytes = password_hash.hash.as_ref().unwrap().as_bytes();
		let aes_key = Key::<Aes256Gcm>::from(<[u8; 32]>::try_from(&hash_bytes[..32]).unwrap());
		let cipher = Aes256Gcm::new(&aes_key);
		let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
		let encrypted_data =
			cipher.encrypt(&nonce, serde_json::to_vec(data).unwrap().as_ref()).unwrap();

		EncryptedWallet {
			name: data.name.clone(),
			address: data.keypair.to_account_id_ss58check(),
			encrypted_data,
			kyber_ciphertext: vec![],
			kyber_public_key: vec![],
			argon2_salt: argon2_salt.to_vec(),
			argon2_params: password_hash.to_string(), // legacy: includes the digest
			aes_nonce: nonce.to_vec(),
			encryption_version: 1,
			created_at: chrono::Utc::now(),
		}
	}

	#[test]
	fn test_encrypt_does_not_store_key_material() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());
		let data = make_test_wallet_data("no-key-material", 7);

		let encrypted = keystore
			.encrypt_wallet_data(&data, "hunter2")
			.expect("Encryption should succeed");

		// The stored params must NOT contain the Argon2 digest - the AES key is
		// derived from that digest, so storing it would store the key.
		let parsed = PasswordHash::new(&encrypted.argon2_params).expect("Params should parse");
		assert!(parsed.hash.is_none(), "argon2_params must not contain the Argon2 digest");
		assert_eq!(encrypted.encryption_version, 2);
		assert!(!Keystore::has_embedded_key_material(&encrypted));

		// The serialized wallet file must not contain the base64 digest anywhere.
		let argon2 = Argon2::default();
		let salt_string =
			argon2::password_hash::SaltString::encode_b64(&encrypted.argon2_salt).unwrap();
		let full_phc = argon2.hash_password(b"hunter2", &salt_string).unwrap().to_string();
		let digest_b64 = full_phc.rsplit('$').next().expect("PHC should contain a digest");
		let wallet_json = serde_json::to_string(&encrypted).unwrap();
		assert!(!wallet_json.contains(digest_b64), "wallet JSON leaks the encryption key");

		// Round-trip still works with the correct password.
		let decrypted = keystore
			.decrypt_wallet_data(&encrypted, "hunter2")
			.expect("Decryption should succeed");
		assert_eq!(decrypted.name, data.name);
		assert_eq!(decrypted.mnemonic, data.mnemonic);
		assert_eq!(decrypted.keypair.private_key, data.keypair.private_key);
	}

	#[test]
	fn test_decrypt_wrong_password_fails() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());
		let data = make_test_wallet_data("wrong-password", 8);

		let encrypted =
			keystore.encrypt_wallet_data(&data, "right").expect("Encryption should succeed");

		let result = keystore.decrypt_wallet_data(&encrypted, "wrong");
		assert!(
			matches!(result, Err(crate::error::QuantusError::Wallet(WalletError::InvalidPassword))),
			"Wrong password must be rejected, got: {result:?}"
		);
	}

	#[test]
	fn decrypt_rejects_tampered_envelope_address() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());
		let victim = make_test_wallet_data("integrity-victim", 10);
		let attacker = make_test_wallet_data("integrity-attacker", 11);

		let mut encrypted = keystore
			.encrypt_wallet_data(&victim, "correct-password")
			.expect("Encryption should succeed");
		let victim_address = encrypted.address.clone();
		let attacker_address = attacker.keypair.to_account_id_ss58check();
		assert_ne!(victim_address, attacker_address);

		// Attacker rewrites only the plaintext envelope address; ciphertext is untouched.
		encrypted.address = attacker_address;

		let result = keystore.decrypt_wallet_data(&encrypted, "correct-password");
		assert!(
			matches!(
				result,
				Err(crate::error::QuantusError::Wallet(WalletError::Integrity(_)))
			),
			"tampered envelope address must fail integrity after authenticated decrypt, got: {result:?}"
		);
	}

	#[test]
	fn test_legacy_wallet_decrypt_and_migration() {
		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());
		let data = make_test_wallet_data("legacy-wallet", 9);

		// Save a wallet in the legacy format (digest embedded in argon2_params)
		let legacy = encrypt_legacy(&data, "pw");
		assert!(Keystore::has_embedded_key_material(&legacy));
		keystore.save_wallet(&legacy).expect("Save should succeed");

		// Legacy files must still decrypt with the correct password...
		let decrypted = keystore
			.decrypt_wallet_data(&legacy, "pw")
			.expect("Legacy decrypt should succeed");
		assert_eq!(decrypted.name, data.name);
		assert_eq!(decrypted.keypair.private_key, data.keypair.private_key);

		// ...and reject the wrong one
		let result = keystore.decrypt_wallet_data(&legacy, "nope");
		assert!(
			matches!(result, Err(crate::error::QuantusError::Wallet(WalletError::InvalidPassword))),
			"Wrong password must be rejected for legacy files, got: {result:?}"
		);

		// Unlocking via WalletManager transparently re-encrypts the file
		use crate::wallet::WalletManager;
		let wallet_manager = WalletManager { wallets_dir: temp_dir.path().to_path_buf() };
		wallet_manager.load_wallet("legacy-wallet", "pw").expect("Load should succeed");

		let reloaded = keystore
			.load_wallet("legacy-wallet")
			.expect("Load should succeed")
			.expect("Wallet should exist");
		assert!(
			!Keystore::has_embedded_key_material(&reloaded),
			"wallet file should be migrated: no digest in argon2_params"
		);
		assert_eq!(reloaded.encryption_version, 2);

		// The migrated file still decrypts with the same password
		let decrypted = keystore
			.decrypt_wallet_data(&reloaded, "pw")
			.expect("Migrated wallet should decrypt");
		assert_eq!(decrypted.name, data.name);
		assert_eq!(decrypted.keypair.private_key, data.keypair.private_key);
	}

	/// When migration cannot persist the re-encrypted wallet, load_wallet must
	/// fail closed rather than returning Ok while leaving password-bypassable
	/// key material on disk.
	#[cfg(unix)]
	#[test]
	fn test_legacy_migration_save_failure_fails_closed() {
		use std::fs;
		use std::os::unix::fs::PermissionsExt;

		let temp_dir = TempDir::new().expect("Failed to create temp directory");
		let keystore = Keystore::new(temp_dir.path());
		let data = make_test_wallet_data("legacy-ro-wallet", 12);

		let legacy = encrypt_legacy(&data, "pw");
		assert!(Keystore::has_embedded_key_material(&legacy));
		keystore.save_wallet(&legacy).expect("Save should succeed");

		// Force migration save to fail (cannot create .json.tmp in read-only dir).
		let mut perms = fs::metadata(temp_dir.path()).unwrap().permissions();
		perms.set_mode(0o555);
		fs::set_permissions(temp_dir.path(), perms).unwrap();

		use crate::wallet::WalletManager;
		let wallet_manager = WalletManager { wallets_dir: temp_dir.path().to_path_buf() };
		let result = wallet_manager.load_wallet("legacy-ro-wallet", "pw");

		// Restore writability so TempDir cleanup and assertions can proceed.
		let mut perms = fs::metadata(temp_dir.path()).unwrap().permissions();
		perms.set_mode(0o755);
		fs::set_permissions(temp_dir.path(), perms).unwrap();

		assert!(
			result.is_err(),
			"load_wallet must Err when migration cannot save, got: {result:?}"
		);

		let reloaded = keystore
			.load_wallet("legacy-ro-wallet")
			.expect("Load should succeed")
			.expect("Wallet should exist");
		assert!(
			Keystore::has_embedded_key_material(&reloaded),
			"failed migration must leave legacy file with embedded digest"
		);
	}

	/// #160598: a predictable `{name}.json.tmp` symlink must not be followed or
	/// cause an outside file to be overwritten when saving a wallet.
	#[cfg(unix)]
	#[test]
	fn save_wallet_does_not_follow_predictable_tmp_symlink() {
		use std::fs;
		use std::os::unix::fs::symlink;

		let temp = TempDir::new().expect("temp dir");
		let wallets_dir = temp.path().join("wallets");
		let outside_dir = temp.path().join("outside");
		fs::create_dir_all(&wallets_dir).expect("wallet dir");
		fs::create_dir_all(&outside_dir).expect("outside dir");

		let victim = outside_dir.join("outside_component_state.txt");
		let original = b"owned by another local component\n";
		fs::write(&victim, original).expect("seed victim");

		let wallet_name = "raceable-wallet";
		let predictable_tmp = wallets_dir.join(format!("{wallet_name}.json.tmp"));
		symlink(&victim, &predictable_tmp).expect("attacker symlink at predictable tmp");

		let keystore = Keystore::new(&wallets_dir);
		let data = make_test_wallet_data(wallet_name, 21);
		let encrypted = keystore
			.encrypt_wallet_data(&data, "password chosen by wallet owner")
			.expect("encrypt");

		keystore.save_wallet(&encrypted).expect("save must succeed without following symlink");

		assert_eq!(
			fs::read(&victim).expect("read victim"),
			original,
			"outside file must not be overwritten via predictable tmp symlink"
		);
		let final_path = wallets_dir.join(format!("{wallet_name}.json"));
		assert!(final_path.is_file(), "final wallet must be a regular file");
		assert!(
			fs::symlink_metadata(&final_path).expect("stat").file_type().is_file(),
			"final wallet entry must not be a symlink"
		);
	}

	/// #160737: exclusive create must refuse to replace an existing wallet file.
	#[test]
	fn save_new_wallet_does_not_replace_existing() {
		let temp = TempDir::new().expect("temp dir");
		let keystore = Keystore::new(temp.path());

		let original = make_test_wallet_data("exclusive-wallet", 22);
		let first = keystore.encrypt_wallet_data(&original, "pw").expect("encrypt first");
		keystore.save_new_wallet(&first).expect("first create must succeed");

		let replacement = make_test_wallet_data("exclusive-wallet", 23);
		let second = keystore.encrypt_wallet_data(&replacement, "pw").expect("encrypt second");
		let result = keystore.save_new_wallet(&second);
		assert!(
			matches!(result, Err(crate::error::QuantusError::Wallet(WalletError::AlreadyExists))),
			"second create must fail with AlreadyExists, got: {result:?}"
		);

		let loaded = keystore
			.load_wallet("exclusive-wallet")
			.expect("load")
			.expect("wallet present");
		assert_eq!(
			loaded.address, first.address,
			"existing wallet key material must not be replaced"
		);
		assert_ne!(loaded.address, second.address);
	}

	/// #160598 / #160737: path separators and traversal names are rejected.
	#[test]
	fn rejects_wallet_names_with_path_separators() {
		let temp = TempDir::new().expect("temp dir");
		let keystore = Keystore::new(temp.path());
		let data = make_test_wallet_data("safe-name", 24);
		let mut encrypted =
			keystore.encrypt_wallet_data(&data, "pw").expect("encrypt");

		for bad_name in ["../evil", "foo/bar", "foo\\bar", ".", "..", ""] {
			encrypted.name = bad_name.to_string();
			let save = keystore.save_wallet(&encrypted);
			assert!(
				matches!(save, Err(crate::error::QuantusError::Wallet(WalletError::InvalidName))),
				"save_wallet must reject {bad_name:?}, got: {save:?}"
			);
			let create = keystore.save_new_wallet(&encrypted);
			assert!(
				matches!(create, Err(crate::error::QuantusError::Wallet(WalletError::InvalidName))),
				"save_new_wallet must reject {bad_name:?}, got: {create:?}"
			);
			let load = keystore.load_wallet(bad_name);
			assert!(
				matches!(load, Err(crate::error::QuantusError::Wallet(WalletError::InvalidName))),
				"load_wallet must reject {bad_name:?}, got: {load:?}"
			);
			let delete = keystore.delete_wallet(bad_name);
			assert!(
				matches!(delete, Err(crate::error::QuantusError::Wallet(WalletError::InvalidName))),
				"delete_wallet must reject {bad_name:?}, got: {delete:?}"
			);
		}
	}
}
