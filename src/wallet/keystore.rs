/// Quantum-safe keystore for wallet data
///
/// This module handles:
/// - Quantum-safe encrypting and storing wallet data using Argon2 + AES-256-GCM
/// - Loading and decrypting wallet data with post-quantum cryptography
/// - Managing wallet files on disk with quantum-resistant security
use crate::error::{Result, WalletError};
use rusty_crystals_dilithium::ml_dsa_87::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::ByteArray;

// Quantum-safe encryption imports
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::{rng, RngCore};

use std::path::Path;

use dilithium_crypto::types::{DilithiumPair, DilithiumPublic};
use sp_runtime::traits::IdentifyAccount;

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
        Ok(Keypair {
            public: PublicKey::from_bytes(&self.public_key).expect("Failed to parse public key"),
            secret: SecretKey::from_bytes(&self.private_key).expect("Failed to parse private key"),
        })
    }

    /// Convert to DilithiumPair for use with substrate-api-client
    pub fn to_resonance_pair(&self) -> Result<DilithiumPair> {
        // Convert our QuantumKeyPair to DilithiumPair using from_seed
        // Use the private key as the seed
        Ok(DilithiumPair {
            public: self.public_key.as_slice().try_into().unwrap(),
            secret: self.private_key.as_slice().try_into().unwrap(),
        })
    }

    #[allow(dead_code)]
    pub fn from_resonance_pair(keypair: &DilithiumPair) -> Self {
        Self {
            public_key: keypair.public.as_ref().to_vec(),
            private_key: keypair.secret.as_ref().to_vec(),
        }
    }

    pub fn to_account_id_32(&self) -> AccountId32 {
        // Use the DilithiumPublic's into_account method for correct address generation
        let resonance_public =
            DilithiumPublic::from_slice(&self.public_key).expect("Invalid public key");
        resonance_public.into_account()
    }

    pub fn to_account_id_ss58check(&self) -> String {
        let account = self.to_account_id_32();
        account.to_ss58check()
    }

    /// Convert to subxt Signer for use
    pub fn to_subxt_signer(&self) -> Result<dilithium_crypto::types::DilithiumPair> {
        // Convert to DilithiumPair first - now it implements subxt::tx::Signer<ChainConfig>
        let resonance_pair = self.to_resonance_pair()?;

        Ok(resonance_pair)
    }

    #[allow(dead_code)]
    pub fn ss58_to_account_id(s: &str) -> Vec<u8> {
        // from_ss58check returns a Result, we unwrap it to panic on invalid input.
        // We then convert the AccountId32 struct to a Vec<u8> to be compatible with Polkadart's typedef.
        AsRef::<[u8]>::as_ref(&AccountId32::from_ss58check(s).unwrap()).to_vec()
    }
}

/// Quantum-safe encrypted wallet data structure
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub name: String,
    pub address: String, // SS58-encoded address (public, not encrypted)
    pub encrypted_data: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>, // Reserved for future ML-KEM implementation
    pub kyber_public_key: Vec<u8>, // Reserved for future ML-KEM implementation
    pub argon2_salt: Vec<u8>,      // Salt for password-based key derivation
    pub argon2_params: String,     // Argon2 parameters for verification
    pub aes_nonce: Vec<u8>,        // AES-GCM nonce
    pub encryption_version: u32,   // Version for future crypto upgrades
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Wallet data structure (before encryption)
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletData {
    pub name: String,
    pub keypair: QuantumKeyPair,
    pub mnemonic: Option<String>,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Keystore manager for handling encrypted wallet storage
pub struct Keystore {
    storage_path: std::path::PathBuf,
}

impl Keystore {
    /// Create a new keystore instance
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Self {
        Self {
            storage_path: storage_path.as_ref().to_path_buf(),
        }
    }

    /// Save an encrypted wallet to disk
    pub fn save_wallet(&self, wallet: &EncryptedWallet) -> Result<()> {
        let wallet_file = self.storage_path.join(format!("{}.json", wallet.name));
        let wallet_json = serde_json::to_string_pretty(wallet)?;
        std::fs::write(wallet_file, wallet_json)?;
        Ok(())
    }

    /// Load an encrypted wallet from disk
    pub fn load_wallet(&self, name: &str) -> Result<Option<EncryptedWallet>> {
        let wallet_file = self.storage_path.join(format!("{}.json", name));

        if !wallet_file.exists() {
            return Ok(None);
        }

        let wallet_json = std::fs::read_to_string(wallet_file)?;
        let wallet: EncryptedWallet = serde_json::from_str(&wallet_json)?;
        Ok(Some(wallet))
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
                    wallets.push(name.to_string());
                }
            }
        }

        Ok(wallets)
    }

    /// Delete a wallet file
    pub fn delete_wallet(&self, name: &str) -> Result<bool> {
        let wallet_file = self.storage_path.join(format!("{}.json", name));

        if wallet_file.exists() {
            std::fs::remove_file(wallet_file)?;
            Ok(true)
        } else {
            Ok(false)
        }
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
        let aes_key = Key::<Aes256Gcm>::from_slice(&hash_bytes[..32]);
        let cipher = Aes256Gcm::new(aes_key);

        // 4. Generate nonce and encrypt the wallet data
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
        let serialized_data = serde_json::to_vec(data)?;
        let encrypted_data = cipher
            .encrypt(&nonce, serialized_data.as_ref())
            .map_err(|e| WalletError::Encryption(e.to_string()))?;

        Ok(EncryptedWallet {
            name: data.name.clone(),
            address: data.keypair.to_account_id_ss58check(), // Store public address
            encrypted_data,
            kyber_ciphertext: vec![], // Reserved for future ML-KEM implementation
            kyber_public_key: vec![], // Reserved for future ML-KEM implementation
            argon2_salt: argon2_salt.to_vec(),
            argon2_params: password_hash.to_string(),
            aes_nonce: nonce.to_vec(),
            encryption_version: 1, // Version 1: Argon2 + AES-256-GCM (quantum-safe)
            created_at: chrono::Utc::now(),
        })
    }

    /// Decrypt wallet data using quantum-safe decryption
    pub fn decrypt_wallet_data(
        &self,
        encrypted: &EncryptedWallet,
        password: &str,
    ) -> Result<WalletData> {
        // 1. Verify password using stored Argon2 hash
        let argon2 = Argon2::default();
        let password_hash = PasswordHash::new(&encrypted.argon2_params)
            .map_err(|_| WalletError::InvalidPassword)?;

        argon2
            .verify_password(password.as_bytes(), &password_hash)
            .map_err(|_| WalletError::InvalidPassword)?;

        // 2. Derive AES key from verified password hash
        let hash_bytes = password_hash.hash.as_ref().unwrap().as_bytes();
        let aes_key = Key::<Aes256Gcm>::from_slice(&hash_bytes[..32]);
        let cipher = Aes256Gcm::new(aes_key);

        // 3. Decrypt the data
        let nonce = Nonce::from_slice(&encrypted.aes_nonce);
        let decrypted_data = cipher
            .decrypt(nonce, encrypted.encrypted_data.as_ref())
            .map_err(|_| WalletError::Decryption)?;

        // 4. Deserialize the wallet data
        let wallet_data: WalletData = serde_json::from_slice(&decrypted_data)?;

        Ok(wallet_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dilithium_crypto::{crystal_alice, crystal_charlie, dilithium_bob};
    use rusty_crystals_dilithium::ml_dsa_87::Keypair;
    use tempfile::TempDir;

    #[test]
    fn test_quantum_keypair_from_dilithium_keypair() {
        // Generate a test keypair
        let entropy = [1u8; 32];
        let dilithium_keypair = Keypair::generate(Some(&entropy));

        // Convert to QuantumKeyPair
        let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

        // Verify the conversion
        assert_eq!(
            quantum_keypair.public_key,
            dilithium_keypair.public.to_bytes().to_vec()
        );
        assert_eq!(
            quantum_keypair.private_key,
            dilithium_keypair.secret.to_bytes().to_vec()
        );
    }

    #[test]
    fn test_quantum_keypair_to_dilithium_keypair_roundtrip() {
        // Generate a test keypair
        let entropy = [2u8; 32];
        let original_keypair = Keypair::generate(Some(&entropy));

        // Convert to QuantumKeyPair and back
        let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&original_keypair);
        let converted_keypair = quantum_keypair
            .to_dilithium_keypair()
            .expect("Conversion should succeed");

        // Verify round-trip conversion preserves data
        assert_eq!(
            original_keypair.public.to_bytes(),
            converted_keypair.public.to_bytes()
        );
        assert_eq!(
            original_keypair.secret.to_bytes(),
            converted_keypair.secret.to_bytes()
        );
    }

    #[test]
    fn test_quantum_keypair_from_resonance_pair() {
        // Test with crystal_alice
        let resonance_pair = crystal_alice();
        let quantum_keypair = QuantumKeyPair::from_resonance_pair(&resonance_pair);

        // Verify the conversion
        assert_eq!(
            quantum_keypair.public_key,
            resonance_pair.public.as_ref().to_vec()
        );
        assert_eq!(
            quantum_keypair.private_key,
            resonance_pair.secret.as_ref().to_vec()
        );
    }

    #[test]
    fn test_quantum_keypair_to_resonance_pair_roundtrip() {
        // Test with crystal_bob
        let original_pair = dilithium_bob();
        let quantum_keypair = QuantumKeyPair::from_resonance_pair(&original_pair);
        let converted_pair = quantum_keypair
            .to_resonance_pair()
            .expect("Conversion should succeed");

        // Verify round-trip conversion preserves data
        assert_eq!(
            original_pair.public.as_ref(),
            converted_pair.public.as_ref()
        );
        assert_eq!(
            original_pair.secret.as_ref(),
            converted_pair.secret.as_ref()
        );
    }

    #[test]
    fn test_quantum_keypair_address_generation() {
        // Test with known test keypairs
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

            // Verify address format
            assert!(
                ss58_address.starts_with("5"),
                "SS58 address for {} should start with 5",
                name
            );
            assert!(
                ss58_address.len() >= 47,
                "SS58 address for {} should be at least 47 characters",
                name
            );

            // Verify consistency between methods
            assert_eq!(
                account_id.to_ss58check(),
                ss58_address,
                "Address methods should be consistent for {}",
                name
            );

            // Verify it matches the direct DilithiumPair method
            let expected_address = resonance_pair.public().into_account().to_ss58check();
            assert_eq!(
                ss58_address, expected_address,
                "Address should match DilithiumPair method for {}",
                name
            );
        }
    }

    #[test]
    fn test_ss58_to_account_id_conversion() {
        // Test with known addresses
        let test_cases = vec![
            crystal_alice().public().into_account().to_ss58check(),
            dilithium_bob().public().into_account().to_ss58check(),
            crystal_charlie().public().into_account().to_ss58check(),
        ];

        for ss58_address in test_cases {
            // Convert SS58 to account ID bytes
            let account_bytes = QuantumKeyPair::ss58_to_account_id(&ss58_address);

            // Verify length (AccountId32 should be 32 bytes)
            assert_eq!(account_bytes.len(), 32, "Account ID should be 32 bytes");

            // Convert back to SS58 and verify round-trip
            let account_id =
                AccountId32::from_slice(&account_bytes).expect("Should create valid AccountId32");
            let round_trip_address = account_id.to_ss58check();
            assert_eq!(
                ss58_address, round_trip_address,
                "Round-trip conversion should preserve address"
            );
        }
    }

    #[test]
    fn test_address_consistency_across_conversions() {
        // Start with a Dilithium keypair
        let entropy = [3u8; 32];
        let dilithium_keypair = Keypair::generate(Some(&entropy));

        // Convert through different paths
        let quantum_from_dilithium = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);
        let resonance_from_quantum = quantum_from_dilithium
            .to_resonance_pair()
            .expect("Should convert");
        let quantum_from_resonance = QuantumKeyPair::from_resonance_pair(&resonance_from_quantum);

        // All should generate the same address
        let addr1 = quantum_from_dilithium.to_account_id_ss58check();
        let addr2 = quantum_from_resonance.to_account_id_ss58check();
        let addr3 = resonance_from_quantum
            .public()
            .into_account()
            .to_ss58check();

        assert_eq!(
            addr1, addr2,
            "Addresses should be consistent across conversion paths"
        );
        assert_eq!(
            addr2, addr3,
            "Address should match direct DilithiumPair calculation"
        );
    }

    #[test]
    fn test_known_test_wallet_addresses() {
        // Test that our test wallets generate expected addresses
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
        assert_ne!(
            alice_addr, bob_addr,
            "Alice and Bob should have different addresses"
        );
        assert_ne!(
            bob_addr, charlie_addr,
            "Bob and Charlie should have different addresses"
        );
        assert_ne!(
            alice_addr, charlie_addr,
            "Alice and Charlie should have different addresses"
        );

        // All should be valid SS58 addresses
        assert!(
            alice_addr.starts_with("5"),
            "Alice address should be valid SS58"
        );
        assert!(
            bob_addr.starts_with("5"),
            "Bob address should be valid SS58"
        );
        assert!(
            charlie_addr.starts_with("5"),
            "Charlie address should be valid SS58"
        );

        println!("Test wallet addresses:");
        println!("  Alice:   {}", alice_addr);
        println!("  Bob:     {}", bob_addr);
        println!("  Charlie: {}", charlie_addr);
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
            assert!(
                result.is_err(),
                "Should panic on invalid address: {}",
                invalid_addr
            );
        }
    }

    #[test]
    fn test_stored_wallet_address_generation() {
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
            metadata,
        };

        // Test that we can generate address from the stored keypair
        let result = std::panic::catch_unwind(|| wallet_data.keypair.to_account_id_ss58check());

        match result {
            Ok(address) => {
                println!("✅ Address generation successful: {}", address);
                // Verify it matches the expected address
                let expected = alice_pair.public().into_account().to_ss58check();
                assert_eq!(
                    address, expected,
                    "Stored wallet should generate correct address"
                );
            }
            Err(_) => {
                panic!("❌ Address generation failed - this is the bug we need to fix!");
            }
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
            metadata,
        };

        // Encrypt the wallet (like developer wallets use empty password)
        let encrypted_wallet = keystore
            .encrypt_wallet_data(&wallet_data, "")
            .expect("Encryption should succeed");

        // Save and reload the wallet
        keystore
            .save_wallet(&encrypted_wallet)
            .expect("Save should succeed");
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
                println!(
                    "✅ Encrypted wallet address generation successful: {}",
                    address
                );
                // Verify it matches the expected address
                let expected = alice_pair.public().into_account().to_ss58check();
                assert_eq!(
                    address, expected,
                    "Decrypted wallet should generate correct address"
                );
            }
            Err(_) => {
                panic!("❌ Encrypted wallet address generation failed - this reproduces the send command bug!");
            }
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
            metadata,
        };

        // Encrypt and save the wallet (like developer wallets use empty password)
        let encrypted_wallet = keystore
            .encrypt_wallet_data(&wallet_data, "")
            .expect("Encryption should succeed");
        keystore
            .save_wallet(&encrypted_wallet)
            .expect("Save should succeed");

        // Now simulate what the send command does:
        // 1. Create a WalletManager and load the wallet with password
        use crate::wallet::WalletManager;
        let wallet_manager = WalletManager {
            wallets_dir: temp_dir.path().to_path_buf(),
        };
        let loaded_wallet_data = wallet_manager
            .load_wallet("crystal_alice", "")
            .expect("Should load wallet");

        // 2. Try to generate address from the loaded keypair (should work now)
        let result = std::panic::catch_unwind(|| {
            // The keypair is already decrypted, so we can use it directly
            loaded_wallet_data.keypair.to_account_id_ss58check()
        });

        match result {
            Ok(address) => {
                println!("✅ Send command flow works: {}", address);
                // If this passes, the bug is fixed
                let expected = alice_pair.public().into_account().to_ss58check();
                assert_eq!(
                    address, expected,
                    "Loaded wallet should generate correct address"
                );
            }
            Err(_) => {
                println!("❌ Send command flow failed - this reproduces the bug!");
                // This test should fail initially, proving we found the bug
                panic!(
                    "This test reproduces the send command bug - load_wallet returns dummy data!"
                );
            }
        }
    }

    #[test]
    fn test_keypair_data_integrity() {
        // Generate multiple keypairs and verify they maintain data integrity
        for i in 0..5 {
            let entropy = [i as u8; 32];
            let dilithium_keypair = Keypair::generate(Some(&entropy));
            let quantum_keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

            // Print actual key sizes for debugging (first iteration only)
            if i == 0 {
                println!(
                    "Actual public key size: {}",
                    quantum_keypair.public_key.len()
                );
                println!(
                    "Actual private key size: {}",
                    quantum_keypair.private_key.len()
                );
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
}
