//! NEAR wire types, borsh-encoded exactly as nearcore defines them.
//!
//! Layout is consensus-critical: enum variants are borsh u8 tags in
//! declaration order, so the unused variants below hold tag positions and
//! must stay. Mirrors `core/crypto/src/signature.rs` and
//! `core/primitives/src/transaction.rs` in nearcore (the unversioned
//! `TransactionV0` layout, which is what wallets produce).
//!
//! ML-DSA-65 keys ride in transactions as the full 1952-byte public key
//! (`ml-dsa-65:` text form). On-chain, NEAR stores only a SHA3-256 handle of
//! the key, and access-key lists return it under the `ml-dsa-65-hash:` text
//! form; [`PublicKey::handle_string`] computes it for reconciliation.

use crate::error::{QuantusError, Result};
use borsh::BorshSerialize;

pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const SECP256K1_PUBLIC_KEY_LEN: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;

/// Domain-separation tag nearcore hashes before the raw public key to form
/// the on-trie access-key handle (`near_crypto::hash_domain`).
pub const ML_DSA_65_HANDLE_DOMAIN_TAG: &[u8] = b"near:ml-dsa-65-pubkey-hash:v1";

/// A public key as carried in transactions and actions.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum PublicKey {
	Ed25519([u8; ED25519_PUBLIC_KEY_LEN]),
	Secp256k1(Box<[u8; SECP256K1_PUBLIC_KEY_LEN]>),
	MlDsa65(Box<[u8; ML_DSA_65_PUBLIC_KEY_LEN]>),
}

impl PublicKey {
	pub fn from_ml_dsa_65_bytes(bytes: &[u8]) -> Result<Self> {
		let key: [u8; ML_DSA_65_PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| {
			QuantusError::Generic(format!(
				"ML-DSA-65 public key must be {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {}",
				bytes.len()
			))
		})?;
		Ok(PublicKey::MlDsa65(Box::new(key)))
	}

	/// The `<scheme>:<base58>` text form NEAR RPC and tooling use.
	pub fn to_near_string(&self) -> String {
		match self {
			PublicKey::Ed25519(bytes) => format!("ed25519:{}", bs58::encode(bytes).into_string()),
			PublicKey::Secp256k1(bytes) =>
				format!("secp256k1:{}", bs58::encode(bytes.as_ref()).into_string()),
			PublicKey::MlDsa65(bytes) =>
				format!("ml-dsa-65:{}", bs58::encode(bytes.as_ref()).into_string()),
		}
	}

	/// Parse the `<scheme>:<base58>` text form.
	pub fn parse(s: &str) -> Result<Self> {
		let (scheme, data) = s.split_once(':').ok_or_else(|| {
			QuantusError::Generic(format!("public key '{s}' has no scheme prefix"))
		})?;
		let bytes = bs58::decode(data)
			.into_vec()
			.map_err(|e| QuantusError::Generic(format!("public key base58: {e}")))?;
		match scheme {
			"ed25519" => Ok(PublicKey::Ed25519(bytes.as_slice().try_into().map_err(|_| {
				QuantusError::Generic(format!(
					"ed25519 public key must be {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
					bytes.len()
				))
			})?)),
			"secp256k1" => {
				let key: [u8; SECP256K1_PUBLIC_KEY_LEN] =
					bytes.as_slice().try_into().map_err(|_| {
						QuantusError::Generic(format!(
							"secp256k1 public key must be {SECP256K1_PUBLIC_KEY_LEN} bytes, got {}",
							bytes.len()
						))
					})?;
				Ok(PublicKey::Secp256k1(Box::new(key)))
			},
			"ml-dsa-65" => Self::from_ml_dsa_65_bytes(&bytes),
			other => Err(QuantusError::Generic(format!("unsupported key scheme '{other}'"))),
		}
	}

	/// SHA3-256 handle of an ML-DSA-65 key: what NEAR stores on-chain and
	/// what `view_access_key_list` returns for these keys.
	pub fn ml_dsa_65_handle(&self) -> Option<[u8; 32]> {
		let PublicKey::MlDsa65(bytes) = self else {
			return None;
		};
		use sha3::{Digest, Sha3_256};
		let mut hasher = Sha3_256::new();
		hasher.update(ML_DSA_65_HANDLE_DOMAIN_TAG);
		hasher.update(bytes.as_ref());
		Some(hasher.finalize().into())
	}

	/// The `ml-dsa-65-hash:<base58>` text form of [`Self::ml_dsa_65_handle`].
	pub fn handle_string(&self) -> Option<String> {
		self.ml_dsa_65_handle()
			.map(|h| format!("ml-dsa-65-hash:{}", bs58::encode(h).into_string()))
	}
}

/// A transaction signature. Same tag space as [`PublicKey`].
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum Signature {
	Ed25519([u8; ED25519_SIGNATURE_LEN]),
	/// Tag position only; this CLI never signs secp256k1.
	#[allow(dead_code)]
	Secp256k1(Box<[u8; 65]>),
	MlDsa65(Box<[u8; ML_DSA_65_SIGNATURE_LEN]>),
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct AccessKey {
	/// Starting nonce for the key. 0 for a key on a brand-new account.
	pub nonce: u64,
	pub permission: AccessKeyPermission,
}

impl AccessKey {
	pub fn full_access() -> Self {
		AccessKey { nonce: 0, permission: AccessKeyPermission::FullAccess }
	}
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum AccessKeyPermission {
	/// Tag position only; this CLI adds full-access keys.
	#[allow(dead_code)]
	FunctionCall(FunctionCallPermission),
	FullAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct FunctionCallPermission {
	/// Allowance in yoctoNEAR the key may spend on gas; `None` = unlimited.
	pub allowance: Option<u128>,
	pub receiver_id: String,
	pub method_names: Vec<String>,
}

/// A transaction action. Variant order fixes the borsh tags; only the ones
/// this CLI builds carry real payload types, but every position must exist.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum Action {
	CreateAccount,
	#[allow(dead_code)]
	DeployContract(DeployContractAction),
	FunctionCall(FunctionCallAction),
	Transfer(TransferAction),
	#[allow(dead_code)]
	Stake(StakeAction),
	AddKey(AddKeyAction),
	#[allow(dead_code)]
	DeleteKey(DeleteKeyAction),
	#[allow(dead_code)]
	DeleteAccount(DeleteAccountAction),
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct DeployContractAction {
	pub code: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct FunctionCallAction {
	pub method_name: String,
	pub args: Vec<u8>,
	pub gas: u64,
	pub deposit: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct TransferAction {
	/// Amount in yoctoNEAR (24 decimals).
	pub deposit: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct StakeAction {
	pub stake: u128,
	pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct AddKeyAction {
	pub public_key: PublicKey,
	pub access_key: AccessKey,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct DeleteKeyAction {
	pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct DeleteAccountAction {
	pub beneficiary_id: String,
}

/// The signable transaction body (nearcore `TransactionV0`).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct Transaction {
	pub signer_id: String,
	/// Key the signer signs with; full ML-DSA-65 key, never the hash form.
	pub public_key: PublicKey,
	/// Access-key nonce + 1 at submission time.
	pub nonce: u64,
	pub receiver_id: String,
	/// A recent block hash (transactions expire ~24h after it).
	pub block_hash: [u8; 32],
	pub actions: Vec<Action>,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct SignedTransaction {
	pub transaction: Transaction,
	pub signature: Signature,
}

/// NEAR uses 24 decimals (yoctoNEAR).
pub const NEAR_DECIMALS: u8 = 24;

/// Light client-side validation of a NEAR account id (the chain re-validates).
pub fn validate_account_id(account_id: &str) -> Result<()> {
	let valid_len = (2..=64).contains(&account_id.len());
	let valid_chars = account_id.split(['.', '_', '-']).all(|part| {
		!part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
	});
	if !valid_len || !valid_chars {
		return Err(QuantusError::Generic(format!(
			"'{account_id}' is not a valid NEAR account id (2-64 chars, lowercase alphanumerics \
			 separated by '.', '_' or '-')"
		)));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Hand-built borsh bytes pin the wire layout independent of the derive.
	#[test]
	fn transaction_borsh_layout_is_the_near_wire_format() {
		let tx = Transaction {
			signer_id: "alice.testnet".to_string(),
			public_key: PublicKey::Ed25519([0x11; 32]),
			nonce: 42,
			receiver_id: "bob.testnet".to_string(),
			block_hash: [0x22; 32],
			actions: vec![
				Action::CreateAccount,
				Action::Transfer(TransferAction { deposit: 1_000_000 }),
				Action::AddKey(AddKeyAction {
					public_key: PublicKey::MlDsa65(Box::new([0x33; ML_DSA_65_PUBLIC_KEY_LEN])),
					access_key: AccessKey::full_access(),
				}),
			],
		};

		let mut expected: Vec<u8> = Vec::new();
		expected.extend(13u32.to_le_bytes()); // signer_id length
		expected.extend(b"alice.testnet");
		expected.push(0); // PublicKey tag: ed25519
		expected.extend([0x11; 32]);
		expected.extend(42u64.to_le_bytes()); // nonce
		expected.extend(11u32.to_le_bytes()); // receiver_id length
		expected.extend(b"bob.testnet");
		expected.extend([0x22; 32]); // block_hash (fixed array: no length prefix)
		expected.extend(3u32.to_le_bytes()); // actions vec length
		expected.push(0); // Action tag: CreateAccount (no payload)
		expected.push(3); // Action tag: Transfer
		expected.extend(1_000_000u128.to_le_bytes());
		expected.push(5); // Action tag: AddKey
		expected.push(2); // PublicKey tag: ml-dsa-65
		expected.extend([0x33; ML_DSA_65_PUBLIC_KEY_LEN]);
		expected.extend(0u64.to_le_bytes()); // AccessKey nonce
		expected.push(1); // AccessKeyPermission tag: FullAccess

		assert_eq!(borsh::to_vec(&tx).unwrap(), expected);

		// Independently computed golden (Python hashlib over the same bytes).
		assert_eq!(
			hex::encode(crate::near::sign::transaction_hash(&tx).unwrap()),
			"c2a1f5de00a9538f35cfc24316fc8748315b837299153eafc47abde7c187b92e"
		);
	}

	#[test]
	fn function_call_action_borsh_layout() {
		let args = br#"{"id":0,"action":"VoteApprove"}"#.to_vec();
		let action = Action::FunctionCall(FunctionCallAction {
			method_name: "act_proposal".to_string(),
			args: args.clone(),
			gas: 300_000_000_000_000,
			deposit: 1,
		});

		let mut expected: Vec<u8> = Vec::new();
		expected.push(2); // Action tag: FunctionCall
		expected.extend(12u32.to_le_bytes()); // method_name length
		expected.extend(b"act_proposal");
		expected.extend((args.len() as u32).to_le_bytes());
		expected.extend(&args);
		expected.extend(300_000_000_000_000u64.to_le_bytes()); // gas
		expected.extend(1u128.to_le_bytes()); // deposit

		assert_eq!(borsh::to_vec(&action).unwrap(), expected);
	}

	#[test]
	fn signed_transaction_appends_the_signature() {
		let tx = Transaction {
			signer_id: "a.testnet".to_string(),
			public_key: PublicKey::Ed25519([0; 32]),
			nonce: 1,
			receiver_id: "b.testnet".to_string(),
			block_hash: [0; 32],
			actions: vec![Action::Transfer(TransferAction { deposit: 1 })],
		};
		let tx_bytes = borsh::to_vec(&tx).unwrap();

		let signed = SignedTransaction {
			transaction: tx,
			signature: Signature::MlDsa65(Box::new([0x44; ML_DSA_65_SIGNATURE_LEN])),
		};
		let signed_bytes = borsh::to_vec(&signed).unwrap();

		assert_eq!(&signed_bytes[..tx_bytes.len()], &tx_bytes[..]);
		assert_eq!(signed_bytes[tx_bytes.len()], 2, "Signature tag: ml-dsa-65");
		assert_eq!(signed_bytes.len(), tx_bytes.len() + 1 + ML_DSA_65_SIGNATURE_LEN);
	}

	#[test]
	fn key_text_forms_roundtrip() {
		let ml = PublicKey::MlDsa65(Box::new([0x42; ML_DSA_65_PUBLIC_KEY_LEN]));
		let s = ml.to_near_string();
		assert!(s.starts_with("ml-dsa-65:"));
		assert_eq!(PublicKey::parse(&s).unwrap(), ml);

		let ed = PublicKey::Ed25519([7; 32]);
		let s = ed.to_near_string();
		assert!(s.starts_with("ed25519:"));
		assert_eq!(PublicKey::parse(&s).unwrap(), ed);

		assert!(PublicKey::parse("ml-dsa-65-hash:11111111111111111111111111111111").is_err());
		assert!(PublicKey::parse("no-prefix").is_err());
	}

	#[test]
	fn handle_is_domain_separated_sha3_of_the_pubkey() {
		let key = PublicKey::MlDsa65(Box::new([0x42; ML_DSA_65_PUBLIC_KEY_LEN]));
		let handle = key.ml_dsa_65_handle().unwrap();

		// Independently computed golden (Python hashlib over tag ‖ pubkey).
		assert_eq!(
			hex::encode(handle),
			"0ef8ccba4bb1a8859f1cc3d17c4d9d35712b8ddedd3875906559c50f7dd86505"
		);

		use sha3::{Digest, Sha3_256};
		let mut plain = Sha3_256::new();
		plain.update([0x42; ML_DSA_65_PUBLIC_KEY_LEN]);
		let plain: [u8; 32] = plain.finalize().into();
		assert_ne!(handle, plain, "handle must hash the domain tag first");

		let s = key.handle_string().unwrap();
		assert!(s.starts_with("ml-dsa-65-hash:"));

		assert!(PublicKey::Ed25519([0; 32]).handle_string().is_none());
	}

	#[test]
	fn account_id_validation() {
		assert!(validate_account_id("alice.testnet").is_ok());
		assert!(validate_account_id("vault.alice.near").is_ok());
		assert!(validate_account_id("a-b_c.d").is_ok());
		assert!(validate_account_id("a").is_err());
		assert!(validate_account_id("Alice.testnet").is_err());
		assert!(validate_account_id("double..dot").is_err());
		assert!(validate_account_id(&"x".repeat(65)).is_err());
	}
}
