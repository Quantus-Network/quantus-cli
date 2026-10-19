//! NEAR transaction hashing and signing.
//!
//! NEAR signs the SHA-256 of the borsh-encoded transaction body. For
//! ML-DSA-65 that hash is the message of a *pure* FIPS 204 signature with an
//! empty context — the `[0x00, 0x00]` context prefix — which is exactly what
//! [`crate::chain::signing::sign_ml_dsa_65`] produces when passed `None`.
//! The wire carries the raw 3309-byte signature, without the public key
//! suffix Quantus extrinsics use.

use crate::{
	error::{QuantusError, Result},
	near::protocol::{
		PublicKey, Signature, SignedTransaction, Transaction, ML_DSA_65_SIGNATURE_LEN,
	},
};
use qp_dilithium_crypto::types::Dilithium65Pair;
use sha2::{Digest, Sha256};
use sp_core::Pair as _;
use std::path::Path;

/// SHA-256 of the borsh transaction body: what NEAR signs and verifies, and
/// the transaction id the RPC reports (base58).
pub fn transaction_hash(tx: &Transaction) -> Result<[u8; 32]> {
	let bytes = borsh::to_vec(tx)
		.map_err(|e| QuantusError::Generic(format!("borsh-encoding transaction: {e}")))?;
	Ok(Sha256::digest(&bytes).into())
}

/// Sign with the Quantus wallet's ML-DSA-65 key. `tx.public_key` must be this
/// key, or the chain would reject the signature against the declared key.
pub fn sign_transaction_ml_dsa_65(
	tx: Transaction,
	pair: &Dilithium65Pair,
) -> Result<SignedTransaction> {
	let expected = PublicKey::from_ml_dsa_65_bytes(pair.public().as_ref())?;
	if tx.public_key != expected {
		return Err(QuantusError::Generic(
			"transaction.public_key is not the signing wallet's ML-DSA-65 key".to_string(),
		));
	}

	let hash = transaction_hash(&tx)?;
	let swp = crate::chain::signing::sign_ml_dsa_65(pair, &hash, None);
	let signature: [u8; ML_DSA_65_SIGNATURE_LEN] = swp
		.signature()
		.as_ref()
		.try_into()
		.expect("ML-DSA-65 signature length is fixed");

	Ok(SignedTransaction { transaction: tx, signature: Signature::MlDsa65(Box::new(signature)) })
}

/// Sign with a classical NEAR ed25519 key (the parent account in
/// `create-account`).
pub fn sign_transaction_ed25519(
	tx: Transaction,
	key: &ed25519_dalek::SigningKey,
) -> Result<SignedTransaction> {
	if tx.public_key != PublicKey::Ed25519(key.verifying_key().to_bytes()) {
		return Err(QuantusError::Generic(
			"transaction.public_key is not the signing ed25519 key".to_string(),
		));
	}

	let hash = transaction_hash(&tx)?;
	use ed25519_dalek::Signer;
	let signature = key.sign(&hash);
	Ok(SignedTransaction { transaction: tx, signature: Signature::Ed25519(signature.to_bytes()) })
}

/// A classical NEAR account credential, as written by near-cli to
/// `~/.near-credentials/<network>/<account>.json`.
pub struct NearCredentials {
	pub account_id: String,
	pub public_key: PublicKey,
	pub signing_key: ed25519_dalek::SigningKey,
}

/// Load a near-cli credentials file: JSON with `account_id` and an
/// `ed25519:<base58>` private key under `private_key` (or `secret_key`).
/// The 64-byte keypair form carries the public half, which
/// `from_keypair_bytes` cross-checks against the secret.
pub fn load_credentials(path: &Path) -> Result<NearCredentials> {
	let text = std::fs::read_to_string(path).map_err(|e| {
		QuantusError::Generic(format!("reading credentials {}: {e}", path.display()))
	})?;
	let json: serde_json::Value = serde_json::from_str(&text)
		.map_err(|e| QuantusError::Generic(format!("credentials JSON: {e}")))?;

	let account_id = json
		.get("account_id")
		.and_then(|v| v.as_str())
		.ok_or_else(|| QuantusError::Generic("credentials file has no account_id".to_string()))?
		.to_string();

	let private_key = json
		.get("private_key")
		.or_else(|| json.get("secret_key"))
		.and_then(|v| v.as_str())
		.ok_or_else(|| {
			QuantusError::Generic("credentials file has no private_key/secret_key".to_string())
		})?;

	let encoded = private_key.strip_prefix("ed25519:").ok_or_else(|| {
		QuantusError::Generic(
			"only ed25519 parent credentials are supported (private_key must start with \
			 'ed25519:')"
				.to_string(),
		)
	})?;
	let key_bytes = bs58::decode(encoded)
		.into_vec()
		.map_err(|e| QuantusError::Generic(format!("private key base58: {e}")))?;

	let signing_key = match key_bytes.len() {
		64 => {
			let keypair: [u8; 64] = key_bytes.as_slice().try_into().expect("length checked");
			ed25519_dalek::SigningKey::from_keypair_bytes(&keypair).map_err(|e| {
				QuantusError::Generic(format!(
					"credentials private key is inconsistent (public half does not match): {e}"
				))
			})?
		},
		32 => {
			let seed: [u8; 32] = key_bytes.as_slice().try_into().expect("length checked");
			ed25519_dalek::SigningKey::from_bytes(&seed)
		},
		other =>
			return Err(QuantusError::Generic(format!(
				"ed25519 private key must be 32 or 64 bytes, got {other}"
			))),
	};

	let public_key = PublicKey::Ed25519(signing_key.verifying_key().to_bytes());
	if let Some(stated) = json.get("public_key").and_then(|v| v.as_str()) {
		let stated = PublicKey::parse(stated)?;
		if stated != public_key {
			return Err(QuantusError::Generic(
				"credentials public_key does not match the private key".to_string(),
			));
		}
	}

	Ok(NearCredentials { account_id, public_key, signing_key })
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::near::protocol::{Action, TransferAction};

	fn test_tx(public_key: PublicKey) -> Transaction {
		Transaction {
			signer_id: "alice.testnet".to_string(),
			public_key,
			nonce: 5,
			receiver_id: "bob.testnet".to_string(),
			block_hash: [9; 32],
			actions: vec![Action::Transfer(TransferAction { deposit: 10u128.pow(24) })],
		}
	}

	#[test]
	fn ml_dsa_65_signature_is_pure_fips204_over_the_tx_hash() {
		let pair = Dilithium65Pair::from_seed(&[3u8; 32]).expect("valid seed");
		let public = PublicKey::from_ml_dsa_65_bytes(pair.public().as_ref()).unwrap();
		let tx = test_tx(public);
		let hash = transaction_hash(&tx).unwrap();

		let signed = sign_transaction_ml_dsa_65(tx, &pair).unwrap();
		let Signature::MlDsa65(sig) = &signed.signature else {
			panic!("must sign as ml-dsa-65");
		};

		// Empty-context pure ML-DSA over the 32-byte hash, verifiable with the
		// upstream verifier exactly as NEAR's runtime does it.
		let verifier =
			qp_rusty_crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(pair.public().as_ref())
				.unwrap();
		assert!(verifier.verify(&hash, sig.as_ref(), None));
		assert!(!verifier.verify(&hash, sig.as_ref(), Some(b"QUANTUS_EXTRINSIC")));

		// Signing under the wrong declared key is refused.
		let other = Dilithium65Pair::from_seed(&[4u8; 32]).expect("valid seed");
		let tx = test_tx(PublicKey::from_ml_dsa_65_bytes(other.public().as_ref()).unwrap());
		assert!(sign_transaction_ml_dsa_65(tx, &pair).is_err());
	}

	#[test]
	fn ed25519_signature_verifies_over_the_tx_hash() {
		let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
		let tx = test_tx(PublicKey::Ed25519(key.verifying_key().to_bytes()));
		let hash = transaction_hash(&tx).unwrap();

		let signed = sign_transaction_ed25519(tx, &key).unwrap();
		let Signature::Ed25519(sig) = &signed.signature else {
			panic!("must sign as ed25519");
		};

		use ed25519_dalek::Verifier;
		let sig = ed25519_dalek::Signature::from_bytes(sig);
		assert!(key.verifying_key().verify(&hash, &sig).is_ok());
	}

	#[test]
	fn credentials_file_roundtrip() {
		let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
		let mut keypair = key.to_bytes().to_vec();
		keypair.extend(key.verifying_key().to_bytes());

		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("alice.testnet.json");
		std::fs::write(
			&path,
			serde_json::json!({
				"account_id": "alice.testnet",
				"public_key": format!("ed25519:{}", bs58::encode(key.verifying_key().to_bytes()).into_string()),
				"private_key": format!("ed25519:{}", bs58::encode(&keypair).into_string()),
			})
			.to_string(),
		)
		.unwrap();

		let creds = load_credentials(&path).unwrap();
		assert_eq!(creds.account_id, "alice.testnet");
		assert_eq!(creds.public_key, PublicKey::Ed25519(key.verifying_key().to_bytes()));

		// A mismatched public_key field is refused.
		std::fs::write(
			&path,
			serde_json::json!({
				"account_id": "alice.testnet",
				"public_key": format!("ed25519:{}", bs58::encode([9u8; 32]).into_string()),
				"private_key": format!("ed25519:{}", bs58::encode(&keypair).into_string()),
			})
			.to_string(),
		)
		.unwrap();
		assert!(load_credentials(&path).is_err());
	}
}
