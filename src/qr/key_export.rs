//! A cold wallet's NEAR public key, as published in a QR.
//!
//! A cold wallet record holds only an SS58 address, which is a hash of the
//! public key: it cannot be turned back into the 1952-byte ML-DSA-65 key that
//! NEAR needs to register an access key or to name the signer of a
//! transaction. The cold wallet app shows the key in a QR and this envelope is
//! what it shows — `NearPublicKeyExport` in quantus_sdk
//! (`lib/src/models/near_public_key_export.dart`). Keep the two in step: the
//! wallets write these four keys and no others.
//!
//! `address` lets the reader tie the key to a cold account it already knows,
//! and [`NearPublicKeyExport::decode`] refuses an export whose key does not
//! hash to that address, so a mismatched or forged QR cannot attach a stranger's
//! key to a wallet.
use crate::{
	error::{QuantusError, Result},
	near::protocol::PublicKey,
};
use qp_dilithium_crypto::types::Dilithium65Public;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, ByteArray, Ss58Codec};
use sp_runtime::traits::IdentifyAccount;

pub const NEAR_KEY_EXPORT_VERSION: u8 = 1;
pub const NEAR_KEY_EXPORT_KIND: &str = "near-public-key";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearPublicKeyExport {
	/// Quantus SS58 address of the account holding the key.
	pub address: String,
	/// The key in NEAR's `ml-dsa-65:<base58>` text form.
	pub near_public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
	v: u8,
	kind: String,
	address: String,
	near_public_key: String,
}

impl NearPublicKeyExport {
	/// Build an export, checking that `near_public_key` is an ML-DSA-65 key
	/// whose Quantus account is `address`.
	pub fn new(address: impl Into<String>, near_public_key: impl Into<String>) -> Result<Self> {
		let export = Self { address: address.into(), near_public_key: near_public_key.into() };
		export.public_key()?;
		Ok(export)
	}

	/// The bytes that go into the UR frames.
	pub fn encode(&self) -> Vec<u8> {
		let wire = Wire {
			v: NEAR_KEY_EXPORT_VERSION,
			kind: NEAR_KEY_EXPORT_KIND.to_string(),
			address: self.address.clone(),
			near_public_key: self.near_public_key.clone(),
		};
		serde_json::to_vec(&wire).expect("key export serialises")
	}

	/// Reads an export, rejecting anything that is not exactly one.
	pub fn decode(bytes: &[u8]) -> Result<Self> {
		let wire: Wire = serde_json::from_slice(bytes)
			.map_err(|e| QuantusError::Generic(format!("Not a NEAR public key export ({e})")))?;
		if wire.v != NEAR_KEY_EXPORT_VERSION {
			return Err(QuantusError::Generic(format!(
				"Unsupported NEAR public key export version: {} (this build reads \
				 {NEAR_KEY_EXPORT_VERSION})",
				wire.v
			)));
		}
		if wire.kind != NEAR_KEY_EXPORT_KIND {
			return Err(QuantusError::Generic(format!(
				"QR is a '{}', not a NEAR public key export",
				wire.kind
			)));
		}
		Self::new(wire.address, wire.near_public_key)
	}

	/// The exported key, verified to be ML-DSA-65 and to belong to `address`.
	pub fn public_key(&self) -> Result<PublicKey> {
		let key = PublicKey::parse(&self.near_public_key)?;
		let PublicKey::MlDsa65(bytes) = &key else {
			let scheme = key.to_near_string();
			let scheme = scheme.split_once(':').map(|(s, _)| s).unwrap_or_default();
			return Err(QuantusError::Generic(format!(
				"NEAR public key export carries a {scheme} key; only ML-DSA-65 keys belong to a \
				 Quantus account"
			)));
		};
		let public = Dilithium65Public::from_slice(bytes.as_slice()).map_err(|_| {
			QuantusError::Generic("NEAR public key export key is not a valid ML-DSA-65 key".into())
		})?;
		let derived: AccountId32 = public.into_account();
		let (claimed, _) =
			AccountId32::from_ss58check_with_version(&self.address).map_err(|e| {
				QuantusError::Generic(format!(
					"NEAR public key export address '{}' is not a valid SS58 address: {e:?}",
					self.address
				))
			})?;
		if derived != claimed {
			return Err(QuantusError::Generic(format!(
				"NEAR public key export is inconsistent: the key belongs to {}, not to {}",
				derived
					.to_ss58check_with_version(crate::cli::address_format::quantus_ss58_format()),
				self.address
			)));
		}
		Ok(key)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use qp_dilithium_crypto::types::Dilithium65Pair;
	use sp_core::Pair;

	fn near_key(seed: u8) -> (String, String) {
		let pair = Dilithium65Pair::from_seed(&[seed; 32]).expect("seed");
		let account: AccountId32 = pair.public().into_account();
		let address =
			account.to_ss58check_with_version(crate::cli::address_format::quantus_ss58_format());
		let key = PublicKey::from_ml_dsa_65_bytes(pair.public().as_slice())
			.expect("1952 bytes")
			.to_near_string();
		(address, key)
	}

	fn export() -> NearPublicKeyExport {
		let (address, key) = near_key(7);
		NearPublicKeyExport::new(address, key).expect("consistent export")
	}

	#[test]
	fn round_trips_through_the_wire_format() {
		let export = export();
		let decoded = NearPublicKeyExport::decode(&export.encode()).expect("decodes");
		assert_eq!(decoded, export);
	}

	#[test]
	fn wire_format_matches_the_sdk() {
		let export = export();
		let json: serde_json::Value = serde_json::from_slice(&export.encode()).expect("json");
		let object = json.as_object().expect("object");
		let mut keys: Vec<_> = object.keys().cloned().collect();
		keys.sort();
		assert_eq!(keys, ["address", "kind", "near_public_key", "v"]);
		assert_eq!(object["v"], 1);
		assert_eq!(object["kind"], "near-public-key");
		assert!(object["near_public_key"].as_str().unwrap().starts_with("ml-dsa-65:"));
	}

	#[test]
	fn rejects_unknown_keys_version_and_kind() {
		let export = export();
		let mut json: serde_json::Value = serde_json::from_slice(&export.encode()).unwrap();

		json["extra"] = serde_json::json!(1);
		assert!(NearPublicKeyExport::decode(json.to_string().as_bytes()).is_err());
		json.as_object_mut().unwrap().remove("extra");

		json["v"] = serde_json::json!(2);
		let err = NearPublicKeyExport::decode(json.to_string().as_bytes()).unwrap_err();
		assert!(err.to_string().contains("version"), "{err}");
		json["v"] = serde_json::json!(1);

		json["kind"] = serde_json::json!("quantus-address");
		let err = NearPublicKeyExport::decode(json.to_string().as_bytes()).unwrap_err();
		assert!(err.to_string().contains("not a NEAR public key export"), "{err}");
	}

	#[test]
	fn rejects_a_signing_request() {
		let request = crate::qr::SignRequest::new("qz...", vec![1, 2, 3]).encode();
		assert!(NearPublicKeyExport::decode(&request).is_err());
	}

	#[test]
	fn rejects_a_key_that_does_not_belong_to_the_address() {
		let export = export();
		let (_, other_key) = near_key(8);
		let err = NearPublicKeyExport::new(export.address, other_key).unwrap_err();
		assert!(err.to_string().contains("inconsistent"), "{err}");
	}

	#[test]
	fn rejects_a_non_ml_dsa_key() {
		let export = export();
		let ed = format!("ed25519:{}", bs58::encode([1u8; 32]).into_string());
		let err = NearPublicKeyExport::new(export.address, ed).unwrap_err();
		assert!(err.to_string().contains("ML-DSA-65"), "{err}");
	}

	#[test]
	fn rejects_a_bad_address() {
		let export = export();
		let err = NearPublicKeyExport::new("not-an-address", export.near_public_key).unwrap_err();
		assert!(err.to_string().contains("SS58"), "{err}");
	}
}
