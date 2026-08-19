//! The envelope a signing payload travels in.
//!
//! A payload on its own says nothing about whose key it belongs to: a signer
//! holding several accounts cannot tell which one the request wants, and one
//! holding none of them cannot tell that it holds the wrong key. The envelope
//! names the account, and every wallet refuses a request for an account it does
//! not hold.
//!
//! The JSON is the wire format the Quantus mobile app, the cold wallet app and
//! the Keystone firmware read — `SigningRequest` in quantus_sdk
//! (`lib/src/models/signing_request.dart`). Keep the two in step: the wallets
//! accept these three keys and no others, and refuse any other version.
use crate::error::{QuantusError, Result};
use serde::{Deserialize, Serialize};

/// Envelope version the wallets accept.
pub const SIGN_REQUEST_VERSION: u8 = 1;

/// Largest payload a wallet will read, matching `maxPayloadBytes` in the SDK.
const MAX_PAYLOAD_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
	/// SS58 address of the account that must sign.
	pub signer: String,
	/// The SCALE signing payload: call plus signed extensions.
	pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Wire {
	v: u8,
	signer: String,
	payload: String,
}

impl SignRequest {
	pub fn new(signer: impl Into<String>, payload: Vec<u8>) -> Self {
		Self { signer: signer.into(), payload }
	}

	/// The bytes that go into the UR frames.
	pub fn encode(&self) -> Vec<u8> {
		let wire = Wire {
			v: SIGN_REQUEST_VERSION,
			signer: self.signer.clone(),
			payload: format!("0x{}", hex::encode(&self.payload)),
		};
		// The struct has no field that can fail to serialise.
		serde_json::to_vec(&wire).expect("sign request serialises")
	}

	/// Reads an envelope, rejecting anything that is not exactly one.
	///
	/// Deliberately as strict as the wallets: a request that cannot be read in
	/// full is refused rather than signed on a guess about what it meant.
	pub fn decode(bytes: &[u8]) -> Result<Self> {
		let wire: Wire = serde_json::from_slice(bytes).map_err(|e| {
			QuantusError::Generic(format!(
				"Not a signing request. A wallet built before the request envelope sends a bare \
				 payload, which cannot say which account it is for ({e})"
			))
		})?;

		if wire.v != SIGN_REQUEST_VERSION {
			return Err(QuantusError::Generic(format!(
				"Unsupported signing request version: {} (this build reads {SIGN_REQUEST_VERSION})",
				wire.v
			)));
		}

		let hex_payload = wire.payload.strip_prefix("0x").ok_or_else(|| {
			QuantusError::Generic("Signing request payload is not 0x hex".to_string())
		})?;
		let payload = hex::decode(hex_payload).map_err(|e| {
			QuantusError::Generic(format!("Signing request payload is not hex: {e}"))
		})?;

		if payload.is_empty() {
			return Err(QuantusError::Generic("Signing request payload is empty".to_string()));
		}
		if payload.len() > MAX_PAYLOAD_BYTES {
			return Err(QuantusError::Generic(format!(
				"Signing request payload too large: {} bytes",
				payload.len()
			)));
		}

		Ok(Self { signer: wire.signer, payload })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const ADDRESS: &str = "qznQKhufTDfU3szAzfgCny7wMhxUN3qjEqneiRUNgC7MjSDyG";

	#[test]
	fn round_trips_through_the_wire_format() {
		let request = SignRequest::new(ADDRESS, vec![0x02, 0x00, 0xff]);

		assert_eq!(SignRequest::decode(&request.encode()).unwrap(), request);
	}

	#[test]
	fn carries_exactly_the_keys_the_wallets_read() {
		let encoded = SignRequest::new(ADDRESS, vec![0xab]).encode();
		let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();

		assert_eq!(json["v"], 1);
		assert_eq!(json["signer"], ADDRESS);
		assert_eq!(json["payload"], "0xab");
		assert_eq!(json.as_object().unwrap().len(), 3, "a wallet refuses any other key set");
	}

	#[test]
	fn refuses_a_bare_payload() {
		// What this CLI used to send, and what a wallet now refuses because it
		// names no account.
		let bare = vec![0x02, 0x00, 0x01, 0x02];

		assert!(SignRequest::decode(&bare).is_err());
	}

	#[test]
	fn refuses_a_version_it_does_not_read() {
		let wire = serde_json::json!({ "v": 2, "signer": ADDRESS, "payload": "0xab" });

		let error = SignRequest::decode(wire.to_string().as_bytes()).unwrap_err().to_string();
		assert!(error.contains("version"), "unexpected error: {error}");
	}

	#[test]
	fn refuses_a_payload_that_is_not_hex_bytes() {
		for payload in ["", "0x", "abcd", "0xnothex"] {
			let wire = serde_json::json!({ "v": 1, "signer": ADDRESS, "payload": payload });
			assert!(
				SignRequest::decode(wire.to_string().as_bytes()).is_err(),
				"payload {payload:?} was accepted"
			);
		}
	}

	#[test]
	fn refuses_a_payload_past_the_size_a_wallet_reads() {
		let wire = serde_json::json!({
			"v": 1,
			"signer": ADDRESS,
			"payload": format!("0x{}", hex::encode(vec![0u8; MAX_PAYLOAD_BYTES + 1])),
		});

		assert!(SignRequest::decode(wire.to_string().as_bytes()).is_err());
	}
}
