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
//!
//! Version 2 ([`NearSignRequest`]) carries a NEAR transaction instead of a
//! Substrate payload: `{v: 2, chain: "near", network, payload}`. There is no
//! `signer` field because the borsh transaction already names its signer
//! account and the exact public key that must sign; a device matches that key
//! against its own. Both versions travel in the same `ur:quantus-sign-request`
//! UR type, so wallets that only read v1 refuse v2 by version, as before.
use crate::error::{QuantusError, Result};
use serde::{Deserialize, Serialize};

/// Envelope version the wallets accept.
pub const SIGN_REQUEST_VERSION: u8 = 1;

/// Envelope version carrying a NEAR transaction.
pub const NEAR_SIGN_REQUEST_VERSION: u8 = 2;

/// Largest payload a wallet will read, matching `maxPayloadBytes` in the SDK.
/// Largest payload any client accepts in a signing request, v1 or v2. Shared
/// with the cold wallet app, so a request above it is refused on both sides.
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;

fn encode_payload(payload: &[u8]) -> String {
	format!("0x{}", hex::encode(payload))
}

fn decode_payload(payload: &str) -> Result<Vec<u8>> {
	let hex_payload = payload.strip_prefix("0x").ok_or_else(|| {
		QuantusError::Generic("Signing request payload is not 0x hex".to_string())
	})?;
	let payload = hex::decode(hex_payload)
		.map_err(|e| QuantusError::Generic(format!("Signing request payload is not hex: {e}")))?;

	if payload.is_empty() {
		return Err(QuantusError::Generic("Signing request payload is empty".to_string()));
	}
	if payload.len() > MAX_PAYLOAD_BYTES {
		return Err(QuantusError::Generic(format!(
			"Signing request payload too large: {} bytes",
			payload.len()
		)));
	}
	Ok(payload)
}

/// Reads only the version, so a decoder can pick the envelope to parse.
#[derive(Deserialize)]
struct VersionProbe {
	v: u8,
}

/// Any envelope this CLI reads, dispatched on `v`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnySignRequest {
	Quantus(SignRequest),
	Near(NearSignRequest),
}

impl AnySignRequest {
	pub fn decode(bytes: &[u8]) -> Result<Self> {
		let probe: VersionProbe = serde_json::from_slice(bytes).map_err(|e| {
			QuantusError::Generic(format!(
				"Not a signing request. A wallet built before the request envelope sends a bare \
				 payload, which cannot say which account it is for ({e})"
			))
		})?;
		match probe.v {
			SIGN_REQUEST_VERSION => SignRequest::decode(bytes).map(Self::Quantus),
			NEAR_SIGN_REQUEST_VERSION => NearSignRequest::decode(bytes).map(Self::Near),
			other => Err(QuantusError::Generic(format!(
				"Unsupported signing request version: {other} (this build reads \
				 {SIGN_REQUEST_VERSION} and {NEAR_SIGN_REQUEST_VERSION})"
			))),
		}
	}
}

/// A NEAR transaction for a cold wallet to sign (envelope v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NearSignRequest {
	/// `mainnet` or `testnet`; shown by the device, not part of what is signed
	/// (NEAR transactions carry no chain id — the block hash pins the chain).
	pub network: String,
	/// Borsh-encoded NEAR `TransactionV0`. The device decodes it to display the
	/// actions and signs SHA-256 of these exact bytes.
	pub transaction: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NearWire {
	v: u8,
	chain: String,
	network: String,
	payload: String,
}

const NEAR_CHAIN: &str = "near";

/// The only network labels a NEAR request may carry, spelled exactly. The
/// cold wallet shows the label and picks its account-name check from it, so
/// both ends refuse anything else rather than display a lookalike.
pub const NEAR_NETWORKS: [&str; 2] = ["mainnet", "testnet"];

impl NearSignRequest {
	/// Refuses a transaction the decoders on the other side would refuse, so
	/// the user hears about it before a QR is shown rather than after a
	/// fruitless scan.
	pub fn new(network: impl Into<String>, transaction: Vec<u8>) -> Result<Self> {
		let network = network.into();
		if !NEAR_NETWORKS.contains(&network.as_str()) {
			return Err(QuantusError::Generic(format!(
				"NEAR network {network:?} is not one of {NEAR_NETWORKS:?}"
			)));
		}
		if transaction.len() > MAX_PAYLOAD_BYTES {
			return Err(QuantusError::Generic(format!(
				"Transaction is {} bytes; cold-signing requests carry at most {MAX_PAYLOAD_BYTES} bytes. \
				 Split the call or shrink its arguments.",
				transaction.len()
			)));
		}
		Ok(Self { network, transaction })
	}

	/// The bytes that go into the UR frames.
	pub fn encode(&self) -> Vec<u8> {
		let wire = NearWire {
			v: NEAR_SIGN_REQUEST_VERSION,
			chain: NEAR_CHAIN.to_string(),
			network: self.network.clone(),
			payload: encode_payload(&self.transaction),
		};
		serde_json::to_vec(&wire).expect("sign request serialises")
	}

	pub fn decode(bytes: &[u8]) -> Result<Self> {
		let wire: NearWire = serde_json::from_slice(bytes)
			.map_err(|e| QuantusError::Generic(format!("Not a NEAR signing request ({e})")))?;
		if wire.v != NEAR_SIGN_REQUEST_VERSION {
			return Err(QuantusError::Generic(format!(
				"Unsupported signing request version: {} (NEAR requests are version \
				 {NEAR_SIGN_REQUEST_VERSION})",
				wire.v
			)));
		}
		if wire.chain != NEAR_CHAIN {
			return Err(QuantusError::Generic(format!(
				"Signing request is for chain '{}', not NEAR",
				wire.chain
			)));
		}
		Self::new(wire.network, decode_payload(&wire.payload)?)
	}
}

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
			payload: encode_payload(&self.payload),
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

		Ok(Self { signer: wire.signer, payload: decode_payload(&wire.payload)? })
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

	#[test]
	fn near_request_round_trips_through_the_wire_format() {
		let request = NearSignRequest::new("testnet", vec![0x0d, 0x00, 0x00, 0x00]).unwrap();
		let encoded = request.encode();

		assert_eq!(NearSignRequest::decode(&encoded).unwrap(), request);
		assert_eq!(AnySignRequest::decode(&encoded).unwrap(), AnySignRequest::Near(request));

		let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
		assert_eq!(json["v"], 2);
		assert_eq!(json["chain"], "near");
		assert_eq!(json["network"], "testnet");
		assert_eq!(json["payload"], "0x0d000000");
		assert_eq!(json.as_object().unwrap().len(), 4);
	}

	#[test]
	fn any_request_dispatches_on_version() {
		let v1 = SignRequest::new(ADDRESS, vec![0x02, 0x00]);
		assert_eq!(AnySignRequest::decode(&v1.encode()).unwrap(), AnySignRequest::Quantus(v1));

		let v3 = serde_json::json!({ "v": 3, "payload": "0xab" });
		let error = AnySignRequest::decode(v3.to_string().as_bytes()).unwrap_err().to_string();
		assert!(error.contains("version"), "unexpected error: {error}");

		assert!(AnySignRequest::decode(&[0x02, 0x00, 0x01]).is_err());
	}

	#[test]
	fn near_request_accepts_only_exact_network_labels() {
		for network in NEAR_NETWORKS {
			assert_eq!(NearSignRequest::new(network, vec![1]).unwrap().network, network);
		}
		// Each would read as a known network on the device while disabling
		// that network's account-name check.
		for lookalike in
			["testnet ", " testnet", "Testnet", "test\u{200B}net", "mainnet\n", "localnet", ""]
		{
			assert!(NearSignRequest::new(lookalike, vec![1]).is_err(), "{lookalike:?}");
			let wire = serde_json::json!({
				"v": 2, "chain": "near", "network": lookalike, "payload": "0x01"
			});
			assert!(
				NearSignRequest::decode(&serde_json::to_vec(&wire).unwrap()).is_err(),
				"{lookalike:?}"
			);
		}
	}

	#[test]
	fn near_request_refuses_a_transaction_its_decoder_would_refuse() {
		assert!(NearSignRequest::new("testnet", vec![0u8; MAX_PAYLOAD_BYTES]).is_ok());
		let err = NearSignRequest::new("testnet", vec![0u8; MAX_PAYLOAD_BYTES + 1]).unwrap_err();
		assert!(err.to_string().contains("at most 8192 bytes"), "{err}");
	}

	#[test]
	fn near_request_refuses_other_chains_versions_and_extra_keys() {
		let base =
			serde_json::json!({ "v": 2, "chain": "near", "network": "mainnet", "payload": "0xab" });
		assert!(NearSignRequest::decode(base.to_string().as_bytes()).is_ok());

		let mut other_chain = base.clone();
		other_chain["chain"] = "solana".into();
		assert!(NearSignRequest::decode(other_chain.to_string().as_bytes()).is_err());

		let mut v1 = base.clone();
		v1["v"] = 1.into();
		assert!(NearSignRequest::decode(v1.to_string().as_bytes()).is_err());

		let mut no_network = base.clone();
		no_network["network"] = "".into();
		assert!(NearSignRequest::decode(no_network.to_string().as_bytes()).is_err());

		let mut extra = base.clone();
		extra["signer"] = ADDRESS.into();
		assert!(NearSignRequest::decode(extra.to_string().as_bytes()).is_err());

		let mut missing = base;
		missing.as_object_mut().unwrap().remove("network");
		assert!(NearSignRequest::decode(missing.to_string().as_bytes()).is_err());
	}
}
