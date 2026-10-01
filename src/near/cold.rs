//! Air-gapped signing of NEAR transactions with a Quantus cold wallet.
//!
//! The transaction is built elsewhere (near-cli-rs `sign-later`, or any tool
//! that emits a borsh `TransactionV0`) and handed to the cold wallet over the
//! same `ur:quantus-sign-request` QR transport Quantus extrinsics use, in the
//! version-2 envelope ([`crate::qr::NearSignRequest`]):
//!
//! 1. The CLI displays `{v: 2, chain: "near", network, payload: borsh(tx)}`. The transaction is
//!    sent raw so the device can decode and show the actions.
//! 2. The device checks `tx.public_key` is its own ML-DSA-65 key, signs `SHA-256(borsh(tx))` as a
//!    pure FIPS 204 signature (empty context — NEAR verifies without one), and answers
//!    `signature[3309] ‖ public_key[1952]`.
//! 3. The CLI checks the response key is `tx.public_key` *and* hashes to the cold wallet's stored
//!    SS58 address, verifies the signature, and assembles `borsh(tx) ‖ 0x02 ‖ signature` — the
//!    `SignedTransaction` NEAR accepts.
//!
//! The ML-DSA-87 response size is refused: NEAR defined ML-DSA-65 only.

use crate::{
	cli::cold_signing::{
		confirm_or_abort, present_sign_request, read_signature_response, response_source, ColdIo,
		SIGNATURE_RESPONSE_LEN_ML_DSA_65,
	},
	error::{QuantusError, Result},
	log_print, log_verbose,
	near::{
		protocol::{PublicKey, Signature, SignedTransaction, Transaction, ML_DSA_65_SIGNATURE_LEN},
		sign::transaction_hash,
	},
	qr::NearSignRequest,
};
use colored::Colorize;
use qp_dilithium_crypto::types::Dilithium65SignatureWithPublic;
use sp_core::crypto::AccountId32;
use sp_runtime::traits::IdentifyAccount;

/// Why a NEAR signature response was rejected.
#[derive(Debug)]
pub enum ResponseError {
	/// Wrong size — an incomplete scan, or an ML-DSA-87 device. Rescan-safe.
	BadLength(usize),
	/// Bytes do not parse as signature ‖ public key. Rescan-safe.
	Malformed(String),
	/// The response key is not the key the transaction declares.
	WrongKey { got: String },
	/// The response key is `tx.public_key` but not the cold wallet's. The
	/// transaction was built for a different wallet than `--wallet` names.
	WrongWallet { got: String },
	/// Right key, signature does not verify over this transaction.
	BadSignature,
}

impl ResponseError {
	pub fn rescan_safe(&self) -> bool {
		matches!(self, ResponseError::BadLength(_) | ResponseError::Malformed(_))
	}

	pub fn message(&self, wallet_name: &str) -> String {
		match self {
			ResponseError::BadLength(got) => format!(
				"Response has {got} bytes, expected {SIGNATURE_RESPONSE_LEN_ML_DSA_65} \
				 (ML-DSA-65 signature ‖ public key). The scan was likely incomplete, or the device \
				 signed with an ML-DSA-87 key, which NEAR does not accept — rescan the response."
			),
			ResponseError::Malformed(e) => format!(
				"Response bytes do not parse as an ML-DSA-65 signature + public key ({e}) — \
				 rescan the response."
			),
			ResponseError::WrongKey { got } => format!(
				"Response was signed by {got}, which is not the key this transaction declares. \
				 Aborting — check that the right device/account signed."
			),
			ResponseError::WrongWallet { got } => format!(
				"Response key {got} matches the transaction but is not cold wallet \
				 '{wallet_name}'. Aborting — the transaction was built for a different wallet's \
				 key."
			),
			ResponseError::BadSignature =>
				"Signature does not verify over this transaction. Aborting — the cold wallet may \
				 have signed a stale QR; run the command again."
					.to_string(),
		}
	}
}

/// Check a device response against the transaction it was requested for and
/// the cold wallet it was requested from, returning the bare NEAR signature.
pub fn validate_near_response(
	tx: &Transaction,
	response: &[u8],
	expected_account: &AccountId32,
) -> std::result::Result<Signature, ResponseError> {
	if response.len() != SIGNATURE_RESPONSE_LEN_ML_DSA_65 {
		return Err(ResponseError::BadLength(response.len()));
	}
	let swp = Dilithium65SignatureWithPublic::from_bytes(response)
		.map_err(|e| ResponseError::Malformed(format!("{e:?}")))?;

	let response_key = PublicKey::from_ml_dsa_65_bytes(swp.public().as_ref())
		.map_err(|e| ResponseError::Malformed(e.to_string()))?;
	if response_key != tx.public_key {
		return Err(ResponseError::WrongKey { got: response_key.to_near_string() });
	}

	let derived_account: AccountId32 = swp.public().into_account();
	if derived_account != *expected_account {
		return Err(ResponseError::WrongWallet { got: response_key.to_near_string() });
	}

	let hash = transaction_hash(tx).map_err(|e| ResponseError::Malformed(e.to_string()))?;
	if !crate::chain::signing::verify_ml_dsa_65(&swp, &hash, None) {
		return Err(ResponseError::BadSignature);
	}

	let signature: [u8; ML_DSA_65_SIGNATURE_LEN] = swp
		.signature()
		.as_ref()
		.try_into()
		.expect("ML-DSA-65 signature length is fixed");
	Ok(Signature::MlDsa65(Box::new(signature)))
}

/// Parse the cold wallet's stored SS58 address into the account the response
/// key must hash to.
pub fn parse_cold_account(wallet_name: &str, cold_address_ss58: &str) -> Result<AccountId32> {
	use sp_core::crypto::Ss58Codec;
	AccountId32::from_ss58check_with_version(cold_address_ss58)
		.map(|(account, _)| account)
		.map_err(|e| {
			QuantusError::Generic(format!(
				"Cold wallet '{wallet_name}' has an invalid stored address: {e:?}"
			))
		})
}

/// Run the QR roundtrip for `tx` against cold wallet `wallet_name` and return
/// the signed transaction. Nothing is submitted here.
pub async fn sign_transaction_cold(
	tx: Transaction,
	network: &str,
	wallet_name: &str,
	cold_address_ss58: &str,
	io: &ColdIo,
) -> Result<SignedTransaction> {
	let PublicKey::MlDsa65(_) = &tx.public_key else {
		return Err(QuantusError::Generic(format!(
			"transaction declares key {}; a Quantus cold wallet can only sign for an ml-dsa-65 \
			 key",
			tx.public_key.to_near_string()
		)));
	};
	let account = parse_cold_account(wallet_name, cold_address_ss58)?;
	let tx_bytes = tx.to_bytes()?;
	let request = NearSignRequest::new(network, tx_bytes)?;

	log_print!("🧊 Cold wallet signing with '{}'", wallet_name.bright_blue().bold());
	log_print!("   Wallet:   {}", cold_address_ss58.bright_cyan());
	log_print!("   Network:  {network}");
	log_print!("   Signer:   {}", tx.signer_id.bright_cyan());
	log_print!("   Key:      {}", tx.public_key.to_near_string());
	log_print!("   Receiver: {}", tx.receiver_id.bright_cyan());
	log_print!("   Nonce:    {}", tx.nonce);
	log_print!("   Block:    {}", bs58::encode(tx.block_hash).into_string());
	for action in tx.describe_actions() {
		log_print!("   Action:   {action}");
	}
	log_print!("   Hash:     {}", hex::encode(transaction_hash(&tx)?));
	log_verbose!("   Transaction borsh: 0x{}", hex::encode(&request.transaction));

	let interactive = present_sign_request(&request.encode(), io).await?;

	let source = response_source(io)?;
	let signature = loop {
		let response = read_signature_response(&source).await?;
		match validate_near_response(&tx, &response, &account) {
			Ok(signature) => break signature,
			Err(err) => {
				let msg = err.message(wallet_name);
				if err.rescan_safe() && interactive {
					log_print!("⚠️  {}", msg);
					confirm_or_abort("Rescan? [Enter to rescan / q to abort]: ")?;
					continue;
				}
				return Err(QuantusError::Generic(msg));
			},
		}
	};
	log_print!("✅ Signature verified against cold wallet '{}'", wallet_name.bright_blue());

	Ok(SignedTransaction { transaction: tx, signature })
}

/// Read an unsigned transaction from the CLI argument: inline base64, or
/// `@path` to a file holding either bare base64 or the JSON near-cli-rs
/// `sign-later ... save-to-file` writes.
pub fn load_unsigned_transaction(arg: &str) -> Result<Transaction> {
	let Some(path) = arg.strip_prefix('@') else {
		return Transaction::from_base64(arg);
	};
	let text = std::fs::read_to_string(path)
		.map_err(|e| QuantusError::Generic(format!("reading {path}: {e}")))?;
	transaction_from_file_text(&text)
}

fn transaction_from_file_text(text: &str) -> Result<Transaction> {
	let text = text.trim();
	if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
		// near-cli-rs keys its file by prose; pick the value that decodes.
		let candidates: Vec<&str> = match &json {
			serde_json::Value::Object(map) => map.values().filter_map(|v| v.as_str()).collect(),
			serde_json::Value::String(s) => vec![s.as_str()],
			_ => Vec::new(),
		};
		return candidates.iter().find_map(|c| Transaction::from_base64(c).ok()).ok_or_else(|| {
			QuantusError::Generic(
				"no field in the JSON file decodes as a base64 NEAR transaction".to_string(),
			)
		});
	}
	Transaction::from_base64(text)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::near::protocol::{Action, TransferAction};
	use qp_dilithium_crypto::types::Dilithium65Pair;
	use sp_core::Pair as _;

	fn tx_for(pair: &Dilithium65Pair) -> Transaction {
		Transaction {
			signer_id: "vault.alice.testnet".to_string(),
			public_key: PublicKey::from_ml_dsa_65_bytes(pair.public().as_ref()).unwrap(),
			nonce: 12,
			receiver_id: "bob.testnet".to_string(),
			block_hash: [0x22; 32],
			actions: vec![Action::Transfer(TransferAction { deposit: 10u128.pow(24) })],
		}
	}

	fn device_response(pair: &Dilithium65Pair, tx: &Transaction) -> Vec<u8> {
		let hash = transaction_hash(tx).unwrap();
		crate::chain::signing::sign_ml_dsa_65(pair, &hash, None).to_bytes().to_vec()
	}

	#[test]
	fn validates_a_correct_device_response_into_a_near_signature() {
		let pair = Dilithium65Pair::from_seed(&[7u8; 32]).unwrap();
		let account: AccountId32 = pair.public().into_account();
		let tx = tx_for(&pair);
		let response = device_response(&pair, &tx);
		assert_eq!(response.len(), SIGNATURE_RESPONSE_LEN_ML_DSA_65);

		let signature = validate_near_response(&tx, &response, &account).unwrap();
		let Signature::MlDsa65(sig) = &signature else { panic!("ml-dsa-65 signature") };

		// The bare signature verifies as pure ML-DSA over the hash, as NEAR does.
		let verifier =
			qp_rusty_crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(pair.public().as_ref())
				.unwrap();
		assert!(verifier.verify(&transaction_hash(&tx).unwrap(), sig.as_ref(), None));

		// And the assembled wire form is borsh(tx) ‖ tag ‖ signature.
		let signed = SignedTransaction { transaction: tx.clone(), signature };
		let bytes = borsh::to_vec(&signed).unwrap();
		let tx_bytes = tx.to_bytes().unwrap();
		assert_eq!(&bytes[..tx_bytes.len()], &tx_bytes[..]);
		assert_eq!(bytes[tx_bytes.len()], 2);
		assert_eq!(bytes.len(), tx_bytes.len() + 1 + ML_DSA_65_SIGNATURE_LEN);
	}

	#[test]
	fn rejects_wrong_lengths_keys_wallets_and_signatures() {
		let pair = Dilithium65Pair::from_seed(&[7u8; 32]).unwrap();
		let account: AccountId32 = pair.public().into_account();
		let tx = tx_for(&pair);
		let response = device_response(&pair, &tx);

		// Truncated → rescan-safe.
		let err =
			validate_near_response(&tx, &response[..response.len() - 1], &account).unwrap_err();
		assert!(err.rescan_safe());
		assert!(matches!(err, ResponseError::BadLength(_)));

		// An ML-DSA-87 device answers with the 87 size → refused, rescan-safe.
		let alice87 = qp_dilithium_crypto::crystal_alice();
		let hash = transaction_hash(&tx).unwrap();
		let r87 = crate::chain::signing::sign_ml_dsa_87(&alice87, &hash, None).to_bytes();
		let err = validate_near_response(&tx, &r87, &account).unwrap_err();
		assert!(matches!(err, ResponseError::BadLength(_)));

		// A different 65 key signed → WrongKey, not retryable.
		let other = Dilithium65Pair::from_seed(&[9u8; 32]).unwrap();
		let err = validate_near_response(&tx, &device_response(&other, &tx), &account).unwrap_err();
		assert!(!err.rescan_safe());
		assert!(matches!(err, ResponseError::WrongKey { .. }));

		// Right key for the tx, but --wallet names another cold wallet → WrongWallet.
		let other_account: AccountId32 = other.public().into_account();
		let err = validate_near_response(&tx, &response, &other_account).unwrap_err();
		assert!(matches!(err, ResponseError::WrongWallet { .. }));

		// Right key, signed a different transaction → BadSignature.
		let mut stale = tx.clone();
		stale.nonce = 13;
		let err = validate_near_response(&stale, &response, &account).unwrap_err();
		assert!(matches!(err, ResponseError::BadSignature));

		// Signed under the Quantus extrinsic context instead of none → BadSignature.
		let ctx_signed = crate::chain::signing::sign_ml_dsa_65(
			&pair,
			&hash,
			Some(crate::chain::signing::EXTRINSIC),
		)
		.to_bytes();
		let err = validate_near_response(&tx, &ctx_signed, &account).unwrap_err();
		assert!(matches!(err, ResponseError::BadSignature));
	}

	#[test]
	fn reads_near_cli_save_to_file_json_and_bare_base64() {
		let b64 = "DQAAAGFsaWNlLnRlc3RuZXQAEREREREREREREREREREREREREREREREREREREREREREqAAAAAAAAAAsAAABib2IudGVzdG5ldCIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiAQAAAAMAAACh7czOG8LTAAAAAAAA";
		let json = serde_json::json!({
			"Transaction hash to sign": "be358ec90e89b70256db586f72c4a280daa1199ba6f91398e9d034b72a7a6c9f",
			"Unsigned transaction (serialized as base64)": b64,
		})
		.to_string();

		let from_json = transaction_from_file_text(&json).unwrap();
		let from_bare = transaction_from_file_text(&format!("{b64}\n")).unwrap();
		let inline = load_unsigned_transaction(b64).unwrap();
		assert_eq!(from_json, from_bare);
		assert_eq!(from_json, inline);
		assert_eq!(from_json.signer_id, "alice.testnet");

		assert!(transaction_from_file_text(r#"{"x": "not a tx"}"#).is_err());
		assert!(load_unsigned_transaction("@/nonexistent/path").is_err());
	}

	/// The full simulator loop as the CLI drives it: v2 request → UR → device
	/// decodes, signs → UR → CLI validates.
	#[test]
	fn end_to_end_request_and_response_over_ur() {
		let pair = Dilithium65Pair::from_seed(&[7u8; 32]).unwrap();
		let account: AccountId32 = pair.public().into_account();
		let tx = tx_for(&pair);

		let request = NearSignRequest::new("testnet", tx.to_bytes().unwrap()).unwrap();
		let parts = quantus_ur::encode_bytes(&request.encode()).unwrap();
		let received = NearSignRequest::decode(&quantus_ur::decode_bytes(&parts).unwrap()).unwrap();
		assert_eq!(received.network, "testnet");
		let device_tx = Transaction::from_bytes(&received.transaction).unwrap();
		assert_eq!(device_tx, tx);

		let response = device_response(&pair, &device_tx);
		let response_parts = quantus_ur::encode_bytes(&response).unwrap();
		assert!(response_parts.len() > 1, "5261-byte response must be multi-part");
		let response = quantus_ur::decode_bytes(&response_parts).unwrap();

		assert!(validate_near_response(&tx, &response, &account).is_ok());
	}
}
