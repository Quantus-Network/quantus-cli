//! Minimal NEAR JSON-RPC client: just the calls the `near` commands need.

use crate::{
	error::{QuantusError, Result},
	near::protocol::SignedTransaction,
};
use serde_json::{json, Value};

/// NEAR accepts ML-DSA-65 transactions and access keys from this protocol
/// version (the `PostQuantumSignatures` feature).
pub const MIN_ML_DSA_PROTOCOL_VERSION: u64 = 85;

pub struct NearRpcClient {
	url: String,
	http: reqwest::Client,
}

/// An access key's state, plus the queried block hash — recent enough to
/// anchor the next transaction.
pub struct AccessKeyView {
	pub nonce: u64,
	pub block_hash: [u8; 32],
}

/// One `view_access_key_list` entry: the text-form key (`ed25519:…` or
/// `ml-dsa-65-hash:…`) and whether it is full-access.
pub struct AccessKeyListEntry {
	pub public_key: String,
	pub full_access: bool,
}

impl NearRpcClient {
	pub fn new(url: impl Into<String>) -> Result<Self> {
		let http = reqwest::Client::builder()
			.build()
			.map_err(|e| QuantusError::Generic(format!("HTTP client: {e}")))?;
		Ok(Self { url: url.into(), http })
	}

	/// Resolve `--network`/`--rpc-url` to a client. An explicit URL wins; the
	/// network name may itself be an RPC URL. The named networks use FastNear:
	/// `rpc.{mainnet,testnet}.near.org` is deprecated and rate-limits.
	pub fn for_network(network: &str, rpc_url: Option<String>) -> Result<Self> {
		let url = match (rpc_url, network) {
			(Some(url), _) => url,
			(None, "testnet") => "https://test.rpc.fastnear.com".to_string(),
			(None, "mainnet") => "https://rpc.mainnet.fastnear.com".to_string(),
			(None, url) if url.starts_with("https://") || url.starts_with("http://") =>
				url.to_string(),
			(None, other) =>
				return Err(QuantusError::Generic(format!(
					"unknown network '{other}' — use testnet, mainnet, an RPC URL, or --rpc-url"
				))),
		};
		Self::new(url)
	}

	async fn call(&self, method: &str, params: Value) -> Result<Value> {
		let body =
			json!({ "jsonrpc": "2.0", "id": "quantus-cli", "method": method, "params": params });
		let response = self
			.http
			.post(&self.url)
			.json(&body)
			.send()
			.await
			.map_err(|e| QuantusError::NetworkError(format!("NEAR RPC {method}: {e}")))?;

		let status = response.status();
		let text = response
			.text()
			.await
			.map_err(|e| QuantusError::NetworkError(format!("NEAR RPC {method}: {e}")))?;
		if !status.is_success() {
			return Err(QuantusError::NetworkError(format!(
				"NEAR RPC {method} failed with {status}: {text}"
			)));
		}

		let envelope: Value = serde_json::from_str(&text)
			.map_err(|e| QuantusError::Generic(format!("NEAR RPC {method} response: {e}")))?;
		if let Some(error) = envelope.get("error") {
			return Err(QuantusError::Generic(format!("NEAR RPC {method} error: {error}")));
		}
		Ok(envelope.get("result").cloned().unwrap_or(Value::Null))
	}

	pub async fn protocol_version(&self) -> Result<u64> {
		let status = self.call("status", json!([])).await?;
		status
			.get("protocol_version")
			.and_then(|v| v.as_u64())
			.ok_or_else(|| QuantusError::Generic("status response has no protocol_version".into()))
	}

	/// Fail early on networks that predate ML-DSA-65 support.
	pub async fn ensure_ml_dsa_support(&self) -> Result<()> {
		let version = self.protocol_version().await?;
		if version < MIN_ML_DSA_PROTOCOL_VERSION {
			return Err(QuantusError::Generic(format!(
				"this NEAR network runs protocol version {version}; ML-DSA-65 needs \
				 {MIN_ML_DSA_PROTOCOL_VERSION}+"
			)));
		}
		Ok(())
	}

	/// Look up an access key by its full text form. Works with the full
	/// `ml-dsa-65:` key — the node hashes it for the trie lookup.
	pub async fn view_access_key(
		&self,
		account_id: &str,
		public_key: &str,
	) -> Result<AccessKeyView> {
		let result = self
			.call(
				"query",
				json!({
					"request_type": "view_access_key",
					"finality": "final",
					"account_id": account_id,
					"public_key": public_key,
				}),
			)
			.await?;

		// Missing keys come back as a result-level error string, not an RPC error.
		if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
			return Err(QuantusError::Generic(format!(
				"access key lookup for {account_id}: {error}"
			)));
		}

		let nonce = result
			.get("nonce")
			.and_then(|v| v.as_u64())
			.ok_or_else(|| QuantusError::Generic("view_access_key response has no nonce".into()))?;
		let block_hash = decode_block_hash(&result)?;
		Ok(AccessKeyView { nonce, block_hash })
	}

	pub async fn view_access_key_list(&self, account_id: &str) -> Result<Vec<AccessKeyListEntry>> {
		let result = self
			.call(
				"query",
				json!({
					"request_type": "view_access_key_list",
					"finality": "final",
					"account_id": account_id,
				}),
			)
			.await?;
		if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
			return Err(QuantusError::Generic(format!("access key list for {account_id}: {error}")));
		}

		let keys = result
			.get("keys")
			.and_then(|k| k.as_array())
			.ok_or_else(|| QuantusError::Generic("view_access_key_list has no keys".into()))?;
		keys.iter()
			.map(|entry| {
				let public_key = entry
					.get("public_key")
					.and_then(|v| v.as_str())
					.ok_or_else(|| {
						QuantusError::Generic("access key entry has no public_key".into())
					})?
					.to_string();
				let full_access = entry
					.pointer("/access_key/permission")
					.map(|p| p == &json!("FullAccess"))
					.unwrap_or(false);
				Ok(AccessKeyListEntry { public_key, full_access })
			})
			.collect()
	}

	/// Whether the account exists (`view_account` succeeds).
	pub async fn account_exists(&self, account_id: &str) -> Result<bool> {
		let result = self
			.call(
				"query",
				json!({
					"request_type": "view_account",
					"finality": "final",
					"account_id": account_id,
				}),
			)
			.await;
		match result {
			Ok(value) => Ok(value.get("error").is_none()),
			Err(e) => {
				let text = e.to_string();
				if text.contains("does not exist") || text.contains("UNKNOWN_ACCOUNT") {
					Ok(false)
				} else {
					Err(e)
				}
			},
		}
	}

	/// Call a contract view method with JSON args and decode its JSON return
	/// value.
	pub async fn call_view_function(
		&self,
		account_id: &str,
		method_name: &str,
		args: &Value,
	) -> Result<Value> {
		use base64::Engine as _;
		let args_base64 = base64::engine::general_purpose::STANDARD.encode(args.to_string());
		let result = self
			.call(
				"query",
				json!({
					"request_type": "call_function",
					"finality": "final",
					"account_id": account_id,
					"method_name": method_name,
					"args_base64": args_base64,
				}),
			)
			.await?;
		if let Some(error) = result.get("error").and_then(|e| e.as_str()) {
			return Err(QuantusError::Generic(format!(
				"view call {account_id}.{method_name}: {error}"
			)));
		}
		parse_call_function_result(&result, account_id, method_name)
	}

	/// Submit and wait for finality. Returns the execution outcome only if it
	/// explicitly reports a finalized success; anything else is an error.
	pub async fn send_tx(&self, signed: &SignedTransaction) -> Result<Value> {
		let bytes = borsh::to_vec(signed)
			.map_err(|e| QuantusError::Generic(format!("borsh-encoding transaction: {e}")))?;
		use base64::Engine as _;
		let signed_tx_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

		let result = self
			.call("send_tx", json!({ "signed_tx_base64": signed_tx_base64, "wait_until": "FINAL" }))
			.await?;

		check_send_tx_outcome(&result)?;
		Ok(result)
	}
}

/// Accept only a finalized, successful `send_tx` outcome. A missing result,
/// missing/unfinished status, or non-FINAL execution status is an error even
/// when the RPC call itself returned 200.
fn check_send_tx_outcome(result: &Value) -> Result<()> {
	if !result.is_object() {
		return Err(QuantusError::Generic(
			"send_tx returned no execution outcome; transaction state unknown".into(),
		));
	}
	if let Some(failure) = result.pointer("/status/Failure") {
		return Err(QuantusError::Generic(format!("transaction failed on-chain: {failure}")));
	}
	if result.pointer("/status/SuccessValue").is_none() {
		let status = result.get("status").cloned().unwrap_or(Value::Null);
		return Err(QuantusError::Generic(format!(
			"transaction did not report a successful outcome (status: {status}); \
			 check the explorer before retrying"
		)));
	}
	match result.get("final_execution_status").and_then(|v| v.as_str()) {
		Some("FINAL") => Ok(()),
		other => Err(QuantusError::Generic(format!(
			"transaction succeeded but is not finalized (final_execution_status: {other:?}); \
			 check the explorer before retrying"
		))),
	}
}

/// A `call_function` query returns the method's JSON return value as an
/// array of byte numbers.
fn parse_call_function_result(
	result: &Value,
	account_id: &str,
	method_name: &str,
) -> Result<Value> {
	let bytes = result
		.get("result")
		.and_then(|r| r.as_array())
		.ok_or_else(|| {
			QuantusError::Generic(format!(
				"view call {account_id}.{method_name} returned no result bytes"
			))
		})?
		.iter()
		.map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
		.collect::<Option<Vec<u8>>>()
		.ok_or_else(|| {
			QuantusError::Generic(format!(
				"view call {account_id}.{method_name} result bytes are malformed"
			))
		})?;
	serde_json::from_slice(&bytes).map_err(|e| {
		QuantusError::Generic(format!(
			"view call {account_id}.{method_name} returned non-JSON: {e}"
		))
	})
}

/// Decode a finalized outcome's base64 `SuccessValue` as JSON (e.g. the
/// proposal id `add_proposal` returns). `None` when empty or not JSON.
pub fn decode_success_value(outcome: &Value) -> Option<Value> {
	use base64::Engine as _;
	let b64 = outcome.pointer("/status/SuccessValue")?.as_str()?;
	let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
	if bytes.is_empty() {
		return None;
	}
	serde_json::from_slice(&bytes).ok()
}

fn decode_block_hash(result: &Value) -> Result<[u8; 32]> {
	let text = result
		.get("block_hash")
		.and_then(|v| v.as_str())
		.ok_or_else(|| QuantusError::Generic("response has no block_hash".into()))?;
	let bytes = bs58::decode(text)
		.into_vec()
		.map_err(|e| QuantusError::Generic(format!("block_hash base58: {e}")))?;
	bytes.as_slice().try_into().map_err(|_| {
		QuantusError::Generic(format!("block_hash must be 32 bytes, got {}", bytes.len()))
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn send_tx_outcome_accepts_finalized_success() {
		let result = json!({
			"status": { "SuccessValue": "" },
			"final_execution_status": "FINAL",
			"transaction": { "hash": "abc" },
		});
		assert!(check_send_tx_outcome(&result).is_ok());
	}

	#[test]
	fn send_tx_outcome_rejects_missing_result() {
		let err = check_send_tx_outcome(&Value::Null).unwrap_err();
		assert!(err.to_string().contains("no execution outcome"), "{err}");
	}

	#[test]
	fn send_tx_outcome_rejects_failure() {
		let result = json!({
			"status": { "Failure": { "ActionError": { "index": 0 } } },
			"final_execution_status": "FINAL",
		});
		let err = check_send_tx_outcome(&result).unwrap_err();
		assert!(err.to_string().contains("failed on-chain"), "{err}");
	}

	#[test]
	fn send_tx_outcome_rejects_missing_status() {
		let result = json!({ "final_execution_status": "FINAL" });
		let err = check_send_tx_outcome(&result).unwrap_err();
		assert!(err.to_string().contains("did not report a successful outcome"), "{err}");
	}

	#[test]
	fn send_tx_outcome_rejects_unstarted_status() {
		let result = json!({ "status": "Started", "final_execution_status": "FINAL" });
		let err = check_send_tx_outcome(&result).unwrap_err();
		assert!(err.to_string().contains("did not report a successful outcome"), "{err}");
	}

	#[test]
	fn send_tx_outcome_rejects_unfinalized_success() {
		let result = json!({
			"status": { "SuccessValue": "" },
			"final_execution_status": "EXECUTED_OPTIMISTIC",
		});
		let err = check_send_tx_outcome(&result).unwrap_err();
		assert!(err.to_string().contains("not finalized"), "{err}");
	}

	#[test]
	fn send_tx_outcome_rejects_missing_final_execution_status() {
		let result = json!({ "status": { "SuccessValue": "" } });
		let err = check_send_tx_outcome(&result).unwrap_err();
		assert!(err.to_string().contains("not finalized"), "{err}");
	}

	#[test]
	fn call_function_result_decodes_json_bytes() {
		let payload = br#"{"proposal_bond":"100000000000000000000000"}"#;
		let bytes: Vec<Value> = payload.iter().map(|b| json!(b)).collect();
		let result = json!({ "result": bytes, "block_height": 1 });
		let value = parse_call_function_result(&result, "dao.near", "get_policy").unwrap();
		assert_eq!(value["proposal_bond"], "100000000000000000000000");
	}

	#[test]
	fn call_function_result_rejects_missing_or_malformed_bytes() {
		let err = parse_call_function_result(&json!({}), "dao.near", "get_policy").unwrap_err();
		assert!(err.to_string().contains("no result bytes"), "{err}");

		let result = json!({ "result": [300, -1] });
		let err = parse_call_function_result(&result, "dao.near", "get_policy").unwrap_err();
		assert!(err.to_string().contains("malformed"), "{err}");
	}

	#[test]
	fn success_value_decodes_returned_json() {
		// base64("0") — add_proposal returning proposal id 0.
		let outcome = json!({ "status": { "SuccessValue": "MA==" } });
		assert_eq!(decode_success_value(&outcome), Some(json!(0)));

		let empty = json!({ "status": { "SuccessValue": "" } });
		assert_eq!(decode_success_value(&empty), None);

		assert_eq!(decode_success_value(&json!({ "status": "Started" })), None);
	}
}
