//! Common client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing clients
//! across all CLI modules.

use crate::{error::QuantusError, log_verbose};
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use qp_dilithium_crypto::types::DilithiumSignatureScheme;
use sp_core::crypto::AccountId32;
use sp_runtime::{traits::IdentifyAccount, MultiAddress};
use std::{sync::Arc, time::Duration};
use subxt::{
	backend::rpc::RpcClient,
	config::{substrate::SubstrateHeader, DefaultExtrinsicParams},
	Config, OnlineClient,
};
use subxt_metadata::Metadata as SubxtMetadata;

#[derive(Debug, Clone, Copy)]
pub struct SubxtBlake2bHasher;

impl subxt::config::Hasher for SubxtBlake2bHasher {
	type Output = sp_core::H256;

	fn new(_metadata: &SubxtMetadata) -> Self {
		SubxtBlake2bHasher
	}

	fn hash(&self, bytes: &[u8]) -> Self::Output {
		<sp_runtime::traits::BlakeTwo256 as sp_runtime::traits::Hash>::hash(bytes)
	}
}

/// Configuration of the chain
pub enum ChainConfig {}
impl Config for ChainConfig {
	type AccountId = AccountId32;
	type Address = MultiAddress<Self::AccountId, ()>;
	type Signature = DilithiumSignatureScheme;
	type Hasher = SubxtBlake2bHasher;
	type Header = SubstrateHeader<u32, SubxtBlake2bHasher>;
	type AssetId = u32;
	type ExtrinsicParams = DefaultExtrinsicParams<Self>;
}

/// Wrapper around OnlineClient that also stores the node URL and RPC client
#[derive(Clone)]
pub struct QuantusClient {
	client: OnlineClient<ChainConfig>,
	rpc_client: Arc<WsClient>,
	node_url: String,
}

impl QuantusClient {
	/// Return a URL suitable for logs and user-facing diagnostics by removing credentials.
	fn sanitize_url_for_diagnostics(url: &str) -> String {
		let Some(scheme_end) = url.find("://") else {
			return url.to_string();
		};

		let authority_start = scheme_end + 3;
		let authority_end = url[authority_start..]
			.find(['/', '?', '#'])
			.map(|offset| authority_start + offset)
			.unwrap_or(url.len());
		let authority = &url[authority_start..authority_end];

		if let Some(userinfo_end) = authority.rfind('@') {
			format!(
				"{}{}{}",
				&url[..authority_start],
				&authority[userinfo_end + 1..],
				&url[authority_end..]
			)
		} else {
			url.to_string()
		}
	}

	/// Create a new QuantusClient by connecting to the specified node URL
	pub async fn new(node_url: &str) -> crate::error::Result<Self> {
		Self::connect(node_url, true).await
	}

	/// Connect without enforcing the runtime identity gate.
	///
	/// Only for read-only diagnostics (e.g. `compatibility-check`) that must be able to
	/// inspect nodes this CLI would otherwise reject. Never use this client to sign or
	/// submit transactions.
	pub async fn new_without_runtime_check(node_url: &str) -> crate::error::Result<Self> {
		Self::connect(node_url, false).await
	}

	async fn connect(node_url: &str, enforce_runtime_identity: bool) -> crate::error::Result<Self> {
		let display_node_url = Self::sanitize_url_for_diagnostics(node_url);
		log_verbose!("🔗 Connecting to Quantus node: {}", display_node_url);

		// Validate URL format and provide helpful error messages
		if !node_url.starts_with("ws://") && !node_url.starts_with("wss://") {
			return Err(QuantusError::NetworkError(format!(
                "Invalid WebSocket URL: '{display_node_url}'. URL must start with 'ws://' (unsecured) or 'wss://' (secured)"
            )));
		}

		// Create WS client with custom timeouts
		let ws_client = WsClientBuilder::default()
            // TODO: Make these configurable in a separate change
            // These timeouts should be configurable via CLI or config file
            .connection_timeout(Duration::from_secs(30))
            .request_timeout(Duration::from_secs(30))
            .build(node_url)
            .await
            .map_err(|e| {
                // Provide more helpful error messages for common issues
                let error_str = format!("{e:?}").replace(node_url, &display_node_url);
                let error_msg = if error_str.contains("TimedOut") || error_str.contains("timed out") {
                    if node_url.starts_with("ws://") {
                        format!(
                            "Connection timed out. Try using 'wss://{}' instead of '{}'",
                            display_node_url.strip_prefix("ws://").unwrap_or(&display_node_url),
                            display_node_url
                        )
                    } else {
                        format!("Connection timed out. Please check if the node is running and accessible at: {display_node_url}")
                    }
                } else if error_str.contains("HTTP") {
                    format!("HTTP error: {error_str}. This might indicate the node doesn't support WebSocket connections")
                } else {
                    format!("Failed to create RPC client: {error_str}")
                };
                QuantusError::NetworkError(error_msg)
            })?;

		// Wrap WS client in Arc for sharing
		let ws_client = Arc::new(ws_client);

		// Create RPC client wrapper for subxt
		let rpc_client = RpcClient::new(ws_client.clone());

		// Create SubXT client using the configured RPC client
		let client = OnlineClient::<ChainConfig>::from_rpc_client(rpc_client).await?;

		// Reject non-Quantus / older-unsupported runtimes before encode/sign. Newer-than-table
		// Quantus specs are allowed with a warning (see validate_runtime_identity).
		if enforce_runtime_identity {
			use jsonrpsee::core::client::ClientT;
			let runtime_version: serde_json::Value = ws_client
				.request::<serde_json::Value, [(); 0]>("state_getRuntimeVersion", [])
				.await
				.map_err(|e| {
					QuantusError::NetworkError(format!("Failed to fetch runtime version: {e:?}"))
				})?;
			crate::config::validate_runtime_version_value(&runtime_version).map_err(
				|e| match e {
					QuantusError::NetworkError(msg) =>
						QuantusError::NetworkError(format!("{msg} (from {display_node_url})")),
					other => other,
				},
			)?;
		}

		log_verbose!("✅ Connected to Quantus node successfully!");

		Ok(QuantusClient { client, rpc_client: ws_client, node_url: node_url.to_string() })
	}

	/// Get reference to the underlying SubXT client
	pub fn client(&self) -> &OnlineClient<ChainConfig> {
		&self.client
	}

	/// Get the node URL
	pub fn node_url(&self) -> &str {
		&self.node_url
	}

	/// Get reference to the RPC client
	pub fn rpc_client(&self) -> &WsClient {
		&self.rpc_client
	}

	/// Get the latest block (best block) using RPC call
	/// This bypasses SubXT's default behavior of using finalized blocks
	pub async fn get_latest_block(&self) -> crate::error::Result<subxt::utils::H256> {
		log_verbose!("🔍 Fetching latest block hash via RPC...");

		// Use RPC call to get the latest block hash
		use jsonrpsee::core::client::ClientT;
		let latest_hash: subxt::utils::H256 = self
			.rpc_client
			.request::<subxt::utils::H256, [(); 0]>("chain_getBlockHash", [])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to fetch latest block hash: {e:?}"
				))
			})?;

		log_verbose!("📦 Latest block hash: {:?}", latest_hash);
		Ok(latest_hash)
	}

	/// Interpret a System::Account nonce lookup without collapsing absence into a silent zero.
	///
	/// Returns `(nonce, account_exists)`. Missing accounts use nonce `0` (correct for the first
	/// extrinsic) but callers can log the absence explicitly.
	pub(crate) fn interpret_account_nonce(fetched_nonce: Option<u32>) -> (u32, bool) {
		match fetched_nonce {
			Some(nonce) => (nonce, true),
			None => (0, false),
		}
	}

	/// Get account nonce from the best block (latest) using direct RPC call
	/// This bypasses SubXT's default behavior of using finalized blocks
	pub async fn get_account_nonce_from_best_block(
		&self,
		account_id: &AccountId32,
	) -> crate::error::Result<u64> {
		log_verbose!("🔍 Fetching account nonce from best block via RPC...");

		// Get latest block hash first
		let latest_block_hash = self.get_latest_block().await?;
		log_verbose!("📦 Latest block hash for nonce query: {:?}", latest_block_hash);

		// Convert sp_core::AccountId32 to subxt::utils::AccountId32
		let account_bytes: [u8; 32] = *account_id.as_ref();
		let subxt_account_id = subxt::utils::AccountId32::from(account_bytes);

		// Use SubXT's storage API to query nonce at the best block
		use crate::chain::quantus_subxt::api;
		let storage_addr = api::storage().system().account(subxt_account_id);

		let storage_at = self.client.storage().at(latest_block_hash);

		let account_info = storage_at.fetch(&storage_addr).await?;
		let (nonce, exists) = Self::interpret_account_nonce(account_info.map(|info| info.nonce));
		if exists {
			log_verbose!("✅ Nonce from best block: {}", nonce);
		} else {
			log_verbose!(
				"⚠️  Account has no on-chain entry at best block; using nonce 0 for first extrinsic"
			);
		}
		Ok(nonce as u64)
	}

	/// Get genesis hash using RPC call
	pub async fn get_genesis_hash(&self) -> crate::error::Result<subxt::utils::H256> {
		log_verbose!("🔍 Fetching genesis hash via RPC...");

		use jsonrpsee::core::client::ClientT;
		let genesis_hash: subxt::utils::H256 = self
			.rpc_client
			.request::<subxt::utils::H256, [u32; 1]>("chain_getBlockHash", [0u32])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to fetch genesis hash: {e:?}"
				))
			})?;

		log_verbose!("🧬 Genesis hash: {:?}", genesis_hash);
		Ok(genesis_hash)
	}

	/// Get runtime version using RPC call
	pub async fn get_runtime_version(&self) -> crate::error::Result<(u32, u32)> {
		log_verbose!("🔍 Fetching runtime version via RPC...");

		use jsonrpsee::core::client::ClientT;
		let runtime_version: serde_json::Value = self
			.rpc_client
			.request::<serde_json::Value, [(); 0]>("state_getRuntimeVersion", [])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to fetch runtime version: {e:?}"
				))
			})?;

		let spec_version = runtime_version["specVersion"].as_u64().ok_or_else(|| {
			crate::error::QuantusError::NetworkError("Failed to parse spec version".to_string())
		})? as u32;

		let transaction_version =
			runtime_version["transactionVersion"].as_u64().ok_or_else(|| {
				crate::error::QuantusError::NetworkError(
					"Failed to parse transaction version".to_string(),
				)
			})? as u32;

		log_verbose!("🔧 Runtime version: spec={}, tx={}", spec_version, transaction_version);
		Ok((spec_version, transaction_version))
	}

	/// Get runtime hash using RPC call (if available)
	pub async fn get_runtime_hash(&self) -> crate::error::Result<Option<String>> {
		log_verbose!("🔍 Fetching runtime hash via RPC...");

		use jsonrpsee::core::client::ClientT;

		// Try different possible RPC calls for runtime hash
		let possible_calls = ["state_getRuntimeHash", "state_getRuntime", "chain_getRuntimeHash"];

		for call_name in &possible_calls {
			match self.rpc_client.request::<serde_json::Value, [(); 0]>(call_name, []).await {
				Ok(result) => {
					log_verbose!("✅ Found runtime hash via {}", call_name);
					if let Some(hash) = result.as_str() {
						return Ok(Some(hash.to_string()));
					} else if let Some(hash_obj) = result.get("hash") {
						if let Some(hash) = hash_obj.as_str() {
							return Ok(Some(hash.to_string()));
						}
					}
				},
				Err(_e) => {
					log_verbose!("❌ {} failed: {:?}", call_name, _e);
				},
			}
		}

		log_verbose!("⚠️  No runtime hash RPC call available");
		Ok(None)
	}
}

/// Scheme-aware subxt signer (ML-DSA-65 or ML-DSA-87).
///
/// Pairs are boxed: Dilithium secret material is multi‑KB, and an unboxed enum
/// trips `clippy::large_enum_variant`.
pub enum QuantusSigner {
	MlDsa65(Box<qp_dilithium_crypto::types::Dilithium65Pair>),
	MlDsa87(Box<qp_dilithium_crypto::types::Dilithium87Pair>),
}

impl subxt::tx::Signer<ChainConfig> for QuantusSigner {
	fn account_id(&self) -> <ChainConfig as Config>::AccountId {
		use sp_core::Pair;
		match self {
			Self::MlDsa65(pair) =>
				<qp_dilithium_crypto::types::Dilithium65Public as IdentifyAccount>::into_account(
					pair.public(),
				),
			Self::MlDsa87(pair) =>
				<qp_dilithium_crypto::types::Dilithium87Public as IdentifyAccount>::into_account(
					pair.public(),
				),
		}
	}

	fn sign(&self, signer_payload: &[u8]) -> <ChainConfig as Config>::Signature {
		match self {
			Self::MlDsa65(pair) => DilithiumSignatureScheme::Dilithium65(
				crate::chain::signing::sign_ml_dsa_65(pair, signer_payload),
			),
			Self::MlDsa87(pair) => DilithiumSignatureScheme::Dilithium87(
				crate::chain::signing::sign_ml_dsa_87(pair, signer_payload),
			),
		}
	}
}

impl subxt::tx::Signer<ChainConfig> for qp_dilithium_crypto::types::Dilithium87Pair {
	fn account_id(&self) -> <ChainConfig as Config>::AccountId {
		use sp_core::Pair;
		<qp_dilithium_crypto::types::Dilithium87Public as IdentifyAccount>::into_account(
			self.public(),
		)
	}

	fn sign(&self, signer_payload: &[u8]) -> <ChainConfig as Config>::Signature {
		DilithiumSignatureScheme::Dilithium87(crate::chain::signing::sign_ml_dsa_87(
			self,
			signer_payload,
		))
	}
}

impl subxt::tx::Signer<ChainConfig> for qp_dilithium_crypto::types::Dilithium65Pair {
	fn account_id(&self) -> <ChainConfig as Config>::AccountId {
		use sp_core::Pair;
		<qp_dilithium_crypto::types::Dilithium65Public as IdentifyAccount>::into_account(
			self.public(),
		)
	}

	fn sign(&self, signer_payload: &[u8]) -> <ChainConfig as Config>::Signature {
		DilithiumSignatureScheme::Dilithium65(crate::chain::signing::sign_ml_dsa_65(
			self,
			signer_payload,
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn quantus_client_new_redacts_userinfo_in_invalid_url_error() {
		let secret = format!(
			"rpc-token-{}-{}",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.expect("clock must be after unix epoch")
				.as_nanos()
		);
		let attacker_controlled_url = format!("https://api-user:{secret}@rpc.example.invalid/ws");

		let error = match QuantusClient::new(&attacker_controlled_url).await {
			Ok(_) => panic!("non-WebSocket scheme must fail"),
			Err(error) => error,
		};
		let diagnostic = error.to_string();

		assert!(
			!diagnostic.contains(&secret),
			"NetworkError must not expose URL userinfo; diagnostic was: {diagnostic}"
		);
		assert!(
			!diagnostic.contains(&format!("api-user:{secret}")),
			"NetworkError must not expose raw credentialed URL; diagnostic was: {diagnostic}"
		);
		assert!(
			diagnostic.contains("rpc.example.invalid"),
			"sanitized host should remain visible; diagnostic was: {diagnostic}"
		);
	}

	#[test]
	fn sanitize_url_for_diagnostics_strips_userinfo() {
		assert_eq!(
			QuantusClient::sanitize_url_for_diagnostics("wss://user:pass@rpc.example.com/path?q=1"),
			"wss://rpc.example.com/path?q=1"
		);
		assert_eq!(
			QuantusClient::sanitize_url_for_diagnostics("ws://token@localhost:9944"),
			"ws://localhost:9944"
		);
		assert_eq!(
			QuantusClient::sanitize_url_for_diagnostics("wss://rpc.example.com"),
			"wss://rpc.example.com"
		);
	}

	#[test]
	fn interpret_account_nonce_distinguishes_absent_account() {
		// #159454/#159455: absence must not be indistinguishable from a real nonce-0 account.
		assert_eq!(QuantusClient::interpret_account_nonce(None), (0, false));
		assert_eq!(QuantusClient::interpret_account_nonce(Some(0)), (0, true));
		assert_eq!(QuantusClient::interpret_account_nonce(Some(7)), (7, true));
	}
}
