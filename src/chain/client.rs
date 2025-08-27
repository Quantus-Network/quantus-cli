//! Common client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing clients
//! across all CLI modules.

use crate::{error::QuantusError, log_verbose};
use dilithium_crypto::types::DilithiumSignatureScheme;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use poseidon_resonance::PoseidonHasher;
use sp_core::{crypto::AccountId32, ByteArray};
use sp_runtime::{traits::IdentifyAccount, MultiAddress};
use std::{sync::Arc, time::Duration};
use subxt::{
	backend::rpc::RpcClient,
	config::{substrate::SubstrateHeader, DefaultExtrinsicParams},
	Config, OnlineClient,
};
use subxt_metadata::Metadata as SubxtMetadata;

#[derive(Debug, Clone, Copy)]
pub struct SubxtPoseidonHasher;

impl subxt::config::Hasher for SubxtPoseidonHasher {
	type Output = sp_core::H256;

	fn new(_metadata: &SubxtMetadata) -> Self {
		SubxtPoseidonHasher
	}

	fn hash(&self, bytes: &[u8]) -> Self::Output {
		<PoseidonHasher as sp_runtime::traits::Hash>::hash(bytes)
	}
}

/// Configuration of the chain
pub enum ChainConfig {}
impl Config for ChainConfig {
	type AccountId = AccountId32;
	type Address = MultiAddress<Self::AccountId, ()>;
	type Signature = DilithiumSignatureScheme;
	type Hasher = SubxtPoseidonHasher;
	type Header = SubstrateHeader<u32, SubxtPoseidonHasher>;
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
	/// Create a new QuantusClient by connecting to the specified node URL
	pub async fn new(node_url: &str) -> crate::error::Result<Self> {
		log_verbose!("🔗 Connecting to Quantus node: {}", node_url);

		// Validate URL format and provide helpful error messages
		if !node_url.starts_with("ws://") && !node_url.starts_with("wss://") {
			return Err(QuantusError::NetworkError(format!(
                "Invalid WebSocket URL: '{node_url}'. URL must start with 'ws://' (unsecured) or 'wss://' (secured)"
            )));
		}

		// Provide helpful hints for common URL issues
		if node_url.starts_with("ws://") &&
			(node_url.contains("a.i.res.fm") || node_url.contains("a.t.res.fm"))
		{
			log_verbose!(
				"💡 Hint: Remote nodes typically require secure WebSocket connections (wss://)"
			);
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
                let error_str = format!("{e:?}");
                let error_msg = if error_str.contains("TimedOut") || error_str.contains("timed out") {
                    if node_url.starts_with("ws://") && (node_url.contains("a.i.res.fm") || node_url.contains("a.t.res.fm")) {
                        format!(
                            "Connection timed out. This remote node requires secure WebSocket connections (wss://). Try using 'wss://{}' instead of 'ws://{}'",
                            node_url.strip_prefix("ws://").unwrap_or(node_url),
                            node_url.strip_prefix("ws://").unwrap_or(node_url)
                        )
                    } else {
                        format!("Connection timed out. Please check if the node is running and accessible at: {node_url}")
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

		let account_info = storage_at.fetch_or_default(&storage_addr).await?;

		log_verbose!("✅ Nonce from best block: {}", account_info.nonce);
		Ok(account_info.nonce as u64)
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
				Err(e) => {
					log_verbose!("❌ {} failed: {:?}", call_name, e);
				},
			}
		}

		log_verbose!("⚠️  No runtime hash RPC call available");
		Ok(None)
	}
}

// Implement subxt::tx::Signer for ResonancePair
impl subxt::tx::Signer<ChainConfig> for dilithium_crypto::types::DilithiumPair {
	fn account_id(&self) -> <ChainConfig as Config>::AccountId {
		let resonance_public =
			dilithium_crypto::types::DilithiumPublic::from_slice(self.public.as_slice())
				.expect("Invalid public key");
		<dilithium_crypto::types::DilithiumPublic as IdentifyAccount>::into_account(
			resonance_public,
		)
	}

	fn sign(&self, signer_payload: &[u8]) -> <ChainConfig as Config>::Signature {
		// Use the sign method from the trait implemented for ResonancePair
		// sp_core::Pair::sign returns ResonanceSignatureWithPublic, which we need to wrap in
		// ResonanceSignatureScheme
		let signature_with_public =
			<dilithium_crypto::types::DilithiumPair as sp_core::Pair>::sign(self, signer_payload);
		dilithium_crypto::types::DilithiumSignatureScheme::Dilithium(signature_with_public)
	}
}
