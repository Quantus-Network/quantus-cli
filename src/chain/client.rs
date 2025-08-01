//! Common client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing clients
//! across all CLI modules.

use crate::{error::QuantusError, log_verbose};
use dilithium_crypto::ResonanceSignatureScheme;
use jsonrpsee::ws_client::{WsClient, WsClientBuilder};
use poseidon_resonance::PoseidonHasher;
use sp_core::crypto::AccountId32;
use sp_core::ByteArray;
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::MultiAddress;
use std::sync::Arc;
use std::time::Duration;
use subxt::backend::rpc::RpcClient;
use subxt::config::substrate::SubstrateHeader;
use subxt::config::DefaultExtrinsicParams;
use subxt::{Config, OnlineClient};
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
    type Address = MultiAddress<Self::AccountId, u32>;
    type Signature = ResonanceSignatureScheme;
    type Hasher = SubxtPoseidonHasher;
    type Header = SubstrateHeader<u32, SubxtPoseidonHasher>;
    type AssetId = u32;
    type ExtrinsicParams = DefaultExtrinsicParams<Self>;
}

/// Wrapper around OnlineClient that also stores the node URL and RPC client
pub struct QuantusClient {
    client: OnlineClient<ChainConfig>,
    rpc_client: Arc<WsClient>,
    node_url: String,
}

impl QuantusClient {
    /// Create a new QuantusClient by connecting to the specified node URL
    pub async fn new(node_url: &str) -> crate::error::Result<Self> {
        log_verbose!("🔗 Connecting to Quantus node: {}", node_url);

        // Create WS client with custom timeouts
        let ws_client = WsClientBuilder::default()
            // TODO: Make these configurable in a separate change
            .connection_timeout(Duration::from_secs(30))
            .request_timeout(Duration::from_secs(30))
            .build(node_url)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to create RPC client: {:?}", e))
            })?;

        // Wrap WS client in Arc for sharing
        let ws_client = Arc::new(ws_client);

        // Create RPC client wrapper for subxt
        let rpc_client = RpcClient::new(ws_client.clone());

        // Create SubXT client using the configured RPC client
        let client = OnlineClient::<ChainConfig>::from_rpc_client(rpc_client)
            .await
            .map_err(|e| QuantusError::NetworkError(format!("Failed to connect: {:?}", e)))?;

        log_verbose!("✅ Connected to Quantus node successfully!");

        Ok(QuantusClient {
            client,
            rpc_client: ws_client,
            node_url: node_url.to_string(),
        })
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
                    "Failed to fetch latest block hash: {:?}",
                    e
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
        log_verbose!(
            "📦 Latest block hash for nonce query: {:?}",
            latest_block_hash
        );

        // Convert sp_core::AccountId32 to subxt::utils::AccountId32
        let account_bytes: [u8; 32] = *account_id.as_ref();
        let subxt_account_id = subxt::utils::AccountId32::from(account_bytes);

        // Use SubXT's storage API to query nonce at the best block
        use crate::chain::quantus_subxt::api;
        let storage_addr = api::storage().system().account(subxt_account_id);

        let storage_at = self.client.storage().at(latest_block_hash);

        let account_info = storage_at
            .fetch_or_default(&storage_addr)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to fetch account info from best block: {:?}",
                    e
                ))
            })?;

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
                    "Failed to fetch genesis hash: {:?}",
                    e
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
                    "Failed to fetch runtime version: {:?}",
                    e
                ))
            })?;

        let spec_version = runtime_version["specVersion"].as_u64().ok_or_else(|| {
            crate::error::QuantusError::NetworkError("Failed to parse spec version".to_string())
        })? as u32;

        let transaction_version =
            runtime_version["transactionVersion"]
                .as_u64()
                .ok_or_else(|| {
                    crate::error::QuantusError::NetworkError(
                        "Failed to parse transaction version".to_string(),
                    )
                })? as u32;

        log_verbose!(
            "🔧 Runtime version: spec={}, tx={}",
            spec_version,
            transaction_version
        );
        Ok((spec_version, transaction_version))
    }

    /// Get chain parameters including era information
    pub async fn get_chain_params(&self) -> crate::error::Result<()> {
        log_verbose!("🔍 Fetching chain parameters via RPC...");

        // Get genesis hash
        let genesis_hash = self.get_genesis_hash().await?;
        log_verbose!("🧬 Genesis hash: {:?}", genesis_hash);

        // Get runtime version
        let (spec_version, transaction_version) = self.get_runtime_version().await?;
        log_verbose!("🔧 Spec version: {}", spec_version);
        log_verbose!("🔄 Transaction version: {}", transaction_version);

        // Try to get era information from chain state
        use jsonrpsee::core::client::ClientT;
        let chain_state: serde_json::Value = self
            .rpc_client
            .request::<serde_json::Value, [(); 0]>("state_getRuntimeVersion", [])
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to fetch runtime version: {:?}",
                    e
                ))
            })?;

        log_verbose!("📋 Full runtime info: {:?}", chain_state);

        // Try to get chain properties
        let chain_props: serde_json::Value = self
            .rpc_client
            .request::<serde_json::Value, [(); 0]>("system_properties", [])
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to fetch chain properties: {:?}",
                    e
                ))
            })?;

        log_verbose!("🔗 Chain properties: {:?}", chain_props);

        // Try to get transaction parameters
        let tx_params: serde_json::Value = self
            .rpc_client
            .request::<serde_json::Value, [(); 0]>("state_getRuntimeVersion", [])
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to fetch transaction params: {:?}",
                    e
                ))
            })?;

        log_verbose!("📋 Transaction params: {:?}", tx_params);

        // Try to get current block header to understand era
        let current_block: serde_json::Value = self
            .rpc_client
            .request::<serde_json::Value, [(); 0]>("chain_getHeader", [])
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to fetch current block: {:?}",
                    e
                ))
            })?;

        log_verbose!("📦 Current block: {:?}", current_block);

        // Try to get era information from block header
        if let Some(block_number_str) = current_block["number"].as_str() {
            if let Ok(block_number) = u64::from_str_radix(&block_number_str[2..], 16) {
                log_verbose!("📊 Current block number: {}", block_number);

                // Calculate era based on block number
                // For mortal transactions, era is typically calculated as:
                // period = 64 blocks (typical for Substrate)
                // phase = block_number % period
                let period = 64u64;
                let phase = block_number % period;
                log_verbose!("⏰ Calculated era: period={}, phase={}", period, phase);
                log_verbose!("💡 For mortal transactions, use Era::Mortal(period, phase)");
                log_verbose!("💡 For immortal transactions, use Era::Immortal");
            }
        }

        Ok(())
    }
}

// Implement subxt::tx::Signer for ResonancePair
impl subxt::tx::Signer<ChainConfig> for dilithium_crypto::types::ResonancePair {
    fn account_id(&self) -> <ChainConfig as Config>::AccountId {
        let resonance_public =
            dilithium_crypto::types::ResonancePublic::from_slice(&self.public.as_slice())
                .expect("Invalid public key");
        let account_id =
            <dilithium_crypto::types::ResonancePublic as IdentifyAccount>::into_account(
                resonance_public,
            );
        account_id
    }

    fn sign(&self, signer_payload: &[u8]) -> <ChainConfig as Config>::Signature {
        // Use the sign method from the trait implemented for ResonancePair
        // sp_core::Pair::sign returns ResonanceSignatureWithPublic, which we need to wrap in ResonanceSignatureScheme
        let signature_with_public =
            <dilithium_crypto::types::ResonancePair as sp_core::Pair>::sign(self, signer_payload);
        dilithium_crypto::ResonanceSignatureScheme::Resonance(signature_with_public)
    }
}
