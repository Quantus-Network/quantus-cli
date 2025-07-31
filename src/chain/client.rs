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
