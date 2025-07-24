//! Common client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing clients
//! across all CLI modules.

use crate::{error::QuantusError, log_verbose};
use dilithium_crypto::ResonanceSignatureScheme;
use poseidon_resonance::PoseidonHasher;
use sp_core::crypto::AccountId32;
use sp_core::ByteArray;
use sp_runtime::traits::IdentifyAccount;
use sp_runtime::MultiAddress;
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

/// Common client creation function
///
/// This function is used by all CLI modules to create a connection to the Quantus node.
/// It provides consistent error handling and logging across all implementations.
pub async fn create_subxt_client(
    node_url: &str,
) -> crate::error::Result<OnlineClient<ChainConfig>> {
    log_verbose!("🔗 Connecting to Quantus node: {}", node_url);

    let client = OnlineClient::<ChainConfig>::from_url(node_url)
        .await
        .map_err(|e| QuantusError::NetworkError(format!("Failed to connect: {:?}", e)))?;

    log_verbose!("✅ Connected to Quantus node successfully!");

    Ok(client)
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
        println!("signing with DILITHIUM!");
        // Use the sign method from the trait implemented for ResonancePair
        // sp_core::Pair::sign returns ResonanceSignatureWithPublic, which we need to wrap in ResonanceSignatureScheme
        let signature_with_public =
            <dilithium_crypto::types::ResonancePair as sp_core::Pair>::sign(self, signer_payload);
        dilithium_crypto::ResonanceSignatureScheme::Resonance(signature_with_public)
    }
}
