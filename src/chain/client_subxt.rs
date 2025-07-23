//! Common SubXT client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing SubXT clients
//! across all CLI SubXT modules.

use crate::{chain::types::ChainConfig, error::QuantusError, log_verbose};
use sp_core::ByteArray;
use sp_runtime::traits::IdentifyAccount;
use subxt::OnlineClient;

// Removed SubxtClient struct - using OnlineClient<ChainConfig> directly

/// Common SubXT client creation function
///
/// This function is used by all SubXT CLI modules to create a connection to the Quantus node.
/// It provides consistent error handling and logging across all SubXT implementations.
pub async fn create_subxt_client(
    node_url: &str,
) -> crate::error::Result<OnlineClient<ChainConfig>> {
    log_verbose!("🔗 Connecting to Quantus node with subxt: {}", node_url);

    let client = OnlineClient::<ChainConfig>::from_url(node_url)
        .await
        .map_err(|e| {
            QuantusError::NetworkError(format!("Failed to connect with subxt: {:?}", e))
        })?;

    log_verbose!("✅ Connected to Quantus node successfully with subxt!");

    Ok(client)
}

// Implement subxt::tx::Signer for ResonancePair
impl subxt::tx::Signer<crate::chain::types::ChainConfig>
    for dilithium_crypto::types::ResonancePair
{
    fn account_id(&self) -> <crate::chain::types::ChainConfig as subxt::Config>::AccountId {
        // Convert ResonancePair to AccountId using the same logic as QuantumKeyPair
        let resonance_public =
            dilithium_crypto::types::ResonancePublic::from_slice(&self.public.as_slice())
                .expect("Invalid public key");
        let account_id =
            <dilithium_crypto::types::ResonancePublic as IdentifyAccount>::into_account(
                resonance_public,
            );
        account_id
    }

    fn sign(
        &self,
        signer_payload: &[u8],
    ) -> <crate::chain::types::ChainConfig as subxt::Config>::Signature {
        // Use the sign method from the trait implemented for ResonancePair
        // sp_core::Pair::sign returns ResonanceSignatureWithPublic, which we need to wrap in ResonanceSignatureScheme
        let signature_with_public =
            <dilithium_crypto::types::ResonancePair as sp_core::Pair>::sign(self, signer_payload);
        dilithium_crypto::ResonanceSignatureScheme::Resonance(signature_with_public)
    }
}
