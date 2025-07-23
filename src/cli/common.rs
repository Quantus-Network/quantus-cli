//! Common SubXT utilities and functions shared across CLI commands
use crate::{chain::client::ChainConfig, error::Result, log_verbose};
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::OnlineClient;

/// Get fresh nonce for account using direct storage query to avoid cache
/// This function ensures we always get the latest nonce from the chain
/// to avoid "Transaction is outdated" errors
pub async fn get_fresh_nonce(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &crate::wallet::QuantumKeyPair,
) -> Result<u64> {
    let from_account_id = AccountId32::from_ss58check(&from_keypair.to_account_id_ss58check())
        .map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Invalid from address: {:?}", e))
        })?;

    let nonce = client
        .tx()
        .account_nonce(&from_account_id)
        .await
        .map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Failed to get account nonce: {:?}",
                e
            ))
        })?;

    log_verbose!("🔢 Using fresh nonce from tx API: {}", nonce);
    Ok(nonce)
}
