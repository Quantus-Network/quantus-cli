//! Common SubXT utilities and functions shared across CLI commands
use crate::{chain::client::ChainConfig, error::Result, log_verbose};
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::OnlineClient;

/// Resolve address - if it's a wallet name, return the wallet's address
/// If it's already an SS58 address, return it as is
pub fn resolve_address(address_or_wallet_name: &str) -> Result<String> {
    // First, try to parse as SS58 address
    if let Ok(_) = AccountId32::from_ss58check(address_or_wallet_name) {
        // It's a valid SS58 address, return as is
        return Ok(address_or_wallet_name.to_string());
    }

    // If not a valid SS58 address, try to find it as a wallet name
    let wallet_manager = crate::wallet::WalletManager::new()?;
    if let Some(wallet_address) = wallet_manager.find_wallet_address(address_or_wallet_name)? {
        log_verbose!(
            "🔍 Found wallet '{}' with address: {}",
            address_or_wallet_name.bright_cyan(),
            wallet_address.bright_green()
        );
        return Ok(wallet_address);
    }

    // Neither a valid SS58 address nor a wallet name
    Err(crate::error::QuantusError::Generic(format!(
        "Invalid destination: '{}' is neither a valid SS58 address nor a known wallet name",
        address_or_wallet_name
    )))
}

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
