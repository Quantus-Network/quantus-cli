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

/// Get incremented nonce for retry scenarios
/// This is useful when a transaction fails but the chain doesn't update the nonce
pub async fn get_incremented_nonce(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &crate::wallet::QuantumKeyPair,
    base_nonce: u64,
) -> Result<u64> {
    let from_account_id = AccountId32::from_ss58check(&from_keypair.to_account_id_ss58check())
        .map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Invalid from address: {:?}", e))
        })?;

    let current_nonce = client
        .tx()
        .account_nonce(&from_account_id)
        .await
        .map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Failed to get account nonce: {:?}",
                e
            ))
        })?;

    // Use the higher of current nonce or base_nonce + 1
    let incremented_nonce = std::cmp::max(current_nonce, base_nonce + 1);
    log_verbose!(
        "🔢 Using incremented nonce: {} (base: {}, current: {})",
        incremented_nonce,
        base_nonce,
        current_nonce
    );
    Ok(incremented_nonce)
}

/// Helper function to submit transaction with nonce management and retry logic
pub async fn submit_transaction<Call>(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &crate::wallet::QuantumKeyPair,
    call: Call,
    tip: Option<u128>,
) -> crate::error::Result<subxt::utils::H256>
where
    Call: subxt::tx::Payload,
{
    let signer = from_keypair.to_subxt_signer().map_err(|e| {
        crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
    })?;

    // Retry logic with automatic nonce management
    let mut attempt = 0;
    let mut current_nonce = None;

    loop {
        attempt += 1;

        // Get fresh nonce for each attempt, or increment if we have a previous nonce
        let nonce = if let Some(prev_nonce) = current_nonce {
            // After first failure, try with incremented nonce
            let incremented_nonce = get_incremented_nonce(client, from_keypair, prev_nonce).await?;
            log_verbose!(
                "🔢 Using incremented nonce: {} (previous: {})",
                incremented_nonce,
                prev_nonce
            );
            incremented_nonce
        } else {
            // First attempt - get fresh nonce
            let fresh_nonce = get_fresh_nonce(client, from_keypair).await?;
            log_verbose!("🔢 Using fresh nonce: {}", fresh_nonce);
            fresh_nonce
        };
        current_nonce = Some(nonce);

        // Get current block for logging
        let current_block = client.blocks().at_latest().await.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Failed to get current block: {:?}",
                e
            ))
        })?;

        log_verbose!("🔗 Current block: #{}", current_block.number());

        // Create custom params with fresh nonce and optional tip
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let mut params_builder = DefaultExtrinsicParamsBuilder::new().nonce(nonce);

        if let Some(tip_amount) = tip {
            params_builder = params_builder.tip(tip_amount);
            log_verbose!("💰 Using tip: {} to increase priority", tip_amount);
        } else {
            log_verbose!("💰 No tip specified, using default priority");
        }

        let params = params_builder.build();

        // Submit the transaction with fresh nonce and optional tip
        match client.tx().sign_and_submit(&call, &signer, params).await {
            Ok(tx_hash) => {
                crate::log_verbose!("📋 Transaction submitted: {:?}", tx_hash);
                return Ok(tx_hash);
            }
            Err(e) => {
                let error_msg = format!("{:?}", e);

                // Check if it's a retryable error
                let is_retryable = error_msg.contains("Priority is too low")
                    || error_msg.contains("Transaction is outdated")
                    || error_msg.contains("Transaction is temporarily banned")
                    || error_msg.contains("Transaction has a bad signature")
                    || error_msg.contains("Invalid Transaction");

                if is_retryable && attempt < 5 {
                    log_verbose!(
                        "⚠️  Transaction error detected (attempt {}/5): {}",
                        attempt,
                        error_msg
                    );

                    // Exponential backoff: 2s, 4s, 8s, 16s
                    let delay = std::cmp::min(2u64.pow(attempt as u32), 16);
                    log_verbose!("⏳ Waiting {} seconds before retry...", delay);
                    tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                    continue;
                } else {
                    log_verbose!("❌ Final error after {} attempts: {}", attempt, error_msg);
                    return Err(crate::error::QuantusError::NetworkError(format!(
                        "Failed to submit transaction: {:?}",
                        e
                    )));
                }
            }
        }
    }
}
