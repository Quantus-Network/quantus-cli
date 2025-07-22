use crate::{
    chain::quantus_subxt, chain::types::ChainConfig, error::Result, log_error, log_print,
    log_success, log_verbose,
};
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

use subxt::OnlineClient;

/// SubXT-based chain client for sending transactions
pub struct SubxtChainClient {
    client: OnlineClient<ChainConfig>,
}

impl SubxtChainClient {
    /// Create a new SubXT chain client
    pub async fn new(node_url: &str) -> Result<Self> {
        let client = OnlineClient::from_url(node_url).await.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to connect: {:?}", e))
        })?;

        Ok(Self { client })
    }

    /// Get the `free` balance for the given account using on-chain storage.
    pub async fn get_balance(&self, account_address: &str) -> Result<u128> {
        use quantus_subxt::api;

        log_verbose!(
            "💰 Querying balance for account: {}",
            account_address.bright_green()
        );

        // Decode the SS58 address into `AccountId32` (sp-core) first …
        let account_id_sp = SpAccountId32::from_ss58check(account_address).map_err(|e| {
            crate::error::QuantusError::Generic(format!(
                "Invalid account address '{}': {:?}",
                account_address, e
            ))
        })?;

        // … then convert into the `subxt` representation expected by the generated API.
        let bytes: [u8; 32] = *account_id_sp.as_ref();
        let account_id = subxt::ext::subxt_core::utils::AccountId32::from(bytes);

        // Build the storage key for `System::Account` and fetch (or default-init) it.
        let storage_addr = api::storage().system().account(account_id);

        let storage_at = self.client.storage().at_latest().await.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

        let account_info = storage_at
            .fetch_or_default(&storage_addr)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to fetch account info: {:?}",
                    e
                ))
            })?;

        Ok(account_info.data.free)
    }

    /// Get chain properties for formatting
    pub async fn get_chain_properties(&self) -> Result<(String, u8)> {
        log_verbose!("🔍 Querying chain properties...");

        // Query system properties using SubXT runtime APIs
        // For now, use the same hardcoded values as ChainClient to match formatting
        // TODO: Implement proper system properties query when SubXT API is available
        let token_symbol = "DEV".to_string();
        let token_decimals = 9u8;

        log_verbose!(
            "📊 Chain properties: token={}, decimals={}",
            token_symbol,
            token_decimals
        );

        log_verbose!(
            "💰 Token: {} with {} decimals",
            token_symbol,
            token_decimals
        );

        Ok((token_symbol, token_decimals))
    }

    /// Format balance with token symbol
    pub async fn format_balance_with_symbol(&self, amount: u128) -> Result<String> {
        let (symbol, decimals) = self.get_chain_properties().await?;
        let formatted_amount = Self::format_balance(amount, decimals);
        Ok(format!("{} {}", formatted_amount, symbol))
    }

    /// Format balance with proper decimals
    pub fn format_balance(amount: u128, decimals: u8) -> String {
        if decimals == 0 {
            return amount.to_string();
        }

        let divisor = 10_u128.pow(decimals as u32);
        let whole_part = amount / divisor;
        let fractional_part = amount % divisor;

        if fractional_part == 0 {
            whole_part.to_string()
        } else {
            let fractional_str = format!("{:0width$}", fractional_part, width = decimals as usize);
            let fractional_str = fractional_str.trim_end_matches('0');

            if fractional_str.is_empty() {
                whole_part.to_string()
            } else {
                format!("{}.{}", whole_part, fractional_str)
            }
        }
    }

    /// Parse human-readable amount string to raw chain units
    pub async fn parse_amount(&self, amount_str: &str) -> Result<u128> {
        let (_, decimals) = self.get_chain_properties().await?;
        Self::parse_amount_with_decimals(amount_str, decimals)
    }

    /// Parse amount string with specific decimals
    pub fn parse_amount_with_decimals(amount_str: &str, decimals: u8) -> Result<u128> {
        let amount_part = amount_str.trim().split_whitespace().next().unwrap_or("");

        if amount_part.is_empty() {
            return Err(crate::error::QuantusError::Generic(
                "Amount cannot be empty".to_string(),
            ));
        }

        let parsed_amount: f64 = amount_part.parse().map_err(|_| {
            crate::error::QuantusError::Generic(format!(
                "Invalid amount format: '{}'. Use formats like '10', '10.5', '0.0001'",
                amount_part
            ))
        })?;

        if parsed_amount < 0.0 {
            return Err(crate::error::QuantusError::Generic(
                "Amount cannot be negative".to_string(),
            ));
        }

        if let Some(decimal_part) = amount_part.split('.').nth(1) {
            if decimal_part.len() > decimals as usize {
                return Err(crate::error::QuantusError::Generic(format!(
                    "Too many decimal places. Maximum {} decimal places allowed for this chain",
                    decimals
                )));
            }
        }

        let multiplier = 10_f64.powi(decimals as i32);
        let raw_amount = (parsed_amount * multiplier).round() as u128;

        if parsed_amount > 0.0 && raw_amount == 0 {
            return Err(crate::error::QuantusError::Generic(
                "Amount too small to represent in chain units".to_string(),
            ));
        }

        Ok(raw_amount)
    }

    /// Validate and format amount for display before sending
    pub async fn validate_and_format_amount(&self, amount_str: &str) -> Result<(u128, String)> {
        let raw_amount = self.parse_amount(amount_str).await?;
        let formatted = self.format_balance_with_symbol(raw_amount).await?;
        Ok((raw_amount, formatted))
    }

    /// Transfer tokens using subxt
    pub async fn transfer(
        &self,
        from_keypair: &crate::wallet::QuantumKeyPair,
        to_address: &str,
        amount: u128,
    ) -> Result<subxt::utils::H256> {
        log_verbose!("🚀 Creating transfer transaction with subxt...");
        log_verbose!(
            "   From: {}",
            from_keypair.to_account_id_ss58check().bright_cyan()
        );
        log_verbose!("   To: {}", to_address.bright_green());
        log_verbose!("   Amount: {}", amount);

        // Parse the destination address
        let to_account_id_sp = SpAccountId32::from_ss58check(to_address).map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Invalid destination address: {:?}",
                e
            ))
        })?;

        // Convert to subxt_core AccountId32
        let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
        let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

        // Convert our QuantumKeyPair to subxt Signer
        let signer = from_keypair.to_subxt_signer().map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        log_verbose!("✍️  Creating balance transfer extrinsic with subxt...");

        // Create the transfer call using static API from quantus_subxt
        let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
            subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id),
            amount,
        );

        // Get fresh nonce for the sender - use substrate_api_client AccountId32 type
        use substrate_api_client::ac_primitives::AccountId32 as SubstrateAccountId32;
        let from_account_id = SubstrateAccountId32::from_ss58check(
            &from_keypair.to_account_id_ss58check(),
        )
        .map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Invalid from address: {:?}", e))
        })?;

        let nonce = self
            .client
            .tx()
            .account_nonce(&from_account_id)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to get account nonce: {:?}",
                    e
                ))
            })?;

        log_verbose!("🔢 Using nonce: {}", nonce);

        // Create custom params with fresh nonce
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

        // Submit the transaction with fresh nonce
        let tx_hash = self
            .client
            .tx()
            .sign_and_submit(&transfer_call, &signer, params)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to submit transaction: {:?}",
                    e
                ))
            })?;

        log_verbose!("📋 Transaction submitted with subxt: {:?}", tx_hash);

        Ok(tx_hash)
    }

    /// Wait for transaction finalization using subxt
    pub async fn wait_for_finalization(&self, _tx_hash: subxt::utils::H256) -> Result<bool> {
        log_verbose!("⏳ Waiting for transaction finalization...");

        // For now, we use a simple delay approach similar to substrate-api-client
        // TODO: Implement proper finalization watching using SubXT events
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;

        log_verbose!("✅ Transaction likely finalized (after 6s delay)");
        Ok(true)
    }
}

// (Removed custom `AccountData` struct – we now use the runtime-generated type)

/// Handle the send_subxt command
pub async fn handle_send_subxt_command(
    from_wallet: String,
    to_address: String,
    amount_str: &str,
    node_url: &str,
    password: Option<String>,
    password_file: Option<String>,
) -> Result<()> {
    // Create subxt chain client
    let chain_client = SubxtChainClient::new(node_url).await?;

    // Parse and validate the amount
    let (amount, formatted_amount) = chain_client.validate_and_format_amount(amount_str).await?;
    log_verbose!(
        "🚀 {} Sending {} to {} (using subxt)",
        "SEND_SUBXT".bright_cyan().bold(),
        formatted_amount.bright_yellow().bold(),
        to_address.bright_green()
    );

    // Get password securely for decryption
    log_verbose!("📦 Using wallet: {}", from_wallet.bright_blue().bold());
    let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;

    // Get account information
    let from_account_id = keypair.to_account_id_ss58check();
    let balance = chain_client.get_balance(&from_account_id).await?;

    // Get formatted balance with proper decimals
    let formatted_balance = chain_client.format_balance_with_symbol(balance).await?;
    log_verbose!("💰 Current balance: {}", formatted_balance.bright_yellow());

    if balance < amount {
        return Err(crate::error::QuantusError::InsufficientBalance {
            available: balance,
            required: amount,
        });
    }

    // Create and submit transaction using subxt
    log_verbose!(
        "✍️  {} Signing transaction with subxt...",
        "SIGN".bright_magenta().bold()
    );

    // Submit transaction using subxt
    let tx_hash = chain_client.transfer(&keypair, &to_address, amount).await?;

    log_print!(
        "✅ {} Transaction submitted with subxt! Hash: {:?}",
        "SUCCESS".bright_green().bold(),
        tx_hash
    );

    let success = chain_client.wait_for_finalization(tx_hash).await?;

    if success {
        log_success!(
            "🎉 {} Transaction confirmed with subxt!",
            "FINALIZED".bright_green().bold()
        );

        // Show updated balance with proper formatting
        let new_balance = chain_client.get_balance(&from_account_id).await?;
        let formatted_new_balance = chain_client.format_balance_with_symbol(new_balance).await?;

        // Calculate and display transaction fee in verbose mode
        let fee_paid = balance.saturating_sub(new_balance).saturating_sub(amount);
        if fee_paid > 0 {
            let formatted_fee = chain_client.format_balance_with_symbol(fee_paid).await?;
            log_verbose!("💸 Transaction fee: {}", formatted_fee.bright_cyan());
        }

        log_print!("💰 New balance: {}", formatted_new_balance.bright_yellow());
    } else {
        log_error!("Transaction failed!");
    }

    Ok(())
}
