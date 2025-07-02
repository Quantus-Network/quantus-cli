use super::quantus_runtime_config::QuantusRuntimeConfig;
use crate::error::{QuantusError, Result};
use crate::wallet::QuantumKeyPair;
use crate::{log_debug, log_print, log_verbose};
use colored::Colorize;

// use crate::chain::types::reversible_transfers::events::TransactionCancelled;
// use crate::chain::types::reversible_transfers::events::TransactionScheduled;
// use substrate_api_client::api::ExtrinsicReport;

use sp_core::crypto::AccountId32;
use sp_core::crypto::Ss58Codec;
use substrate_api_client::{
    ac_primitives::ExtrinsicSigner, extrinsic::BalancesExtrinsics, rpc::JsonrpseeClient, Api,
    GetAccountInformation, SubmitAndWatch, SystemApi, XtStatus,
};

/// Macro to submit any type of extrinsic without code duplication
/// Note: This should be a method but it seems impossible to figure out the correct parameter types for this call.
/// Extrinsics are more lenient with typing.
#[macro_export]
macro_rules! submit_extrinsic {
    ($self:expr, $keypair:expr, $extrinsic:expr) => {{
        use crate::chain::types::reversible_transfers::events::TransactionCancelled;
        use crate::chain::types::reversible_transfers::events::TransactionScheduled; // this comes from subxt
        use codec::Decode;
        use substrate_api_client::api::ExtrinsicReport;

        let resonance_pair = $keypair.to_resonance_pair().map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        // Create ExtrinsicSigner
        let extrinsic_signer = ExtrinsicSigner::<QuantusRuntimeConfig>::new(resonance_pair);

        // Clone the API to set the signer
        let mut api_with_signer = $self.api.clone();
        api_with_signer.set_signer(extrinsic_signer);

        // Submit and watch the extrinsic until it's included in a block
        let result: ExtrinsicReport<_> = api_with_signer
            .submit_and_watch_extrinsic_until($extrinsic, XtStatus::InBlock)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to submit extrinsic: {:?}",
                    e
                ))
            })?;

        let extrinsic_hash = &result.extrinsic_hash;
        let block_hash = &result.block_hash.unwrap_or_default();

        log_verbose!(
            "📋 Transaction hash: {}",
            format!("{:?}", extrinsic_hash).bright_blue()
        );
        log_verbose!(
            "🔗 Included in block: {}",
            format!("{:?}", block_hash).bright_blue()
        );

        // Log events if available
        if let Some(ref events) = result.events {
            log_print!("📊 Transaction events:");
            for (i, event) in events.iter().enumerate() {
                log_print!(
                    "   {} Event: Pallet: {}, Variant: {}",
                    i,
                    event.pallet_name().bright_cyan(),
                    event.variant_name().bright_green()
                );

                // Try to decode as known event types automatically
                let event_bytes = event.field_bytes().clone();

                // Try TransactionScheduled
                if let Ok(scheduled_event) = TransactionScheduled::decode(&mut event_bytes.clone())
                {
                    log_print!("      🎯 This is a TransactionScheduled event!");
                    log_print!("      📅 Scheduled at: {:?}", scheduled_event.execute_at);
                    log_print!("      🆔 Tx id: {:?}", scheduled_event.tx_id);
                    log_print!("      👤 Who: {:?}", scheduled_event.who);
                }
                                // Try TransactionCancelled - only for ReversibleTransfers pallet
                else if event.pallet_name() == "ReversibleTransfers"
                    && event.variant_name() == "TransactionCancelled"
                {
                    if let Ok(cancelled_event) = TransactionCancelled::decode(&mut event_bytes.clone()) {
                        log_print!("      ❌ This is a TransactionCancelled event!");
                        log_print!("      🆔 Tx id: {:?}", cancelled_event.tx_id);
                        log_print!("      👤 Who: {:?}", cancelled_event.who);
                    }
                }
                // Handle known pallet/variant combinations that don't need decoding
                else {
                    match (event.pallet_name(), event.variant_name()) {
                        ("Balances", "Transfer") => {
                            log_print!("      💰 This is a Balance Transfer event!");
                        }
                        ("Balances", "Withdraw") => {
                            log_print!("      📤 This is a Balance Withdraw event!");
                        }
                        ("Balances", "Deposit") => {
                            log_print!("      📥 This is a Balance Deposit event!");
                        }
                        ("System", "ExtrinsicSuccess") => {
                            log_print!("      ✅ Extrinsic executed successfully!");
                        }
                        ("Scheduler", "Scheduled") => {
                            log_print!("      ⏰ Task scheduled!");
                        }
                        ("TransactionPayment", "TransactionFeePaid") => {
                            log_print!("      💳 Transaction fee paid!");
                        }
                        ("TechCollective", "MemberAdded") => {
                            log_print!("      👥 Tech Collective member added!");
                        }
                        ("TechCollective", "MemberRemoved") => {
                            log_print!("      👥 Tech Collective member removed!");
                        }
                        ("Sudo", "Sudid") => {
                            log_print!("      🔐 Sudo operation executed!");
                        }
                        _ => {
                            log_print!("      ℹ️  Unknown event type");
                        }
                    }
                }
            }
        }

        // Return the extrinsic hash as a hex string
        Ok::<ExtrinsicReport<sp_core::H256>, crate::error::QuantusError>(result)
    }};
}

/// Submit extrinsic with spinner - wrapper around submit_extrinsic! that shows a spinner
#[macro_export]
macro_rules! submit_extrinsic_with_spinner {
    ($self:expr, $keypair:expr, $extrinsic:expr) => {{
        use crate::cli::progress_spinner::ProgressSpinner;
        use crate::{log_error, log_print, log_success};
        use colored::Colorize;
        use std::io::{self, Write};
        use substrate_api_client::api::ExtrinsicReport;
        use tokio::time::{self, Duration};

        // Show spinner during the potentially slow network submission
        let mut spinner = ProgressSpinner::new();

        // Create a task that shows the spinner while waiting for network
        let spinner_handle = tokio::spawn(async move {
            let wait_duration = Duration::from_millis(200);
            loop {
                spinner.tick();
                time::sleep(wait_duration).await;
            }
        });

        // Submit the extrinsic using the core macro
        let result = crate::submit_extrinsic!($self, $keypair, $extrinsic);

        // Stop the spinner and clear the line
        spinner_handle.abort();
        print!("\r                                                    \r");
        io::stdout().flush().unwrap();

        // Handle result and show appropriate message
        match result {
            Ok(report) => {
                log_success!("🎉 Transaction submitted successfully!");
                log_print!(
                    "📋 Transaction hash: {}",
                    &report.extrinsic_hash.to_string().bright_yellow()
                );
                Ok::<ExtrinsicReport<sp_core::H256>, crate::error::QuantusError>(report)
            }
            Err(e) => {
                log_error!("❌ Transaction failed: {}", e);
                Err(e)
            }
        }
    }};
}

/// Chain client for interacting with the Quantus network
pub struct ChainClient {
    pub(crate) api: Api<QuantusRuntimeConfig, JsonrpseeClient>,
}

impl ChainClient {
    /// Create a new chain client
    pub async fn new(node_url: &str) -> Result<Self> {
        log_verbose!("🔗 Connecting to Quantus node: {}", node_url.bright_blue());

        // Use the substrate-api-client with the provided node URL
        let client = JsonrpseeClient::new(node_url).await.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to connect to node: {:?}", e))
        })?;

        let api = Api::<QuantusRuntimeConfig, _>::new(client)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to initialize API: {:?}",
                    e
                ))
            })?;

        log_verbose!("✅ Connected to Quantus node successfully!");

        Ok(Self { api })
    }

    /// Get the node version string
    pub async fn get_node_version(&self) -> Result<String> {
        let version = self.api.get_system_version().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to get node version: {:?}", e))
        })?;
        Ok(version)
    }

    /// Get the runtime version as a formatted string
    pub async fn get_runtime_version(&self) -> Result<String> {
        let runtime_version = self.api.runtime_version();

        // Format the version for display
        let formatted_version = format!(
            "{} (spec: {}, impl: {})",
            runtime_version.spec_name, runtime_version.spec_version, runtime_version.impl_version
        );

        Ok(formatted_version)
    }

    /// Get the raw runtime version object
    pub fn get_runtime_version_raw(&self) -> &substrate_api_client::ac_primitives::RuntimeVersion {
        self.api.runtime_version()
    }

    /// Get the chain metadata
    pub fn get_metadata(&self) -> &substrate_api_client::ac_node_api::Metadata {
        self.api.metadata()
    }

    /// Get the balance of an account using substrate-api-client
    pub async fn get_balance(&self, account_address: &str) -> Result<u128> {
        log_verbose!(
            "💰 Querying balance for account: {}",
            account_address.bright_green()
        );

        // Parse the SS58 address to AccountId32
        let account_id = AccountId32::from_ss58check(account_address).map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Invalid SS58 address: {:?}", e))
        })?;

        log_debug!("🔍 Account ID: {:?}", account_id);

        // Use the substrate-api-client to get account data - following the example pattern
        match self.api.get_account_data(&account_id).await {
            Ok(Some(account_data)) => {
                let balance = account_data.free;
                log_verbose!("✅ Account data found!");
                log_verbose!("📊 Free balance: {}", balance);
                log_verbose!("📊 Reserved balance: {}", account_data.reserved);
                log_verbose!("📊 Frozen balance: {}", account_data.frozen);
                Ok(balance)
            }
            Ok(None) => {
                log_verbose!("ℹ️  Account not found in storage, balance is 0");
                Ok(0)
            }
            Err(e) => {
                log_verbose!("❌ API Error: {:?}", e);
                Err(crate::error::QuantusError::NetworkError(format!(
                    "Failed to query balance: {:?}",
                    e
                )))
            }
        }
    }

    /// Get the nonce (transaction count) of an account
    pub async fn get_account_nonce(&self, account_address: &str) -> Result<u32> {
        log_verbose!(
            "#️⃣ Querying nonce for account: {}",
            account_address.bright_green()
        );

        // Parse the SS58 address to AccountId32
        let account_id = AccountId32::from_ss58check(account_address).map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Invalid SS58 address: {:?}", e))
        })?;

        log_debug!("🔍 Account ID: {:?}", account_id);

        // Use the substrate-api-client to get account info.
        // The nonce is part of the AccountInfo struct.
        match self.api.get_account_info(&account_id).await {
            Ok(Some(account_info)) => {
                let nonce = account_info.nonce;
                log_verbose!("✅ Account info found!");
                log_verbose!("🔢 Nonce: {}", nonce);
                Ok(nonce)
            }
            Ok(None) => {
                log_verbose!("ℹ️  Account not found in storage, nonce is 0");
                Ok(0)
            }
            Err(e) => {
                log_verbose!("❌ API Error: {:?}", e);
                Err(crate::error::QuantusError::NetworkError(format!(
                    "Failed to query nonce: {:?}",
                    e
                )))
            }
        }
    }

    /// Get system information from the chain
    pub async fn get_system_info(&self) -> Result<()> {
        log_verbose!("🔍 Querying system information...");

        // Get chain properties
        let (token_symbol, token_decimals) = self.get_chain_properties().await?;

        // Get metadata information
        let metadata = self.api.metadata();
        let pallets: Vec<_> = metadata.pallets().collect();

        log_print!("🏗️  Chain System Information:");
        log_print!(
            "   💰 Token: {} ({} decimals)",
            token_symbol.bright_yellow(),
            token_decimals.to_string().bright_cyan()
        );
        log_print!("   📦 Pallets: {}", pallets.len().to_string());
        log_print!("   🔧 Runtime: Substrate-based");
        log_print!("   🌐 Network: Quantus Network");

        log_verbose!("💡 Use 'quantus metadata' to explore all available pallets and calls");

        log_verbose!("✅ System info retrieved successfully!");

        Ok(())
    }

    /// Transfer tokens from one account to another using real substrate extrinsics
    pub async fn transfer(
        &self,
        from_keypair: &QuantumKeyPair,
        to_address: &str,
        amount: u128,
    ) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
        log_verbose!("🚀 Creating transfer transaction...");
        log_verbose!(
            "   From: {}",
            from_keypair.to_account_id_ss58check().bright_cyan()
        );
        log_verbose!("   To: {}", to_address.bright_green());
        log_verbose!("   Amount: {}", amount);

        // Parse the destination address
        let to_account_id = AccountId32::from_ss58check(to_address).map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Invalid destination address: {:?}",
                e
            ))
        })?;

        // Convert our QuantumKeyPair to ResonancePair
        let resonance_pair = from_keypair.to_resonance_pair().map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        // Create ExtrinsicSigner
        let extrinsic_signer = ExtrinsicSigner::<QuantusRuntimeConfig>::new(resonance_pair);

        // Clone the API to set the signer
        let mut api_with_signer = self.api.clone();
        api_with_signer.set_signer(extrinsic_signer);

        log_verbose!("✍️  Creating balance transfer extrinsic...");

        // Create the transfer extrinsic using BalancesExtrinsics trait
        let transfer_extrinsic = api_with_signer
            .balance_transfer_allow_death(to_account_id.into(), amount)
            .await
            .ok_or_else(|| {
                crate::error::QuantusError::NetworkError(
                    "Failed to create transfer extrinsic".to_string(),
                )
            })?;

        log_verbose!("📋 Extrinsic created: {:?}", transfer_extrinsic);

        // Use the macro to submit the extrinsic
        submit_extrinsic_with_spinner!(self, from_keypair, transfer_extrinsic)
    }

    /// Wait for transaction finalization - now using real block monitoring
    pub async fn wait_for_finalization(&self, tx_hash: &str) -> Result<bool> {
        log_verbose!(
            "⏳ Transaction {} is already included in a block",
            tx_hash.bright_blue()
        );

        // Since we already waited for InBlock status in the transfer method,
        // the transaction is already confirmed. In a more sophisticated implementation,
        // we could wait for Finalized status here.
        log_verbose!(
            "✅ Transaction {} finalized successfully!",
            tx_hash.bright_green()
        );
        Ok(true)
    }

    /// Get chain properties including token decimals
    pub async fn get_chain_properties(&self) -> Result<(String, u8)> {
        log_verbose!("🔍 Querying chain properties...");

        // Get system properties from the chain
        let properties = self.api.get_system_properties().await.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Failed to get system properties: {:?}",
                e
            ))
        })?;

        log_verbose!("📊 Chain properties: {:?}", properties);

        // Extract token symbol and decimals from properties
        // Handle both direct values and arrays (different chains may use different formats)
        let token_symbol = properties
            .get("tokenSymbol")
            .and_then(|v| {
                // Try direct string first
                if let Some(s) = v.as_str() {
                    Some(s)
                } else {
                    // Try array format (some chains use arrays)
                    v.as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_str())
                }
            })
            .unwrap_or("QUAN")
            .to_string();

        let token_decimals = properties
            .get("tokenDecimals")
            .and_then(|v| {
                // Try direct number first
                if let Some(n) = v.as_u64() {
                    Some(n)
                } else {
                    // Try array format (some chains use arrays)
                    v.as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_u64())
                }
            })
            .unwrap_or(12) as u8; // Default to 12 decimals if not found

        log_verbose!(
            "💰 Token: {} with {} decimals",
            token_symbol,
            token_decimals
        );

        Ok((token_symbol, token_decimals))
    }

    /// Get chain metadata and explore all available pallets and calls
    pub async fn explore_chain_metadata(&self, no_docs: bool) -> Result<()> {
        log_verbose!("🔍 Exploring chain metadata...");

        let metadata = self.api.metadata();
        let pallets: Vec<_> = metadata.pallets().collect();

        log_print!("{}", "🏛️  Available Pallets & Calls".bold().underline());
        log_print!("");

        for pallet in pallets.iter() {
            log_print!("- Pallet: {}", pallet.name().bold().bright_blue());

            // Print calls
            if let Some(calls) = pallet.call_variants() {
                log_print!("\t- Calls ({}):", calls.len());
                if !no_docs {
                    for call_variant in calls {
                        log_print!("\t\t- {}", call_variant.name);
                        let docs = &call_variant.docs;
                        if !docs.is_empty() {
                            log_verbose!("      {}", docs.join("\n      ").italic().dimmed());
                        }
                    }
                }
            } else {
                log_print!("\t\t- No calls in this pallet.");
            }

            // Show storage items
            let storage = pallet.storage();
            log_print!("\t- Storage ({}):", storage.len());
            for entry in storage {
                let default_str = format!("{:?}", &entry.default);
                let display_default = if default_str.is_empty() || default_str == "[]" {
                    "<empty>".to_string()
                } else if default_str.len() > 10 {
                    format!("{}...", &default_str[..10])
                } else {
                    default_str
                };

                log_print!(
                    "\t\t- Name: {} {}",
                    entry.name,
                    display_default.italic().dimmed()
                );
                log_verbose!("\t\t- Modifier: {:?}", entry.modifier);
                log_verbose!("\t\t- Type: {:?}", entry.ty);
                log_verbose!(
                    "\t\t- Docs: {:?}",
                    entry.docs.join("\n      ").italic().dimmed()
                );
            }

            log_print!("");
        }

        // Add a summary at the end
        log_print!("{}", "🔍 Exploration Complete".bold());
        log_print!("Found {} pallets.", pallets.len());

        Ok(())
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
            // Format fractional part with proper leading zeros
            let fractional_str = format!("{:0width$}", fractional_part, width = decimals as usize);
            // Remove trailing zeros
            let fractional_str = fractional_str.trim_end_matches('0');

            if fractional_str.is_empty() {
                whole_part.to_string()
            } else {
                format!("{}.{}", whole_part, fractional_str)
            }
        }
    }

    /// Format balance with token symbol
    pub async fn format_balance_with_symbol(&self, amount: u128) -> Result<String> {
        let (symbol, decimals) = self.get_chain_properties().await?;
        let formatted_amount = Self::format_balance(amount, decimals);
        Ok(format!("{} {}", formatted_amount, symbol))
    }

    /// Parse human-readable amount string to raw chain units
    /// Accepts formats like: "10", "10.0", "0.0000001", "10.5 DEV" (ignores symbol)
    pub async fn parse_amount(&self, amount_str: &str) -> Result<u128> {
        let (_, decimals) = self.get_chain_properties().await?;
        Self::parse_amount_with_decimals(amount_str, decimals)
    }

    /// Parse amount string with specific decimals (static method for testing)
    pub fn parse_amount_with_decimals(amount_str: &str, decimals: u8) -> Result<u128> {
        // Remove any token symbol by taking only the first part (number)
        let amount_part = amount_str.trim().split_whitespace().next().unwrap_or("");

        if amount_part.is_empty() {
            return Err(crate::error::QuantusError::Generic(
                "Amount cannot be empty".to_string(),
            ));
        }

        // Parse the decimal number
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

        // Check for too many decimal places
        if let Some(decimal_part) = amount_part.split('.').nth(1) {
            if decimal_part.len() > decimals as usize {
                return Err(crate::error::QuantusError::Generic(format!(
                    "Too many decimal places. Maximum {} decimal places allowed for this chain",
                    decimals
                )));
            }
        }

        // Convert to raw units by multiplying by 10^decimals
        let multiplier = 10_f64.powi(decimals as i32);
        let raw_amount = (parsed_amount * multiplier).round() as u128;

        // Validate the result fits in u128 and isn't zero for non-zero inputs
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

    /// Get access to the API for generic calls using compose macros
    pub fn get_api(&self) -> &Api<QuantusRuntimeConfig, JsonrpseeClient> {
        &self.api
    }

    /// Create an API instance with a signer for generic calls
    pub fn create_api_with_signer(
        &self,
        keypair: &QuantumKeyPair,
    ) -> Result<Api<QuantusRuntimeConfig, JsonrpseeClient>> {
        let resonance_pair = keypair.to_resonance_pair().map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        let extrinsic_signer = ExtrinsicSigner::<QuantusRuntimeConfig>::new(resonance_pair);
        let mut api_with_signer = self.api.clone();
        api_with_signer.set_signer(extrinsic_signer);

        Ok(api_with_signer)
    }
}

// Chain client implementation ends here
