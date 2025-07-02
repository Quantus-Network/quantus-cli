use crate::chain::client::ChainClient;
use crate::chain::quantus_runtime_config::QuantusRuntimeConfig;
// to decode PendingTransfer, we need to use the following types:
// use crate::chain::types::reversible_transfers::events::TransactionCancelled;
// use crate::chain::types::runtime_types::bounded_collections::bounded_vec::BoundedVec;
// use crate::chain::types::runtime_types::pallet_reversible_transfers::PendingTransfer;

use codec::Decode;

use crate::error::Result;
use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;
use qp_scheduler::BlockNumberOrTimestamp;
use sp_core::crypto::AccountId32;
use sp_core::crypto::Ss58Codec;
use sp_runtime::MultiAddress;
use substrate_api_client::ac_compose_macros::compose_extrinsic;
use substrate_api_client::ac_primitives::ExtrinsicSigner;
use substrate_api_client::{SubmitAndWatch, XtStatus};

/// Reversible transfer commands
#[derive(Subcommand, Debug)]
pub enum ReversibleCommands {
    /// Schedule a transfer with default delay
    ScheduleTransfer {
        /// The recipient's account address
        #[arg(short, long)]
        to: String,

        /// Amount to transfer (e.g., "10", "10.5", "0.0001")
        #[arg(short, long)]
        amount: String,

        /// Wallet name to send from
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Schedule a transfer with custom delay
    ScheduleTransferWithDelay {
        /// The recipient's account address
        #[arg(short, long)]
        to: String,

        /// Amount to transfer (e.g., "10", "10.5", "0.0001")
        #[arg(short, long)]
        amount: String,

        /// Delay in seconds (default) or blocks if --unit-blocks is specified
        #[arg(short, long)]
        delay: u64,

        /// Use blocks instead of seconds for delay
        #[arg(long)]
        unit_blocks: bool,

        /// Wallet name to send from
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Cancel a pending reversible transaction
    Cancel {
        /// Transaction ID to cancel (hex hash)
        #[arg(long)]
        tx_id: String,

        /// Wallet name to sign with
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Set reversibility for your account
    SetReversibility {
        /// Delay in blocks or milliseconds (None to disable)
        #[arg(short, long)]
        delay: Option<u64>,

        /// Policy: "BlockDelay" or "TimeDelay"
        #[arg(short, long, default_value = "TimeDelay")]
        policy: String,

        /// Optional reverser account (defaults to self)
        #[arg(long)]
        reverser: Option<String>,

        /// Wallet name to sign with
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Execute a pending transfer (called by scheduler)
    ExecuteTransfer {
        /// Transaction ID to execute (hex hash)
        #[arg(long)]
        tx_id: String,

        /// Wallet name to sign with
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },

    /// List all pending reversible transactions for an account
    ListPending {
        /// Account address to query (optional, uses wallet address if not provided)
        #[arg(short, long)]
        address: Option<String>,

        /// Wallet name (used for address if --address not provided)
        #[arg(short, long)]
        from: Option<String>,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },
}

/// Handle reversible transfer commands
pub async fn handle_reversible_command(command: ReversibleCommands, node_url: &str) -> Result<()> {
    log_print!("🔄 Reversible Transfers");

    let chain_client = ChainClient::new(node_url).await?;

    match command {
        ReversibleCommands::ScheduleTransfer {
            to,
            amount,
            from,
            password,
        } => schedule_transfer(&chain_client, &to, &amount, &from, password).await,
        ReversibleCommands::ScheduleTransferWithDelay {
            to,
            amount,
            delay,
            unit_blocks,
            from,
            password,
        } => {
            schedule_transfer_with_delay(
                &chain_client,
                &to,
                &amount,
                delay,
                unit_blocks,
                &from,
                password,
            )
            .await
        }
        ReversibleCommands::Cancel {
            tx_id,
            from,
            password,
        } => cancel_transaction(&chain_client, &tx_id, &from, password).await,
        ReversibleCommands::SetReversibility {
            delay,
            policy,
            reverser,
            from,
            password,
        } => set_reversibility(&chain_client, delay, &policy, reverser, &from, password).await,
        ReversibleCommands::ExecuteTransfer {
            tx_id,
            from,
            password,
        } => execute_transfer(&chain_client, &tx_id, &from, password).await,
        ReversibleCommands::ListPending {
            address,
            from,
            password,
        } => list_pending_transactions(&chain_client, address, from, password).await,
    }
}

/// Schedule a transfer with default delay
async fn schedule_transfer(
    chain_client: &ChainClient,
    to: &str,
    amount: &str,
    wallet_name: &str,
    password: Option<String>,
) -> Result<()> {
    log_print!("📅 Scheduling transfer");
    log_print!("To: {}", to.bright_green());
    log_print!("Amount: {}", amount.bright_cyan());
    log_print!("From: {}", wallet_name.bright_yellow());

    let keypair = crate::wallet::load_keypair_from_wallet(&wallet_name, password, None)?;

    // Parse destination address
    let dest_account = AccountId32::from_ss58check(to).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid destination address: {:?}", e))
    })?;
    let dest: MultiAddress<AccountId32, u32> = MultiAddress::Id(dest_account);

    // Parse amount
    let amount_value = chain_client.parse_amount(amount).await?;
    log_verbose!("✅ Parsed amount: {} raw units", amount_value);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic
    let extrinsic = compose_extrinsic!(
        &api_with_signer,
        "ReversibleTransfers",
        "schedule_transfer",
        dest,
        amount_value
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic(
            "Failed to create schedule_transfer extrinsic".to_string(),
        )
    })?;

    // Submit extrinsic with spinner
    let tx_report = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("🎉 Transfer scheduled successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        tx_report.extrinsic_hash.to_string().bright_yellow()
    );
    log_print!("💡 Transfer will execute after the configured delay period");

    Ok(())
}

/// Schedule a transfer with custom delay
async fn schedule_transfer_with_delay(
    chain_client: &ChainClient,
    to: &str,
    amount: &str,
    delay: u64,
    unit_blocks: bool,
    from: &str,
    password: Option<String>,
) -> Result<()> {
    let unit_str = if unit_blocks { "blocks" } else { "seconds" };
    log_print!("📅 Scheduling transfer with custom delay");
    log_print!("To: {}", to.bright_green());
    log_print!("Amount: {}", amount.bright_cyan());
    log_print!("Delay: {} {}", delay.to_string().bright_magenta(), unit_str);
    log_print!("From: {}", from.bright_yellow());

    let keypair = crate::wallet::load_keypair_from_wallet(&from, password, None)?;

    // Convert delay to proper BlockNumberOrTimestamp
    let delay_value = if unit_blocks {
        BlockNumberOrTimestamp::BlockNumber(delay as u32)
    } else {
        // Convert seconds to milliseconds for the runtime
        BlockNumberOrTimestamp::Timestamp(delay * 1000)
    };

    // Parse destination address
    let dest_account = AccountId32::from_ss58check(to).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid destination address: {:?}", e))
    })?;
    let dest: MultiAddress<AccountId32, u32> = MultiAddress::Id(dest_account);

    // Parse amount
    let amount_value = chain_client.parse_amount(amount).await?;
    log_verbose!("✅ Parsed amount: {} raw units", amount_value);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic
    let extrinsic = compose_extrinsic!(
        &api_with_signer,
        "ReversibleTransfers",
        "schedule_transfer_with_delay",
        dest,
        amount_value,
        delay_value
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic(
            "Failed to create schedule_transfer_with_delay extrinsic".to_string(),
        )
    })?;

    // Submit extrinsic with spinner
    let tx_report = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("🎉 Transfer with custom delay scheduled successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        tx_report.extrinsic_hash.to_string().bright_yellow()
    );
    log_print!("⏰ Transfer will execute after {} {}", delay, unit_str);

    Ok(())
}

/// Cancel a pending reversible transaction
async fn cancel_transaction(
    chain_client: &ChainClient,
    tx_id: &str,
    from: &str,
    password: Option<String>,
) -> Result<()> {
    log_print!("❌ Canceling transaction");
    log_print!("Transaction ID: {}", tx_id.bright_red());
    log_print!("From: {}", from.bright_yellow());

    let keypair = crate::wallet::load_keypair_from_wallet(&from, password, None)?;

    // Parse transaction ID (hex hash)
    let tx_hash = if tx_id.starts_with("0x") {
        hex::decode(&tx_id[2..]).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid hex transaction ID: {:?}", e))
        })?
    } else {
        hex::decode(tx_id).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid hex transaction ID: {:?}", e))
        })?
    };

    if tx_hash.len() != 32 {
        return Err(crate::error::QuantusError::Generic(
            "Transaction ID must be 32 bytes (64 hex characters)".to_string(),
        )
        .into());
    }

    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&tx_hash);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic
    let extrinsic = compose_extrinsic!(
        &api_with_signer,
        "ReversibleTransfers",
        "cancel",
        hash_array
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic("Failed to create cancel extrinsic".to_string())
    })?;

    // Submit extrinsic with spinner
    let result_report = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("🎉 Transaction canceled successfully!");
    log_print!(
        "📋 Cancellation hash: {}",
        result_report.extrinsic_hash.to_string().bright_yellow()
    );

    Ok(())
}

/// Set reversibility for an account
async fn set_reversibility(
    chain_client: &ChainClient,
    delay: Option<u64>,
    policy: &str,
    reverser: Option<String>,
    from: &str,
    password: Option<String>,
) -> Result<()> {
    log_print!("⚙️  Setting reversibility");
    log_print!("Delay: {:?}", delay);
    log_print!("Policy: {}", policy.bright_cyan());
    log_print!("From: {}", from.bright_yellow());

    let keypair = crate::wallet::load_keypair_from_wallet(&from, password, None)?;

    // Parse reverser account if provided
    let reverser_account = if let Some(reverser_addr) = reverser {
        Some(AccountId32::from_ss58check(&reverser_addr).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid reverser address: {:?}", e))
        })?)
    } else {
        None
    };

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // For now, we'll use a simplified approach since the exact DelayPolicy enum structure isn't clear
    // This will need to be adjusted based on the actual runtime types
    let extrinsic = compose_extrinsic!(
        &api_with_signer,
        "ReversibleTransfers",
        "set_reversibility",
        delay,
        policy,
        reverser_account
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic(
            "Failed to create set_reversibility extrinsic".to_string(),
        )
    })?;

    // Submit extrinsic with spinner
    let tx_report = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("🎉 Reversibility settings updated successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        tx_report.extrinsic_hash.to_string().bright_yellow()
    );

    Ok(())
}

/// Execute a pending transfer (usually called by scheduler)
async fn execute_transfer(
    chain_client: &ChainClient,
    tx_id: &str,
    from: &str,
    password: Option<String>,
) -> Result<()> {
    log_print!("▶️  Executing transfer");
    log_print!("Transaction ID: {}", tx_id.bright_green());
    log_print!("From: {}", from.bright_yellow());

    let keypair = crate::wallet::load_keypair_from_wallet(&from, password, None)?;

    // Parse transaction ID (hex hash)
    let tx_hash = if tx_id.starts_with("0x") {
        hex::decode(&tx_id[2..]).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid hex transaction ID: {:?}", e))
        })?
    } else {
        hex::decode(tx_id).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid hex transaction ID: {:?}", e))
        })?
    };

    if tx_hash.len() != 32 {
        return Err(crate::error::QuantusError::Generic(
            "Transaction ID must be 32 bytes (64 hex characters)".to_string(),
        )
        .into());
    }

    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&tx_hash);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create extrinsic
    let extrinsic = compose_extrinsic!(
        &api_with_signer,
        "ReversibleTransfers",
        "execute_transfer",
        hash_array
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic(
            "Failed to create execute_transfer extrinsic".to_string(),
        )
    })?;

    // Submit extrinsic with spinner
    let result_hash = crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)?;

    log_success!("🎉 Transfer executed successfully!");
    log_print!(
        "📋 Execution hash: {}",
        result_hash.extrinsic_hash.to_string().bright_yellow()
    );

    Ok(())
}

/// List all pending reversible transactions for an account
/// This really is a developer feature - real chain will have too many
/// pending transactions to do this.
async fn list_pending_transactions(
    chain_client: &ChainClient,
    address: Option<String>,
    wallet_name: Option<String>,
    password: Option<String>,
) -> Result<()> {
    log_print!("📋 Listing pending reversible transactions (Dev mode)");

    // Determine which address to query
    let target_address = match (address, wallet_name) {
        (Some(addr), _) => {
            // Validate the provided address
            AccountId32::from_ss58check(&addr).map_err(|e| {
                crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e))
            })?;
            addr
        }
        (None, Some(wallet)) => {
            // Load wallet and get its address
            let keypair = crate::wallet::load_keypair_from_wallet(&wallet, password, None)?;
            keypair.to_account_id_ss58check()
        }
        (None, None) => {
            return Err(crate::error::QuantusError::Generic(
                "Either --address or --from must be provided".to_string(),
            )
            .into());
        }
    };

    // Convert to AccountId32 for storage queries
    let account_id = AccountId32::from_ss58check(&target_address)
        .map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e)))?;

    // Check AccountPendingIndex to see if the account has any pending transactions
    use substrate_api_client::GetStorage;
    match chain_client
        .get_api()
        .get_storage_map::<AccountId32, u32>(
            "ReversibleTransfers",
            "AccountPendingIndex",
            account_id.clone(),
            None,
        )
        .await
    {
        Ok(Some(pending_count)) => {
            if pending_count == 0 {
                log_print!(
                    "📝 No pending transfers found for account: {}",
                    target_address
                );
                return Ok(());
            }
        }
        Ok(None) => {
            log_print!(
                "📝 No pending transfers found for account: {}",
                target_address
            );
            return Ok(());
        }
        Err(_) => {
            // Continue with scan approach if index query fails
        }
    }

    // Get all pending transfers and find ones belonging to this account
    match chain_client
        .get_api()
        .get_storage_map_key_prefix("ReversibleTransfers", "PendingTransfers")
        .await
    {
        Ok(prefix) => {
            match chain_client
                .get_api()
                .get_storage_keys_paged(Some(prefix), 1000, None, None)
                .await
            {
                Ok(keys) => {
                    if keys.is_empty() {
                        log_print!("✅ No pending transfers found in the system");
                        return Ok(());
                    }

                    let mut user_transfers = Vec::new();

                    // Check each transfer
                    for key in keys.iter() {
                        if let Ok(Some(transfer_data)) = chain_client
                            .get_api()
                            .get_opaque_storage_by_key(key.clone(), None)
                            .await
                        {
                            // Extract transaction hash from storage key
                            if key.0.len() >= 32 {
                                let tx_hash_bytes = &key.0[key.0.len() - 32..];
                                let tx_hash = hex::encode(tx_hash_bytes);

                                // Decode the 'who' field (first field in PendingTransfer)
                                let mut data = transfer_data.as_slice();
                                if let Ok(who) = AccountId32::decode(&mut data) {
                                    // Check if this transfer belongs to our target account
                                    if who.to_ss58check() == target_address {
                                        log_print!("📋 Transaction: 0x{}", tx_hash);
                                        log_print!(
                                            "   👤 From: {}",
                                            who.to_ss58check().bright_cyan()
                                        );

                                        // Try to decode amount and count from the end
                                        let remaining_data = data;
                                        if remaining_data.len() >= 20 {
                                            let amount_start = remaining_data.len() - 20;
                                            let count_start = remaining_data.len() - 4;

                                            let amount_bytes =
                                                &remaining_data[amount_start..count_start];
                                            let count_bytes = &remaining_data[count_start..];

                                            if let (Ok(amount), Ok(count)) = (
                                                u128::decode(&mut &amount_bytes[..]),
                                                u32::decode(&mut &count_bytes[..]),
                                            ) {
                                                let formatted_amount = chain_client
                                                    .format_balance_with_symbol(amount)
                                                    .await
                                                    .unwrap_or_else(|_| amount.to_string());
                                                log_print!("   💰 Amount: {}", formatted_amount);
                                                log_print!("   📊 Count: {}", count);
                                            }
                                        }

                                        user_transfers.push(tx_hash);
                                    }
                                }
                            }
                        }
                    }

                    if user_transfers.is_empty() {
                        log_print!("✅ No pending transfers found for this account");
                    } else {
                        log_print!("📋 Found {} pending transfer(s):", user_transfers.len());
                        for (i, hash) in user_transfers.iter().enumerate() {
                            log_print!("   {}. 0x{}", i + 1, hash);
                        }
                        log_print!("💡 Use transaction hash with 'quantus reversible cancel --tx-id <hash>' to cancel");
                    }
                }
                Err(e) => {
                    log_print!("❌ Error getting storage keys: {:?}", e);
                }
            }
        }
        Err(e) => {
            log_print!("❌ Error getting storage prefix: {:?}", e);
        }
    }

    Ok(())
}
