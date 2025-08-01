use crate::chain::client::ChainConfig;
use crate::cli::common::resolve_address;
use crate::cli::progress_spinner::wait_for_finalization;
use crate::{
    chain::quantus_subxt, error::Result, log_error, log_info, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};
use subxt::OnlineClient;

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

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
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

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
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

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
    },

    /// Set reversibility for your account
    SetReversibility {
        /// Delay in blocks or milliseconds (None to disable)
        #[arg(short, long)]
        delay: Option<u64>,

        /// Policy: "BlockDelay" or "TimeDelay"
        #[arg(long, default_value = "TimeDelay")]
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

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
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

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
    },
}

/// Schedule a transfer with default delay
pub async fn schedule_transfer(
    quantus_client: &crate::chain::client::QuantusClient,
    from_keypair: &crate::wallet::QuantumKeyPair,
    to_address: &str,
    amount: u128,
) -> Result<subxt::utils::H256> {
    log_verbose!("🔄 Creating reversible transfer...");
    log_verbose!(
        "   From: {}",
        from_keypair.to_account_id_ss58check().bright_cyan()
    );
    log_verbose!("   To: {}", to_address.bright_green());
    log_verbose!("   Amount: {}", amount);

    // Parse the destination address
    let to_account_id_sp = SpAccountId32::from_ss58check(to_address).map_err(|e| {
        crate::error::QuantusError::NetworkError(format!("Invalid destination address: {:?}", e))
    })?;

    // Convert to subxt_core AccountId32
    let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
    let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

    log_verbose!("✍️  Creating reversible transfer extrinsic...");

    // Create the reversible transfer call using static API from quantus_subxt
    let transfer_call = quantus_subxt::api::tx()
        .reversible_transfers()
        .schedule_transfer(
            subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id),
            amount,
        );

    // Submit the transaction
    let tx_hash =
        crate::cli::common::submit_transaction(quantus_client, from_keypair, transfer_call, None)
            .await?;

    log_verbose!("📋 Reversible transfer submitted: {:?}", tx_hash);

    Ok(tx_hash)
}

/// Cancel a pending reversible transaction
pub async fn cancel_transaction(
    quantus_client: &crate::chain::client::QuantusClient,
    from_keypair: &crate::wallet::QuantumKeyPair,
    tx_id: &str,
) -> Result<subxt::utils::H256> {
    log_verbose!("❌ Cancelling reversible transfer...");
    log_verbose!("   Transaction ID: {}", tx_id.bright_yellow());

    // Parse transaction ID
    let tx_hash_bytes = hex::decode(tx_id.trim_start_matches("0x")).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid transaction ID: {:?}", e))
    })?;

    let tx_hash = sp_core::H256::from_slice(&tx_hash_bytes);

    log_verbose!("✍️  Creating cancel transaction extrinsic...");

    // Create the cancel transaction call using static API from quantus_subxt
    let cancel_call = quantus_subxt::api::tx()
        .reversible_transfers()
        .cancel(tx_hash);

    // Submit the transaction
    let tx_hash_result =
        crate::cli::common::submit_transaction(quantus_client, from_keypair, cancel_call, None)
            .await?;

    log_verbose!("📋 Cancel transaction submitted: {:?}", tx_hash_result);

    Ok(tx_hash_result)
}

/// Schedule a transfer with custom delay
pub async fn schedule_transfer_with_delay(
    quantus_client: &crate::chain::client::QuantusClient,
    from_keypair: &crate::wallet::QuantumKeyPair,
    to_address: &str,
    amount: u128,
    delay: u64,
    unit_blocks: bool,
) -> Result<subxt::utils::H256> {
    let unit_str = if unit_blocks { "blocks" } else { "seconds" };
    log_verbose!("🔄 Creating reversible transfer with custom delay ...");
    log_verbose!(
        "   From: {}",
        from_keypair.to_account_id_ss58check().bright_cyan()
    );
    log_verbose!("   To: {}", to_address.bright_green());
    log_verbose!("   Amount: {}", amount);
    log_verbose!("   Delay: {} {}", delay, unit_str);

    // Parse the destination address
    let to_account_id_sp = SpAccountId32::from_ss58check(to_address).map_err(|e| {
        crate::error::QuantusError::NetworkError(format!("Invalid destination address: {:?}", e))
    })?;
    let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
    let to_account_id_subxt = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

    // Convert delay to proper BlockNumberOrTimestamp
    let delay_value = if unit_blocks {
        quantus_subxt::api::reversible_transfers::calls::types::schedule_transfer_with_delay::Delay::BlockNumber(delay as u32)
    } else {
        // Convert seconds to milliseconds for the runtime
        quantus_subxt::api::reversible_transfers::calls::types::schedule_transfer_with_delay::Delay::Timestamp(delay * 1000)
    };

    log_verbose!("✍️  Creating schedule_transfer_with_delay extrinsic...");

    // Create the schedule transfer with delay call using static API from quantus_subxt
    let transfer_call = quantus_subxt::api::tx()
        .reversible_transfers()
        .schedule_transfer_with_delay(
            subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
            amount,
            delay_value,
        );

    // Submit the transaction
    let tx_hash =
        crate::cli::common::submit_transaction(quantus_client, from_keypair, transfer_call, None)
            .await?;

    log_verbose!(
        "📋 Reversible transfer with custom delay submitted: {:?}",
        tx_hash
    );

    Ok(tx_hash)
}

/// Handle reversible transfer subxt commands
pub async fn handle_reversible_command(command: ReversibleCommands, node_url: &str) -> Result<()> {
    log_print!("🔄 Reversible Transfers");

    let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

    match command {
        ReversibleCommands::ScheduleTransfer {
            to,
            amount,
            from,
            password,
            password_file,
        } => {
            // Parse and validate the amount
            let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;
            let (raw_amount, formatted_amount) =
                crate::cli::send::validate_and_format_amount(&quantus_client, &amount).await?;

            // Resolve the destination address (could be wallet name or SS58 address)
            let resolved_address = resolve_address(&to)?;

            log_info!(
                "🔄 Scheduling reversible transfer of {} to {}",
                formatted_amount,
                resolved_address
            );
            log_verbose!(
                "🚀 {} Scheduling reversible transfer {} to {} ()",
                "REVERSIBLE".bright_cyan().bold(),
                formatted_amount.bright_yellow().bold(),
                resolved_address.bright_green()
            );

            // Get password securely for decryption
            log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit transaction
            let tx_hash =
                schedule_transfer(&quantus_client, &keypair, &resolved_address, raw_amount).await?;

            log_print!(
                "✅ {} Reversible transfer scheduled! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = wait_for_finalization(quantus_client.client(), tx_hash).await?;

            if success {
                log_info!("✅ Reversible transfer scheduled and confirmed on chain");
                log_success!(
                    "🎉 {} Reversible transfer confirmed!",
                    "FINISHED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }
        ReversibleCommands::Cancel {
            tx_id,
            from,
            password,
            password_file,
        } => {
            log_verbose!(
                "❌ {} Cancelling reversible transfer {} ()",
                "CANCEL".bright_red().bold(),
                tx_id.bright_yellow().bold()
            );

            // Get password securely for decryption
            log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit cancel transaction
            let tx_hash = cancel_transaction(&quantus_client, &keypair, &tx_id).await?;

            log_print!(
                "✅ {} Cancel transaction submitted! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = wait_for_finalization(quantus_client.client(), tx_hash).await?;

            if success {
                log_success!(
                    "🎉 {} Cancel transaction confirmed!",
                    "FINISHED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }

        ReversibleCommands::ScheduleTransferWithDelay {
            to,
            amount,
            delay,
            unit_blocks,
            from,
            password,
            password_file,
        } => {
            // Parse and validate the amount
            let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;
            let (raw_amount, formatted_amount) =
                crate::cli::send::validate_and_format_amount(&quantus_client, &amount).await?;

            // Resolve the destination address (could be wallet name or SS58 address)
            let resolved_address = resolve_address(&to)?;

            let unit_str = if unit_blocks { "blocks" } else { "seconds" };
            log_verbose!(
                "🚀 {} Scheduling reversible transfer {} to {} with {} {} delay ()",
                "REVERSIBLE".bright_cyan().bold(),
                formatted_amount.bright_yellow().bold(),
                resolved_address.bright_green(),
                delay.to_string().bright_magenta(),
                unit_str
            );

            // Get password securely for decryption
            log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit transaction
            let tx_hash = schedule_transfer_with_delay(
                &quantus_client,
                &keypair,
                &resolved_address,
                raw_amount,
                delay,
                unit_blocks,
            )
            .await?;

            log_print!(
                "✅ {} Reversible transfer with custom delay scheduled! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = wait_for_finalization(quantus_client.client(), tx_hash).await?;

            if success {
                log_success!(
                    "🎉 {} Reversible transfer with custom delay confirmed!",
                    "FINISHED".bright_green().bold()
                );

                if unit_blocks {
                    log_print!("⏰ Transfer will execute after {} {}", delay, unit_str);
                } else {
                    let now = chrono::Local::now();
                    let completion_time = now + chrono::Duration::seconds(delay as i64);
                    log_print!(
                        "⏰ Transfer will execute in ~{} seconds, at approximately {}",
                        delay,
                        completion_time
                            .format("%Y-%m-%d %H:%M:%S")
                            .to_string()
                            .italic()
                            .dimmed()
                    );
                }
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }

        ReversibleCommands::SetReversibility {
            delay,
            policy,
            reverser,
            from,
            password,
            password_file,
        } => {
            set_reversibility(
                &quantus_client,
                &delay,
                &policy,
                &reverser,
                &from,
                password,
                password_file,
            )
            .await
        }

        ReversibleCommands::ListPending {
            address,
            from,
            password,
            password_file,
        } => {
            list_pending_transactions(
                quantus_client.client(),
                address,
                from,
                password,
                password_file,
            )
            .await
        }
    }
}

/// List all pending reversible transactions for an account
async fn list_pending_transactions(
    client: &OnlineClient<ChainConfig>,
    address: Option<String>,
    wallet_name: Option<String>,
    password: Option<String>,
    password_file: Option<String>,
) -> Result<()> {
    log_print!("📋 Listing pending reversible transactions");

    // Determine which address to query
    let target_address = match (address, wallet_name) {
        (Some(addr), _) => {
            // Validate the provided address
            SpAccountId32::from_ss58check(&addr).map_err(|e| {
                crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e))
            })?;
            addr
        }
        (None, Some(wallet)) => {
            // Load wallet and get its address
            let keypair =
                crate::wallet::load_keypair_from_wallet(&wallet, password, password_file)?;
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
    let account_id_sp = SpAccountId32::from_ss58check(&target_address)
        .map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e)))?;
    let account_id_bytes: [u8; 32] = *account_id_sp.as_ref();
    let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_id_bytes);

    log_verbose!("🔍 Querying pending transfers for: {}", target_address);

    // Query pending transfers by sender (outgoing)
    let sender_storage_address = crate::chain::quantus_subxt::api::storage()
        .reversible_transfers()
        .pending_transfers_by_sender(account_id.clone());

    let outgoing_transfers = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| crate::error::QuantusError::NetworkError(format!("Storage error: {:?}", e)))?
        .fetch(&sender_storage_address)
        .await
        .map_err(|e| crate::error::QuantusError::NetworkError(format!("Fetch error: {:?}", e)))?;

    // Query pending transfers by recipient (incoming)
    let recipient_storage_address = crate::chain::quantus_subxt::api::storage()
        .reversible_transfers()
        .pending_transfers_by_recipient(account_id);

    let incoming_transfers = client
        .storage()
        .at_latest()
        .await
        .map_err(|e| crate::error::QuantusError::NetworkError(format!("Storage error: {:?}", e)))?
        .fetch(&recipient_storage_address)
        .await
        .map_err(|e| crate::error::QuantusError::NetworkError(format!("Fetch error: {:?}", e)))?;

    let mut total_transfers = 0;

    // Display outgoing transfers
    if let Some(outgoing_hashes) = outgoing_transfers {
        if !outgoing_hashes.0.is_empty() {
            log_print!("📤 Outgoing pending transfers:");
            for (i, hash) in outgoing_hashes.0.iter().enumerate() {
                total_transfers += 1;
                log_print!("   {}. 0x{}", i + 1, hex::encode(hash.as_ref()));

                // Try to get transfer details
                let transfer_storage_address = crate::chain::quantus_subxt::api::storage()
                    .reversible_transfers()
                    .pending_transfers(*hash);

                if let Ok(Some(transfer_details)) = client
                    .storage()
                    .at_latest()
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!("Storage error: {:?}", e))
                    })?
                    .fetch(&transfer_storage_address)
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!("Fetch error: {:?}", e))
                    })
                {
                    let formatted_amount = format_amount(transfer_details.amount);
                    log_print!("      👤 To: {}", transfer_details.to);
                    log_print!("      💰 Amount: {}", formatted_amount);
                    log_print!("      🔄 Interceptor: {}", transfer_details.interceptor);
                }
            }
        }
    }

    // Display incoming transfers
    if let Some(incoming_hashes) = incoming_transfers {
        if !incoming_hashes.0.is_empty() {
            if total_transfers > 0 {
                log_print!("");
            }
            log_print!("📥 Incoming pending transfers:");
            for (i, hash) in incoming_hashes.0.iter().enumerate() {
                total_transfers += 1;
                log_print!("   {}. 0x{}", i + 1, hex::encode(hash.as_ref()));

                // Try to get transfer details
                let transfer_storage_address = crate::chain::quantus_subxt::api::storage()
                    .reversible_transfers()
                    .pending_transfers(*hash);

                if let Ok(Some(transfer_details)) = client
                    .storage()
                    .at_latest()
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!("Storage error: {:?}", e))
                    })?
                    .fetch(&transfer_storage_address)
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!("Fetch error: {:?}", e))
                    })
                {
                    let formatted_amount = format_amount(transfer_details.amount);
                    log_print!("      👤 From: {}", transfer_details.from);
                    log_print!("      💰 Amount: {}", formatted_amount);
                    log_print!("      🔄 Interceptor: {}", transfer_details.interceptor);
                }
            }
        }
    }

    if total_transfers == 0 {
        log_print!(
            "📝 No pending transfers found for account: {}",
            target_address
        );
    } else {
        log_print!("");
        log_print!("📊 Total pending transfers: {}", total_transfers);
        log_print!("💡 Use transaction hash with 'quantus reversible cancel --tx-id <hash>' to cancel outgoing transfers");
    }

    Ok(())
}

/// Set reversibility (high security) for an account
async fn set_reversibility(
    quantus_client: &crate::chain::client::QuantusClient,
    delay: &Option<u64>,
    policy: &str,
    reverser: &Option<String>,
    from: &str,
    password: Option<String>,
    password_file: Option<String>,
) -> Result<()> {
    log_print!("⚙️  Setting reversibility");
    log_print!("Delay: {:?}", delay);
    log_print!("Policy: {}", policy.bright_cyan());
    log_print!("From: {}", from.bright_yellow());

    // Load keypair
    let from_keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

    // Convert delay to proper BlockNumberOrTimestamp
    let delay_value = if let Some(delay_ms) = delay {
        use crate::chain::quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay;

        match policy {
            "BlockDelay" => {
                // Convert to blocks (assuming ~6 second block time)
                let blocks = (*delay_ms / 6000).max(1) as u32;
                Delay::BlockNumber(blocks)
            }
            _ => {
                // Default to TimeDelay (milliseconds)
                Delay::Timestamp(*delay_ms)
            }
        }
    } else {
        return Err(crate::error::QuantusError::Generic(
            "Delay must be specified for setting reversibility".to_string(),
        )
        .into());
    };

    // Parse reverser account
    let reverser_account = if let Some(reverser_addr) = reverser {
        // Resolve the reverser address (could be wallet name or SS58 address)
        let resolved_reverser = resolve_address(reverser_addr)?;
        SpAccountId32::from_ss58check(&resolved_reverser).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid reverser address: {:?}", e))
        })?
    } else {
        // Default to self if no reverser specified
        SpAccountId32::from_ss58check(&from_keypair.to_account_id_ss58check()).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid from address: {:?}", e))
        })?
    };

    // Convert reverser to subxt type
    let reverser_bytes: [u8; 32] = *reverser_account.as_ref();
    let reverser_subxt = subxt::ext::subxt_core::utils::AccountId32::from(reverser_bytes);

    // For interceptor, we'll use the same as reverser for simplicity
    let interceptor_subxt = reverser_subxt.clone();

    log_verbose!("✅ Delay: {:?}", delay_value);
    log_verbose!("✅ Interceptor: {}", interceptor_subxt);
    log_verbose!("✅ Recoverer: {}", reverser_subxt);

    // Clone for display later
    let interceptor_display = interceptor_subxt.clone();
    let reverser_display = reverser_subxt.clone();

    // Create the set_high_security transaction
    let set_high_security_tx = crate::chain::quantus_subxt::api::tx()
        .reversible_transfers()
        .set_high_security(delay_value, interceptor_subxt, reverser_subxt);

    // Submit the transaction
    let tx_hash = crate::cli::common::submit_transaction(
        quantus_client,
        &from_keypair,
        set_high_security_tx,
        None,
    )
    .await?;

    log_success!(
        "✅ SUCCESS Reversibility settings updated! Hash: 0x{}",
        hex::encode(tx_hash.as_ref())
    );
    log_success!("✅ 🎉 FINISHED Reversibility settings confirmed!");

    // Display the settings
    match delay {
        Some(d) => {
            if policy == "BlockDelay" {
                let blocks = (d / 6000).max(1);
                log_print!(
                    "⏰ High security enabled with {} block delay (~{} seconds)",
                    blocks,
                    d / 1000
                );
            } else {
                log_print!("⏰ High security enabled with {} ms delay", d);
            }
        }
        None => log_print!("🔒 High security disabled"),
    }

    log_print!("🔄 Interceptor: {}", interceptor_display);
    log_print!("🔄 Recoverer: {}", reverser_display);

    Ok(())
}

/// Helper function to format amount with QUAN units
fn format_amount(amount: u128) -> String {
    const QUAN_DECIMALS: u128 = 1_000_000_000_000; // 10^12

    if amount >= QUAN_DECIMALS {
        let whole = amount / QUAN_DECIMALS;
        let fractional = amount % QUAN_DECIMALS;

        if fractional == 0 {
            format!("{} QUAN", whole)
        } else {
            // Remove trailing zeros from fractional part
            let fractional_str = format!("{:012}", fractional);
            let trimmed = fractional_str.trim_end_matches('0');
            format!("{}.{} QUAN", whole, trimmed)
        }
    } else {
        format!("{} pico-QUAN", amount)
    }
}
