use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::{common::resolve_address, progress_spinner::wait_for_tx_confirmation},
	error::Result,
	log_error, log_info, log_print, log_success, log_verbose,
};
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

/// Get the `free` balance for the given account using on-chain storage.
pub async fn get_balance(quantus_client: &QuantusClient, account_address: &str) -> Result<u128> {
	use quantus_subxt::api;

	log_verbose!("💰 Querying balance for account: {}", account_address.bright_green());

	// Decode the SS58 address into `AccountId32` (sp-core) first …
	let (account_id_sp, _) =
		SpAccountId32::from_ss58check_with_version(account_address).map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Invalid account address '{account_address}': {e:?}"
			))
		})?;

	// … then convert into the `subxt` representation expected by the generated API.
	let bytes: [u8; 32] = *account_id_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(bytes);

	// Build the storage key for `System::Account` and fetch (or default-init) it.
	let storage_addr = api::storage().system().account(account_id);

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let account_info = storage_at.fetch_or_default(&storage_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch account info: {e:?}"))
	})?;

	Ok(account_info.data.free)
}

/// Get chain properties for formatting (uses system.rs ChainHead API)
pub async fn get_chain_properties(quantus_client: &QuantusClient) -> Result<(String, u8)> {
	// Use the shared ChainHead API from system.rs to avoid duplication
	match crate::cli::system::get_complete_chain_info(quantus_client.node_url()).await {
		Ok(chain_info) => {
			log_verbose!(
				"💰 Token: {} with {} decimals",
				chain_info.token.symbol,
				chain_info.token.decimals
			);

			Ok((chain_info.token.symbol, chain_info.token.decimals))
		},
		Err(e) => {
			log_verbose!("❌ ChainHead API failed: {:?}", e);
			Err(e)
		},
	}
}

/// Format balance with token symbol
pub async fn format_balance_with_symbol(
	quantus_client: &QuantusClient,
	amount: u128,
) -> Result<String> {
	let (symbol, decimals) = get_chain_properties(quantus_client).await?;
	let formatted_amount = format_balance(amount, decimals);
	Ok(format!("{formatted_amount} {symbol}"))
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
			format!("{whole_part}.{fractional_str}")
		}
	}
}

/// Parse human-readable amount string to raw chain units
pub async fn parse_amount(quantus_client: &QuantusClient, amount_str: &str) -> Result<u128> {
	let (_, decimals) = get_chain_properties(quantus_client).await?;
	parse_amount_with_decimals(amount_str, decimals)
}

/// Parse amount string with specific decimals
pub fn parse_amount_with_decimals(amount_str: &str, decimals: u8) -> Result<u128> {
	let amount_part = amount_str.split_whitespace().next().unwrap_or("");

	if amount_part.is_empty() {
		return Err(crate::error::QuantusError::Generic("Amount cannot be empty".to_string()));
	}

	let parsed_amount: f64 = amount_part.parse().map_err(|_| {
		crate::error::QuantusError::Generic(format!(
			"Invalid amount format: '{amount_part}'. Use formats like '10', '10.5', '0.0001'"
		))
	})?;

	if parsed_amount < 0.0 {
		return Err(crate::error::QuantusError::Generic("Amount cannot be negative".to_string()));
	}

	if let Some(decimal_part) = amount_part.split('.').nth(1) {
		if decimal_part.len() > decimals as usize {
			return Err(crate::error::QuantusError::Generic(format!(
				"Too many decimal places. Maximum {decimals} decimal places allowed for this chain"
			)));
		}
	}

	let multiplier = 10_f64.powi(decimals as i32);
	let raw_amount = (parsed_amount * multiplier).round() as u128;

	if raw_amount == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Amount too small to represent in chain units".to_string(),
		));
	}

	Ok(raw_amount)
}

/// Validate and format amount for display before sending
pub async fn validate_and_format_amount(
	quantus_client: &QuantusClient,
	amount_str: &str,
) -> Result<(u128, String)> {
	let raw_amount = parse_amount(quantus_client, amount_str).await?;
	let formatted = format_balance_with_symbol(quantus_client, raw_amount).await?;
	Ok((raw_amount, formatted))
}

/// Transfer tokens with automatic nonce
#[allow(dead_code)] // Used by external libraries via lib.rs export
pub async fn transfer(
	quantus_client: &QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	to_address: &str,
	amount: u128,
	tip: Option<u128>,
) -> Result<subxt::utils::H256> {
	transfer_with_nonce(quantus_client, from_keypair, to_address, amount, tip, None).await
}

/// Transfer tokens with manual nonce override
pub async fn transfer_with_nonce(
	quantus_client: &QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	to_address: &str,
	amount: u128,
	tip: Option<u128>,
	nonce: Option<u32>,
) -> Result<subxt::utils::H256> {
	log_verbose!("🚀 Creating transfer transaction...");
	log_verbose!("   From: {}", from_keypair.to_account_id_ss58check().bright_cyan());
	log_verbose!("   To: {}", to_address.bright_green());
	log_verbose!("   Amount: {}", amount);

	// Resolve the destination address (could be wallet name or SS58 address)
	let resolved_address = resolve_address(to_address)?;
	log_verbose!("   Resolved to: {}", resolved_address.bright_green());

	// Parse the destination address
	let (to_account_id_sp, _) = SpAccountId32::from_ss58check_with_version(&resolved_address)
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Invalid destination address: {e:?}"))
		})?;

	// Convert to subxt_core AccountId32
	let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
	let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

	log_verbose!("✍️  Creating balance transfer extrinsic...");

	// Create the transfer call using static API from quantus_subxt
	let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id.clone()),
		amount,
	);

	// Use provided tip or default tip of 10 DEV to increase priority and avoid temporarily
	// banned errors
	let tip_to_use = tip.unwrap_or(10_000_000_000); // Use provided tip or default 10 DEV

	// Submit the transaction with optional manual nonce
	let tx_hash = if let Some(manual_nonce) = nonce {
		log_verbose!("🔢 Using manual nonce: {}", manual_nonce);
		crate::cli::common::submit_transaction_with_nonce(
			quantus_client,
			from_keypair,
			transfer_call,
			Some(tip_to_use),
			manual_nonce,
		)
		.await?
	} else {
		crate::cli::common::submit_transaction(
			quantus_client,
			from_keypair,
			transfer_call,
			Some(tip_to_use),
		)
		.await?
	};

	log_verbose!("📋 Transaction submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// Batch transfer tokens to multiple recipients in a single transaction
pub async fn batch_transfer(
	quantus_client: &QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	transfers: Vec<(String, u128)>, // (to_address, amount) pairs
	tip: Option<u128>,
) -> Result<subxt::utils::H256> {
	log_verbose!("🚀 Creating batch transfer transaction with {} transfers...", transfers.len());
	log_verbose!("   From: {}", from_keypair.to_account_id_ss58check().bright_cyan());

	if transfers.is_empty() {
		return Err(crate::error::QuantusError::Generic(
			"No transfers provided for batch".to_string(),
		));
	}

	// Get dynamic limits from chain
	let (safe_limit, recommended_limit) =
		get_batch_limits(quantus_client).await.unwrap_or((500, 1000));

	if transfers.len() as u32 > recommended_limit {
		return Err(crate::error::QuantusError::Generic(format!(
			"Too many transfers in batch ({}) - chain limit is ~{} (safe: {})",
			transfers.len(),
			recommended_limit,
			safe_limit
		)));
	}

	// Warn about large batches
	if transfers.len() as u32 > safe_limit {
		log_verbose!(
			"⚠️  Large batch ({} transfers) - approaching chain limits (safe: {}, max: {})",
			transfers.len(),
			safe_limit,
			recommended_limit
		);
	}

	// Prepare all transfer calls as RuntimeCall
	let mut calls = Vec::new();
	for (to_address, amount) in transfers {
		log_verbose!("   To: {} Amount: {}", to_address.bright_green(), amount);

		// Resolve the destination address
		let resolved_address = crate::cli::common::resolve_address(&to_address)?;

		// Parse the destination address
		let to_account_id_sp = SpAccountId32::from_ss58check(&resolved_address).map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Invalid destination address {resolved_address}: {e:?}"
			))
		})?;

		// Convert to subxt_core AccountId32
		let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
		let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

		// Create the transfer call as RuntimeCall
		use quantus_subxt::api::runtime_types::{
			pallet_balances::pallet::Call as BalancesCall, quantus_runtime::RuntimeCall,
		};

		let transfer_call = RuntimeCall::Balances(BalancesCall::transfer_allow_death {
			dest: subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id),
			value: amount,
		});

		calls.push(transfer_call);
	}

	log_verbose!("✍️  Creating batch extrinsic with {} calls...", calls.len());

	// Create the batch call using utility pallet
	let batch_call = quantus_subxt::api::tx().utility().batch(calls);

	// Use provided tip or default tip
	let tip_to_use = tip.unwrap_or(10_000_000_000);

	// Submit the batch transaction
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		batch_call,
		Some(tip_to_use),
	)
	.await?;

	log_verbose!("📋 Batch transaction submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

// (Removed custom `AccountData` struct – we now use the runtime-generated type)

/// Handle the send command
pub async fn handle_send_command(
	from_wallet: String,
	to_address: String,
	amount_str: &str,
	node_url: &str,
	password: Option<String>,
	password_file: Option<String>,
	tip: Option<String>,
	nonce: Option<u32>,
) -> Result<()> {
	// Create quantus chain client
	let quantus_client = QuantusClient::new(node_url).await?;

	// Parse and validate the amount
	let (amount, formatted_amount) =
		validate_and_format_amount(&quantus_client, amount_str).await?;

	// Resolve the destination address (could be wallet name or SS58 address)
	let resolved_address = resolve_address(&to_address)?;

	log_info!("🚀 Initiating transfer of {} to {}", formatted_amount, resolved_address);
	log_verbose!(
		"🚀 {} Sending {} to {}",
		"SEND".bright_cyan().bold(),
		formatted_amount.bright_yellow().bold(),
		resolved_address.bright_green()
	);

	// Get password securely for decryption
	log_verbose!("📦 Using wallet: {}", from_wallet.bright_blue().bold());
	let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;

	// Get account information
	let from_account_id = keypair.to_account_id_ss58check();
	let balance = get_balance(&quantus_client, &from_account_id).await?;

	// Get formatted balance with proper decimals
	let formatted_balance = format_balance_with_symbol(&quantus_client, balance).await?;
	log_verbose!("💰 Current balance: {}", formatted_balance.bright_yellow());

	if balance < amount {
		return Err(crate::error::QuantusError::InsufficientBalance {
			available: balance,
			required: amount,
		});
	}

	// Create and submit transaction
	log_verbose!("✍️  {} Signing transaction...", "SIGN".bright_magenta().bold());

	// Parse tip amount if provided
	let tip_amount = if let Some(tip_str) = &tip {
		// Get chain properties for proper decimal parsing
		let (_, decimals) = get_chain_properties(&quantus_client).await?;
		parse_amount_with_decimals(tip_str, decimals).ok()
	} else {
		None
	};

	// Submit transaction
	let tx_hash = transfer_with_nonce(
		&quantus_client,
		&keypair,
		&resolved_address,
		amount,
		tip_amount,
		nonce,
	)
	.await?;

	log_print!("✅ {} Transaction submitted! Hash: {:?}", "SUCCESS".bright_green().bold(), tx_hash);

	let success = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;

	if success {
		log_info!("✅ Transaction confirmed and finalized on chain");
		log_success!("🎉 {} Transaction confirmed!", "FINISHED".bright_green().bold());

		// Show updated balance with proper formatting
		let new_balance = get_balance(&quantus_client, &from_account_id).await?;
		let formatted_new_balance =
			format_balance_with_symbol(&quantus_client, new_balance).await?;

		// Calculate and display transaction fee in verbose mode
		let fee_paid = balance.saturating_sub(new_balance).saturating_sub(amount);
		if fee_paid > 0 {
			let formatted_fee = format_balance_with_symbol(&quantus_client, fee_paid).await?;
			log_verbose!("💸 Transaction fee: {}", formatted_fee.bright_cyan());
		}

		log_print!("💰 New balance: {}", formatted_new_balance.bright_yellow());
	} else {
		log_error!("Transaction failed!");
	}

	Ok(())
}

/// Load transfers from JSON file
pub async fn load_transfers_from_file(file_path: &str) -> Result<Vec<(String, u128)>> {
	use serde_json;
	use std::fs;

	#[derive(serde::Deserialize)]
	struct TransferEntry {
		to: String,
		amount: String,
	}

	let content = fs::read_to_string(file_path).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read batch file: {e:?}"))
	})?;

	let entries: Vec<TransferEntry> = serde_json::from_str(&content).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to parse batch file JSON: {e:?}"))
	})?;

	let mut transfers = Vec::new();
	for entry in entries {
		// Parse amount as raw units (no decimals conversion here)
		let amount = entry.amount.parse::<u128>().map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid amount '{}': {e:?}", entry.amount))
		})?;
		transfers.push((entry.to, amount));
	}

	Ok(transfers)
}

/// Get chain constants for batch limits
pub async fn get_batch_limits(quantus_client: &QuantusClient) -> Result<(u32, u32)> {
	// Try to get actual chain constants
	let constants = quantus_client.client().constants();

	// Get block weight limit
	let block_weight_limit = constants
		.at(&quantus_subxt::api::constants().system().block_weights())
		.map(|weights| weights.max_block.ref_time)
		.unwrap_or(2_000_000_000_000); // Default 2 trillion weight units

	// Estimate transfers per block (rough calculation)
	let transfer_weight = 1_500_000_000u64; // Rough estimate per transfer
	let max_transfers_by_weight = (block_weight_limit / transfer_weight) as u32;

	// Get max extrinsic length
	let max_extrinsic_length = constants
		.at(&quantus_subxt::api::constants().system().block_length())
		.map(|length| length.max.normal)
		.unwrap_or(5_242_880); // Default 5MB

	// Estimate transfers per extrinsic size (very rough)
	let transfer_size = 100u32; // Rough estimate per transfer in bytes
	let max_transfers_by_size = max_extrinsic_length / transfer_size;

	let recommended_limit = std::cmp::min(max_transfers_by_weight, max_transfers_by_size);
	let safe_limit = recommended_limit / 2; // Be conservative

	log_verbose!(
		"📊 Chain limits: weight allows ~{}, size allows ~{}",
		max_transfers_by_weight,
		max_transfers_by_size
	);
	log_verbose!("📊 Recommended batch size: {} (safe: {})", recommended_limit, safe_limit);

	Ok((safe_limit, recommended_limit))
}
