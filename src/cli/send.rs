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

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let account_info = storage_at.fetch_or_default(&storage_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch account info: {:?}", e))
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
			"Invalid amount format: '{}'. Use formats like '10', '10.5', '0.0001'",
			amount_part
		))
	})?;

	if parsed_amount < 0.0 {
		return Err(crate::error::QuantusError::Generic("Amount cannot be negative".to_string()));
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

/// Transfer tokens
pub async fn transfer(
	quantus_client: &QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	to_address: &str,
	amount: u128,
	tip: Option<u128>,
) -> Result<subxt::utils::H256> {
	log_verbose!("🚀 Creating transfer transaction...");
	log_verbose!("   From: {}", from_keypair.to_account_id_ss58check().bright_cyan());
	log_verbose!("   To: {}", to_address.bright_green());
	log_verbose!("   Amount: {}", amount);

	// Resolve the destination address (could be wallet name or SS58 address)
	let resolved_address = resolve_address(to_address)?;
	log_verbose!("   Resolved to: {}", resolved_address.bright_green());

	// Parse the destination address
	let to_account_id_sp = SpAccountId32::from_ss58check(&resolved_address).map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Invalid destination address: {:?}", e))
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

	// Submit the transaction
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		transfer_call,
		Some(tip_to_use),
	)
	.await?;

	log_verbose!("📋 Transaction submitted: {:?}", tx_hash);

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
	let tx_hash =
		transfer(&quantus_client, &keypair, &resolved_address, amount, tip_amount).await?;

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
