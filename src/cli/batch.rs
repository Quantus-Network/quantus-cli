//! Batch transfer commands and configuration
use crate::{
	chain::client::QuantusClient,
	cli::send::{
		batch_transfer, get_batch_limits, load_transfers_from_file, validate_and_format_amount,
	},
	error::Result,
	log_info, log_print, log_success,
};
use clap::Subcommand;
use colored::Colorize;

#[derive(Subcommand, Debug)]
pub enum BatchCommands {
	/// Send tokens to multiple recipients in a single batch transaction
	Send {
		/// Wallet name to send from
		#[arg(short, long)]
		from: String,

		/// Password for the wallet (or use environment variables)
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Optional tip amount to prioritize the transaction (e.g., "1", "0.5")
		#[arg(long)]
		tip: Option<String>,

		/// Batch file with transfers (JSON format: [{"to": "address", "amount": "1000"}, ...];
		/// amounts are raw smallest-unit integers)
		#[arg(long)]
		batch_file: Option<String>,

		/// Number of identical transfers to generate for testing
		#[arg(long)]
		count: Option<u32>,

		/// Recipient address for generated transfers (required with --count)
		#[arg(long)]
		to: Option<String>,

		/// Amount per transfer for generated transfers (required with --count)
		#[arg(long)]
		amount: Option<String>,
	},

	/// Configuration and limits for batch transfers
	Config {
		/// Show current batch transfer limits for the connected chain
		#[arg(long)]
		limits: bool,

		/// Show batch transfer configuration and recommendations
		#[arg(long)]
		info: bool,
	},
}

/// Handle batch commands
pub async fn handle_batch_command(
	command: BatchCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<()> {
	match command {
		BatchCommands::Send {
			from,
			password,
			password_file,
			tip,
			batch_file,
			count,
			to,
			amount,
		} =>
			handle_batch_send_command(
				from,
				node_url,
				password,
				password_file,
				tip,
				batch_file,
				count,
				to,
				amount,
				execution_mode,
			)
			.await,
		BatchCommands::Config { limits, info } =>
			handle_batch_config_command(node_url, limits, info).await,
	}
}

/// Handle the batch send command (moved from send.rs)
async fn handle_batch_send_command(
	from_wallet: String,
	node_url: &str,
	password: Option<String>,
	password_file: Option<String>,
	tip: Option<String>,
	batch_file: Option<String>,
	count: Option<u32>,
	to: Option<String>,
	amount: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<()> {
	// Create quantus chain client
	let quantus_client = QuantusClient::new(node_url).await?;

	// Prepare transfers list
	let transfers = if let Some(file_path) = batch_file {
		// Load from JSON file
		load_transfers_from_file(&file_path).await?
	} else if let (Some(count_val), Some(to_addr), Some(amount_str)) = (count, to, amount) {
		// Generate identical transfers
		let (parsed_amount, _) = validate_and_format_amount(&quantus_client, &amount_str).await?;
		let mut transfers = Vec::new();
		for _ in 0..count_val {
			transfers.push((to_addr.clone(), parsed_amount));
		}
		transfers
	} else {
		return Err(crate::error::QuantusError::Generic(
			"Either --batch-file or (--count + --to + --amount) must be provided".to_string(),
		));
	};

	if transfers.is_empty() {
		return Err(crate::error::QuantusError::Generic("No transfers to process".to_string()));
	}

	log_info!("🚀 Initiating batch transfer with {} transfers", transfers.len());

	// Parse tip if provided
	let tip_amount = if let Some(tip_str) = tip {
		let (tip_val, _) = validate_and_format_amount(&quantus_client, &tip_str).await?;
		Some(tip_val)
	} else {
		None
	};

	// Load wallet
	let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;
	let from_account_id = keypair.to_account_id_ss58check();
	let effective_tip = crate::cli::send::effective_tip_amount(tip_amount);

	// Check balance
	let balance = crate::cli::send::get_balance(&quantus_client, &from_account_id).await?;
	let total_amount = transfers.iter().try_fold(0u128, |acc, (_, amount)| {
		acc.checked_add(*amount).ok_or_else(|| {
			crate::error::QuantusError::Generic(
				"Batch amount total is too large to represent".to_string(),
			)
		})
	})?;
	let exact_required = total_amount.checked_add(effective_tip).ok_or_else(|| {
		crate::error::QuantusError::Generic(
			"Batch amount total is too large to represent".to_string(),
		)
	})?;

	if balance < exact_required {
		let formatted_balance =
			crate::cli::send::format_balance_with_symbol(&quantus_client, balance).await?;
		let formatted_needed =
			crate::cli::send::format_balance_with_symbol(&quantus_client, exact_required).await?;
		return Err(crate::error::QuantusError::Generic(format!(
			"Insufficient balance. Have: {formatted_balance}, Need: {formatted_needed} (including tip)"
		)));
	}

	let batch_call = crate::cli::send::build_batch_transfer_call(&transfers)?;
	match crate::cli::send::estimate_transaction_partial_fee(
		&quantus_client,
		&keypair,
		&batch_call,
		Some(effective_tip),
	)
	.await
	{
		Ok(estimated_fee) => {
			let estimated_total = exact_required.checked_add(estimated_fee).ok_or_else(|| {
				crate::error::QuantusError::Generic(
					"Batch amount total is too large to represent".to_string(),
				)
			})?;
			if balance < estimated_total {
				let formatted_balance =
					crate::cli::send::format_balance_with_symbol(&quantus_client, balance).await?;
				let formatted_needed =
					crate::cli::send::format_balance_with_symbol(&quantus_client, estimated_total)
						.await?;
				let formatted_tip =
					crate::cli::send::format_balance_with_symbol(&quantus_client, effective_tip)
						.await?;
				let formatted_fee =
					crate::cli::send::format_balance_with_symbol(&quantus_client, estimated_fee)
						.await?;
				return Err(crate::error::QuantusError::Generic(format!(
					"Insufficient balance. Have: {formatted_balance}, Need: {formatted_needed} (tip: {formatted_tip}, estimated fee: {formatted_fee})"
				)));
			}
		},
		Err(err) => {
			log_print!(
				"ℹ️  Fee estimation unavailable; proceeding with exact amount+tip check only: {}",
				err
			);
		},
	}

	// Submit batch transaction
	let tx_hash =
		batch_transfer(&quantus_client, &keypair, transfers, tip_amount, execution_mode).await?;

	let transaction_stage = execution_mode.transaction_stage();
	log_print!(
		"✅ {} Batch transaction {}. Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		transaction_stage.status_label(),
		tx_hash
	);

	if !execution_mode.should_refresh_post_submit_state() {
		log_print!(
			"ℹ️  The batch transaction was {} but this command did not wait for block inclusion. Use --wait-for-transaction or --finalized-tx to wait before returning.",
			transaction_stage.success_detail()
		);
		return Ok(());
	}

	log_success!(
		"🎉 {} Batch transaction {}.",
		"FINISHED".bright_green().bold(),
		transaction_stage.success_detail()
	);

	// Show updated balance
	let new_balance = crate::cli::send::get_balance(&quantus_client, &from_account_id).await?;
	let formatted_new_balance =
		crate::cli::send::format_balance_with_symbol(&quantus_client, new_balance).await?;
	log_print!("💰 New balance: {}", formatted_new_balance.bright_yellow());

	Ok(())
}

/// Handle batch config command
async fn handle_batch_config_command(
	node_url: &str,
	show_limits: bool,
	show_info: bool,
) -> Result<()> {
	let quantus_client = QuantusClient::new(node_url).await?;

	if show_limits {
		log_info!("🔍 Checking batch transfer limits for chain...");

		let (safe_limit, recommended_limit) = get_batch_limits(&quantus_client).await?;

		log_print!("📊 {} Batch Transfer Limits", "CHAIN".bright_cyan().bold());
		log_print!("   • Safe batch size: {} transfers", safe_limit.to_string().bright_green());
		log_print!(
			"   • Maximum batch size: {} transfers",
			recommended_limit.to_string().bright_yellow()
		);
		log_print!("   • For larger batches, split into multiple transactions");
	}

	if show_info {
		log_print!("ℹ️  {} Batch Transfer Information", "CONFIG".bright_cyan().bold());
		log_print!("   • Batch transfers use utility.batch() pallet");
		log_print!("   • All transfers in one transaction (atomic)");
		log_print!("   • Single nonce used for all transfers");
		log_print!("   • Lower fees compared to individual transfers");
		log_print!("   • If one transfer fails, entire batch fails");
		log_print!("");
		log_print!("📝 {} Usage Examples", "EXAMPLES".bright_cyan().bold());
		log_print!("   quantus batch send --from alice --count 100 --to bob --amount 1000");
		log_print!("   quantus batch send --from alice --batch-file transfers.json");
		log_print!("   quantus batch config --limits");
	}

	// If no flags provided, show both
	if !show_limits && !show_info {
		// Avoid recursion by calling the logic directly
		let quantus_client = QuantusClient::new(node_url).await?;

		// Show limits
		log_info!("🔍 Checking batch transfer limits for chain...");
		let (safe_limit, recommended_limit) = get_batch_limits(&quantus_client).await?;
		log_print!("📊 {} Batch Transfer Limits", "CHAIN".bright_cyan().bold());
		log_print!("   • Safe batch size: {} transfers", safe_limit.to_string().bright_green());
		log_print!(
			"   • Maximum batch size: {} transfers",
			recommended_limit.to_string().bright_yellow()
		);
		log_print!("   • For larger batches, split into multiple transactions");

		// Show info
		log_print!("ℹ️  {} Batch Transfer Information", "CONFIG".bright_cyan().bold());
		log_print!("   • Batch transfers use utility.batch() pallet");
		log_print!("   • All transfers in one transaction (atomic)");
		log_print!("   • Single nonce used for all transfers");
		log_print!("   • Lower fees compared to individual transfers");
		log_print!("   • If one transfer fails, entire batch fails");
		log_print!("");
		log_print!("📝 {} Usage Examples", "EXAMPLES".bright_cyan().bold());
		log_print!("   quantus batch send --from alice --count 100 --to bob --amount 1000");
		log_print!("   quantus batch send --from alice --batch-file transfers.json");
		log_print!("   quantus batch config --limits");
	}

	Ok(())
}
