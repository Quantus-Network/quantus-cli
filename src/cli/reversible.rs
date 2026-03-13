use crate::{
	chain::quantus_subxt,
	cli::{address_format::QuantusSS58, common::resolve_address},
	error::Result,
	log_info, log_print, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};
use std::str::FromStr;

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
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<subxt::utils::H256> {
	log_verbose!("🔄 Creating reversible transfer...");
	log_verbose!("   From: {}", from_keypair.to_account_id_ss58check().bright_cyan());
	log_verbose!("   To: {}", to_address.bright_green());
	log_verbose!("   Amount: {}", amount);

	// Parse the destination address
	let (to_account_id_sp, _version) = SpAccountId32::from_ss58check_with_version(to_address)
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Invalid destination address: {e:?}"))
		})?;

	// Convert to subxt_core AccountId32
	let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
	let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

	log_verbose!("✍️  Creating reversible transfer extrinsic...");

	// Create the reversible transfer call using static API from quantus_subxt
	let transfer_call = quantus_subxt::api::tx()
		.reversible_transfers()
		.schedule_transfer(subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id), amount);

	// Submit the transaction
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		transfer_call,
		None,
		execution_mode,
	)
	.await?;

	log_verbose!("📋 Reversible transfer submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// Cancel a pending reversible transaction
pub async fn cancel_transaction(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	tx_id: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<subxt::utils::H256> {
	log_verbose!("❌ Cancelling reversible transfer...");
	log_verbose!("   Transaction ID: {}", tx_id.bright_yellow());

	// Parse transaction ID using H256::from_str
	let tx_hash = subxt::utils::H256::from_str(tx_id).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Invalid transaction ID: {e:?}"))
	})?;

	log_verbose!("✍️  Creating cancel transaction extrinsic...");

	// Create the cancel transaction call using static API from quantus_subxt
	let cancel_call = quantus_subxt::api::tx().reversible_transfers().cancel(tx_hash);

	// Submit the transaction
	let tx_hash_result = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		cancel_call,
		None,
		execution_mode,
	)
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
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<subxt::utils::H256> {
	let unit_str = if unit_blocks { "blocks" } else { "seconds" };
	log_verbose!("🔄 Creating reversible transfer with custom delay ...");
	log_verbose!("   From: {}", from_keypair.to_account_id_ss58check().bright_cyan());
	log_verbose!("   To: {}", to_address.bright_green());
	log_verbose!("   Amount: {}", amount);
	log_verbose!("   Delay: {} {}", delay, unit_str);

	// Parse the destination address
	let to_account_id_sp = SpAccountId32::from_ss58check(to_address).map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Invalid destination address: {e:?}"))
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
	let transfer_call =
		quantus_subxt::api::tx().reversible_transfers().schedule_transfer_with_delay(
			subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
			amount,
			delay_value,
		);

	// Submit the transaction
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		transfer_call,
		None,
		execution_mode,
	)
	.await?;

	log_verbose!("📋 Reversible transfer with custom delay submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// Handle reversible transfer subxt commands
pub async fn handle_reversible_command(
	command: ReversibleCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<()> {
	log_print!("🔄 Reversible Transfers");

	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		ReversibleCommands::ListPending { address, from, password, password_file } =>
			list_pending_transactions(&quantus_client, address, from, password, password_file).await,
		ReversibleCommands::ScheduleTransfer { to, amount, from, password, password_file } => {
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
			let tx_hash = schedule_transfer(
				&quantus_client,
				&keypair,
				&resolved_address,
				raw_amount,
				execution_mode,
			)
			.await?;

			log_print!(
				"✅ {} Reversible transfer scheduled! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);

			Ok(())
		},
		ReversibleCommands::Cancel { tx_id, from, password, password_file } => {
			log_verbose!(
				"❌ {} Cancelling reversible transfer {} ()",
				"CANCEL".bright_red().bold(),
				tx_id.bright_yellow().bold()
			);

			// Get password securely for decryption
			log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

			// Submit cancel transaction
			let tx_hash =
				cancel_transaction(&quantus_client, &keypair, &tx_id, execution_mode).await?;

			log_print!(
				"✅ {} Cancel transaction submitted! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);

			Ok(())
		},

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
				execution_mode,
			)
			.await?;

			log_print!(
				"✅ {} Reversible transfer with custom delay scheduled! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);

			Ok(())
		},
	}
}

/// List all pending reversible transactions for an account
async fn list_pending_transactions(
	quantus_client: &crate::chain::client::QuantusClient,
	address: Option<String>,
	wallet_name: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	log_print!("📋 Listing pending reversible transactions");

	// Determine which address to query
	let target_address = match (address, wallet_name) {
		(Some(addr), _) => {
			// --address accepts SS58 or wallet name
			resolve_address(&addr)?
		},
		(None, Some(wallet)) => {
			// Load wallet and get its address
			let keypair =
				crate::wallet::load_keypair_from_wallet(&wallet, password, password_file)?;
			keypair.to_account_id_ss58check()
		},
		(None, None) => {
			return Err(crate::error::QuantusError::Generic(
				"Either --address or --from must be provided".to_string(),
			));
		},
	};

	// Convert to AccountId32 for storage queries
	let account_id_sp = SpAccountId32::from_ss58check(&target_address)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {e:?}")))?;
	let account_id_bytes: [u8; 32] = *account_id_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_id_bytes);

	log_verbose!("🔍 Querying pending transfers for: {}", target_address);

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let pending_iter = crate::chain::quantus_subxt::api::storage()
		.reversible_transfers()
		.pending_transfers_iter();

	let mut outgoing = Vec::new();
	let mut incoming = Vec::new();
	let mut iter = storage_at.iter(pending_iter).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Storage iter error: {e:?}"))
	})?;

	while let Some(result) = iter.next().await {
		match result {
			Ok(entry) => {
				// Key is storage prefix + tx_id (H256, 32 bytes). Extract last 32 bytes.
				let tx_id_hex = if entry.key_bytes.len() >= 32 {
					hex::encode(&entry.key_bytes[entry.key_bytes.len() - 32..])
				} else {
					hex::encode(&entry.key_bytes)
				};
				let transfer = entry.value;
				if transfer.from == account_id {
					outgoing.push((tx_id_hex, transfer));
				} else if transfer.to == account_id {
					incoming.push((tx_id_hex, transfer));
				}
			},
			Err(e) => {
				log_verbose!("⚠️  Error reading pending transfer: {:?}", e);
			},
		}
	}

	let mut total_transfers = 0;

	if !outgoing.is_empty() {
		log_print!("📤 Outgoing pending transfers:");
		for (i, (tx_id_hex, transfer)) in outgoing.iter().enumerate() {
			total_transfers += 1;
			log_print!("   {}. 0x{}", i + 1, tx_id_hex);
			let formatted_amount = format_amount(transfer.amount);
			log_print!("      👤 To: {}", transfer.to.to_quantus_ss58());
			log_print!("      💰 Amount: {}", formatted_amount);
			log_print!("      🔄 Interceptor: {}", transfer.interceptor.to_quantus_ss58());
		}
	}

	if !incoming.is_empty() {
		if total_transfers > 0 {
			log_print!("");
		}
		log_print!("📥 Incoming pending transfers:");
		for (i, (tx_id_hex, transfer)) in incoming.iter().enumerate() {
			total_transfers += 1;
			log_print!("   {}. 0x{}", i + 1, tx_id_hex);
			let formatted_amount = format_amount(transfer.amount);
			log_print!("      👤 From: {}", transfer.from.to_quantus_ss58());
			log_print!("      💰 Amount: {}", formatted_amount);
			log_print!("      🔄 Interceptor: {}", transfer.interceptor.to_quantus_ss58());
		}
	}

	if total_transfers == 0 {
		log_print!("📝 No pending transfers found for account: {}", target_address);
	} else {
		log_print!("");
		log_print!("📊 Total pending transfers: {}", total_transfers);
		log_print!("💡 Use transaction hash with 'quantus reversible cancel --tx-id <hash>' to cancel outgoing transfers");
	}

	Ok(())
}

/// Helper function to format amount with QUAN units
fn format_amount(amount: u128) -> String {
	const QUAN_DECIMALS: u128 = 1_000_000_000_000; // 10^12

	if amount >= QUAN_DECIMALS {
		let whole = amount / QUAN_DECIMALS;
		let fractional = amount % QUAN_DECIMALS;

		if fractional == 0 {
			format!("{whole} QUAN")
		} else {
			// Remove trailing zeros from fractional part
			let fractional_str = format!("{fractional:012}");
			let trimmed = fractional_str.trim_end_matches('0');
			format!("{whole}.{trimmed} QUAN")
		}
	} else {
		format!("{amount} pico-QUAN")
	}
}
