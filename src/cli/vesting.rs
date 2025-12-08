//! `quantus vesting` subcommand - manage Vesting schedules
use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::common::{resolve_address, submit_transaction_with_finalization},
	log_print, log_success,
	wallet::load_keypair_from_wallet,
};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};

/// Vesting management commands
#[derive(Subcommand, Debug)]
pub enum VestingCommands {
	/// Show vesting information for an account
	Info {
		/// Account address to query
		#[arg(long)]
		address: String,
	},

	/// Unlock vested funds (your own or help someone else)
	Unlock {
		/// Unlock vesting for another account (optional - if not provided, unlocks for yourself)
		#[arg(long)]
		for_account: Option<String>,

		/// Wallet name to sign with
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Create a vested transfer
	Transfer {
		/// Recipient address
		#[arg(long)]
		to: String,

		/// Total locked amount (e.g., "1000.0")
		#[arg(long)]
		locked: String,

		/// Duration value
		#[arg(long)]
		duration: u32,

		/// Time unit: blocks, hours, days, weeks, months, years (default: days)
		#[arg(long, default_value = "days")]
		unit: String,

		/// Starting block number (defaults to current block + 10)
		#[arg(long)]
		starting_block: Option<u32>,

		/// Wallet name to sign with
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Force a vested transfer (requires Root/Sudo)
	ForceTransfer {
		/// Source account (funds will be taken from here)
		#[arg(long)]
		source: String,

		/// Recipient address
		#[arg(long)]
		target: String,

		/// Total locked amount (e.g., "1000.0")
		#[arg(long)]
		locked: String,

		/// Duration value
		#[arg(long)]
		duration: u32,

		/// Time unit: blocks, hours, days, weeks, months, years (default: days)
		#[arg(long, default_value = "days")]
		unit: String,

		/// Starting block number (defaults to current block + 10)
		#[arg(long)]
		starting_block: Option<u32>,

		/// Wallet name to sign with (must have sudo/root)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Merge two vesting schedules
	Merge {
		/// Index of first schedule
		#[arg(long)]
		schedule1: u32,

		/// Index of second schedule
		#[arg(long)]
		schedule2: u32,

		/// Wallet name to sign with
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// List all vesting schedules for an account
	List {
		/// Account address to query
		#[arg(long)]
		address: String,
	},

	/// Calculate vesting parameters
	Calculate {
		/// Total locked amount (e.g., "1000.0")
		#[arg(long)]
		locked: String,

		/// Duration value
		#[arg(long)]
		duration: u32,

		/// Time unit: blocks, hours, days, weeks, months, years (default: days)
		#[arg(long, default_value = "days")]
		unit: String,

		/// Starting block (optional, defaults to current)
		#[arg(long)]
		starting_block: Option<u32>,
	},
}

/// Handle vesting commands
pub async fn handle_vesting_command(
	command: VestingCommands,
	node_url: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	match command {
		VestingCommands::Info { address } => handle_info(address, node_url).await,
		VestingCommands::Unlock { for_account, from, password, password_file } => {
			handle_unlock(for_account, from, password, password_file, node_url, finalized).await
		},
		VestingCommands::Transfer {
			to,
			locked,
			duration,
			unit,
			starting_block,
			from,
			password,
			password_file,
		} => {
			let duration_in_blocks = convert_to_blocks(duration, &unit)?;
			handle_transfer(
				to,
				locked,
				duration_in_blocks,
				starting_block,
				from,
				password,
				password_file,
				node_url,
				finalized,
			)
			.await
		},
		VestingCommands::ForceTransfer {
			source,
			target,
			locked,
			duration,
			unit,
			starting_block,
			from,
			password,
			password_file,
		} => {
			let duration_in_blocks = convert_to_blocks(duration, &unit)?;
			handle_force_transfer(
				source,
				target,
				locked,
				duration_in_blocks,
				starting_block,
				from,
				password,
				password_file,
				node_url,
				finalized,
			)
			.await
		},
		VestingCommands::Merge { schedule1, schedule2, from, password, password_file } => {
			handle_merge(schedule1, schedule2, from, password, password_file, node_url, finalized)
				.await
		},
		VestingCommands::List { address } => handle_list(address, node_url).await,
		VestingCommands::Calculate { locked, duration, unit, starting_block } => {
			let duration_in_blocks = convert_to_blocks(duration, &unit)?;
			handle_calculate(locked, duration_in_blocks, starting_block, node_url).await
		},
	}
}

/// Constants for time calculations
const BLOCK_TIME_MS: u64 = 6000; // 6 seconds per block
const BLOCKS_PER_HOUR: u32 = 600; // 3600s / 6s
const BLOCKS_PER_DAY: u32 = 14400; // 600 * 24
const BLOCKS_PER_WEEK: u32 = 100800; // 14400 * 7
const BLOCKS_PER_MONTH: u32 = 432000; // 14400 * 30
const BLOCKS_PER_YEAR: u32 = 5256000; // 14400 * 365

/// Convert duration with unit to blocks
fn convert_to_blocks(duration: u32, unit: &str) -> crate::error::Result<u32> {
	match unit.to_lowercase().as_str() {
		"blocks" | "block" => Ok(duration),
		"hours" | "hour" | "h" => Ok(duration * BLOCKS_PER_HOUR),
		"days" | "day" | "d" => Ok(duration * BLOCKS_PER_DAY),
		"weeks" | "week" | "w" => Ok(duration * BLOCKS_PER_WEEK),
		"months" | "month" | "m" => Ok(duration * BLOCKS_PER_MONTH),
		"years" | "year" | "y" => Ok(duration * BLOCKS_PER_YEAR),
		_ => Err(crate::error::QuantusError::Generic(format!(
			"Invalid time unit: '{}'. Valid units: blocks, hours, days, weeks, months, years",
			unit
		))),
	}
}

/// Convert block number to UTC timestamp
async fn block_to_utc(
	client: &QuantusClient,
	block_number: u32,
) -> crate::error::Result<DateTime<Utc>> {
	// Get current block
	let current_block = client
		.client()
		.blocks()
		.at_latest()
		.await
		.map_err(|e| crate::error::QuantusError::Subxt(Box::new(e)))?
		.number();

	// Calculate time difference in milliseconds
	// Can be negative (past) or positive (future)
	let block_diff = (block_number as i64) - (current_block as i64);

	let time_diff_ms = block_diff * (BLOCK_TIME_MS as i64);
	let timestamp = Utc::now() + chrono::Duration::milliseconds(time_diff_ms);

	Ok(timestamp)
}

/// Format duration in a human-readable way
fn format_duration(blocks: u32) -> String {
	let total_seconds = (blocks as u64) * (BLOCK_TIME_MS / 1000);
	let days = total_seconds / 86400;
	let hours = (total_seconds % 86400) / 3600;
	let minutes = (total_seconds % 3600) / 60;

	if days > 0 {
		format!("{} days, {} hours", days, hours)
	} else if hours > 0 {
		format!("{} hours, {} minutes", hours, minutes)
	} else {
		format!("{} minutes", minutes)
	}
}

/// Parse amount string to planck (smallest unit)
fn parse_amount_to_planck(amount: &str) -> crate::error::Result<u128> {
	let value: f64 = amount
		.parse()
		.map_err(|_| crate::error::QuantusError::Generic(format!("Invalid amount: {}", amount)))?;

	if value < 0.0 {
		return Err(crate::error::QuantusError::Generic("Amount cannot be negative".to_string()));
	}

	// Convert to planck (assuming 12 decimals)
	let planck = (value * 1_000_000_000_000.0) as u128;
	Ok(planck)
}

/// Format planck to human-readable amount
fn format_planck(planck: u128) -> String {
	let amount = (planck as f64) / 1_000_000_000_000.0;
	format!("{:.4} QUAN", amount)
}

/// Validate vesting parameters
fn validate_vesting_params(
	locked: u128,
	per_block: u128,
	starting_block: u32,
	current_block: u32,
) -> crate::error::Result<()> {
	// Validate locked amount
	if locked == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Locked amount must be greater than 0".to_string(),
		));
	}

	// Validate per_block
	if per_block == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Per-block amount must be greater than 0".to_string(),
		));
	}

	// per_block should not exceed locked amount
	if per_block > locked {
		return Err(crate::error::QuantusError::Generic(
			"Per-block amount cannot exceed total locked amount".to_string(),
		));
	}

	// Starting block should be in the future or very close to current
	if starting_block < current_block && (current_block - starting_block) > 10 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Starting block {} is too far in the past (current: {})",
			starting_block, current_block
		)));
	}

	Ok(())
}

/// Handle info command
async fn handle_info(address: String, node_url: &str) -> crate::error::Result<()> {
	log_print!("📊 {} Vesting Info", "VESTING".bright_cyan().bold());
	log_print!("");

	let client = QuantusClient::new(node_url).await?;
	let address_str = resolve_address(&address)?;
	let account_id = AccountId32::from_ss58check(&address_str)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {e:?}")))?;

	// Convert to subxt AccountId32
	let account_id_bytes: [u8; 32] = *account_id.as_ref();
	let account_id_subxt = subxt::utils::AccountId32::from(account_id_bytes);

	// Query vesting schedules
	let storage_query = quantus_subxt::api::storage().vesting().vesting(account_id_subxt);

	let schedules = client
		.client()
		.storage()
		.at_latest()
		.await
		.map_err(|e| crate::error::QuantusError::Subxt(Box::new(e)))?
		.fetch(&storage_query)
		.await
		.map_err(|e| crate::error::QuantusError::Subxt(Box::new(e)))?;

	if let Some(schedules) = schedules {
		let current_block = client.client().blocks().at_latest().await?.number();

		log_print!("Address: {}", address.bright_cyan());
		log_print!("Current Block: {}", current_block.to_string().bright_yellow());
		log_print!("");
		log_print!("Vesting Schedules:");
		log_print!("");

		for (idx, schedule) in schedules.0.iter().enumerate() {
			log_print!("  {} Schedule #{}", "◆".bright_green(), idx);
			log_print!("    Locked:         {}", format_planck(schedule.locked).bright_yellow());
			log_print!("    Per Block:      {}", format_planck(schedule.per_block).bright_blue());
			log_print!(
				"    Starting Block: {}",
				schedule.starting_block.to_string().bright_magenta()
			);

			// Calculate ending block
			let duration_blocks = schedule.locked / schedule.per_block;
			let ending_block = schedule.starting_block + duration_blocks as u32;

			log_print!("    Ending Block:   {}", ending_block.to_string().bright_magenta());

			// Calculate and show UTC times
			let start_time = block_to_utc(&client, schedule.starting_block).await?;
			let end_time = block_to_utc(&client, ending_block).await?;

			log_print!(
				"    Start Time:     {} {}",
				start_time.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan(),
				"UTC".dimmed()
			);
			log_print!(
				"    End Time:       {} {}",
				end_time.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan(),
				"UTC".dimmed()
			);

			// Calculate progress
			if current_block < schedule.starting_block {
				log_print!("    Status:         {}", "Not Started".bright_yellow());
			} else if current_block >= ending_block {
				log_print!("    Status:         {}", "Completed".bright_green());
			} else {
				let elapsed_blocks = current_block - schedule.starting_block;
				let unlocked = elapsed_blocks as u128 * schedule.per_block;
				let remaining = schedule.locked - unlocked;

				let progress_pct = (unlocked as f64 / schedule.locked as f64) * 100.0;

				log_print!("    Status:         {}", "Active".bright_green());
				log_print!(
					"    Unlocked:       {} ({:.2}%)",
					format_planck(unlocked).bright_green(),
					progress_pct
				);
				log_print!("    Remaining:      {}", format_planck(remaining).bright_red());
				log_print!(
					"    Duration:       {}",
					format_duration(duration_blocks as u32).dimmed()
				);
			}

			log_print!("");
		}
	} else {
		log_print!("Address: {}", address.bright_cyan());
		log_print!("");
		log_print!("  {} No vesting schedules found", "ℹ".bright_blue());
	}

	Ok(())
}

/// Handle unlock command (vest or vest_other depending on for_account parameter)
async fn handle_unlock(
	for_account: Option<String>,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	let keypair = load_keypair_from_wallet(&from, password, password_file)?;
	let client = QuantusClient::new(node_url).await?;

	match for_account {
		None => {
			// Unlock own vesting
			log_print!("🔓 {} Unlocking Your Vested Funds", "VESTING".bright_cyan().bold());
			log_print!("");

			let vest_tx = quantus_subxt::api::tx().vesting().vest();
			submit_transaction_with_finalization(&client, &keypair, vest_tx, None, finalized)
				.await?;

			log_success!("✅ Vesting unlock transaction submitted successfully");
		},
		Some(target) => {
			// Unlock someone else's vesting
			log_print!(
				"🔓 {} Unlocking Vested Funds for {}",
				"VESTING".bright_cyan().bold(),
				target.bright_cyan()
			);
			log_print!("");

			let target_address_str = resolve_address(&target)?;
			let target_account_id =
				AccountId32::from_ss58check(&target_address_str).map_err(|e| {
					crate::error::QuantusError::Generic(format!("Invalid address: {e:?}"))
				})?;
			let target_account_bytes: [u8; 32] = *target_account_id.as_ref();
			let target_account_subxt = subxt::utils::AccountId32::from(target_account_bytes);

			let vest_other_tx =
				quantus_subxt::api::tx().vesting().vest_other(target_account_subxt.into());
			submit_transaction_with_finalization(&client, &keypair, vest_other_tx, None, finalized)
				.await?;

			log_success!("✅ Vesting unlocked for {}", target.bright_cyan());
		},
	}

	Ok(())
}

/// Handle transfer command
#[allow(clippy::too_many_arguments)]
async fn handle_transfer(
	to: String,
	locked: String,
	duration_blocks: u32,
	starting_block: Option<u32>,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("📤 {} Vested Transfer", "VESTING".bright_cyan().bold());
	log_print!("");

	let keypair = load_keypair_from_wallet(&from, password, password_file)?;
	let client = QuantusClient::new(node_url).await?;
	let target_address_str = resolve_address(&to)?;
	let target_account_id = AccountId32::from_ss58check(&target_address_str)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {e:?}")))?;
	let target_account_bytes: [u8; 32] = *target_account_id.as_ref();
	let target_account_subxt = subxt::utils::AccountId32::from(target_account_bytes);

	// Parse locked amount
	let locked_planck = parse_amount_to_planck(&locked)?;

	// Validate duration
	if duration_blocks == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Duration must be greater than 0".to_string(),
		));
	}

	// Calculate per_block from duration
	let per_block_planck = locked_planck / duration_blocks as u128;

	if per_block_planck == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Duration is too long - per_block amount would be zero".to_string(),
		));
	}

	// Get current block and determine starting block
	let current_block = client.client().blocks().at_latest().await?.number();
	let start_block = starting_block.unwrap_or(current_block + 10);

	// Validate parameters
	validate_vesting_params(locked_planck, per_block_planck, start_block, current_block)?;

	// Show summary
	log_print!("Transfer Details:");
	log_print!("  To:            {}", to.bright_cyan());
	log_print!("  Locked:        {}", format_planck(locked_planck).bright_yellow());
	log_print!("  Start Block:   {}", start_block.to_string().bright_magenta());

	let duration = locked_planck / per_block_planck;
	let end_block = start_block + duration as u32;
	log_print!("  End Block:     {}", end_block.to_string().bright_magenta());
	log_print!("  Duration:      {}", format_duration(duration as u32).dimmed());

	let start_time = block_to_utc(&client, start_block).await?;
	let end_time = block_to_utc(&client, end_block).await?;
	log_print!(
		"  Start Time:    {} {}",
		start_time.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan(),
		"UTC".dimmed()
	);
	log_print!(
		"  End Time:      {} {}",
		end_time.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan(),
		"UTC".dimmed()
	);
	log_print!("");

	// Create vesting schedule
	let schedule = quantus_subxt::api::runtime_types::pallet_vesting::vesting_info::VestingInfo {
		locked: locked_planck,
		per_block: per_block_planck,
		starting_block: start_block,
	};

	let transfer_tx = quantus_subxt::api::tx()
		.vesting()
		.vested_transfer(target_account_subxt.into(), schedule);

	submit_transaction_with_finalization(&client, &keypair, transfer_tx, None, finalized).await?;

	log_success!("✅ Vested transfer submitted successfully");

	Ok(())
}

/// Handle force-transfer command
#[allow(clippy::too_many_arguments)]
async fn handle_force_transfer(
	source: String,
	target: String,
	locked: String,
	duration_blocks: u32,
	starting_block: Option<u32>,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("⚡ {} Force Vested Transfer (Sudo)", "VESTING".bright_cyan().bold());
	log_print!("");

	let keypair = load_keypair_from_wallet(&from, password, password_file)?;
	let client = QuantusClient::new(node_url).await?;

	let source_address_str = resolve_address(&source)?;
	let source_account_id = AccountId32::from_ss58check(&source_address_str).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Invalid source address: {e:?}"))
	})?;
	let source_account_bytes: [u8; 32] = *source_account_id.as_ref();
	let source_account_subxt = subxt::utils::AccountId32::from(source_account_bytes);

	let target_address_str = resolve_address(&target)?;
	let target_account_id = AccountId32::from_ss58check(&target_address_str).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Invalid target address: {e:?}"))
	})?;
	let target_account_bytes: [u8; 32] = *target_account_id.as_ref();
	let target_account_subxt = subxt::utils::AccountId32::from(target_account_bytes);

	// Parse locked amount
	let locked_planck = parse_amount_to_planck(&locked)?;

	// Validate duration
	if duration_blocks == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Duration must be greater than 0".to_string(),
		));
	}

	// Calculate per_block from duration
	let per_block_planck = locked_planck / duration_blocks as u128;

	if per_block_planck == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Duration is too long - per_block amount would be zero".to_string(),
		));
	}

	// Get current block and determine starting block
	let current_block = client.client().blocks().at_latest().await?.number();
	let start_block = starting_block.unwrap_or(current_block + 10);

	// Validate parameters
	validate_vesting_params(locked_planck, per_block_planck, start_block, current_block)?;

	// Show summary
	log_print!("Transfer Details:");
	log_print!("  From:          {}", source.bright_yellow());
	log_print!("  To:            {}", target.bright_cyan());
	log_print!("  Locked:        {}", format_planck(locked_planck).bright_yellow());
	log_print!("  Start Block:   {}", start_block.to_string().bright_magenta());

	let duration = locked_planck / per_block_planck;
	let end_block = start_block + duration as u32;
	log_print!("  End Block:     {}", end_block.to_string().bright_magenta());
	log_print!("  Duration:      {}", format_duration(duration as u32).dimmed());

	let start_time = block_to_utc(&client, start_block).await?;
	let end_time = block_to_utc(&client, end_block).await?;
	log_print!(
		"  Start Time:    {} {}",
		start_time.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan(),
		"UTC".dimmed()
	);
	log_print!(
		"  End Time:      {} {}",
		end_time.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan(),
		"UTC".dimmed()
	);
	log_print!("");

	// Create vesting schedule
	let schedule = quantus_subxt::api::runtime_types::pallet_vesting::vesting_info::VestingInfo {
		locked: locked_planck,
		per_block: per_block_planck,
		starting_block: start_block,
	};

	let force_transfer_tx = quantus_subxt::api::tx().vesting().force_vested_transfer(
		source_account_subxt.into(),
		target_account_subxt.into(),
		schedule,
	);

	submit_transaction_with_finalization(&client, &keypair, force_transfer_tx, None, finalized)
		.await?;

	log_success!("✅ Force vested transfer submitted successfully");

	Ok(())
}

/// Handle merge command
async fn handle_merge(
	schedule1: u32,
	schedule2: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("🔀 {} Merge Vesting Schedules", "VESTING".bright_cyan().bold());
	log_print!("");

	if schedule1 == schedule2 {
		return Err(crate::error::QuantusError::Generic(
			"Cannot merge a schedule with itself".to_string(),
		));
	}

	let keypair = load_keypair_from_wallet(&from, password, password_file)?;
	let client = QuantusClient::new(node_url).await?;

	log_print!("Merging schedules #{} and #{}", schedule1, schedule2);
	log_print!("");

	let merge_tx = quantus_subxt::api::tx().vesting().merge_schedules(schedule1, schedule2);

	submit_transaction_with_finalization(&client, &keypair, merge_tx, None, finalized).await?;

	log_success!("✅ Vesting schedules merged successfully");

	Ok(())
}

/// Handle list command
async fn handle_list(address: String, node_url: &str) -> crate::error::Result<()> {
	// List is essentially the same as info, but with a different presentation
	handle_info(address, node_url).await
}

/// Handle calculate command
async fn handle_calculate(
	locked: String,
	duration_blocks: u32,
	starting_block: Option<u32>,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("🧮 {} Vesting Calculator", "CALCULATE".bright_cyan().bold());
	log_print!("");

	let locked_planck = parse_amount_to_planck(&locked)?;

	if duration_blocks == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Duration must be greater than 0".to_string(),
		));
	}

	// Try to connect to node, but if it fails, use a default block number
	let current_block = match QuantusClient::new(node_url).await {
		Ok(client) => match client.client().blocks().at_latest().await {
			Ok(block) => block.number(),
			Err(_) => 1000000, // Default block if can't fetch
		},
		Err(_) => 1000000, // Default block if can't connect
	};

	let start_block = starting_block.unwrap_or(current_block + 10);
	let end_block = start_block + duration_blocks;

	log_print!("Input:");
	log_print!("  Locked Amount:   {}", format_planck(locked_planck).bright_yellow());
	log_print!("  Duration:        {} blocks", duration_blocks.to_string().bright_blue());
	log_print!("");

	log_print!("Calculated:");
	log_print!("  Starting Block:  {}", start_block.to_string().bright_magenta());
	log_print!("  Ending Block:    {}", end_block.to_string().bright_magenta());
	log_print!("  Duration:        {}", format_duration(duration_blocks).dimmed());

	// Calculate estimated times (offline calculation)
	let start_time_estimate = Utc::now()
		+ chrono::Duration::milliseconds(
			((start_block - current_block) as i64) * (BLOCK_TIME_MS as i64),
		);
	let end_time_estimate = Utc::now()
		+ chrono::Duration::milliseconds(
			((end_block - current_block) as i64) * (BLOCK_TIME_MS as i64),
		);

	log_print!("");
	log_print!("Estimated Timing (UTC):");
	log_print!(
		"  Start:           {}",
		start_time_estimate.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan()
	);
	log_print!(
		"  End:             {}",
		end_time_estimate.format("%Y-%m-%d %H:%M:%S").to_string().bright_cyan()
	);

	Ok(())
}
