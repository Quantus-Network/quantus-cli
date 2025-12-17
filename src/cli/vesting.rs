//! `quantus vesting` subcommand - manage token vesting schedules
use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::{
		common::{resolve_address, submit_transaction},
		send::{format_balance, get_chain_properties, parse_amount},
	},
	error::Result,
	log_error, log_info, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

/// Vesting management commands
#[derive(Subcommand, Debug)]
pub enum VestingCommands {
	/// Create a linear vesting schedule
	Create {
		/// Beneficiary address or wallet name
		#[arg(long)]
		to: String,

		/// Amount to vest (e.g., "1000.0")
		#[arg(long)]
		amount: String,

		/// Start timestamp (UTC, e.g., "2025-01-01 00:00:00" or timestamp in milliseconds)
		#[arg(long)]
		start: String,

		/// End timestamp (UTC, e.g., "2026-01-01 00:00:00" or timestamp in milliseconds)
		#[arg(long)]
		end: String,

		/// Wallet name to sign with (creator)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Create a vesting schedule with cliff
	CreateCliff {
		/// Beneficiary address or wallet name
		#[arg(long)]
		to: String,

		/// Amount to vest (e.g., "10000.0")
		#[arg(long)]
		amount: String,

		/// Cliff timestamp - nothing unlocks until this time (UTC or timestamp in ms)
		#[arg(long)]
		cliff: String,

		/// End timestamp - when vesting completes (UTC or timestamp in ms)
		#[arg(long)]
		end: String,

		/// Wallet name to sign with (creator)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Create a stepped vesting schedule (unlocks in equal portions)
	CreateStepped {
		/// Beneficiary address or wallet name
		#[arg(long)]
		to: String,

		/// Amount to vest (e.g., "12000.0")
		#[arg(long)]
		amount: String,

		/// Start timestamp (UTC or timestamp in ms)
		#[arg(long)]
		start: String,

		/// End timestamp (UTC or timestamp in ms)
		#[arg(long)]
		end: String,

		/// Step duration in days (e.g., "30" for monthly)
		#[arg(long)]
		step_days: u64,

		/// Wallet name to sign with (creator)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Claim vested tokens from a schedule
	Claim {
		/// Schedule ID to claim from
		#[arg(long)]
		schedule_id: u64,

		/// Wallet name to sign with (anyone can claim for beneficiary)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Claim all vested tokens for a beneficiary (helper command)
	ClaimAll {
		/// Beneficiary address or wallet name to claim all schedules for
		#[arg(long)]
		beneficiary: String,

		/// Wallet name to sign with (will pay gas fees)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Cancel a vesting schedule (creator only, refunds unclaimed)
	Cancel {
		/// Schedule ID to cancel
		#[arg(long)]
		schedule_id: u64,

		/// Wallet name to sign with (must be creator)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Show detailed information about a vesting schedule
	Info {
		/// Schedule ID to query
		#[arg(long)]
		schedule_id: u64,
	},

	/// List all vesting schedules for a beneficiary
	List {
		/// Beneficiary address or wallet name
		#[arg(long)]
		address: String,
	},

	/// List all vesting schedules created by an account
	ListCreated {
		/// Creator address or wallet name
		#[arg(long)]
		creator: String,
	},

	/// Calculate and preview a vesting schedule
	Calculate {
		/// Vesting type: "linear", "cliff", or "stepped"
		#[arg(long)]
		vesting_type: String,

		/// Amount to vest
		#[arg(long)]
		amount: String,

		/// Duration in days
		#[arg(long)]
		duration_days: u64,

		/// Cliff duration in days (for cliff type)
		#[arg(long)]
		cliff_days: Option<u64>,

		/// Step duration in days (for stepped type)
		#[arg(long)]
		step_days: Option<u64>,
	},
}

/// Handle vesting commands
pub async fn handle_vesting_command(
	command: VestingCommands,
	node_url: &str,
	finalized: bool,
) -> Result<()> {
	let quantus_client = QuantusClient::new(node_url).await?;

	match command {
		VestingCommands::Create { to, amount, start, end, from, password, password_file } => {
			handle_create(
				&quantus_client,
				&to,
				&amount,
				&start,
				&end,
				&from,
				password,
				password_file,
				finalized,
			)
			.await
		},
		VestingCommands::CreateCliff { to, amount, cliff, end, from, password, password_file } => {
			handle_create_cliff(
				&quantus_client,
				&to,
				&amount,
				&cliff,
				&end,
				&from,
				password,
				password_file,
				finalized,
			)
			.await
		},
		VestingCommands::CreateStepped {
			to,
			amount,
			start,
			end,
			step_days,
			from,
			password,
			password_file,
		} => {
			handle_create_stepped(
				&quantus_client,
				&to,
				&amount,
				&start,
				&end,
				step_days,
				&from,
				password,
				password_file,
				finalized,
			)
			.await
		},
		VestingCommands::Claim { schedule_id, from, password, password_file } => {
			handle_claim(&quantus_client, schedule_id, &from, password, password_file, finalized)
				.await
		},
		VestingCommands::ClaimAll { beneficiary, from, password, password_file } => {
			handle_claim_all(
				&quantus_client,
				&beneficiary,
				&from,
				password,
				password_file,
				finalized,
			)
			.await
		},
		VestingCommands::Cancel { schedule_id, from, password, password_file } => {
			handle_cancel(&quantus_client, schedule_id, &from, password, password_file, finalized)
				.await
		},
		VestingCommands::Info { schedule_id } => handle_info(&quantus_client, schedule_id).await,
		VestingCommands::List { address } => handle_list(&quantus_client, &address).await,
		VestingCommands::ListCreated { creator } => {
			handle_list_created(&quantus_client, &creator).await
		},
		VestingCommands::Calculate {
			vesting_type,
			amount,
			duration_days,
			cliff_days,
			step_days,
		} => {
			handle_calculate(
				&quantus_client,
				&vesting_type,
				&amount,
				duration_days,
				cliff_days,
				step_days,
			)
			.await
		},
	}
}

// ============================================================================
// Implementation functions
// ============================================================================

/// Parse timestamp from string (UTC datetime or milliseconds)
fn parse_timestamp(input: &str) -> Result<u64> {
	// Try parsing as milliseconds first
	if let Ok(ms) = input.parse::<u64>() {
		return Ok(ms);
	}

	// Try parsing as UTC datetime (e.g., "2025-01-01 00:00:00")
	use chrono::{DateTime, NaiveDateTime, Utc};

	// Try with space separator first
	if let Ok(naive) = NaiveDateTime::parse_from_str(input, "%Y-%m-%d %H:%M:%S") {
		let dt: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
		return Ok(dt.timestamp_millis() as u64);
	}

	// Try with T separator (ISO 8601)
	if let Ok(naive) = NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S") {
		let dt: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
		return Ok(dt.timestamp_millis() as u64);
	}

	Err(crate::error::QuantusError::Generic(format!(
		"Invalid timestamp format: '{}'. Use either milliseconds or 'YYYY-MM-DD HH:MM:SS'",
		input
	)))
}

/// Format timestamp for display
fn format_timestamp(ms: u64) -> String {
	use chrono::DateTime;

	// Check if timestamp is within valid i64 range to prevent overflow
	// i64::MAX milliseconds = ~292 million years from epoch
	if ms > i64::MAX as u64 {
		return format!("{} ms (out of displayable range)", ms);
	}

	match DateTime::from_timestamp_millis(ms as i64) {
		Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
		None => format!("{} ms (invalid timestamp)", ms),
	}
}

/// Create linear vesting schedule
#[allow(clippy::too_many_arguments)]
async fn handle_create(
	quantus_client: &QuantusClient,
	to: &str,
	amount: &str,
	start: &str,
	end: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> Result<()> {
	log_info!("🔒 Creating linear vesting schedule...");

	// Parse parameters
	let beneficiary = resolve_address(to)?;
	let beneficiary_account_id = parse_address_to_account_id(&beneficiary)?;
	let beneficiary_subxt = account_id_sp_to_subxt(&beneficiary_account_id);
	let amount_planck = parse_amount(quantus_client, amount).await?;
	let start_ms = parse_timestamp(start)?;
	let end_ms = parse_timestamp(end)?;

	// Validate timestamps
	if end_ms <= start_ms {
		return Err(crate::error::QuantusError::Generic(format!(
			"End timestamp ({}) must be after start timestamp ({})",
			format_timestamp(end_ms),
			format_timestamp(start_ms)
		)));
	}

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Build transaction
	let tx = quantus_subxt::api::tx().vesting().create_vesting_schedule(
		beneficiary_subxt,
		amount_planck,
		start_ms,
		end_ms,
	);

	log_verbose!("📋 Schedule parameters:");
	log_verbose!("   Beneficiary: {}", beneficiary.bright_cyan());
	log_verbose!(
		"   Amount: {} ({})",
		format_token_amount(quantus_client, amount_planck).await?,
		amount_planck
	);
	log_verbose!("   Start: {}", format_timestamp(start_ms).bright_yellow());
	log_verbose!("   End: {}", format_timestamp(end_ms).bright_yellow());

	// Submit transaction
	submit_transaction(quantus_client, &keypair, tx, None, finalized).await?;

	log_success!("✅ Linear vesting schedule created successfully!");
	log_info!("💡 Use 'quantus vesting list --address {}' to see the schedule", to);

	Ok(())
}

/// Create vesting schedule with cliff
#[allow(clippy::too_many_arguments)]
async fn handle_create_cliff(
	quantus_client: &QuantusClient,
	to: &str,
	amount: &str,
	cliff: &str,
	end: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> Result<()> {
	log_info!("🔒 Creating vesting schedule with cliff...");

	// Parse parameters
	let beneficiary = resolve_address(to)?;
	let beneficiary_account_id = parse_address_to_account_id(&beneficiary)?;
	let beneficiary_subxt = account_id_sp_to_subxt(&beneficiary_account_id);
	let amount_planck = parse_amount(quantus_client, amount).await?;
	let cliff_ms = parse_timestamp(cliff)?;
	let end_ms = parse_timestamp(end)?;

	// Validate timestamps
	if end_ms <= cliff_ms {
		return Err(crate::error::QuantusError::Generic(format!(
			"End timestamp ({}) must be after cliff timestamp ({})",
			format_timestamp(end_ms),
			format_timestamp(cliff_ms)
		)));
	}

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Build transaction
	let tx = quantus_subxt::api::tx().vesting().create_vesting_schedule_with_cliff(
		beneficiary_subxt,
		amount_planck,
		cliff_ms,
		end_ms,
	);

	log_verbose!("📋 Schedule parameters:");
	log_verbose!("   Beneficiary: {}", beneficiary.bright_cyan());
	log_verbose!(
		"   Amount: {} ({})",
		format_token_amount(quantus_client, amount_planck).await?,
		amount_planck
	);
	log_verbose!("   Cliff: {}", format_timestamp(cliff_ms).bright_yellow());
	log_verbose!("   End: {}", format_timestamp(end_ms).bright_yellow());
	log_verbose!("   Type: Linear with Cliff");

	// Submit transaction
	submit_transaction(quantus_client, &keypair, tx, None, finalized).await?;

	log_success!("✅ Vesting schedule with cliff created successfully!");
	log_info!(
		"💡 No tokens will be available until: {}",
		format_timestamp(cliff_ms).bright_yellow()
	);
	log_info!("💡 Use 'quantus vesting list --address {}' to see the schedule", to);

	Ok(())
}

/// Create stepped vesting schedule
#[allow(clippy::too_many_arguments)]
async fn handle_create_stepped(
	quantus_client: &QuantusClient,
	to: &str,
	amount: &str,
	start: &str,
	end: &str,
	step_days: u64,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> Result<()> {
	log_info!("🔒 Creating stepped vesting schedule...");

	// Parse parameters
	let beneficiary = resolve_address(to)?;
	let beneficiary_account_id = parse_address_to_account_id(&beneficiary)?;
	let beneficiary_subxt = account_id_sp_to_subxt(&beneficiary_account_id);
	let amount_planck = parse_amount(quantus_client, amount).await?;
	let start_ms = parse_timestamp(start)?;
	let end_ms = parse_timestamp(end)?;
	let step_duration_ms = step_days * 24 * 60 * 60 * 1000; // days to milliseconds

	// Validate timestamps
	if end_ms <= start_ms {
		return Err(crate::error::QuantusError::Generic(format!(
			"End timestamp ({}) must be after start timestamp ({})",
			format_timestamp(end_ms),
			format_timestamp(start_ms)
		)));
	}

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Build transaction
	let tx = quantus_subxt::api::tx().vesting().create_stepped_vesting_schedule(
		beneficiary_subxt,
		amount_planck,
		start_ms,
		end_ms,
		step_duration_ms,
	);

	let total_duration_ms = end_ms - start_ms; // Safe now due to validation above
	let num_steps = (total_duration_ms as f64 / step_duration_ms as f64).ceil() as u64;

	log_verbose!("📋 Schedule parameters:");
	log_verbose!("   Beneficiary: {}", beneficiary.bright_cyan());
	log_verbose!(
		"   Amount: {} ({})",
		format_token_amount(quantus_client, amount_planck).await?,
		amount_planck
	);
	log_verbose!("   Start: {}", format_timestamp(start_ms).bright_yellow());
	log_verbose!("   End: {}", format_timestamp(end_ms).bright_yellow());
	log_verbose!("   Step: {} days", step_days);
	log_verbose!("   Steps: ~{}", num_steps);
	log_verbose!("   Type: Stepped");

	// Submit transaction
	submit_transaction(quantus_client, &keypair, tx, None, finalized).await?;

	log_success!("✅ Stepped vesting schedule created successfully!");
	log_info!("💡 Tokens will unlock in ~{} steps every {} days", num_steps, step_days);
	log_info!("💡 Use 'quantus vesting list --address {}' to see the schedule", to);

	Ok(())
}

/// Claim vested tokens
async fn handle_claim(
	quantus_client: &QuantusClient,
	schedule_id: u64,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> Result<()> {
	log_info!("💰 Claiming vested tokens from schedule #{}...", schedule_id);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Build transaction
	let tx = quantus_subxt::api::tx().vesting().claim(schedule_id);

	// Submit transaction
	submit_transaction(quantus_client, &keypair, tx, None, finalized).await?;

	log_success!("✅ Claim transaction submitted successfully!");
	log_info!(
		"💡 Use 'quantus vesting info --schedule-id {}' to check updated status",
		schedule_id
	);

	Ok(())
}

/// Claim all schedules for a beneficiary
async fn handle_claim_all(
	quantus_client: &QuantusClient,
	beneficiary: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> Result<()> {
	log_info!("💰 Finding all vesting schedules for {}...", beneficiary.bright_cyan());

	// Resolve beneficiary address
	let beneficiary_address = resolve_address(beneficiary)?;

	// Get all schedules for beneficiary
	let schedules = get_schedules_for_beneficiary(quantus_client, &beneficiary_address).await?;

	if schedules.is_empty() {
		log_info!("ℹ️  No vesting schedules found for this address");
		return Ok(());
	}

	log_info!("📋 Found {} schedule(s), claiming all...", schedules.len());

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Claim each schedule
	let mut claimed = 0;
	let mut errors = 0;

	for schedule_id in schedules {
		log_verbose!("   Claiming schedule #{}...", schedule_id);
		let tx = quantus_subxt::api::tx().vesting().claim(schedule_id);

		match submit_transaction(quantus_client, &keypair, tx, None, finalized).await {
			Ok(_) => {
				claimed += 1;
				log_success!("   ✅ Schedule #{} claimed", schedule_id);
			},
			Err(e) => {
				errors += 1;
				log_error!("   ❌ Schedule #{} failed: {}", schedule_id, e);
			},
		}
	}

	log_print!("");
	log_success!("🎉 Claim all complete!");
	log_info!("   Successfully claimed: {}", claimed.to_string().bright_green());
	if errors > 0 {
		log_error!("   Failed: {}", errors.to_string().bright_red());
	}

	Ok(())
}

/// Cancel a vesting schedule
async fn handle_cancel(
	quantus_client: &QuantusClient,
	schedule_id: u64,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> Result<()> {
	log_info!("🚫 Cancelling vesting schedule #{}...", schedule_id);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Build transaction
	let tx = quantus_subxt::api::tx().vesting().cancel_vesting_schedule(schedule_id);

	log_verbose!("⚠️  This will:");
	log_verbose!("   1. Claim any vested tokens for beneficiary");
	log_verbose!("   2. Refund unclaimed tokens to creator");
	log_verbose!("   3. Remove the schedule");

	// Submit transaction
	submit_transaction(quantus_client, &keypair, tx, None, finalized).await?;

	log_success!("✅ Vesting schedule cancelled successfully!");
	log_info!("💡 Unclaimed tokens have been refunded to the creator");

	Ok(())
}

/// Show schedule information
async fn handle_info(quantus_client: &QuantusClient, schedule_id: u64) -> Result<()> {
	log_info!("🔍 Fetching vesting schedule #{}...", schedule_id);

	// Query schedule from storage
	let schedule = get_schedule(quantus_client, schedule_id).await?;

	if schedule.is_none() {
		log_error!("❌ Schedule #{} not found", schedule_id);
		return Ok(());
	}

	let schedule = schedule.unwrap();

	// Get current time from chain
	let now = get_current_timestamp(quantus_client).await?;

	// Calculate vested amount (this would require calling the runtime or replicating logic)
	let (_, decimals) = get_chain_properties(quantus_client).await?;

	log_print!("");
	log_print!("{}", format!("Schedule #{}", schedule_id).bright_cyan().bold());
	log_print!("{}", "─".repeat(60).dimmed());

	// Basic info
	log_print!("  {}: {}", "Creator".bright_white(), account_id_to_ss58(&schedule.creator));
	log_print!("  {}: {}", "Beneficiary".bright_white(), account_id_to_ss58(&schedule.beneficiary));
	log_print!(
		"  {}: {} ({})",
		"Total Amount".bright_white(),
		format_balance(schedule.amount, decimals).bright_green(),
		schedule.amount
	);
	log_print!(
		"  {}: {} ({})",
		"Claimed".bright_white(),
		format_balance(schedule.claimed, decimals).bright_yellow(),
		schedule.claimed
	);
	log_print!(
		"  {}: {} ({})",
		"Remaining".bright_white(),
		format_balance(schedule.amount.saturating_sub(schedule.claimed), decimals).bright_magenta(),
		schedule.amount.saturating_sub(schedule.claimed)
	);

	log_print!("");

	// Timeline
	log_print!("  {}", "Timeline".bright_white().bold());

	// Determine vesting type and display accordingly
	let vesting_type_display = format_vesting_type(&schedule);
	log_print!("  {}: {}", "Type".bright_white(), vesting_type_display.bright_cyan());

	log_print!(
		"  {}: {}",
		"Start".bright_white(),
		format_timestamp(schedule.start).bright_yellow()
	);
	log_print!("  {}: {}", "End".bright_white(), format_timestamp(schedule.end).bright_yellow());
	log_print!("  {}: {}", "Now".bright_white(), format_timestamp(now).bright_blue());

	// Status
	let status = if now < schedule.start {
		"Not Started".bright_yellow()
	} else if now >= schedule.end {
		"Complete".bright_green()
	} else {
		"Active".bright_blue()
	};
	log_print!("  {}: {}", "Status".bright_white(), status);

	// Progress bar
	let progress = if now <= schedule.start {
		0.0
	} else if now >= schedule.end {
		100.0
	} else {
		let elapsed = (now - schedule.start) as f64;
		let total = (schedule.end - schedule.start) as f64;
		(elapsed / total * 100.0).min(100.0)
	};

	let bar_width = 40;
	let filled = ((progress / 100.0) * bar_width as f64) as usize;
	let empty = bar_width - filled;
	let bar = format!("{}{}", "█".repeat(filled).bright_cyan(), "░".repeat(empty).dimmed());

	log_print!("  {}: {} {:.1}%", "Progress".bright_white(), bar, progress);

	log_print!("");

	Ok(())
}

/// List schedules for a beneficiary
async fn handle_list(quantus_client: &QuantusClient, address: &str) -> Result<()> {
	log_info!("🔍 Finding vesting schedules for {}...", address.bright_cyan());

	let resolved_address = resolve_address(address)?;
	let schedules = get_schedules_for_beneficiary(quantus_client, &resolved_address).await?;

	if schedules.is_empty() {
		log_info!("ℹ️  No vesting schedules found for this address");
		return Ok(());
	}

	log_print!("");
	log_success!("Found {} schedule(s):", schedules.len());
	log_print!("");

	let (_, decimals) = get_chain_properties(quantus_client).await?;
	let now = get_current_timestamp(quantus_client).await?;

	for schedule_id in schedules {
		if let Some(schedule) = get_schedule(quantus_client, schedule_id).await? {
			let status = if now < schedule.start {
				"Not Started".bright_yellow()
			} else if now >= schedule.end {
				"Complete".bright_green()
			} else {
				"Active".bright_blue()
			};

			let vesting_type = format_vesting_type(&schedule);

			log_print!(
				"  {} {} | {} {} | {} | {}",
				"#".dimmed(),
				schedule_id.to_string().bright_cyan(),
				"Amount:".dimmed(),
				format_balance(schedule.amount, decimals).bright_green(),
				vesting_type.bright_magenta(),
				status
			);
		}
	}

	log_print!("");
	log_info!("💡 Use 'quantus vesting info --schedule-id <ID>' for details");

	Ok(())
}

/// List schedules created by an account
async fn handle_list_created(quantus_client: &QuantusClient, creator: &str) -> Result<()> {
	log_info!("🔍 Finding vesting schedules created by {}...", creator.bright_cyan());

	let resolved_address = resolve_address(creator)?;
	let schedules = get_schedules_by_creator(quantus_client, &resolved_address).await?;

	if schedules.is_empty() {
		log_info!("ℹ️  No vesting schedules found created by this address");
		return Ok(());
	}

	log_print!("");
	log_success!("Found {} schedule(s) created:", schedules.len());
	log_print!("");

	let (_, decimals) = get_chain_properties(quantus_client).await?;
	let now = get_current_timestamp(quantus_client).await?;

	for schedule_id in schedules {
		if let Some(schedule) = get_schedule(quantus_client, schedule_id).await? {
			let status = if now < schedule.start {
				"Not Started".bright_yellow()
			} else if now >= schedule.end {
				"Complete".bright_green()
			} else {
				"Active".bright_blue()
			};

			let vesting_type = format_vesting_type(&schedule);

			log_print!(
				"  {} {} | {} {} | {} {} | {} | {}",
				"#".dimmed(),
				schedule_id.to_string().bright_cyan(),
				"Beneficiary:".dimmed(),
				account_id_to_ss58(&schedule.beneficiary).bright_white(),
				"Amount:".dimmed(),
				format_balance(schedule.amount, decimals).bright_green(),
				vesting_type.bright_magenta(),
				status
			);
		}
	}

	log_print!("");
	log_info!("💡 Use 'quantus vesting info --schedule-id <ID>' for details");

	Ok(())
}

/// Calculate and preview a vesting schedule
async fn handle_calculate(
	quantus_client: &QuantusClient,
	vesting_type: &str,
	amount: &str,
	duration_days: u64,
	cliff_days: Option<u64>,
	step_days: Option<u64>,
) -> Result<()> {
	log_info!("📊 Calculating {} vesting schedule...", vesting_type.bright_cyan());

	let amount_planck = parse_amount(quantus_client, amount).await?;
	let (_, decimals) = get_chain_properties(quantus_client).await?;

	// Validate duration
	if duration_days == 0 {
		return Err(crate::error::QuantusError::Generic(
			"Duration must be greater than 0 days".to_string(),
		));
	}

	log_print!("");
	log_print!("{}", "Vesting Calculation".bright_cyan().bold());
	log_print!("{}", "─".repeat(60).dimmed());

	match vesting_type.to_lowercase().as_str() {
		"linear" => {
			log_print!("  {}: {}", "Type".bright_white(), "Linear".bright_cyan());
			log_print!(
				"  {}: {}",
				"Amount".bright_white(),
				format_balance(amount_planck, decimals).bright_green()
			);
			log_print!("  {}: {} days", "Duration".bright_white(), duration_days);
			log_print!("");
			log_print!("  {}", "Timeline:".bright_white().bold());

			let total_days = duration_days as f64;
			for milestone in [0.0, 0.25, 0.5, 0.75, 1.0] {
				let days = (total_days * milestone) as u64;
				let vested = ((amount_planck as f64) * milestone) as u128;
				let percentage = milestone * 100.0;

				log_print!(
					"    Day {}: {} ({:.0}%)",
					days.to_string().bright_yellow(),
					format_balance(vested, decimals).bright_green(),
					percentage
				);
			}

			let daily_rate = (amount_planck as f64) / total_days;
			log_print!("");
			log_print!(
				"  {}: ~{} per day",
				"Rate".bright_white(),
				format_balance(daily_rate as u128, decimals).bright_cyan()
			);
		},

		"cliff" => {
			let cliff = cliff_days.ok_or_else(|| {
				crate::error::QuantusError::Generic(
					"--cliff-days is required for cliff type".to_string(),
				)
			})?;

			// Validate cliff duration vs total duration
			if cliff >= duration_days {
				return Err(crate::error::QuantusError::Generic(format!(
					"Cliff duration ({} days) must be less than total duration ({} days)",
					cliff, duration_days
				)));
			}

			log_print!("  {}: {}", "Type".bright_white(), "Linear with Cliff".bright_cyan());
			log_print!(
				"  {}: {}",
				"Amount".bright_white(),
				format_balance(amount_planck, decimals).bright_green()
			);
			log_print!("  {}: {} days", "Cliff".bright_white(), cliff.to_string().bright_yellow());
			log_print!("  {}: {} days", "Duration".bright_white(), duration_days);
			log_print!("");
			log_print!("  {}", "Timeline:".bright_white().bold());

			log_print!(
				"    Day 0-{}: {} (cliff period)",
				cliff.to_string().bright_yellow(),
				format_balance(0, decimals).bright_red()
			);

			let vesting_duration = duration_days - cliff; // Safe now due to validation above
			let vesting_duration_f = vesting_duration as f64;

			for milestone in [0.25, 0.5, 0.75, 1.0] {
				let days_after_cliff = (vesting_duration_f * milestone) as u64;
				let total_days = cliff + days_after_cliff;
				let vested = ((amount_planck as f64) * milestone) as u128;
				let percentage = milestone * 100.0;

				log_print!(
					"    Day {}: {} ({:.0}%)",
					total_days.to_string().bright_yellow(),
					format_balance(vested, decimals).bright_green(),
					percentage
				);
			}

			let daily_rate = (amount_planck as f64) / vesting_duration_f;
			log_print!("");
			log_print!(
				"  {}: ~{} per day (after cliff)",
				"Rate".bright_white(),
				format_balance(daily_rate as u128, decimals).bright_cyan()
			);
		},

		"stepped" => {
			let step = step_days.ok_or_else(|| {
				crate::error::QuantusError::Generic(
					"--step-days is required for stepped type".to_string(),
				)
			})?;

			// Validate step duration
			if step == 0 {
				return Err(crate::error::QuantusError::Generic(
					"Step duration must be greater than 0 days".to_string(),
				));
			}

			if step > duration_days {
				return Err(crate::error::QuantusError::Generic(format!(
					"Step duration ({} days) must be less than or equal to total duration ({} days)",
					step, duration_days
				)));
			}

			let num_steps = ((duration_days as f64) / (step as f64)).ceil() as u64;
			let amount_per_step = amount_planck / num_steps as u128;

			log_print!("  {}: {}", "Type".bright_white(), "Stepped".bright_cyan());
			log_print!(
				"  {}: {}",
				"Amount".bright_white(),
				format_balance(amount_planck, decimals).bright_green()
			);
			log_print!("  {}: {} days", "Duration".bright_white(), duration_days);
			log_print!("  {}: {} days", "Step".bright_white(), step);
			log_print!("  {}: {}", "Steps".bright_white(), num_steps.to_string().bright_cyan());
			log_print!("");
			log_print!("  {}", "Timeline:".bright_white().bold());

			log_print!("    Day 0: {} (0%)", format_balance(0, decimals).bright_red());

			for i in 1..=num_steps.min(5) {
				let days = i * step;
				let vested = amount_per_step * i as u128;
				let percentage = (vested as f64 / amount_planck as f64) * 100.0;

				log_print!(
					"    Day {}: {} ({:.0}%)",
					days.to_string().bright_yellow(),
					format_balance(vested, decimals).bright_green(),
					percentage
				);
			}

			if num_steps > 5 {
				log_print!("    {} steps", "...".dimmed());
			}

			log_print!("");
			log_print!(
				"  {}: {} every {} days",
				"Rate".bright_white(),
				format_balance(amount_per_step, decimals).bright_cyan(),
				step
			);
		},

		_ => {
			return Err(crate::error::QuantusError::Generic(format!(
				"Invalid vesting type: '{}'. Use 'linear', 'cliff', or 'stepped'",
				vesting_type
			)));
		},
	}

	log_print!("");

	Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

/// Parse SS58 address to AccountId32
fn parse_address_to_account_id(address: &str) -> Result<SpAccountId32> {
	let (account_id, _) = SpAccountId32::from_ss58check_with_version(address)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e)))?;
	Ok(account_id)
}

/// Convert sp_core AccountId32 to subxt AccountId32
fn account_id_sp_to_subxt(
	account_id: &SpAccountId32,
) -> subxt::ext::subxt_core::utils::AccountId32 {
	let bytes: [u8; 32] = *account_id.as_ref();
	subxt::ext::subxt_core::utils::AccountId32::from(bytes)
}

/// Convert AccountId32 to SS58 string
fn account_id_to_ss58(account_id: &subxt::ext::subxt_core::utils::AccountId32) -> String {
	let bytes: [u8; 32] = account_id.0;
	let sp_account = SpAccountId32::from(bytes);
	sp_account.to_ss58check()
}

/// Format token amount with symbol
async fn format_token_amount(quantus_client: &QuantusClient, amount: u128) -> Result<String> {
	let (symbol, decimals) = get_chain_properties(quantus_client).await?;
	Ok(format!("{} {}", format_balance(amount, decimals), symbol))
}

/// Get current timestamp from chain
async fn get_current_timestamp(quantus_client: &QuantusClient) -> Result<u64> {
	use quantus_subxt::api;

	let latest_block = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block);

	let now_addr = api::storage().timestamp().now();
	let now = storage_at.fetch_or_default(&now_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch timestamp: {}", e))
	})?;

	Ok(now)
}

/// Get a vesting schedule by ID
async fn get_schedule(
	quantus_client: &QuantusClient,
	schedule_id: u64,
) -> Result<
	Option<
		quantus_subxt::api::runtime_types::pallet_vesting::pallet::VestingSchedule<
			subxt::ext::subxt_core::utils::AccountId32,
			u128,
			u64,
		>,
	>,
> {
	use quantus_subxt::api;

	let latest_block = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block);

	let schedule_addr = api::storage().vesting().vesting_schedules(schedule_id);
	let schedule = storage_at.fetch(&schedule_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch schedule: {}", e))
	})?;

	Ok(schedule)
}

/// Get all schedule IDs for a beneficiary (iterates through all schedules)
async fn get_schedules_for_beneficiary(
	quantus_client: &QuantusClient,
	beneficiary: &str,
) -> Result<Vec<u64>> {
	use quantus_subxt::api;

	let beneficiary_account = parse_address_to_account_id(beneficiary)?;
	let beneficiary_bytes: [u8; 32] = *beneficiary_account.as_ref();
	let beneficiary_subxt = subxt::ext::subxt_core::utils::AccountId32::from(beneficiary_bytes);

	let latest_block = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block);

	// Get total number of schedules
	let counter_addr = api::storage().vesting().schedule_counter();
	let total_schedules = storage_at.fetch_or_default(&counter_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch schedule counter: {}", e))
	})?;

	let mut schedules = Vec::new();

	// Iterate through all schedules (this is inefficient but necessary without index)
	for id in 1..=total_schedules {
		if let Some(schedule) = get_schedule(quantus_client, id).await? {
			if schedule.beneficiary == beneficiary_subxt {
				schedules.push(id);
			}
		}
	}

	Ok(schedules)
}

/// Get all schedule IDs created by an account
async fn get_schedules_by_creator(
	quantus_client: &QuantusClient,
	creator: &str,
) -> Result<Vec<u64>> {
	use quantus_subxt::api;

	let creator_account = parse_address_to_account_id(creator)?;
	let creator_bytes: [u8; 32] = *creator_account.as_ref();
	let creator_subxt = subxt::ext::subxt_core::utils::AccountId32::from(creator_bytes);

	let latest_block = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block);

	// Get total number of schedules
	let counter_addr = api::storage().vesting().schedule_counter();
	let total_schedules = storage_at.fetch_or_default(&counter_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch schedule counter: {}", e))
	})?;

	let mut schedules = Vec::new();

	// Iterate through all schedules
	for id in 1..=total_schedules {
		if let Some(schedule) = get_schedule(quantus_client, id).await? {
			if schedule.creator == creator_subxt {
				schedules.push(id);
			}
		}
	}

	Ok(schedules)
}

/// Format vesting type for display
fn format_vesting_type(
	schedule: &quantus_subxt::api::runtime_types::pallet_vesting::pallet::VestingSchedule<
		subxt::ext::subxt_core::utils::AccountId32,
		u128,
		u64,
	>,
) -> String {
	use quantus_subxt::api::runtime_types::pallet_vesting::pallet::VestingType;

	match &schedule.vesting_type {
		VestingType::Linear => "Linear".to_string(),
		VestingType::LinearWithCliff { cliff } => format!("Cliff ({})", format_timestamp(*cliff)),
		VestingType::Stepped { step_duration } => {
			let days = step_duration / (24 * 60 * 60 * 1000);
			format!("Stepped ({}d)", days)
		},
	}
}
