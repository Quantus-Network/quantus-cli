//! `quantus vesting` — treasury-funded vesting schedules.
//!
//! The Vesting pallet holds treasury-granted schedules in a pot account and pays
//! beneficiaries linearly between `start` and `end` (nothing before `cliff`).
//! `claim` is permissionless: anyone may trigger a payout, which always goes to
//! the stored beneficiary. The admin calls (`create-schedule`, `end-schedule`,
//! `retarget`) require the treasury origin (or Root): on real deployments the
//! treasury is a multisig, so route them through `quantus multisig propose`
//! using the call data these commands can print with `--call-data-only`.
use crate::{
	chain::quantus_subxt,
	cli::{address_format::QuantusSS58, common::ExecutionMode},
	error::{QuantusError, Result},
	log_print, log_success,
};
use clap::Subcommand;
use colored::Colorize;
use subxt::tx::Payload;

type VestingScheduleInfo =
	quantus_subxt::api::runtime_types::pallet_vesting::pallet::VestingSchedule<
		crate::cli::common::SubxtAccountId32,
		u128,
	>;

/// Vesting commands
#[derive(Subcommand, Debug)]
pub enum VestingCommands {
	/// Show vesting pallet constants and the next schedule id
	Info,

	/// List all vesting schedules (optionally filtered by beneficiary)
	List {
		/// Only show schedules for this beneficiary (address or wallet name)
		#[arg(long)]
		beneficiary: Option<String>,
	},

	/// Show a single vesting schedule
	Show {
		/// Schedule id
		#[arg(long)]
		schedule_id: u64,
	},

	/// Claim the currently vested payout of a schedule (permissionless; pays the beneficiary)
	Claim {
		/// Schedule id
		#[arg(long)]
		schedule_id: u64,

		/// Wallet name to sign with (any funded account)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet (or use environment variables)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Create a schedule, moving `total` from the treasury into the vesting pot
	/// (requires the treasury origin; use --call-data-only to route via multisig)
	CreateSchedule {
		/// Beneficiary address or wallet name
		#[arg(long)]
		beneficiary: String,

		/// Vesting start: unix ms, or "now", or "+<seconds>" relative to now
		#[arg(long)]
		start: String,

		/// Cliff: unix ms, "now", or "+<seconds>" (defaults to the start moment)
		#[arg(long)]
		cliff: Option<String>,

		/// Vesting end: unix ms, "now", or "+<seconds>"
		#[arg(long)]
		end: String,

		/// Total amount to vest (e.g., "1000", "10.5")
		#[arg(long)]
		total: String,

		/// Wallet name to sign with (must be the treasury account unless printing call data)
		#[arg(short, long, required_unless_present = "call_data_only")]
		from: Option<String>,

		/// Password for the wallet (or use environment variables)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Print the hex call data instead of submitting (for multisig proposals)
		#[arg(long)]
		call_data_only: bool,
	},

	/// End a schedule early: unpaid vested part to the beneficiary, the rest back to
	/// the treasury (requires the treasury origin)
	EndSchedule {
		/// Schedule id
		#[arg(long)]
		schedule_id: u64,

		/// Wallet name to sign with (must be the treasury account unless printing call data)
		#[arg(short, long, required_unless_present = "call_data_only")]
		from: Option<String>,

		/// Password for the wallet (or use environment variables)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Print the hex call data instead of submitting (for multisig proposals)
		#[arg(long)]
		call_data_only: bool,
	},

	/// Change a schedule's beneficiary after settling any currently claimable payout
	/// (requires the treasury origin)
	Retarget {
		/// Schedule id
		#[arg(long)]
		schedule_id: u64,

		/// New beneficiary address or wallet name
		#[arg(long)]
		new_beneficiary: String,

		/// Wallet name to sign with (must be the treasury account unless printing call data)
		#[arg(short, long, required_unless_present = "call_data_only")]
		from: Option<String>,

		/// Password for the wallet (or use environment variables)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Print the hex call data instead of submitting (for multisig proposals)
		#[arg(long)]
		call_data_only: bool,
	},
}

/// Handle vesting commands
pub async fn handle_vesting_command(
	command: VestingCommands,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		VestingCommands::Info => show_info(&quantus_client).await,
		VestingCommands::List { beneficiary } => list_schedules(&quantus_client, beneficiary).await,
		VestingCommands::Show { schedule_id } => show_schedule(&quantus_client, schedule_id).await,
		VestingCommands::Claim { schedule_id, from, password, password_file } => {
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;
			claim(&quantus_client, &keypair, schedule_id, execution_mode).await
		},
		VestingCommands::CreateSchedule {
			beneficiary,
			start,
			cliff,
			end,
			total,
			from,
			password,
			password_file,
			call_data_only,
		} => {
			let beneficiary_id = crate::cli::common::resolve_to_subxt_account_id(&beneficiary)?;
			let start_ms = parse_moment(&start)?;
			let cliff_ms = match &cliff {
				Some(value) => parse_moment(value)?,
				None => start_ms,
			};
			let end_ms = parse_moment(&end)?;
			let total_amount = crate::cli::send::parse_amount(&quantus_client, &total).await?;
			let call = quantus_subxt::api::tx().vesting().create_schedule(
				beneficiary_id,
				start_ms,
				cliff_ms,
				end_ms,
				total_amount,
			);
			if call_data_only {
				return print_call_data(&quantus_client, &call);
			}
			let keypair = load_admin_keypair(from, password, password_file)?;
			log_print!("🪙 Creating vesting schedule...");
			log_print!("   Beneficiary: {}", beneficiary.bright_cyan());
			log_print!("   Start: {}   Cliff: {}   End: {}", start_ms, cliff_ms, end_ms);
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&keypair,
				call,
				None,
				execution_mode,
			)
			.await?;
			log_success!("✅ Schedule created. Tx: {:?}", tx_hash);
			Ok(())
		},
		VestingCommands::EndSchedule {
			schedule_id,
			from,
			password,
			password_file,
			call_data_only,
		} => {
			let call = quantus_subxt::api::tx().vesting().end_schedule(schedule_id);
			if call_data_only {
				return print_call_data(&quantus_client, &call);
			}
			let keypair = load_admin_keypair(from, password, password_file)?;
			log_print!("🪙 Ending vesting schedule #{schedule_id}...");
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&keypair,
				call,
				None,
				execution_mode,
			)
			.await?;
			log_success!("✅ Schedule ended. Tx: {:?}", tx_hash);
			Ok(())
		},
		VestingCommands::Retarget {
			schedule_id,
			new_beneficiary,
			from,
			password,
			password_file,
			call_data_only,
		} => {
			let new_beneficiary_id =
				crate::cli::common::resolve_to_subxt_account_id(&new_beneficiary)?;
			let call = quantus_subxt::api::tx()
				.vesting()
				.retarget_schedule(schedule_id, new_beneficiary_id);
			if call_data_only {
				return print_call_data(&quantus_client, &call);
			}
			let keypair = load_admin_keypair(from, password, password_file)?;
			log_print!(
				"🪙 Retargeting schedule #{schedule_id} to {}...",
				new_beneficiary.bright_cyan()
			);
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&keypair,
				call,
				None,
				execution_mode,
			)
			.await?;
			log_success!("✅ Schedule retargeted. Tx: {:?}", tx_hash);
			Ok(())
		},
	}
}

fn load_admin_keypair(
	from: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<crate::wallet::QuantumKeyPair> {
	let from = from.ok_or_else(|| {
		QuantusError::Generic(
			"--from is required when submitting (or pass --call-data-only)".into(),
		)
	})?;
	crate::wallet::load_keypair_from_wallet(&from, password, password_file)
}

fn print_call_data<Call: Payload>(
	quantus_client: &crate::chain::client::QuantusClient,
	call: &Call,
) -> Result<()> {
	let call_data = call
		.encode_call_data(&quantus_client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call: {e:?}")))?;
	log_print!("0x{}", hex::encode(&call_data));
	log_print!(
		"💡 Propose it from the treasury multisig: quantus multisig propose --multisig <treasury> --call-data <hex> ..."
	);
	Ok(())
}

/// Parse a vesting moment: unix milliseconds, "now", or "+<seconds>" relative to now.
fn parse_moment(value: &str) -> Result<u64> {
	let now_ms = || -> Result<u64> {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_millis() as u64)
			.map_err(|e| QuantusError::Generic(format!("System clock error: {e}")))
	};
	if value == "now" {
		return now_ms();
	}
	if let Some(offset) = value.strip_prefix('+') {
		let seconds: u64 = offset.parse().map_err(|_| {
			QuantusError::Generic(format!("Invalid relative moment '+{offset}': expected seconds"))
		})?;
		return Ok(now_ms()? + seconds * 1_000);
	}
	value.parse().map_err(|_| {
		QuantusError::Generic(format!(
			"Invalid moment '{value}': expected unix milliseconds, \"now\", or \"+<seconds>\""
		))
	})
}

async fn show_info(quantus_client: &crate::chain::client::QuantusClient) -> Result<()> {
	let constants = quantus_client.client().constants();
	let payout_quantum =
		constants.at(&quantus_subxt::api::constants().vesting().payout_quantum())?;
	let minimum_payout =
		constants.at(&quantus_subxt::api::constants().vesting().minimum_payout())?;
	let min_claim_interval =
		constants.at(&quantus_subxt::api::constants().vesting().min_claim_interval())?;

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let next_id_addr = quantus_subxt::api::storage().vesting().next_schedule_id();
	let next_id = storage_at.fetch_or_default(&next_id_addr).await?;

	let quantum_fmt =
		crate::cli::send::format_balance_with_symbol(quantus_client, payout_quantum).await?;
	let minimum_fmt =
		crate::cli::send::format_balance_with_symbol(quantus_client, minimum_payout).await?;

	log_print!("🪙 {}", "Vesting".bright_green().bold());
	log_print!("   Payout quantum:     {}", quantum_fmt);
	log_print!("   Minimum payout:     {}", minimum_fmt);
	log_print!("   Min claim interval: {} ms", min_claim_interval);
	log_print!("   Next schedule id:   {}", next_id.to_string().bright_yellow());
	Ok(())
}

/// Fetch all schedules as (id, schedule) pairs, sorted by id.
pub async fn fetch_all_schedules(
	quantus_client: &crate::chain::client::QuantusClient,
) -> Result<Vec<(u64, VestingScheduleInfo)>> {
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage = quantus_client.client().storage().at(latest_block_hash);
	let address = quantus_subxt::api::storage().vesting().schedules_iter();
	let mut iter = storage.iter(address).await?;

	let mut schedules = Vec::new();
	while let Some(result) = iter.next().await {
		let kv = result?;
		// Twox64Concat key: the raw u64 id is the last 8 bytes of the storage key.
		if kv.key_bytes.len() >= 8 {
			let id_bytes: [u8; 8] = kv.key_bytes[kv.key_bytes.len() - 8..]
				.try_into()
				.expect("slice is 8 bytes; qed");
			schedules.push((u64::from_le_bytes(id_bytes), kv.value));
		}
	}
	schedules.sort_by_key(|(id, _)| *id);
	Ok(schedules)
}

/// Fetch a single schedule by id.
pub async fn fetch_schedule(
	quantus_client: &crate::chain::client::QuantusClient,
	schedule_id: u64,
) -> Result<Option<VestingScheduleInfo>> {
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage = quantus_client.client().storage().at(latest_block_hash);
	let address = quantus_subxt::api::storage().vesting().schedules(schedule_id);
	Ok(storage.fetch(&address).await?)
}

async fn list_schedules(
	quantus_client: &crate::chain::client::QuantusClient,
	beneficiary: Option<String>,
) -> Result<()> {
	let filter = match &beneficiary {
		Some(value) => Some(crate::cli::common::resolve_to_subxt_account_id(value)?),
		None => None,
	};

	let mut schedules = fetch_all_schedules(quantus_client).await?;
	if let Some(filter_id) = &filter {
		schedules.retain(|(_, s)| &s.beneficiary == filter_id);
	}

	if schedules.is_empty() {
		log_print!("🪙 No vesting schedules found");
		return Ok(());
	}

	log_print!("🪙 {} vesting schedule(s):", schedules.len().to_string().bright_yellow());
	for (id, schedule) in &schedules {
		log_print!("");
		print_schedule(quantus_client, *id, schedule).await?;
	}
	Ok(())
}

async fn show_schedule(
	quantus_client: &crate::chain::client::QuantusClient,
	schedule_id: u64,
) -> Result<()> {
	match fetch_schedule(quantus_client, schedule_id).await? {
		Some(schedule) => print_schedule(quantus_client, schedule_id, &schedule).await,
		None => Err(QuantusError::Generic(format!("No vesting schedule with id {schedule_id}"))),
	}
}

fn format_moment(ms: u64) -> String {
	use chrono::TimeZone;
	match chrono::Utc.timestamp_millis_opt(ms as i64) {
		chrono::LocalResult::Single(dt) => format!("{ms} ({})", dt.format("%Y-%m-%d %H:%M:%S UTC")),
		_ => format!("{ms}"),
	}
}

async fn print_schedule(
	quantus_client: &crate::chain::client::QuantusClient,
	id: u64,
	schedule: &VestingScheduleInfo,
) -> Result<()> {
	let total_fmt =
		crate::cli::send::format_balance_with_symbol(quantus_client, schedule.total).await?;
	let claimed_fmt =
		crate::cli::send::format_balance_with_symbol(quantus_client, schedule.claimed).await?;

	log_print!("📋 Schedule #{}", id.to_string().bright_yellow());
	log_print!("   Beneficiary: {}", schedule.beneficiary.to_quantus_ss58().bright_cyan());
	log_print!("   Start: {}", format_moment(schedule.start));
	log_print!("   Cliff: {}", format_moment(schedule.cliff));
	log_print!("   End:   {}", format_moment(schedule.end));
	log_print!("   Total:   {}", total_fmt);
	log_print!("   Claimed: {}", claimed_fmt);
	match schedule.last_claim_at {
		Some(at) => log_print!("   Last claim: {}", format_moment(at)),
		None => log_print!("   Last claim: never"),
	}
	Ok(())
}

async fn claim(
	quantus_client: &crate::chain::client::QuantusClient,
	keypair: &crate::wallet::QuantumKeyPair,
	schedule_id: u64,
	execution_mode: ExecutionMode,
) -> Result<()> {
	log_print!("🪙 Claiming vesting schedule #{schedule_id}...");

	let call = quantus_subxt::api::tx().vesting().claim(schedule_id);
	let wait_mode = ExecutionMode { wait_for_transaction: true, ..execution_mode };
	let (tx_hash, included_in) = crate::cli::common::submit_transaction_with_inclusion_block(
		quantus_client,
		keypair,
		call,
		None,
		wait_mode,
	)
	.await?;

	// Report the actual payout from the Claimed event in the inclusion block.
	if let Some(block_hash) = included_in {
		let events = quantus_client.client().events().at(block_hash).await?;
		for event in events.find::<quantus_subxt::api::vesting::events::Claimed>().flatten() {
			if event.schedule_id == schedule_id {
				let amount_fmt =
					crate::cli::send::format_balance_with_symbol(quantus_client, event.amount)
						.await?;
				log_success!(
					"✅ Paid {} to {}",
					amount_fmt,
					event.beneficiary.to_quantus_ss58().bright_cyan()
				);
			}
		}
	}
	log_success!("✅ Claim submitted. Tx: {:?}", tx_hash);
	Ok(())
}
