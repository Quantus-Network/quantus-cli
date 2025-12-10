use crate::{chain::quantus_subxt, error::Result, log_print, log_success};
use clap::Subcommand;

/// Scheduler-related commands
#[derive(Subcommand, Debug)]
pub enum SchedulerCommands {
	/// Get the last processed timestamp from the scheduler
	GetLastProcessedTimestamp,

	/// List Scheduler::Agenda entries over a block range (e.g., --range 80..100)
	Agenda {
		/// Range in form from..to (inclusive)
		#[arg(long)]
		range: String,
	},

	/// Schedule a test System::remark after N blocks
	ScheduleRemark {
		/// Blocks after current to schedule
		#[arg(long)]
		after: u32,
		/// Wallet name to sign with
		#[arg(long)]
		from: String,
	},
}

/// Get the last processed timestamp from the scheduler
pub async fn get_last_processed_timestamp(
	quantus_client: &crate::chain::client::QuantusClient,
) -> Result<Option<u64>> {
	use quantus_subxt::api;

	log_print!("🕒 Getting last processed timestamp from the scheduler");

	// Build the storage key for Scheduler::LastProcessedTimestamp
	let storage_addr = api::storage().scheduler().last_processed_timestamp();

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let timestamp = storage_at.fetch(&storage_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!(
			"Failed to fetch last processed timestamp: {e:?}"
		))
	})?;

	Ok(timestamp)
}

async fn list_agenda_range(
	quantus_client: &crate::chain::client::QuantusClient,
	range: &str,
) -> Result<()> {
	use quantus_subxt::api;

	// Parse range: from..to (inclusive)
	let parts: Vec<&str> = range.split("..").collect();
	if parts.len() != 2 {
		return Err(crate::error::QuantusError::Generic(
			"Invalid range format. Use --range <from>..<to>".to_string(),
		));
	}
	let start: u32 = parts[0].trim().parse().map_err(|_| {
		crate::error::QuantusError::Generic("Invalid start block in range".to_string())
	})?;
	let end: u32 = parts[1].trim().parse().map_err(|_| {
		crate::error::QuantusError::Generic("Invalid end block in range".to_string())
	})?;
	if start > end {
		return Err(crate::error::QuantusError::Generic("Range start must be <= end".to_string()));
	}

	// Work at latest state
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	log_print!("🗓️  Scheduler::Agenda entries for blocks {}..={} (inclusive)", start, end);

	for bn in start..=end {
		let addr = api::storage().scheduler().agenda(
			quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp::BlockNumber(
				bn,
			),
		);
		match storage_at.fetch(&addr).await {
			Ok(Some(agenda)) => {
				log_print!("#{}: {:?}", bn, agenda);
			},
			Ok(None) => {
				log_print!("#{}: <empty>", bn);
			},
			Err(e) => {
				log_print!("#{}: error fetching agenda: {:?}", bn, e);
			},
		}
	}

	log_success!("Finished scanning Scheduler::Agenda");
	Ok(())
}

async fn schedule_remark(
	quantus_client: &crate::chain::client::QuantusClient,
	after: u32,
	from: &str,
	finalized: bool,
) -> Result<()> {
	use quantus_subxt::api;

	log_print!("🗓️  Scheduling System::remark after {} blocks", after);

	// Build call as RuntimeCall
	let system_remark = quantus_subxt::api::runtime_types::frame_system::pallet::Call::remark {
		remark: Vec::new(),
	};
	let runtime_call =
		quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall::System(system_remark);

	// When: after N blocks (u32)
	let when_u32: u32 = after;
	let maybe_periodic = None;
	let priority: u8 = 0;

	// Submit schedule extrinsic
	let keypair = crate::wallet::load_keypair_from_wallet(from, None, None)?;
	let schedule_tx =
		api::tx().scheduler().schedule(when_u32, maybe_periodic, priority, runtime_call);
	let tx_hash = crate::cli::common::submit_transaction_with_finalization(
		quantus_client,
		&keypair,
		schedule_tx,
		None,
		finalized,
	)
	.await?;
	log_success!("📩 Schedule extrinsic submitted: {:?}", tx_hash);

	Ok(())
}

/// Handle scheduler commands
pub async fn handle_scheduler_command(
	command: SchedulerCommands,
	node_url: &str,
	tx_options: &crate::cli::common::TransactionOptions,
) -> Result<()> {
	log_print!("🗓️  Scheduler");

	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;
	let finalized = tx_options.finalized;

	match command {
		SchedulerCommands::GetLastProcessedTimestamp => {
			match get_last_processed_timestamp(&quantus_client).await? {
				Some(timestamp) => {
					log_success!("🎉 Last processed timestamp: {}", timestamp);
				},
				None => {
					log_print!(
						"🤷 No last processed timestamp found. The scheduler may not have run yet."
					);
				},
			}
			Ok(())
		},
		SchedulerCommands::Agenda { range } => list_agenda_range(&quantus_client, &range).await,
		SchedulerCommands::ScheduleRemark { after, from } =>
			schedule_remark(&quantus_client, after, &from, finalized).await,
	}
}
