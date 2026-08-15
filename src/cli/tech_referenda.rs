//! `quantus tech-referenda` subcommand - manage Tech Referenda proposals
use crate::{
	chain::quantus_subxt, cli::common::submit_transaction, error::QuantusError, log_error,
	log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use std::{path::PathBuf, str::FromStr};

/// Tech Referenda: governance system for technical proposals (runtime upgrades, parameter changes).
///
/// Proposals go through: Submit -> Decision Deposit -> Voting -> Enactment.
/// Only Tech Collective members can submit proposals.
#[derive(Subcommand, Debug)]
pub enum TechReferendaCommands {
	/// Submit a runtime upgrade proposal using an existing on-chain preimage
	#[command(arg_required_else_help = true)]
	Submit {
		/// Hash of the preimage already stored on-chain (hex, with or without 0x prefix)
		#[arg(long, value_name = "HASH")]
		preimage_hash: String,

		/// Wallet name to sign with (must be a Tech Collective member)
		#[arg(short, long, value_name = "WALLET")]
		from: String,

		#[arg(short, long, hide = true)]
		password: Option<String>,

		#[arg(long)]
		password_file: Option<String>,
	},

	/// Submit a runtime upgrade proposal (uploads WASM as preimage, then submits)
	#[command(arg_required_else_help = true)]
	SubmitWithPreimage {
		/// Path to the compiled runtime WASM file to propose
		#[arg(short, long, value_name = "PATH")]
		wasm_file: PathBuf,

		/// Wallet name to sign with (must be a Tech Collective member)
		#[arg(short, long, value_name = "WALLET")]
		from: String,

		#[arg(short, long, hide = true)]
		password: Option<String>,

		#[arg(long)]
		password_file: Option<String>,
	},

	/// Propose a new Treasury portion (% of block rewards sent to treasury)
	///
	/// Creates the preimage and submits the referendum in one step.
	#[command(
		arg_required_else_help = true,
		after_help = "Examples:\n  quantus tech-referenda submit-treasury-portion --portion-permill 500000 --from alice   # 50%\n  quantus tech-referenda submit-treasury-portion --portion-permill 100000 --from alice   # 10%"
	)]
	SubmitTreasuryPortion {
		/// New treasury portion in Permill (parts per million, 0-1000000). 500000 = 50%
		#[arg(long, value_name = "PERMILL", value_parser = clap::value_parser!(u32).range(0..=1_000_000))]
		portion_permill: u32,

		/// Wallet name to sign with (must be a Tech Collective member)
		#[arg(short, long, value_name = "WALLET")]
		from: String,

		#[arg(short, long, hide = true)]
		password: Option<String>,

		#[arg(long)]
		password_file: Option<String>,
	},

	/// List all Tech Referenda proposals and their current status
	List,

	/// Show full details of a specific Tech Referendum (raw on-chain data)
	#[command(arg_required_else_help = true)]
	Get {
		/// Referendum index (shown in `list` output)
		#[arg(short, long, value_name = "REFERENDUM_INDEX")]
		index: u32,
	},

	/// Check the status of a Tech Referendum: phase, tally, timings and enactment estimates
	#[command(arg_required_else_help = true)]
	Status {
		/// Referendum index (shown in `list` output)
		#[arg(short, long, value_name = "REFERENDUM_INDEX")]
		index: u32,
	},

	/// Place the decision deposit to move a referendum from Preparing to Deciding phase
	///
	/// Required before voting can begin. The deposit is refundable after the referendum ends.
	#[command(
		arg_required_else_help = true,
		after_help = "Example:\n  quantus tech-referenda place-decision-deposit --index 0 --from alice"
	)]
	PlaceDecisionDeposit {
		/// Referendum index to place the deposit for
		#[arg(short, long, value_name = "REFERENDUM_INDEX")]
		index: u32,

		/// Wallet name to pay the deposit from (anyone can place it, not just the proposer)
		#[arg(short, long, value_name = "WALLET")]
		from: String,

		#[arg(short, long, hide = true)]
		password: Option<String>,

		#[arg(long)]
		password_file: Option<String>,
	},

	/// Refund the submission deposit after a Tech Referendum has completed
	///
	/// Only callable after the referendum is no longer ongoing (approved/rejected/timed out).
	#[command(arg_required_else_help = true)]
	RefundSubmissionDeposit {
		/// Referendum index to refund for
		#[arg(short, long, value_name = "REFERENDUM_INDEX")]
		index: u32,

		/// Wallet name to sign the refund transaction
		#[arg(short, long, value_name = "WALLET")]
		from: String,

		#[arg(short, long, hide = true)]
		password: Option<String>,

		#[arg(long)]
		password_file: Option<String>,
	},

	/// Refund the decision deposit after a Tech Referendum has completed
	///
	/// Only callable after the referendum is no longer ongoing (approved/rejected/timed out).
	#[command(arg_required_else_help = true)]
	RefundDecisionDeposit {
		/// Referendum index to refund for
		#[arg(short, long, value_name = "REFERENDUM_INDEX")]
		index: u32,

		/// Wallet name to sign the refund transaction
		#[arg(short, long, value_name = "WALLET")]
		from: String,

		#[arg(short, long, hide = true)]
		password: Option<String>,

		#[arg(long)]
		password_file: Option<String>,
	},

	/// Show Tech Referenda on-chain configuration (tracks, periods, deposits)
	Config,
}

/// Handle tech referenda commands
pub async fn handle_tech_referenda_command(
	command: TechReferendaCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		TechReferendaCommands::Submit { preimage_hash, from, password, password_file } =>
			submit_runtime_upgrade(
				&quantus_client,
				&preimage_hash,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await,
		TechReferendaCommands::SubmitWithPreimage { wasm_file, from, password, password_file } =>
			submit_runtime_upgrade_with_preimage(
				&quantus_client,
				&wasm_file,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await,
		TechReferendaCommands::SubmitTreasuryPortion {
			portion_permill,
			from,
			password,
			password_file,
		} =>
			submit_treasury_portion_with_preimage(
				&quantus_client,
				portion_permill,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await,
		TechReferendaCommands::List => list_proposals(&quantus_client).await,
		TechReferendaCommands::Get { index } => get_proposal_details(&quantus_client, index).await,
		TechReferendaCommands::Status { index } =>
			get_proposal_status(&quantus_client, index).await,
		TechReferendaCommands::PlaceDecisionDeposit { index, from, password, password_file } =>
			place_decision_deposit(
				&quantus_client,
				index,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await,
		TechReferendaCommands::RefundSubmissionDeposit { index, from, password, password_file } =>
			refund_submission_deposit(
				&quantus_client,
				index,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await,
		TechReferendaCommands::RefundDecisionDeposit { index, from, password, password_file } =>
			refund_decision_deposit(
				&quantus_client,
				index,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await,
		TechReferendaCommands::Config => get_config(&quantus_client).await,
	}
}

/// Submit a runtime upgrade proposal to Tech Referenda (uses existing preimage)
async fn submit_runtime_upgrade(
	quantus_client: &crate::chain::client::QuantusClient,
	preimage_hash: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("📝 Submitting Runtime Upgrade Proposal to Tech Referenda");
	log_print!("   🔗 Preimage hash: {}", preimage_hash.bright_cyan());
	log_print!("   🔑 Submitted by: {}", from.bright_yellow());

	// Parse preimage hash (trim 0x)
	let hash_str = preimage_hash.trim_start_matches("0x");
	let preimage_hash_parsed: sp_core::H256 = sp_core::H256::from_str(hash_str)
		.map_err(|_| QuantusError::Generic("Invalid preimage hash format".to_string()))?;

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from, password, password_file)?;

	// Check if preimage exists and get its length
	log_print!("🔍 Checking preimage status...");
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let preimage_status = storage_at
		.fetch(
			&quantus_subxt::api::storage()
				.preimage()
				.request_status_for(preimage_hash_parsed),
		)
		.await
		.map_err(|e| QuantusError::Generic(format!("Failed to fetch preimage status: {:?}", e)))?
		.ok_or_else(|| QuantusError::Generic("Preimage not found on chain".to_string()))?;

	let preimage_len = match preimage_status {
		quantus_subxt::api::runtime_types::pallet_preimage::RequestStatus::Unrequested {
			ticket: _,
			len,
		} => len,
		quantus_subxt::api::runtime_types::pallet_preimage::RequestStatus::Requested {
			maybe_ticket: _,
			count: _,
			maybe_len,
		} => match maybe_len {
			Some(len) => len,
			None => return Err(QuantusError::Generic("Preimage length not available".to_string())),
		},
	};

	log_print!("✅ Preimage found! Length: {} bytes", preimage_len);

	// Build TechReferenda::submit call using Lookup preimage reference
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::sp_runtime::traits::BlakeTwo256,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash_parsed;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: preimage_len };

	let raw_origin_root =
		quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root;
	let origin_caller =
		quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin_root);

	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			0u32,
		);

	log_print!("🔧 Creating TechReferenda::submit call...");
	let submit_call =
		quantus_subxt::api::tx()
			.tech_referenda()
			.submit(origin_caller, proposal, enactment);

	let tx_hash =
		submit_transaction(quantus_client, &signer, submit_call, None, execution_mode).await?;
	log_print!(
		"✅ {} Runtime upgrade proposal submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_print!("💡 Use 'quantus tech-referenda list' to see active proposals");
	Ok(())
}

/// Submit a runtime upgrade proposal to Tech Referenda (creates preimage first)
async fn submit_runtime_upgrade_with_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_file: &PathBuf,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	use sp_runtime::traits::{BlakeTwo256, Hash};

	log_print!("📝 Submitting Runtime Upgrade Proposal to Tech Referenda");
	log_print!("   📂 WASM file: {}", wasm_file.display().to_string().bright_cyan());
	log_print!("   🔑 Submitted by: {}", from.bright_yellow());

	if !wasm_file.exists() {
		return Err(QuantusError::Generic(format!("WASM file not found: {}", wasm_file.display())));
	}

	if let Some(ext) = wasm_file.extension() {
		if ext != "wasm" {
			log_verbose!("⚠️  Warning: File doesn't have .wasm extension");
		}
	}

	// Read WASM file
	let wasm_code = std::fs::read(wasm_file)
		.map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {}", e)))?;

	log_print!("📊 WASM file size: {} bytes", wasm_code.len());

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from, password, password_file)?;

	// Build a static payload for System::set_code and encode full call data (pallet + call + args)
	let set_code_payload = quantus_subxt::api::tx().system().set_code(wasm_code.clone());
	let metadata = quantus_client.client().metadata();
	let encoded_call = <_ as subxt::tx::Payload>::encode_call_data(&set_code_payload, &metadata)
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call data: {:?}", e)))?;

	log_verbose!("📝 Encoded call size: {} bytes", encoded_call.len());

	// Must match `frame_system::Config::Hashing` (BlakeTwo256) — same key as `pallet_preimage`.
	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(&encoded_call);

	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	let call_len = encoded_call.len() as u32;
	crate::cli::common::submit_preimage(quantus_client, &signer, encoded_call, execution_mode)
		.await?;

	// Build TechReferenda::submit call using Lookup preimage reference
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::sp_runtime::traits::BlakeTwo256,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: call_len };

	let raw_origin_root =
		quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root;
	let origin_caller =
		quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin_root);

	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			0u32,
		);

	log_print!("🔧 Submitting TechReferenda::submit...");
	let submit_call =
		quantus_subxt::api::tx()
			.tech_referenda()
			.submit(origin_caller, proposal, enactment);

	let tx_hash =
		submit_transaction(quantus_client, &signer, submit_call, None, execution_mode).await?;
	log_success!("Runtime upgrade proposal submitted! Hash: {:?}", tx_hash);

	log_print!("💡 Use 'quantus tech-referenda list' to see active proposals");
	Ok(())
}

/// Submit a Tech Referenda proposal to set the Treasury portion (creates preimage first)
async fn submit_treasury_portion_with_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	portion_permill: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	use sp_runtime::traits::{BlakeTwo256, Hash};

	log_print!("📝 Submitting Treasury Portion Update Proposal to Tech Referenda");
	log_print!("   📊 New portion (Permill): {}", portion_permill.to_string().bright_cyan());
	log_print!(
		"   📊 New portion (%): {}",
		format!("{:.2}%", (portion_permill as f64) / 10000.0).bright_cyan()
	);
	log_print!("   🔑 Submitted by: {}", from.bright_yellow());

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from, password, password_file)?;

	// Build a static payload for TreasuryPallet::set_treasury_portion and encode full call data
	// Note: runtime_types::Permill is a tuple struct (u32 parts-per-million).
	let portion =
		quantus_subxt::api::runtime_types::sp_arithmetic::per_things::Permill(portion_permill);
	let set_portion_payload =
		quantus_subxt::api::tx().treasury_pallet().set_treasury_portion(portion);

	let metadata = quantus_client.client().metadata();
	let encoded_call = <_ as subxt::tx::Payload>::encode_call_data(&set_portion_payload, &metadata)
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call data: {:?}", e)))?;

	log_verbose!("📝 Encoded call size: {} bytes", encoded_call.len());

	// Must match `frame_system::Config::Hashing` (BlakeTwo256) — same key as `pallet_preimage`.
	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(&encoded_call);
	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	let call_len = encoded_call.len() as u32;
	crate::cli::common::submit_preimage(quantus_client, &signer, encoded_call, execution_mode)
		.await?;

	// Build TechReferenda::submit call using Lookup preimage reference
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::sp_runtime::traits::BlakeTwo256,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: call_len };

	let raw_origin_root =
		quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root;
	let origin_caller =
		quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin_root);

	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			0u32,
		);

	log_print!("🔧 Submitting TechReferenda::submit...");
	let submit_call =
		quantus_subxt::api::tx()
			.tech_referenda()
			.submit(origin_caller, proposal, enactment);

	let tx_hash =
		submit_transaction(quantus_client, &signer, submit_call, None, execution_mode).await?;
	log_success!("Treasury portion proposal submitted! Hash: {:?}", tx_hash);

	log_print!("💡 Use 'quantus tech-referenda list' to see active proposals");
	Ok(())
}

/// List recent Tech Referenda proposals
async fn list_proposals(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("📜 Active Tech Referenda Proposals");
	log_print!("");

	let addr = quantus_subxt::api::storage().tech_referenda().referendum_count();

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let count = storage_at.fetch(&addr).await?;

	if let Some(total) = count {
		log_print!("📊 Total referenda created: {}", total);
		if total == 0 {
			log_print!("📭 No active proposals found");
			return Ok(());
		}
		log_print!("🔍 Fetching recent referenda...");
		for i in (0..total).rev().take(10) {
			get_proposal_status(quantus_client, i).await?;
			log_print!("----------------------------------------");
		}
	} else {
		log_print!("📭 No referenda found - Tech Referenda may be empty");
	}

	Ok(())
}

/// Get details of a specific Tech Referendum
async fn get_proposal_details(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
) -> crate::error::Result<()> {
	log_print!("📄 Tech Referendum #{} Details", index);
	log_print!("");

	let addr = quantus_subxt::api::storage().tech_referenda().referendum_info_for(index);

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let info = storage_at.fetch(&addr).await?;

	if let Some(referendum_info) = info {
		log_print!("📋 Referendum Information (raw):");
		log_print!("{:#?}", referendum_info);
	} else {
		log_print!("📭 Referendum #{} not found", index);
	}
	Ok(())
}

type TrackDetails =
	quantus_subxt::api::runtime_types::pallet_referenda::types::TrackDetails<u128, u32, String>;

/// Fetch the TechReferenda track list from chain constants
fn fetch_tracks(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<Vec<(u16, TrackDetails)>> {
	quantus_client
		.client()
		.constants()
		.at(&quantus_subxt::api::constants().tech_referenda().tracks())
		.map_err(|e| QuantusError::Generic(format!("Failed to decode Tracks constant: {e:?}")))
}

/// Fetch the chain's target block time in milliseconds
fn target_block_time_ms(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<u64> {
	quantus_client
		.client()
		.constants()
		.at(&quantus_subxt::api::constants().q_po_w().target_block_time())
		.map_err(|e| {
			QuantusError::Generic(format!("Failed to read TargetBlockTime constant: {e:?}"))
		})
}

/// Track names are stored as fixed-width, NUL-padded strings on chain
fn track_display_name(name: &str) -> &str {
	name.trim_matches(|c: char| c == '\0' || c.is_whitespace())
}

/// Human-readable duration for a number of blocks at the target block time
fn format_blocks_duration(blocks: u64, block_time_ms: u64) -> String {
	let secs = blocks.saturating_mul(block_time_ms) / 1000;
	if secs < 60 {
		format!("{}s", secs)
	} else if secs < 3600 {
		format!("{:.0}min", secs as f64 / 60.0)
	} else if secs < 172_800 {
		format!("{:.1}h", secs as f64 / 3600.0)
	} else {
		format!("{:.1} days", secs as f64 / 86400.0)
	}
}

/// Describe a block number relative to the current block, with an estimated wall-clock time
fn format_block_eta(target_block: u32, current_block: u32, block_time_ms: u64) -> String {
	if target_block <= current_block {
		let ago = (current_block - target_block) as u64;
		let at = chrono::Utc::now() -
			chrono::Duration::milliseconds(ago.saturating_mul(block_time_ms) as i64);
		format!(
			"block {} (~{} ago, ≈ {})",
			target_block,
			format_blocks_duration(ago, block_time_ms),
			at.format("%Y-%m-%d %H:%M UTC")
		)
	} else {
		let delta = (target_block - current_block) as u64;
		let eta = chrono::Utc::now() +
			chrono::Duration::milliseconds(delta.saturating_mul(block_time_ms) as i64);
		format!(
			"block {} (in {} blocks / ~{}, ≈ {})",
			target_block,
			delta,
			format_blocks_duration(delta, block_time_ms),
			eta.format("%Y-%m-%d %H:%M UTC")
		)
	}
}

/// Scheduler task id for a referendum's enactment call (matches pallet-referenda).
fn enactment_task_name(index: u32) -> [u8; 32] {
	use codec::Encode;
	const ASSEMBLY_ID: [u8; 8] = *b"assembly";
	sp_core::hashing::blake2_256(&(ASSEMBLY_ID, "enactment", index).encode())
}

/// Resolve the scheduled enactment block from Scheduler::Lookup, if still pending.
async fn scheduled_enactment_block(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	at_block: subxt::utils::H256,
) -> crate::error::Result<Option<u32>> {
	use quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp;

	let addr = quantus_subxt::api::storage().scheduler().lookup(enactment_task_name(index));
	let storage_at = quantus_client.client().storage().at(at_block);
	let Some((when, _)) = storage_at.fetch(&addr).await.map_err(|e| {
		QuantusError::NetworkError(format!(
			"Failed to fetch Scheduler::Lookup for referendum #{index}: {e:?}"
		))
	})?
	else {
		return Ok(None);
	};

	match when {
		BlockNumberOrTimestamp::BlockNumber(block) => Ok(Some(block)),
		BlockNumberOrTimestamp::Timestamp(_) => Err(QuantusError::Generic(format!(
			"Referendum #{index} enactment is scheduled by timestamp, not block number"
		))),
	}
}

/// Compute the enactment block for a given approval block, honoring the track's minimum delay
fn enactment_block(
	enactment: &quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime<
		u32,
	>,
	approval_block: u32,
	min_enactment_period: u32,
) -> u32 {
	use quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime;
	let desired = match enactment {
		DispatchTime::At(block) => *block,
		DispatchTime::After(offset) => approval_block.saturating_add(*offset),
	};
	desired.max(approval_block.saturating_add(min_enactment_period))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreDecidingState {
	Preparing { deposit_placed: bool },
	WaitingForDecisionDeposit,
	WaitingForTrackSlot,
	Ready,
}

impl PreDecidingState {
	fn enactment_estimate_reason(self) -> &'static str {
		match self {
			Self::Preparing { deposit_placed: false } =>
				"until the prepare period ends, the decision deposit is placed, and Deciding starts",
			Self::Preparing { deposit_placed: true } =>
				"until the prepare period ends and Deciding starts",
			Self::WaitingForDecisionDeposit =>
				"until the decision deposit is placed and Deciding starts",
			Self::WaitingForTrackSlot => "until a deciding slot opens and Deciding starts",
			Self::Ready => "until Deciding starts",
		}
	}
}

fn pre_deciding_state(
	prepare_end: u32,
	current_block: u32,
	deposit_placed: bool,
	in_queue: bool,
) -> PreDecidingState {
	if in_queue {
		PreDecidingState::WaitingForTrackSlot
	} else if current_block < prepare_end {
		PreDecidingState::Preparing { deposit_placed }
	} else if !deposit_placed {
		PreDecidingState::WaitingForDecisionDeposit
	} else {
		PreDecidingState::Ready
	}
}

/// Get the status of a Tech Referendum
async fn get_proposal_status(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
) -> crate::error::Result<()> {
	use quantus_subxt::api::runtime_types::pallet_referenda::types::ReferendumInfo;

	log_verbose!("📊 Fetching status for Tech Referendum #{}...", index);

	let addr = quantus_subxt::api::storage().tech_referenda().referendum_info_for(index);

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let info_res = storage_at.fetch(&addr).await;

	match info_res {
		Ok(Some(info)) => {
			log_print!("📊 Status for Referendum #{}", index.to_string().bright_yellow());
			match info {
				ReferendumInfo::Ongoing(status) => {
					let current_block =
						quantus_client.client().blocks().at(latest_block_hash).await?.number();
					let block_time_ms = target_block_time_ms(quantus_client)?;
					let tracks = fetch_tracks(quantus_client)?;
					let (_, track) =
						tracks.iter().find(|(id, _)| *id == status.track).ok_or_else(|| {
							QuantusError::Generic(format!(
								"Track {} not found in Tracks constant",
								status.track
							))
						})?;

					log_print!("   - Status: {}", "Ongoing".bright_green());
					log_print!(
						"   - Track: {} ({})",
						status.track,
						track_display_name(&track.name).bright_cyan()
					);
					log_print!("   - Current block: {}", current_block);
					log_print!(
						"   - Submitted at: {}",
						format_block_eta(status.submitted, current_block, block_time_ms)
					);
					log_print!(
						"   - Tally: Ayes: {}, Nays: {}",
						status.tally.ayes,
						status.tally.nays
					);
					log_print!(
						"   - Decision deposit: {}",
						if status.decision_deposit.is_some() {
							"placed".green()
						} else {
							"not placed".yellow()
						}
					);

					log_print!("");
					log_print!(
						"   ⏱️  Track phase durations (target block time {}s):",
						block_time_ms / 1000
					);
					log_print!(
						"      - Prepare: {} blocks (~{})",
						track.prepare_period,
						format_blocks_duration(track.prepare_period as u64, block_time_ms)
					);
					log_print!(
						"      - Decide: up to {} blocks (~{})",
						track.decision_period,
						format_blocks_duration(track.decision_period as u64, block_time_ms)
					);
					log_print!(
						"      - Confirm: {} blocks (~{})",
						track.confirm_period,
						format_blocks_duration(track.confirm_period as u64, block_time_ms)
					);
					log_print!(
						"      - Enactment delay after approval: ≥ {} blocks (~{})",
						track.min_enactment_period,
						format_blocks_duration(track.min_enactment_period as u64, block_time_ms)
					);

					log_print!("");
					let prepare_end = status.submitted.saturating_add(track.prepare_period);
					match &status.deciding {
						None => {
							let pre_deciding = pre_deciding_state(
								prepare_end,
								current_block,
								status.decision_deposit.is_some(),
								status.in_queue,
							);
							log_print!(
								"   🧭 Phase: {} (1 of 3: Preparing → Deciding → Confirming)",
								"Preparing".bright_yellow()
							);
							log_print!(
								"      - Prepare period ends at {}",
								format_block_eta(prepare_end, current_block, block_time_ms)
							);
							log_print!("");
							match pre_deciding {
								PreDecidingState::Preparing { deposit_placed } => log_print!(
									"   ⏭️  Next phase: Deciding — earliest at {}{}",
									format_block_eta(prepare_end, current_block, block_time_ms),
									if deposit_placed {
										""
									} else {
										" (requires the decision deposit to be placed)"
									}
								),
								PreDecidingState::WaitingForDecisionDeposit => {
									log_print!(
											"   ⏭️  Next phase: Deciding — prepare period complete, starts once the decision deposit is placed"
										);
									log_print!(
											"      💡 Run: quantus tech-referenda place-decision-deposit --index {} --from <wallet>",
											index
										);
								},
								PreDecidingState::WaitingForTrackSlot => log_print!(
										"   ⏭️  Next phase: Deciding — waiting for a free deciding slot on this track"
									),
								PreDecidingState::Ready => log_print!(
										"   ⏭️  Next phase: Deciding — prepare period complete, waiting for the chain transition"
									),
							}
							log_print!(
								"   🏁 Enactment estimate: unavailable {}",
								pre_deciding.enactment_estimate_reason()
							);
						},
						Some(deciding) => match deciding.confirming {
							None => {
								let decision_end =
									deciding.since.saturating_add(track.decision_period);
								log_print!(
									"   🧭 Phase: {} (2 of 3: Preparing → Deciding → Confirming)",
									"Deciding".bright_yellow()
								);
								log_print!(
									"      - Started at {}",
									format_block_eta(deciding.since, current_block, block_time_ms)
								);
								log_print!(
									"      - Decision deadline: {} — must enter Confirming by then or it is rejected",
									format_block_eta(decision_end, current_block, block_time_ms)
								);
								log_print!("");
								log_print!(
									"   ⏭️  Next phase: Confirming — starts as soon as approval & support thresholds pass; lasts {} blocks (~{})",
									track.confirm_period,
									format_blocks_duration(
										track.confirm_period as u64,
										block_time_ms
									)
								);
								let earliest_approval =
									current_block.saturating_add(track.confirm_period);
								let latest_approval =
									decision_end.saturating_add(track.confirm_period);
								log_print!(
									"   🏁 Earliest enactment: {} (confirmation starts now)",
									format_block_eta(
										enactment_block(
											&status.enactment,
											earliest_approval,
											track.min_enactment_period
										),
										current_block,
										block_time_ms
									)
								);
								log_print!(
									"   🏁 Latest enactment: {} (confirmation only starts at the decision deadline)",
									format_block_eta(
										enactment_block(
											&status.enactment,
											latest_approval,
											track.min_enactment_period
										),
										current_block,
										block_time_ms
									)
								);
							},
							Some(confirm_end) => {
								log_print!(
									"   🧭 Phase: {} (3 of 3: Preparing → Deciding → Confirming)",
									"Confirming".bright_green()
								);
								log_print!(
									"      - Confirmation started at {}",
									format_block_eta(
										confirm_end.saturating_sub(track.confirm_period),
										current_block,
										block_time_ms
									)
								);
								log_print!(
									"      - Approval at {} (if support holds; otherwise it falls back to Deciding)",
									format_block_eta(confirm_end, current_block, block_time_ms)
								);
								log_print!("");
								log_print!("   ⏭️  Next phase: Approved → enactment is scheduled");
								log_print!(
									"   🏁 Enactment: {}",
									format_block_eta(
										enactment_block(
											&status.enactment,
											confirm_end,
											track.min_enactment_period
										),
										current_block,
										block_time_ms
									)
								);
							},
						},
					}
					log_verbose!("   - Full status: {:#?}", status);
				},
				ReferendumInfo::Approved(since, ..) => {
					let current_block =
						quantus_client.client().blocks().at(latest_block_hash).await?.number();
					let block_time_ms = target_block_time_ms(quantus_client)?;
					log_print!("   - Status: {}", "Approved".green());
					log_print!(
						"   - Approved at: {}",
						format_block_eta(since, current_block, block_time_ms)
					);
					match scheduled_enactment_block(quantus_client, index, latest_block_hash)
						.await?
					{
						Some(when) => log_print!(
							"   🏁 Enactment: {}",
							format_block_eta(when, current_block, block_time_ms)
						),
						None => log_print!(
							"   🏁 Enactment: no longer scheduled; execution outcome unavailable"
						),
					}
				},
				ReferendumInfo::Rejected(since, ..) => {
					log_print!("   - Status: {}", "Rejected".red());
					log_print!("   - Rejected at block: {}", since);
				},
				ReferendumInfo::Cancelled(since, ..) => {
					log_print!("   - Status: {}", "Cancelled".yellow());
					log_print!("   - Cancelled at block: {}", since);
				},
				ReferendumInfo::TimedOut(since, ..) => {
					log_print!("   - Status: {}", "TimedOut".dimmed());
					log_print!("   - Timed out at block: {}", since);
				},
				ReferendumInfo::Killed(since) => {
					log_print!("   - Status: {}", "Killed".red().bold());
					log_print!("   - Killed at block: {}", since);
				},
			}
		},
		Ok(None) => log_print!("📭 Referendum #{} not found", index),
		Err(e) => log_error!("❌ Failed to fetch referendum #{}: {:?}", index, e),
	}

	Ok(())
}

/// Place a decision deposit for a Tech Referendum
async fn place_decision_deposit(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("📋 Placing decision deposit for Tech Referendum #{}", index);
	log_print!("   🔑 Placed by: {}", from.bright_yellow());

	let signer = crate::wallet::load_signer_from_wallet(from, password, password_file)?;

	let deposit_call = quantus_subxt::api::tx().tech_referenda().place_decision_deposit(index);
	let tx_hash =
		submit_transaction(quantus_client, &signer, deposit_call, None, execution_mode).await?;
	log_success!("✅ Decision deposit placed! Hash: {:?}", tx_hash.to_string().bright_yellow());
	Ok(())
}

/// Get Tech Referenda configuration
async fn get_config(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("⚙️  Tech Referenda Configuration");
	log_print!("");

	let tracks = fetch_tracks(quantus_client)?;
	let block_time_ms = target_block_time_ms(quantus_client)?;

	log_print!("{}", "📊 Track Configuration:".bold());
	log_print!("   Target block time: {}s", block_time_ms / 1000);
	for (id, info) in tracks.iter() {
		log_print!("   ------------------------------------");
		log_print!(
			"   • {} #{}: {}",
			"Track".bold(),
			id,
			track_display_name(&info.name).bright_cyan()
		);
		log_print!("   • Max Deciding: {}", info.max_deciding);
		log_print!("   • Decision Deposit: {}", info.decision_deposit);
		log_print!(
			"   • Prepare Period: {} blocks (~{})",
			info.prepare_period,
			format_blocks_duration(info.prepare_period as u64, block_time_ms)
		);
		log_print!(
			"   • Decision Period: {} blocks (~{})",
			info.decision_period,
			format_blocks_duration(info.decision_period as u64, block_time_ms)
		);
		log_print!(
			"   • Confirm Period: {} blocks (~{})",
			info.confirm_period,
			format_blocks_duration(info.confirm_period as u64, block_time_ms)
		);
		log_print!(
			"   • Min Enactment Period: {} blocks (~{})",
			info.min_enactment_period,
			format_blocks_duration(info.min_enactment_period as u64, block_time_ms)
		);
	}
	log_print!("   ------------------------------------");

	Ok(())
}

/// Refund submission deposit for a completed Tech Referendum
async fn refund_submission_deposit(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("💰 Refunding submission deposit for Tech Referendum #{}", index);
	log_print!("   🔑 Refund to: {}", from.bright_yellow());

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from, password, password_file)?;

	// Create refund_submission_deposit call for TechReferenda instance
	let refund_call = quantus_subxt::api::tx().tech_referenda().refund_submission_deposit(index);

	let tx_hash =
		submit_transaction(quantus_client, &signer, refund_call, None, execution_mode).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Submission deposit refunded!", "FINISHED".bright_green().bold());
	log_print!("💡 Check your balance to confirm the refund");
	Ok(())
}

/// Refund decision deposit for a completed Tech Referendum
async fn refund_decision_deposit(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("💰 Refunding decision deposit for Tech Referendum #{}", index);
	log_print!("   🔑 Refund to: {}", from.bright_yellow());

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from, password, password_file)?;

	// Create refund_decision_deposit call for TechReferenda instance
	let refund_call = quantus_subxt::api::tx().tech_referenda().refund_decision_deposit(index);

	let tx_hash =
		submit_transaction(quantus_client, &signer, refund_call, None, execution_mode).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Decision deposit refunded!", "FINISHED".bright_green().bold());
	log_print!("💡 Check your balance to confirm the refund");
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::{enactment_task_name, format_block_eta, pre_deciding_state, PreDecidingState};
	use codec::Encode;

	#[test]
	fn missing_deposit_blocks_pre_deciding_enactment_estimate() {
		let state = pre_deciding_state(100, 100, false, false);

		assert_eq!(state, PreDecidingState::WaitingForDecisionDeposit);
		assert_eq!(
			state.enactment_estimate_reason(),
			"until the decision deposit is placed and Deciding starts"
		);
	}

	#[test]
	fn queued_referendum_blocks_pre_deciding_enactment_estimate() {
		let state = pre_deciding_state(100, 200, true, true);

		assert_eq!(state, PreDecidingState::WaitingForTrackSlot);
		assert_eq!(
			state.enactment_estimate_reason(),
			"until a deciding slot opens and Deciding starts"
		);
	}

	#[test]
	fn enactment_task_name_matches_pallet_referenda_formula() {
		const ASSEMBLY_ID: [u8; 8] = *b"assembly";
		let index = 4u32;
		let expected = sp_core::hashing::blake2_256(&(ASSEMBLY_ID, "enactment", index).encode());
		assert_eq!(enactment_task_name(index), expected);
	}

	#[test]
	fn format_block_eta_includes_absolute_time_for_past_and_future() {
		let past = format_block_eta(100, 200, 6_000);
		assert!(past.contains("block 100"), "{past}");
		assert!(past.contains("ago"), "{past}");
		assert!(past.contains("UTC"), "{past}");

		let future = format_block_eta(300, 200, 6_000);
		assert!(future.contains("block 300"), "{future}");
		assert!(future.contains("in 100 blocks"), "{future}");
		assert!(future.contains("UTC"), "{future}");
	}
}
