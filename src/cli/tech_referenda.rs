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

		#[arg(short, long)]
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

		#[arg(short, long)]
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

		#[arg(short, long)]
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

	/// Check the voting status and tally for a specific Tech Referendum
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

		#[arg(short, long)]
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

		#[arg(short, long)]
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

		#[arg(short, long)]
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

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

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
		submit_transaction(quantus_client, &keypair, submit_call, None, execution_mode).await?;
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

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

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
	crate::cli::common::submit_preimage(quantus_client, &keypair, encoded_call, execution_mode)
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
		submit_transaction(quantus_client, &keypair, submit_call, None, execution_mode).await?;
	log_success!(
		"Runtime upgrade proposal submitted! Hash: {:?}",
		tx_hash
	);

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

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

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
	crate::cli::common::submit_preimage(quantus_client, &keypair, encoded_call, execution_mode)
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
		submit_transaction(quantus_client, &keypair, submit_call, None, execution_mode).await?;
	log_success!(
		"Treasury portion proposal submitted! Hash: {:?}",
		tx_hash
	);

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
					log_print!("   - Status: {}", "Ongoing".bright_green());
					log_print!("   - Track: {}", status.track);
					log_print!("   - Submitted at: block {}", status.submitted);
					log_print!(
						"   - Tally: Ayes: {}, Nays: {}",
						status.tally.ayes,
						status.tally.nays
					);
					log_verbose!("   - Full status: {:#?}", status);
				},
				ReferendumInfo::Approved(submitted, ..) => {
					log_print!("   - Status: {}", "Approved".green());
					log_print!("   - Submitted at block: {}", submitted);
				},
				ReferendumInfo::Rejected(submitted, ..) => {
					log_print!("   - Status: {}", "Rejected".red());
					log_print!("   - Submitted at block: {}", submitted);
				},
				ReferendumInfo::Cancelled(submitted, ..) => {
					log_print!("   - Status: {}", "Cancelled".yellow());
					log_print!("   - Submitted at block: {}", submitted);
				},
				ReferendumInfo::TimedOut(submitted, ..) => {
					log_print!("   - Status: {}", "TimedOut".dimmed());
					log_print!("   - Submitted at block: {}", submitted);
				},
				ReferendumInfo::Killed(submitted) => {
					log_print!("   - Status: {}", "Killed".red().bold());
					log_print!("   - Killed at block: {}", submitted);
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

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	let deposit_call = quantus_subxt::api::tx().tech_referenda().place_decision_deposit(index);
	let tx_hash =
		submit_transaction(quantus_client, &keypair, deposit_call, None, execution_mode).await?;
	log_success!("✅ Decision deposit placed! Hash: {:?}", tx_hash.to_string().bright_yellow());
	Ok(())
}

/// Get Tech Referenda configuration
async fn get_config(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("⚙️  Tech Referenda Configuration");
	log_print!("");

	let constants = quantus_client.client().constants();
	let tracks_addr = quantus_subxt::api::constants().tech_referenda().tracks();

	match constants.at(&tracks_addr) {
		Ok(tracks) => {
			log_print!("{}", "📊 Track Configuration:".bold());
			for (id, info) in tracks.iter() {
				log_print!("   ------------------------------------");
				log_print!(
					"   • {} #{}: {}",
					"Track".bold(),
					id,
					info.name.to_string().bright_cyan()
				);
				log_print!("   • Max Deciding: {}", info.max_deciding);
				log_print!("   • Decision Deposit: {}", info.decision_deposit);
				log_print!("   • Prepare Period: {} blocks", info.prepare_period);
				log_print!("   • Decision Period: {} blocks", info.decision_period);
				log_print!("   • Confirm Period: {} blocks", info.confirm_period);
				log_print!("   • Min Enactment Period: {} blocks", info.min_enactment_period);
			}
			log_print!("   ------------------------------------");
		},
		Err(e) => {
			log_error!("❌ Failed to decode Tracks constant: {:?}", e);
			log_print!("💡 It's possible the Tracks constant is not in the expected format.");
		},
	}

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

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create refund_submission_deposit call for TechReferenda instance
	let refund_call = quantus_subxt::api::tx().tech_referenda().refund_submission_deposit(index);

	let tx_hash =
		submit_transaction(quantus_client, &keypair, refund_call, None, execution_mode).await?;
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

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create refund_decision_deposit call for TechReferenda instance
	let refund_call = quantus_subxt::api::tx().tech_referenda().refund_decision_deposit(index);

	let tx_hash =
		submit_transaction(quantus_client, &keypair, refund_call, None, execution_mode).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Decision deposit refunded!", "FINISHED".bright_green().bold());
	log_print!("💡 Check your balance to confirm the refund");
	Ok(())
}
