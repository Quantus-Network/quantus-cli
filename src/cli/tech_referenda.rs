//! `quantus tech-referenda` subcommand - manage Tech Referenda proposals
use crate::{
	chain::quantus_subxt,
	cli::{common::submit_transaction, progress_spinner::wait_for_tx_confirmation},
	error::QuantusError,
	log_error, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use std::{path::PathBuf, str::FromStr};

/// Tech Referenda management commands
#[derive(Subcommand, Debug)]
pub enum TechReferendaCommands {
	/// Submit a runtime upgrade proposal to Tech Referenda (requires existing preimage)
	Submit {
		/// Preimage hash (must already exist on chain)
		#[arg(long)]
		preimage_hash: String,

		/// Wallet name to sign with (must be a Tech Collective member or root)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Submit a runtime upgrade proposal to Tech Referenda (creates preimage first)
	SubmitWithPreimage {
		/// Path to the runtime WASM file
		#[arg(short, long)]
		wasm_file: PathBuf,

		/// Wallet name to sign with (must be a Tech Collective member or root)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// List all active Tech Referenda proposals
	List,

	/// Get details of a specific Tech Referendum
	Get {
		/// Referendum index
		#[arg(short, long)]
		index: u32,
	},

	/// Check the status of a Tech Referendum
	Status {
		/// Referendum index
		#[arg(short, long)]
		index: u32,
	},

	/// Place a decision deposit for a Tech Referendum
	PlaceDecisionDeposit {
		/// Referendum index
		#[arg(short, long)]
		index: u32,

		/// Wallet name to sign with
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Cancel a Tech Referendum (requires root permissions)
	Cancel {
		/// Referendum index to cancel
		#[arg(short, long)]
		index: u32,

		/// Wallet name to sign with (must have root permissions)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Kill a Tech Referendum (requires root permissions)
	Kill {
		/// Referendum index to kill
		#[arg(short, long)]
		index: u32,

		/// Wallet name to sign with (must have root permissions)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Nudge a Tech Referendum to next phase (sudo origin)
	Nudge {
		/// Referendum index to nudge
		#[arg(short, long)]
		index: u32,

		/// Wallet name to sign with
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Refund submission deposit for a completed Tech Referendum
	RefundSubmissionDeposit {
		/// Referendum index
		#[arg(short, long)]
		index: u32,

		/// Wallet name that submitted the referendum
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Refund decision deposit for a completed Tech Referendum
	RefundDecisionDeposit {
		/// Referendum index
		#[arg(short, long)]
		index: u32,

		/// Wallet name that placed the decision deposit
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Get Tech Referenda configuration
	Config,
}

/// Handle tech referenda commands
pub async fn handle_tech_referenda_command(
	command: TechReferendaCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		TechReferendaCommands::Submit { preimage_hash, from, password, password_file } =>
			submit_runtime_upgrade(&quantus_client, &preimage_hash, &from, password, password_file)
				.await,
		TechReferendaCommands::SubmitWithPreimage { wasm_file, from, password, password_file } =>
			submit_runtime_upgrade_with_preimage(
				&quantus_client,
				&wasm_file,
				&from,
				password,
				password_file,
			)
			.await,
		TechReferendaCommands::List => list_proposals(&quantus_client).await,
		TechReferendaCommands::Get { index } => get_proposal_details(&quantus_client, index).await,
		TechReferendaCommands::Status { index } =>
			get_proposal_status(&quantus_client, index).await,
		TechReferendaCommands::PlaceDecisionDeposit { index, from, password, password_file } =>
			place_decision_deposit(&quantus_client, index, &from, password, password_file).await,
		TechReferendaCommands::Cancel { index, from, password, password_file } =>
			cancel_proposal(&quantus_client, index, &from, password, password_file).await,
		TechReferendaCommands::Kill { index, from, password, password_file } =>
			kill_proposal(&quantus_client, index, &from, password, password_file).await,
		TechReferendaCommands::Nudge { index, from, password, password_file } =>
			nudge_proposal(&quantus_client, index, &from, password, password_file).await,
		TechReferendaCommands::RefundSubmissionDeposit { index, from, password, password_file } =>
			refund_submission_deposit(&quantus_client, index, &from, password, password_file).await,
		TechReferendaCommands::RefundDecisionDeposit { index, from, password, password_file } =>
			refund_decision_deposit(&quantus_client, index, &from, password, password_file).await,
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
			quantus_subxt::api::runtime_types::qp_poseidon::PoseidonHasher,
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

	let tx_hash = submit_transaction(quantus_client, &keypair, submit_call, None).await?;
	log_print!(
		"✅ {} Runtime upgrade proposal submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	log_success!("🎉 {} Proposal created!", "FINISHED".bright_green().bold());
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
) -> crate::error::Result<()> {
	use qp_poseidon::PoseidonHasher;

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

	// Compute preimage hash using Poseidon (runtime uses PoseidonHasher)
	let preimage_hash: sp_core::H256 =
		<PoseidonHasher as sp_runtime::traits::Hash>::hash(&encoded_call);

	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	// Submit Preimage::note_preimage with bounded bytes
	type PreimageBytes = quantus_subxt::api::preimage::calls::types::note_preimage::Bytes;
	let bounded_bytes: PreimageBytes = encoded_call.clone();

	log_print!("📝 Submitting preimage...");
	let note_preimage_tx = quantus_subxt::api::tx().preimage().note_preimage(bounded_bytes);
	let preimage_tx_hash =
		submit_transaction(quantus_client, &keypair, note_preimage_tx, None).await?;
	log_print!("✅ Preimage transaction submitted: {:?}", preimage_tx_hash);

	// Wait for preimage transaction confirmation
	log_print!("⏳ Waiting for preimage transaction confirmation...");
	let _ = wait_for_tx_confirmation(quantus_client.client(), preimage_tx_hash).await?;
	log_print!("✅ Preimage transaction confirmed!");

	// Build TechReferenda::submit call using Lookup preimage reference
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::qp_poseidon::PoseidonHasher,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: encoded_call.len() as u32 };

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

	let tx_hash = submit_transaction(quantus_client, &keypair, submit_call, None).await?;
	log_print!(
		"✅ {} Runtime upgrade proposal submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	log_success!("🎉 {} Proposal created!", "FINISHED".bright_green().bold());
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
) -> crate::error::Result<()> {
	log_print!("📋 Placing decision deposit for Tech Referendum #{}", index);
	log_print!("   🔑 Placed by: {}", from.bright_yellow());

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	let deposit_call = quantus_subxt::api::tx().tech_referenda().place_decision_deposit(index);
	let tx_hash = submit_transaction(quantus_client, &keypair, deposit_call, None).await?;
	log_success!("✅ Decision deposit placed! Hash: {:?}", tx_hash.to_string().bright_yellow());
	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	Ok(())
}

/// Cancel a Tech Referendum (sudo)
async fn cancel_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	log_print!("❌ Cancelling Tech Referendum #{}", index);
	log_print!("   🔑 Cancelled by: {}", from.bright_yellow());

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	let inner =
		quantus_subxt::api::Call::TechReferenda(quantus_subxt::api::tech_referenda::Call::cancel {
			index,
		});
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(inner);

	let tx_hash = submit_transaction(quantus_client, &keypair, sudo_call, None).await?;
	log_success!("✅ Referendum cancelled! Hash: {:?}", tx_hash.to_string().bright_yellow());
	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	Ok(())
}

/// Kill a Tech Referendum (sudo)
async fn kill_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	log_print!("💀 Killing Tech Referendum #{}", index);
	log_print!("   🔑 Killed by: {}", from.bright_yellow());

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	let inner =
		quantus_subxt::api::Call::TechReferenda(quantus_subxt::api::tech_referenda::Call::kill {
			index,
		});
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(inner);

	let tx_hash = submit_transaction(quantus_client, &keypair, sudo_call, None).await?;
	log_success!("✅ Referendum killed! Hash: {:?}", tx_hash.to_string().bright_yellow());
	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	Ok(())
}

/// Nudge a Tech Referendum to next phase (sudo)
async fn nudge_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	log_print!("🔄 Nudging Tech Referendum #{}", index);
	log_print!("   🔑 Nudged by: {}", from.bright_yellow());

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	let inner = quantus_subxt::api::Call::TechReferenda(
		quantus_subxt::api::tech_referenda::Call::nudge_referendum { index },
	);
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(inner);

	let tx_hash = submit_transaction(quantus_client, &keypair, sudo_call, None).await?;
	log_success!("✅ Referendum nudged! Hash: {:?}", tx_hash.to_string().bright_yellow());
	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
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
) -> crate::error::Result<()> {
	log_print!("💰 Refunding submission deposit for Tech Referendum #{}", index);
	log_print!("   🔑 Refund to: {}", from.bright_yellow());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create refund_submission_deposit call for TechReferenda instance
	let refund_call = quantus_subxt::api::tx().tech_referenda().refund_submission_deposit(index);

	let tx_hash = submit_transaction(quantus_client, &keypair, refund_call, None).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
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
) -> crate::error::Result<()> {
	log_print!("💰 Refunding decision deposit for Tech Referendum #{}", index);
	log_print!("   🔑 Refund to: {}", from.bright_yellow());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create refund_decision_deposit call for TechReferenda instance
	let refund_call = quantus_subxt::api::tx().tech_referenda().refund_decision_deposit(index);

	let tx_hash = submit_transaction(quantus_client, &keypair, refund_call, None).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	log_success!("🎉 {} Decision deposit refunded!", "FINISHED".bright_green().bold());
	log_print!("💡 Check your balance to confirm the refund");
	Ok(())
}
