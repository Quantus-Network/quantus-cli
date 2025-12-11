//! `quantus referenda` subcommand - manage standard Referenda proposals
use crate::{
	chain::quantus_subxt, cli::common::submit_transaction, error::QuantusError, log_error,
	log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use std::str::FromStr;

/// Standard Referenda management commands
#[derive(Subcommand, Debug)]
pub enum ReferendaCommands {
	/// Submit a simple proposal (System::remark) to test Referenda
	SubmitRemark {
		/// Message to include in the remark
		#[arg(long)]
		message: String,

		/// Wallet name to sign with
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Origin type: signed (default), none (for signaling track), root
		#[arg(long, default_value = "signed")]
		origin: String,
	},

	/// Submit a proposal using existing preimage hash
	Submit {
		/// Preimage hash (must already exist on chain)
		#[arg(long)]
		preimage_hash: String,

		/// Wallet name to sign with
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Origin type: signed (default), none (for signaling track), root
		#[arg(long, default_value = "signed")]
		origin: String,
	},

	/// List all active Referenda proposals
	List,

	/// Get details of a specific Referendum
	Get {
		/// Referendum index
		#[arg(short, long)]
		index: u32,

		/// Decode and display the proposal call in human-readable format
		#[arg(long)]
		decode: bool,
	},

	/// Check the status of a Referendum
	Status {
		/// Referendum index
		#[arg(short, long)]
		index: u32,
	},

	/// Place a decision deposit for a Referendum
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

	/// Vote on a Referendum (uses conviction voting)
	Vote {
		/// Referendum index
		#[arg(short, long)]
		index: u32,

		/// Vote aye (true) or nay (false)
		#[arg(long)]
		aye: bool,

		/// Conviction (0=None, 1=Locked1x, 2=Locked2x, up to 6=Locked6x)
		#[arg(long, default_value = "0")]
		conviction: u8,

		/// Amount to vote with
		#[arg(long)]
		amount: String,

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

	/// Refund submission deposit for a completed Referendum
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

	/// Refund decision deposit for a completed Referendum
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

	/// Get Referenda configuration
	Config,
}

/// Handle referenda commands
pub async fn handle_referenda_command(
	command: ReferendaCommands,
	node_url: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		ReferendaCommands::SubmitRemark { message, from, password, password_file, origin } =>
			submit_remark_proposal(
				&quantus_client,
				&message,
				&from,
				password,
				password_file,
				&origin,
				finalized,
			)
			.await,
		ReferendaCommands::Submit { preimage_hash, from, password, password_file, origin } =>
			submit_proposal(
				&quantus_client,
				&preimage_hash,
				&from,
				password,
				password_file,
				&origin,
				finalized,
			)
			.await,
		ReferendaCommands::List => list_proposals(&quantus_client).await,
		ReferendaCommands::Get { index, decode } =>
			get_proposal_details(&quantus_client, index, decode).await,
		ReferendaCommands::Status { index } => get_proposal_status(&quantus_client, index).await,
		ReferendaCommands::PlaceDecisionDeposit { index, from, password, password_file } =>
			place_decision_deposit(
				&quantus_client,
				index,
				&from,
				password,
				password_file,
				finalized,
			)
			.await,
		ReferendaCommands::Vote {
			index,
			aye,
			conviction,
			amount,
			from,
			password,
			password_file,
		} =>
			vote_on_referendum(
				&quantus_client,
				index,
				aye,
				conviction,
				&amount,
				&from,
				password,
				password_file,
				finalized,
			)
			.await,
		ReferendaCommands::RefundSubmissionDeposit { index, from, password, password_file } =>
			refund_submission_deposit(
				&quantus_client,
				index,
				&from,
				password,
				password_file,
				finalized,
			)
			.await,
		ReferendaCommands::RefundDecisionDeposit { index, from, password, password_file } =>
			refund_decision_deposit(
				&quantus_client,
				index,
				&from,
				password,
				password_file,
				finalized,
			)
			.await,
		ReferendaCommands::Config => get_config(&quantus_client).await,
	}
}

/// Submit a simple System::remark proposal
async fn submit_remark_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	message: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	origin_type: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	use qp_poseidon::PoseidonHasher;

	log_print!("📝 Submitting System::remark Proposal to Referenda");
	log_print!("   💬 Message: {}", message.bright_cyan());
	log_print!("   🔑 Submitted by: {}", from.bright_yellow());
	log_print!("   🎯 Origin type: {}", origin_type.bright_magenta());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Build System::remark call and encode it
	let remark_bytes = message.as_bytes().to_vec();
	let remark_payload = quantus_subxt::api::tx().system().remark(remark_bytes.clone());
	let metadata = quantus_client.client().metadata();
	let encoded_call = <_ as subxt::tx::Payload>::encode_call_data(&remark_payload, &metadata)
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call data: {:?}", e)))?;

	log_verbose!("📝 Encoded call size: {} bytes", encoded_call.len());

	// Compute preimage hash using Poseidon
	let preimage_hash: sp_core::H256 =
		<PoseidonHasher as sp_runtime::traits::Hash>::hash(&encoded_call);

	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	// Submit Preimage::note_preimage
	type PreimageBytes = quantus_subxt::api::preimage::calls::types::note_preimage::Bytes;
	let bounded_bytes: PreimageBytes = encoded_call.clone();

	log_print!("📝 Submitting preimage...");
	let note_preimage_tx = quantus_subxt::api::tx().preimage().note_preimage(bounded_bytes);
	let preimage_tx_hash =
		submit_transaction(quantus_client, &keypair, note_preimage_tx, None, finalized).await?;
	log_print!("✅ Preimage transaction submitted: {:?}", preimage_tx_hash);

	// Wait for preimage transaction confirmation
	log_print!("⏳ Waiting for preimage transaction confirmation...");

	// Build Referenda::submit call using Lookup preimage reference
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::qp_poseidon::PoseidonHasher,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: encoded_call.len() as u32 };

	// Create origin based on origin_type parameter
	let account_id_sp = keypair.to_account_id_32();
	let account_id_subxt: subxt::ext::subxt_core::utils::AccountId32 =
		subxt::ext::subxt_core::utils::AccountId32(*account_id_sp.as_ref());

	let origin_caller = match origin_type.to_lowercase().as_str() {
		"signed" => {
			let raw_origin =
				quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Signed(
					account_id_subxt,
				);
			quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin)
		},
		"none" => {
			let raw_origin =
				quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::None;
			quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin)
		},
		"root" => {
			let raw_origin =
				quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root;
			quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin)
		},
		_ =>
			return Err(QuantusError::Generic(format!(
				"Invalid origin type: {}. Must be 'signed', 'none', or 'root'",
				origin_type
			))),
	};

	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			10u32, // Execute 10 blocks after approval
		);

	log_print!("🔧 Creating Referenda::submit call...");
	let submit_call =
		quantus_subxt::api::tx().referenda().submit(origin_caller, proposal, enactment);

	let tx_hash =
		submit_transaction(quantus_client, &keypair, submit_call, None, finalized).await?;
	log_print!(
		"✅ {} Referendum proposal submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_print!("💡 Use 'quantus referenda list' to see active proposals");
	Ok(())
}

/// Submit a proposal using existing preimage hash
async fn submit_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	preimage_hash: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	origin_type: &str,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("📝 Submitting Proposal to Referenda");
	log_print!("   🔗 Preimage hash: {}", preimage_hash.bright_cyan());
	log_print!("   🔑 Submitted by: {}", from.bright_yellow());
	log_print!("   🎯 Origin type: {}", origin_type.bright_magenta());

	// Parse preimage hash
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

	// Build Referenda::submit call
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::qp_poseidon::PoseidonHasher,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash_parsed;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: preimage_len };

	// Create origin based on origin_type parameter
	let account_id_sp = keypair.to_account_id_32();
	let account_id_subxt: subxt::ext::subxt_core::utils::AccountId32 =
		subxt::ext::subxt_core::utils::AccountId32(*account_id_sp.as_ref());

	let origin_caller = match origin_type.to_lowercase().as_str() {
		"signed" => {
			let raw_origin =
				quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Signed(
					account_id_subxt,
				);
			quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin)
		},
		"none" => {
			let raw_origin =
				quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::None;
			quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin)
		},
		"root" => {
			let raw_origin =
				quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root;
			quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin)
		},
		_ =>
			return Err(QuantusError::Generic(format!(
				"Invalid origin type: {}. Must be 'signed', 'none', or 'root'",
				origin_type
			))),
	};

	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			10u32,
		);

	log_print!("🔧 Creating Referenda::submit call...");
	let submit_call =
		quantus_subxt::api::tx().referenda().submit(origin_caller, proposal, enactment);

	let tx_hash =
		submit_transaction(quantus_client, &keypair, submit_call, None, finalized).await?;
	log_print!(
		"✅ {} Referendum proposal submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_print!("💡 Use 'quantus referenda list' to see active proposals");
	Ok(())
}

/// List recent Referenda proposals
async fn list_proposals(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("📜 Active Referenda Proposals");
	log_print!("");

	let addr = quantus_subxt::api::storage().referenda().referendum_count();

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
		log_print!("📭 No referenda found - Referenda may be empty");
	}

	Ok(())
}

/// Get details of a specific Referendum
async fn get_proposal_details(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	decode: bool,
) -> crate::error::Result<()> {
	use quantus_subxt::api::runtime_types::pallet_referenda::types::ReferendumInfo;

	log_print!("📄 Referendum #{} Details", index);
	log_print!("");

	let addr = quantus_subxt::api::storage().referenda().referendum_info_for(index);

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let info = storage_at.fetch(&addr).await?;

	if let Some(referendum_info) = info {
		if decode {
			// Try to decode the proposal
			match &referendum_info {
				ReferendumInfo::Ongoing(status) => {
					log_print!("📊 {} Referendum #{}", "Ongoing".bright_green(), index);
					log_print!("   🛤️  Track: {}", status.track);
					log_print!("   📅 Submitted: Block #{}", status.submitted);
					log_print!(
						"   🗳️  Tally: Ayes: {}, Nays: {}, Support: {}",
						status.tally.ayes,
						status.tally.nays,
						status.tally.support
					);
					log_print!("");

					// Extract preimage hash and length from proposal
					if let quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded::Lookup {
						hash,
						len,
					} = &status.proposal
					{
						log_print!("📝 Proposal Details:");
						log_print!("   🔗 Preimage Hash: {:?}", hash);
						log_print!("   📏 Length: {} bytes", len);
						log_print!("");

						// Fetch and decode the preimage
					match crate::cli::referenda_decode::decode_preimage(quantus_client, hash, *len).await {
						Ok(decoded) => {
							log_print!("✅ Decoded Proposal:");
							log_print!("{}", decoded);
						},
						Err(e) => {
							log_print!("⚠️  Could not decode proposal: {}", e);
							log_print!("   Run 'quantus preimage get --hash {:?} --len {}' to see raw data", hash, len);
						},
					}
					} else {
						log_print!("⚠️  Proposal is inline (not a preimage lookup)");
					}
				},
				ReferendumInfo::Approved(..) => {
					log_print!("📊 {} Referendum #{}", "Approved".green(), index);
					log_print!(
						"   ℹ️  Proposal details no longer available (referendum finalized)"
					);
				},
				ReferendumInfo::Rejected(..) => {
					log_print!("📊 {} Referendum #{}", "Rejected".red(), index);
					log_print!(
						"   ℹ️  Proposal details no longer available (referendum finalized)"
					);
				},
				ReferendumInfo::Cancelled(..) => {
					log_print!("📊 {} Referendum #{}", "Cancelled".yellow(), index);
					log_print!(
						"   ℹ️  Proposal details no longer available (referendum finalized)"
					);
				},
				ReferendumInfo::TimedOut(..) => {
					log_print!("📊 {} Referendum #{}", "TimedOut".dimmed(), index);
					log_print!(
						"   ℹ️  Proposal details no longer available (referendum finalized)"
					);
				},
				ReferendumInfo::Killed(..) => {
					log_print!("📊 {} Referendum #{}", "Killed".red().bold(), index);
					log_print!("   ℹ️  Proposal details no longer available (referendum killed)");
				},
			}
		} else {
			// Raw output (original behavior)
			log_print!("📋 Referendum Information (raw):");
			log_print!("{:#?}", referendum_info);
		}
	} else {
		log_print!("📭 Referendum #{} not found", index);
	}
	Ok(())
}

/// Get the status of a Referendum
async fn get_proposal_status(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
) -> crate::error::Result<()> {
	use quantus_subxt::api::runtime_types::pallet_referenda::types::ReferendumInfo;

	log_verbose!("📊 Fetching status for Referendum #{}...", index);

	let addr = quantus_subxt::api::storage().referenda().referendum_info_for(index);

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

/// Place a decision deposit for a Referendum
async fn place_decision_deposit(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("📋 Placing decision deposit for Referendum #{}", index);
	log_print!("   🔑 Placed by: {}", from.bright_yellow());

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	let deposit_call = quantus_subxt::api::tx().referenda().place_decision_deposit(index);
	let tx_hash =
		submit_transaction(quantus_client, &keypair, deposit_call, None, finalized).await?;
	log_success!("✅ Decision deposit placed! Hash: {:?}", tx_hash.to_string().bright_yellow());
	Ok(())
}

/// Vote on a Referendum
async fn vote_on_referendum(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	aye: bool,
	conviction: u8,
	amount: &str,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("🗳️  Voting on Referendum #{}", index);
	log_print!("   📊 Vote: {}", if aye { "AYE ✅".bright_green() } else { "NAY ❌".bright_red() });
	log_print!("   💰 Amount: {}", amount.bright_cyan());
	log_print!("   🔒 Conviction: {}", conviction);
	log_print!("   🔑 Signed by: {}", from.bright_yellow());

	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Parse amount
	let amount_value: u128 = (amount
		.parse::<f64>()
		.map_err(|_| QuantusError::Generic("Invalid amount format".to_string()))?
		.max(0.0) *
		1_000_000_000_000_000_000.0) as u128;

	// Validate conviction
	if conviction > 6 {
		return Err(QuantusError::Generic("Invalid conviction (must be 0-6)".to_string()));
	}

	// Build vote
	let vote =
		quantus_subxt::api::runtime_types::pallet_conviction_voting::vote::AccountVote::Standard {
			vote: quantus_subxt::api::runtime_types::pallet_conviction_voting::vote::Vote(
				if aye { 128 } else { 0 } | conviction,
			),
			balance: amount_value,
		};

	let vote_call = quantus_subxt::api::tx().conviction_voting().vote(index, vote);
	let tx_hash = submit_transaction(quantus_client, &keypair, vote_call, None, finalized).await?;

	log_print!(
		"✅ {} Vote transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("🎉 {} Vote submitted!", "FINISHED".bright_green().bold());
	Ok(())
}

/// Get Referenda configuration
async fn get_config(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("⚙️  Referenda Configuration");
	log_print!("");

	let constants = quantus_client.client().constants();
	let tracks_addr = quantus_subxt::api::constants().referenda().tracks();

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

/// Refund submission deposit for a completed Referendum
async fn refund_submission_deposit(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("💰 Refunding submission deposit for Referendum #{}", index);
	log_print!("   🔑 Refund to: {}", from.bright_yellow());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create refund_submission_deposit call
	let refund_call = quantus_subxt::api::tx().referenda().refund_submission_deposit(index);

	let tx_hash =
		submit_transaction(quantus_client, &keypair, refund_call, None, finalized).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_print!("💡 Check your balance to confirm the refund");
	Ok(())
}

/// Refund decision deposit for a completed Referendum
async fn refund_decision_deposit(
	quantus_client: &crate::chain::client::QuantusClient,
	index: u32,
	from: &str,
	password: Option<String>,
	password_file: Option<String>,
	finalized: bool,
) -> crate::error::Result<()> {
	log_print!("💰 Refunding decision deposit for Referendum #{}", index);
	log_print!("   🔑 Refund to: {}", from.bright_yellow());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

	// Create refund_decision_deposit call
	let refund_call = quantus_subxt::api::tx().referenda().refund_decision_deposit(index);

	let tx_hash =
		submit_transaction(quantus_client, &keypair, refund_call, None, finalized).await?;
	log_print!(
		"✅ {} Refund transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_print!("💡 Check your balance to confirm the refund");
	Ok(())
}
