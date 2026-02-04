use crate::{
	chain::quantus_subxt::{self},
	cli::common::ExecutionMode,
	log_error, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use hex;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

// Base unit (QUAN) decimals for amount conversions
const QUAN_DECIMALS: u128 = 1_000_000_000_000; // 10^12

// ============================================================================
// PUBLIC LIBRARY API - Data Structures
// ============================================================================

/// Multisig account information
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MultisigInfo {
	/// Multisig address (SS58 format)
	pub address: String,
	/// Current balance (spendable)
	pub balance: u128,
	/// Approval threshold
	pub threshold: u32,
	/// List of signer addresses (SS58 format)
	pub signers: Vec<String>,
	/// Next proposal ID
	pub proposal_nonce: u32,
	/// Locked deposit amount
	pub deposit: u128,
	/// Number of active proposals
	pub active_proposals: u32,
}

/// Proposal status
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ProposalStatus {
	Active,
	Executed,
	Cancelled,
}

/// Proposal information
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProposalInfo {
	/// Proposal ID
	pub id: u32,
	/// Proposer address (SS58 format)
	pub proposer: String,
	/// Encoded call data
	pub call_data: Vec<u8>,
	/// Expiry block number
	pub expiry: u32,
	/// List of approver addresses (SS58 format)
	pub approvals: Vec<String>,
	/// Locked deposit amount
	pub deposit: u128,
	/// Proposal status
	pub status: ProposalStatus,
}

// ============================================================================
// PUBLIC LIBRARY API - Helper Functions
// ============================================================================

/// Parse amount from human-readable format (e.g., "10", "10.5", "0.001")
/// or raw format (e.g., "10000000000000")
pub fn parse_amount(amount: &str) -> crate::error::Result<u128> {
	// If contains decimal point, parse as float and multiply by QUAN_DECIMALS
	if amount.contains('.') {
		let amount_f64: f64 = amount
			.parse()
			.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid amount: {}", e)))?;

		if amount_f64 < 0.0 {
			return Err(crate::error::QuantusError::Generic(
				"Amount cannot be negative".to_string(),
			));
		}

		// Multiply by decimals and convert to u128
		let base_amount = (amount_f64 * QUAN_DECIMALS as f64) as u128;
		Ok(base_amount)
	} else {
		// Try parsing as u128 first (raw format)
		if let Ok(raw) = amount.parse::<u128>() {
			// If the number is very large (>= 10^10), assume it's already in base units
			if raw >= 10_000_000_000 {
				Ok(raw)
			} else {
				// Otherwise assume it's in QUAN and convert
				Ok(raw * QUAN_DECIMALS)
			}
		} else {
			Err(crate::error::QuantusError::Generic(format!("Invalid amount: {}", amount)))
		}
	}
}

/// Subcommands for proposing transactions
#[derive(Subcommand, Debug)]
pub enum ProposeSubcommand {
	/// Propose a simple transfer (most common case)
	Transfer {
		/// Multisig account address (SS58 format)
		#[arg(long)]
		address: String,

		/// Recipient address (SS58 format)
		#[arg(long)]
		to: String,

		/// Amount to transfer (e.g., "10", "10.5", or raw "10000000000000")
		#[arg(long)]
		amount: String,

		/// Expiry block number (when this proposal expires)
		#[arg(long)]
		expiry: u32,

		/// Proposer wallet name (must be a signer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Propose a custom transaction (full flexibility)
	Custom {
		/// Multisig account address (SS58 format)
		#[arg(long)]
		address: String,

		/// Pallet name for the call (e.g., "Balances")
		#[arg(long)]
		pallet: String,

		/// Call/function name (e.g., "transfer_allow_death")
		#[arg(long)]
		call: String,

		/// Arguments as JSON array (e.g., '["5GrwvaEF...", "1000000000000"]')
		#[arg(long)]
		args: Option<String>,

		/// Expiry block number (when this proposal expires)
		#[arg(long)]
		expiry: u32,

		/// Proposer wallet name (must be a signer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Propose to enable high-security for this multisig
	HighSecurity {
		/// Multisig account address (SS58 format)
		#[arg(long)]
		address: String,

		/// Guardian/Interceptor account (SS58 or wallet name)
		#[arg(long)]
		interceptor: String,

		/// Delay in blocks (mutually exclusive with --delay-seconds)
		#[arg(long, conflicts_with = "delay_seconds")]
		delay_blocks: Option<u32>,

		/// Delay in seconds (mutually exclusive with --delay-blocks)
		#[arg(long, conflicts_with = "delay_blocks")]
		delay_seconds: Option<u64>,

		/// Expiry block number (when this proposal expires)
		#[arg(long)]
		expiry: u32,

		/// Proposer wallet name (must be a signer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Multisig-related commands
#[derive(Subcommand, Debug)]
pub enum MultisigCommands {
	/// Create a new multisig account
	Create {
		/// List of signer addresses (SS58 or wallet names), comma-separated
		#[arg(long)]
		signers: String,

		/// Number of approvals required to execute transactions
		#[arg(long)]
		threshold: u32,

		/// Nonce for deterministic address generation (allows creating multiple multisigs with
		/// same signers)
		#[arg(long, default_value = "0")]
		nonce: u64,

		/// Wallet name to pay for multisig creation
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Predict multisig address without creating it (deterministic calculation)
	PredictAddress {
		/// List of signer addresses (SS58 or wallet names), comma-separated
		#[arg(long)]
		signers: String,

		/// Number of approvals required to execute transactions
		#[arg(long)]
		threshold: u32,

		/// Nonce for deterministic address generation
		#[arg(long, default_value = "0")]
		nonce: u64,
	},

	/// Propose a transaction to be executed by the multisig
	#[command(subcommand)]
	Propose(ProposeSubcommand),

	/// Approve a proposed transaction
	Approve {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Proposal ID (u32 nonce)
		#[arg(long)]
		proposal_id: u32,

		/// Approver wallet name (must be a signer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Cancel a proposed transaction (only by proposer)
	Cancel {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Proposal ID (u32 nonce) to cancel
		#[arg(long)]
		proposal_id: u32,

		/// Wallet name (must be the proposer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Remove an expired proposal
	RemoveExpired {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Proposal ID (u32 nonce) to remove
		#[arg(long)]
		proposal_id: u32,

		/// Wallet name (must be a signer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Claim all deposits from removable proposals (batch operation)
	ClaimDeposits {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Wallet name (must be the proposer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Dissolve a multisig and recover the creation deposit
	Dissolve {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Wallet name (must be creator or a signer)
		#[arg(long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Query multisig information (or specific proposal if --proposal-id provided)
	Info {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Optional: Query specific proposal by ID
		#[arg(long)]
		proposal_id: Option<u32>,
	},

	/// List all proposals for a multisig
	ListProposals {
		/// Multisig account address
		#[arg(long)]
		address: String,
	},

	/// High-Security operations for multisig accounts
	#[command(subcommand)]
	HighSecurity(HighSecuritySubcommands),
}

/// High-Security subcommands for multisig (query only)
#[derive(Subcommand, Debug)]
pub enum HighSecuritySubcommands {
	/// Check if multisig has high-security enabled
	Status {
		/// Multisig account address
		#[arg(long)]
		address: String,
	},
}

// ============================================================================
// PUBLIC LIBRARY API - Core Functions
// ============================================================================
// Note: These functions are public library API and may not be used by the CLI binary

/// Predict multisig address deterministically
///
/// This function calculates what the multisig address will be BEFORE creating it.
/// The address is computed as: hash(pallet_id || sorted_signers || threshold || nonce)
///
/// # Arguments
/// * `signers` - List of signer AccountId32 (order doesn't matter - will be sorted)
/// * `threshold` - Number of approvals required
/// * `nonce` - Nonce for uniqueness (allows multiple multisigs with same signers)
///
/// # Returns
/// Predicted multisig address in SS58 format
#[allow(dead_code)]
pub fn predict_multisig_address(
	signers: Vec<subxt::ext::subxt_core::utils::AccountId32>,
	threshold: u32,
	nonce: u64,
) -> String {
	use codec::Encode;

	// Pallet ID from runtime: py/mltsg
	const PALLET_ID: [u8; 8] = *b"py/mltsg";

	// Convert subxt AccountId32 to sp_core AccountId32 for consistent encoding
	use sp_core::crypto::AccountId32 as SpAccountId32;
	let sp_signers: Vec<SpAccountId32> = signers
		.iter()
		.map(|s| {
			let bytes: [u8; 32] = *s.as_ref();
			SpAccountId32::from(bytes)
		})
		.collect();

	// Sort signers for deterministic address (same as runtime does)
	let mut sorted_signers = sp_signers;
	sorted_signers.sort();

	// Build data to hash: pallet_id || sorted_signers || threshold || nonce
	// IMPORTANT: Must match runtime encoding exactly
	let mut data = Vec::new();
	data.extend_from_slice(&PALLET_ID);
	// Encode Vec<sp_core::AccountId32> - same as runtime!
	data.extend_from_slice(&sorted_signers.encode());
	data.extend_from_slice(&threshold.encode());
	data.extend_from_slice(&nonce.encode());

	// Hash the data and map it deterministically into an AccountId
	// CRITICAL: Use PoseidonHasher (same as runtime!) and TrailingZeroInput
	use codec::Decode;
	use qp_poseidon::PoseidonHasher;
	use sp_core::crypto::AccountId32;
	use sp_runtime::traits::{Hash as HashT, TrailingZeroInput};

	let hash = PoseidonHasher::hash(&data);
	let account_id = AccountId32::decode(&mut TrailingZeroInput::new(hash.as_ref()))
		.expect("TrailingZeroInput provides sufficient bytes; qed");

	// Convert to SS58 format (network 189 for Quantus)
	account_id.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189))
}

/// Create a multisig account
///
/// # Arguments
/// * `quantus_client` - Connected Quantus client
/// * `creator_keypair` - Keypair of the account creating the multisig
/// * `signers` - List of signer addresses (AccountId32)
/// * `threshold` - Number of approvals required
/// * `nonce` - Nonce for deterministic address (allows multiple multisigs with same signers)
/// * `wait_for_inclusion` - Whether to wait for transaction inclusion
///
/// # Returns
/// Transaction hash and optionally the multisig address (if wait_for_inclusion=true)
#[allow(dead_code)]
pub async fn create_multisig(
	quantus_client: &crate::chain::client::QuantusClient,
	creator_keypair: &crate::wallet::QuantumKeyPair,
	signers: Vec<subxt::ext::subxt_core::utils::AccountId32>,
	threshold: u32,
	nonce: u64,
	wait_for_inclusion: bool,
) -> crate::error::Result<(subxt::utils::H256, Option<String>)> {
	// Build transaction with nonce
	let create_tx =
		quantus_subxt::api::tx()
			.multisig()
			.create_multisig(signers.clone(), threshold, nonce);

	// Submit transaction
	let execution_mode =
		ExecutionMode { finalized: false, wait_for_transaction: wait_for_inclusion };
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		creator_keypair,
		create_tx,
		None,
		execution_mode,
	)
	.await?;

	// If waiting, extract address from events
	let multisig_address = if wait_for_inclusion {
		let latest_block_hash = quantus_client.get_latest_block().await?;
		let events = quantus_client.client().events().at(latest_block_hash).await?;

		let mut multisig_events =
			events.find::<quantus_subxt::api::multisig::events::MultisigCreated>();

		let address: Option<String> = if let Some(Ok(ev)) = multisig_events.next() {
			let addr_bytes: &[u8; 32] = ev.multisig_address.as_ref();
			let addr = SpAccountId32::from(*addr_bytes);
			Some(addr.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189)))
		} else {
			None
		};
		address
	} else {
		None
	};

	Ok((tx_hash, multisig_address))
}

/// Propose a transfer from multisig
///
/// # Returns
/// Transaction hash
#[allow(dead_code)]
pub async fn propose_transfer(
	quantus_client: &crate::chain::client::QuantusClient,
	proposer_keypair: &crate::wallet::QuantumKeyPair,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
	to_address: subxt::ext::subxt_core::utils::AccountId32,
	amount: u128,
	expiry: u32,
) -> crate::error::Result<subxt::utils::H256> {
	use codec::{Compact, Encode};

	// Build Balances::transfer_allow_death call
	let pallet_index = 5u8; // Balances pallet
	let call_index = 0u8; // transfer_allow_death

	let mut call_data = Vec::new();
	call_data.push(pallet_index);
	call_data.push(call_index);

	// Encode destination (MultiAddress::Id)
	call_data.push(0u8); // MultiAddress::Id variant
	call_data.extend_from_slice(to_address.as_ref());

	// Encode amount (Compact<u128>)
	Compact(amount).encode_to(&mut call_data);

	// Build propose transaction
	let propose_tx =
		quantus_subxt::api::tx().multisig().propose(multisig_address, call_data, expiry);

	// Submit transaction
	let execution_mode = ExecutionMode { finalized: false, wait_for_transaction: false };
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		proposer_keypair,
		propose_tx,
		None,
		execution_mode,
	)
	.await?;

	Ok(tx_hash)
}

/// Propose a custom call from multisig
///
/// # Returns
/// Transaction hash
#[allow(dead_code)]
pub async fn propose_custom(
	quantus_client: &crate::chain::client::QuantusClient,
	proposer_keypair: &crate::wallet::QuantumKeyPair,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
	call_data: Vec<u8>,
	expiry: u32,
) -> crate::error::Result<subxt::utils::H256> {
	// Build propose transaction
	let propose_tx =
		quantus_subxt::api::tx().multisig().propose(multisig_address, call_data, expiry);

	// Submit transaction
	let execution_mode = ExecutionMode { finalized: false, wait_for_transaction: false };
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		proposer_keypair,
		propose_tx,
		None,
		execution_mode,
	)
	.await?;

	Ok(tx_hash)
}

/// Approve a proposal
///
/// # Returns
/// Transaction hash
#[allow(dead_code)]
pub async fn approve_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	approver_keypair: &crate::wallet::QuantumKeyPair,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
	proposal_id: u32,
) -> crate::error::Result<subxt::utils::H256> {
	let approve_tx = quantus_subxt::api::tx().multisig().approve(multisig_address, proposal_id);

	let execution_mode = ExecutionMode { finalized: false, wait_for_transaction: false };
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		approver_keypair,
		approve_tx,
		None,
		execution_mode,
	)
	.await?;

	Ok(tx_hash)
}

/// Cancel a proposal (only by proposer)
///
/// # Returns
/// Transaction hash
#[allow(dead_code)]
pub async fn cancel_proposal(
	quantus_client: &crate::chain::client::QuantusClient,
	proposer_keypair: &crate::wallet::QuantumKeyPair,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
	proposal_id: u32,
) -> crate::error::Result<subxt::utils::H256> {
	let cancel_tx = quantus_subxt::api::tx().multisig().cancel(multisig_address, proposal_id);

	let execution_mode = ExecutionMode { finalized: false, wait_for_transaction: false };
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		proposer_keypair,
		cancel_tx,
		None,
		execution_mode,
	)
	.await?;

	Ok(tx_hash)
}

/// Get multisig information
///
/// # Returns
/// Multisig information or None if not found
#[allow(dead_code)]
pub async fn get_multisig_info(
	quantus_client: &crate::chain::client::QuantusClient,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
) -> crate::error::Result<Option<MultisigInfo>> {
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	// Query multisig data
	let storage_query =
		quantus_subxt::api::storage().multisig().multisigs(multisig_address.clone());
	let multisig_data = storage_at.fetch(&storage_query).await?;

	if let Some(data) = multisig_data {
		// Query balance
		let balance_query =
			quantus_subxt::api::storage().system().account(multisig_address.clone());
		let account_info = storage_at.fetch(&balance_query).await?;
		let balance = account_info.map(|info| info.data.free).unwrap_or(0);

		// Convert to SS58
		let multisig_bytes: &[u8; 32] = multisig_address.as_ref();
		let multisig_sp = SpAccountId32::from(*multisig_bytes);
		let address =
			multisig_sp.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));

		let signers: Vec<String> = data
			.signers
			.0
			.iter()
			.map(|signer| {
				let signer_bytes: &[u8; 32] = signer.as_ref();
				let signer_sp = SpAccountId32::from(*signer_bytes);
				signer_sp.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189))
			})
			.collect();

		Ok(Some(MultisigInfo {
			address,
			balance,
			threshold: data.threshold,
			signers,
			proposal_nonce: data.proposal_nonce,
			deposit: data.deposit,
			active_proposals: data.active_proposals,
		}))
	} else {
		Ok(None)
	}
}

/// Get proposal information
///
/// # Returns
/// Proposal information or None if not found
#[allow(dead_code)]
pub async fn get_proposal_info(
	quantus_client: &crate::chain::client::QuantusClient,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
	proposal_id: u32,
) -> crate::error::Result<Option<ProposalInfo>> {
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let storage_query = quantus_subxt::api::storage()
		.multisig()
		.proposals(multisig_address, proposal_id);

	let proposal_data = storage_at.fetch(&storage_query).await?;

	if let Some(data) = proposal_data {
		let proposer_bytes: &[u8; 32] = data.proposer.as_ref();
		let proposer_sp = SpAccountId32::from(*proposer_bytes);
		let proposer =
			proposer_sp.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));

		let approvals: Vec<String> = data
			.approvals
			.0
			.iter()
			.map(|approver| {
				let approver_bytes: &[u8; 32] = approver.as_ref();
				let approver_sp = SpAccountId32::from(*approver_bytes);
				approver_sp
					.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189))
			})
			.collect();

		let status = match data.status {
			quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Active =>
				ProposalStatus::Active,
			quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Executed =>
				ProposalStatus::Executed,
			quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Cancelled =>
				ProposalStatus::Cancelled,
		};

		Ok(Some(ProposalInfo {
			id: proposal_id,
			proposer,
			call_data: data.call.0,
			expiry: data.expiry,
			approvals,
			deposit: data.deposit,
			status,
		}))
	} else {
		Ok(None)
	}
}

/// List all proposals for a multisig
///
/// # Returns
/// List of proposals
#[allow(dead_code)]
pub async fn list_proposals(
	quantus_client: &crate::chain::client::QuantusClient,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
) -> crate::error::Result<Vec<ProposalInfo>> {
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage = quantus_client.client().storage().at(latest_block_hash);

	let address = quantus_subxt::api::storage()
		.multisig()
		.proposals_iter1(multisig_address.clone());
	let mut proposals_iter = storage.iter(address).await?;

	let mut proposals = Vec::new();

	while let Some(result) = proposals_iter.next().await {
		if let Ok(kv) = result {
			// Extract proposal_id from key
			let key_bytes = kv.key_bytes;
			if key_bytes.len() >= 4 {
				let id_bytes = &key_bytes[key_bytes.len() - 4..];
				let proposal_id =
					u32::from_le_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]);

				// Use value directly from iterator (more efficient)
				let data = kv.value;

				let proposer_bytes: &[u8; 32] = data.proposer.as_ref();
				let proposer_sp = SpAccountId32::from(*proposer_bytes);
				let proposer = proposer_sp
					.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));

				let approvals: Vec<String> = data
					.approvals
					.0
					.iter()
					.map(|approver| {
						let approver_bytes: &[u8; 32] = approver.as_ref();
						let approver_sp = SpAccountId32::from(*approver_bytes);
						approver_sp.to_ss58check_with_version(
							sp_core::crypto::Ss58AddressFormat::custom(189),
						)
					})
					.collect();

				let status = match data.status {
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Active =>
						ProposalStatus::Active,
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Executed =>
						ProposalStatus::Executed,
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Cancelled =>
						ProposalStatus::Cancelled,
				};

				proposals.push(ProposalInfo {
					id: proposal_id,
					proposer,
					call_data: data.call.0,
					expiry: data.expiry,
					approvals,
					deposit: data.deposit,
					status,
				});
			}
		}
	}

	Ok(proposals)
}

/// Approve dissolving a multisig
///
/// Requires threshold approvals. When threshold is reached, multisig is dissolved.
/// Requirements:
/// - No proposals exist (active, executed, or cancelled)
/// - Multisig account balance must be zero
/// - Deposit is burned (not returned)
///
/// # Returns
/// Transaction hash
#[allow(dead_code)]
pub async fn approve_dissolve_multisig(
	quantus_client: &crate::chain::client::QuantusClient,
	caller_keypair: &crate::wallet::QuantumKeyPair,
	multisig_address: subxt::ext::subxt_core::utils::AccountId32,
) -> crate::error::Result<subxt::utils::H256> {
	let approve_tx = quantus_subxt::api::tx().multisig().approve_dissolve(multisig_address);

	let execution_mode = ExecutionMode { finalized: false, wait_for_transaction: false };
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		caller_keypair,
		approve_tx,
		None,
		execution_mode,
	)
	.await?;

	Ok(tx_hash)
}

// ============================================================================
// CLI HANDLERS (Internal)
// ============================================================================

/// Handle multisig command
pub async fn handle_multisig_command(
	command: MultisigCommands,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	match command {
		MultisigCommands::Create { signers, threshold, nonce, from, password, password_file } =>
			handle_create_multisig(
				signers,
				threshold,
				nonce,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
		MultisigCommands::PredictAddress { signers, threshold, nonce } =>
			handle_predict_address(signers, threshold, nonce).await,
		MultisigCommands::Propose(subcommand) => match subcommand {
			ProposeSubcommand::Transfer {
				address,
				to,
				amount,
				expiry,
				from,
				password,
				password_file,
			} =>
				handle_propose_transfer(
					address,
					to,
					amount,
					expiry,
					from,
					password,
					password_file,
					node_url,
					execution_mode,
				)
				.await,
			ProposeSubcommand::Custom {
				address,
				pallet,
				call,
				args,
				expiry,
				from,
				password,
				password_file,
			} =>
				handle_propose(
					address,
					pallet,
					call,
					args,
					expiry,
					from,
					password,
					password_file,
					node_url,
					execution_mode,
				)
				.await,
			ProposeSubcommand::HighSecurity {
				address,
				interceptor,
				delay_blocks,
				delay_seconds,
				expiry,
				from,
				password,
				password_file,
			} =>
				handle_high_security_set(
					address,
					interceptor,
					delay_blocks,
					delay_seconds,
					expiry,
					from,
					password,
					password_file,
					node_url,
					execution_mode,
				)
				.await,
		},
		MultisigCommands::Approve { address, proposal_id, from, password, password_file } =>
			handle_approve(
				address,
				proposal_id,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
		MultisigCommands::Cancel { address, proposal_id, from, password, password_file } =>
			handle_cancel(
				address,
				proposal_id,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
		MultisigCommands::RemoveExpired { address, proposal_id, from, password, password_file } =>
			handle_remove_expired(
				address,
				proposal_id,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
		MultisigCommands::ClaimDeposits { address, from, password, password_file } =>
			handle_claim_deposits(address, from, password, password_file, node_url, execution_mode)
				.await,
		MultisigCommands::Dissolve { address, from, password, password_file } =>
			handle_dissolve(address, from, password, password_file, node_url, execution_mode).await,
		MultisigCommands::Info { address, proposal_id } =>
			handle_info(address, proposal_id, node_url).await,
		MultisigCommands::ListProposals { address } =>
			handle_list_proposals(address, node_url).await,
		MultisigCommands::HighSecurity(subcommand) => match subcommand {
			HighSecuritySubcommands::Status { address } =>
				handle_high_security_status(address, node_url).await,
		},
	}
}

/// Create a new multisig account
async fn handle_create_multisig(
	signers: String,
	threshold: u32,
	nonce: u64,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🔐 {} Creating multisig...", "MULTISIG".bright_magenta().bold());

	// Parse signers - convert to AccountId32
	let signer_addresses: Vec<subxt::ext::subxt_core::utils::AccountId32> = signers
		.split(',')
		.map(|s| s.trim())
		.map(|addr| {
			// Resolve wallet name or SS58 address to SS58 string
			let ss58_str = crate::cli::common::resolve_address(addr)?;
			// Convert SS58 to AccountId32
			let (account_id, _) =
				SpAccountId32::from_ss58check_with_version(&ss58_str).map_err(|e| {
					crate::error::QuantusError::Generic(format!(
						"Invalid address '{}': {:?}",
						addr, e
					))
				})?;
			// Convert to subxt AccountId32
			let bytes: [u8; 32] = *account_id.as_ref();
			Ok(subxt::ext::subxt_core::utils::AccountId32::from(bytes))
		})
		.collect::<Result<Vec<_>, crate::error::QuantusError>>()?;

	log_verbose!("Signers: {} addresses", signer_addresses.len());
	log_verbose!("Threshold: {}", threshold);
	log_verbose!("Nonce: {}", nonce);

	// Validate inputs
	if signer_addresses.is_empty() {
		log_error!("❌ At least one signer is required");
		return Err(crate::error::QuantusError::Generic("No signers provided".to_string()));
	}

	if threshold == 0 {
		log_error!("❌ Threshold must be greater than zero");
		return Err(crate::error::QuantusError::Generic("Invalid threshold".to_string()));
	}

	if threshold > signer_addresses.len() as u32 {
		log_error!("❌ Threshold cannot exceed number of signers");
		return Err(crate::error::QuantusError::Generic("Threshold too high".to_string()));
	}

	// Calculate predicted address BEFORE submission (deterministic)
	let predicted_address = predict_multisig_address(signer_addresses.clone(), threshold, nonce);

	log_print!("");
	log_print!("📍 {} Predicted multisig address:", "DETERMINISTIC".bright_green().bold());
	log_print!("   {}", predicted_address.bright_cyan().bold());
	log_print!("");

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction with nonce
	let create_tx = quantus_subxt::api::tx().multisig().create_multisig(
		signer_addresses.clone(),
		threshold,
		nonce,
	);

	// Always wait for transaction to confirm creation
	let create_execution_mode = ExecutionMode {
		finalized: execution_mode.finalized,
		wait_for_transaction: true, // Always wait to confirm address
	};

	let _tx_hash = crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		create_tx,
		None,
		create_execution_mode,
	)
	.await?;

	log_success!("✅ Multisig creation transaction confirmed");

	// Extract and verify address from events
	{
		log_print!("");
		log_print!("🔍 Looking for MultisigCreated event...");

		// Query latest block events
		let latest_block_hash = quantus_client.get_latest_block().await?;
		let events = quantus_client.client().events().at(latest_block_hash).await?;

		// Find MultisigCreated event
		let multisig_events =
			events.find::<quantus_subxt::api::multisig::events::MultisigCreated>();

		let mut actual_address: Option<String> = None;
		for event_result in multisig_events {
			match event_result {
				Ok(ev) => {
					let addr_bytes: &[u8; 32] = ev.multisig_address.as_ref();
					let addr = SpAccountId32::from(*addr_bytes);
					actual_address = Some(addr.to_ss58check_with_version(
						sp_core::crypto::Ss58AddressFormat::custom(189),
					));
					log_verbose!("Found MultisigCreated event");
					break;
				},
				Err(e) => {
					log_verbose!("Error parsing event: {:?}", e);
				},
			}
		}

		if let Some(address) = actual_address {
			log_print!("");

			// Verify address matches prediction
			if address == predicted_address {
				log_success!("✅ Confirmed multisig address: {}", address.bright_cyan().bold());
				log_print!("   {} Matches predicted address!", "✓".bright_green().bold());
			} else {
				log_error!("⚠️  Address mismatch!");
				log_print!("   Expected: {}", predicted_address.bright_yellow());
				log_print!("   Got:      {}", address.bright_red());
				log_print!("   This should never happen with deterministic addresses!");
			}

			log_print!("");
			log_print!(
				"💡 {} You can now use this address to propose transactions",
				"TIP".bright_blue().bold()
			);
			log_print!(
				"   Example: quantus multisig propose transfer --address {} --to recipient --amount 100",
				address.bright_cyan()
			);
		} else {
			log_error!("⚠️  Couldn't find MultisigCreated event");
			log_print!("   Check events manually: quantus events --latest --pallet Multisig");
		}
	}

	log_print!("");

	Ok(())
}

/// Predict multisig address without creating it
async fn handle_predict_address(
	signers: String,
	threshold: u32,
	nonce: u64,
) -> crate::error::Result<()> {
	log_print!("🔮 {} Predicting multisig address...", "PREDICT".bright_cyan().bold());
	log_print!("");

	// Parse signers - convert to AccountId32
	let signer_addresses: Vec<subxt::ext::subxt_core::utils::AccountId32> = signers
		.split(',')
		.map(|s| s.trim())
		.map(|addr| {
			// Resolve wallet name or SS58 address to SS58 string
			let ss58_str = crate::cli::common::resolve_address(addr)?;
			// Convert SS58 to AccountId32
			let (account_id, _) =
				SpAccountId32::from_ss58check_with_version(&ss58_str).map_err(|e| {
					crate::error::QuantusError::Generic(format!(
						"Invalid address '{}': {:?}",
						addr, e
					))
				})?;
			// Convert to subxt AccountId32
			let bytes: [u8; 32] = *account_id.as_ref();
			Ok(subxt::ext::subxt_core::utils::AccountId32::from(bytes))
		})
		.collect::<Result<Vec<_>, crate::error::QuantusError>>()?;

	// Validate inputs
	if signer_addresses.is_empty() {
		log_error!("❌ At least one signer is required");
		return Err(crate::error::QuantusError::Generic("No signers provided".to_string()));
	}

	if threshold == 0 {
		log_error!("❌ Threshold must be greater than zero");
		return Err(crate::error::QuantusError::Generic("Invalid threshold".to_string()));
	}

	if threshold > signer_addresses.len() as u32 {
		log_error!("❌ Threshold cannot exceed number of signers");
		return Err(crate::error::QuantusError::Generic("Threshold too high".to_string()));
	}

	// Calculate deterministic address
	let predicted_address = predict_multisig_address(signer_addresses.clone(), threshold, nonce);

	log_print!("📍 {} Predicted multisig address:", "RESULT".bright_green().bold());
	log_print!("   {}", predicted_address.bright_cyan().bold());
	log_print!("");
	log_print!("⚙️  {} Configuration:", "PARAMS".bright_blue().bold());
	log_print!("   Signers: {}", signer_addresses.len());
	log_print!("   Threshold: {}", threshold);
	log_print!("   Nonce: {}", nonce);
	log_print!("");
	log_print!("💡 {} This address is deterministic:", "INFO".bright_yellow().bold());
	log_print!("   - Same signers + threshold + nonce = same address");
	log_print!("   - Order of signers doesn't matter (automatically sorted)");
	log_print!("   - Use different nonce to create multiple multisigs with same signers");
	log_print!("");
	log_print!("🚀 {} To create this multisig, run:", "NEXT".bright_magenta().bold());
	log_print!(
		"   quantus multisig create --signers \"{}\" --threshold {} --nonce {} --from <wallet>",
		signers,
		threshold,
		nonce
	);
	log_print!("");

	Ok(())
}

/// Propose a transaction
/// Propose a transfer transaction (simplified interface)
async fn handle_propose_transfer(
	multisig_address: String,
	to: String,
	amount: String,
	expiry: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("📝 {} Creating transfer proposal...", "MULTISIG".bright_magenta().bold());

	// Resolve recipient address (wallet name or SS58)
	let to_address = crate::cli::common::resolve_address(&to)?;

	// Parse amount (supports both human format "10" and raw "10000000000000")
	let amount_u128: u128 = parse_amount(&amount)?;

	// Build args as JSON array (using serde_json for proper escaping)
	let args_json = serde_json::to_string(&vec![
		serde_json::Value::String(to_address),
		serde_json::Value::String(amount_u128.to_string()),
	])
	.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to serialize args: {}", e)))?;

	// Use the existing handle_propose with Balances::transfer_allow_death
	handle_propose(
		multisig_address,
		"Balances".to_string(),
		"transfer_allow_death".to_string(),
		Some(args_json),
		expiry,
		from,
		password,
		password_file,
		node_url,
		execution_mode,
	)
	.await
}

/// Propose a custom transaction
async fn handle_propose(
	multisig_address: String,
	pallet: String,
	call: String,
	args: Option<String>,
	expiry: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("📝 {} Creating proposal...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Parse arguments
	let args_vec: Vec<serde_json::Value> = if let Some(args_str) = args {
		serde_json::from_str(&args_str).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid JSON for arguments: {}", e))
		})?
	} else {
		vec![]
	};

	log_verbose!("Multisig: {}", multisig_ss58);
	log_verbose!("Call: {}::{}", pallet, call);
	log_verbose!("Expiry: block {}", expiry);

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Validate expiry is in the future (client-side check)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let latest_block = quantus_client.client().blocks().at(latest_block_hash).await?;
	let current_block_number = latest_block.number();

	if expiry <= current_block_number {
		log_error!(
			"❌ Expiry block {} is in the past (current block: {})",
			expiry,
			current_block_number
		);
		log_print!("   Use a higher block number, e.g., --expiry {}", current_block_number + 1000);
		return Err(crate::error::QuantusError::Generic("Expiry must be in the future".to_string()));
	}

	log_verbose!("Current block: {}, expiry valid", current_block_number);

	// Validate proposer is a signer (client-side check before submitting)
	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let multisig_query =
		quantus_subxt::api::storage().multisig().multisigs(multisig_address.clone());
	let multisig_data = storage_at.fetch(&multisig_query).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"Multisig not found at address: {}",
			multisig_ss58
		))
	})?;

	// Resolve proposer address
	let proposer_ss58 = crate::cli::common::resolve_address(&from)?;
	let (proposer_id, _) =
		SpAccountId32::from_ss58check_with_version(&proposer_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid proposer address: {:?}", e))
		})?;
	let proposer_bytes: [u8; 32] = *proposer_id.as_ref();
	let proposer_account_id = subxt::ext::subxt_core::utils::AccountId32::from(proposer_bytes);

	// Check if proposer is in signers list
	if !multisig_data.signers.0.contains(&proposer_account_id) {
		log_error!("❌ Not authorized: {} is not a signer of this multisig", proposer_ss58);
		return Err(crate::error::QuantusError::Generic(
			"Only multisig signers can create proposals".to_string(),
		));
	}

	// Check for expired proposals from this proposer (will be auto-cleaned by runtime)
	let mut expired_count = 0;
	let proposals_query = quantus_subxt::api::storage().multisig().proposals_iter();
	let mut proposals_stream = storage_at.iter(proposals_query).await?;

	while let Some(Ok(kv)) = proposals_stream.next().await {
		let proposal = kv.value;
		// Check if this proposal belongs to our proposer
		if proposal.proposer == proposer_account_id {
			// Check if expired
			if proposal.expiry <= current_block_number {
				expired_count += 1;
			}
		}
	}

	if expired_count > 0 {
		log_print!("");
		log_print!(
			"🧹 {} Auto-cleanup: Runtime will remove your {} expired proposal(s)",
			"INFO".bright_blue().bold(),
			expired_count.to_string().bright_yellow()
		);
		log_print!("   This happens automatically before creating the new proposal");
		log_print!("");
	}

	// Build the call data using runtime metadata
	let call_data = build_runtime_call(&quantus_client, &pallet, &call, args_vec).await?;

	log_verbose!("Call data size: {} bytes", call_data.len());

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Build transaction
	let propose_tx =
		quantus_subxt::api::tx()
			.multisig()
			.propose(multisig_address.clone(), call_data, expiry);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		propose_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Proposal submitted");
	log_print!("");
	log_print!("💡 {} Check the events to find the proposal hash", "NOTE".bright_blue().bold());
	log_print!("");

	Ok(())
}

/// Approve a proposal
async fn handle_approve(
	multisig_address: String,
	proposal_id: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("✅ {} Approving proposal...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	log_verbose!("Multisig: {}", multisig_ss58);
	log_verbose!("Proposal ID: {}", proposal_id);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Validate approver is a signer (client-side check before submitting)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let multisig_query =
		quantus_subxt::api::storage().multisig().multisigs(multisig_address.clone());
	let multisig_data = storage_at.fetch(&multisig_query).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"Multisig not found at address: {}",
			multisig_ss58
		))
	})?;

	// Resolve approver address
	let approver_ss58 = crate::cli::common::resolve_address(&from)?;
	let (approver_id, _) =
		SpAccountId32::from_ss58check_with_version(&approver_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid approver address: {:?}", e))
		})?;
	let approver_bytes: [u8; 32] = *approver_id.as_ref();
	let approver_account_id = subxt::ext::subxt_core::utils::AccountId32::from(approver_bytes);

	// Check if approver is in signers list
	if !multisig_data.signers.0.contains(&approver_account_id) {
		log_error!("❌ Not authorized: {} is not a signer of this multisig", approver_ss58);
		return Err(crate::error::QuantusError::Generic(
			"Only multisig signers can approve proposals".to_string(),
		));
	}

	// Check if proposal exists
	let proposal_query = quantus_subxt::api::storage()
		.multisig()
		.proposals(multisig_address.clone(), proposal_id);
	let proposal_data = storage_at.fetch(&proposal_query).await?;
	if proposal_data.is_none() {
		log_error!("❌ Proposal {} not found", proposal_id);
		return Err(crate::error::QuantusError::Generic(format!(
			"Proposal {} does not exist",
			proposal_id
		)));
	}
	let proposal = proposal_data.unwrap();

	// Check if already approved by this signer
	if proposal.approvals.0.contains(&approver_account_id) {
		log_error!("❌ Already approved: you have already approved this proposal");
		return Err(crate::error::QuantusError::Generic(
			"You have already approved this proposal".to_string(),
		));
	}

	// Build transaction
	let approve_tx = quantus_subxt::api::tx().multisig().approve(multisig_address, proposal_id);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		approve_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Approval submitted");
	log_print!("   If threshold is reached, the proposal will execute automatically");

	Ok(())
}

/// Cancel a proposal
async fn handle_cancel(
	multisig_address: String,
	proposal_id: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🚫 {} Cancelling proposal...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	log_verbose!("Proposal ID: {}", proposal_id);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Validate caller is the proposer (client-side check before submitting)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let proposal_query = quantus_subxt::api::storage()
		.multisig()
		.proposals(multisig_address.clone(), proposal_id);
	let proposal_data = storage_at.fetch(&proposal_query).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic(format!("Proposal {} not found", proposal_id))
	})?;

	// Resolve canceller address
	let canceller_ss58 = crate::cli::common::resolve_address(&from)?;
	let (canceller_id, _) =
		SpAccountId32::from_ss58check_with_version(&canceller_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid canceller address: {:?}", e))
		})?;
	let canceller_bytes: [u8; 32] = *canceller_id.as_ref();
	let canceller_account_id = subxt::ext::subxt_core::utils::AccountId32::from(canceller_bytes);

	// Check if caller is the proposer
	if proposal_data.proposer != canceller_account_id {
		log_error!("❌ Not authorized: only the proposer can cancel this proposal");
		let proposer_bytes: &[u8; 32] = proposal_data.proposer.as_ref();
		let proposer_sp = SpAccountId32::from(*proposer_bytes);
		let proposer_ss58 =
			proposer_sp.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));
		log_print!("   Proposer: {}", proposer_ss58);
		return Err(crate::error::QuantusError::Generic(
			"Only the proposer can cancel their proposal".to_string(),
		));
	}

	// Build transaction
	let cancel_tx = quantus_subxt::api::tx().multisig().cancel(multisig_address, proposal_id);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		cancel_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Proposal cancelled and removed");
	log_print!("   Deposit returned to proposer");

	Ok(())
}

/// Remove an expired proposal
async fn handle_remove_expired(
	multisig_address: String,
	proposal_id: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🧹 {} Removing expired proposal...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	log_verbose!("Proposal ID: {}", proposal_id);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction
	let remove_tx = quantus_subxt::api::tx()
		.multisig()
		.remove_expired(multisig_address, proposal_id);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		remove_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Expired proposal removed and deposit returned");

	Ok(())
}

/// Claim all deposits (batch cleanup)
async fn handle_claim_deposits(
	multisig_address: String,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("💰 {} Claiming deposits...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction
	let claim_tx = quantus_subxt::api::tx().multisig().claim_deposits(multisig_address);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		claim_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Deposits claimed");
	log_print!("   All removable proposals have been cleaned up");

	Ok(())
}

/// Approve dissolving a multisig
async fn handle_dissolve(
	multisig_address: String,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🗑️  {} Approving multisig dissolution...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Get threshold for info message
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let multisig_query =
		quantus_subxt::api::storage().multisig().multisigs(multisig_address.clone());
	let multisig_info = storage_at.fetch(&multisig_query).await?;

	// Build transaction
	let approve_tx = quantus_subxt::api::tx().multisig().approve_dissolve(multisig_address);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		approve_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Dissolution approval submitted");

	if let Some(info) = multisig_info {
		log_print!("   Requires {} total approvals to dissolve", info.threshold);
		log_print!("");
		log_print!("⚠️  {} When threshold is reached:", "WARNING".bright_yellow().bold());
		log_print!("   - Multisig will be dissolved automatically");
		log_print!("   - Deposit will be BURNED (not returned)");
		log_print!("   - Storage will be removed");
	}

	Ok(())
}

/// Query multisig information (or specific proposal if proposal_id provided)
async fn handle_info(
	multisig_address: String,
	proposal_id: Option<u32>,
	node_url: &str,
) -> crate::error::Result<()> {
	// If proposal_id is provided, delegate to handle_proposal_info
	if let Some(id) = proposal_id {
		return handle_proposal_info(multisig_address, id, node_url).await;
	}

	log_print!("🔍 {} Querying multisig info...", "MULTISIG".bright_magenta().bold());
	log_print!("");

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Query storage using direct fetch with explicit block hash
	crate::log_verbose!("🔍 Querying multisig with address: {}", multisig_ss58);
	crate::log_verbose!("🔍 Address bytes: {}", hex::encode(multisig_bytes));

	// Get latest block hash explicitly
	let latest_block_hash = quantus_client.get_latest_block().await?;
	crate::log_verbose!("📦 Latest block hash: {:?}", latest_block_hash);

	let storage_query =
		quantus_subxt::api::storage().multisig().multisigs(multisig_address.clone());

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let multisig_data = storage_at.fetch(&storage_query).await?;

	crate::log_verbose!(
		"🔍 Fetch result: {}",
		if multisig_data.is_some() { "Found" } else { "Not found" }
	);

	match multisig_data {
		Some(data) => {
			// Query balance for multisig address
			let balance_query =
				quantus_subxt::api::storage().system().account(multisig_address.clone());
			let account_info = storage_at.fetch(&balance_query).await?;
			let balance = account_info.map(|info| info.data.free).unwrap_or(0);

			log_print!("📋 {} Information:", "MULTISIG".bright_green().bold());
			log_print!("   Address: {}", multisig_ss58.bright_cyan());
			log_print!("   Balance: {}", format_balance(balance).bright_green().bold());
			log_print!("   Threshold: {}", data.threshold.to_string().bright_yellow());
			log_print!("   Signers ({}):", data.signers.0.len().to_string().bright_yellow());
			for (i, signer) in data.signers.0.iter().enumerate() {
				// Convert subxt AccountId32 to SS58
				let signer_bytes: &[u8; 32] = signer.as_ref();
				let signer_sp = SpAccountId32::from(*signer_bytes);
				log_print!("     {}. {}", i + 1, signer_sp.to_ss58check().bright_cyan());
			}
			log_print!("   Proposal Nonce: {}", data.proposal_nonce);
			log_print!("   Deposit: {} (locked until dissolution)", format_balance(data.deposit));
			log_print!(
				"   Active Proposals: {}",
				data.active_proposals.to_string().bright_yellow()
			);

			// Check for dissolution progress
			let dissolve_query = quantus_subxt::api::storage()
				.multisig()
				.dissolve_approvals(multisig_address.clone());
			if let Some(dissolve_approvals) = storage_at.fetch(&dissolve_query).await? {
				log_print!("");
				log_print!("🗑️  {} Dissolution in progress:", "DISSOLVE".bright_red().bold());
				log_print!(
					"   Progress: {}/{}",
					dissolve_approvals.0.len().to_string().bright_yellow(),
					data.threshold.to_string().bright_yellow()
				);
				log_print!("   Approvals:");
				for (i, approver) in dissolve_approvals.0.iter().enumerate() {
					let approver_bytes: &[u8; 32] = approver.as_ref();
					let approver_sp = SpAccountId32::from(*approver_bytes);
					log_print!("     {}. {}", i + 1, approver_sp.to_ss58check().bright_cyan());
				}

				// Show pending approvals
				let pending_signers: Vec<_> =
					data.signers.0.iter().filter(|s| !dissolve_approvals.0.contains(s)).collect();

				if !pending_signers.is_empty() {
					log_print!("   Pending:");
					for (i, signer) in pending_signers.iter().enumerate() {
						let signer_bytes: &[u8; 32] = signer.as_ref();
						let signer_sp = SpAccountId32::from(*signer_bytes);
						log_print!("     {}. {}", i + 1, signer_sp.to_ss58check().dimmed());
					}
				}

				log_print!("");
				log_print!("   ⚠️  {} When threshold is reached:", "WARNING".bright_red().bold());
				log_print!("      - Multisig will be dissolved IMMEDIATELY");
				log_print!("      - All proposals will be cancelled");
				log_print!("      - Deposit will be BURNED (not returned)");
			} else {
				log_print!("");
				log_print!(
					"   ⚠️  {} Deposit will be BURNED (not returned) when dissolved",
					"NOTE".bright_yellow().bold()
				);
			}
		},
		None => {
			log_error!("❌ Multisig not found at address: {}", multisig_ss58);
		},
	}

	log_print!("");
	Ok(())
}

/// Decode call data into human-readable format
async fn decode_call_data(
	quantus_client: &crate::chain::client::QuantusClient,
	call_data: &[u8],
) -> crate::error::Result<String> {
	use codec::Decode;

	if call_data.len() < 2 {
		return Ok(format!("   {}  {} bytes (too short)", "Call Size:".dimmed(), call_data.len()));
	}

	let pallet_index = call_data[0];
	let call_index = call_data[1];
	let args = &call_data[2..];

	// Get metadata to find pallet and call names
	let metadata = quantus_client.client().metadata();

	// Try to find pallet by index
	let pallet_name = metadata
		.pallets()
		.find(|p| p.index() == pallet_index)
		.map(|p| p.name())
		.unwrap_or("Unknown");

	// Try to decode based on known patterns
	match (pallet_index, call_index) {
		// Balances pallet transfers
		// transfer_allow_death (0) or transfer_keep_alive (3)
		(_, idx) if pallet_name == "Balances" && (idx == 0 || idx == 3) => {
			let call_name = match idx {
				0 => "transfer_allow_death",
				3 => "transfer_keep_alive",
				_ => unreachable!(),
			};

			if args.len() < 33 {
				return Ok(format!(
					"   {}  {}::{} (index {})\n   {}  {} bytes (too short)",
					"Call:".dimmed(),
					pallet_name.bright_cyan(),
					call_name.bright_yellow(),
					idx,
					"Args:".dimmed(),
					args.len()
				));
			}

			// Decode MultiAddress::Id (first byte is variant, 0x00 = Id)
			// Then 32 bytes for AccountId32
			let address_variant = args[0];
			if address_variant != 0 {
				return Ok(format!(
					"   {}  {}::{} (index {})\n   {}  {} bytes\n   {}  Unknown address variant: {}",
					"Call:".dimmed(),
					pallet_name.bright_cyan(),
					call_name.bright_yellow(),
					idx,
					"Args:".dimmed(),
					args.len(),
					"Error:".dimmed(),
					address_variant
				));
			}

			let account_bytes: [u8; 32] = args[1..33].try_into().map_err(|_| {
				crate::error::QuantusError::Generic("Failed to extract account bytes".to_string())
			})?;
			let account_id = SpAccountId32::from(account_bytes);
			let to_address = account_id.to_ss58check();

			// Decode amount (Compact<u128>)
			let mut cursor = &args[33..];
			let amount: u128 = match codec::Compact::<u128>::decode(&mut cursor) {
				Ok(compact) => compact.0,
				Err(_) => {
					return Ok(format!(
						"   {}  {}::{} (index {})\n   {}  {}\n   {}  Failed to decode amount",
						"Call:".dimmed(),
						pallet_name.bright_cyan(),
						call_name.bright_yellow(),
						idx,
						"To:".dimmed(),
						to_address.bright_cyan(),
						"Error:".dimmed()
					));
				},
			};

			Ok(format!(
				"   {}  {}::{}\n   {}  {}\n   {}  {}",
				"Call:".dimmed(),
				pallet_name.bright_cyan(),
				call_name.bright_yellow(),
				"To:".dimmed(),
				to_address.bright_cyan(),
				"Amount:".dimmed(),
				format_balance(amount).bright_green()
			))
		},
		// ReversibleTransfers::set_high_security
		(_, idx) if pallet_name == "ReversibleTransfers" && idx == 0 => {
			// set_high_security has: delay (enum), interceptor (AccountId32)
			if args.is_empty() {
				return Ok(format!(
					"   {}  {}::set_high_security\n   {}  {} bytes (too short)",
					"Call:".dimmed(),
					pallet_name.bright_cyan(),
					"Args:".dimmed(),
					args.len()
				));
			}

			// Decode delay (BlockNumberOrTimestamp enum)
			let delay_variant = args[0];
			let delay_str: String;
			let offset: usize;

			match delay_variant {
				0 => {
					// BlockNumber(u32)
					if args.len() < 5 {
						return Ok(format!(
							"   {}  {}::set_high_security\n   {}  Failed to decode delay (BlockNumber)",
							"Call:".dimmed(),
							pallet_name.bright_cyan(),
							"Error:".dimmed()
						));
					}
					let blocks = u32::from_le_bytes([args[1], args[2], args[3], args[4]]);
					delay_str = format!("{} blocks", blocks);
					offset = 5;
				},
				1 => {
					// Timestamp(u64)
					if args.len() < 9 {
						return Ok(format!(
							"   {}  {}::set_high_security\n   {}  Failed to decode delay (Timestamp)",
							"Call:".dimmed(),
							pallet_name.bright_cyan(),
							"Error:".dimmed()
						));
					}
					let millis = u64::from_le_bytes([
						args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8],
					]);
					let seconds = millis / 1000;
					delay_str = format!("{} seconds ({} ms)", seconds, millis);
					offset = 9;
				},
				_ => {
					return Ok(format!(
						"   {}  {}::set_high_security\n   {}  Unknown delay variant: {}",
						"Call:".dimmed(),
						pallet_name.bright_cyan(),
						"Error:".dimmed(),
						delay_variant
					));
				},
			}

			// Decode interceptor (AccountId32)
			if args.len() < offset + 32 {
				return Ok(format!(
					"   {}  {}::set_high_security\n   {}  {}\n   {}  Failed to decode interceptor",
					"Call:".dimmed(),
					pallet_name.bright_cyan(),
					"Delay:".dimmed(),
					delay_str.bright_yellow(),
					"Error:".dimmed()
				));
			}

			let interceptor_bytes: [u8; 32] =
				args[offset..offset + 32].try_into().map_err(|_| {
					crate::error::QuantusError::Generic(
						"Failed to extract interceptor bytes".to_string(),
					)
				})?;
			let interceptor = SpAccountId32::from(interceptor_bytes);
			let interceptor_ss58 = interceptor
				.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));

			Ok(format!(
				"   {}  {}::set_high_security\n   {}  {}\n   {}  {}",
				"Call:".dimmed(),
				pallet_name.bright_cyan(),
				"Delay:".dimmed(),
				delay_str.bright_yellow(),
				"Guardian:".dimmed(),
				interceptor_ss58.bright_green()
			))
		},
		_ => {
			// Try to get call name from metadata
			let call_name = metadata
				.pallets()
				.find(|p| p.index() == pallet_index)
				.and_then(|p| {
					p.call_variants().and_then(|calls| {
						calls.iter().find(|v| v.index == call_index).map(|v| v.name.as_str())
					})
				})
				.unwrap_or("unknown");

			Ok(format!(
				"   {}  {}::{} (index {}:{})\n   {}  {} bytes\n   {}  {}",
				"Call:".dimmed(),
				pallet_name.bright_cyan(),
				call_name.bright_yellow(),
				pallet_index,
				call_index,
				"Args:".dimmed(),
				args.len(),
				"Raw:".dimmed(),
				hex::encode(args).bright_green()
			))
		},
	}
}

/// Query proposal information
async fn handle_proposal_info(
	multisig_address: String,
	proposal_id: u32,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("🔍 {} Querying proposal info...", "MULTISIG".bright_magenta().bold());
	log_print!("");

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Get latest block hash explicitly
	let latest_block_hash = quantus_client.get_latest_block().await?;

	// Get current block number
	let latest_block = quantus_client.client().blocks().at(latest_block_hash).await?;
	let current_block_number = latest_block.number();

	// Query storage by proposal ID
	let storage_query = quantus_subxt::api::storage()
		.multisig()
		.proposals(multisig_address.clone(), proposal_id);

	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let proposal_data = storage_at.fetch(&storage_query).await?;

	match proposal_data {
		Some(data) => {
			// Get multisig info for context
			let multisig_query =
				quantus_subxt::api::storage().multisig().multisigs(multisig_address.clone());
			let multisig_info = storage_at.fetch(&multisig_query).await?;

			log_print!("📝 {} Information:", "PROPOSAL".bright_green().bold());
			log_print!(
				"   Current Block: {}",
				current_block_number.to_string().bright_white().bold()
			);
			log_print!("   Multisig: {}", multisig_ss58.bright_cyan());

			// Show threshold and approval progress
			if let Some(ref ms_data) = multisig_info {
				let progress = format!("{}/{}", data.approvals.0.len(), ms_data.threshold);
				log_print!(
					"   Threshold: {} (progress: {})",
					ms_data.threshold.to_string().bright_yellow(),
					progress.bright_cyan()
				);
			}

			log_print!("   Proposal ID: {}", proposal_id.to_string().bright_yellow());
			// Convert proposer to SS58
			let proposer_bytes: &[u8; 32] = data.proposer.as_ref();
			let proposer_sp = SpAccountId32::from(*proposer_bytes);
			log_print!("   Proposer: {}", proposer_sp.to_ss58check().bright_cyan());

			// Decode and display call data
			log_print!("");
			match decode_call_data(&quantus_client, &data.call.0).await {
				Ok(decoded) => {
					log_print!("{}", decoded);
				},
				Err(e) => {
					log_print!("   Call Size: {} bytes", data.call.0.len());
					log_verbose!("Failed to decode call data: {:?}", e);
				},
			}
			log_print!("");

			// Calculate blocks remaining until expiry
			if data.expiry > current_block_number {
				let blocks_remaining = data.expiry - current_block_number;
				log_print!(
					"   Expiry: block {} ({} blocks remaining)",
					data.expiry,
					blocks_remaining.to_string().bright_green()
				);
			} else {
				log_print!("   Expiry: block {} ({})", data.expiry, "EXPIRED".bright_red().bold());
			}
			log_print!("   Deposit: {} (locked)", format_balance(data.deposit));
			log_print!(
				"   Status: {}",
				match data.status {
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Active =>
						"Active".bright_green(),
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Executed =>
						"Executed".bright_blue(),
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Cancelled =>
						"Cancelled".bright_red(),
				}
			);
			log_print!("   Approvals ({}):", data.approvals.0.len().to_string().bright_yellow());
			for (i, approver) in data.approvals.0.iter().enumerate() {
				// Convert approver to SS58
				let approver_bytes: &[u8; 32] = approver.as_ref();
				let approver_sp = SpAccountId32::from(*approver_bytes);
				log_print!("     {}. {}", i + 1, approver_sp.to_ss58check().bright_cyan());
			}

			// Show which signers haven't approved yet
			if let Some(ms_data) = multisig_info {
				let pending_signers: Vec<String> = ms_data
					.signers
					.0
					.iter()
					.filter(|s| !data.approvals.0.contains(s))
					.map(|s| {
						let bytes: &[u8; 32] = s.as_ref();
						let sp = SpAccountId32::from(*bytes);
						sp.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(
							189,
						))
					})
					.collect();

				if !pending_signers.is_empty() {
					log_print!("");
					log_print!(
						"   Pending Approvals ({}):",
						pending_signers.len().to_string().bright_red()
					);
					for (i, signer) in pending_signers.iter().enumerate() {
						log_print!("     {}. {}", i + 1, signer.bright_red());
					}
				}
			}
		},
		None => {
			log_error!("❌ Proposal not found");
		},
	}

	log_print!("");
	Ok(())
}

/// List all proposals for a multisig
async fn handle_list_proposals(
	multisig_address: String,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("📋 {} Listing proposals...", "MULTISIG".bright_magenta().bold());
	log_print!("");

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Get latest block hash explicitly
	let latest_block_hash = quantus_client.get_latest_block().await?;

	// Query all proposals for this multisig using prefix iteration
	let storage = quantus_client.client().storage().at(latest_block_hash);

	// Use iter_key_values to iterate over the double map
	let address = quantus_subxt::api::storage().multisig().proposals_iter1(multisig_address);
	let mut proposals = storage.iter(address).await?;

	let mut count = 0;
	let mut active_count = 0;
	let mut executed_count = 0;
	let mut cancelled_count = 0;

	while let Some(result) = proposals.next().await {
		match result {
			Ok(kv) => {
				count += 1;

				let status_str = match kv.value.status {
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Active => {
						active_count += 1;
						"Active".bright_green()
					},
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Executed => {
						executed_count += 1;
						"Executed".bright_blue()
					},
					quantus_subxt::api::runtime_types::pallet_multisig::ProposalStatus::Cancelled => {
						cancelled_count += 1;
						"Cancelled".bright_red()
					},
				};

				// Extract proposal ID from key_bytes (u32, 4 bytes with Twox64Concat hasher)
				// The key_bytes contains:
				// [storage_prefix][Blake2_128Concat(multisig)][Twox64Concat(u32)] Twox64Concat
				// encoding: [8-byte hash][4-byte value] We need the last 4 bytes as
				// little-endian u32
				let key_bytes = kv.key_bytes;
				if key_bytes.len() >= 4 {
					let id_bytes = &key_bytes[key_bytes.len() - 4..];
					let proposal_id =
						u32::from_le_bytes([id_bytes[0], id_bytes[1], id_bytes[2], id_bytes[3]]);

					log_print!("📝 Proposal #{}", count);
					log_print!("   ID: {}", proposal_id.to_string().bright_yellow());

					// Convert proposer to SS58
					let proposer_bytes: &[u8; 32] = kv.value.proposer.as_ref();
					let proposer_sp = SpAccountId32::from(*proposer_bytes);
					log_print!("   Proposer: {}", proposer_sp.to_ss58check().bright_cyan());

					// Decode and display call data (compact format for list)
					match decode_call_data(&quantus_client, &kv.value.call.0).await {
						Ok(decoded) => {
							// Extract just the call info line for compact display
							let lines: Vec<&str> = decoded.lines().collect();
							if !lines.is_empty() {
								log_print!("   {}", lines[0].trim_start());
							}
						},
						Err(_) => {
							log_print!("   Call Size: {} bytes", kv.value.call.0.len());
						},
					}

					log_print!("   Status: {}", status_str);
					log_print!("   Approvals: {}", kv.value.approvals.0.len());
					log_print!("   Expiry: block {}", kv.value.expiry);
					log_print!("");
				}
			},
			Err(e) => {
				log_error!("Error reading proposal: {:?}", e);
			},
		}
	}

	if count == 0 {
		log_print!("   No proposals found for this multisig");
	} else {
		log_print!("📊 {} Summary:", "PROPOSALS".bright_green().bold());
		log_print!("   Total: {}", count.to_string().bright_yellow());
		log_print!("   Active: {}", active_count.to_string().bright_green());
		log_print!("   Executed: {}", executed_count.to_string().bright_blue());
		log_print!("   Cancelled: {}", cancelled_count.to_string().bright_red());
	}

	log_print!("");
	Ok(())
}

/// Build runtime call data from pallet, call name, and arguments
async fn build_runtime_call(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet: &str,
	call: &str,
	args: Vec<serde_json::Value>,
) -> crate::error::Result<Vec<u8>> {
	// Validate pallet/call exists in metadata
	let metadata = quantus_client.client().metadata();
	let pallet_metadata = metadata.pallet_by_name(pallet).ok_or_else(|| {
		crate::error::QuantusError::Generic(format!("Pallet '{}' not found in metadata", pallet))
	})?;

	log_verbose!("✅ Found pallet '{}' with index {}", pallet, pallet_metadata.index());

	// Find the call in the pallet
	let call_metadata = pallet_metadata.call_variant_by_name(call).ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"Call '{}' not found in pallet '{}'",
			call, pallet
		))
	})?;

	log_verbose!("✅ Found call '{}' with index {}", call, call_metadata.index);

	// For now, we'll construct a basic call using the generic approach
	// This is a simplified implementation - in production, you'd want to handle all argument types
	use codec::Encode;

	let mut call_data = Vec::new();
	// Pallet index
	call_data.push(pallet_metadata.index());
	// Call index
	call_data.push(call_metadata.index);

	// Encode arguments based on call type
	// This is a simplified version - in production you'd need proper argument encoding
	match (pallet, call) {
		("Balances", "transfer_allow_death") | ("Balances", "transfer_keep_alive") => {
			if args.len() != 2 {
				return Err(crate::error::QuantusError::Generic(
					"Balances transfer requires 2 arguments: [to_address, amount]".to_string(),
				));
			}

			let to_address = args[0].as_str().ok_or_else(|| {
				crate::error::QuantusError::Generic(
					"First argument must be a string (to_address)".to_string(),
				)
			})?;

			// Parse amount - can be either string or number in JSON
			let amount: u128 = if let Some(amount_str) = args[1].as_str() {
				// If it's a string, parse it
				amount_str.parse().map_err(|_| {
					crate::error::QuantusError::Generic(
						"Second argument must be a valid number (amount)".to_string(),
					)
				})?
			} else if let Some(amount_num) = args[1].as_u64() {
				// If it's a number, use it directly
				amount_num as u128
			} else {
				// Try as_i64 for negative numbers (though we'll reject them)
				return Err(crate::error::QuantusError::Generic(
					"Second argument must be a number (amount)".to_string(),
				));
			};

			// Convert to AccountId32
			let (to_account_id, _) = SpAccountId32::from_ss58check_with_version(to_address)
				.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Invalid to_address: {:?}", e))
				})?;

			// Convert to subxt AccountId32
			let to_account_id_bytes: [u8; 32] = *to_account_id.as_ref();
			let to_account_id_subxt =
				subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

			// Encode as MultiAddress::Id
			let multi_address: subxt::ext::subxt_core::utils::MultiAddress<
				subxt::ext::subxt_core::utils::AccountId32,
				(),
			> = subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt);

			multi_address.encode_to(&mut call_data);
			// Amount must be Compact encoded for Balance type
			codec::Compact(amount).encode_to(&mut call_data);
		},
		("System", "remark") | ("System", "remark_with_event") => {
			// System::remark takes a Vec<u8> argument
			if args.len() != 1 {
				return Err(crate::error::QuantusError::Generic(
					"System remark requires 1 argument: [hex_data]".to_string(),
				));
			}

			let hex_data = args[0].as_str().ok_or_else(|| {
				crate::error::QuantusError::Generic(
					"Argument must be a hex string (e.g., \"0x48656c6c6f\")".to_string(),
				)
			})?;

			// Remove 0x prefix if present
			let hex_str = hex_data.trim_start_matches("0x");

			// Decode hex to bytes
			let data_bytes = hex::decode(hex_str).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid hex data: {}", e))
			})?;

			// Encode as Vec<u8> (with length prefix)
			data_bytes.encode_to(&mut call_data);
		},
		_ => {
			return Err(crate::error::QuantusError::Generic(format!(
			"Building call data for {}.{} is not yet implemented. Use a simpler approach or add support.",
			pallet, call
		)));
		},
	}

	Ok(call_data)
}

/// Format balance for display
fn format_balance(balance: u128) -> String {
	let quan = balance / QUAN_DECIMALS;
	let remainder = balance % QUAN_DECIMALS;

	if remainder == 0 {
		format!("{} QUAN", quan)
	} else {
		// Show up to 12 decimal places, removing trailing zeros
		let decimal_str = format!("{:012}", remainder).trim_end_matches('0').to_string();
		format!("{}.{} QUAN", quan, decimal_str)
	}
}

// ============================================================================
// HIGH SECURITY HANDLERS
// ============================================================================

/// Check high-security status for a multisig
async fn handle_high_security_status(
	multisig_address: String,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("🔍 {} Checking High-Security status...", "MULTISIG".bright_magenta().bold());
	log_print!("");

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_account_id = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Query high-security status
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let storage_query = quantus_subxt::api::storage()
		.reversible_transfers()
		.high_security_accounts(multisig_account_id);

	let high_security_data = storage_at.fetch(&storage_query).await?;

	log_print!("📋 Multisig: {}", multisig_ss58.bright_cyan());
	log_print!("");

	match high_security_data {
		Some(data) => {
			log_success!("✅ High-Security: {}", "ENABLED".bright_green().bold());
			log_print!("");

			// Convert interceptor to SS58
			let interceptor_bytes: &[u8; 32] = data.interceptor.as_ref();
			let interceptor_sp = SpAccountId32::from(*interceptor_bytes);
			let interceptor_ss58 = interceptor_sp
				.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));

			log_print!("🛡️  Guardian/Interceptor: {}", interceptor_ss58.bright_green().bold());

			// Format delay display
			match data.delay {
				quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp::BlockNumber(
					blocks,
				) => {
					log_print!("⏱️  Delay: {} blocks", blocks.to_string().bright_yellow());
				},
				quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp::Timestamp(
					ms,
				) => {
					let seconds = ms / 1000;
					log_print!("⏱️  Delay: {} seconds", seconds.to_string().bright_yellow());
				},
			}

			log_print!("");
			log_print!(
				"💡 {} All transfers from this multisig will be delayed and reversible",
				"INFO".bright_blue().bold()
			);
			log_print!("   The guardian can intercept transactions during the delay period");
			log_print!("");
			log_print!(
				"⚠️  {} Guardian interception requires direct runtime call (not yet in CLI)",
				"NOTE".bright_yellow().bold()
			);
			log_print!("   Use: pallet_reversible_transfers::cancel(tx_id) as guardian account");
		},
		None => {
			log_print!("❌ High-Security: {}", "DISABLED".bright_red().bold());
			log_print!("");
			log_print!("💡 This multisig does not have high-security enabled.");
			log_print!("   Use 'quantus multisig high-security set' to enable it via a proposal.");
		},
	}

	log_print!("");
	Ok(())
}

/// Enable high-security for a multisig (via proposal)
async fn handle_high_security_set(
	multisig_address: String,
	interceptor: String,
	delay_blocks: Option<u32>,
	delay_seconds: Option<u64>,
	expiry: u32,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!(
		"🛡️  {} Enabling High-Security (via proposal)...",
		"MULTISIG".bright_magenta().bold()
	);

	// Validate delay parameters
	if delay_blocks.is_none() && delay_seconds.is_none() {
		log_error!("❌ You must specify either --delay-blocks or --delay-seconds");
		return Err(crate::error::QuantusError::Generic("Missing delay parameter".to_string()));
	}

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_account_id = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);

	// Resolve interceptor address
	let interceptor_ss58 = crate::cli::common::resolve_address(&interceptor)?;
	let (interceptor_id, _) = SpAccountId32::from_ss58check_with_version(&interceptor_ss58)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid interceptor address: {:?}", e))
		})?;
	let interceptor_bytes: [u8; 32] = *interceptor_id.as_ref();
	let interceptor_account_id =
		subxt::ext::subxt_core::utils::AccountId32::from(interceptor_bytes);

	log_verbose!("Multisig: {}", multisig_ss58);
	log_verbose!("Interceptor: {}", interceptor_ss58);

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build the set_high_security call
	use quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay as HsDelay;

	let delay_value = if let Some(blocks) = delay_blocks {
		HsDelay::BlockNumber(blocks)
	} else if let Some(seconds) = delay_seconds {
		HsDelay::Timestamp(seconds * 1000) // Convert seconds to milliseconds
	} else {
		return Err(crate::error::QuantusError::Generic("Missing delay parameter".to_string()));
	};

	log_verbose!("Delay: {:?}", delay_value);

	// Build the runtime call
	let set_hs_call = quantus_subxt::api::tx()
		.reversible_transfers()
		.set_high_security(delay_value, interceptor_account_id);

	// Encode the call
	use subxt::tx::Payload;
	let call_data =
		set_hs_call.encode_call_data(&quantus_client.client().metadata()).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to encode call: {:?}", e))
		})?;

	log_verbose!("Call data size: {} bytes", call_data.len());

	// Validate expiry is in the future (client-side check)
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let latest_block = quantus_client.client().blocks().at(latest_block_hash).await?;
	let current_block_number = latest_block.number();

	if expiry <= current_block_number {
		log_error!(
			"❌ Expiry block {} is in the past (current block: {})",
			expiry,
			current_block_number
		);
		log_print!("   Use a higher block number, e.g., --expiry {}", current_block_number + 1000);
		return Err(crate::error::QuantusError::Generic("Expiry must be in the future".to_string()));
	}

	// Validate proposer is a signer
	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let multisig_query =
		quantus_subxt::api::storage().multisig().multisigs(multisig_account_id.clone());
	let multisig_data = storage_at.fetch(&multisig_query).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"Multisig not found at address: {}",
			multisig_ss58
		))
	})?;

	// Resolve proposer address
	let proposer_ss58 = crate::cli::common::resolve_address(&from)?;
	let (proposer_id, _) =
		SpAccountId32::from_ss58check_with_version(&proposer_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid proposer address: {:?}", e))
		})?;
	let proposer_bytes: [u8; 32] = *proposer_id.as_ref();
	let proposer_account_id = subxt::ext::subxt_core::utils::AccountId32::from(proposer_bytes);

	// Check if proposer is in signers list
	if !multisig_data.signers.0.contains(&proposer_account_id) {
		log_error!("❌ Not authorized: {} is not a signer of this multisig", proposer_ss58);
		return Err(crate::error::QuantusError::Generic(
			"Only multisig signers can create proposals".to_string(),
		));
	}

	// Check for expired proposals from this proposer (will be auto-cleaned by runtime)
	let mut expired_count = 0;
	let proposals_query = quantus_subxt::api::storage().multisig().proposals_iter();
	let mut proposals_stream = storage_at.iter(proposals_query).await?;

	while let Some(Ok(kv)) = proposals_stream.next().await {
		let proposal = kv.value;
		// Check if this proposal belongs to our proposer
		if proposal.proposer == proposer_account_id {
			// Check if expired
			if proposal.expiry <= current_block_number {
				expired_count += 1;
			}
		}
	}

	if expired_count > 0 {
		log_print!("");
		log_print!(
			"🧹 {} Auto-cleanup: Runtime will remove your {} expired proposal(s)",
			"INFO".bright_blue().bold(),
			expired_count.to_string().bright_yellow()
		);
		log_print!("   This happens automatically before creating the new proposal");
		log_print!("");
	}

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Build propose transaction
	let propose_tx =
		quantus_subxt::api::tx()
			.multisig()
			.propose(multisig_account_id, call_data, expiry);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		propose_tx,
		None,
		execution_mode,
	)
	.await?;

	log_print!("");
	log_success!("✅ High-Security proposal created!");
	log_print!("");
	log_print!(
		"💡 {} Once this proposal reaches threshold, High-Security will be enabled",
		"NEXT STEPS".bright_blue().bold()
	);
	log_print!(
		"   - Other signers need to approve: quantus multisig approve --address {} --proposal-id <ID> --from <SIGNER>",
		multisig_ss58.bright_cyan()
	);
	log_print!("   - After threshold is reached, all transfers will be delayed and reversible");
	log_print!("");

	Ok(())
}
