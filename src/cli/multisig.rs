use crate::{
	chain::quantus_subxt::{self},
	cli::common::ExecutionMode,
	log_error, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use hex;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};
use subxt::utils::H256;

// Base unit (QUAN) decimals for amount conversions
const QUAN_DECIMALS: u128 = 1_000_000_000_000; // 10^12

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

		/// Amount to transfer (in base units, e.g., 1000000000000 for 1 QUAN)
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

	/// Propose a transaction to be executed by the multisig
	#[command(subcommand)]
	Propose(ProposeSubcommand),

	/// Approve a proposed transaction
	Approve {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Proposal hash to approve
		#[arg(long)]
		proposal_hash: String,

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

		/// Proposal hash to cancel
		#[arg(long)]
		proposal_hash: String,

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

	/// Remove an expired/executed/cancelled proposal
	RemoveExpired {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Proposal hash to remove
		#[arg(long)]
		proposal_hash: String,

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

	/// Query multisig information
	Info {
		/// Multisig account address
		#[arg(long)]
		address: String,
	},

	/// Query proposal information
	ProposalInfo {
		/// Multisig account address
		#[arg(long)]
		address: String,

		/// Proposal hash
		#[arg(long)]
		proposal_hash: String,
	},

	/// List all proposals for a multisig
	ListProposals {
		/// Multisig account address
		#[arg(long)]
		address: String,
	},
}

/// Handle multisig command
pub async fn handle_multisig_command(
	command: MultisigCommands,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	match command {
		MultisigCommands::Create { signers, threshold, from, password, password_file } =>
			handle_create_multisig(
				signers,
				threshold,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
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
		},
		MultisigCommands::Approve { address, proposal_hash, from, password, password_file } =>
			handle_approve(
				address,
				proposal_hash,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
		MultisigCommands::Cancel { address, proposal_hash, from, password, password_file } =>
			handle_cancel(
				address,
				proposal_hash,
				from,
				password,
				password_file,
				node_url,
				execution_mode,
			)
			.await,
		MultisigCommands::RemoveExpired {
			address,
			proposal_hash,
			from,
			password,
			password_file,
		} =>
			handle_remove_expired(
				address,
				proposal_hash,
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
		MultisigCommands::Info { address } => handle_info(address, node_url).await,
		MultisigCommands::ProposalInfo { address, proposal_hash } =>
			handle_proposal_info(address, proposal_hash, node_url).await,
		MultisigCommands::ListProposals { address } =>
			handle_list_proposals(address, node_url).await,
	}
}

/// Create a new multisig account
async fn handle_create_multisig(
	signers: String,
	threshold: u32,
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

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction
	let create_tx = quantus_subxt::api::tx()
		.multisig()
		.create_multisig(signer_addresses.clone(), threshold);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		create_tx,
		None, // no tip
		execution_mode,
	)
	.await?;

	log_success!("✅ Multisig creation transaction submitted");
	log_print!("");
	log_print!(
		"💡 {} The multisig address will be generated deterministically",
		"NOTE".bright_blue().bold()
	);
	log_print!("   Check the events to find the multisig address");
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

	// Parse amount
	let amount_u128: u128 = amount
		.parse()
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid amount: {}", e)))?;

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

	// Build the call data using runtime metadata
	let call_data = build_runtime_call(&quantus_client, &pallet, &call, args_vec).await?;

	log_verbose!("Call data size: {} bytes", call_data.len());

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Build transaction
	let propose_tx =
		quantus_subxt::api::tx().multisig().propose(multisig_address, call_data, expiry);

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
	proposal_hash: String,
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
	let hash = parse_hash(&proposal_hash)?;

	log_verbose!("Multisig: {}", multisig_ss58);
	log_verbose!("Proposal hash: {}", proposal_hash);

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction
	let approve_tx = quantus_subxt::api::tx().multisig().approve(multisig_address, hash);

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
	proposal_hash: String,
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
	let hash = parse_hash(&proposal_hash)?;

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction
	let cancel_tx = quantus_subxt::api::tx().multisig().cancel(multisig_address, hash);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		cancel_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Proposal cancelled");
	log_print!("   Use remove-expired to cleanup and recover deposit");

	Ok(())
}

/// Remove an expired/executed/cancelled proposal
async fn handle_remove_expired(
	multisig_address: String,
	proposal_hash: String,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🧹 {} Removing proposal...", "MULTISIG".bright_magenta().bold());

	// Resolve multisig address
	let multisig_ss58 = crate::cli::common::resolve_address(&multisig_address)?;
	let (multisig_id, _) =
		SpAccountId32::from_ss58check_with_version(&multisig_ss58).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid multisig address: {:?}", e))
		})?;
	let multisig_bytes: [u8; 32] = *multisig_id.as_ref();
	let multisig_address = subxt::ext::subxt_core::utils::AccountId32::from(multisig_bytes);
	let hash = parse_hash(&proposal_hash)?;

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Build transaction
	let remove_tx = quantus_subxt::api::tx().multisig().remove_expired(multisig_address, hash);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		remove_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Proposal removed and deposit returned");

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

/// Dissolve a multisig
async fn handle_dissolve(
	multisig_address: String,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
	execution_mode: ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🗑️  {} Dissolving multisig...", "MULTISIG".bright_magenta().bold());

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
	let dissolve_tx = quantus_subxt::api::tx().multisig().dissolve_multisig(multisig_address);

	// Submit transaction
	crate::cli::common::submit_transaction(
		&quantus_client,
		&keypair,
		dissolve_tx,
		None,
		execution_mode,
	)
	.await?;

	log_success!("✅ Multisig dissolved and deposit returned");

	Ok(())
}

/// Query multisig information
async fn handle_info(multisig_address: String, node_url: &str) -> crate::error::Result<()> {
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
			log_print!("📋 {} Information:", "MULTISIG".bright_green().bold());
			log_print!("   Address: {}", multisig_ss58.bright_cyan());
			log_print!("   Threshold: {}", data.threshold.to_string().bright_yellow());
			log_print!("   Signers ({}):", data.signers.0.len().to_string().bright_yellow());
			for (i, signer) in data.signers.0.iter().enumerate() {
				// Convert subxt AccountId32 to SS58
				let signer_bytes: &[u8; 32] = signer.as_ref();
				let signer_sp = SpAccountId32::from(*signer_bytes);
				log_print!("     {}. {}", i + 1, signer_sp.to_ss58check().bright_cyan());
			}
			log_print!("   Nonce: {}", data.nonce);
			log_print!("   Proposal Nonce: {}", data.proposal_nonce);
			// Convert creator to SS58
			let creator_bytes: &[u8; 32] = data.creator.as_ref();
			let creator_sp = SpAccountId32::from(*creator_bytes);
			log_print!("   Creator: {}", creator_sp.to_ss58check().bright_cyan());
			log_print!("   Deposit: {} (locked)", format_balance(data.deposit));
			log_print!("   Last Activity: block {}", data.last_activity);
			log_print!(
				"   Active Proposals: {}",
				data.active_proposals.to_string().bright_yellow()
			);
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
		// Balances pallet - typically index 10 or similar
		(_, idx) if pallet_name == "Balances" && (idx == 0 || idx == 1) => {
			// transfer_allow_death (0) or transfer_keep_alive (1)
			if args.len() < 33 {
				return Ok(format!(
					"   {}  {}::{} (index {})\n   {}  {} bytes (too short)",
					"Call:".dimmed(),
					pallet_name.bright_cyan(),
					if idx == 0 { "transfer_allow_death" } else { "transfer_keep_alive" }
						.bright_yellow(),
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
					if idx == 0 { "transfer_allow_death" } else { "transfer_keep_alive" }
						.bright_yellow(),
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
						if idx == 0 { "transfer_allow_death" } else { "transfer_keep_alive" }
							.bright_yellow(),
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
				if idx == 0 { "transfer_allow_death" } else { "transfer_keep_alive" }
					.bright_yellow(),
				"To:".dimmed(),
				to_address.bright_cyan(),
				"Amount:".dimmed(),
				format_balance(amount).bright_green()
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
	proposal_hash: String,
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
	let hash = parse_hash(&proposal_hash)?;

	// Connect to chain
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	// Get latest block hash explicitly
	let latest_block_hash = quantus_client.get_latest_block().await?;

	// Query storage
	let storage_query = quantus_subxt::api::storage()
		.multisig()
		.proposals(multisig_address.clone(), hash);

	let storage_at = quantus_client.client().storage().at(latest_block_hash);
	let proposal_data = storage_at.fetch(&storage_query).await?;

	match proposal_data {
		Some(data) => {
			log_print!("📝 {} Information:", "PROPOSAL".bright_green().bold());
			log_print!("   Multisig: {}", multisig_ss58.bright_cyan());
			log_print!("   Proposal Hash: {}", proposal_hash.bright_yellow());
			// Convert proposer to SS58
			let proposer_bytes: &[u8; 32] = data.proposer.as_ref();
			let proposer_sp = SpAccountId32::from(*proposer_bytes);
			log_print!("   Proposer: {}", proposer_sp.to_ss58check().bright_cyan());

			// Decode and display call data
			match decode_call_data(&quantus_client, &data.call.0).await {
				Ok(decoded) => {
					log_print!("{}", decoded);
				},
				Err(e) => {
					log_print!("   Call Size: {} bytes", data.call.0.len());
					log_verbose!("Failed to decode call data: {:?}", e);
				},
			}

			log_print!("   Expiry: block {}", data.expiry);
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

				// Extract hash from key_bytes - it's the second key in the double map
				// Skip the storage prefix and first key (multisig address), get the hash (32 bytes)
				let key_bytes = kv.key_bytes;
				// The key_bytes contains: [storage_prefix][multisig_address(32)][hash(32)]
				// We need to extract just the hash part
				if key_bytes.len() >= 32 {
					let hash_bytes = &key_bytes[key_bytes.len() - 32..];

					log_print!("📝 Proposal #{}", count);
					log_print!(
						"   Hash: {}",
						format!("0x{}", hex::encode(hash_bytes)).bright_yellow()
					);
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

/// Parse a hex hash string into H256
fn parse_hash(hash_str: &str) -> crate::error::Result<H256> {
	let hash_str = hash_str.trim_start_matches("0x");

	if hash_str.len() != 64 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Invalid hash length: expected 64 hex characters, got {}",
			hash_str.len()
		)));
	}

	let mut bytes = [0u8; 32];
	hex::decode_to_slice(hash_str, &mut bytes)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid hex hash: {}", e)))?;

	Ok(H256::from(bytes))
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
