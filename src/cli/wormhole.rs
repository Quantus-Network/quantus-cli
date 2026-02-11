use crate::{
	chain::{
		client::{ChainConfig, QuantusClient},
		quantus_subxt::{self as quantus_node, api::wormhole},
	},
	cli::common::{submit_transaction, ExecutionMode},
	cli::send::get_balance,
	log_error, log_print, log_success, log_verbose,
	wallet::{password, QuantumKeyPair, WalletManager},
};
use clap::Subcommand;
use indicatif::{ProgressBar, ProgressStyle};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_poseidon::PoseidonHasher;
use qp_rusty_crystals_hdwallet::{
	derive_wormhole_from_mnemonic, generate_mnemonic, SensitiveBytes32, WormholePair,
	QUANTUS_WORMHOLE_CHAIN_ID,
};
use qp_wormhole_circuit::{
	inputs::{
		AggregatedPublicCircuitInputs, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs,
	},
	nullifier::Nullifier,
};
use qp_wormhole_prover::WormholeProver;
use qp_zk_circuits_common::{
	circuit::{C, D, F},
	storage_proof::prepare_proof_for_circuit,
	utils::{BytesDigest, Digest},
};
use rand::RngCore;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	Hasher,
};
use std::path::Path;
use subxt::{
	backend::legacy::rpc_methods::ReadProof,
	blocks::Block,
	ext::{
		codec::Encode,
		jsonrpsee::{core::client::ClientT, rpc_params},
	},
	utils::{to_hex, AccountId32 as SubxtAccountId},
	OnlineClient,
};

/// Native asset id
pub const NATIVE_ASSET_ID: u32 = 0;

/// Scale down factor for quantizing amounts (10^10 to go from 12 to 2 decimal places)
pub const SCALE_DOWN_FACTOR: u128 = 10_000_000_000;

/// Volume fee rate in basis points (10 bps = 0.1%)
/// This must match the on-chain VolumeFeeRateBps configuration
pub const VOLUME_FEE_BPS: u32 = 10;

/// Compute output amount after fee deduction
/// output = input * (10000 - fee_bps) / 10000
pub fn compute_output_amount(input_amount: u32, fee_bps: u32) -> u32 {
	((input_amount as u64) * (10000 - fee_bps as u64) / 10000) as u32
}

/// Parse a hex-encoded secret string into a 32-byte array
pub fn parse_secret_hex(secret_hex: &str) -> Result<[u8; 32], String> {
	let secret_bytes = hex::decode(secret_hex.trim_start_matches("0x"))
		.map_err(|e| format!("Invalid secret hex: {}", e))?;

	if secret_bytes.len() != 32 {
		return Err(format!("Secret must be exactly 32 bytes, got {} bytes", secret_bytes.len()));
	}

	secret_bytes
		.try_into()
		.map_err(|_| "Failed to convert secret to 32-byte array".to_string())
}

/// Parse an exit account from either hex or SS58 format
pub fn parse_exit_account(exit_account_str: &str) -> Result<[u8; 32], String> {
	if let Some(hex_str) = exit_account_str.strip_prefix("0x") {
		let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid exit account hex: {}", e))?;

		if bytes.len() != 32 {
			return Err(format!("Exit account must be 32 bytes, got {} bytes", bytes.len()));
		}

		bytes.try_into().map_err(|_| "Failed to convert exit account".to_string())
	} else {
		// Try to parse as SS58
		let account_id = AccountId32::from_ss58check(exit_account_str)
			.map_err(|e| format!("Invalid SS58 address: {}", e))?;

		Ok(account_id.into())
	}
}

/// Quantize a funding amount from 12 decimal places to 2 decimal places
/// Returns an error if the quantized value doesn't fit in u32
pub fn quantize_funding_amount(amount: u128) -> Result<u32, String> {
	let quantized = amount / SCALE_DOWN_FACTOR;

	quantized
		.try_into()
		.map_err(|_| format!("Funding amount {} too large after quantization", quantized))
}

/// Read and decode a hex-encoded proof file
pub fn read_proof_file(path: &str) -> Result<Vec<u8>, String> {
	let proof_hex =
		std::fs::read_to_string(path).map_err(|e| format!("Failed to read proof file: {}", e))?;

	hex::decode(proof_hex.trim()).map_err(|e| format!("Failed to decode proof hex: {}", e))
}

/// Write a proof to a hex-encoded file
pub fn write_proof_file(path: &str, proof_bytes: &[u8]) -> Result<(), String> {
	let proof_hex = hex::encode(proof_bytes);
	std::fs::write(path, proof_hex).map_err(|e| format!("Failed to write proof file: {}", e))
}

/// Format a balance amount from raw units (12 decimals) to human-readable format
pub fn format_balance(amount: u128) -> String {
	let whole = amount / 1_000_000_000_000;
	let frac = (amount % 1_000_000_000_000) / 10_000_000_000; // 2 decimal places
	format!("{}.{:02} DEV", whole, frac)
}

/// Result of checking proof verification events
pub struct VerificationResult {
	pub success: bool,
	pub exit_amount: Option<u128>,
	pub error_message: Option<String>,
}

/// Check for proof verification events in a transaction
/// Returns whether ProofVerified event was found and the exit amount
async fn check_proof_verification_events(
	client: &subxt::OnlineClient<ChainConfig>,
	block_hash: &subxt::utils::H256,
	tx_hash: &subxt::utils::H256,
	verbose: bool,
) -> crate::error::Result<VerificationResult> {
	use crate::chain::quantus_subxt::api::system::events::ExtrinsicFailed;
	use colored::Colorize;

	let block = client.blocks().at(*block_hash).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get block: {e:?}"))
	})?;

	let extrinsics = block.extrinsics().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get extrinsics: {e:?}"))
	})?;

	// Find our extrinsic index
	let our_extrinsic_index = extrinsics
		.iter()
		.enumerate()
		.find(|(_, ext)| ext.hash() == *tx_hash)
		.map(|(idx, _)| idx);

	let events = block.events().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch events: {e:?}"))
	})?;

	let metadata = client.metadata();

	let mut verification_result =
		VerificationResult { success: false, exit_amount: None, error_message: None };

	if verbose {
		log_print!("");
		log_print!("📋 Transaction Events:");
	}

	if let Some(ext_idx) = our_extrinsic_index {
		for event_result in events.iter() {
			let event = event_result.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!("Failed to decode event: {e:?}"))
			})?;

			// Only process events for our extrinsic
			if let subxt::events::Phase::ApplyExtrinsic(event_ext_idx) = event.phase() {
				if event_ext_idx != ext_idx as u32 {
					continue;
				}

				// Display event in verbose mode
				if verbose {
					log_print!(
						"  📌 {}.{}",
						event.pallet_name().bright_cyan(),
						event.variant_name().bright_yellow()
					);

					// Try to decode and display event details
					if let Ok(typed_event) =
						event.as_root_event::<crate::chain::quantus_subxt::api::Event>()
					{
						log_print!("     📝 {:?}", typed_event);
					}
				}

				// Check for ProofVerified event
				if let Ok(Some(proof_verified)) =
					event.as_event::<wormhole::events::ProofVerified>()
				{
					verification_result.success = true;
					verification_result.exit_amount = Some(proof_verified.exit_amount);
				}

				// Check for ExtrinsicFailed event
				if let Ok(Some(ExtrinsicFailed { dispatch_error, .. })) =
					event.as_event::<ExtrinsicFailed>()
				{
					let error_msg = format_dispatch_error(&dispatch_error, &metadata);
					verification_result.success = false;
					verification_result.error_message = Some(error_msg);
				}
			}
		}
	}

	if verbose {
		log_print!("");
	}

	Ok(verification_result)
}

/// Format dispatch error for display
fn format_dispatch_error(
	error: &crate::chain::quantus_subxt::api::runtime_types::sp_runtime::DispatchError,
	metadata: &subxt::Metadata,
) -> String {
	use crate::chain::quantus_subxt::api::runtime_types::sp_runtime::DispatchError;

	match error {
		DispatchError::Module(module_error) => {
			let pallet_name = metadata
				.pallet_by_index(module_error.index)
				.map(|p| p.name())
				.unwrap_or("Unknown");
			let error_index = module_error.error[0];
			format!("{}::Error[{}]", pallet_name, error_index)
		},
		DispatchError::BadOrigin => "BadOrigin".to_string(),
		DispatchError::CannotLookup => "CannotLookup".to_string(),
		DispatchError::Other => "Other".to_string(),
		_ => format!("{:?}", error),
	}
}

/// Validate aggregation parameters
pub fn validate_aggregation_params(
	num_proofs: usize,
	depth: usize,
	branching_factor: usize,
) -> Result<usize, String> {
	if num_proofs == 0 {
		return Err("No proofs provided".to_string());
	}

	if branching_factor < 2 {
		return Err("Branching factor must be at least 2".to_string());
	}

	if depth == 0 {
		return Err("Depth must be at least 1".to_string());
	}

	// Calculate max leaf proofs for given depth and branching factor
	let max_leaf_proofs = branching_factor.pow(depth as u32);

	if num_proofs > max_leaf_proofs {
		return Err(format!(
			"Too many proofs: {} provided, max {} for depth={} branching_factor={}",
			num_proofs, max_leaf_proofs, depth, branching_factor
		));
	}

	Ok(max_leaf_proofs)
}

#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
	/// Submit a wormhole transfer to an unspendable account
	Transfer {
		/// Secret (32-byte hex string) - used to derive the unspendable account
		#[arg(long)]
		secret: String,

		/// Amount to transfer
		#[arg(long)]
		amount: u128,

		/// Wallet name to fund from
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
	/// Generate a wormhole proof from an existing transfer
	Generate {
		/// Secret (32-byte hex string) used for the transfer
		#[arg(long)]
		secret: String,

		/// Funding amount that was transferred
		#[arg(long)]
		amount: u128,

		/// Exit account (where funds will be withdrawn, hex or SS58)
		#[arg(long)]
		exit_account: String,

		/// Block hash to generate proof against (hex)
		#[arg(long)]
		block: String,

		/// Transfer count from the transfer event
		#[arg(long)]
		transfer_count: u64,

		/// Funding account (sender of transfer, hex or SS58)
		#[arg(long)]
		funding_account: String,

		/// Output file for the proof (default: proof.hex)
		#[arg(short, long, default_value = "proof.hex")]
		output: String,
	},
	/// Verify a single wormhole proof on-chain
	Verify {
		/// Path to the proof file (hex-encoded)
		#[arg(short, long, default_value = "proof.hex")]
		proof: String,
	},
	/// Aggregate multiple wormhole proofs into a single proof
	Aggregate {
		/// Input proof files (hex-encoded)
		#[arg(short, long, num_args = 1..)]
		proofs: Vec<String>,

		/// Output file for the aggregated proof (default: aggregated_proof.hex)
		#[arg(short, long, default_value = "aggregated_proof.hex")]
		output: String,

		/// Tree depth for aggregation (default: 3, supports up to 8 proofs with
		/// branching_factor=2)
		#[arg(long, default_value = "3")]
		depth: usize,

		/// Branching factor for aggregation tree (default: 2)
		#[arg(long, default_value = "2")]
		branching_factor: usize,
	},
	/// Verify an aggregated wormhole proof on-chain
	VerifyAggregated {
		/// Path to the aggregated proof file (hex-encoded)
		#[arg(short, long, default_value = "aggregated_proof.hex")]
		proof: String,
	},
	/// Parse and display the contents of a proof file (for debugging)
	ParseProof {
		/// Path to the proof file (hex-encoded)
		#[arg(short, long)]
		proof: String,

		/// Parse as aggregated proof (default: false, parses as leaf proof)
		#[arg(long)]
		aggregated: bool,
	},
	/// Run a multi-round wormhole test: wallet -> wormhole -> ... -> wallet
	Multiround {
		/// Number of proofs per round (default: 2, max: 8)
		#[arg(short, long, default_value = "2")]
		num_proofs: usize,

		/// Number of rounds (default: 2)
		#[arg(short, long, default_value = "2")]
		rounds: usize,

		/// Amount per transfer in planck (default: 10 DEV)
		#[arg(short, long, default_value = "10000000000000")]
		amount: u128,

		/// Wallet name to use for funding and final exit
		#[arg(short, long)]
		wallet: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Keep proof files after completion
		#[arg(short, long)]
		keep_files: bool,

		/// Output directory for proof files
		#[arg(short, long, default_value = "/tmp/wormhole_multiround")]
		output_dir: String,

		/// Dry run - show what would be done without executing
		#[arg(long)]
		dry_run: bool,
	},
}

pub async fn handle_wormhole_command(
	command: WormholeCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	match command {
		WormholeCommands::Transfer { secret, amount, from, password, password_file } => {
			submit_wormhole_transfer(secret, amount, from, password, password_file, node_url).await
		},
		WormholeCommands::Generate {
			secret,
			amount,
			exit_account,
			block,
			transfer_count,
			funding_account,
			output,
		} => {
			generate_proof(
				secret,
				amount,
				exit_account,
				block,
				transfer_count,
				funding_account,
				output,
				node_url,
			)
			.await
		},
		WormholeCommands::Verify { proof } => verify_proof(proof, node_url).await,
		WormholeCommands::Aggregate { proofs, output, depth, branching_factor } => {
			aggregate_proofs(proofs, output, depth, branching_factor).await
		},
		WormholeCommands::VerifyAggregated { proof } => {
			verify_aggregated_proof(proof, node_url).await
		},
		WormholeCommands::ParseProof { proof, aggregated } => {
			parse_proof_file(proof, aggregated).await
		},
		WormholeCommands::Multiround {
			num_proofs,
			rounds,
			amount,
			wallet,
			password,
			password_file,
			keep_files,
			output_dir,
			dry_run,
		} => {
			run_multiround(
				num_proofs,
				rounds,
				amount,
				wallet,
				password,
				password_file,
				keep_files,
				output_dir,
				dry_run,
				node_url,
			)
			.await
		},
	}
}

pub type TransferProofKey = (u32, u64, AccountId32, AccountId32, u128);

/// Submit a wormhole transfer to an unspendable account
async fn submit_wormhole_transfer(
	secret_hex: String,
	funding_amount: u128,
	from_wallet: String,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("Submitting wormhole transfer...");

	// Parse secret
	let secret_array =
		parse_secret_hex(&secret_hex).map_err(crate::error::QuantusError::Generic)?;
	let secret: BytesDigest = secret_array.try_into().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to convert secret: {:?}", e))
	})?;

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;
	let client = quantus_client.client();

	let funding_account = AccountId32::new(PoseidonHasher::hash(keypair.public_key.as_ref()).0);

	// Generate unspendable account from secret
	let unspendable_account =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret)
			.account_id;
	let unspendable_account_bytes_digest =
		qp_zk_circuits_common::utils::digest_felts_to_bytes(unspendable_account);
	let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
		.as_ref()
		.try_into()
		.expect("BytesDigest is always 32 bytes");
	let unspendable_account_id = SubxtAccountId(unspendable_account_bytes);

	log_verbose!("Funding account: 0x{}", hex::encode(funding_account.as_ref() as &[u8]));
	log_verbose!("Unspendable account: 0x{}", hex::encode(unspendable_account_bytes));

	// Transfer to unspendable account
	let transfer_tx = quantus_node::api::tx().wormhole().transfer_native(
		subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
		funding_amount,
	);

	let quantum_keypair = QuantumKeyPair {
		public_key: keypair.public_key.clone(),
		private_key: keypair.private_key.clone(),
	};

	submit_transaction(
		&quantus_client,
		&quantum_keypair,
		transfer_tx,
		None,
		ExecutionMode { finalized: false, wait_for_transaction: true },
	)
	.await
	.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	// Get block and event details
	let blocks = at_best_block(&quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let block_hash = blocks.hash();

	let events_api = client
		.events()
		.at(block_hash)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	// Find our specific transfer event
	let event = events_api
		.find::<wormhole::events::NativeTransferred>()
		.find(|e| if let Ok(evt) = e { evt.to.0 == unspendable_account_bytes } else { false })
		.ok_or_else(|| {
			crate::error::QuantusError::Generic(
				"No matching NativeTransferred event found".to_string(),
			)
		})?
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	// Output all the details needed for proof generation
	log_success!("Transfer successful!");
	log_success!("Block: {:?}", block_hash);
	log_print!("");
	log_print!("Use these values for proof generation:");
	log_print!("  --secret {}", secret_hex);
	log_print!("  --amount {}", funding_amount);
	log_print!("  --block 0x{}", hex::encode(block_hash.as_ref()));
	log_print!("  --transfer-count {}", event.transfer_count);
	log_print!("  --funding-account 0x{}", hex::encode(funding_account.as_ref() as &[u8]));

	Ok(())
}

/// Generate a wormhole proof from an existing transfer
async fn generate_proof(
	secret_hex: String,
	funding_amount: u128,
	exit_account_str: String,
	block_hash_str: String,
	transfer_count: u64,
	funding_account_str: String,
	output_file: String,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("Generating proof from existing transfer...");

	// Parse secret
	let secret_array =
		parse_secret_hex(&secret_hex).map_err(crate::error::QuantusError::Generic)?;
	let secret: BytesDigest = secret_array.try_into().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to convert secret: {:?}", e))
	})?;

	// Parse exit account
	let exit_account_bytes =
		parse_exit_account(&exit_account_str).map_err(crate::error::QuantusError::Generic)?;
	let exit_account_id = SubxtAccountId(exit_account_bytes);

	// Parse funding account
	let funding_account_bytes =
		parse_exit_account(&funding_account_str).map_err(crate::error::QuantusError::Generic)?;
	let funding_account = AccountId32::new(funding_account_bytes);

	// Parse block hash
	let hash_bytes = hex::decode(block_hash_str.trim_start_matches("0x"))
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid block hash: {}", e)))?;
	if hash_bytes.len() != 32 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Block hash must be 32 bytes, got {}",
			hash_bytes.len()
		)));
	}
	let hash: [u8; 32] = hash_bytes.try_into().unwrap();
	let block_hash = subxt::utils::H256::from(hash);

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;
	let client = quantus_client.client();

	log_verbose!("Connected to node, using block: {:?}", block_hash);

	// Generate unspendable account from secret
	let unspendable_account =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret)
			.account_id;
	let unspendable_account_bytes_digest =
		qp_zk_circuits_common::utils::digest_felts_to_bytes(unspendable_account);
	let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
		.as_ref()
		.try_into()
		.expect("BytesDigest is always 32 bytes");

	let from_account = funding_account.clone();
	let to_account = AccountId32::new(unspendable_account_bytes);

	// Get block
	let blocks =
		client.blocks().at(block_hash).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
		})?;

	// Build storage key
	let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferProofKey>(
		&(
			NATIVE_ASSET_ID,
			transfer_count,
			from_account.clone(),
			to_account.clone(),
			funding_amount,
		)
			.encode(),
	);

	let proof_address = quantus_node::api::storage().wormhole().transfer_proof((
		NATIVE_ASSET_ID,
		transfer_count,
		SubxtAccountId(from_account.clone().into()),
		SubxtAccountId(to_account.clone().into()),
		funding_amount,
	));

	let mut final_key = proof_address.to_root_bytes();
	final_key.extend_from_slice(&leaf_hash);

	// Verify storage key exists
	let storage_api = client.storage().at(block_hash);
	let val = storage_api
		.fetch_raw(final_key.clone())
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	if val.is_none() {
		return Err(crate::error::QuantusError::Generic(
			"Storage key not found - transfer may not exist in this block".to_string(),
		));
	}

	// Get storage proof
	let proof_params = rpc_params![vec![to_hex(&final_key)], block_hash];
	let read_proof: ReadProof<sp_core::H256> = quantus_client
		.rpc_client()
		.request("state_getReadProof", proof_params)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let header = blocks.header();
	let state_root = BytesDigest::try_from(header.state_root.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let digest =
		header.digest.encode().try_into().map_err(|_| {
			crate::error::QuantusError::Generic("Failed to encode digest".to_string())
		})?;
	let block_number = header.number;

	// Prepare storage proof
	let processed_storage_proof = prepare_proof_for_circuit(
		read_proof.proof.iter().map(|proof| proof.0.clone()).collect(),
		hex::encode(header.state_root.0),
		leaf_hash,
	)
	.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	// Quantize amounts
	let input_amount_quantized: u32 =
		quantize_funding_amount(funding_amount).map_err(crate::error::QuantusError::Generic)?;
	let output_amount_quantized = compute_output_amount(input_amount_quantized, VOLUME_FEE_BPS);

	let inputs = CircuitInputs {
		private: PrivateCircuitInputs {
			secret,
			transfer_count,
			funding_account: BytesDigest::try_from(funding_account.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			storage_proof: processed_storage_proof,
			unspendable_account: Digest::from(unspendable_account).into(),
			state_root,
			extrinsics_root,
			digest,
			input_amount: input_amount_quantized,
		},
		public: PublicCircuitInputs {
			output_amount_1: output_amount_quantized,
			output_amount_2: 0, // No change output for single-output spend
			volume_fee_bps: VOLUME_FEE_BPS,
			nullifier: Nullifier::from_preimage(secret, transfer_count).hash.into(),
			exit_account_1: BytesDigest::try_from(exit_account_id.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			exit_account_2: BytesDigest::try_from([0u8; 32].as_ref())
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?, // Unused
			block_hash: BytesDigest::try_from(block_hash.as_ref())
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			parent_hash,
			block_number,
			asset_id: NATIVE_ASSET_ID,
		},
	};

	log_verbose!("Generating ZK proof...");
	// Load prover from pre-built bins to ensure circuit digest matches on-chain verifier
	let bins_dir = std::path::Path::new("generated-bins");
	let prover =
		WormholeProver::new_from_files(&bins_dir.join("prover.bin"), &bins_dir.join("common.bin"))
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!("Failed to load prover: {}", e))
			})?;
	let prover_next = prover
		.commit(&inputs)
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let proof: ProofWithPublicInputs<_, _, 2> = prover_next.prove().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Proof generation failed: {}", e))
	})?;

	let public_inputs = PublicCircuitInputs::try_from(&proof)
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let proof_hex = hex::encode(proof.to_bytes());
	std::fs::write(&output_file, proof_hex).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to write proof: {}", e))
	})?;

	log_success!("Proof generated successfully!");
	log_success!("Output: {}", output_file);
	log_success!("Block: {:?}", block_hash);
	log_verbose!("Public inputs: {:?}", public_inputs);

	Ok(())
}

async fn at_best_block(
	quantus_client: &QuantusClient,
) -> anyhow::Result<Block<ChainConfig, OnlineClient<ChainConfig>>> {
	let best_block = quantus_client.get_latest_block().await?;
	let block = quantus_client.client().blocks().at(best_block).await?;
	Ok(block)
}

async fn aggregate_proofs(
	proof_files: Vec<String>,
	output_file: String,
	depth: usize,
	branching_factor: usize,
) -> crate::error::Result<()> {
	use qp_wormhole_aggregator::{
		aggregator::WormholeProofAggregator, circuits::tree::TreeAggregationConfig,
	};

	use std::path::Path;

	log_print!("Aggregating {} proofs...", proof_files.len());

	// Validate aggregation parameters using helper function
	let max_leaf_proofs = validate_aggregation_params(proof_files.len(), depth, branching_factor)
		.map_err(crate::error::QuantusError::Generic)?;

	// Configure aggregation
	let aggregation_config = TreeAggregationConfig::new(branching_factor, depth as u32);

	log_verbose!(
		"Aggregation config: branching_factor={}, depth={}, num_leaf_proofs={}",
		aggregation_config.tree_branching_factor,
		aggregation_config.tree_depth,
		max_leaf_proofs
	);

	// Load aggregator from pre-built bins to ensure circuit digest matches on-chain verifier
	let bins_dir = Path::new("generated-bins");
	let mut aggregator = WormholeProofAggregator::from_prebuilt_with_paths(
		&bins_dir.join("prover.bin"),
		&bins_dir.join("common.bin"),
		&bins_dir.join("verifier.bin"),
	)
	.map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to load aggregator from pre-built bins: {}",
			e
		))
	})?
	.with_config(aggregation_config);
	let common_data = aggregator.leaf_circuit_data.common.clone();

	// Load and add proofs using helper function
	for (idx, proof_file) in proof_files.iter().enumerate() {
		log_verbose!("Loading proof {}/{}: {}", idx + 1, proof_files.len(), proof_file);

		let proof_bytes = read_proof_file(proof_file).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to load {}: {}", proof_file, e))
		})?;

		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &common_data)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to deserialize proof from {}: {}",
					proof_file, e
				))
			})?;

		aggregator.push_proof(proof).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to add proof: {}", e))
		})?;
	}

	log_print!("Running aggregation...");
	let aggregated_proof = aggregator
		.aggregate()
		.map_err(|e| crate::error::QuantusError::Generic(format!("Aggregation failed: {}", e)))?;

	// Parse and display aggregated public inputs
	let aggregated_public_inputs = AggregatedPublicCircuitInputs::try_from_slice(
		aggregated_proof.proof.public_inputs.as_slice(),
	)
	.map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to parse aggregated public inputs: {}",
			e
		))
	})?;

	log_verbose!("Aggregated public inputs: {:#?}", aggregated_public_inputs);

	// Log exit accounts and amounts that will be minted
	log_print!("  Exit accounts in aggregated proof:");
	for (idx, account_data) in aggregated_public_inputs.account_data.iter().enumerate() {
		let exit_bytes: &[u8] = account_data.exit_account.as_ref();
		let is_dummy = exit_bytes.iter().all(|&b| b == 0) || account_data.summed_output_amount == 0;
		if is_dummy {
			log_verbose!("    [{}] DUMMY (skipped)", idx);
		} else {
			// De-quantize to show actual amount that will be minted
			let dequantized_amount =
				(account_data.summed_output_amount as u128) * SCALE_DOWN_FACTOR;
			log_print!(
				"    [{}] {} -> {} quantized ({} planck = {})",
				idx,
				hex::encode(exit_bytes),
				account_data.summed_output_amount,
				dequantized_amount,
				format_balance(dequantized_amount)
			);
		}
	}

	// Verify the aggregated proof locally
	log_verbose!("Verifying aggregated proof locally...");
	aggregated_proof
		.circuit_data
		.verify(aggregated_proof.proof.clone())
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Aggregated proof verification failed: {}",
				e
			))
		})?;

	// Save aggregated proof using helper function
	write_proof_file(&output_file, &aggregated_proof.proof.to_bytes()).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to write proof: {}", e))
	})?;

	log_success!("Aggregation complete!");
	log_success!("Output: {}", output_file);
	log_print!(
		"Aggregated {} proofs into 1 proof with {} exit accounts",
		proof_files.len(),
		aggregated_public_inputs.account_data.len()
	);

	Ok(())
}

async fn verify_aggregated_proof(proof_file: String, node_url: &str) -> crate::error::Result<()> {
	use subxt::tx::TxStatus;

	log_print!("Verifying aggregated wormhole proof on-chain...");

	// Read proof from file
	let proof_hex = std::fs::read_to_string(&proof_file).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read proof file: {}", e))
	})?;

	let proof_bytes = hex::decode(proof_hex.trim())
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to decode hex: {}", e)))?;

	log_verbose!("Aggregated proof size: {} bytes", proof_bytes.len());

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;

	log_verbose!("Connected to node");

	// Create the verify_aggregated_proof transaction payload
	let verify_tx = quantus_node::api::tx().wormhole().verify_aggregated_proof(proof_bytes);

	log_verbose!("Submitting unsigned aggregated verification transaction...");

	// Submit as unsigned extrinsic
	let unsigned_tx = quantus_client.client().tx().create_unsigned(&verify_tx).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create unsigned tx: {}", e))
	})?;

	let mut tx_progress = unsigned_tx
		.submit_and_watch()
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to submit tx: {}", e)))?;

	// Wait for transaction inclusion and verify events
	while let Some(Ok(status)) = tx_progress.next().await {
		log_verbose!("Transaction status: {:?}", status);
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				let tx_hash = tx_in_block.extrinsic_hash();

				// Check for ProofVerified event
				let result = check_proof_verification_events(
					quantus_client.client(),
					&block_hash,
					&tx_hash,
					crate::log::is_verbose(),
				)
				.await?;

				if result.success {
					log_success!("Aggregated proof verified successfully on-chain!");
					if let Some(amount) = result.exit_amount {
						log_success!("Total exit amount: {}", format_balance(amount));
					}
					log_verbose!("Included in block: {:?}", block_hash);
					return Ok(());
				} else {
					let error_msg = result.error_message.unwrap_or_else(|| {
						"Aggregated proof verification failed - no ProofVerified event found"
							.to_string()
					});
					log_error!("❌ {}", error_msg);
					return Err(crate::error::QuantusError::Generic(error_msg));
				}
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				let tx_hash = tx_in_block.extrinsic_hash();

				// Check for ProofVerified event
				let result = check_proof_verification_events(
					quantus_client.client(),
					&block_hash,
					&tx_hash,
					crate::log::is_verbose(),
				)
				.await?;

				if result.success {
					log_success!("Aggregated proof verified successfully on-chain!");
					if let Some(amount) = result.exit_amount {
						log_success!("Total exit amount: {}", format_balance(amount));
					}
					log_verbose!("Finalized in block: {:?}", block_hash);
					return Ok(());
				} else {
					let error_msg = result.error_message.unwrap_or_else(|| {
						"Aggregated proof verification failed - no ProofVerified event found"
							.to_string()
					});
					log_error!("❌ {}", error_msg);
					return Err(crate::error::QuantusError::Generic(error_msg));
				}
			},
			TxStatus::Error { message } | TxStatus::Invalid { message } => {
				return Err(crate::error::QuantusError::Generic(format!(
					"Transaction failed: {}",
					message
				)));
			},
			_ => continue,
		}
	}

	Err(crate::error::QuantusError::Generic("Transaction stream ended unexpectedly".to_string()))
}

async fn verify_proof(proof_file: String, node_url: &str) -> crate::error::Result<()> {
	use subxt::tx::TxStatus;

	log_print!("Verifying wormhole proof on-chain...");

	// Read proof from file
	let proof_hex = std::fs::read_to_string(&proof_file).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read proof file: {}", e))
	})?;

	let proof_bytes = hex::decode(proof_hex.trim())
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to decode hex: {}", e)))?;

	log_verbose!("Proof size: {} bytes", proof_bytes.len());

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;

	log_verbose!("Connected to node");

	// Create the verify transaction payload
	let verify_tx = quantus_node::api::tx().wormhole().verify_wormhole_proof(proof_bytes);

	log_verbose!("Submitting unsigned verification transaction...");

	// Submit as unsigned extrinsic
	let unsigned_tx = quantus_client.client().tx().create_unsigned(&verify_tx).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create unsigned tx: {}", e))
	})?;

	let mut tx_progress = unsigned_tx
		.submit_and_watch()
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to submit tx: {}", e)))?;

	// Wait for transaction inclusion and verify events
	while let Some(Ok(status)) = tx_progress.next().await {
		log_verbose!("Transaction status: {:?}", status);
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				let tx_hash = tx_in_block.extrinsic_hash();

				// Check for ProofVerified event
				let result = check_proof_verification_events(
					quantus_client.client(),
					&block_hash,
					&tx_hash,
					crate::log::is_verbose(),
				)
				.await?;

				if result.success {
					log_success!("Proof verified successfully on-chain!");
					if let Some(amount) = result.exit_amount {
						log_success!("Exit amount: {}", format_balance(amount));
					}
					log_verbose!("Included in block: {:?}", block_hash);
					return Ok(());
				} else {
					let error_msg = result.error_message.unwrap_or_else(|| {
						"Proof verification failed - no ProofVerified event found".to_string()
					});
					log_error!("❌ {}", error_msg);
					return Err(crate::error::QuantusError::Generic(error_msg));
				}
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				let tx_hash = tx_in_block.extrinsic_hash();

				// Check for ProofVerified event
				let result = check_proof_verification_events(
					quantus_client.client(),
					&block_hash,
					&tx_hash,
					crate::log::is_verbose(),
				)
				.await?;

				if result.success {
					log_success!("Proof verified successfully on-chain!");
					if let Some(amount) = result.exit_amount {
						log_success!("Exit amount: {}", format_balance(amount));
					}
					log_verbose!("Finalized in block: {:?}", block_hash);
					return Ok(());
				} else {
					let error_msg = result.error_message.unwrap_or_else(|| {
						"Proof verification failed - no ProofVerified event found".to_string()
					});
					log_error!("❌ {}", error_msg);
					return Err(crate::error::QuantusError::Generic(error_msg));
				}
			},
			TxStatus::Error { message } | TxStatus::Invalid { message } => {
				return Err(crate::error::QuantusError::Generic(format!(
					"Transaction failed: {}",
					message
				)));
			},
			_ => continue,
		}
	}

	Err(crate::error::QuantusError::Generic("Transaction stream ended unexpectedly".to_string()))
}

// ============================================================================
// Multi-round wormhole flow implementation
// ============================================================================

/// Aggregation config - hardcoded for now
const MULTIROUND_BRANCHING_FACTOR: usize = 2;
const MULTIROUND_DEPTH: usize = 3;
const MULTIROUND_MAX_PROOFS: usize = 8; // 2^3

/// Information about a transfer needed for proof generation
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TransferInfo {
	/// Block hash where the transfer was included
	block_hash: subxt::utils::H256,
	/// Transfer count for this specific transfer
	transfer_count: u64,
	/// Amount transferred
	amount: u128,
	/// The wormhole address (destination of transfer)
	wormhole_address: SubxtAccountId,
	/// The funding account (source of transfer)
	funding_account: SubxtAccountId,
}

/// Derive a wormhole secret using HD derivation
/// Path: m/44'/189189189'/0'/round'/index'
fn derive_wormhole_secret(
	mnemonic: &str,
	round: usize,
	index: usize,
) -> Result<WormholePair, crate::error::QuantusError> {
	// QUANTUS_WORMHOLE_CHAIN_ID already includes the ' (e.g., "189189189'")
	let path = format!("m/44'/{}/0'/{}'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, round, index);
	derive_wormhole_from_mnemonic(mnemonic, None, &path)
		.map_err(|e| crate::error::QuantusError::Generic(format!("HD derivation failed: {:?}", e)))
}

/// Calculate the amount for a given round, accounting for fees
/// Each round deducts 0.1% fee (10 bps)
/// Round 1: fee applied once, Round 2: fee applied twice, etc.
fn calculate_round_amount(initial_amount: u128, round: usize) -> u128 {
	let mut amount = initial_amount;
	for _ in 0..round {
		// Output = Input * (10000 - 10) / 10000
		amount = amount * 9990 / 10000;
	}
	amount
}

/// Get the minting account from chain constants
async fn get_minting_account(
	client: &OnlineClient<ChainConfig>,
) -> Result<SubxtAccountId, crate::error::QuantusError> {
	let minting_account_addr = quantus_node::api::constants().wormhole().minting_account();
	let minting_account = client.constants().at(&minting_account_addr).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to get minting account: {}", e))
	})?;
	Ok(minting_account)
}

/// Parse transfer info from NativeTransferred events in a block
fn parse_transfer_events(
	events: &[wormhole::events::NativeTransferred],
	expected_addresses: &[SubxtAccountId],
) -> Result<Vec<TransferInfo>, crate::error::QuantusError> {
	let mut transfer_infos = Vec::new();

	for expected_addr in expected_addresses {
		// Find the event matching this address
		let matching_event = events.iter().find(|e| &e.to == expected_addr).ok_or_else(|| {
			crate::error::QuantusError::Generic(format!(
				"No transfer event found for address {:?}",
				expected_addr
			))
		})?;

		transfer_infos.push(TransferInfo {
			block_hash: subxt::utils::H256::default(), // Will be set by caller
			transfer_count: matching_event.transfer_count,
			amount: matching_event.amount,
			wormhole_address: expected_addr.clone(),
			funding_account: matching_event.from.clone(),
		});
	}

	Ok(transfer_infos)
}

/// Run the multi-round wormhole flow
#[allow(clippy::too_many_arguments)]
async fn run_multiround(
	num_proofs: usize,
	rounds: usize,
	amount: u128,
	wallet_name: String,
	password: Option<String>,
	password_file: Option<String>,
	keep_files: bool,
	output_dir: String,
	dry_run: bool,
	node_url: &str,
) -> crate::error::Result<()> {
	use colored::Colorize;

	log_print!("");
	log_print!("==================================================");
	log_print!("  Wormhole Multi-Round Flow Test");
	log_print!("==================================================");
	log_print!("");

	// Validate parameters
	if num_proofs < 1 || num_proofs > MULTIROUND_MAX_PROOFS {
		return Err(crate::error::QuantusError::Generic(format!(
			"num_proofs must be between 1 and {} (got: {})",
			MULTIROUND_MAX_PROOFS, num_proofs
		)));
	}
	if rounds < 1 {
		return Err(crate::error::QuantusError::Generic(format!(
			"rounds must be at least 1 (got: {})",
			rounds
		)));
	}

	// Load wallet
	let wallet_manager = WalletManager::new()?;
	let wallet_password = password::get_wallet_password(&wallet_name, password, password_file)?;
	let wallet_data = wallet_manager.load_wallet(&wallet_name, &wallet_password)?;
	let wallet_address = wallet_data.keypair.to_account_id_ss58check();
	let wallet_account_id = SubxtAccountId(wallet_data.keypair.to_account_id_32().into());

	// Get or generate mnemonic for HD derivation
	let mnemonic = match wallet_data.mnemonic {
		Some(m) => {
			log_verbose!("Using wallet mnemonic for HD derivation");
			m
		},
		None => {
			log_print!("Wallet has no mnemonic - generating random mnemonic for wormhole secrets");
			let mut entropy = [0u8; 32];
			rand::rng().fill_bytes(&mut entropy);
			let sensitive_entropy = SensitiveBytes32::from(&mut entropy);
			let m = generate_mnemonic(sensitive_entropy).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Failed to generate mnemonic: {:?}", e))
			})?;
			log_verbose!("Generated mnemonic (not saved): {}", m);
			m
		},
	};

	log_print!("{}", "Configuration:".bright_cyan());
	log_print!("  Wallet: {}", wallet_name);
	log_print!("  Wallet address: {}", wallet_address);
	log_print!("  Initial amount: {} ({})", amount, format_balance(amount));
	log_print!("  Proofs per round: {}", num_proofs);
	log_print!("  Rounds: {}", rounds);
	log_print!(
		"  Aggregation: branching_factor={}, depth={}",
		MULTIROUND_BRANCHING_FACTOR,
		MULTIROUND_DEPTH
	);
	log_print!("  Output directory: {}", output_dir);
	log_print!("  Keep files: {}", keep_files);
	log_print!("  Dry run: {}", dry_run);
	log_print!("");

	// Show expected amounts per round
	log_print!("{}", "Expected amounts per round:".bright_cyan());
	for r in 1..=rounds {
		let round_amount = calculate_round_amount(amount, r);
		log_print!("  Round {}: {} ({})", r, round_amount, format_balance(round_amount));
	}
	log_print!("");

	// Create output directory
	std::fs::create_dir_all(&output_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create output directory: {}", e))
	})?;

	if dry_run {
		return run_multiround_dry_run(&mnemonic, num_proofs, rounds, amount, &wallet_address);
	}

	// Connect to node
	let quantus_client = QuantusClient::new(node_url).await.map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to connect to node: {}", e))
	})?;
	let client = quantus_client.client();

	// Get minting account from chain
	let minting_account = get_minting_account(client).await?;
	log_verbose!("Minting account: {:?}", minting_account);

	// Record initial wallet balance for verification
	let initial_balance = get_balance(&quantus_client, &wallet_address).await?;
	log_print!("{}", "Initial Balance:".bright_cyan());
	log_print!("  Wallet balance: {} ({})", initial_balance, format_balance(initial_balance));
	log_print!("");

	// Track transfer info for the current round
	let mut current_transfers: Vec<TransferInfo> = Vec::new();

	for round in 1..=rounds {
		let is_final = round == rounds;

		log_print!("");
		log_print!("--------------------------------------------------");
		log_print!(
			"  {} Round {} of {} {}",
			">>>".bright_blue(),
			round,
			rounds,
			"<<<".bright_blue()
		);
		log_print!("--------------------------------------------------");
		log_print!("");

		// Create round output directory
		let round_dir = format!("{}/round{}", output_dir, round);
		std::fs::create_dir_all(&round_dir).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to create round directory: {}", e))
		})?;

		// Derive secrets for this round
		let pb = ProgressBar::new(num_proofs as u64);
		pb.set_style(
			ProgressStyle::default_bar()
				.template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
				.unwrap()
				.progress_chars("#>-"),
		);
		pb.set_message("Deriving secrets...");

		let mut secrets: Vec<WormholePair> = Vec::new();
		for i in 1..=num_proofs {
			let secret = derive_wormhole_secret(&mnemonic, round, i)?;
			secrets.push(secret);
			pb.inc(1);
		}
		pb.finish_with_message("Secrets derived");

		// Determine exit accounts
		let exit_accounts: Vec<SubxtAccountId> = if is_final {
			log_print!("Final round - all proofs exit to wallet: {}", wallet_address);
			vec![wallet_account_id.clone(); num_proofs]
		} else {
			log_print!(
				"Intermediate round - proofs exit to round {} wormhole addresses",
				round + 1
			);
			let mut addrs = Vec::new();
			for i in 1..=num_proofs {
				let next_secret = derive_wormhole_secret(&mnemonic, round + 1, i)?;
				addrs.push(SubxtAccountId(next_secret.address));
			}
			addrs
		};

		// Step 1: Get transfer info
		if round == 1 {
			log_print!("{}", "Step 1: Sending wormhole transfers from wallet...".bright_yellow());

			let pb = ProgressBar::new(num_proofs as u64);
			pb.set_style(
				ProgressStyle::default_bar()
					.template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
					.unwrap()
					.progress_chars("#>-"),
			);

			current_transfers.clear();
			for (i, secret) in secrets.iter().enumerate() {
				pb.set_message(format!("Transfer {}/{}", i + 1, num_proofs));

				let wormhole_address = SubxtAccountId(secret.address);

				// Submit transfer
				let transfer_tx = quantus_node::api::tx().wormhole().transfer_native(
					subxt::ext::subxt_core::utils::MultiAddress::Id(wormhole_address.clone()),
					amount,
				);

				let quantum_keypair = QuantumKeyPair {
					public_key: wallet_data.keypair.public_key.clone(),
					private_key: wallet_data.keypair.private_key.clone(),
				};

				submit_transaction(
					&quantus_client,
					&quantum_keypair,
					transfer_tx,
					None,
					ExecutionMode { finalized: false, wait_for_transaction: true },
				)
				.await
				.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Transfer failed: {}", e))
				})?;

				// Get the block and find our event
				let block = at_best_block(&quantus_client).await.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
				})?;
				let block_hash = block.hash();

				let events_api = client.events().at(block_hash).await.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Failed to get events: {}", e))
				})?;

				// Find our transfer event
				let event = events_api
					.find::<wormhole::events::NativeTransferred>()
					.find(|e| if let Ok(evt) = e { evt.to.0 == secret.address } else { false })
					.ok_or_else(|| {
						crate::error::QuantusError::Generic(
							"No matching transfer event found".to_string(),
						)
					})?
					.map_err(|e| {
						crate::error::QuantusError::Generic(format!("Event decode error: {}", e))
					})?;

				let funding_account_bytes = wallet_data.keypair.to_account_id_32();
				current_transfers.push(TransferInfo {
					block_hash,
					transfer_count: event.transfer_count,
					amount,
					wormhole_address,
					funding_account: SubxtAccountId(funding_account_bytes.into()),
				});

				pb.inc(1);
			}
			pb.finish_with_message("Transfers complete");

			// Log balance immediately after funding transfers
			let balance_after_funding = get_balance(&quantus_client, &wallet_address).await?;
			let funding_deducted = initial_balance.saturating_sub(balance_after_funding);
			log_print!(
				"  Balance after funding: {} ({}) [deducted: {} planck]",
				balance_after_funding,
				format_balance(balance_after_funding),
				funding_deducted
			);
		} else {
			log_print!("{}", "Step 1: Using transfer info from previous round...".bright_yellow());
			// current_transfers was populated from the previous round's verification events
			// The secrets for this round ARE the exit secrets from round-1
			// So current_transfers already has the right wormhole addresses
			log_print!("  Found {} transfer(s) from previous round", current_transfers.len());
		}

		// Step 2: Generate proofs
		log_print!("{}", "Step 2: Generating proofs...".bright_yellow());

		// All proofs in an aggregation batch must use the same block for storage proofs.
		// Use the best block (which contains all transfers' state) for all proofs.
		let proof_block = at_best_block(&quantus_client).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
		})?;
		let proof_block_hash = proof_block.hash();
		log_print!("  Using block {} for all proofs", hex::encode(proof_block_hash.0));

		let pb = ProgressBar::new(num_proofs as u64);
		pb.set_style(
			ProgressStyle::default_bar()
				.template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
				.unwrap()
				.progress_chars("#>-"),
		);

		let mut proof_files: Vec<String> = Vec::new();
		for (i, (secret, transfer)) in secrets.iter().zip(current_transfers.iter()).enumerate() {
			pb.set_message(format!("Proof {}/{}", i + 1, num_proofs));

			let proof_file = format!("{}/proof_{}.hex", round_dir, i + 1);
			let exit_account_hex = format!("0x{}", hex::encode(exit_accounts[i].0));

			// Use the funding account from the transfer info
			let funding_account_hex = format!("0x{}", hex::encode(transfer.funding_account.0));

			// Generate proof using internal function
			// Use the actual transfer amount (not calculated round_amount) for storage key lookup
			// All proofs use the same block hash for aggregation compatibility
			generate_proof_internal(
				&hex::encode(secret.secret),
				transfer.amount, // Use actual transfer amount for storage key
				&exit_account_hex,
				&format!("0x{}", hex::encode(proof_block_hash.0)),
				transfer.transfer_count,
				&funding_account_hex,
				&proof_file,
				&quantus_client,
			)
			.await?;

			proof_files.push(proof_file);
			pb.inc(1);
		}
		pb.finish_with_message("Proofs generated");

		// Step 3: Aggregate proofs
		log_print!("{}", "Step 3: Aggregating proofs...".bright_yellow());

		let aggregated_file = format!("{}/aggregated.hex", round_dir);
		aggregate_proofs(
			proof_files,
			aggregated_file.clone(),
			MULTIROUND_DEPTH,
			MULTIROUND_BRANCHING_FACTOR,
		)
		.await?;

		log_print!("  Aggregated proof saved to {}", aggregated_file);

		// Step 4: Verify aggregated proof on-chain
		log_print!("{}", "Step 4: Submitting aggregated proof on-chain...".bright_yellow());

		let (verification_block, transfer_events) =
			verify_aggregated_and_get_events(&aggregated_file, &quantus_client).await?;

		log_print!(
			"  {} Proof verified in block {}",
			"✓".bright_green(),
			hex::encode(verification_block.0)
		);

		// If not final round, prepare transfer info for next round
		if !is_final {
			log_print!("{}", "Step 5: Capturing transfer info for next round...".bright_yellow());

			// Parse events to get transfer info for next round's wormhole addresses
			let next_round_addresses: Vec<SubxtAccountId> = (1..=num_proofs)
				.map(|i| {
					let next_secret = derive_wormhole_secret(&mnemonic, round + 1, i).unwrap();
					SubxtAccountId(next_secret.address)
				})
				.collect();

			current_transfers = parse_transfer_events(&transfer_events, &next_round_addresses)?;

			// Update block hash for all transfers
			for transfer in &mut current_transfers {
				transfer.block_hash = verification_block;
			}

			log_print!(
				"  Captured {} transfer(s) for round {}",
				current_transfers.len(),
				round + 1
			);
		}

		// Log balance after this round
		let balance_after_round = get_balance(&quantus_client, &wallet_address).await?;
		let change_from_initial = balance_after_round as i128 - initial_balance as i128;
		let change_str = if change_from_initial >= 0 {
			format!("+{}", change_from_initial)
		} else {
			format!("{}", change_from_initial)
		};
		log_print!("");
		log_print!(
			"  Balance after round {}: {} ({}) [change: {} planck]",
			round,
			balance_after_round,
			format_balance(balance_after_round),
			change_str
		);

		log_print!("");
		log_print!("  {} Round {} complete!", "✓".bright_green(), round);
	}

	log_print!("");
	log_print!("==================================================");
	log_success!("  All {} rounds completed successfully!", rounds);
	log_print!("==================================================");
	log_print!("");

	// Final balance verification
	log_print!("{}", "Balance Verification:".bright_cyan());

	// Query final balance
	let final_balance = get_balance(&quantus_client, &wallet_address).await?;

	// Calculate expected balance change
	// Total sent in round 1: num_proofs * amount
	let total_sent = (num_proofs as u128) * amount;

	// Total received in final round: num_proofs * final_round_amount
	let final_round_amount = calculate_round_amount(amount, rounds);
	let total_received = (num_proofs as u128) * final_round_amount;

	// Expected net change (may be negative due to fees)
	let expected_change = total_received as i128 - total_sent as i128;
	let actual_change = final_balance as i128 - initial_balance as i128;

	log_print!("  Initial balance: {} ({})", initial_balance, format_balance(initial_balance));
	log_print!("  Final balance:   {} ({})", final_balance, format_balance(final_balance));
	log_print!("");
	log_print!("  Total sent (round 1):     {} ({})", total_sent, format_balance(total_sent));
	log_print!(
		"  Total received (round {}): {} ({})",
		rounds,
		total_received,
		format_balance(total_received)
	);
	log_print!("");

	// Format signed amounts for display
	let expected_change_str = if expected_change >= 0 {
		format!("+{}", expected_change)
	} else {
		format!("{}", expected_change)
	};
	let actual_change_str = if actual_change >= 0 {
		format!("+{}", actual_change)
	} else {
		format!("{}", actual_change)
	};

	log_print!("  Expected change: {} planck", expected_change_str);
	log_print!("  Actual change:   {} planck", actual_change_str);
	log_print!("");

	// Allow some tolerance for transaction fees (e.g., 1% or a fixed amount)
	// The actual change may differ slightly due to transaction fees for the initial transfers
	let tolerance = (total_sent / 100).max(1_000_000_000_000); // 1% or 1 QNT minimum

	let diff = (actual_change - expected_change).abs() as u128;
	if diff <= tolerance {
		log_success!(
			"  {} Balance verification PASSED (within tolerance of {} planck)",
			"✓".bright_green(),
			tolerance
		);
	} else {
		log_print!(
			"  {} Balance verification: difference of {} planck (tolerance: {} planck)",
			"!".bright_yellow(),
			diff,
			tolerance
		);
		log_print!(
			"    Note: Transaction fees for {} initial transfers may account for the difference",
			num_proofs
		);
	}
	log_print!("");

	if keep_files {
		log_print!("Proof files preserved in: {}", output_dir);
	} else {
		log_print!("Cleaning up proof files...");
		std::fs::remove_dir_all(&output_dir).ok();
	}

	Ok(())
}

/// Internal proof generation that uses already-connected client
#[allow(clippy::too_many_arguments)]
async fn generate_proof_internal(
	secret_hex: &str,
	funding_amount: u128,
	exit_account_str: &str,
	block_hash_str: &str,
	transfer_count: u64,
	funding_account_str: &str,
	output_file: &str,
	quantus_client: &QuantusClient,
) -> crate::error::Result<()> {
	// Parse secret
	let secret_array = parse_secret_hex(secret_hex).map_err(crate::error::QuantusError::Generic)?;
	let secret: BytesDigest = secret_array.try_into().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to convert secret: {:?}", e))
	})?;

	// Parse exit account
	let exit_account_bytes =
		parse_exit_account(exit_account_str).map_err(crate::error::QuantusError::Generic)?;
	let exit_account_id = SubxtAccountId(exit_account_bytes);

	// Parse funding account
	let funding_account_bytes =
		parse_exit_account(funding_account_str).map_err(crate::error::QuantusError::Generic)?;
	let funding_account = AccountId32::new(funding_account_bytes);

	// Parse block hash
	let hash_bytes = hex::decode(block_hash_str.trim_start_matches("0x"))
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid block hash: {}", e)))?;
	if hash_bytes.len() != 32 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Block hash must be 32 bytes, got {}",
			hash_bytes.len()
		)));
	}
	let hash: [u8; 32] = hash_bytes.try_into().unwrap();
	let block_hash = subxt::utils::H256::from(hash);

	let client = quantus_client.client();

	// Generate unspendable account from secret
	let unspendable_account =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret)
			.account_id;
	let unspendable_account_bytes_digest =
		qp_zk_circuits_common::utils::digest_felts_to_bytes(unspendable_account);
	let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
		.as_ref()
		.try_into()
		.expect("BytesDigest is always 32 bytes");

	let from_account = funding_account.clone();
	let to_account = AccountId32::new(unspendable_account_bytes);

	// Get block
	let blocks =
		client.blocks().at(block_hash).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
		})?;

	// Build storage key
	let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferProofKey>(
		&(
			NATIVE_ASSET_ID,
			transfer_count,
			from_account.clone(),
			to_account.clone(),
			funding_amount,
		)
			.encode(),
	);

	let proof_address = quantus_node::api::storage().wormhole().transfer_proof((
		NATIVE_ASSET_ID,
		transfer_count,
		SubxtAccountId(from_account.clone().into()),
		SubxtAccountId(to_account.clone().into()),
		funding_amount,
	));

	let mut final_key = proof_address.to_root_bytes();
	final_key.extend_from_slice(&leaf_hash);

	// Verify storage key exists
	let storage_api = client.storage().at(block_hash);
	let val = storage_api
		.fetch_raw(final_key.clone())
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	if val.is_none() {
		return Err(crate::error::QuantusError::Generic(
			"Storage key not found - transfer may not exist in this block".to_string(),
		));
	}

	// Get storage proof
	let proof_params = rpc_params![vec![to_hex(&final_key)], block_hash];
	let read_proof: ReadProof<sp_core::H256> = quantus_client
		.rpc_client()
		.request("state_getReadProof", proof_params)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let header = blocks.header();
	let state_root = BytesDigest::try_from(header.state_root.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let digest =
		header.digest.encode().try_into().map_err(|_| {
			crate::error::QuantusError::Generic("Failed to encode digest".to_string())
		})?;
	let block_number = header.number;

	// Prepare storage proof
	let processed_storage_proof = prepare_proof_for_circuit(
		read_proof.proof.iter().map(|proof| proof.0.clone()).collect(),
		hex::encode(header.state_root.0),
		leaf_hash,
	)
	.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	// Quantize amounts
	let input_amount_quantized: u32 =
		quantize_funding_amount(funding_amount).map_err(crate::error::QuantusError::Generic)?;
	let output_amount_quantized = compute_output_amount(input_amount_quantized, VOLUME_FEE_BPS);

	let inputs = CircuitInputs {
		private: PrivateCircuitInputs {
			secret,
			transfer_count,
			funding_account: BytesDigest::try_from(funding_account.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			storage_proof: processed_storage_proof,
			unspendable_account: Digest::from(unspendable_account).into(),
			state_root,
			extrinsics_root,
			digest,
			input_amount: input_amount_quantized,
		},
		public: PublicCircuitInputs {
			output_amount_1: output_amount_quantized,
			output_amount_2: 0, // No change output for single-output spend
			volume_fee_bps: VOLUME_FEE_BPS,
			nullifier: Nullifier::from_preimage(secret, transfer_count).hash.into(),
			exit_account_1: BytesDigest::try_from(exit_account_id.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			exit_account_2: BytesDigest::try_from([0u8; 32].as_ref())
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?, // Unused
			block_hash: BytesDigest::try_from(block_hash.as_ref())
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			parent_hash,
			block_number,
			asset_id: NATIVE_ASSET_ID,
		},
	};

	// Load prover from pre-built bins
	let bins_dir = Path::new("generated-bins");
	let prover =
		WormholeProver::new_from_files(&bins_dir.join("prover.bin"), &bins_dir.join("common.bin"))
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!("Failed to load prover: {}", e))
			})?;
	let prover_next = prover
		.commit(&inputs)
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let proof: ProofWithPublicInputs<_, _, 2> = prover_next.prove().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Proof generation failed: {}", e))
	})?;

	let proof_hex = hex::encode(proof.to_bytes());
	std::fs::write(output_file, proof_hex).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to write proof: {}", e))
	})?;

	Ok(())
}

/// Verify an aggregated proof and return the block hash and transfer events
async fn verify_aggregated_and_get_events(
	proof_file: &str,
	quantus_client: &QuantusClient,
) -> crate::error::Result<(subxt::utils::H256, Vec<wormhole::events::NativeTransferred>)> {
	use crate::chain::quantus_subxt::api::system::events::ExtrinsicFailed;
	use qp_wormhole_verifier::WormholeVerifier;
	use subxt::tx::TxStatus;

	// Read proof from file
	let proof_hex = std::fs::read_to_string(proof_file).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read proof file: {}", e))
	})?;

	let proof_bytes = hex::decode(proof_hex.trim())
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to decode hex: {}", e)))?;

	// Verify locally before submitting on-chain
	log_verbose!("Verifying aggregated proof locally before on-chain submission...");
	let aggregated_verifier_bytes = include_bytes!("../../generated-bins/aggregated_verifier.bin");
	let aggregated_common_bytes = include_bytes!("../../generated-bins/aggregated_common.bin");
	let verifier =
		WormholeVerifier::new_from_bytes(aggregated_verifier_bytes, aggregated_common_bytes)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to load aggregated verifier: {}",
					e
				))
			})?;

	// Use the verifier crate's ProofWithPublicInputs type (different from plonky2's)
	let proof = qp_wormhole_verifier::ProofWithPublicInputs::<
		qp_wormhole_verifier::F,
		qp_wormhole_verifier::C,
		{ qp_wormhole_verifier::D },
	>::from_bytes(proof_bytes.clone(), &verifier.circuit_data.common)
	.map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to deserialize aggregated proof: {}",
			e
		))
	})?;

	verifier.verify(proof).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Local aggregated proof verification failed: {}",
			e
		))
	})?;
	log_verbose!("Local verification passed!");

	// Create the verify_aggregated_proof transaction payload
	let verify_tx = quantus_node::api::tx().wormhole().verify_aggregated_proof(proof_bytes);

	// Submit as unsigned extrinsic
	let unsigned_tx = quantus_client.client().tx().create_unsigned(&verify_tx).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create unsigned tx: {}", e))
	})?;

	let mut tx_progress = unsigned_tx
		.submit_and_watch()
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to submit tx: {}", e)))?;

	while let Some(Ok(status)) = tx_progress.next().await {
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				let tx_hash = tx_in_block.extrinsic_hash();

				// Get all events from the block
				let block = quantus_client.client().blocks().at(block_hash).await.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
				})?;

				let events = block.events().await.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Failed to get events: {}", e))
				})?;

				// Find our extrinsic index
				let extrinsics = block.extrinsics().await.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Failed to get extrinsics: {}", e))
				})?;

				let our_ext_idx = extrinsics
					.iter()
					.enumerate()
					.find(|(_, ext)| ext.hash() == tx_hash)
					.map(|(idx, _)| idx as u32);

				// Collect NativeTransferred events for our extrinsic
				let mut transfer_events = Vec::new();
				let mut found_proof_verified = false;

				log_verbose!("  Events for our extrinsic (idx={:?}):", our_ext_idx);
				for event_result in events.iter() {
					let event = event_result.map_err(|e| {
						crate::error::QuantusError::Generic(format!(
							"Failed to decode event: {}",
							e
						))
					})?;

					if let subxt::events::Phase::ApplyExtrinsic(ext_idx) = event.phase() {
						if Some(ext_idx) == our_ext_idx {
							// Log all events for our extrinsic
							log_print!(
								"    Event: {}::{}",
								event.pallet_name(),
								event.variant_name()
							);

							// Decode ExtrinsicFailed to get the specific error
							if let Ok(Some(ExtrinsicFailed { dispatch_error, .. })) =
								event.as_event::<ExtrinsicFailed>()
							{
								let metadata = quantus_client.client().metadata();
								let error_msg = format_dispatch_error(&dispatch_error, &metadata);
								log_print!("    DispatchError: {}", error_msg);
							}

							if let Ok(Some(_)) = event.as_event::<wormhole::events::ProofVerified>()
							{
								found_proof_verified = true;
							}
							if let Ok(Some(transfer)) =
								event.as_event::<wormhole::events::NativeTransferred>()
							{
								transfer_events.push(transfer);
							}
						}
					}
				}

				if found_proof_verified {
					// Log the minted amounts from transfer events
					log_print!("  Tokens minted (from NativeTransferred events):");
					for (idx, transfer) in transfer_events.iter().enumerate() {
						let to_hex = hex::encode(transfer.to.0);
						log_print!(
							"    [{}] {} -> {} planck ({})",
							idx,
							to_hex,
							transfer.amount,
							format_balance(transfer.amount)
						);
					}
					return Ok((block_hash, transfer_events));
				} else {
					return Err(crate::error::QuantusError::Generic(
						"Proof verification failed - no ProofVerified event".to_string(),
					));
				}
			},
			TxStatus::Error { message } | TxStatus::Invalid { message } => {
				return Err(crate::error::QuantusError::Generic(format!(
					"Transaction failed: {}",
					message
				)));
			},
			_ => continue,
		}
	}

	Err(crate::error::QuantusError::Generic("Transaction stream ended unexpectedly".to_string()))
}

/// Dry run - show what would happen without executing
fn run_multiround_dry_run(
	mnemonic: &str,
	num_proofs: usize,
	rounds: usize,
	amount: u128,
	wallet_address: &str,
) -> crate::error::Result<()> {
	use colored::Colorize;

	log_print!("");
	log_print!("{}", "=== DRY RUN MODE ===".bright_yellow());
	log_print!("No transactions will be executed.");
	log_print!("");

	for round in 1..=rounds {
		let is_final = round == rounds;
		let round_amount = calculate_round_amount(amount, round);

		log_print!("");
		log_print!("{}", format!("Round {}", round).bright_cyan());
		log_print!("  Amount: {} ({})", round_amount, format_balance(round_amount));
		log_print!("");

		log_print!("  Wormhole addresses (to be funded):");
		for i in 1..=num_proofs {
			let secret = derive_wormhole_secret(mnemonic, round, i)?;
			let address = sp_core::crypto::AccountId32::new(secret.address)
				.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));
			log_print!("    [{}] {}", i, address);
			log_verbose!("        secret: 0x{}", hex::encode(secret.secret));
		}

		log_print!("");
		log_print!("  Exit accounts:");
		if is_final {
			log_print!("    All proofs exit to wallet: {}", wallet_address);
		} else {
			for i in 1..=num_proofs {
				let next_secret = derive_wormhole_secret(mnemonic, round + 1, i)?;
				let address = sp_core::crypto::AccountId32::new(next_secret.address)
					.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));
				log_print!("    [{}] {} (round {} wormhole)", i, address, round + 1);
			}
		}
	}

	log_print!("");
	log_print!("{}", "=== END DRY RUN ===".bright_yellow());
	log_print!("");

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use plonky2::plonk::circuit_data::CircuitConfig;
	use qp_wormhole_circuit::inputs::{
		AggregatedPublicCircuitInputs, CircuitInputs, PublicCircuitInputs,
	};
	use qp_wormhole_prover::WormholeProver;
	use qp_wormhole_test_helpers::TestInputs;

	use tempfile::NamedTempFile;

	/// Helper to get a standard circuit config for tests
	fn test_circuit_config() -> CircuitConfig {
		CircuitConfig::standard_recursion_zk_config()
	}

	#[test]
	fn test_compute_output_amount() {
		// 0.1% fee (10 bps): output = input * 9990 / 10000
		assert_eq!(compute_output_amount(1000, 10), 999);
		assert_eq!(compute_output_amount(10000, 10), 9990);

		// 1% fee (100 bps): output = input * 9900 / 10000
		assert_eq!(compute_output_amount(1000, 100), 990);
		assert_eq!(compute_output_amount(10000, 100), 9900);

		// 0% fee
		assert_eq!(compute_output_amount(1000, 0), 1000);

		// Edge cases
		assert_eq!(compute_output_amount(0, 10), 0);
		assert_eq!(compute_output_amount(1, 10), 0); // rounds down
		assert_eq!(compute_output_amount(100, 10), 99);
	}

	#[test]
	fn test_parse_secret_hex() {
		// Valid hex with and without 0x prefix
		let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
		assert!(parse_secret_hex(secret).is_ok());
		assert!(parse_secret_hex(&format!("0x{}", secret)).is_ok());

		// Wrong length
		assert!(parse_secret_hex("0123456789abcdef").unwrap_err().contains("32 bytes"));

		// Invalid hex characters
		assert!(parse_secret_hex("ghij".repeat(16).as_str())
			.unwrap_err()
			.contains("Invalid secret hex"));
	}

	#[test]
	fn test_parse_exit_account() {
		// Valid hex account
		let hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
		assert!(parse_exit_account(hex).is_ok());

		// Wrong length
		assert!(parse_exit_account("0x0123456789abcdef").unwrap_err().contains("32 bytes"));

		// Invalid SS58
		assert!(parse_exit_account("not_valid").unwrap_err().contains("Invalid SS58"));
	}

	#[test]
	fn test_quantize_funding_amount() {
		// Basic quantization: 1 token (12 decimals) -> 100 (2 decimals)
		assert_eq!(quantize_funding_amount(1_000_000_000_000).unwrap(), 100);

		// Zero and small amounts
		assert_eq!(quantize_funding_amount(0).unwrap(), 0);
		assert_eq!(quantize_funding_amount(5_000_000_000).unwrap(), 0); // < 10^10

		// Max valid and overflow
		let max_valid = (u32::MAX as u128) * SCALE_DOWN_FACTOR;
		assert_eq!(quantize_funding_amount(max_valid).unwrap(), u32::MAX);
		assert!(quantize_funding_amount(max_valid + SCALE_DOWN_FACTOR)
			.unwrap_err()
			.contains("too large"));
	}

	#[test]
	fn test_validate_aggregation_params() {
		// Valid configurations
		assert_eq!(validate_aggregation_params(2, 1, 2).unwrap(), 2);
		assert_eq!(validate_aggregation_params(9, 2, 3).unwrap(), 9); // 3^2 = 9

		// Invalid: no proofs, bad branching factor, zero depth
		assert!(validate_aggregation_params(0, 1, 2).unwrap_err().contains("No proofs"));
		assert!(validate_aggregation_params(2, 1, 1).unwrap_err().contains("Branching factor"));
		assert!(validate_aggregation_params(2, 0, 2).unwrap_err().contains("Depth"));

		// Too many proofs for tree size
		assert!(validate_aggregation_params(3, 1, 2).unwrap_err().contains("Too many proofs"));
	}

	#[test]
	fn test_proof_file_roundtrip() {
		let temp_file = NamedTempFile::new().unwrap();
		let path = temp_file.path().to_str().unwrap();
		let proof_bytes = vec![0x01, 0x02, 0x03, 0xaa, 0xbb, 0xcc];

		write_proof_file(path, &proof_bytes).unwrap();
		assert_eq!(read_proof_file(path).unwrap(), proof_bytes);
	}

	#[test]
	fn test_read_proof_file_errors() {
		// File not found
		assert!(read_proof_file("/nonexistent/path/proof.hex")
			.unwrap_err()
			.contains("Failed to read"));

		// Invalid hex content
		let temp_file = NamedTempFile::new().unwrap();
		std::fs::write(temp_file.path(), "not valid hex!").unwrap();
		assert!(read_proof_file(temp_file.path().to_str().unwrap())
			.unwrap_err()
			.contains("Failed to decode"));
	}

	#[test]
	fn test_fee_calculation_edge_cases() {
		// Test the circuit fee constraint: output_amount * 10000 <= input_amount * (10000 -
		// volume_fee_bps) This is equivalent to: output <= input * (1 - fee_rate)

		// Small amounts where fee rounds to zero
		let input_small: u32 = 100;
		let output_small = compute_output_amount(input_small, VOLUME_FEE_BPS);
		assert_eq!(output_small, 99);
		// Verify constraint: 99 * 10000 = 990000 <= 100 * 9990 = 999000 ✓
		assert!(
			(output_small as u64) * 10000 <= (input_small as u64) * (10000 - VOLUME_FEE_BPS as u64)
		);

		// Medium amounts
		let input_medium: u32 = 10000;
		let output_medium = compute_output_amount(input_medium, VOLUME_FEE_BPS);
		assert_eq!(output_medium, 9990);
		assert!(
			(output_medium as u64) * 10000
				<= (input_medium as u64) * (10000 - VOLUME_FEE_BPS as u64)
		);

		// Large amounts near u32::MAX
		let input_large: u32 = u32::MAX / 2;
		let output_large = compute_output_amount(input_large, VOLUME_FEE_BPS);
		assert!(
			(output_large as u64) * 10000 <= (input_large as u64) * (10000 - VOLUME_FEE_BPS as u64)
		);

		// Test with different fee rates
		for fee_bps in [0u32, 1, 10, 50, 100, 500, 1000] {
			let input: u32 = 100000;
			let output = compute_output_amount(input, fee_bps);
			assert!(
				(output as u64) * 10000 <= (input as u64) * (10000 - fee_bps as u64),
				"Fee constraint violated for fee_bps={}: {} * 10000 > {} * {}",
				fee_bps,
				output,
				input,
				10000 - fee_bps
			);
		}
	}

	#[test]
	fn test_nullifier_determinism() {
		use qp_wormhole_circuit::nullifier::Nullifier;
		use qp_zk_circuits_common::utils::BytesDigest;

		let secret: BytesDigest = [1u8; 32].try_into().expect("valid secret");
		let transfer_count = 42u64;

		// Generate nullifier multiple times - should be identical
		let nullifier1 = Nullifier::from_preimage(secret, transfer_count);
		let nullifier2 = Nullifier::from_preimage(secret, transfer_count);
		let nullifier3 = Nullifier::from_preimage(secret, transfer_count);

		assert_eq!(nullifier1.hash, nullifier2.hash);
		assert_eq!(nullifier2.hash, nullifier3.hash);

		// Different transfer count should produce different nullifier
		let nullifier_different = Nullifier::from_preimage(secret, transfer_count + 1);
		assert_ne!(nullifier1.hash, nullifier_different.hash);

		// Different secret should produce different nullifier
		let different_secret: BytesDigest = [2u8; 32].try_into().expect("valid secret");
		let nullifier_different_secret = Nullifier::from_preimage(different_secret, transfer_count);
		assert_ne!(nullifier1.hash, nullifier_different_secret.hash);
	}

	#[test]
	fn test_unspendable_account_determinism() {
		use qp_wormhole_circuit::unspendable_account::UnspendableAccount;
		use qp_zk_circuits_common::utils::BytesDigest;

		let secret: BytesDigest = [1u8; 32].try_into().expect("valid secret");

		// Generate unspendable account multiple times - should be identical
		let account1 = UnspendableAccount::from_secret(secret);
		let account2 = UnspendableAccount::from_secret(secret);

		assert_eq!(account1.account_id, account2.account_id);

		// Different secret should produce different account
		let different_secret: BytesDigest = [2u8; 32].try_into().expect("valid secret");
		let account_different = UnspendableAccount::from_secret(different_secret);
		assert_ne!(account1.account_id, account_different.account_id);
	}

	/// Integration test: Generate a real ZK proof using test fixtures and verify it
	#[test]
	#[ignore] // This test is slow (~30s) - run with `cargo test -- --ignored`
	fn test_full_proof_generation_and_verification() {
		// Use test fixtures from qp-wormhole-test-helpers
		let inputs = CircuitInputs::test_inputs_0();

		// Verify the test inputs have correct fee configuration
		assert_eq!(inputs.public.volume_fee_bps, VOLUME_FEE_BPS);
		assert_eq!(inputs.public.asset_id, NATIVE_ASSET_ID);

		// Verify fee constraint is satisfied in test inputs
		let input_amount = inputs.private.input_amount;
		let output_amount = inputs.public.output_amount_1 + inputs.public.output_amount_2;
		assert!(
			(output_amount as u64) * 10000
				<= (input_amount as u64) * (10000 - VOLUME_FEE_BPS as u64),
			"Test inputs violate fee constraint"
		);

		// Create prover and generate proof
		let config = test_circuit_config();
		let prover = WormholeProver::new(config.clone());
		let prover_committed = prover.commit(&inputs).expect("Failed to commit inputs");
		let proof = prover_committed.prove().expect("Failed to generate proof");

		// Parse and verify public inputs from proof
		let parsed_public_inputs =
			PublicCircuitInputs::try_from(&proof).expect("Failed to parse public inputs");

		assert_eq!(parsed_public_inputs.asset_id, inputs.public.asset_id);
		assert_eq!(parsed_public_inputs.output_amount_1, inputs.public.output_amount_1);
		assert_eq!(parsed_public_inputs.output_amount_2, inputs.public.output_amount_2);
		assert_eq!(parsed_public_inputs.volume_fee_bps, inputs.public.volume_fee_bps);
		assert_eq!(parsed_public_inputs.nullifier, inputs.public.nullifier);
		assert_eq!(parsed_public_inputs.exit_account_1, inputs.public.exit_account_1);
		assert_eq!(parsed_public_inputs.exit_account_2, inputs.public.exit_account_2);
		assert_eq!(parsed_public_inputs.block_hash, inputs.public.block_hash);
		assert_eq!(parsed_public_inputs.parent_hash, inputs.public.parent_hash);
		assert_eq!(parsed_public_inputs.block_number, inputs.public.block_number);

		// Create verifier and verify proof
		let verifier = WormholeVerifier::new(config, None);
		verifier.verify(proof).expect("Proof verification failed");
	}

	/// Integration test: Generate proof, serialize/deserialize, then verify
	#[test]
	#[ignore] // This test is slow - run with `cargo test -- --ignored`
	fn test_proof_serialization_roundtrip() {
		let inputs = CircuitInputs::test_inputs_0();
		let config = test_circuit_config();

		// Generate proof
		let prover = WormholeProver::new(config.clone());
		let proof = prover.commit(&inputs).unwrap().prove().unwrap();

		// Serialize to bytes
		let proof_bytes = proof.to_bytes();

		// Write to temp file and read back
		let temp_file = NamedTempFile::new().unwrap();
		let path = temp_file.path().to_str().unwrap();
		write_proof_file(path, &proof_bytes).unwrap();
		let read_bytes = read_proof_file(path).unwrap();

		assert_eq!(proof_bytes, read_bytes, "Proof bytes should match after file roundtrip");

		// Deserialize and verify
		let verifier = WormholeVerifier::new(config, None);
		let deserialized_proof = plonky2::plonk::proof::ProofWithPublicInputs::<
			qp_zk_circuits_common::circuit::F,
			qp_zk_circuits_common::circuit::C,
			{ qp_zk_circuits_common::circuit::D },
		>::from_bytes(read_bytes, &verifier.circuit_data.common)
		.expect("Failed to deserialize proof");

		verifier
			.verify(deserialized_proof)
			.expect("Deserialized proof verification failed");
	}

	/// Integration test: Generate multiple proofs with different inputs
	#[test]
	#[ignore] // This test is slow - run with `cargo test -- --ignored`
	fn test_multiple_proof_generation() {
		let config = test_circuit_config();

		// Generate proofs for both test input sets
		let inputs_0 = CircuitInputs::test_inputs_0();
		let inputs_1 = CircuitInputs::test_inputs_1();

		let prover_0 = WormholeProver::new(config.clone());
		let proof_0 = prover_0.commit(&inputs_0).unwrap().prove().unwrap();

		let prover_1 = WormholeProver::new(config.clone());
		let proof_1 = prover_1.commit(&inputs_1).unwrap().prove().unwrap();

		// Verify both proofs
		let verifier = WormholeVerifier::new(config, None);
		verifier.verify(proof_0.clone()).expect("Proof 0 verification failed");
		verifier.verify(proof_1.clone()).expect("Proof 1 verification failed");

		// Verify public inputs are different (different nullifiers, etc.)
		let public_0 = PublicCircuitInputs::try_from(&proof_0).unwrap();
		let public_1 = PublicCircuitInputs::try_from(&proof_1).unwrap();

		assert_ne!(public_0.nullifier, public_1.nullifier, "Nullifiers should be different");
		assert_ne!(public_0.block_hash, public_1.block_hash, "Block hashes should be different");
	}

	/// Integration test: Aggregate proofs and verify aggregated proof
	#[test]
	#[ignore] // This test is slow (~60s) - run with `cargo test -- --ignored`
	fn test_proof_aggregation() {
		use qp_wormhole_aggregator::aggregator::WormholeProofAggregator;

		let config = test_circuit_config();

		// Generate a proof
		let inputs = CircuitInputs::test_inputs_0();
		let prover = WormholeProver::new(config.clone());
		let proof = prover.commit(&inputs).unwrap().prove().unwrap();

		// Create aggregator with default config (branching_factor=2, depth=1)
		let verifier = WormholeVerifier::new(config, None);
		let mut aggregator = WormholeProofAggregator::new(verifier.circuit_data);

		// Add proof to aggregator
		aggregator.push_proof(proof.clone()).expect("Failed to push proof");

		// Aggregate
		let aggregated_result = aggregator.aggregate().expect("Aggregation failed");

		// Parse aggregated public inputs
		let aggregated_public_inputs = AggregatedPublicCircuitInputs::try_from_slice(
			aggregated_result.proof.public_inputs.as_slice(),
		)
		.expect("Failed to parse aggregated public inputs");

		// Verify aggregated proof structure
		assert_eq!(aggregated_public_inputs.asset_id, NATIVE_ASSET_ID, "Asset ID should be native");
		assert_eq!(
			aggregated_public_inputs.volume_fee_bps, VOLUME_FEE_BPS,
			"Volume fee BPS should match"
		);
		assert!(
			!aggregated_public_inputs.nullifiers.is_empty(),
			"Should have at least one nullifier"
		);
		assert!(
			!aggregated_public_inputs.account_data.is_empty(),
			"Should have at least one account"
		);

		// Verify the aggregated proof locally
		aggregated_result
			.circuit_data
			.verify(aggregated_result.proof)
			.expect("Aggregated proof verification failed");
	}

	/// Integration test: Aggregate multiple proofs with different exit accounts
	#[test]
	#[ignore] // This test is very slow (~120s) - run with `cargo test -- --ignored`
	fn test_proof_aggregation_multiple_accounts() {
		use qp_wormhole_aggregator::aggregator::WormholeProofAggregator;

		let config = test_circuit_config();

		// Generate proofs with different inputs (different exit accounts)
		let inputs_0 = CircuitInputs::test_inputs_0();
		let inputs_1 = CircuitInputs::test_inputs_1();

		let prover_0 = WormholeProver::new(config.clone());
		let proof_0 = prover_0.commit(&inputs_0).unwrap().prove().unwrap();

		let prover_1 = WormholeProver::new(config.clone());
		let proof_1 = prover_1.commit(&inputs_1).unwrap().prove().unwrap();

		// Create aggregator
		let verifier = WormholeVerifier::new(config, None);
		let mut aggregator = WormholeProofAggregator::new(verifier.circuit_data);

		// Add both proofs
		aggregator.push_proof(proof_0).expect("Failed to push proof 0");
		aggregator.push_proof(proof_1).expect("Failed to push proof 1");

		// Aggregate
		let aggregated_result = aggregator.aggregate().expect("Aggregation failed");

		// Parse aggregated public inputs
		let aggregated_public_inputs = AggregatedPublicCircuitInputs::try_from_slice(
			aggregated_result.proof.public_inputs.as_slice(),
		)
		.expect("Failed to parse aggregated public inputs");

		// Verify we have 2 nullifiers (one per proof)
		assert_eq!(
			aggregated_public_inputs.nullifiers.len(),
			2,
			"Should have 2 nullifiers for 2 proofs"
		);

		// Verify all nullifiers are unique
		assert_ne!(
			aggregated_public_inputs.nullifiers[0], aggregated_public_inputs.nullifiers[1],
			"Nullifiers should be unique"
		);

		// Verify the aggregated proof
		aggregated_result
			.circuit_data
			.verify(aggregated_result.proof)
			.expect("Aggregated proof verification failed");
	}

	/// Test that public inputs parsing matches expected structure
	#[test]
	fn test_public_inputs_structure() {
		use qp_wormhole_circuit::inputs::{
			ASSET_ID_INDEX, BLOCK_HASH_END_INDEX, BLOCK_HASH_START_INDEX, BLOCK_NUMBER_INDEX,
			EXIT_ACCOUNT_END_INDEX, EXIT_ACCOUNT_START_INDEX, NULLIFIER_END_INDEX,
			NULLIFIER_START_INDEX, OUTPUT_AMOUNT_INDEX, PARENT_HASH_END_INDEX,
			PARENT_HASH_START_INDEX, PUBLIC_INPUTS_FELTS_LEN, VOLUME_FEE_BPS_INDEX,
		};

		// Verify expected public inputs layout
		assert_eq!(PUBLIC_INPUTS_FELTS_LEN, 20, "Public inputs should be 20 field elements");
		assert_eq!(ASSET_ID_INDEX, 0, "Asset ID should be first");
		assert_eq!(OUTPUT_AMOUNT_INDEX, 1, "Output amount should be second");
		assert_eq!(VOLUME_FEE_BPS_INDEX, 2, "Volume fee BPS should be third");
		assert_eq!(NULLIFIER_START_INDEX, 3, "Nullifier should start at index 3");
		assert_eq!(NULLIFIER_END_INDEX, 7, "Nullifier should end at index 7");
		assert_eq!(EXIT_ACCOUNT_START_INDEX, 7, "Exit account should start at index 7");
		assert_eq!(EXIT_ACCOUNT_END_INDEX, 11, "Exit account should end at index 11");
		assert_eq!(BLOCK_HASH_START_INDEX, 11, "Block hash should start at index 11");
		assert_eq!(BLOCK_HASH_END_INDEX, 15, "Block hash should end at index 15");
		assert_eq!(PARENT_HASH_START_INDEX, 15, "Parent hash should start at index 15");
		assert_eq!(PARENT_HASH_END_INDEX, 19, "Parent hash should end at index 19");
		assert_eq!(BLOCK_NUMBER_INDEX, 19, "Block number should be at index 19");
	}

	/// Test that constants match expected on-chain configuration
	#[test]
	fn test_constants_match_chain_config() {
		// Volume fee rate should be 10 bps (0.1%)
		assert_eq!(VOLUME_FEE_BPS, 10, "Volume fee should be 10 bps");

		// Native asset ID should be 0
		assert_eq!(NATIVE_ASSET_ID, 0, "Native asset ID should be 0");

		// Scale down factor should be 10^10 (12 decimals -> 2 decimals)
		assert_eq!(SCALE_DOWN_FACTOR, 10_000_000_000, "Scale down factor should be 10^10");

		// Verify scale down: 1 token with 12 decimals = 10^12 units
		// After quantization: 10^12 / 10^10 = 100 (which is 1.00 in 2 decimal places)
		let one_token_12_decimals: u128 = 1_000_000_000_000;
		let quantized = quantize_funding_amount(one_token_12_decimals).unwrap();
		assert_eq!(quantized, 100, "1 token should quantize to 100 (1.00 with 2 decimals)");
	}

	#[test]
	fn test_volume_fee_bps_constant() {
		// Ensure VOLUME_FEE_BPS matches expected value (10 bps = 0.1%)
		assert_eq!(VOLUME_FEE_BPS, 10);
	}
}

/// Parse and display the contents of a proof file for debugging
async fn parse_proof_file(proof_file: String, aggregated: bool) -> crate::error::Result<()> {
	use std::path::Path;

	log_print!("Parsing proof file: {}", proof_file);

	// Read proof bytes
	let proof_bytes = read_proof_file(&proof_file)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to read proof: {}", e)))?;

	log_print!("Proof size: {} bytes", proof_bytes.len());

	if aggregated {
		use plonky2::{
			plonk::circuit_data::CommonCircuitData, util::serialization::DefaultGateSerializer,
		};

		// Load aggregated circuit common data
		let bins_dir = Path::new("generated-bins");
		let common_bytes = std::fs::read(bins_dir.join("aggregated_common.bin")).map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Failed to read aggregated_common.bin: {}",
				e
			))
		})?;

		let gate_serializer = DefaultGateSerializer;
		let common_data = CommonCircuitData::<F, D>::from_bytes(common_bytes, &gate_serializer)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to deserialize aggregated common data: {:?}",
					e
				))
			})?;

		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &common_data)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to deserialize aggregated proof: {:?}",
					e
				))
			})?;

		log_print!("\nPublic inputs count: {}", proof.public_inputs.len());
		log_print!("\nPublic inputs (raw field elements):");
		for (i, pi) in proof.public_inputs.iter().enumerate() {
			use plonky2::field::types::PrimeField64;
			log_print!("  [{}] = {}", i, pi.to_canonical_u64());
		}

		// Try to parse as aggregated
		match AggregatedPublicCircuitInputs::try_from_slice(&proof.public_inputs) {
			Ok(agg_inputs) => {
				log_print!("\n=== Parsed Aggregated Public Inputs ===");
				log_print!("Asset ID: {}", agg_inputs.asset_id);
				log_print!("Volume Fee BPS: {}", agg_inputs.volume_fee_bps);
				log_print!(
					"Block Hash: 0x{}",
					hex::encode(agg_inputs.block_data.block_hash.as_ref())
				);
				log_print!("Block Number: {}", agg_inputs.block_data.block_number);
				log_print!("\nAccount Data ({} accounts):", agg_inputs.account_data.len());
				for (i, acct) in agg_inputs.account_data.iter().enumerate() {
					log_print!(
						"  [{}] amount={}, exit=0x{}",
						i,
						acct.summed_output_amount,
						hex::encode(acct.exit_account.as_ref())
					);
				}
				log_print!("\nNullifiers ({} nullifiers):", agg_inputs.nullifiers.len());
				for (i, nullifier) in agg_inputs.nullifiers.iter().enumerate() {
					log_print!("  [{}] 0x{}", i, hex::encode(nullifier.as_ref()));
				}
			},
			Err(e) => {
				log_print!("Failed to parse as aggregated inputs: {}", e);
			},
		}
	} else {
		// Parse as leaf proof
		let bins_dir = Path::new("generated-bins");
		let prover = qp_wormhole_prover::WormholeProver::new_from_files(
			&bins_dir.join("prover.bin"),
			&bins_dir.join("common.bin"),
		)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to load prover: {}", e))
		})?;

		let common_data = &prover.circuit_data.common;
		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, common_data)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!("Failed to deserialize proof: {}", e))
			})?;

		log_print!("\nPublic inputs count: {}", proof.public_inputs.len());

		let pi = PublicCircuitInputs::try_from(&proof).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to parse public inputs: {}", e))
		})?;

		log_print!("\n=== Parsed Leaf Public Inputs ===");
		log_print!("Asset ID: {}", pi.asset_id);
		log_print!("Output Amount 1: {}", pi.output_amount_1);
		log_print!("Output Amount 2: {}", pi.output_amount_2);
		log_print!("Volume Fee BPS: {}", pi.volume_fee_bps);
		log_print!("Nullifier: 0x{}", hex::encode(pi.nullifier.as_ref()));
		log_print!("Exit Account 1: 0x{}", hex::encode(pi.exit_account_1.as_ref()));
		log_print!("Exit Account 2: 0x{}", hex::encode(pi.exit_account_2.as_ref()));
		log_print!("Block Hash: 0x{}", hex::encode(pi.block_hash.as_ref()));
		log_print!("Parent Hash: 0x{}", hex::encode(pi.parent_hash.as_ref()));
		log_print!("Block Number: {}", pi.block_number);
	}

	Ok(())
}
