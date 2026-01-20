use crate::{
	chain::{
		client::{ChainConfig, QuantusClient},
		quantus_subxt::{self as quantus_node, api::wormhole},
	},
	cli::common::{submit_transaction, ExecutionMode},
	log_print, log_success, log_verbose,
	wallet::QuantumKeyPair,
};
use clap::Subcommand;
use plonky2::plonk::{circuit_data::CircuitConfig, proof::ProofWithPublicInputs};
use qp_poseidon::PoseidonHasher;
use qp_wormhole_circuit::inputs::{
	AggregatedPublicCircuitInputs, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs,
};
use qp_wormhole_circuit::nullifier::Nullifier;
use qp_wormhole_prover::WormholeProver;
use qp_wormhole_verifier::WormholeVerifier;
use qp_zk_circuits_common::{
	circuit::{C, D, F},
	storage_proof::prepare_proof_for_circuit,
	utils::{BytesDigest, Digest},
};
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	Hasher,
};
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
	/// Generate a wormhole proof
	Generate {
		/// Secret (32-byte hex string)
		#[arg(long)]
		secret: String,

		/// Funding amount to transfer
		#[arg(long)]
		amount: u128,

		/// Exit account (where funds will be withdrawn)
		#[arg(long)]
		exit_account: String,

		/// Wallet name to fund from
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

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

		/// Tree depth for aggregation (default: 1)
		#[arg(long, default_value = "1")]
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
}

pub async fn handle_wormhole_command(
	command: WormholeCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	match command {
		WormholeCommands::Generate {
			secret,
			amount,
			exit_account,
			from,
			password,
			password_file,
			output,
		} => {
			generate_proof(
				secret,
				amount,
				exit_account,
				from,
				password,
				password_file,
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
	}
}

pub type TransferProofKey = (u32, u64, AccountId32, AccountId32, u128);

async fn generate_proof(
	secret_hex: String,
	funding_amount: u128,
	exit_account_str: String,
	from_wallet: String,
	password: Option<String>,
	password_file: Option<String>,
	output_file: String,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("Generating wormhole proof...");

	// Parse secret
	let secret_bytes = hex::decode(secret_hex.trim_start_matches("0x"))
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid secret hex: {}", e)))?;
	if secret_bytes.len() != 32 {
		return Err(crate::error::QuantusError::Generic(
			"Secret must be exactly 32 bytes".to_string(),
		));
	}
	let secret_array: [u8; 32] = secret_bytes
		.try_into()
		.map_err(|_| crate::error::QuantusError::Generic("Failed to convert secret".to_string()))?;
	let secret: BytesDigest = secret_array.try_into().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to convert secret: {:?}", e))
	})?;

	// Parse exit account
	let exit_account_id = if let Some(exit_account) = exit_account_str.strip_prefix("0x") {
		let exit_account_bytes = hex::decode(exit_account).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid exit account hex: {}", e))
		})?;
		if exit_account_bytes.len() != 32 {
			return Err(crate::error::QuantusError::Generic(
				"Exit account must be 32 bytes".to_string(),
			));
		}
		SubxtAccountId(exit_account_bytes.try_into().map_err(|_| {
			crate::error::QuantusError::Generic("Failed to convert exit account".to_string())
		})?)
	} else {
		// Assume it's a wallet name, resolve it
		let resolved = crate::cli::common::resolve_address(&exit_account_str)?;
		let account_id = AccountId32::from_ss58check(&resolved).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid SS58 address: {}", e))
		})?;
		let bytes: [u8; 32] = account_id.into();
		SubxtAccountId(bytes)
	};

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;
	let client = quantus_client.client();

	log_verbose!("Connected to node");

	let funding_account = AccountId32::new(PoseidonHasher::hash(keypair.public_key.as_ref()).0);

	// Generate unspendable account
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

	log_verbose!("Unspendable account: {:?}", &unspendable_account_id);
	log_verbose!("Exit account: {:?}", &exit_account_id);

	// Transfer to unspendable account using wormhole pallet
	let transfer_tx = quantus_node::api::tx().wormhole().transfer_native(
		subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
		funding_amount,
	);

	log_verbose!("Submitting transfer to unspendable account...");

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

	let blocks = at_best_block(&quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let block_hash = blocks.hash();

	log_success!("Transfer included in block: {:?}", block_hash);

	let events_api = client
		.events()
		.at(block_hash)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let event = events_api
		.find::<wormhole::events::NativeTransferred>()
		.next()
		.ok_or_else(|| {
			crate::error::QuantusError::Generic("No NativeTransferred event found".to_string())
		})?
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	log_verbose!(
		"Transfer event: amount={}, transfer_count={}",
		event.amount,
		event.transfer_count
	);

	// Get storage proof
	let storage_api = client.storage().at(block_hash);

	// Convert subxt AccountId32 to sp_core AccountId32 for hash_storage
	let from_account = AccountId32::new(event.from.0);
	let to_account = AccountId32::new(event.to.0);

	let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferProofKey>(
		&(
			NATIVE_ASSET_ID,
			event.transfer_count,
			from_account.clone(),
			to_account.clone(),
			event.amount,
		)
			.encode(),
	);
	let proof_address = quantus_node::api::storage().wormhole().transfer_proof((
		NATIVE_ASSET_ID,
		event.transfer_count,
		event.from.clone(),
		event.to.clone(),
		event.amount,
	));
	let mut final_key = proof_address.to_root_bytes();
	final_key.extend_from_slice(&leaf_hash);
	let val = storage_api
		.fetch_raw(final_key.clone())
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	if val.is_none() {
		return Err(crate::error::QuantusError::Generic("Storage key not found".to_string()));
	}

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

	// Quantize the funding amount (from 12 decimal places to 2)
	// The circuit expects a u32 value.
	let input_amount_quantized: u32 =
		(funding_amount / SCALE_DOWN_FACTOR).try_into().map_err(|_| {
			crate::error::QuantusError::Generic(
				"Funding amount too large after quantization".to_string(),
			)
		})?;

	// Calculate output amount after fee deduction
	let output_amount_quantized = compute_output_amount(input_amount_quantized, VOLUME_FEE_BPS);

	let inputs = CircuitInputs {
		private: PrivateCircuitInputs {
			secret,
			transfer_count: event.transfer_count,
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
			output_amount: output_amount_quantized,
			volume_fee_bps: VOLUME_FEE_BPS,
			nullifier: Nullifier::from_preimage(secret, event.transfer_count).hash.into(),
			exit_account: BytesDigest::try_from(exit_account_id.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			block_hash: BytesDigest::try_from(block_hash.as_ref())
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			parent_hash,
			block_number,
			asset_id: NATIVE_ASSET_ID,
		},
	};

	log_verbose!("Generating ZK proof...");
	let config = CircuitConfig::standard_recursion_zk_config();
	let prover = WormholeProver::new(config);
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

	log_print!("Aggregating {} proofs...", proof_files.len());

	if proof_files.is_empty() {
		return Err(crate::error::QuantusError::Generic("No proof files provided".to_string()));
	}

	// Build the wormhole verifier to get circuit data for parsing proofs
	let config = CircuitConfig::standard_recursion_zk_config();
	let verifier = WormholeVerifier::new(config.clone(), None);
	let common_data = verifier.circuit_data.common.clone();

	// Configure aggregation
	let aggregation_config = TreeAggregationConfig::new(branching_factor, depth as u32);

	log_verbose!(
		"Aggregation config: branching_factor={}, depth={}, num_leaf_proofs={}",
		aggregation_config.tree_branching_factor,
		aggregation_config.tree_depth,
		aggregation_config.num_leaf_proofs
	);

	if proof_files.len() > aggregation_config.num_leaf_proofs {
		return Err(crate::error::QuantusError::Generic(format!(
			"Too many proofs: {} provided, max {} for depth={} branching_factor={}",
			proof_files.len(),
			aggregation_config.num_leaf_proofs,
			depth,
			branching_factor
		)));
	}

	// Create aggregator
	let mut aggregator =
		WormholeProofAggregator::new(verifier.circuit_data).with_config(aggregation_config);

	// Load and add proofs
	for (idx, proof_file) in proof_files.iter().enumerate() {
		log_verbose!("Loading proof {}/{}: {}", idx + 1, proof_files.len(), proof_file);

		let proof_hex = std::fs::read_to_string(proof_file).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to read {}: {}", proof_file, e))
		})?;

		let proof_bytes = hex::decode(proof_hex.trim()).map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Failed to decode hex from {}: {}",
				proof_file, e
			))
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

	// Save aggregated proof
	let proof_hex = hex::encode(aggregated_proof.proof.to_bytes());
	std::fs::write(&output_file, proof_hex).map_err(|e| {
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

	// Wait for transaction inclusion
	while let Some(Ok(status)) = tx_progress.next().await {
		log_verbose!("Transaction status: {:?}", status);
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				log_success!("Aggregated proof verified successfully on-chain!");
				log_verbose!("Included in block: {:?}", block_hash);
				return Ok(());
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				log_success!("Aggregated proof verified successfully on-chain!");
				log_verbose!("Finalized in block: {:?}", block_hash);
				return Ok(());
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

#[cfg(test)]
mod tests {
	use super::*;
	use plonky2::plonk::circuit_data::CircuitConfig;
	use qp_wormhole_circuit::inputs::{
		AggregatedPublicCircuitInputs, CircuitInputs, PublicCircuitInputs,
	};
	use qp_wormhole_prover::WormholeProver;
	use qp_wormhole_test_helpers::TestInputs;
	use qp_wormhole_verifier::WormholeVerifier;
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
		// Test the circuit fee constraint: output_amount * 10000 <= input_amount * (10000 - volume_fee_bps)
		// This is equivalent to: output <= input * (1 - fee_rate)

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
		let output_amount = inputs.public.output_amount;
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
		assert_eq!(parsed_public_inputs.output_amount, inputs.public.output_amount);
		assert_eq!(parsed_public_inputs.volume_fee_bps, inputs.public.volume_fee_bps);
		assert_eq!(parsed_public_inputs.nullifier, inputs.public.nullifier);
		assert_eq!(parsed_public_inputs.exit_account, inputs.public.exit_account);
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

		// Verify it's a reasonable value (less than 100% = 10000 bps)
		assert!(VOLUME_FEE_BPS < 10000);
	}
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

	// Wait for transaction inclusion
	while let Some(Ok(status)) = tx_progress.next().await {
		log_verbose!("Transaction status: {:?}", status);
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				log_success!("Proof verified successfully on-chain!");
				log_verbose!("Included in block: {:?}", block_hash);
				return Ok(());
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				log_success!("Proof verified successfully on-chain!");
				log_verbose!("Finalized in block: {:?}", block_hash);
				return Ok(());
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
