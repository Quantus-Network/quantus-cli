use crate::{
	chain::{
		client::{ChainConfig, QuantusClient},
		quantus_subxt::{self as quantus_node, api::wormhole},
	},
	cli::{
		address_format::{bytes_to_quantus_ss58, slice_to_quantus_ss58},
		common::{submit_transaction, ExecutionMode},
		send::get_balance,
	},
	log_error, log_print, log_success, log_verbose,
	wallet::{password, QuantumKeyPair, WalletManager},
};
use clap::Subcommand;
use indicatif::{ProgressBar, ProgressStyle};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_rusty_crystals_hdwallet::{
	derive_wormhole_from_mnemonic, generate_mnemonic, SensitiveBytes32, WormholePair,
	QUANTUS_WORMHOLE_CHAIN_ID,
};
use qp_wormhole_aggregator::{
	aggregator::{AggregationBackend, CircuitType},
	config::CircuitBinsConfig,
};
use qp_wormhole_circuit::inputs::ParseAggregatedPublicInputs;
use qp_wormhole_inputs::AggregatedPublicCircuitInputs;
use qp_zk_circuits_common::{
	circuit::{C, D, F},
	utils::BytesDigest,
};
use rand::RngCore;
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::path::Path;
use subxt::{
	blocks::Block,
	ext::{
		codec::Encode,
		jsonrpsee::{core::client::ClientT, rpc_params},
	},
	utils::AccountId32 as SubxtAccountId,
	OnlineClient,
};

// Re-export constants and functions from wormhole_lib module for backward compatibility
use crate::wormhole_lib;
pub use crate::wormhole_lib::{
	compute_output_amount, NATIVE_ASSET_ID, SCALE_DOWN_FACTOR, VOLUME_FEE_BPS,
};

// ============================================================================
// ZK Tree Types (for 4-ary Poseidon Merkle proofs)
// ============================================================================

/// A 32-byte hash output.
pub type Hash256 = [u8; 32];

/// Merkle proof from the ZK tree RPC.
///
/// This is the client-side representation of the proof returned by `zkTree_getMerkleProof`.
/// Siblings are unsorted - the client computes position hints by sorting siblings + current hash.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(dead_code)] // Fields used for deserialization and future use when ZK trie is deployed
pub struct ZkMerkleProofRpc {
	/// Index of the leaf
	pub leaf_index: u64,
	/// The leaf data (SCALE-encoded ZkLeaf)
	#[serde(with = "byte_array")]
	pub leaf_data: Vec<u8>,
	/// Leaf hash
	#[serde(with = "hash_array")]
	pub leaf_hash: Hash256,
	/// Sibling hashes at each level (3 siblings per level for 4-ary tree).
	/// These are unsorted - client sorts and computes positions.
	#[serde(with = "siblings_format")]
	pub siblings: Vec<[Hash256; 3]>,
	/// Current tree root
	#[serde(with = "hash_array")]
	pub root: Hash256,
	/// Current tree depth
	pub depth: u8,
}

/// Helper module for deserializing byte arrays (chain sends as array of numbers)
mod byte_array {
	use serde::{Deserialize, Deserializer};

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Vec::<u8>::deserialize(deserializer)
	}
}

/// Helper module for deserializing 32-byte hashes (chain sends as array of numbers)
mod hash_array {
	use serde::{Deserialize, Deserializer};

	pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
	where
		D: Deserializer<'de>,
	{
		let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
		bytes.try_into().map_err(|v: Vec<u8>| {
			serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
		})
	}
}

/// Helper module for deserializing siblings array (chain sends as array of arrays of numbers)
mod siblings_format {
	use serde::{Deserialize, Deserializer};

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[[u8; 32]; 3]>, D::Error>
	where
		D: Deserializer<'de>,
	{
		// Chain sends: Vec<[[u8; 32]; 3]> serialized as array of arrays of arrays of numbers
		let levels: Vec<Vec<Vec<u8>>> = Deserialize::deserialize(deserializer)?;
		levels
			.into_iter()
			.map(|level| {
				if level.len() != 3 {
					return Err(serde::de::Error::custom(format!(
						"expected 3 siblings per level, got {}",
						level.len()
					)));
				}
				let mut siblings = [[0u8; 32]; 3];
				for (i, bytes) in level.into_iter().enumerate() {
					siblings[i] = bytes.try_into().map_err(|v: Vec<u8>| {
						serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
					})?;
				}
				Ok(siblings)
			})
			.collect()
	}
}

/// Fetch a ZK Merkle proof from the chain via RPC at a specific block.
///
/// # Arguments
/// * `quantus_client` - The chain client
/// * `leaf_index` - The index of the leaf to get the proof for
/// * `at_block` - The block hash to fetch the proof at (MUST match the block you're proving
///   against)
///
/// # Returns
/// The Merkle proof if the leaf exists, or an error
///
/// # Important
/// The `at_block` parameter is critical for ZK proof generation. The tree root changes
/// with each block, so the Merkle proof MUST be fetched at the same block whose header
/// you're including in the ZK proof.
#[allow(dead_code)] // Will be used when ZK tree is deployed to production
pub async fn get_zk_merkle_proof(
	quantus_client: &QuantusClient,
	leaf_index: u64,
	at_block: subxt::utils::H256,
) -> crate::error::Result<ZkMerkleProofRpc> {
	let proof_params = rpc_params![leaf_index, at_block];
	let proof: Option<ZkMerkleProofRpc> = quantus_client
		.rpc_client()
		.request("zkTree_getMerkleProof", proof_params)
		.await
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"RPC error fetching proof at block {:?}: {}",
				at_block, e
			))
		})?;

	proof.ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"Leaf index {} not found in ZK tree at block {:?}",
			leaf_index, at_block
		))
	})
}

/// Compute sorted siblings and position hints from unsorted siblings.
///
/// The chain returns unsorted siblings at each level. This function:
/// 1. Combines current hash with the 3 siblings
/// 2. Sorts all 4 hashes
/// 3. Finds the position (0-3) of the current hash in the sorted order
/// 4. Extracts the 3 sorted siblings (excluding current hash)
/// 5. Computes the parent hash for the next level
///
/// # Arguments
/// * `unsorted_siblings` - Siblings at each level (3 per level), unsorted
/// * `leaf_hash` - The hash of the leaf
///
/// # Returns
/// A tuple of (sorted_siblings, positions) ready for the circuit
pub fn compute_merkle_positions(
	unsorted_siblings: &[[Hash256; 3]],
	leaf_hash: Hash256,
) -> (Vec<[Hash256; 3]>, Vec<u8>) {
	use qp_zk_circuits_common::zk_merkle::hash_node_presorted;

	let mut current_hash = leaf_hash;
	let mut sorted_siblings = Vec::with_capacity(unsorted_siblings.len());
	let mut positions = Vec::with_capacity(unsorted_siblings.len());

	for level_siblings in unsorted_siblings.iter() {
		// Combine current hash with the 3 siblings
		let mut all_four: [Hash256; 4] =
			[current_hash, level_siblings[0], level_siblings[1], level_siblings[2]];

		// Sort to get the order used by hash_node
		all_four.sort();

		// Find position of current_hash in sorted order
		let pos = all_four
			.iter()
			.position(|h| *h == current_hash)
			.expect("current hash must be in the array") as u8;
		positions.push(pos);

		// Extract the 3 siblings in sorted order (excluding current_hash)
		let sorted_sibs: [Hash256; 3] = {
			let mut sibs = [[0u8; 32]; 3];
			let mut sib_idx = 0;
			for (i, h) in all_four.iter().enumerate() {
				if i as u8 != pos {
					sibs[sib_idx] = *h;
					sib_idx += 1;
				}
			}
			sibs
		};
		sorted_siblings.push(sorted_sibs);

		// Compute parent hash for next level using Poseidon
		current_hash = hash_node_presorted(&all_four);
	}

	(sorted_siblings, positions)
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
	wormhole_lib::quantize_amount(amount).map_err(|e| e.message)
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

/// Randomly partition a total amount into n parts.
/// Each part will be at least `min_per_part` and the sum equals `total`.
/// Returns amounts aligned to SCALE_DOWN_FACTOR for clean quantization.
pub fn random_partition(total: u128, n: usize, min_per_part: u128) -> Vec<u128> {
	use rand::Rng;

	if n == 0 {
		return vec![];
	}
	if n == 1 {
		return vec![total];
	}

	// Ensure minimum is achievable
	let min_total = min_per_part * n as u128;
	if total < min_total {
		// Fall back to equal distribution if total is too small
		let per_part = total / n as u128;
		let remainder = total % n as u128;
		let mut parts: Vec<u128> = vec![per_part; n];
		// Add remainder to last part
		parts[n - 1] += remainder;
		return parts;
	}

	// Amount available for random distribution after ensuring minimums
	let distributable = total - min_total;

	// Generate n-1 random cut points in [0, distributable]
	let mut rng = rand::rng();
	let mut cuts: Vec<u128> = (0..n - 1).map(|_| rng.random_range(0..=distributable)).collect();
	cuts.sort();

	// Convert cuts to amounts
	let mut parts = Vec::with_capacity(n);
	let mut prev = 0u128;
	for cut in cuts {
		parts.push(min_per_part + (cut - prev));
		prev = cut;
	}
	parts.push(min_per_part + (distributable - prev));

	// Note: Input 'total' is already in quantized units (e.g., 998 = 9.98 DEV).
	// No further alignment is needed - just ensure the sum equals total.
	let sum: u128 = parts.iter().sum();
	let diff = total as i128 - sum as i128;
	if diff != 0 {
		// Add/subtract difference from a random part
		let idx = rng.random_range(0..n);
		parts[idx] = (parts[idx] as i128 + diff).max(0) as u128;
	}

	parts
}

/// Output assignment for a single proof (supports dual outputs)
#[derive(Debug, Clone)]
pub struct ProofOutputAssignment {
	/// Amount for output 1 (quantized, 2 decimal places)
	pub output_amount_1: u32,
	/// Exit account for output 1
	pub exit_account_1: [u8; 32],
	/// Amount for output 2 (quantized, 0 if unused)
	pub output_amount_2: u32,
	/// Exit account for output 2 (all zeros if unused)
	pub exit_account_2: [u8; 32],
}

/// Compute random output assignments for a set of proofs.
///
/// This takes the input amounts for each proof and randomly distributes the outputs
/// across the target exit accounts. Each proof can have up to 2 outputs.
///
/// # Algorithm:
/// 1. Compute total output amount (sum of inputs after fee deduction)
/// 2. Randomly partition total output across all target addresses
/// 3. Greedily assign outputs to proofs, using dual outputs when necessary
///
/// # Arguments
/// * `input_amounts` - The input amount for each proof (in planck, before fee)
/// * `target_accounts` - The exit accounts to distribute outputs to
/// * `fee_bps` - Fee in basis points
///
/// # Returns
/// A vector of output assignments, one per proof, or an error if quantization fails
pub fn compute_random_output_assignments(
	input_amounts: &[u128],
	target_accounts: &[[u8; 32]],
	fee_bps: u32,
) -> Result<Vec<ProofOutputAssignment>, String> {
	use rand::seq::SliceRandom;

	let num_proofs = input_amounts.len();
	let num_targets = target_accounts.len();

	if num_proofs == 0 || num_targets == 0 {
		return Ok(vec![]);
	}

	// Step 1: Compute output amounts per proof (after fee deduction)
	let mut proof_outputs: Vec<u32> = Vec::with_capacity(input_amounts.len());
	for (i, &input) in input_amounts.iter().enumerate() {
		let input_quantized = quantize_funding_amount(input).map_err(|e| {
			format!("Failed to quantize input amount {} for proof {}: {}", input, i, e)
		})?;
		proof_outputs.push(compute_output_amount(input_quantized, fee_bps));
	}

	let total_output: u64 = proof_outputs.iter().map(|&x| x as u64).sum();

	// Step 2: Randomly partition total output across target accounts
	// Minimum 3 quantized units (0.03 DEV) per target. After fee deduction in the
	// next round: compute_output_amount(3, 10) = 3 * 9990 / 10000 = 2, which is safe.
	// With 2: compute_output_amount(2, 10) = 1, borderline.
	// With 1: compute_output_amount(1, 10) = 0, causes circuit failure.
	let min_per_target = 3u128;
	let target_amounts_u128 = random_partition(total_output as u128, num_targets, min_per_target);
	let target_amounts: Vec<u32> = target_amounts_u128.iter().map(|&x| x as u32).collect();

	// Step 3: Assign outputs to proofs.
	// Each proof can have at most 2 outputs to different targets.
	//
	// Strategy:
	//   Pass 1 - Guarantee every target gets at least one output slot by round-robin
	//            assigning each target as output_1 of successive proofs.
	//   Pass 2 - Fill remaining capacity (output_2 slots and any leftover amounts)
	//            greedily from targets that still have remaining allocation.
	//
	// This ensures every target address appears in at least one proof output,
	// which is critical for the multiround flow where each target is a next-round
	// wormhole address that must receive minted tokens.

	let mut rng = rand::rng();

	// Track remaining needs per target
	let mut target_remaining: Vec<u32> = target_amounts.clone();

	// Pre-allocate assignments with output_1 = full proof output, output_2 = 0
	let mut assignments: Vec<ProofOutputAssignment> = proof_outputs
		.iter()
		.map(|&po| ProofOutputAssignment {
			output_amount_1: po,
			exit_account_1: [0u8; 32],
			output_amount_2: 0,
			exit_account_2: [0u8; 32],
		})
		.collect();

	// Pass 1: Round-robin assign each target to a proof's output_1.
	// If num_targets <= num_proofs, each target gets its own proof.
	// If num_targets > num_proofs, later targets share proofs via output_2.
	let mut shuffled_targets: Vec<usize> = (0..num_targets).collect();
	shuffled_targets.shuffle(&mut rng);

	for (assign_idx, &tidx) in shuffled_targets.iter().enumerate() {
		let proof_idx = assign_idx % num_proofs;
		let assignment = &mut assignments[proof_idx];

		if assignment.exit_account_1 == [0u8; 32] {
			// First target for this proof -> use output_1
			let assign = assignment.output_amount_1.min(target_remaining[tidx]);
			assignment.exit_account_1 = target_accounts[tidx];
			// We'll fix up the exact amounts in pass 2; for now just mark the account
			assignment.output_amount_1 = assign;
			target_remaining[tidx] -= assign;
		} else if assignment.exit_account_2 == [0u8; 32] {
			// Second target for this proof -> use output_2
			let avail = proof_outputs[proof_idx].saturating_sub(assignment.output_amount_1);
			let assign = avail.min(target_remaining[tidx]);
			assignment.exit_account_2 = target_accounts[tidx];
			assignment.output_amount_2 = assign;
			target_remaining[tidx] -= assign;
		}
		// If both slots taken, skip (shouldn't happen when num_targets <= 2*num_proofs)
	}

	// Pass 2: Distribute any remaining target allocations into available proof outputs.
	// Also ensure each proof's output_1 + output_2 == proof_outputs[i].
	for proof_idx in 0..num_proofs {
		let total_proof_output = proof_outputs[proof_idx];
		let current_sum =
			assignments[proof_idx].output_amount_1 + assignments[proof_idx].output_amount_2;
		let mut shortfall = total_proof_output.saturating_sub(current_sum);

		if shortfall > 0 {
			// Add shortfall to output_1 (its account is already set)
			assignments[proof_idx].output_amount_1 += shortfall;
			shortfall = 0;
		}

		// If output_1_account is still [0;32] (shouldn't happen), assign first target as fallback
		if assignments[proof_idx].exit_account_1 == [0u8; 32] && num_targets > 0 {
			assignments[proof_idx].exit_account_1 = target_accounts[0];
		}

		let _ = shortfall; // suppress unused warning
	}

	Ok(assignments)
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

			// Try to decode the error name and docs from metadata
			let error_info = metadata.pallet_by_index(module_error.index).and_then(|p| {
				p.error_variant_by_index(error_index)
					.map(|v| (v.name.clone(), v.docs.join(" ")))
			});

			match error_info {
				Some((name, docs)) if !docs.is_empty() => {
					format!("{}::{} ({})", pallet_name, name, docs)
				},
				Some((name, _)) => format!("{}::{}", pallet_name, name),
				None => format!("{}::Error[{}]", pallet_name, error_index),
			}
		},
		DispatchError::BadOrigin => "BadOrigin".to_string(),
		DispatchError::CannotLookup => "CannotLookup".to_string(),
		DispatchError::Other => "Other".to_string(),
		_ => format!("{:?}", error),
	}
}

#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
	/// Derive the unspendable wormhole address from a secret
	Address {
		/// Secret (32-byte hex string) - used to derive the unspendable account
		#[arg(long)]
		secret: String,
	},
	/// Generate a wormhole proof from an existing transfer
	Prove {
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

		/// ZK trie leaf index from the transfer event (for Merkle proof lookup)
		#[arg(long)]
		leaf_index: u64,

		/// Funding account (sender of transfer, hex or SS58)
		#[arg(long)]
		funding_account: String,

		/// Output file for the proof (default: proof.hex)
		#[arg(short, long, default_value = "proof.hex")]
		output: String,
	},
	/// Aggregate multiple wormhole proofs into a single proof
	Aggregate {
		/// Input proof files (hex-encoded)
		#[arg(short, long, num_args = 1..)]
		proofs: Vec<String>,

		/// Output file for the aggregated proof (default: aggregated_proof.hex)
		#[arg(short, long, default_value = "aggregated_proof.hex")]
		output: String,
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

		/// Verify the proof cryptographically (local verification, not on-chain)
		#[arg(long)]
		verify: bool,
	},
	/// Run a multi-round wormhole test: wallet -> wormhole -> ... -> wallet
	Multiround {
		/// Number of proofs per round (default: 2, max: 8)
		#[arg(short, long, default_value = "2")]
		num_proofs: usize,

		/// Number of rounds (default: 2)
		#[arg(short, long, default_value = "2")]
		rounds: usize,

		/// Total amount in DEV to partition across all proofs (default: 100)
		#[arg(short, long, default_value = "100")]
		amount: f64,

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
	/// Dissolve a large wormhole deposit into many small outputs for better privacy.
	///
	/// Creates a tree of wormhole transactions: each layer splits outputs into two,
	/// doubling the number of outputs until all are below the target size. This moves
	/// funds from a high-amount bucket (few deposits, low privacy score) into the
	/// low-amount bucket (many miner rewards, high privacy score).
	Dissolve {
		/// Amount in DEV to dissolve
		#[arg(short, long)]
		amount: f64,

		/// Target output size in DEV (stop splitting when all outputs are below this)
		#[arg(short, long, default_value = "1.0")]
		target_size: f64,

		/// Wallet name to use for funding
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
		#[arg(short, long, default_value = "/tmp/wormhole_dissolve")]
		output_dir: String,
	},
	/// Fuzz test the leaf verification by attempting invalid proofs
	Fuzz {
		/// Wallet name to use for funding
		#[arg(short, long)]
		wallet: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Amount in DEV to use for the test transfer (default: 1.0)
		#[arg(short, long, default_value = "1.0")]
		amount: f64,
	},
	/// Collect miner rewards from a wormhole address.
	///
	/// This command queries Subsquid for pending transfers to your wormhole address,
	/// generates ZK proofs, and submits a withdrawal transaction to claim your rewards.
	/// It mirrors the withdrawal flow used by the miner app.
	CollectRewards {
		/// Wallet name (used for HD derivation of wormhole secret and exit address)
		/// Either --wallet or --mnemonic must be provided.
		#[arg(short, long, required_unless_present = "mnemonic")]
		wallet: Option<String>,

		/// Mnemonic phrase for HD derivation (alternative to --wallet)
		/// Use this to derive wormhole secrets without a stored wallet.
		#[arg(short = 'm', long, required_unless_present = "wallet")]
		mnemonic: Option<String>,

		/// Password for the wallet (only used with --wallet)
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file (only used with --wallet)
		#[arg(long)]
		password_file: Option<String>,

		/// Amount in DEV to withdraw (default: withdraw all available)
		#[arg(short, long)]
		amount: Option<f64>,

		/// Destination address for withdrawn funds (required when using --mnemonic)
		#[arg(long)]
		destination: Option<String>,

		/// Subsquid indexer URL for querying transfers
		#[arg(long, default_value = "https://subsquid.quantus.com/blue/graphql")]
		subsquid_url: String,

		/// Wormhole address index for HD derivation (default: 0)
		#[arg(long, default_value = "0")]
		wormhole_index: usize,

		/// Output directory for proof files
		#[arg(short, long, default_value = "/tmp/wormhole_collect")]
		output_dir: String,

		/// Keep proof files after completion
		#[arg(short, long)]
		keep_files: bool,

		/// Dry run - show available transfers without withdrawing
		#[arg(long)]
		dry_run: bool,

		/// Specific block number to use for proofs (default: use latest block)
		#[arg(long)]
		at_block: Option<u32>,
	},
	/// Check if nullifiers have been spent (consumed by a withdrawal).
	///
	/// Given a secret (or wallet) and transfer count(s), computes the nullifier(s) and checks
	/// if they exist in Subsquid (meaning the corresponding transfer has been withdrawn).
	CheckNullifier {
		/// Secret (32-byte hex string) - the wormhole secret.
		/// Either --secret or --wallet must be provided.
		#[arg(long, required_unless_present = "wallet")]
		secret: Option<String>,

		/// Wallet name (used for HD derivation of wormhole secret).
		/// Either --secret or --wallet must be provided.
		#[arg(short, long, required_unless_present = "secret")]
		wallet: Option<String>,

		/// Password for the wallet (only used with --wallet)
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file (only used with --wallet)
		#[arg(long)]
		password_file: Option<String>,

		/// Wormhole address index for HD derivation (default: 0, only used with --wallet)
		#[arg(long, default_value = "0")]
		wormhole_index: usize,

		/// Transfer count(s) to check. Can be a single number or a range (e.g., "0-10")
		#[arg(long)]
		transfer_counts: String,

		/// Subsquid indexer URL for querying nullifiers
		#[arg(long, default_value = "https://subsquid.quantus.com/blue/graphql")]
		subsquid_url: String,
	},
}

pub async fn handle_wormhole_command(
	command: WormholeCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	match command {
		WormholeCommands::Address { secret } => show_wormhole_address(secret),
		WormholeCommands::Prove {
			secret,
			amount,
			exit_account,
			block,
			transfer_count,
			leaf_index,
			funding_account,
			output,
		} => {
			log_print!("Generating proof from existing transfer...");

			// Connect to node
			let quantus_client = QuantusClient::new(node_url).await.map_err(|e| {
				crate::error::QuantusError::Generic(format!("Failed to connect: {}", e))
			})?;

			// Parse exit account
			let exit_account_bytes =
				parse_exit_account(&exit_account).map_err(crate::error::QuantusError::Generic)?;

			// Quantize amount and compute output (single output, no change)
			let input_amount_quantized =
				quantize_funding_amount(amount).map_err(crate::error::QuantusError::Generic)?;
			let output_amount = compute_output_amount(input_amount_quantized, VOLUME_FEE_BPS);

			let output_assignment = ProofOutputAssignment {
				output_amount_1: output_amount,
				exit_account_1: exit_account_bytes,
				output_amount_2: 0,
				exit_account_2: [0u8; 32],
			};

			let prove_start = std::time::Instant::now();
			generate_proof(
				&secret,
				amount,
				&output_assignment,
				&block,
				transfer_count,
				&funding_account,
				leaf_index,
				&output,
				&quantus_client,
			)
			.await?;
			let prove_elapsed = prove_start.elapsed();
			log_print!("Proof generation: {:.2}s", prove_elapsed.as_secs_f64());
			Ok(())
		},
		WormholeCommands::Aggregate { proofs, output } => aggregate_proofs(proofs, output).await,
		WormholeCommands::VerifyAggregated { proof } =>
			verify_aggregated_proof(proof, node_url).await,
		WormholeCommands::ParseProof { proof, aggregated, verify } =>
			parse_proof_file(proof, aggregated, verify).await,
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
			// Convert DEV to planck and align to SCALE_DOWN_FACTOR for clean quantization
			let amount_planck = (amount * 1_000_000_000_000.0) as u128;
			let amount_aligned = (amount_planck / SCALE_DOWN_FACTOR) * SCALE_DOWN_FACTOR;
			run_multiround(
				num_proofs,
				rounds,
				amount_aligned,
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
		WormholeCommands::Dissolve {
			amount,
			target_size,
			wallet,
			password,
			password_file,
			keep_files,
			output_dir,
		} => {
			let amount_planck = (amount * 1_000_000_000_000.0) as u128;
			let amount_aligned = (amount_planck / SCALE_DOWN_FACTOR) * SCALE_DOWN_FACTOR;
			let target_planck = (target_size * 1_000_000_000_000.0) as u128;
			let target_aligned = (target_planck / SCALE_DOWN_FACTOR) * SCALE_DOWN_FACTOR;
			run_dissolve(
				amount_aligned,
				target_aligned,
				wallet,
				password,
				password_file,
				keep_files,
				output_dir,
				node_url,
			)
			.await
		},
		WormholeCommands::Fuzz { wallet: _, password: _, password_file: _, amount: _ } => {
			// TODO: Re-enable fuzz tests once ZK tree is deployed to a test chain.
			// The fuzz tests need to be rewritten to use zkTree_getMerkleProof RPC
			// instead of the old state_getReadProof storage proofs.
			// See run_fuzz_test() and try_generate_fuzz_proof() below for the old implementation.
			Err(crate::error::QuantusError::Generic(
				"Fuzz testing is temporarily disabled during the migration to ZK tree proofs. \
				 The fuzz tests require a chain with pallet-zk-tree deployed and the \
				 zkTree_getMerkleProof RPC endpoint available."
					.to_string(),
			))
		},
		WormholeCommands::CollectRewards {
			wallet,
			mnemonic,
			password,
			password_file,
			amount,
			destination,
			subsquid_url,
			wormhole_index,
			output_dir,
			keep_files,
			dry_run,
			at_block,
		} =>
			run_collect_rewards(
				wallet,
				mnemonic,
				password,
				password_file,
				amount,
				destination,
				subsquid_url,
				wormhole_index,
				output_dir,
				keep_files,
				dry_run,
				node_url,
				at_block,
			)
			.await,
		WormholeCommands::CheckNullifier {
			secret,
			wallet,
			password,
			password_file,
			wormhole_index,
			transfer_counts,
			subsquid_url,
		} =>
			run_check_nullifier(
				secret,
				wallet,
				password,
				password_file,
				wormhole_index,
				transfer_counts,
				subsquid_url,
			)
			.await,
	}
}

// NOTE: TransferProofKey and TransferProofData type aliases were removed during
// the migration to ZK tree. The new ZK leaf structure is:
// (to: AccountId32, transfer_count: u64, asset_id: u32, amount: u32)
// No longer includes `from` (funding_account).

/// Derive and display the unspendable wormhole address from a secret.
/// Users can then send funds to this address using `quantus send`.
fn show_wormhole_address(secret_hex: String) -> crate::error::Result<()> {
	use colored::Colorize;

	let secret_array =
		parse_secret_hex(&secret_hex).map_err(crate::error::QuantusError::Generic)?;
	let secret: BytesDigest = secret_array.try_into().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to convert secret: {:?}", e))
	})?;

	let unspendable_account =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret)
			.account_id;
	let unspendable_account_bytes_digest =
		qp_zk_circuits_common::utils::digest_to_bytes(unspendable_account);
	let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
		.as_ref()
		.try_into()
		.expect("BytesDigest is always 32 bytes");

	let account_id = sp_core::crypto::AccountId32::new(unspendable_account_bytes);
	let ss58_address =
		account_id.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));

	log_print!("{}", "Wormhole Address".bright_cyan());
	log_print!("  SS58:  {}", ss58_address.bright_green());
	log_print!("  Hex:   0x{}", hex::encode(unspendable_account_bytes));
	log_print!("");
	log_print!("To fund this address:");
	log_print!("  quantus send --from <wallet> --to {} --amount <amount>", ss58_address);

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
) -> crate::error::Result<()> {
	use qp_wormhole_aggregator::aggregator::{AggregationBackend, CircuitType, Layer0Aggregator};

	use std::path::Path;

	log_print!("Aggregating {} proofs...", proof_files.len());

	// Load config first to validate and calculate padding needs
	let bins_dir = Path::new("generated-bins");
	let agg_config = CircuitBinsConfig::load(bins_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to load circuit bins config from {:?}: {}",
			bins_dir, e
		))
	})?;

	// Validate number of proofs before doing expensive work
	if proof_files.len() > agg_config.num_leaf_proofs {
		return Err(crate::error::QuantusError::Generic(format!(
			"Too many proofs: {} provided, max {} supported by circuit",
			proof_files.len(),
			agg_config.num_leaf_proofs
		)));
	}

	let num_padding_proofs = agg_config.num_leaf_proofs - proof_files.len();

	log_print!("  Loading aggregator and generating {} dummy proofs...", num_padding_proofs);

	let mut aggregator = Layer0Aggregator::new(bins_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to load aggregator from pre-built bins: {}",
			e
		))
	})?;

	log_verbose!("Aggregation config: num_leaf_proofs={}", aggregator.batch_size());
	let common_data = aggregator.load_common_data(CircuitType::Leaf).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to load leaf circuit data: {}", e))
	})?;

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

	log_print!("  Running aggregation...");
	let agg_start = std::time::Instant::now();
	let aggregated_proof = aggregator
		.aggregate()
		.map_err(|e| crate::error::QuantusError::Generic(format!("Aggregation failed: {}", e)))?;
	let agg_elapsed = agg_start.elapsed();
	log_print!("  Aggregation: {:.2}s", agg_elapsed.as_secs_f64());

	// Parse and display aggregated public inputs
	let aggregated_public_inputs =
		AggregatedPublicCircuitInputs::try_from_felts(aggregated_proof.public_inputs.as_slice())
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
			let ss58_address = slice_to_quantus_ss58(exit_bytes);
			log_print!(
				"    [{}] {} -> {} quantized ({} planck = {})",
				idx,
				ss58_address,
				account_data.summed_output_amount,
				dequantized_amount,
				format_balance(dequantized_amount)
			);
		}
	}

	// Verify the aggregated proof locally
	log_verbose!("Verifying aggregated proof locally...");
	aggregator.verify(aggregated_proof.clone()).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Aggregated proof verification failed: {}", e))
	})?;

	// Save aggregated proof using helper function
	write_proof_file(&output_file, &aggregated_proof.to_bytes()).map_err(|e| {
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

#[derive(Debug, Clone, Copy)]
enum IncludedAt {
	Best,
	Finalized,
}

impl IncludedAt {
	fn label(self) -> &'static str {
		match self {
			IncludedAt::Best => "best block",
			IncludedAt::Finalized => "finalized block",
		}
	}
}

fn read_hex_proof_file_to_bytes(proof_file: &str) -> crate::error::Result<Vec<u8>> {
	let proof_hex = std::fs::read_to_string(proof_file).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read proof file: {}", e))
	})?;

	let proof_bytes = hex::decode(proof_hex.trim())
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to decode hex: {}", e)))?;

	Ok(proof_bytes)
}

/// Submit unsigned verify_aggregated_proof(proof_bytes) and return (included_at, block_hash,
/// tx_hash).
async fn submit_unsigned_verify_aggregated_proof(
	quantus_client: &QuantusClient,
	proof_bytes: Vec<u8>,
) -> crate::error::Result<(IncludedAt, subxt::utils::H256, subxt::utils::H256)> {
	use subxt::tx::TxStatus;

	let verify_tx = quantus_node::api::tx().wormhole().verify_aggregated_proof(proof_bytes);

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
				return Ok((
					IncludedAt::Best,
					tx_in_block.block_hash(),
					tx_in_block.extrinsic_hash(),
				));
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				return Ok((
					IncludedAt::Finalized,
					tx_in_block.block_hash(),
					tx_in_block.extrinsic_hash(),
				));
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

/// Collect wormhole events for our extrinsic (by tx_hash) in a given block.
/// Returns (found_proof_verified, native_transfers).
async fn collect_wormhole_events_for_extrinsic(
	quantus_client: &QuantusClient,
	block_hash: subxt::utils::H256,
	tx_hash: subxt::utils::H256,
) -> crate::error::Result<(bool, Vec<wormhole::events::NativeTransferred>)> {
	use crate::chain::quantus_subxt::api::system::events::ExtrinsicFailed;

	let block =
		quantus_client.client().blocks().at(block_hash).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
		})?;

	let events = block
		.events()
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to get events: {}", e)))?;

	let extrinsics = block.extrinsics().await.map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to get extrinsics: {}", e))
	})?;

	let our_ext_idx = extrinsics
		.iter()
		.enumerate()
		.find(|(_, ext)| ext.hash() == tx_hash)
		.map(|(idx, _)| idx as u32)
		.ok_or_else(|| {
			crate::error::QuantusError::Generic(
				"Could not find submitted extrinsic in included block".to_string(),
			)
		})?;

	let mut transfer_events = Vec::new();
	let mut found_proof_verified = false;

	log_verbose!("  Events for our extrinsic (idx={}):", our_ext_idx);

	for event_result in events.iter() {
		let event = event_result.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to decode event: {}", e))
		})?;

		if let subxt::events::Phase::ApplyExtrinsic(ext_idx) = event.phase() {
			if ext_idx == our_ext_idx {
				log_print!("    Event: {}::{}", event.pallet_name(), event.variant_name());

				// Decode ExtrinsicFailed to get the specific error
				if let Ok(Some(ExtrinsicFailed { dispatch_error, .. })) =
					event.as_event::<ExtrinsicFailed>()
				{
					let metadata = quantus_client.client().metadata();
					let error_msg = format_dispatch_error(&dispatch_error, &metadata);
					log_print!("    DispatchError: {}", error_msg);
				}

				if let Ok(Some(_)) = event.as_event::<wormhole::events::ProofVerified>() {
					found_proof_verified = true;
				}

				if let Ok(Some(transfer)) = event.as_event::<wormhole::events::NativeTransferred>()
				{
					transfer_events.push(transfer);
				}
			}
		}
	}

	Ok((found_proof_verified, transfer_events))
}

async fn verify_aggregated_proof(proof_file: String, node_url: &str) -> crate::error::Result<()> {
	log_print!("Verifying aggregated wormhole proof on-chain...");

	let proof_bytes = read_hex_proof_file_to_bytes(&proof_file)?;
	log_verbose!("Aggregated proof size: {} bytes", proof_bytes.len());

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;
	log_verbose!("Connected to node");

	log_verbose!("Submitting unsigned aggregated verification transaction...");

	let (included_at, block_hash, tx_hash) =
		submit_unsigned_verify_aggregated_proof(&quantus_client, proof_bytes).await?;

	// One unified check (no best/finalized copy-paste)
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

		log_print!("  Block: 0x{}", hex::encode(block_hash.0));
		log_print!("  Extrinsic: 0x{}", hex::encode(tx_hash.0));
		log_verbose!("Included in {}: {:?}", included_at.label(), block_hash);
		return Ok(());
	}

	let error_msg = result.error_message.unwrap_or_else(|| {
		"Aggregated proof verification failed - no ProofVerified event found".to_string()
	});
	log_error!("❌ {}", error_msg);
	Err(crate::error::QuantusError::Generic(error_msg))
}

// ============================================================================
// Multi-round wormhole flow implementation
// ============================================================================

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
	/// Index of this transfer in the ZK trie (for Merkle proof lookup)
	leaf_index: u64,
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

/// Parse transfer info from NativeTransferred events in a block and updates block hash for all
/// transfers
fn parse_transfer_events(
	events: &[wormhole::events::NativeTransferred],
	expected_addresses: &[SubxtAccountId],
	block_hash: subxt::utils::H256,
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
			block_hash,
			transfer_count: matching_event.transfer_count,
			amount: matching_event.amount,
			wormhole_address: expected_addr.clone(),
			funding_account: matching_event.from.clone(),
			leaf_index: matching_event.leaf_index,
		});
	}

	Ok(transfer_infos)
}

/// Configuration for multiround execution
struct MultiroundConfig {
	num_proofs: usize,
	rounds: usize,
	amount: u128,
	output_dir: String,
	keep_files: bool,
}

/// Wallet context for multiround execution
struct MultiroundWalletContext {
	wallet_name: String,
	wallet_address: String,
	wallet_account_id: SubxtAccountId,
	keypair: QuantumKeyPair,
	mnemonic: String,
}

/// Validate multiround parameters
fn validate_multiround_params(
	num_proofs: usize,
	rounds: usize,
	max_proofs: usize,
) -> crate::error::Result<()> {
	if !(1..=max_proofs).contains(&num_proofs) {
		return Err(crate::error::QuantusError::Generic(format!(
			"num_proofs must be between 1 and {} (got: {})",
			max_proofs, num_proofs
		)));
	}
	if rounds < 1 {
		return Err(crate::error::QuantusError::Generic(format!(
			"rounds must be at least 1 (got: {})",
			rounds
		)));
	}
	Ok(())
}

/// Load wallet and prepare context for multiround execution
fn load_multiround_wallet(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<MultiroundWalletContext> {
	let wallet_manager = WalletManager::new()?;
	let wallet_password = password::get_wallet_password(wallet_name, password, password_file)?;
	let wallet_data = wallet_manager.load_wallet(wallet_name, &wallet_password)?;
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

	Ok(MultiroundWalletContext {
		wallet_name: wallet_name.to_string(),
		wallet_address,
		wallet_account_id,
		keypair: wallet_data.keypair,
		mnemonic,
	})
}

/// Print multiround configuration summary
fn print_multiround_config(
	config: &MultiroundConfig,
	wallet: &MultiroundWalletContext,
	num_leaf_proofs: usize,
) {
	use colored::Colorize;

	log_print!("{}", "Configuration:".bright_cyan());
	log_print!("  Wallet: {}", wallet.wallet_name);
	log_print!("  Wallet address: {}", wallet.wallet_address);
	log_print!(
		"  Total amount: {} ({}) - randomly partitioned across {} proofs",
		config.amount,
		format_balance(config.amount),
		config.num_proofs
	);
	log_print!("  Proofs per round: {}", config.num_proofs);
	log_print!("  Rounds: {}", config.rounds);
	log_print!("  Aggregation: num_leaf_proofs={}", num_leaf_proofs);
	log_print!("  Output directory: {}", config.output_dir);
	log_print!("  Keep files: {}", config.keep_files);
	log_print!("");

	// Show expected amounts per round
	log_print!("{}", "Expected amounts per round:".bright_cyan());
	for r in 1..=config.rounds {
		let round_amount = calculate_round_amount(config.amount, r);
		log_print!("  Round {}: {} ({})", r, round_amount, format_balance(round_amount));
	}
	log_print!("");
}

/// Execute initial transfers from wallet to wormhole addresses (round 1 only).
///
/// Sends all transfers in a single batched extrinsic using `utility.batch()`.
/// Transfer counts are queried from chain storage (not events) to determine the
/// `transfer_count` for each recipient, which is needed for proof generation.
///
/// Note: We query `TransferCount` storage BEFORE submitting the batch because
/// the transfer_count in the proof must be the value at the time of transfer
/// (i.e., before the increment that happens during `record_transfer`).
async fn execute_initial_transfers(
	quantus_client: &QuantusClient,
	wallet: &MultiroundWalletContext,
	secrets: &[WormholePair],
	amount: u128,
	num_proofs: usize,
) -> crate::error::Result<Vec<TransferInfo>> {
	use colored::Colorize;
	use quantus_node::api::runtime_types::{
		pallet_balances::pallet::Call as BalancesCall, quantus_runtime::RuntimeCall,
	};

	log_print!("{}", "Step 1: Sending batched transfer to wormhole addresses...".bright_yellow());

	// Randomly partition the total amount among proofs
	// Each partition must meet the on-chain minimum transfer amount
	// Minimum per partition is 0.02 DEV (2 quantized units) to ensure non-trivial amounts
	let partition_amounts = random_partition(amount, num_proofs, 3 * SCALE_DOWN_FACTOR);
	log_print!("  Random partition of {} ({}):", amount, format_balance(amount));
	for (i, &amt) in partition_amounts.iter().enumerate() {
		log_print!("    Proof {}: {} ({})", i + 1, amt, format_balance(amt));
	}

	// Build batch of transfer calls
	let mut calls = Vec::with_capacity(num_proofs);
	for (i, secret) in secrets.iter().enumerate() {
		let wormhole_address = SubxtAccountId(secret.address);
		let transfer_call = RuntimeCall::Balances(BalancesCall::transfer_allow_death {
			dest: subxt::ext::subxt_core::utils::MultiAddress::Id(wormhole_address),
			value: partition_amounts[i],
		});
		calls.push(transfer_call);
	}

	let batch_tx = quantus_node::api::tx().utility().batch(calls);

	let quantum_keypair = QuantumKeyPair {
		public_key: wallet.keypair.public_key.clone(),
		private_key: wallet.keypair.private_key.clone(),
	};

	log_print!("  Submitting batch of {} transfers...", num_proofs);

	// Query transfer counts BEFORE submitting the batch.
	// The transfer_count used in the proof is the count at the time of transfer,
	// which equals the count before the transfer (since it increments after).
	let client = quantus_client.client();
	let mut transfer_counts_before: Vec<u64> = Vec::with_capacity(num_proofs);
	for secret in secrets.iter() {
		let wormhole_address = SubxtAccountId(secret.address);
		let count = client
			.storage()
			.at_latest()
			.await
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!("Failed to get storage: {}", e))
			})?
			.fetch(&quantus_node::api::storage().wormhole().transfer_count(wormhole_address))
			.await
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to fetch transfer count for {}: {}",
					hex::encode(secret.address),
					e
				))
			})?
			.unwrap_or(0);
		transfer_counts_before.push(count);
	}

	submit_transaction(
		quantus_client,
		&quantum_keypair,
		batch_tx,
		None,
		ExecutionMode { finalized: false, wait_for_transaction: true },
	)
	.await
	.map_err(|e| crate::error::QuantusError::Generic(format!("Batch transfer failed: {}", e)))?;

	// Get the block hash for the transfer info
	let block = at_best_block(quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to get block: {}", e)))?;
	let block_hash = block.hash();

	// Fetch events from the block to get leaf_index values
	let events_api =
		quantus_client.client().events().at(block_hash).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get events: {}", e))
		})?;

	// Build transfer info using the transfer counts we captured before the batch
	// and leaf_index from events
	let funding_account: SubxtAccountId = SubxtAccountId(wallet.keypair.to_account_id_32().into());
	let mut transfers = Vec::with_capacity(num_proofs);

	for (i, secret) in secrets.iter().enumerate() {
		let wormhole_address = SubxtAccountId(secret.address);

		// Find the matching event to get leaf_index
		let event = events_api
			.find::<wormhole::events::NativeTransferred>()
			.find(|e| {
				if let Ok(evt) = e {
					evt.to == wormhole_address && evt.transfer_count == transfer_counts_before[i]
				} else {
					false
				}
			})
			.ok_or_else(|| {
				crate::error::QuantusError::Generic(format!(
					"No transfer event found for address {}",
					hex::encode(secret.address)
				))
			})?
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!("Event decode error: {}", e))
			})?;

		transfers.push(TransferInfo {
			block_hash,
			transfer_count: transfer_counts_before[i],
			amount: partition_amounts[i],
			wormhole_address,
			funding_account: funding_account.clone(),
			leaf_index: event.leaf_index,
		});
	}

	log_success!(
		"  {} transfers submitted in a single batch (block {})",
		num_proofs,
		hex::encode(block_hash.0)
	);

	Ok(transfers)
}

/// Generate proofs for a round with random output partitioning
async fn generate_round_proofs(
	quantus_client: &QuantusClient,
	secrets: &[WormholePair],
	transfers: &[TransferInfo],
	exit_accounts: &[SubxtAccountId],
	round_dir: &str,
	num_proofs: usize,
) -> crate::error::Result<Vec<String>> {
	use colored::Colorize;

	log_print!("{}", "Step 2: Generating proofs...".bright_yellow());

	// All proofs in an aggregation batch must use the same block for storage proofs.
	let proof_block = at_best_block(quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to get block: {}", e)))?;
	let proof_block_hash = proof_block.hash();
	log_print!("  Using block {} for all proofs", hex::encode(proof_block_hash.0));

	// Collect input amounts and exit accounts for random assignment
	let input_amounts: Vec<u128> = transfers.iter().map(|t| t.amount).collect();
	let exit_account_bytes: Vec<[u8; 32]> = exit_accounts.iter().map(|a| a.0).collect();

	// Compute random output assignments (each proof can have 2 outputs)
	let output_assignments =
		compute_random_output_assignments(&input_amounts, &exit_account_bytes, VOLUME_FEE_BPS)
			.map_err(|e| crate::error::QuantusError::Generic(e))?;

	// Log the random partition
	log_print!("  Random output partition:");
	for (i, assignment) in output_assignments.iter().enumerate() {
		let amt1_planck = (assignment.output_amount_1 as u128) * SCALE_DOWN_FACTOR;
		let ss58_1 = bytes_to_quantus_ss58(&assignment.exit_account_1);
		if assignment.output_amount_2 > 0 {
			let amt2_planck = (assignment.output_amount_2 as u128) * SCALE_DOWN_FACTOR;
			let ss58_2 = bytes_to_quantus_ss58(&assignment.exit_account_2);
			log_print!(
				"    Proof {}: {} ({}) -> {}, {} ({}) -> {}",
				i + 1,
				assignment.output_amount_1,
				format_balance(amt1_planck),
				ss58_1,
				assignment.output_amount_2,
				format_balance(amt2_planck),
				ss58_2
			);
		} else {
			log_print!(
				"    Proof {}: {} ({}) -> {}",
				i + 1,
				assignment.output_amount_1,
				format_balance(amt1_planck),
				ss58_1
			);
		}
	}

	let pb = ProgressBar::new(num_proofs as u64);
	pb.set_style(
		ProgressStyle::default_bar()
			.template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
			.unwrap()
			.progress_chars("#>-"),
	);

	let proof_gen_start = std::time::Instant::now();
	let mut proof_files = Vec::new();
	for (i, (secret, transfer)) in secrets.iter().zip(transfers.iter()).enumerate() {
		pb.set_message(format!("Proof {}/{}", i + 1, num_proofs));

		let proof_file = format!("{}/proof_{}.hex", round_dir, i + 1);

		// Use the funding account from the transfer info
		let funding_account_hex = format!("0x{}", hex::encode(transfer.funding_account.0));

		let single_start = std::time::Instant::now();

		// Generate proof with dual output assignment
		generate_proof(
			&hex::encode(secret.secret),
			transfer.amount, // Use actual transfer amount for storage key
			&output_assignments[i],
			&format!("0x{}", hex::encode(proof_block_hash.0)),
			transfer.transfer_count,
			&funding_account_hex,
			transfer.leaf_index, // ZK trie leaf index for Merkle proof lookup
			&proof_file,
			quantus_client,
		)
		.await?;

		let single_elapsed = single_start.elapsed();
		log_verbose!("  Proof {} generated in {:.2}s", i + 1, single_elapsed.as_secs_f64());

		proof_files.push(proof_file);
		pb.inc(1);
	}
	pb.finish_with_message("Proofs generated");
	let proof_gen_elapsed = proof_gen_start.elapsed();
	log_print!(
		"  Proof generation: {:.2}s ({} proofs, {:.2}s avg)",
		proof_gen_elapsed.as_secs_f64(),
		num_proofs,
		proof_gen_elapsed.as_secs_f64() / num_proofs as f64,
	);

	Ok(proof_files)
}

/// Derive wormhole secrets for a round
fn derive_round_secrets(
	mnemonic: &str,
	round: usize,
	num_proofs: usize,
) -> crate::error::Result<Vec<WormholePair>> {
	let pb = ProgressBar::new(num_proofs as u64);
	pb.set_style(
		ProgressStyle::default_bar()
			.template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
			.unwrap()
			.progress_chars("#>-"),
	);
	pb.set_message("Deriving secrets...");

	let mut secrets = Vec::new();
	for i in 1..=num_proofs {
		let secret = derive_wormhole_secret(mnemonic, round, i)?;
		secrets.push(secret);
		pb.inc(1);
	}
	pb.finish_with_message("Secrets derived");

	Ok(secrets)
}

/// Verify final balance and print summary
fn verify_final_balance(
	initial_balance: u128,
	final_balance: u128,
	total_sent: u128,
	rounds: usize,
	num_proofs: usize,
) {
	use colored::Colorize;

	log_print!("{}", "Balance Verification:".bright_cyan());

	// Total received in final round: apply fee deduction for each round
	let total_received = calculate_round_amount(total_sent, rounds);

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

	// Allow some tolerance for transaction fees
	let tolerance = (total_sent / 100).max(1_000_000_000_000); // 1% or 1 QNT minimum

	let diff = (actual_change - expected_change).unsigned_abs();
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

	// Load aggregation config from generated-bins/config.json
	let bins_dir = Path::new("generated-bins");
	let agg_config = CircuitBinsConfig::load(bins_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to load aggregation config: {}", e))
	})?;

	// Validate parameters
	validate_multiround_params(num_proofs, rounds, agg_config.num_leaf_proofs)?;

	// Load wallet
	let wallet = load_multiround_wallet(&wallet_name, password, password_file)?;

	// Create config struct
	let config =
		MultiroundConfig { num_proofs, rounds, amount, output_dir: output_dir.clone(), keep_files };

	// Print configuration
	print_multiround_config(&config, &wallet, agg_config.num_leaf_proofs);
	log_print!("  Dry run: {}", dry_run);
	log_print!("");

	// Create output directory
	std::fs::create_dir_all(&output_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create output directory: {}", e))
	})?;

	if dry_run {
		return run_multiround_dry_run(
			&wallet.mnemonic,
			num_proofs,
			rounds,
			amount,
			&wallet.wallet_address,
		);
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
	let initial_balance = get_balance(&quantus_client, &wallet.wallet_address).await?;
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
		let secrets = derive_round_secrets(&wallet.mnemonic, round, num_proofs)?;

		// Determine exit accounts
		let exit_accounts: Vec<SubxtAccountId> = if is_final {
			log_print!("Final round - all proofs exit to wallet: {}", wallet.wallet_address);
			vec![wallet.wallet_account_id.clone(); num_proofs]
		} else {
			log_print!(
				"Intermediate round - proofs exit to round {} wormhole addresses",
				round + 1
			);
			let mut addrs = Vec::new();
			for i in 1..=num_proofs {
				let next_secret = derive_wormhole_secret(&wallet.mnemonic, round + 1, i)?;
				addrs.push(SubxtAccountId(next_secret.address));
			}
			addrs
		};

		// Step 1: Get transfer info (execute transfers for round 1, reuse from previous round
		// otherwise)
		if round == 1 {
			current_transfers =
				execute_initial_transfers(&quantus_client, &wallet, &secrets, amount, num_proofs)
					.await?;

			// Log balance immediately after funding transfers
			let balance_after_funding =
				get_balance(&quantus_client, &wallet.wallet_address).await?;
			let funding_deducted = initial_balance.saturating_sub(balance_after_funding);
			log_print!(
				"  Balance after funding: {} ({}) [deducted: {} planck]",
				balance_after_funding,
				format_balance(balance_after_funding),
				funding_deducted
			);
		} else {
			log_print!("{}", "Step 1: Using transfer info from previous round...".bright_yellow());
			log_print!("  Found {} transfer(s) from previous round", current_transfers.len());
		}

		// Step 2: Generate proofs with random output partitioning
		let proof_files = generate_round_proofs(
			&quantus_client,
			&secrets,
			&current_transfers,
			&exit_accounts,
			&round_dir,
			num_proofs,
		)
		.await?;

		// Step 3: Aggregate proofs
		log_print!("{}", "Step 3: Aggregating proofs...".bright_yellow());

		let aggregated_file = format!("{}/aggregated.hex", round_dir);
		aggregate_proofs(proof_files, aggregated_file.clone()).await?;

		log_print!("  Aggregated proof saved to {}", aggregated_file);

		// Step 4: Verify aggregated proof on-chain
		log_print!("{}", "Step 4: Submitting aggregated proof on-chain...".bright_yellow());

		let (verification_block, extrinsic_hash, transfer_events) =
			verify_aggregated_and_get_events(&aggregated_file, &quantus_client).await?;

		log_print!(
			"  {} Proof verified in block {} (extrinsic: 0x{})",
			"✓".bright_green(),
			hex::encode(verification_block.0),
			hex::encode(extrinsic_hash.0)
		);

		// If not final round, prepare transfer info for next round
		if !is_final {
			log_print!("{}", "Step 5: Capturing transfer info for next round...".bright_yellow());

			// Parse events to get transfer info for next round's wormhole addresses
			let next_round_addresses: Vec<SubxtAccountId> = (1..=num_proofs)
				.map(|i| {
					let next_secret =
						derive_wormhole_secret(&wallet.mnemonic, round + 1, i).unwrap();
					SubxtAccountId(next_secret.address)
				})
				.collect();

			current_transfers =
				parse_transfer_events(&transfer_events, &next_round_addresses, verification_block)?;

			log_print!(
				"  Captured {} transfer(s) for round {}",
				current_transfers.len(),
				round + 1
			);
		}

		// Log balance after this round
		let balance_after_round = get_balance(&quantus_client, &wallet.wallet_address).await?;
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
	let final_balance = get_balance(&quantus_client, &wallet.wallet_address).await?;
	verify_final_balance(initial_balance, final_balance, amount, rounds, num_proofs);

	if keep_files {
		log_print!("Proof files preserved in: {}", output_dir);
	} else {
		log_print!("Cleaning up proof files...");
		std::fs::remove_dir_all(&output_dir).ok();
	}

	Ok(())
}

/// Generate a wormhole proof with dual outputs (used for random partitioning in multiround)
///
/// This function fetches the necessary data from the chain and delegates to
/// `wormhole_lib::generate_proof` for the actual proof generation.
async fn generate_proof(
	secret_hex: &str,
	_funding_amount: u128, // No longer needed - input_amount comes from ZK leaf
	output_assignment: &ProofOutputAssignment,
	block_hash_str: &str,
	transfer_count: u64,
	_funding_account_str: &str, // No longer needed - no `from` field in ZK leaf
	leaf_index: u64,            // ZK trie leaf index for Merkle proof lookup
	output_file: &str,
	quantus_client: &QuantusClient,
) -> crate::error::Result<()> {
	// Parse inputs
	let secret = parse_secret_hex(secret_hex).map_err(crate::error::QuantusError::Generic)?;

	let block_hash_bytes: [u8; 32] = hex::decode(block_hash_str.trim_start_matches("0x"))
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid block hash: {}", e)))?
		.try_into()
		.map_err(|_| {
			crate::error::QuantusError::Generic("Block hash must be 32 bytes".to_string())
		})?;

	// Compute wormhole address using wormhole_lib
	let wormhole_address = wormhole_lib::compute_wormhole_address(&secret)
		.map_err(|e| crate::error::QuantusError::Generic(e.message))?;

	// Fetch data from chain
	let block_hash = subxt::utils::H256::from(block_hash_bytes);
	let client = quantus_client.client();

	// Get block header
	let blocks =
		client.blocks().at(block_hash).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get block: {}", e))
		})?;

	// Fetch ZK Merkle proof from chain via RPC using the leaf_index
	// CRITICAL: We MUST fetch the proof at the same block we're proving against.
	// The tree root changes with each block, so proof must match header.zk_tree_root.
	let proof_params = rpc_params![leaf_index, block_hash];
	let zk_proof: Option<ZkMerkleProofRpc> = quantus_client
		.rpc_client()
		.request("zkTree_getMerkleProof", proof_params)
		.await
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Failed to get ZK Merkle proof at block {:?}: {}",
				block_hash, e
			))
		})?;

	let zk_proof = zk_proof.ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"No ZK Merkle proof found for leaf_index {}",
			leaf_index
		))
	})?;

	// Decode the input amount from the leaf data
	// The leaf data is SCALE-encoded ZkLeaf: (to: AccountId, transfer_count: u64, asset_id:
	// AssetId, amount: Balance) For now, we'll use the quantized amount that the circuit expects
	// The chain stores the quantized amount directly in the ZK leaf
	let input_amount = decode_input_amount_from_leaf(&zk_proof.leaf_data)?;

	// Extract header data
	let header = blocks.header();
	let parent_hash: [u8; 32] = header.parent_hash.0;
	let state_root: [u8; 32] = header.state_root.0;
	let extrinsics_root: [u8; 32] = header.extrinsics_root.0;
	let digest = header.digest.encode();
	let block_number = header.number;

	// Compute sorted siblings and positions from unsorted siblings returned by chain
	// The chain returns unsorted siblings; we sort them and compute position hints
	let (sorted_siblings, positions) =
		compute_merkle_positions(&zk_proof.siblings, zk_proof.leaf_hash);

	// Build ProofGenerationInput using wormhole_lib types with ZK Merkle proof
	let input = wormhole_lib::ProofGenerationInput {
		secret,
		transfer_count,
		wormhole_address,
		input_amount,
		block_hash: block_hash_bytes,
		block_number,
		parent_hash,
		state_root,
		extrinsics_root,
		digest,
		zk_tree_root: zk_proof.root,
		zk_merkle_siblings: sorted_siblings,
		zk_merkle_positions: positions,
		exit_account_1: output_assignment.exit_account_1,
		exit_account_2: output_assignment.exit_account_2,
		output_amount_1: output_assignment.output_amount_1,
		output_amount_2: output_assignment.output_amount_2,
		volume_fee_bps: VOLUME_FEE_BPS,
		asset_id: NATIVE_ASSET_ID,
	};

	// Generate proof using wormhole_lib
	let bins_dir = Path::new("generated-bins");
	let result = wormhole_lib::generate_proof(
		&input,
		&bins_dir.join("prover.bin"),
		&bins_dir.join("common.bin"),
	)
	.map_err(|e| crate::error::QuantusError::Generic(e.message))?;

	// Write proof to file
	let proof_hex = hex::encode(result.proof_bytes);
	std::fs::write(output_file, proof_hex).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to write proof: {}", e))
	})?;

	Ok(())
}

/// Decode the input amount from SCALE-encoded ZkLeaf data.
/// ZkLeaf structure: (to: AccountId32, transfer_count: u64, asset_id: u32, amount: u128)
///
/// The chain stores the RAW amount (in planck), but hash_leaf() quantizes it.
/// We need to return the QUANTIZED amount for the circuit.
fn decode_input_amount_from_leaf(leaf_data: &[u8]) -> crate::error::Result<u32> {
	// ZkLeaf is: (AccountId32, u64, u32, u128)
	// AccountId32 = 32 bytes
	// u64 = 8 bytes (transfer_count)
	// u32 = 4 bytes (asset_id)
	// u128 = 16 bytes (amount - RAW in planck)
	// Total = 60 bytes

	if leaf_data.len() < 60 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Invalid leaf data length: expected at least 60 bytes, got {}",
			leaf_data.len()
		)));
	}

	// The amount is bytes 44-60 (u128, little-endian)
	let amount_bytes: [u8; 16] = leaf_data[44..60].try_into().map_err(|_| {
		crate::error::QuantusError::Generic("Failed to extract amount bytes".to_string())
	})?;

	let raw_amount = u128::from_le_bytes(amount_bytes);

	// Quantize: divide by 10^10 to get 2 decimal places (matches chain's hash_leaf)
	const AMOUNT_SCALE_DOWN_FACTOR: u128 = 10_000_000_000;
	let quantized = (raw_amount / AMOUNT_SCALE_DOWN_FACTOR) as u32;

	Ok(quantized)
}

/// Decode all fields from SCALE-encoded ZkLeaf data.
/// Returns (to_account, transfer_count, asset_id, raw_amount_u128)
#[allow(dead_code)]
fn decode_full_leaf_data(leaf_data: &[u8]) -> crate::error::Result<([u8; 32], u64, u32, u128)> {
	// ZkLeaf is: (AccountId32, u64, u32, u128)
	// AccountId32 = 32 bytes
	// u64 = 8 bytes (transfer_count)
	// u32 = 4 bytes (asset_id)
	// u128 = 16 bytes (amount - RAW in planck)
	// Total = 60 bytes

	if leaf_data.len() < 60 {
		return Err(crate::error::QuantusError::Generic(format!(
			"Invalid leaf data length: expected at least 60 bytes, got {}",
			leaf_data.len()
		)));
	}

	let to_account: [u8; 32] = leaf_data[0..32].try_into().map_err(|_| {
		crate::error::QuantusError::Generic("Failed to extract to_account".to_string())
	})?;

	let transfer_count = u64::from_le_bytes(leaf_data[32..40].try_into().map_err(|_| {
		crate::error::QuantusError::Generic("Failed to extract transfer_count".to_string())
	})?);

	let asset_id = u32::from_le_bytes(leaf_data[40..44].try_into().map_err(|_| {
		crate::error::QuantusError::Generic("Failed to extract asset_id".to_string())
	})?);

	let amount = u128::from_le_bytes(leaf_data[44..60].try_into().map_err(|_| {
		crate::error::QuantusError::Generic("Failed to extract amount".to_string())
	})?);

	Ok((to_account, transfer_count, asset_id, amount))
}

/// Verify an aggregated proof and return the block hash, extrinsic hash, and transfer events
async fn verify_aggregated_and_get_events(
	proof_file: &str,
	quantus_client: &QuantusClient,
) -> crate::error::Result<(
	subxt::utils::H256,
	subxt::utils::H256,
	Vec<wormhole::events::NativeTransferred>,
)> {
	use qp_wormhole_verifier::WormholeVerifier;

	let proof_bytes = read_hex_proof_file_to_bytes(proof_file)?;

	// Verify locally before submitting on-chain
	log_verbose!("Verifying aggregated proof locally before on-chain submission...");
	let bins_dir = Path::new("generated-bins");

	// Log circuit binary hashes for debugging
	let common_bytes = std::fs::read(bins_dir.join("aggregated_common.bin")).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to read aggregated_common.bin: {}", e))
	})?;
	let verifier_bytes = std::fs::read(bins_dir.join("aggregated_verifier.bin")).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to read aggregated_verifier.bin: {}",
			e
		))
	})?;
	println!(
		"[quantus-cli] Circuit binaries: common_bytes.len={}, verifier_bytes.len={}, common_hash={}, verifier_hash={}",
		common_bytes.len(),
		verifier_bytes.len(),
		hex::encode(blake3::hash(&common_bytes).as_bytes()),
		hex::encode(blake3::hash(&verifier_bytes).as_bytes()),
	);

	let verifier = WormholeVerifier::new_from_files(
		&bins_dir.join("aggregated_verifier.bin"),
		&bins_dir.join("aggregated_common.bin"),
	)
	.map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to load aggregated verifier: {}", e))
	})?;

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

	// Submit unsigned tx + wait for inclusion (best or finalized)
	let (included_at, block_hash, tx_hash) =
		submit_unsigned_verify_aggregated_proof(quantus_client, proof_bytes).await?;

	log_verbose!(
		"Submitted tx included in {}: block={:?}, tx={:?}",
		included_at.label(),
		block_hash,
		tx_hash
	);

	// Collect events for our extrinsic only
	let (found_proof_verified, transfer_events) =
		collect_wormhole_events_for_extrinsic(quantus_client, block_hash, tx_hash).await?;

	if !found_proof_verified {
		return Err(crate::error::QuantusError::Generic(
			"Proof verification failed - no ProofVerified event".to_string(),
		));
	}

	// Log minted amounts
	log_print!("  Tokens minted (from NativeTransferred events):");
	for (idx, transfer) in transfer_events.iter().enumerate() {
		let ss58_address = bytes_to_quantus_ss58(&transfer.to.0);
		log_print!(
			"    [{}] {} -> {} planck ({})",
			idx,
			ss58_address,
			transfer.amount,
			format_balance(transfer.amount)
		);
	}

	Ok((block_hash, tx_hash, transfer_events))
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
		log_print!("  Total amount: {} ({})", round_amount, format_balance(round_amount));

		// Show sample random partition for round 1
		if round == 1 {
			let partition = random_partition(amount, num_proofs, 3 * SCALE_DOWN_FACTOR);
			log_print!("  Sample random partition (actual partition will differ):");
			for (i, &amt) in partition.iter().enumerate() {
				log_print!("    Proof {}: {} ({})", i + 1, amt, format_balance(amt));
			}
		}
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

/// Parse and display the contents of a proof file for debugging
async fn parse_proof_file(
	proof_file: String,
	aggregated: bool,
	verify: bool,
) -> crate::error::Result<()> {
	use qp_wormhole_verifier::WormholeVerifier;

	log_print!("Parsing proof file: {}", proof_file);

	// Read proof bytes
	let proof_bytes = read_proof_file(&proof_file)
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to read proof: {}", e)))?;

	log_print!("Proof size: {} bytes", proof_bytes.len());

	let bins_dir = Path::new("generated-bins");

	if aggregated {
		// Load aggregated verifier
		let verifier = WormholeVerifier::new_from_files(
			&bins_dir.join("aggregated_verifier.bin"),
			&bins_dir.join("aggregated_common.bin"),
		)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to load verifier: {}", e))
		})?;

		// Deserialize proof using verifier's types
		let proof = qp_wormhole_verifier::ProofWithPublicInputs::<
			qp_wormhole_verifier::F,
			qp_wormhole_verifier::C,
			{ qp_wormhole_verifier::D },
		>::from_bytes(proof_bytes.clone(), &verifier.circuit_data.common)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Failed to deserialize aggregated proof: {:?}",
				e
			))
		})?;

		log_print!("\nPublic inputs count: {}", proof.public_inputs.len());
		log_verbose!("\nPublic inputs count: {}", proof.public_inputs.len());

		// Try to parse as aggregated
		match qp_wormhole_verifier::parse_aggregated_public_inputs(&proof) {
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

		// Verify if requested
		if verify {
			log_print!("\n=== Verifying Proof ===");
			match verifier.verify(proof) {
				Ok(()) => {
					log_success!("Proof verification PASSED");
				},
				Err(e) => {
					log_error!("Proof verification FAILED: {}", e);
					return Err(crate::error::QuantusError::Generic(format!(
						"Proof verification failed: {}",
						e
					)));
				},
			}
		}
	} else {
		// Load leaf verifier
		let verifier = WormholeVerifier::new_from_files(
			&bins_dir.join("verifier.bin"),
			&bins_dir.join("common.bin"),
		)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to load verifier: {}", e))
		})?;

		// Deserialize proof using verifier's types
		let proof = qp_wormhole_verifier::ProofWithPublicInputs::<
			qp_wormhole_verifier::F,
			qp_wormhole_verifier::C,
			{ qp_wormhole_verifier::D },
		>::from_bytes(proof_bytes, &verifier.circuit_data.common)
		.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to deserialize proof: {:?}", e))
		})?;

		log_print!("\nPublic inputs count: {}", proof.public_inputs.len());

		let pi = qp_wormhole_verifier::parse_public_inputs(&proof).map_err(|e| {
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
		log_print!("Block Number: {}", pi.block_number);

		// Verify if requested
		if verify {
			log_print!("\n=== Verifying Proof ===");
			match verifier.verify(proof) {
				Ok(()) => {
					log_success!("Proof verification PASSED");
				},
				Err(e) => {
					log_error!("Proof verification FAILED: {}", e);
					return Err(crate::error::QuantusError::Generic(format!(
						"Proof verification failed: {}",
						e
					)));
				},
			}
		}
	}

	Ok(())
}

/// A pending wormhole output that can be used as input for the next dissolve layer.
#[derive(Debug, Clone)]
struct DissolveOutput {
	/// The secret used to derive the wormhole address
	secret: [u8; 32],
	/// Amount in planck
	amount: u128,
	/// Transfer count from the NativeTransferred event
	transfer_count: u64,
	/// Funding account (sender)
	funding_account: SubxtAccountId,
	/// Block hash where the transfer was recorded (needed for storage proof)
	proof_block_hash: subxt::utils::H256,
	/// ZK trie leaf index for Merkle proof lookup
	leaf_index: u64,
}

/// Dissolve a large wormhole deposit into many small outputs for better privacy.
///
/// Creates a tree of wormhole transactions where each layer doubles the number of outputs
/// by splitting each input into 2 via the dual-output proof mechanism.
///
/// ```text
/// Layer 0: 1 input  → 2 outputs
/// Layer 1: 2 inputs → 4 outputs
/// Layer 2: 4 inputs → 8 outputs
/// ...
/// Layer N: 2^(N-1) inputs → 2^N outputs (all below target_size)
/// ```
///
/// Each layer: batch inputs into groups of ≤16, generate proofs, aggregate, verify on-chain.
/// The final outputs are small enough to blend with the miner reward noise floor.
#[allow(clippy::too_many_arguments)]
async fn run_dissolve(
	amount: u128,
	target_size: u128,
	wallet_name: String,
	password: Option<String>,
	password_file: Option<String>,
	keep_files: bool,
	output_dir: String,
	node_url: &str,
) -> crate::error::Result<()> {
	use colored::Colorize;

	log_print!("");
	log_print!("==================================================");
	log_print!("  Wormhole Dissolve");
	log_print!("==================================================");
	log_print!("");

	// Calculate number of layers needed
	let mut num_outputs = 1u128;
	let mut layers = 0usize;
	while amount / num_outputs > target_size {
		num_outputs *= 2;
		layers += 1;
	}
	let final_output_count = num_outputs as usize;

	log_print!("  Amount: {} ({})", amount, format_balance(amount));
	log_print!("  Target size: {} ({})", target_size, format_balance(target_size));
	log_print!("  Layers: {}", layers);
	log_print!("  Final outputs: {}", final_output_count);
	log_print!(
		"  Approximate output size: {} ({})",
		amount / num_outputs,
		format_balance(amount / num_outputs)
	);
	log_print!("");

	// Load wallet (reuse multiround wallet loader for HD derivation)
	let wallet = load_multiround_wallet(&wallet_name, password, password_file)?;
	let funding_account = wallet.wallet_account_id.clone();

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;

	// Create output directory
	std::fs::create_dir_all(&output_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create output directory: {}", e))
	})?;

	// Load aggregation config
	let bins_dir = std::path::Path::new("generated-bins");
	let agg_config = CircuitBinsConfig::load(bins_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!(
			"Failed to load aggregation circuit config: {}",
			e
		))
	})?;

	// === Layer 0: Initial funding ===
	log_print!("{}", "Layer 0: Initial funding".bright_yellow());

	let initial_secret = derive_wormhole_secret(&wallet.mnemonic, 0, 1)?;
	let wormhole_address = SubxtAccountId(initial_secret.address);

	// Transfer to the wormhole address
	let transfer_tx = quantus_node::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(wormhole_address.clone()),
		amount,
	);

	let quantum_keypair = QuantumKeyPair {
		public_key: wallet.keypair.public_key.clone(),
		private_key: wallet.keypair.private_key.clone(),
	};

	submit_transaction(
		&quantus_client,
		&quantum_keypair,
		transfer_tx,
		None,
		ExecutionMode { finalized: false, wait_for_transaction: true },
	)
	.await
	.map_err(|e| crate::error::QuantusError::Generic(format!("Initial transfer failed: {}", e)))?;

	// Get block and event
	let block = at_best_block(&quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to get block: {}", e)))?;
	let block_hash = block.hash();
	let events_api =
		quantus_client.client().events().at(block_hash).await.map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to get events: {}", e))
		})?;
	let event = events_api
		.find::<wormhole::events::NativeTransferred>()
		.find(|e| if let Ok(evt) = e { evt.to.0 == initial_secret.address } else { false })
		.ok_or_else(|| crate::error::QuantusError::Generic("No transfer event found".to_string()))?
		.map_err(|e| crate::error::QuantusError::Generic(format!("Event decode error: {}", e)))?;

	let mut current_outputs = vec![DissolveOutput {
		secret: initial_secret.secret,
		amount,
		transfer_count: event.transfer_count,
		funding_account: funding_account.clone(),
		proof_block_hash: block_hash,
		leaf_index: event.leaf_index,
	}];

	log_success!("  Funded 1 wormhole address with {}", format_balance(amount));

	// === Layers 1..N: Split outputs ===
	for layer in 1..=layers {
		let num_inputs = current_outputs.len();
		let layer_dir = format!("{}/layer{}", output_dir, layer);
		std::fs::create_dir_all(&layer_dir).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to create layer directory: {}", e))
		})?;

		log_print!("");
		log_print!(
			"{} Layer {}/{}: {} inputs → {} outputs {}",
			">>>".bright_blue(),
			layer,
			layers,
			num_inputs,
			num_inputs * 2,
			"<<<".bright_blue()
		);

		// Derive secrets for this layer's outputs (2 per input)
		let mut next_secrets: Vec<WormholePair> = Vec::new();
		for i in 0..(num_inputs * 2) {
			next_secrets.push(derive_wormhole_secret(&wallet.mnemonic, layer, i + 1)?);
		}

		// Process inputs in batches of ≤16 (aggregation batch size)
		let batch_size = agg_config.num_leaf_proofs;
		let mut all_next_outputs: Vec<DissolveOutput> = Vec::new();
		let num_batches = num_inputs.div_ceil(batch_size);

		for batch_idx in 0..num_batches {
			let batch_start = batch_idx * batch_size;
			let batch_end = (batch_start + batch_size).min(num_inputs);
			let batch_inputs = &current_outputs[batch_start..batch_end];
			let batch_num_proofs = batch_inputs.len();

			log_print!("  Batch {}/{}: {} proofs", batch_idx + 1, num_batches, batch_num_proofs);

			// Each input splits into 2 outputs (equal split)
			let mut proof_files = Vec::new();
			let proof_gen_start = std::time::Instant::now();

			// All inputs in a batch must use the same block for proof generation.
			// Use the proof_block_hash from the first input (all inputs in a batch
			// were created in the same verification block from the previous layer).
			let batch_proof_block_hash = batch_inputs[0].proof_block_hash;

			for (i, input) in batch_inputs.iter().enumerate() {
				let global_idx = batch_start + i;
				let exit_1_idx = global_idx * 2;
				let exit_2_idx = global_idx * 2 + 1;

				let input_quantized = quantize_funding_amount(input.amount)
					.map_err(crate::error::QuantusError::Generic)?;
				let total_output = compute_output_amount(input_quantized, VOLUME_FEE_BPS);
				let output_1 = total_output / 2;
				let output_2 = total_output - output_1;

				let assignment = ProofOutputAssignment {
					output_amount_1: output_1.max(1),
					exit_account_1: next_secrets[exit_1_idx].address,
					output_amount_2: output_2.max(1),
					exit_account_2: next_secrets[exit_2_idx].address,
				};

				let proof_file = format!("{}/batch{}_proof{}.hex", layer_dir, batch_idx, i);

				generate_proof(
					&hex::encode(input.secret),
					input.amount,
					&assignment,
					&format!("0x{}", hex::encode(batch_proof_block_hash.0)),
					input.transfer_count,
					&format!("0x{}", hex::encode(input.funding_account.0)),
					input.leaf_index, // ZK trie leaf index for Merkle proof lookup
					&proof_file,
					&quantus_client,
				)
				.await?;

				proof_files.push(proof_file);
			}

			let proof_gen_elapsed = proof_gen_start.elapsed();
			log_print!(
				"    Proof generation: {:.2}s ({} proofs)",
				proof_gen_elapsed.as_secs_f64(),
				batch_num_proofs
			);

			// Aggregate
			log_print!("    Aggregating...");
			let aggregated_file = format!("{}/batch{}_aggregated.hex", layer_dir, batch_idx);
			aggregate_proofs_to_file(&proof_files, &aggregated_file)?;

			// Verify on-chain
			log_print!("    Verifying on-chain...");
			let (verification_block, _extrinsic_hash, transfer_events) =
				verify_aggregated_and_get_events(&aggregated_file, &quantus_client).await?;

			log_success!("    Verified in block 0x{}", hex::encode(verification_block.0));

			// Collect next layer's outputs from the transfer events
			// Use the verification_block as the proof_block_hash for the next layer
			for (i, _input) in batch_inputs.iter().enumerate() {
				let global_idx = batch_start + i;
				let exit_1_idx = global_idx * 2;
				let exit_2_idx = global_idx * 2 + 1;

				for (secret_idx, target_address) in [
					(exit_1_idx, &next_secrets[exit_1_idx]),
					(exit_2_idx, &next_secrets[exit_2_idx]),
				] {
					let event = transfer_events
						.iter()
						.find(|e| e.to.0 == target_address.address)
						.ok_or_else(|| {
						crate::error::QuantusError::Generic(format!(
							"No transfer event for output {} at layer {}",
							secret_idx, layer
						))
					})?;

					all_next_outputs.push(DissolveOutput {
						secret: target_address.secret,
						amount: event.amount,
						transfer_count: event.transfer_count,
						funding_account: event.from.clone(),
						proof_block_hash: verification_block,
						leaf_index: event.leaf_index,
					});
				}
			}
		}

		log_print!("  Layer {} complete: {} outputs", layer, all_next_outputs.len());

		current_outputs = all_next_outputs;
	}

	// Summary
	log_print!("");
	log_print!("==================================================");
	log_success!("  Dissolve complete!");
	log_print!("==================================================");
	log_print!("");
	log_print!("  Final outputs: {}", current_outputs.len());
	let min_output = current_outputs.iter().map(|o| o.amount).min().unwrap_or(0);
	let max_output = current_outputs.iter().map(|o| o.amount).max().unwrap_or(0);
	let total_output: u128 = current_outputs.iter().map(|o| o.amount).sum();
	log_print!(
		"  Output range: {} - {} ({})",
		format_balance(min_output),
		format_balance(max_output),
		format_balance(total_output)
	);

	if keep_files {
		log_print!("  Proof files preserved in: {}", output_dir);
	} else {
		log_print!("  Cleaning up proof files...");
		std::fs::remove_dir_all(&output_dir).ok();
	}

	Ok(())
}

/// Collect miner rewards from a wormhole address.
///
/// This mirrors the withdrawal flow from the miner app:
/// 1. Query Subsquid for pending transfers to the wormhole address
/// 2. Filter out already-spent transfers (nullifier check)
/// 3. Generate ZK proofs for each transfer
/// 4. Aggregate proofs
/// 5. Submit withdrawal transaction
#[allow(clippy::too_many_arguments)]
async fn run_collect_rewards(
	wallet_name: Option<String>,
	mnemonic_arg: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
	amount: Option<f64>,
	destination: Option<String>,
	subsquid_url: String,
	wormhole_index: usize,
	_output_dir: String,
	_keep_files: bool,
	dry_run: bool,
	node_url: &str,
	at_block: Option<u32>,
) -> crate::error::Result<()> {
	use crate::collect_rewards_lib::{collect_rewards, CollectRewardsConfig, ProgressCallback};
	use colored::Colorize;

	log_print!("");
	log_print!("==================================================");
	log_print!("  Wormhole Collect Rewards");
	log_print!("==================================================");
	log_print!("");

	// Get mnemonic and wallet address from either wallet or direct mnemonic
	let (mnemonic, wallet_address) = if let Some(wallet_name) = wallet_name {
		// Load from stored wallet
		let wallet = load_multiround_wallet(&wallet_name, password, password_file)?;
		(wallet.mnemonic, Some(wallet.wallet_address))
	} else if let Some(mnemonic) = mnemonic_arg {
		// Use provided mnemonic directly
		(mnemonic, None)
	} else {
		return Err(crate::error::QuantusError::Generic(
			"Either --wallet or --mnemonic must be provided".to_string(),
		));
	};

	// Destination address - required when using mnemonic directly
	let destination_address = if let Some(dest) = &destination {
		dest.clone()
	} else if let Some(addr) = wallet_address.as_ref() {
		addr.clone()
	} else {
		return Err(crate::error::QuantusError::Generic(
			"--destination is required when using --mnemonic".to_string(),
		));
	};

	// Convert amount from DEV to planck
	let amount_planck = amount.map(|a| (a * 1_000_000_000_000.0) as u128);

	// Print initial info
	if let Some(ref addr) = wallet_address {
		log_print!("  Wallet:            {}", addr.bright_yellow());
	} else {
		log_print!("  Wallet:            {}", "(from mnemonic)".bright_yellow());
	}
	log_print!("  Wormhole index:    {}", wormhole_index);
	log_print!("  Destination:       {}", destination_address.bright_green());
	log_print!("  Subsquid URL:      {}", subsquid_url);
	log_print!("  Node URL:          {}", node_url);
	log_print!("");

	// Create CLI progress callback
	struct CliProgress;
	impl ProgressCallback for CliProgress {
		fn on_step(&self, step: &str, details: &str) {
			use colored::Colorize;
			match step {
				"derive" => log_print!("{}", format!("Step 1: {}...", details).bright_yellow()),
				"query" => log_print!("{}", format!("Step 2: {}...", details).bright_yellow()),
				"nullifiers" => log_print!("{}", format!("Step 3: {}...", details).bright_yellow()),
				"connect" => log_print!("{}", format!("Step 4: {}...", details).bright_yellow()),
				"proofs" => log_print!("{}", format!("Step 5: {}...", details).bright_yellow()),
				"submit" => log_print!("{}", format!("Step 6: {}...", details).bright_yellow()),
				_ => log_print!("  {}: {}", step, details),
			}
		}
		fn on_proof_generated(&self, index: usize, total: usize) {
			log_print!("  [{}/{}] Proof generated", index, total);
		}
		fn on_batch_submitted(&self, batch_index: usize, total_batches: usize, amount: u128) {
			use colored::Colorize;
			log_print!(
				"  Batch {}/{}: {} withdrawn",
				batch_index,
				total_batches,
				format_balance(amount).bright_cyan()
			);
		}
		fn on_error(&self, message: &str) {
			log_error!("{}", message);
		}
	}

	let config = CollectRewardsConfig {
		mnemonic,
		wormhole_index,
		destination_address: destination_address.clone(),
		subsquid_url,
		node_url: node_url.to_string(),
		bins_dir: "generated-bins".to_string(),
		amount: amount_planck,
		dry_run,
		at_block,
	};

	let result = collect_rewards(config, &CliProgress)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.message))?;

	// Show summary
	log_print!("");
	if result.total_withdrawn > 0 {
		log_print!("{}", "Withdrawal complete!".bright_green().bold());
		log_print!(
			"  Total withdrawn: {} across {} batch(es)",
			format_balance(result.total_withdrawn).bright_cyan(),
			result.batches.len()
		);
		log_print!("  Transfers processed: {}", result.transfers_processed);
		log_print!("  Destination: {}", destination_address.bright_green());

		for (i, batch) in result.batches.iter().enumerate() {
			log_print!(
				"  Batch {}: {} (tx: 0x{}...)",
				i + 1,
				format_balance(batch.amount_withdrawn).bright_cyan(),
				&batch.tx_hash[..16]
			);
		}
	} else if dry_run {
		log_print!("{}", "Dry run complete - no transactions submitted.".bright_blue());
		log_print!("  Transfers available: {}", result.transfers_processed);
	} else {
		log_print!("{}", "No transfers to withdraw.".bright_yellow());
	}

	Ok(())
}

/// Helper to aggregate proof files and write the result (used by dissolve command)
fn aggregate_proofs_to_file(proof_files: &[String], output_file: &str) -> crate::error::Result<()> {
	use qp_wormhole_aggregator::aggregator::Layer0Aggregator;

	let bins_dir = std::path::Path::new("generated-bins");
	let mut aggregator = Layer0Aggregator::new(bins_dir).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to create aggregator: {}", e))
	})?;

	let common_data = aggregator.load_common_data(CircuitType::Leaf).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to load common data: {}", e))
	})?;

	for proof_file in proof_files {
		let proof_bytes = read_hex_proof_file_to_bytes(proof_file)?;
		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &common_data)
			.map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Failed to deserialize proof from {}: {:?}",
					proof_file, e
				))
			})?;
		aggregator.push_proof(proof).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Failed to push proof: {}", e))
		})?;
	}

	let agg_start = std::time::Instant::now();
	let proof = aggregator
		.aggregate()
		.map_err(|e| crate::error::QuantusError::Generic(format!("Aggregation failed: {}", e)))?;
	let agg_elapsed = agg_start.elapsed();
	log_print!("    Aggregation: {:.2}s", agg_elapsed.as_secs_f64());

	let proof_hex = hex::encode(proof.to_bytes());
	std::fs::write(output_file, &proof_hex).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to write proof: {}", e))
	})?;

	Ok(())
}

// =============================================================================
// FUZZ TEST FUNCTIONS - TEMPORARILY DISABLED
// =============================================================================
//
// The fuzz tests below are temporarily disabled during the migration from MPT
// storage proofs to ZK tree Merkle proofs. To re-enable:
//
// 1. Deploy pallet-zk-tree to a test chain
// 2. Update run_fuzz_test() to use zkTree_getMerkleProof RPC instead of state_getReadProof
// 3. Update try_generate_fuzz_proof() to use the new PrivateCircuitInputs fields:
//    - zk_tree_root: [u8; 32]
//    - zk_merkle_siblings: Vec<[[u8; 32]; 3]>
//    - zk_merkle_positions: Vec<u8>
// 4. Note: The ZK leaf no longer contains `from` (funding_account) - it's now: (to: AccountId,
//    transfer_count: u64, asset_id: u32, amount: u32)
// 5. Update generate_fuzz_cases() to remove from-address fuzzing since it's no longer in the leaf
//
// See qp-zk-circuits/wormhole/tests/src/prover/prover_tests.rs for examples of
// how to construct ZK Merkle proofs for testing.
// =============================================================================

// TODO: Re-enable fuzz tests once ZK tree is deployed
// The old implementation used:
// - state_getReadProof RPC to fetch MPT storage proofs
// - prepare_proof_for_circuit() to process proofs
// - PrivateCircuitInputs with funding_account and storage_proof fields
//
// The new implementation should:
// - Use zkTree_getMerkleProof RPC
// - Directly use ZkMerkleProofRpc response (siblings, positions)
// - Use PrivateCircuitInputs with zk_tree_root, zk_merkle_siblings, zk_merkle_positions

/// Check if nullifiers have been spent by querying Subsquid.
///
/// Given a secret (or wallet) and transfer count(s), computes the nullifier(s) and checks
/// if they exist in the indexer (meaning the transfer was already withdrawn).
async fn run_check_nullifier(
	secret_hex: Option<String>,
	wallet_name: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
	wormhole_index: usize,
	transfer_counts_arg: String,
	subsquid_url: String,
) -> crate::error::Result<()> {
	use crate::subsquid::{compute_address_hash, SubsquidClient};
	use colored::Colorize;

	// Get secret either directly or from wallet
	let (secret, secret_hex_display) = if let Some(hex) = secret_hex {
		let secret = parse_secret_hex(&hex).map_err(crate::error::QuantusError::Generic)?;
		(secret, hex)
	} else if let Some(wallet) = wallet_name {
		// Load wallet and derive wormhole secret
		let wallet_manager = WalletManager::new()?;
		let wallet_password = password::get_wallet_password(&wallet, password, password_file)?;
		let wallet_data = wallet_manager.load_wallet(&wallet, &wallet_password)?;

		let mnemonic = wallet_data.mnemonic.ok_or_else(|| {
			crate::error::QuantusError::Generic(
				"Wallet does not contain a mnemonic. Use --secret instead.".to_string(),
			)
		})?;

		// Derive wormhole secret using HD path for miner rewards (purpose = 1)
		let path = format!("m/44'/{}/0'/1'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, wormhole_index);
		let wormhole_pair = derive_wormhole_from_mnemonic(&mnemonic, None, &path).map_err(|e| {
			crate::error::QuantusError::Generic(format!("HD derivation failed: {:?}", e))
		})?;

		let secret: [u8; 32] = wormhole_pair.secret.as_ref().try_into().map_err(|_| {
			crate::error::QuantusError::Generic("Invalid secret length".to_string())
		})?;
		let hex = hex::encode(&secret);
		log_print!("Derived wormhole secret from wallet '{}' (index {})", wallet, wormhole_index);
		(secret, hex)
	} else {
		return Err(crate::error::QuantusError::Generic(
			"Either --secret or --wallet must be provided".to_string(),
		));
	};

	// Parse transfer counts (single number or range like "0-10")
	let transfer_counts: Vec<u64> = if transfer_counts_arg.contains('-') {
		let parts: Vec<&str> = transfer_counts_arg.split('-').collect();
		if parts.len() != 2 {
			return Err(crate::error::QuantusError::Generic(
				"Invalid range format. Use 'start-end' (e.g., '0-10')".to_string(),
			));
		}
		let start: u64 = parts[0].parse().map_err(|_| {
			crate::error::QuantusError::Generic(format!("Invalid start number: {}", parts[0]))
		})?;
		let end: u64 = parts[1].parse().map_err(|_| {
			crate::error::QuantusError::Generic(format!("Invalid end number: {}", parts[1]))
		})?;
		(start..=end).collect()
	} else {
		vec![transfer_counts_arg.parse().map_err(|_| {
			crate::error::QuantusError::Generic(format!(
				"Invalid transfer count: {}",
				transfer_counts_arg
			))
		})?]
	};

	log_print!("{}", "Checking Nullifiers".bright_cyan());
	log_print!("  Secret: 0x{}...", &secret_hex_display[..16.min(secret_hex_display.len())]);
	log_print!("  Transfer counts: {:?}", transfer_counts);
	log_print!("  Subsquid URL: {}", subsquid_url);
	log_print!("");

	// Compute nullifiers for each transfer count
	let mut nullifiers_to_check: Vec<(String, String, u64)> = Vec::new(); // (nullifier_hex, nullifier_hash, transfer_count)

	for tc in &transfer_counts {
		let nullifier = wormhole_lib::compute_nullifier(&secret, *tc).map_err(|e| {
			crate::error::QuantusError::Generic(format!(
				"Failed to compute nullifier for transfer_count {}: {}",
				tc, e.message
			))
		})?;
		let nullifier_hex = hex::encode(nullifier);
		let nullifier_hash = compute_address_hash(&nullifier);
		nullifiers_to_check.push((nullifier_hex, nullifier_hash, *tc));
	}

	// Query Subsquid
	let client = SubsquidClient::new(subsquid_url)?;

	// Build prefix queries (8 char prefix for privacy)
	let prefix_len = 8;
	let nullifier_pairs: Vec<(String, String)> = nullifiers_to_check
		.iter()
		.map(|(nul, hash, _)| (nul.clone(), hash.clone()))
		.collect();

	let spent_set = client.check_nullifiers_spent(&nullifier_pairs, prefix_len).await?;

	// Display results
	log_print!("{}", "Results:".bright_yellow());
	let mut spent_count = 0;
	let mut unspent_count = 0;

	for (nullifier_hex, _nullifier_hash, tc) in &nullifiers_to_check {
		let is_spent = spent_set.contains(nullifier_hex);
		if is_spent {
			log_print!(
				"  [{}] transfer_count={}: {} (nullifier: 0x{}...)",
				"SPENT".bright_red(),
				tc,
				"Already withdrawn".red(),
				&nullifier_hex[..16]
			);
			spent_count += 1;
		} else {
			log_print!(
				"  [{}] transfer_count={}: {} (nullifier: 0x{}...)",
				"UNSPENT".bright_green(),
				tc,
				"Available for withdrawal".green(),
				&nullifier_hex[..16]
			);
			unspent_count += 1;
		}
	}

	log_print!("");
	log_print!(
		"Summary: {} spent, {} unspent out of {} checked",
		spent_count,
		unspent_count,
		nullifiers_to_check.len()
	);

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashSet;
	use tempfile::NamedTempFile;

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
			.contains("exceeds u32::MAX"));
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
			(output_medium as u64) * 10000 <=
				(input_medium as u64) * (10000 - VOLUME_FEE_BPS as u64)
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

	// Note: Integration tests for proof generation, serialization, aggregation, and
	// multi-account aggregation have been moved to qp-zk-circuits/wormhole/tests/
	// where the test-helpers crate (with TestInputs) is available as a workspace dep.

	/// Test that public inputs parsing matches expected structure
	#[test]
	fn test_public_inputs_structure() {
		use qp_wormhole_inputs::{
			ASSET_ID_INDEX, BLOCK_HASH_END_INDEX, BLOCK_HASH_START_INDEX, BLOCK_NUMBER_INDEX,
			EXIT_ACCOUNT_1_END_INDEX, EXIT_ACCOUNT_1_START_INDEX, EXIT_ACCOUNT_2_END_INDEX,
			EXIT_ACCOUNT_2_START_INDEX, NULLIFIER_END_INDEX, NULLIFIER_START_INDEX,
			OUTPUT_AMOUNT_1_INDEX, OUTPUT_AMOUNT_2_INDEX, PUBLIC_INPUTS_FELTS_LEN,
			VOLUME_FEE_BPS_INDEX,
		};

		// Verify expected public inputs layout for dual-output circuit
		assert_eq!(PUBLIC_INPUTS_FELTS_LEN, 21, "Public inputs should be 21 field elements");
		assert_eq!(ASSET_ID_INDEX, 0, "Asset ID should be first");
		assert_eq!(OUTPUT_AMOUNT_1_INDEX, 1, "Output amount 1 should be at index 1");
		assert_eq!(OUTPUT_AMOUNT_2_INDEX, 2, "Output amount 2 should be at index 2");
		assert_eq!(VOLUME_FEE_BPS_INDEX, 3, "Volume fee BPS should be at index 3");
		assert_eq!(NULLIFIER_START_INDEX, 4, "Nullifier should start at index 4");
		assert_eq!(NULLIFIER_END_INDEX, 8, "Nullifier should end at index 8");
		assert_eq!(EXIT_ACCOUNT_1_START_INDEX, 8, "Exit account 1 should start at index 8");
		assert_eq!(EXIT_ACCOUNT_1_END_INDEX, 12, "Exit account 1 should end at index 12");
		assert_eq!(EXIT_ACCOUNT_2_START_INDEX, 12, "Exit account 2 should start at index 12");
		assert_eq!(EXIT_ACCOUNT_2_END_INDEX, 16, "Exit account 2 should end at index 16");
		assert_eq!(BLOCK_HASH_START_INDEX, 16, "Block hash should start at index 16");
		assert_eq!(BLOCK_HASH_END_INDEX, 20, "Block hash should end at index 20");
		assert_eq!(BLOCK_NUMBER_INDEX, 20, "Block number should be at index 20");
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

	#[test]
	fn test_aggregation_config_deserialization_matches_upstream_format() {
		// This test verifies that our local AggregationConfig struct can deserialize
		// the same JSON format that the upstream CircuitBinsConfig produces.
		// If the upstream adds/removes/renames fields, this test will catch it.
		let json = r#"{
			"num_leaf_proofs": 8,
			"num_layer0_proofs": null
		}"#;

		let config: CircuitBinsConfig = serde_json::from_str(json).unwrap();
		assert_eq!(config.num_leaf_proofs, 8);
		assert_eq!(config.num_layer0_proofs, None);
	}

	fn mk_accounts(n: usize) -> Vec<[u8; 32]> {
		(0..n)
			.map(|i| {
				let mut a = [0u8; 32];
				a[0] = (i as u8).wrapping_add(1); // avoid [0;32]
				a
			})
			.collect()
	}

	fn proof_outputs_for_inputs(input_amounts: &[u128], fee_bps: u32) -> Vec<u32> {
		input_amounts
			.iter()
			.map(|&input| {
				let input_quantized = quantize_funding_amount(input).unwrap_or(0);
				compute_output_amount(input_quantized, fee_bps)
			})
			.collect()
	}

	fn total_output_for_inputs(input_amounts: &[u128], fee_bps: u32) -> u64 {
		proof_outputs_for_inputs(input_amounts, fee_bps)
			.into_iter()
			.map(|x| x as u64)
			.sum()
	}

	/// Find some input that yields at least `min_out` quantized output after fee.
	/// Keeps tests robust even if quantization constants change.
	fn find_input_for_min_output(fee_bps: u32, min_out: u32) -> u128 {
		let mut input: u128 = 1;
		for _ in 0..80 {
			let q = quantize_funding_amount(input).unwrap_or(0);
			let out = compute_output_amount(q, fee_bps);
			if out >= min_out {
				return input;
			}
			// grow fast but safely
			input = input.saturating_mul(10);
		}
		panic!("Could not find input producing output >= {}", min_out);
	}

	// --------------------------
	// random_partition tests
	// --------------------------

	#[test]
	fn random_partition_n0() {
		let parts = random_partition(100, 0, 1);
		assert!(parts.is_empty());
	}

	#[test]
	fn random_partition_n1() {
		let total = 12345u128;
		let parts = random_partition(total, 1, 9999);
		assert_eq!(parts, vec![total]);
	}

	#[test]
	fn random_partition_total_less_than_min_total_falls_back_to_equalish() {
		// total < min_per_part * n => fallback path
		let total = 5u128;
		let n = 10usize;
		let min_per_part = 1u128;

		let parts = random_partition(total, n, min_per_part);

		assert_eq!(parts.len(), n);
		assert_eq!(parts.iter().sum::<u128>(), total);

		// fallback behavior: per_part=0, remainder=5, last gets remainder
		for part in parts.iter().take(n - 1) {
			assert_eq!(*part, 0);
		}
		assert_eq!(parts[n - 1], 5);
	}

	#[test]
	fn random_partition_min_achievable_invariants_hold() {
		let total = 100u128;
		let n = 10usize;
		let min_per_part = 3u128;

		for _ in 0..200 {
			let parts = random_partition(total, n, min_per_part);
			assert_eq!(parts.len(), n);
			assert_eq!(parts.iter().sum::<u128>(), total);
			assert!(parts.iter().all(|&p| p >= min_per_part));
		}
	}

	#[test]
	fn random_partition_distributable_zero_all_min() {
		let n = 10usize;
		let min_per_part = 3u128;
		let total = min_per_part * n as u128;

		let parts = random_partition(total, n, min_per_part);

		assert_eq!(parts.len(), n);
		assert_eq!(parts.iter().sum::<u128>(), total);
		assert!(parts.iter().all(|&p| p == min_per_part));
	}

	// --------------------------
	// compute_random_output_assignments tests
	// --------------------------

	#[test]
	fn compute_random_output_assignments_empty_inputs_or_targets() {
		let targets = mk_accounts(3);
		assert!(compute_random_output_assignments(&[], &targets, 0).unwrap().is_empty());

		let inputs = vec![1u128, 2u128, 3u128];
		assert!(compute_random_output_assignments(&inputs, &[], 0).unwrap().is_empty());
	}

	#[test]
	fn compute_random_output_assignments_basic_invariants() {
		let fee_bps = 0u32;

		// ensure non-zero outputs for meaningful checks
		let input = find_input_for_min_output(fee_bps, 5);
		let input_amounts = vec![input, input, input, input, input];
		let targets = mk_accounts(4);

		let assignments =
			compute_random_output_assignments(&input_amounts, &targets, fee_bps).unwrap();
		assert_eq!(assignments.len(), input_amounts.len());

		let proof_outputs = proof_outputs_for_inputs(&input_amounts, fee_bps);

		// per-proof sum matches
		for (i, a) in assignments.iter().enumerate() {
			let per_proof_sum = a.output_amount_1 as u64 + a.output_amount_2 as u64;
			assert_eq!(per_proof_sum, proof_outputs[i] as u64);

			// If an output amount is non-zero, the account must be in targets
			if a.output_amount_1 > 0 {
				assert!(targets.contains(&a.exit_account_1));
			} else {
				// if amount is zero, account can be zero or anything; current impl keeps default
				// [0;32]
			}
			if a.output_amount_2 > 0 {
				assert!(targets.contains(&a.exit_account_2));
				assert_ne!(a.exit_account_2, a.exit_account_1); // should be different if both used
			} else {
				// current impl keeps default [0;32]
				assert_eq!(a.exit_account_2, [0u8; 32]);
			}
		}

		// total sum matches
		let total_assigned: u64 = assignments
			.iter()
			.map(|a| a.output_amount_1 as u64 + a.output_amount_2 as u64)
			.sum();

		let total_expected = total_output_for_inputs(&input_amounts, fee_bps);
		assert_eq!(total_assigned, total_expected);
	}

	#[test]
	fn compute_random_output_assignments_more_targets_than_capacity_still_conserves_funds() {
		// Capacity: each proof can hit at most 2 targets, so distinct-used-targets <= 2 *
		// num_proofs. Set num_targets > 2*num_proofs and ensure total_output >= num_targets so
		// the partition *wants* to give each target >= 1 (though algorithm can't satisfy it).
		let fee_bps = 0u32;
		let num_proofs = 1usize;
		let num_targets = 5usize;

		let input = find_input_for_min_output(fee_bps, 10); // ensure total_output is "big enough"
		let input_amounts = vec![input; num_proofs];
		let targets = mk_accounts(num_targets);

		let assignments =
			compute_random_output_assignments(&input_amounts, &targets, fee_bps).unwrap();
		assert_eq!(assignments.len(), num_proofs);

		// total preserved
		let total_assigned: u64 = assignments
			.iter()
			.map(|a| a.output_amount_1 as u64 + a.output_amount_2 as u64)
			.sum();
		let total_expected = total_output_for_inputs(&input_amounts, fee_bps);
		assert_eq!(total_assigned, total_expected);

		// used targets bounded by 2*num_proofs and thus < num_targets
		let mut used = HashSet::new();
		for a in &assignments {
			if a.output_amount_1 > 0 {
				used.insert(a.exit_account_1);
			}
			if a.output_amount_2 > 0 {
				used.insert(a.exit_account_2);
			}
		}
		assert!(used.len() <= 2 * num_proofs);
		assert!(used.len() < num_targets);
	}

	#[test]
	fn compute_random_output_assignments_total_output_less_than_num_targets_does_not_panic_and_conserves(
	) {
		// This forces random_partition into its fallback branch inside
		// compute_random_output_assignments because min_per_target = 1 and total_output <
		// num_targets.
		let fee_bps = 0u32;

		let num_targets = 50usize;
		let targets = mk_accounts(num_targets);

		// Try to get very small total output: two proofs with output likely >= 1 each,
		// but still far less than 50.
		let input = find_input_for_min_output(fee_bps, 1);
		let input_amounts = vec![input, input];

		let assignments =
			compute_random_output_assignments(&input_amounts, &targets, fee_bps).unwrap();
		assert_eq!(assignments.len(), input_amounts.len());

		let total_assigned: u64 = assignments
			.iter()
			.map(|a| a.output_amount_1 as u64 + a.output_amount_2 as u64)
			.sum();
		let total_expected = total_output_for_inputs(&input_amounts, fee_bps);
		assert_eq!(total_assigned, total_expected);

		// For each assignment: if non-zero amount then account must be in targets.
		for a in &assignments {
			if a.output_amount_1 > 0 {
				assert!(targets.contains(&a.exit_account_1));
			}
			if a.output_amount_2 > 0 {
				assert!(targets.contains(&a.exit_account_2));
				assert_ne!(a.exit_account_2, a.exit_account_1);
			}
		}
	}
}
