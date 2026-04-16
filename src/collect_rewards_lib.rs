//! Collect Rewards Library Functions
//!
//! This module provides library-friendly functions for collecting miner rewards
//! that can be used by external crates (like quantus-sdk) via FFI.
//!
//! The main function `collect_rewards` handles the entire flow:
//! 1. Query Subsquid for pending transfers
//! 2. Generate ZK proofs for each transfer
//! 3. Aggregate proofs into batches
//! 4. Submit withdrawal transactions to chain
//!
//! This is designed to be called from the SDK without needing CLI-specific features.

use crate::{
	chain::{
		client::QuantusClient,
		quantus_subxt::{self as quantus_node, api::wormhole},
	},
	cli::wormhole::{compute_merkle_positions, ZkMerkleProofRpc},
	subsquid::{
		compute_address_hash, get_hash_prefix, SubsquidClient, Transfer, TransferQueryParams,
	},
	wormhole_lib,
	wormhole_lib::{compute_output_amount, NATIVE_ASSET_ID, VOLUME_FEE_BPS},
};
use plonky2::plonk::proof::ProofWithPublicInputs;
use qp_rusty_crystals_hdwallet::{derive_wormhole_from_mnemonic, QUANTUS_WORMHOLE_CHAIN_ID};
use qp_wormhole_aggregator::{
	aggregator::{AggregationBackend, CircuitType, Layer0Aggregator},
	config::CircuitBinsConfig,
};
use qp_zk_circuits_common::circuit::{C, D, F};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::path::Path;
use subxt::{
	ext::{
		codec::Encode,
		jsonrpsee::{core::client::ClientT, rpc_params},
	},
	tx::TxStatus,
};

/// Result type for collect rewards operations
pub type Result<T> = std::result::Result<T, CollectRewardsError>;

/// Error type for collect rewards operations
#[derive(Debug, Clone)]
pub struct CollectRewardsError {
	pub message: String,
}

impl std::fmt::Display for CollectRewardsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for CollectRewardsError {}

impl From<String> for CollectRewardsError {
	fn from(message: String) -> Self {
		Self { message }
	}
}

impl From<crate::error::QuantusError> for CollectRewardsError {
	fn from(e: crate::error::QuantusError) -> Self {
		Self { message: e.to_string() }
	}
}

/// Information about a pending transfer found via Subsquid
#[derive(Debug, Clone)]
pub struct PendingTransfer {
	/// Block height where the transfer was included
	pub block_height: i64,
	/// Block hash (hex encoded)
	pub block_hash: String,
	/// Transfer amount in planck
	pub amount: u128,
	/// Leaf index in the ZK tree
	pub leaf_index: u64,
	/// Transfer count (for nullifier computation)
	pub transfer_count: u64,
	/// Wormhole address that received the transfer (SS58)
	pub wormhole_address: String,
	/// Funding account that sent the transfer (SS58)
	pub funding_account: String,
}

/// Result of querying pending transfers
#[derive(Debug, Clone)]
pub struct QueryPendingTransfersResult {
	/// The wormhole address that was queried (SS58)
	pub wormhole_address: String,
	/// List of pending transfers
	pub transfers: Vec<PendingTransfer>,
	/// Total amount available for withdrawal (in planck)
	pub total_available: u128,
}

/// Progress callback trait for reporting status during collect_rewards
pub trait ProgressCallback: Send + Sync {
	/// Called when a step starts
	fn on_step(&self, step: &str, details: &str);
	/// Called when a proof is generated
	fn on_proof_generated(&self, index: usize, total: usize);
	/// Called when a batch is submitted
	fn on_batch_submitted(&self, batch_index: usize, total_batches: usize, amount_withdrawn: u128);
	/// Called on error
	fn on_error(&self, message: &str);
}

/// No-op progress callback for when caller doesn't need updates
pub struct NoOpProgress;
impl ProgressCallback for NoOpProgress {
	fn on_step(&self, _step: &str, _details: &str) {}
	fn on_proof_generated(&self, _index: usize, _total: usize) {}
	fn on_batch_submitted(&self, _batch_index: usize, _total_batches: usize, _amount: u128) {}
	fn on_error(&self, _message: &str) {}
}

/// Information about a completed withdrawal batch
#[derive(Debug, Clone)]
pub struct WithdrawalBatch {
	/// Block hash where the transaction was included
	pub block_hash: String,
	/// Transaction/extrinsic hash
	pub tx_hash: String,
	/// Amount withdrawn in this batch (planck)
	pub amount_withdrawn: u128,
	/// Number of proofs in this batch
	pub num_proofs: usize,
}

/// Result of the full collect_rewards operation
#[derive(Debug, Clone)]
pub struct CollectRewardsResult {
	/// The wormhole address that was withdrawn from
	pub wormhole_address: String,
	/// Destination address that received the funds
	pub destination_address: String,
	/// Total amount withdrawn (planck)
	pub total_withdrawn: u128,
	/// Information about each batch submitted
	pub batches: Vec<WithdrawalBatch>,
	/// Number of transfers processed
	pub transfers_processed: usize,
}

/// Configuration for collect_rewards
#[derive(Debug, Clone)]
pub struct CollectRewardsConfig {
	/// 24-word BIP39 mnemonic
	pub mnemonic: String,
	/// Wormhole address index (usually 0)
	pub wormhole_index: usize,
	/// Destination address (SS58) to receive withdrawn funds
	pub destination_address: String,
	/// Subsquid GraphQL endpoint URL
	pub subsquid_url: String,
	/// Chain RPC node URL
	pub node_url: String,
	/// Path to circuit binary files (prover.bin, common.bin, etc.)
	pub bins_dir: String,
	/// Optional: specific amount to withdraw (None = withdraw all)
	pub amount: Option<u128>,
	/// If true, only query and return info without submitting transactions
	pub dry_run: bool,
}

/// Collect miner rewards by querying Subsquid, generating proofs, and submitting withdrawals.
///
/// This is the main entry point for the SDK to collect rewards. It handles the entire flow:
/// 1. Derives wormhole address from mnemonic
/// 2. Queries Subsquid for pending transfers to that address
/// 3. Generates ZK proofs for selected transfers
/// 4. Aggregates proofs into batches (max 16 per batch)
/// 5. Submits withdrawal transactions to chain
///
/// # Arguments
/// * `config` - Configuration for the operation
/// * `progress` - Optional callback for progress updates
///
/// # Returns
/// Information about the withdrawal including total amount and batch details
pub async fn collect_rewards<P: ProgressCallback>(
	config: CollectRewardsConfig,
	progress: &P,
) -> Result<CollectRewardsResult> {
	// Step 1: Derive wormhole address
	progress.on_step("derive", "Deriving wormhole address from mnemonic");

	let path = format!("m/44'/{}/0'/1'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, config.wormhole_index);
	let wormhole_secret = derive_wormhole_from_mnemonic(&config.mnemonic, None, &path)
		.map_err(|e| CollectRewardsError::from(format!("HD derivation failed: {:?}", e)))?;

	let wormhole_address = AccountId32::from(wormhole_secret.address).to_ss58check();
	let secret_hex = hex::encode(&wormhole_secret.secret.as_ref());

	// Parse destination address
	let destination_bytes = parse_ss58_address(&config.destination_address)?;

	// Step 2: Query Subsquid for pending transfers
	progress.on_step("query", "Querying Subsquid for pending transfers");

	let subsquid_client = SubsquidClient::new(config.subsquid_url.clone())?;
	let address_hash = compute_address_hash(&wormhole_secret.address);
	let prefix = get_hash_prefix(&address_hash, 8);

	let params = TransferQueryParams::new().with_limit(1000);
	let transfers = subsquid_client
		.query_transfers_by_prefix(Some(vec![prefix]), None, params)
		.await?;

	// Filter to only transfers TO our wormhole address
	let incoming_transfers: Vec<_> =
		transfers.into_iter().filter(|t| t.to_hash == address_hash).collect();

	if incoming_transfers.is_empty() {
		return Ok(CollectRewardsResult {
			wormhole_address,
			destination_address: config.destination_address,
			total_withdrawn: 0,
			batches: vec![],
			transfers_processed: 0,
		});
	}

	// Step 2b: Filter out already-spent transfers by checking nullifiers
	progress.on_step("nullifiers", "Checking for already-spent nullifiers");

	let secret_bytes: [u8; 32] = wormhole_secret
		.secret
		.as_ref()
		.try_into()
		.map_err(|_| CollectRewardsError::from("Invalid secret length".to_string()))?;

	let unspent_transfers =
		filter_unspent_transfers(&incoming_transfers, &secret_bytes, &subsquid_client).await?;

	if unspent_transfers.is_empty() {
		progress
			.on_step("complete", "All transfers have already been withdrawn (nullifiers spent)");
		return Ok(CollectRewardsResult {
			wormhole_address,
			destination_address: config.destination_address,
			total_withdrawn: 0,
			batches: vec![],
			transfers_processed: 0,
		});
	}

	// Calculate total available (only unspent)
	let total_available: u128 =
		unspent_transfers.iter().map(|t| t.amount.parse::<u128>().unwrap_or(0)).sum();

	// Determine amount to withdraw
	let withdraw_amount = config.amount.unwrap_or(total_available);
	if withdraw_amount > total_available {
		return Err(CollectRewardsError::from(format!(
			"Requested {} but only {} available (after filtering spent nullifiers)",
			withdraw_amount, total_available
		)));
	}

	// Select transfers to cover the amount (largest first)
	let mut sorted_transfers = unspent_transfers.clone();
	sorted_transfers.sort_by(|a, b| {
		let amt_a: u128 = b.amount.parse().unwrap_or(0);
		let amt_b: u128 = a.amount.parse().unwrap_or(0);
		amt_a.cmp(&amt_b)
	});

	let mut selected_transfers = Vec::new();
	let mut selected_total: u128 = 0;
	for t in sorted_transfers {
		if selected_total >= withdraw_amount {
			break;
		}
		let amt: u128 = t.amount.parse().unwrap_or(0);
		selected_transfers.push(t);
		selected_total += amt;
	}

	if config.dry_run {
		return Ok(CollectRewardsResult {
			wormhole_address,
			destination_address: config.destination_address,
			total_withdrawn: 0,
			batches: vec![],
			transfers_processed: selected_transfers.len(),
		});
	}

	// Step 3: Connect to chain
	progress.on_step("connect", "Connecting to chain");

	let quantus_client = QuantusClient::new(&config.node_url)
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to connect to node: {}", e)))?;

	// Get current best block for proofs
	let best_block = quantus_client
		.get_latest_block()
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to get latest block: {}", e)))?;
	let proof_block = quantus_client
		.client()
		.blocks()
		.at(best_block)
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to get block: {}", e)))?;
	let proof_block_hash = proof_block.hash();

	// Step 4: Generate proofs
	progress.on_step("proofs", &format!("Generating {} proofs", selected_transfers.len()));

	let bins_dir = Path::new(&config.bins_dir);
	let num_transfers = selected_transfers.len();
	let mut proof_bytes_list: Vec<Vec<u8>> = Vec::new();

	for (i, transfer) in selected_transfers.iter().enumerate() {
		progress.on_proof_generated(i + 1, num_transfers);

		let leaf_index: u64 = transfer.leaf_index.parse().map_err(|_| {
			CollectRewardsError::from(format!("Invalid leaf_index: {}", transfer.leaf_index))
		})?;

		// Fetch ZK Merkle proof from chain
		let proof_params = rpc_params![leaf_index, proof_block_hash];
		let zk_proof: Option<ZkMerkleProofRpc> = quantus_client
			.rpc_client()
			.request("zkTree_getMerkleProof", proof_params)
			.await
			.map_err(|e| {
				CollectRewardsError::from(format!(
					"Failed to get ZK Merkle proof for leaf {}: {}",
					leaf_index, e
				))
			})?;

		let zk_proof = zk_proof.ok_or_else(|| {
			CollectRewardsError::from(format!(
				"No ZK Merkle proof found for leaf_index {}",
				leaf_index
			))
		})?;

		// Decode transfer_count and input_amount from leaf_data
		let (_, transfer_count, _, _) = decode_full_leaf_data(&zk_proof.leaf_data)?;
		let input_amount = decode_input_amount_from_leaf(&zk_proof.leaf_data)?;
		let output_amount = compute_output_amount(input_amount, VOLUME_FEE_BPS);

		// Compute sorted siblings and positions
		let (sorted_siblings, positions) =
			compute_merkle_positions(&zk_proof.siblings, zk_proof.leaf_hash);

		// Get block header data
		let header = proof_block.header();
		let parent_hash: [u8; 32] = header.parent_hash.0;
		let state_root: [u8; 32] = header.state_root.0;
		let extrinsics_root: [u8; 32] = header.extrinsics_root.0;
		let digest = header.digest.encode();
		let block_number = header.number;

		// Parse secret
		let secret = parse_secret_hex(&secret_hex)?;
		let wormhole_address_bytes = wormhole_lib::compute_wormhole_address(&secret)
			.map_err(|e| CollectRewardsError::from(e.message))?;

		// Build proof input
		let input = wormhole_lib::ProofGenerationInput {
			secret,
			transfer_count,
			wormhole_address: wormhole_address_bytes,
			input_amount,
			block_hash: proof_block_hash.0,
			block_number,
			parent_hash,
			state_root,
			extrinsics_root,
			digest,
			zk_tree_root: zk_proof.root,
			zk_merkle_siblings: sorted_siblings,
			zk_merkle_positions: positions,
			exit_account_1: destination_bytes,
			exit_account_2: [0u8; 32],
			output_amount_1: output_amount,
			output_amount_2: 0,
			volume_fee_bps: VOLUME_FEE_BPS,
			asset_id: NATIVE_ASSET_ID,
		};

		// Generate proof
		let result = wormhole_lib::generate_proof(
			&input,
			&bins_dir.join("prover.bin"),
			&bins_dir.join("common.bin"),
		)
		.map_err(|e| CollectRewardsError::from(e.message))?;

		proof_bytes_list.push(result.proof_bytes);
	}

	// Step 5: Aggregate and submit in batches
	const MAX_PROOFS_PER_BATCH: usize = 16;
	let batches: Vec<Vec<Vec<u8>>> = proof_bytes_list
		.chunks(MAX_PROOFS_PER_BATCH)
		.map(|chunk| chunk.to_vec())
		.collect();

	progress.on_step("submit", &format!("Submitting {} batch(es)", batches.len()));

	let mut total_withdrawn: u128 = 0;
	let mut batch_results: Vec<WithdrawalBatch> = Vec::new();

	for (batch_idx, batch_proofs) in batches.iter().enumerate() {
		// Aggregate proofs
		let aggregated_proof = aggregate_proof_bytes(batch_proofs, bins_dir)?;

		// Submit to chain
		let (block_hash, tx_hash, transfer_events) =
			submit_and_get_events(&quantus_client, aggregated_proof).await?;

		let batch_amount: u128 = transfer_events.iter().map(|e| e.amount).sum();
		total_withdrawn += batch_amount;

		progress.on_batch_submitted(batch_idx + 1, batches.len(), batch_amount);

		batch_results.push(WithdrawalBatch {
			block_hash: hex::encode(block_hash.0),
			tx_hash: hex::encode(tx_hash.0),
			amount_withdrawn: batch_amount,
			num_proofs: batch_proofs.len(),
		});
	}

	Ok(CollectRewardsResult {
		wormhole_address,
		destination_address: config.destination_address,
		total_withdrawn,
		batches: batch_results,
		transfers_processed: selected_transfers.len(),
	})
}

/// Query pending transfers for a wormhole address via Subsquid.
///
/// This function queries the Subsquid indexer for transfers that were sent
/// to the wormhole address derived from the given mnemonic. This allows
/// discovery of mining rewards even if they weren't tracked locally.
///
/// # Arguments
/// * `mnemonic` - The 24-word BIP39 mnemonic phrase
/// * `wormhole_index` - The wormhole address index (default: 0)
/// * `subsquid_url` - The Subsquid GraphQL endpoint URL
///
/// # Returns
/// The wormhole address, list of pending transfers, and total available balance.
pub async fn query_pending_transfers(
	mnemonic: &str,
	wormhole_index: usize,
	subsquid_url: &str,
) -> Result<QueryPendingTransfersResult> {
	// Derive wormhole secret using HD path for miner rewards (purpose = 1)
	let path = format!("m/44'/{}/0'/1'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, wormhole_index);
	let wormhole_secret = derive_wormhole_from_mnemonic(mnemonic, None, &path)
		.map_err(|e| CollectRewardsError::from(format!("HD derivation failed: {:?}", e)))?;

	let wormhole_address = AccountId32::from(wormhole_secret.address).to_ss58check();

	// Query Subsquid using privacy-preserving hash prefix
	let subsquid_client = SubsquidClient::new(subsquid_url.to_string())?;
	let address_hash = compute_address_hash(&wormhole_secret.address);
	let prefix = get_hash_prefix(&address_hash, 8); // 8 hex chars for good privacy

	let params = TransferQueryParams::new().with_limit(1000);
	let transfers = subsquid_client
		.query_transfers_by_prefix(Some(vec![prefix]), None, params)
		.await?;

	// Filter to only transfers TO our wormhole address
	let incoming_transfers: Vec<_> =
		transfers.into_iter().filter(|t| t.to_hash == address_hash).collect();

	let mut total_available: u128 = 0;
	let mut pending = Vec::new();

	for t in &incoming_transfers {
		let amount: u128 = t.amount.parse().unwrap_or(0);
		total_available += amount;

		let leaf_index: u64 = t.leaf_index.parse().unwrap_or(0);
		let transfer_count: u64 = t.transfer_count.parse().unwrap_or(0);

		pending.push(PendingTransfer {
			block_height: t.block_height,
			block_hash: t.block_id.clone(),
			amount,
			leaf_index,
			transfer_count,
			wormhole_address: wormhole_address.clone(),
			funding_account: t.from_id.clone(),
		});
	}

	Ok(QueryPendingTransfersResult { wormhole_address, transfers: pending, total_available })
}

/// Query pending transfers for an already-known wormhole address.
///
/// Use this when you already have the wormhole address and don't need to derive it.
///
/// # Arguments
/// * `wormhole_address_bytes` - The 32-byte wormhole address
/// * `subsquid_url` - The Subsquid GraphQL endpoint URL
pub async fn query_pending_transfers_for_address(
	wormhole_address_bytes: &[u8; 32],
	subsquid_url: &str,
) -> Result<QueryPendingTransfersResult> {
	let wormhole_address = AccountId32::from(*wormhole_address_bytes).to_ss58check();

	// Query Subsquid using privacy-preserving hash prefix
	let subsquid_client = SubsquidClient::new(subsquid_url.to_string())?;
	let address_hash = compute_address_hash(wormhole_address_bytes);
	let prefix = get_hash_prefix(&address_hash, 8);

	let params = TransferQueryParams::new().with_limit(1000);
	let transfers = subsquid_client
		.query_transfers_by_prefix(Some(vec![prefix]), None, params)
		.await?;

	// Filter to only transfers TO our wormhole address
	let incoming_transfers: Vec<_> =
		transfers.into_iter().filter(|t| t.to_hash == address_hash).collect();

	let mut total_available: u128 = 0;
	let mut pending = Vec::new();

	for t in &incoming_transfers {
		let amount: u128 = t.amount.parse().unwrap_or(0);
		total_available += amount;

		let leaf_index: u64 = t.leaf_index.parse().unwrap_or(0);
		let transfer_count: u64 = t.transfer_count.parse().unwrap_or(0);

		pending.push(PendingTransfer {
			block_height: t.block_height,
			block_hash: t.block_id.clone(),
			amount,
			leaf_index,
			transfer_count,
			wormhole_address: wormhole_address.clone(),
			funding_account: t.from_id.clone(),
		});
	}

	Ok(QueryPendingTransfersResult { wormhole_address, transfers: pending, total_available })
}

// ============================================================================
// Internal Helper Functions
// ============================================================================

/// Parse an SS58 address to 32 bytes
fn parse_ss58_address(address: &str) -> Result<[u8; 32]> {
	let account = AccountId32::from_ss58check(address)
		.map_err(|e| CollectRewardsError::from(format!("Invalid SS58 address: {:?}", e)))?;
	Ok(account.into())
}

/// Parse secret hex string to bytes
fn parse_secret_hex(secret_hex: &str) -> Result<[u8; 32]> {
	let bytes = hex::decode(secret_hex.trim_start_matches("0x"))
		.map_err(|e| CollectRewardsError::from(format!("Invalid secret hex: {}", e)))?;
	bytes
		.try_into()
		.map_err(|_| CollectRewardsError::from("Secret must be 32 bytes".to_string()))
}

/// Decode all fields from SCALE-encoded ZkLeaf data.
/// Returns (to_account, transfer_count, asset_id, raw_amount_u128)
fn decode_full_leaf_data(leaf_data: &[u8]) -> Result<([u8; 32], u64, u32, u128)> {
	if leaf_data.len() < 60 {
		return Err(CollectRewardsError::from(format!(
			"Invalid leaf data length: expected at least 60 bytes, got {}",
			leaf_data.len()
		)));
	}

	let to_account: [u8; 32] = leaf_data[0..32]
		.try_into()
		.map_err(|_| CollectRewardsError::from("Failed to extract to_account".to_string()))?;

	let transfer_count =
		u64::from_le_bytes(leaf_data[32..40].try_into().map_err(|_| {
			CollectRewardsError::from("Failed to extract transfer_count".to_string())
		})?);

	let asset_id = u32::from_le_bytes(
		leaf_data[40..44]
			.try_into()
			.map_err(|_| CollectRewardsError::from("Failed to extract asset_id".to_string()))?,
	);

	let amount = u128::from_le_bytes(
		leaf_data[44..60]
			.try_into()
			.map_err(|_| CollectRewardsError::from("Failed to extract amount".to_string()))?,
	);

	Ok((to_account, transfer_count, asset_id, amount))
}

/// Decode the input amount from SCALE-encoded ZkLeaf data (quantized).
fn decode_input_amount_from_leaf(leaf_data: &[u8]) -> Result<u32> {
	if leaf_data.len() < 60 {
		return Err(CollectRewardsError::from(format!(
			"Invalid leaf data length: expected at least 60 bytes, got {}",
			leaf_data.len()
		)));
	}

	let amount_bytes: [u8; 16] = leaf_data[44..60]
		.try_into()
		.map_err(|_| CollectRewardsError::from("Failed to extract amount bytes".to_string()))?;

	let raw_amount = u128::from_le_bytes(amount_bytes);

	// Quantize: divide by 10^10 to get 2 decimal places
	const AMOUNT_SCALE_DOWN_FACTOR: u128 = 10_000_000_000;
	let quantized = (raw_amount / AMOUNT_SCALE_DOWN_FACTOR) as u32;

	Ok(quantized)
}

/// Aggregate proof bytes into a single aggregated proof
fn aggregate_proof_bytes(proof_bytes_list: &[Vec<u8>], bins_dir: &Path) -> Result<Vec<u8>> {
	// Load config to validate
	let agg_config = CircuitBinsConfig::load(bins_dir).map_err(|e| {
		CollectRewardsError::from(format!("Failed to load circuit bins config: {}", e))
	})?;

	if proof_bytes_list.len() > agg_config.num_leaf_proofs {
		return Err(CollectRewardsError::from(format!(
			"Too many proofs: {} provided, max {} supported",
			proof_bytes_list.len(),
			agg_config.num_leaf_proofs
		)));
	}

	let mut aggregator = Layer0Aggregator::new(bins_dir)
		.map_err(|e| CollectRewardsError::from(format!("Failed to load aggregator: {}", e)))?;

	let common_data = aggregator.load_common_data(CircuitType::Leaf).map_err(|e| {
		CollectRewardsError::from(format!("Failed to load leaf circuit data: {}", e))
	})?;

	// Add proofs
	for proof_bytes in proof_bytes_list {
		let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), &common_data)
			.map_err(|e| {
				CollectRewardsError::from(format!("Failed to deserialize proof: {:?}", e))
			})?;
		aggregator
			.push_proof(proof)
			.map_err(|e| CollectRewardsError::from(format!("Failed to push proof: {}", e)))?;
	}

	// Aggregate
	let aggregated_proof = aggregator
		.aggregate()
		.map_err(|e| CollectRewardsError::from(format!("Aggregation failed: {}", e)))?;

	Ok(aggregated_proof.to_bytes())
}

/// Submit aggregated proof and collect events
async fn submit_and_get_events(
	quantus_client: &QuantusClient,
	proof_bytes: Vec<u8>,
) -> Result<(subxt::utils::H256, subxt::utils::H256, Vec<wormhole::events::NativeTransferred>)> {
	// Verify locally first
	let bins_dir = Path::new("generated-bins");

	let verifier = qp_wormhole_verifier::WormholeVerifier::new_from_files(
		&bins_dir.join("aggregated_verifier.bin"),
		&bins_dir.join("aggregated_common.bin"),
	)
	.map_err(|e| CollectRewardsError::from(format!("Failed to load verifier: {}", e)))?;

	let proof = qp_wormhole_verifier::ProofWithPublicInputs::<
		qp_wormhole_verifier::F,
		qp_wormhole_verifier::C,
		{ qp_wormhole_verifier::D },
	>::from_bytes(proof_bytes.clone(), &verifier.circuit_data.common)
	.map_err(|e| CollectRewardsError::from(format!("Failed to deserialize proof: {}", e)))?;

	verifier
		.verify(proof)
		.map_err(|e| CollectRewardsError::from(format!("Local verification failed: {}", e)))?;

	// Submit unsigned tx
	let verify_tx = quantus_node::api::tx().wormhole().verify_aggregated_proof(proof_bytes);

	let unsigned_tx =
		quantus_client.client().tx().create_unsigned(&verify_tx).map_err(|e| {
			CollectRewardsError::from(format!("Failed to create unsigned tx: {}", e))
		})?;

	let mut tx_progress = unsigned_tx
		.submit_and_watch()
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to submit tx: {}", e)))?;

	// Wait for inclusion
	let (block_hash, tx_hash) = loop {
		match tx_progress.next().await {
			Some(Ok(TxStatus::InBestBlock(tx_in_block))) => {
				break (tx_in_block.block_hash(), tx_in_block.extrinsic_hash());
			},
			Some(Ok(TxStatus::InFinalizedBlock(tx_in_block))) => {
				break (tx_in_block.block_hash(), tx_in_block.extrinsic_hash());
			},
			Some(Ok(TxStatus::Error { message })) | Some(Ok(TxStatus::Invalid { message })) => {
				return Err(CollectRewardsError::from(format!("Transaction failed: {}", message)));
			},
			Some(Ok(_)) => continue,
			Some(Err(e)) => {
				return Err(CollectRewardsError::from(format!("Transaction error: {}", e)));
			},
			None => {
				return Err(CollectRewardsError::from(
					"Transaction stream ended unexpectedly".to_string(),
				));
			},
		}
	};

	// Collect events
	let block = quantus_client
		.client()
		.blocks()
		.at(block_hash)
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to get block: {}", e)))?;

	let events = block
		.events()
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to get events: {}", e)))?;

	let extrinsics = block
		.extrinsics()
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to get extrinsics: {}", e)))?;

	let our_ext_idx = extrinsics
		.iter()
		.enumerate()
		.find(|(_, ext)| ext.hash() == tx_hash)
		.map(|(idx, _)| idx as u32)
		.ok_or_else(|| {
			CollectRewardsError::from("Could not find extrinsic in block".to_string())
		})?;

	let mut transfer_events = Vec::new();
	let mut found_proof_verified = false;

	for event_result in events.iter() {
		let event = event_result
			.map_err(|e| CollectRewardsError::from(format!("Failed to decode event: {}", e)))?;

		if let subxt::events::Phase::ApplyExtrinsic(ext_idx) = event.phase() {
			if ext_idx == our_ext_idx {
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

	if !found_proof_verified {
		return Err(CollectRewardsError::from(
			"Proof verification failed - no ProofVerified event".to_string(),
		));
	}

	Ok((block_hash, tx_hash, transfer_events))
}

/// Filter out transfers whose nullifiers have already been spent.
///
/// For each transfer, computes the nullifier from (secret, transfer_count)
/// and checks Subsquid to see if it's been consumed by a previous withdrawal.
async fn filter_unspent_transfers(
	transfers: &[Transfer],
	secret_bytes: &[u8; 32],
	subsquid_client: &SubsquidClient,
) -> Result<Vec<Transfer>> {
	use std::collections::HashSet;

	if transfers.is_empty() {
		return Ok(vec![]);
	}

	// Compute nullifiers for all transfers
	// Map: nullifier_hex -> (nullifier_hash, transfer)
	let mut nullifier_map: std::collections::HashMap<String, (String, &Transfer)> =
		std::collections::HashMap::new();

	for transfer in transfers {
		let transfer_count: u64 = transfer.transfer_count.parse().unwrap_or(0);

		let nullifier =
			wormhole_lib::compute_nullifier(&secret_bytes, transfer_count).map_err(|e| {
				CollectRewardsError::from(format!("Failed to compute nullifier: {}", e.message))
			})?;

		let nullifier_hex = hex::encode(nullifier);
		let nullifier_hash = compute_address_hash(&nullifier);

		nullifier_map.insert(nullifier_hex, (nullifier_hash, transfer));
	}

	// Build list for Subsquid query
	let nullifier_pairs: Vec<(String, String)> = nullifier_map
		.iter()
		.map(|(nul_hex, (nul_hash, _))| (nul_hex.clone(), nul_hash.clone()))
		.collect();

	// Query Subsquid for spent nullifiers (using 8-char prefix for privacy)
	let spent_nullifiers: HashSet<String> = subsquid_client
		.check_nullifiers_spent(&nullifier_pairs, 8)
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to query nullifiers: {}", e)))?;

	// Filter to only unspent transfers
	let unspent: Vec<Transfer> = nullifier_map
		.into_iter()
		.filter(|(nul_hex, _)| !spent_nullifiers.contains(nul_hex))
		.map(|(_, (_, transfer))| transfer.clone())
		.collect();

	Ok(unspent)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_collect_rewards_error_from_string() {
		let err = CollectRewardsError::from("test error".to_string());
		assert_eq!(err.message, "test error");
		assert_eq!(format!("{}", err), "test error");
	}

	#[test]
	fn test_parse_ss58_address() {
		// Valid Quantus address (SS58 prefix 189)
		let result = parse_ss58_address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
		assert!(result.is_ok());
	}

	#[test]
	fn test_decode_input_amount_from_leaf() {
		// Create a mock leaf data (60 bytes minimum)
		let mut leaf_data = vec![0u8; 60];
		// Set amount at bytes 44-60 (1 QTM = 10^12 planck)
		let amount: u128 = 1_000_000_000_000; // 1 QTM
		leaf_data[44..60].copy_from_slice(&amount.to_le_bytes());

		let result = decode_input_amount_from_leaf(&leaf_data).unwrap();
		// 1 QTM = 10^12 planck, quantized = 10^12 / 10^10 = 100
		assert_eq!(result, 100);
	}
}
