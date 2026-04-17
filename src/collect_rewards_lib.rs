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
	cli::wormhole::{parse_secret_hex as parse_secret_hex_str, ZkMerkleProofRpc},
	subsquid::{
		compute_address_hash, get_hash_prefix, SubsquidClient, Transfer, TransferQueryParams,
	},
	wormhole_lib,
	wormhole_lib::{compute_output_amount, NATIVE_ASSET_ID, VOLUME_FEE_BPS},
};

type Hash256 = [u8; 32];

/// Compute sorted siblings and position hints from unsorted siblings.
///
/// The chain returns unsorted siblings. This function sorts them and computes
/// position hints that indicate where the current hash fits in the sorted order.
fn compute_merkle_positions(
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

		// Compute parent hash for next level
		current_hash = hash_node_presorted(&all_four);
	}

	(sorted_siblings, positions)
}
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
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct QueryPendingTransfersResult {
	/// The wormhole address that was queried (SS58)
	pub wormhole_address: String,
	/// List of pending transfers
	pub transfers: Vec<PendingTransfer>,
	/// Total amount available for withdrawal (in planck)
	pub total_available: u128,
}

/// Progress callback trait for reporting status during collect_rewards
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct NoOpProgress;
impl ProgressCallback for NoOpProgress {
	fn on_step(&self, _step: &str, _details: &str) {}
	fn on_proof_generated(&self, _index: usize, _total: usize) {}
	fn on_batch_submitted(&self, _batch_index: usize, _total_batches: usize, _amount: u128) {}
	fn on_error(&self, _message: &str) {}
}

/// Information about a completed withdrawal batch
#[derive(Debug, Clone)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
	/// Optional: specific block number to use for proofs (None = use latest)
	pub at_block: Option<u32>,
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
	let secret_hex = hex::encode(wormhole_secret.secret.as_ref());

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

	// Step 2b: Connect to chain (needed for nullifier fallback and proof submission)
	progress.on_step("connect", "Connecting to chain");

	let quantus_client = QuantusClient::new(&config.node_url)
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to connect to node: {}", e)))?;

	// Step 2c: Filter out already-spent transfers by checking nullifiers
	// Tries Subsquid first, falls back to on-chain checking if Subsquid fails
	progress.on_step("nullifiers", "Checking for already-spent nullifiers");

	let secret_bytes: [u8; 32] = wormhole_secret
		.secret
		.as_ref()
		.try_into()
		.map_err(|_| CollectRewardsError::from("Invalid secret length".to_string()))?;

	let unspent_transfers = filter_unspent_transfers_with_fallback(
		&incoming_transfers,
		&secret_bytes,
		&subsquid_client,
		&quantus_client,
	)
	.await?;

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
	let mut total_available: u128 = 0;
	for t in &unspent_transfers {
		total_available += parse_transfer_amount(&t.amount, &format!("transfer {}", t.id))?;
	}

	// Determine amount to withdraw
	let withdraw_amount = config.amount.unwrap_or(total_available);
	if withdraw_amount > total_available {
		return Err(CollectRewardsError::from(format!(
			"Requested {} but only {} available (after filtering spent nullifiers)",
			withdraw_amount, total_available
		)));
	}

	// Parse amounts for sorting (fail early if any are invalid)
	let mut transfers_with_amounts: Vec<(Transfer, u128)> = Vec::new();
	for t in unspent_transfers {
		let amt = parse_transfer_amount(&t.amount, &format!("transfer {}", t.id))?;
		transfers_with_amounts.push((t, amt));
	}

	// Sort by amount descending (largest first)
	transfers_with_amounts.sort_by_key(|k| std::cmp::Reverse(k.1));

	let mut selected_transfers = Vec::new();
	let mut selected_total: u128 = 0;
	for (t, amt) in transfers_with_amounts {
		if selected_total >= withdraw_amount {
			break;
		}
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

	// Get block for proofs - either specific block or latest
	let proof_block = if let Some(block_num) = config.at_block {
		// Fetch block hash for the specified block number
		use subxt::ext::jsonrpsee::{core::client::ClientT, rpc_params};
		let block_hash: Option<subxt::utils::H256> = quantus_client
			.rpc_client()
			.request("chain_getBlockHash", rpc_params![block_num])
			.await
			.map_err(|e| {
				CollectRewardsError::from(format!(
					"Failed to get block hash for block {}: {}",
					block_num, e
				))
			})?;
		let block_hash = block_hash
			.ok_or_else(|| CollectRewardsError::from(format!("Block {} not found", block_num)))?;
		quantus_client
			.client()
			.blocks()
			.at(block_hash)
			.await
			.map_err(|e| CollectRewardsError::from(format!("Failed to get block: {}", e)))?
	} else {
		// Use latest block
		let best_block = quantus_client
			.get_latest_block()
			.await
			.map_err(|e| CollectRewardsError::from(format!("Failed to get latest block: {}", e)))?;
		quantus_client
			.client()
			.blocks()
			.at(best_block)
			.await
			.map_err(|e| CollectRewardsError::from(format!("Failed to get block: {}", e)))?
	};
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

		// Decode transfer data from leaf
		let (leaf_to_account, transfer_count, _leaf_asset_id, _leaf_raw_amount) =
			decode_full_leaf_data(&zk_proof.leaf_data)?;
		let input_amount = decode_input_amount_from_leaf(&zk_proof.leaf_data)?;
		let output_amount = compute_output_amount(input_amount, VOLUME_FEE_BPS);

		// Compute sorted siblings and positions from unsorted RPC data
		let (sorted_siblings, positions) =
			compute_merkle_positions(&zk_proof.siblings, zk_proof.leaf_hash);

		// Get block header data
		let header = proof_block.header();
		let parent_hash: [u8; 32] = header.parent_hash.0;
		let state_root: [u8; 32] = header.state_root.0;
		let extrinsics_root: [u8; 32] = header.extrinsics_root.0;
		let digest = header.digest.encode();
		let block_number = header.number;

		// Parse secret and compute wormhole address
		let secret = parse_secret_hex(&secret_hex)?;
		let wormhole_address_bytes = wormhole_lib::compute_wormhole_address(&secret)
			.map_err(|e| CollectRewardsError::from(e.message))?;

		// Verify the leaf's to_account matches our computed wormhole address
		if leaf_to_account != wormhole_address_bytes {
			return Err(CollectRewardsError::from(format!(
				"Leaf to_account mismatch: expected 0x{}, got 0x{}",
				hex::encode(wormhole_address_bytes),
				hex::encode(leaf_to_account)
			)));
		}

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
			digest: digest.clone(),
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
		let prover_path = bins_dir.join("prover.bin");
		let common_path = bins_dir.join("common.bin");
		let result = wormhole_lib::generate_proof(&input, &prover_path, &common_path)
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
			submit_and_get_events(&quantus_client, aggregated_proof, bins_dir).await?;

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
#[allow(dead_code)]
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
		let ctx = format!("transfer {}", t.id);
		let amount = parse_transfer_amount(&t.amount, &ctx)?;
		let leaf_index = parse_leaf_index(&t.leaf_index, &ctx)?;
		let transfer_count = parse_transfer_count(&t.transfer_count, &ctx)?;

		total_available += amount;

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
#[allow(dead_code)]
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
		let ctx = format!("transfer {}", t.id);
		let amount = parse_transfer_amount(&t.amount, &ctx)?;
		let leaf_index = parse_leaf_index(&t.leaf_index, &ctx)?;
		let transfer_count = parse_transfer_count(&t.transfer_count, &ctx)?;

		total_available += amount;

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

/// Parse a transfer amount string to u128
fn parse_transfer_amount(amount_str: &str, context: &str) -> Result<u128> {
	amount_str.parse::<u128>().map_err(|e| {
		CollectRewardsError::from(format!(
			"Invalid transfer amount '{}' in {}: {}",
			amount_str, context, e
		))
	})
}

/// Parse a leaf index string to u64
fn parse_leaf_index(leaf_index_str: &str, context: &str) -> Result<u64> {
	leaf_index_str.parse::<u64>().map_err(|e| {
		CollectRewardsError::from(format!(
			"Invalid leaf_index '{}' in {}: {}",
			leaf_index_str, context, e
		))
	})
}

/// Parse a transfer count string to u64
fn parse_transfer_count(transfer_count_str: &str, context: &str) -> Result<u64> {
	transfer_count_str.parse::<u64>().map_err(|e| {
		CollectRewardsError::from(format!(
			"Invalid transfer_count '{}' in {}: {}",
			transfer_count_str, context, e
		))
	})
}

/// Parse an SS58 address to 32 bytes
fn parse_ss58_address(address: &str) -> Result<[u8; 32]> {
	let account = AccountId32::from_ss58check(address)
		.map_err(|e| CollectRewardsError::from(format!("Invalid SS58 address: {:?}", e)))?;
	Ok(account.into())
}

/// Parse secret hex string to bytes
fn parse_secret_hex(secret_hex: &str) -> Result<[u8; 32]> {
	parse_secret_hex_str(secret_hex).map_err(CollectRewardsError::from)
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
	bins_dir: &Path,
) -> Result<(subxt::utils::H256, subxt::utils::H256, Vec<wormhole::events::NativeTransferred>)> {
	// Verify locally first

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
		.verify(proof.clone())
		.map_err(|e| CollectRewardsError::from(format!("Local verification failed: {}", e)))?;

	// Parse public inputs to do pre-submission validation
	let inputs = qp_wormhole_verifier::parse_aggregated_public_inputs(&proof).map_err(|e| {
		CollectRewardsError::from(format!("Failed to parse public inputs: {:?}", e))
	})?;

	// Check asset_id (must be 0 for native)
	if inputs.asset_id != 0 {
		return Err(CollectRewardsError::from(format!(
			"Pre-validation failed: NonNativeAssetNotSupported (asset_id = {}, expected 0)",
			inputs.asset_id
		)));
	}

	// Check volume fee BPS (should be 10 for testnet)
	// Note: We can't query the chain config directly, but 10 is the expected value
	const EXPECTED_VOLUME_FEE_BPS: u32 = 10;
	if inputs.volume_fee_bps != EXPECTED_VOLUME_FEE_BPS {
		return Err(CollectRewardsError::from(format!(
			"Pre-validation failed: InvalidVolumeFeeRate (got {}, expected {})",
			inputs.volume_fee_bps, EXPECTED_VOLUME_FEE_BPS
		)));
	}

	// Check block hash exists and matches
	let proof_block_number = inputs.block_data.block_number;
	use subxt::ext::jsonrpsee::{core::client::ClientT, rpc_params};
	let chain_block_hash: Option<subxt::utils::H256> = quantus_client
		.rpc_client()
		.request("chain_getBlockHash", rpc_params![proof_block_number])
		.await
		.map_err(|e| {
			CollectRewardsError::from(format!(
				"Failed to query block hash for block {}: {}",
				proof_block_number, e
			))
		})?;

	match chain_block_hash {
		None => {
			return Err(CollectRewardsError::from(format!(
				"Pre-validation failed: BlockNotFound - Block {} does not exist on chain (may be pruned or too old)",
				proof_block_number
			)));
		},
		Some(chain_hash) => {
			let proof_hash: [u8; 32] = *inputs.block_data.block_hash;
			if chain_hash.0 != proof_hash {
				return Err(CollectRewardsError::from(format!(
					"Pre-validation failed: InvalidPublicInputs - Block hash mismatch!\n  Chain has: 0x{}\n  Proof has: 0x{}",
					hex::encode(chain_hash.0),
					hex::encode(proof_hash)
				)));
			}
		},
	}

	// Check nullifiers aren't already used
	for (i, nullifier) in inputs.nullifiers.iter().enumerate() {
		let nullifier_bytes: [u8; 32] = (*nullifier).as_ref().try_into().map_err(|_| {
			CollectRewardsError::from(format!("Failed to convert nullifier {} to bytes", i))
		})?;

		// Query UsedNullifiers storage
		let storage_key = quantus_node::api::storage().wormhole().used_nullifiers(nullifier_bytes);
		let is_used = quantus_client
			.client()
			.storage()
			.at_latest()
			.await
			.map_err(|e| CollectRewardsError::from(format!("Failed to get storage: {}", e)))?
			.fetch(&storage_key)
			.await
			.map_err(|e| {
				CollectRewardsError::from(format!("Failed to query nullifier {}: {}", i, e))
			})?;

		if is_used.is_some() {
			return Err(CollectRewardsError::from(format!(
				"Pre-validation failed: NullifierAlreadyUsed - Nullifier {} (0x{}) has already been spent",
				i,
				hex::encode(nullifier_bytes)
			)));
		}
	}

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

/// Filter out transfers whose nullifiers have already been spent (on-chain check).
///
/// For each transfer, computes the nullifier from (secret, transfer_count)
/// and checks on-chain storage to see if it's been consumed by a previous withdrawal.
/// This is more reliable than Subsquid as it queries the chain directly.
async fn filter_unspent_transfers_onchain(
	transfers: &[Transfer],
	secret_bytes: &[u8; 32],
	quantus_client: &QuantusClient,
) -> Result<Vec<Transfer>> {
	if transfers.is_empty() {
		return Ok(vec![]);
	}

	let mut unspent = Vec::new();
	let storage = quantus_client
		.client()
		.storage()
		.at_latest()
		.await
		.map_err(|e| CollectRewardsError::from(format!("Failed to get storage: {}", e)))?;

	for transfer in transfers {
		let ctx = format!("transfer {}", transfer.id);
		let transfer_count = parse_transfer_count(&transfer.transfer_count, &ctx)?;

		let nullifier =
			wormhole_lib::compute_nullifier(secret_bytes, transfer_count).map_err(|e| {
				CollectRewardsError::from(format!("Failed to compute nullifier: {}", e.message))
			})?;

		// Query on-chain UsedNullifiers storage
		let storage_key = quantus_node::api::storage().wormhole().used_nullifiers(nullifier);
		let is_used = storage.fetch(&storage_key).await.map_err(|e| {
			CollectRewardsError::from(format!(
				"Failed to query nullifier for transfer_count {}: {}",
				transfer_count, e
			))
		})?;

		if is_used.is_none() {
			unspent.push(transfer.clone());
		}
	}

	Ok(unspent)
}

/// Filter out transfers whose nullifiers have already been spent.
///
/// For each transfer, computes the nullifier from (secret, transfer_count)
/// and checks Subsquid to see if it's been consumed by a previous withdrawal.
/// If Subsquid query fails, falls back to on-chain checking.
async fn filter_unspent_transfers_with_fallback(
	transfers: &[Transfer],
	secret_bytes: &[u8; 32],
	subsquid_client: &SubsquidClient,
	quantus_client: &QuantusClient,
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
		let ctx = format!("transfer {}", transfer.id);
		let transfer_count = parse_transfer_count(&transfer.transfer_count, &ctx)?;

		let nullifier =
			wormhole_lib::compute_nullifier(secret_bytes, transfer_count).map_err(|e| {
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

	// Try Subsquid first, fall back to on-chain if it fails
	let spent_nullifiers: HashSet<String> =
		match subsquid_client.check_nullifiers_spent(&nullifier_pairs, 8).await {
			Ok(spent) => spent,
			Err(_) => {
				// Fall back to on-chain checking
				return filter_unspent_transfers_onchain(transfers, secret_bytes, quantus_client)
					.await;
			},
		};

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
