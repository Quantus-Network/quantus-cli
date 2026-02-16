//! Integration tests for wormhole proof verification on-chain
//!
//! These tests require a local Quantus node running at ws://127.0.0.1:9944
//! with funded developer accounts (crystal_alice, crystal_bob, crystal_charlie).
//!
//! Run with: `cargo test --test wormhole_integration -- --ignored --nocapture`
//!
//! The tests verify the full end-to-end flow:
//! 1. Fund an unspendable account via wormhole transfer
//! 2. Generate a ZK proof of the transfer
//! 3. Submit the proof for on-chain verification
//! 4. For aggregated proofs: generate multiple proofs and aggregate them
//!
//! Note: For aggregation, proofs must be from the same block or consecutive blocks
//! with valid parent hash linkage. We use batch transfers to ensure same-block proofs.

use plonky2::plonk::{circuit_data::CircuitConfig, proof::ProofWithPublicInputs};
use qp_wormhole_circuit::{
	inputs::{CircuitInputs, PrivateCircuitInputs},
	nullifier::Nullifier,
};
use qp_wormhole_inputs::{AggregatedPublicCircuitInputs, PublicCircuitInputs};
use qp_wormhole_prover::WormholeProver;

use qp_zk_circuits_common::{
	circuit::{C, D, F},
	storage_proof::prepare_proof_for_circuit,
	utils::{digest_felts_to_bytes, BytesDigest},
};
use quantus_cli::{
	chain::{
		client::QuantusClient,
		quantus_subxt::{self as quantus_node, api::wormhole},
	},
	wallet::{QuantumKeyPair, WalletManager},
};
use rand::{rng, RngCore};
use serial_test::serial;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	Decode, Hasher,
};
use sp_runtime::Permill;
use std::time::Duration;
use subxt::{
	backend::legacy::rpc_methods::ReadProof,
	ext::{codec::Encode, jsonrpsee::core::client::ClientT},
	tx::TxStatus,
	utils::{to_hex, AccountId32 as SubxtAccountId},
};

/// Default local node URL for testing
const LOCAL_NODE_URL: &str = "ws://127.0.0.1:9944";

/// Native asset ID (matches chain configuration)
const NATIVE_ASSET_ID: u32 = 0;

/// Scale down factor for quantizing amounts (10^10 to go from 12 to 2 decimal places)
const SCALE_DOWN_FACTOR: u128 = 10_000_000_000;

/// Volume fee rate in basis points (10 bps = 0.1%)
const VOLUME_FEE_BPS: u32 = 10;

/// Type alias for transfer proof storage key
type TransferProofKey = (u32, u64, AccountId32, AccountId32, u128);

/// Compute output amount after fee deduction
fn compute_output_amount(input_amount: u32, fee_bps: u32) -> u32 {
	((input_amount as u64) * (10000 - fee_bps as u64) / 10000) as u32
}

/// Generate a random 32-byte secret
fn generate_random_secret() -> [u8; 32] {
	let mut secret = [0u8; 32];
	rng().fill_bytes(&mut secret);
	secret
}

/// Helper struct to hold proof generation context
struct ProofContext {
	proof: ProofWithPublicInputs<F, C, D>,
	proof_bytes: Vec<u8>,
	public_inputs: PublicCircuitInputs,
}

/// Helper struct to hold aggregated proof context
struct AggregatedProofContext {
	proof_bytes: Vec<u8>,
	public_inputs: AggregatedPublicCircuitInputs,
}

/// Data collected from a transfer, needed to generate proof later
struct TransferData {
	secret: [u8; 32],
	exit_account_bytes: [u8; 32],
	funding_amount: u128,
	transfer_count: u64,
	from_account: SubxtAccountId,
	to_account: SubxtAccountId,
	amount: u128,
	funding_account: AccountId32,
	unspendable_account: qp_zk_circuits_common::utils::Digest,
}

/// Submit a transaction and return the block hash where it was included
async fn submit_and_get_block_hash<Call>(
	quantus_client: &QuantusClient,
	keypair: &QuantumKeyPair,
	call: Call,
) -> Result<subxt::utils::H256, String>
where
	Call: subxt::tx::Payload,
{
	let client = quantus_client.client();

	let signer = keypair
		.to_subxt_signer()
		.map_err(|e| format!("Failed to convert keypair: {}", e))?;

	// Get fresh nonce
	let (from_account_id, _version) =
		AccountId32::from_ss58check_with_version(&keypair.to_account_id_ss58check())
			.map_err(|e| format!("Invalid from address: {:?}", e))?;
	let nonce = quantus_client
		.get_account_nonce_from_best_block(&from_account_id)
		.await
		.map_err(|e| format!("Failed to get nonce: {}", e))?;

	// Build transaction params
	use subxt::config::DefaultExtrinsicParamsBuilder;
	let params = DefaultExtrinsicParamsBuilder::new().mortal(256).nonce(nonce).build();

	// Submit and watch for the block hash where it's included
	let mut tx_progress = client
		.tx()
		.sign_and_submit_then_watch(&call, &signer, params)
		.await
		.map_err(|e| format!("Failed to submit transaction: {}", e))?;

	// Wait for transaction to be included and get the block hash
	loop {
		match tx_progress.next().await {
			Some(Ok(TxStatus::InBestBlock(tx_in_block))) => {
				return Ok(tx_in_block.block_hash());
			},
			Some(Ok(TxStatus::InFinalizedBlock(tx_in_block))) => {
				return Ok(tx_in_block.block_hash());
			},
			Some(Ok(TxStatus::Error { message })) | Some(Ok(TxStatus::Invalid { message })) => {
				return Err(format!("Transaction failed: {}", message));
			},
			Some(Err(e)) => {
				return Err(format!("Transaction progress error: {}", e));
			},
			None => {
				return Err("Transaction stream ended unexpectedly".to_string());
			},
			_ => continue,
		}
	}
}

/// Setup developer wallet for testing
/// Creates the wallet if it doesn't exist
async fn setup_developer_wallet(wallet_name: &str) -> QuantumKeyPair {
	let wallet_manager = WalletManager::new().expect("Failed to create wallet manager");

	// Try to load existing wallet, or create if doesn't exist
	// get_wallet returns Ok(Some(...)) if wallet exists, Ok(None) if it doesn't
	match wallet_manager.get_wallet(wallet_name, Some("")) {
		Ok(Some(_wallet_info)) => {
			// Wallet exists, load the keypair (developer wallets use empty password)
			let wallet_data =
				wallet_manager.load_wallet(wallet_name, "").expect("Failed to load wallet data");
			wallet_data.keypair
		},
		Ok(None) | Err(_) => {
			// Wallet doesn't exist, create developer wallet (pre-funded on dev chains)
			println!("    Creating developer wallet '{}'...", wallet_name);
			wallet_manager
				.create_developer_wallet(wallet_name)
				.await
				.expect("Failed to create developer wallet");

			let wallet_data =
				wallet_manager.load_wallet(wallet_name, "").expect("Failed to load wallet data");
			wallet_data.keypair
		},
	}
}

/// Generate a wormhole proof by funding an unspendable account
async fn generate_wormhole_proof(
	quantus_client: &QuantusClient,
	keypair: &QuantumKeyPair,
	funding_amount: u128,
	exit_account_bytes: [u8; 32],
	secret: [u8; 32],
) -> Result<ProofContext, String> {
	// First submit the transfer and collect transfer data
	let transfer_data = submit_wormhole_transfer(
		quantus_client,
		keypair,
		funding_amount,
		exit_account_bytes,
		secret,
	)
	.await?;

	// Wait a moment then get the latest block to use for proof generation
	tokio::time::sleep(Duration::from_millis(500)).await;
	let block_hash = quantus_client
		.get_latest_block()
		.await
		.map_err(|e| format!("Failed to get latest block: {}", e))?;

	// Generate proof from the transfer data using this block
	generate_proof_from_transfer(quantus_client, &transfer_data, block_hash).await
}

/// Submit a wormhole transfer and return the transfer data needed for proof generation
async fn submit_wormhole_transfer(
	quantus_client: &QuantusClient,
	keypair: &QuantumKeyPair,
	funding_amount: u128,
	exit_account_bytes: [u8; 32],
	secret: [u8; 32],
) -> Result<TransferData, String> {
	let secret_digest: BytesDigest =
		secret.try_into().map_err(|e| format!("Failed to convert secret: {:?}", e))?;

	let client = quantus_client.client();
	let funding_account =
		AccountId32::new(qp_poseidon::PoseidonHasher::hash(keypair.public_key.as_ref()).0);

	// Generate unspendable account from secret
	let unspendable_account =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret_digest)
			.account_id;
	let unspendable_account_bytes_digest =
		qp_zk_circuits_common::utils::digest_felts_to_bytes(unspendable_account);
	let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
		.as_ref()
		.try_into()
		.expect("BytesDigest is always 32 bytes");
	let unspendable_account_id = SubxtAccountId(unspendable_account_bytes);

	println!("  Unspendable account: 0x{}", hex::encode(unspendable_account_bytes));
	println!("  Exit account: 0x{}", hex::encode(exit_account_bytes));

	// Fund via Balances (wormhole has no transfer_native; WormholeProofRecorderExtension
	// records every Balances transfer and emits NativeTransferred)
	let transfer_tx = quantus_node::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
		funding_amount,
	);

	println!("  Submitting transfer to unspendable account...");

	let quantum_keypair = QuantumKeyPair {
		public_key: keypair.public_key.clone(),
		private_key: keypair.private_key.clone(),
	};

	// Submit transaction and get the actual block hash where it was included
	let block_hash: subxt::utils::H256 = submit_and_get_block_hash(
		quantus_client,
		&quantum_keypair,
		transfer_tx,
	)
	.await
	.map_err(|e| format!("Transfer failed: {}", e))?;

	println!("  Transfer included in block: {:?}", block_hash);

	// WormholeProofRecorderExtension emits NativeTransferred for every Balances transfer
	let events_api = client
		.events()
		.at(block_hash)
		.await
		.map_err(|e| format!("Failed to get events: {}", e))?;

	// Find the event that matches our specific unspendable account
	let mut matching_event = None;
	for event_result in events_api.find::<wormhole::events::NativeTransferred>() {
		let event = event_result.map_err(|e| format!("Failed to decode event: {}", e))?;
		// Check if this event is for our unspendable account
		if event.to.0 == unspendable_account_bytes {
			matching_event = Some(event);
			break;
		}
	}

	let event = matching_event.ok_or_else(|| {
		"No NativeTransferred event found for our unspendable account".to_string()
	})?;

	println!("  Transfer event: amount={}, transfer_count={}", event.amount, event.transfer_count);

	Ok(TransferData {
		secret,
		exit_account_bytes,
		funding_amount,
		transfer_count: event.transfer_count,
		from_account: event.from,
		to_account: event.to,
		amount: event.amount,
		funding_account,
		unspendable_account,
	})
}

/// Generate a proof from transfer data using a specific block for the storage proof
async fn generate_proof_from_transfer(
	quantus_client: &QuantusClient,
	transfer_data: &TransferData,
	block_hash: subxt::utils::H256,
) -> Result<ProofContext, String> {
	let client = quantus_client.client();

	let secret_digest: BytesDigest = transfer_data
		.secret
		.try_into()
		.map_err(|e| format!("Failed to convert secret: {:?}", e))?;

	let blocks = client
		.blocks()
		.at(block_hash)
		.await
		.map_err(|e| format!("Failed to get block: {}", e))?;

	// Get storage proof
	let from_account = AccountId32::new(transfer_data.from_account.0);
	let to_account = AccountId32::new(transfer_data.to_account.0);

	let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<TransferProofKey>(
		&(
			NATIVE_ASSET_ID,
			transfer_data.transfer_count,
			from_account.clone(),
			to_account.clone(),
			transfer_data.amount,
		)
			.encode(),
	);

	let proof_address = quantus_node::api::storage().wormhole().transfer_proof((
		NATIVE_ASSET_ID,
		transfer_data.transfer_count,
		transfer_data.from_account.clone(),
		transfer_data.to_account.clone(),
		transfer_data.amount,
	));

	let mut final_key = proof_address.to_root_bytes();
	final_key.extend_from_slice(&leaf_hash);

	let storage_api = client.storage().at(block_hash);
	let val = storage_api
		.fetch_raw(final_key.clone())
		.await
		.map_err(|e| format!("Failed to fetch storage: {}", e))?;

	if val.is_none() {
		return Err("Storage key not found".to_string());
	}

	// Get read proof via RPC
	let proof_params = subxt::ext::jsonrpsee::rpc_params![vec![to_hex(&final_key)], block_hash];
	let read_proof: ReadProof<sp_core::H256> = quantus_client
		.rpc_client()
		.request("state_getReadProof", proof_params)
		.await
		.map_err(|e| format!("Failed to get read proof: {}", e))?;

	let header = blocks.header();

	let state_root = BytesDigest::try_from(header.state_root.as_bytes())
		.map_err(|e| format!("Failed to convert state root: {}", e))?;
	let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())
		.map_err(|e| format!("Failed to convert parent hash: {}", e))?;
	let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())
		.map_err(|e| format!("Failed to convert extrinsics root: {}", e))?;
	let digest = header
		.digest
		.encode()
		.try_into()
		.map_err(|_| "Failed to encode digest".to_string())?;

	let block_number = header.number;

	// Prepare storage proof for circuit
	let processed_storage_proof = prepare_proof_for_circuit(
		read_proof.proof.iter().map(|proof| proof.0.clone()).collect(),
		hex::encode(header.state_root.0),
		leaf_hash,
	)
	.map_err(|e| format!("Failed to prepare storage proof: {}", e))?;

	// Quantize the funding amount
	let input_amount_quantized: u32 = (transfer_data.funding_amount / SCALE_DOWN_FACTOR)
		.try_into()
		.map_err(|_| "Funding amount too large after quantization".to_string())?;

	let output_amount_quantized = compute_output_amount(input_amount_quantized, VOLUME_FEE_BPS);

	let exit_account_digest = BytesDigest::try_from(&transfer_data.exit_account_bytes[..])
		.map_err(|e| format!("Failed to convert exit account: {}", e))?;

	let inputs = CircuitInputs {
		private: PrivateCircuitInputs {
			secret: secret_digest,
			transfer_count: transfer_data.transfer_count,
			funding_account: BytesDigest::try_from(transfer_data.funding_account.as_ref() as &[u8])
				.map_err(|e| format!("Failed to convert funding account: {}", e))?,
			storage_proof: processed_storage_proof,
			unspendable_account: digest_felts_to_bytes(transfer_data.unspendable_account),
			state_root,
			extrinsics_root,
			digest,
			input_amount: input_amount_quantized,
		},
		public: PublicCircuitInputs {
			output_amount_1: output_amount_quantized,
			output_amount_2: 0, // No change output for single-output spend
			volume_fee_bps: VOLUME_FEE_BPS,
			nullifier: digest_felts_to_bytes(
				Nullifier::from_preimage(secret_digest, transfer_data.transfer_count).hash,
			),
			exit_account_1: exit_account_digest,
			exit_account_2: BytesDigest::try_from([0u8; 32].as_ref())
				.map_err(|e| format!("Failed to convert zero exit account: {}", e))?,
			block_hash: BytesDigest::try_from(block_hash.as_ref())
				.map_err(|e| format!("Failed to convert block hash: {}", e))?,
			parent_hash,
			block_number,
			asset_id: NATIVE_ASSET_ID,
		},
	};

	println!("  Generating ZK proof (this may take ~30s)...");
	let config = CircuitConfig::standard_recursion_zk_config();
	let prover = WormholeProver::new(config);
	let prover_next = prover.commit(&inputs).map_err(|e| format!("Failed to commit: {}", e))?;
	let proof: ProofWithPublicInputs<_, _, 2> =
		prover_next.prove().map_err(|e| format!("Proof generation failed: {}", e))?;

	use qp_wormhole_circuit::inputs::ParsePublicInputs;
	let public_inputs = PublicCircuitInputs::try_from_proof(&proof)
		.map_err(|e| format!("Failed to parse public inputs: {}", e))?;

	let proof_bytes = proof.to_bytes();
	println!("  Proof generated! Size: {} bytes", proof_bytes.len());

	Ok(ProofContext { proof, proof_bytes, public_inputs })
}

/// Submit a single proof for on-chain verification
async fn submit_single_proof_for_verification(
	quantus_client: &QuantusClient,
	proof_bytes: Vec<u8>,
) -> Result<(), String> {
	println!("  Submitting single proof for on-chain verification...");

	let verify_tx = quantus_node::api::tx().wormhole().verify_aggregated_proof(proof_bytes);

	let unsigned_tx = quantus_client
		.client()
		.tx()
		.create_unsigned(&verify_tx)
		.map_err(|e| format!("Failed to create unsigned tx: {}", e))?;

	let mut tx_progress = unsigned_tx
		.submit_and_watch()
		.await
		.map_err(|e| format!("Failed to submit tx: {}", e))?;

	while let Some(Ok(status)) = tx_progress.next().await {
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				println!("  ✅ Single proof verified on-chain! Block: {:?}", block_hash);
				return Ok(());
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				println!(
					"  ✅ Single proof verified on-chain (finalized)! Block: {:?}",
					block_hash
				);
				return Ok(());
			},
			TxStatus::Error { message } | TxStatus::Invalid { message } => {
				return Err(format!("Transaction failed: {}", message));
			},
			_ => continue,
		}
	}

	Err("Transaction stream ended unexpectedly".to_string())
}

/// Aggregate multiple proofs into one
fn aggregate_proofs(
	proof_contexts: Vec<ProofContext>,
	depth: usize,
	branching_factor: usize,
) -> Result<AggregatedProofContext, String> {
	use qp_wormhole_aggregator::{
		aggregator::WormholeProofAggregator, circuits::tree::TreeAggregationConfig,
	};

	println!(
		"  Aggregating {} proofs (depth={}, branching_factor={})...",
		proof_contexts.len(),
		depth,
		branching_factor
	);

	let config = CircuitConfig::standard_recursion_zk_config();
	let aggregation_config = TreeAggregationConfig::new(branching_factor, depth as u32);

	if proof_contexts.len() > aggregation_config.num_leaf_proofs {
		return Err(format!(
			"Too many proofs: {} provided, max {} for depth={} branching_factor={}",
			proof_contexts.len(),
			aggregation_config.num_leaf_proofs,
			depth,
			branching_factor
		));
	}

	let mut aggregator = WormholeProofAggregator::from_circuit_config(config, aggregation_config);

	for (idx, ctx) in proof_contexts.into_iter().enumerate() {
		println!("    Adding proof {} to aggregator...", idx + 1);
		println!("      Public inputs:");
		println!("        asset_id: {}", ctx.public_inputs.asset_id);
		println!("        output_amount_1: {}", ctx.public_inputs.output_amount_1);
		println!("        output_amount_2: {}", ctx.public_inputs.output_amount_2);
		println!("        volume_fee_bps: {}", ctx.public_inputs.volume_fee_bps);
		println!("        nullifier: {:?}", ctx.public_inputs.nullifier);
		println!("        exit_account_1: {:?}", ctx.public_inputs.exit_account_1);
		println!("        exit_account_2: {:?}", ctx.public_inputs.exit_account_2);
		println!("        block_hash: {:?}", ctx.public_inputs.block_hash);
		println!("        parent_hash: {:?}", ctx.public_inputs.parent_hash);
		println!("        block_number: {}", ctx.public_inputs.block_number);
		aggregator
			.push_proof(ctx.proof)
			.map_err(|e| format!("Failed to push proof: {}", e))?;
	}

	println!("  Running aggregation (this may take ~60s)...");
	let aggregated_result =
		aggregator.aggregate().map_err(|e| format!("Aggregation failed: {}", e))?;

	use qp_wormhole_circuit::inputs::ParseAggregatedPublicInputs;
	let public_inputs = AggregatedPublicCircuitInputs::try_from_felts(
		aggregated_result.proof.public_inputs.as_slice(),
	)
	.map_err(|e| format!("Failed to parse aggregated public inputs: {}", e))?;

	// Verify locally first
	println!("  Verifying aggregated proof locally...");
	aggregated_result
		.circuit_data
		.verify(aggregated_result.proof.clone())
		.map_err(|e| format!("Local verification failed: {}", e))?;

	let proof_bytes = aggregated_result.proof.to_bytes();
	println!(
		"  Aggregation complete! Size: {} bytes, {} nullifiers",
		proof_bytes.len(),
		public_inputs.nullifiers.len()
	);

	Ok(AggregatedProofContext { proof_bytes, public_inputs })
}

/// Submit an aggregated proof for on-chain verification
async fn submit_aggregated_proof_for_verification(
	quantus_client: &QuantusClient,
	proof_bytes: Vec<u8>,
) -> Result<(), String> {
	println!("  Submitting aggregated proof for on-chain verification...");

	let verify_tx = quantus_node::api::tx().wormhole().verify_aggregated_proof(proof_bytes);

	let unsigned_tx = quantus_client
		.client()
		.tx()
		.create_unsigned(&verify_tx)
		.map_err(|e| format!("Failed to create unsigned tx: {}", e))?;

	let mut tx_progress = unsigned_tx
		.submit_and_watch()
		.await
		.map_err(|e| format!("Failed to submit tx: {}", e))?;

	while let Some(Ok(status)) = tx_progress.next().await {
		match status {
			TxStatus::InBestBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				println!("  ✅ Aggregated proof verified on-chain! Block: {:?}", block_hash);
				return Ok(());
			},
			TxStatus::InFinalizedBlock(tx_in_block) => {
				let block_hash = tx_in_block.block_hash();
				println!(
					"  ✅ Aggregated proof verified on-chain (finalized)! Block: {:?}",
					block_hash
				);
				return Ok(());
			},
			TxStatus::Error { message } | TxStatus::Invalid { message } => {
				return Err(format!("Transaction failed: {}", message));
			},
			_ => continue,
		}
	}

	Err("Transaction stream ended unexpectedly".to_string())
}

fn author_from_header_digest(
	header_digest: &subxt::config::substrate::Digest,
) -> Option<SubxtAccountId> {
	header_digest.logs.iter().find_map(|item| match item {
		subxt::config::substrate::DigestItem::PreRuntime(_engine_id, data) =>
			SubxtAccountId::decode(&mut &data[..]).ok(),
		_ => None,
	})
}

/// fee = exit * fee_bps / (10000 - fee_bps)
/// miner_fee = fee - burn_rate*fee
fn expected_miner_fee_u128(total_exit_amount_u128: u128, fee_bps: u32) -> u128 {
	let fee_bps_u128 = fee_bps as u128;

	let fee_u128 = total_exit_amount_u128
		.saturating_mul(fee_bps_u128)
		.checked_div(10_000u128.saturating_sub(fee_bps_u128))
		.unwrap_or(0);

	let burn_rate: Permill = Permill::from_percent(50);
	let burn_amount_u128 = burn_rate * fee_u128;
	fee_u128.saturating_sub(burn_amount_u128)
}

async fn free_balance_at(
	client: &QuantusClient,
	at: sp_core::H256,
	who: &SubxtAccountId,
) -> anyhow::Result<u128> {
	let api = client.client();
	let storage = api.storage().at(at);
	let addr = quantus_node::api::storage().system().account(who.clone());
	let info = storage.fetch(&addr).await?;
	let free: u128 = info.map(|i| i.data.free).unwrap_or(0u128);
	Ok(free)
}

/// Integration test: Generate and verify a single wormhole proof on-chain
///
/// This test:
/// 1. Connects to a local Quantus node
/// 2. Uses a developer wallet (crystal_alice) to fund an unspendable account
/// 3. Generates a ZK proof of the transfer
/// 4. Submits the proof for on-chain verification
/// 5. Miner fee is paid.
#[tokio::test]
#[serial]
#[ignore] // Requires running local node - run with `cargo test -- --ignored`
async fn test_single_proof_on_chain_verification() {
	println!("\n=== Single Proof On-Chain Verification Test ===\n");

	// Connect to local node
	println!("1. Connecting to local node at {}...", LOCAL_NODE_URL);
	let quantus_client = QuantusClient::new(LOCAL_NODE_URL)
		.await
		.expect("Failed to connect to local node");
	println!("   Connected!");

	// Setup developer wallet
	println!("2. Setting up developer wallet (crystal_alice)...");
	let keypair = setup_developer_wallet("crystal_alice").await;
	println!("   Wallet address: {}", keypair.to_account_id_ss58check());

	// Generate random secret and exit account
	let secret = generate_random_secret();
	let mut exit_account = [0u8; 32];
	rng().fill_bytes(&mut exit_account);

	// Use a small funding amount (1 token = 10^12 units)
	let funding_amount: u128 = 1_000_000_000_000; // 1 token

	println!("3. Generating wormhole proof...");
	println!("   Funding amount: {} units (1 token)", funding_amount);
	println!("   Secret: 0x{}", hex::encode(secret));

	let proof_context =
		generate_wormhole_proof(&quantus_client, &keypair, funding_amount, exit_account, secret)
			.await
			.expect("Failed to generate proof");

	println!(
		"   Public inputs - output_amount_1: {}, nullifier: {:?}",
		proof_context.public_inputs.output_amount_1, proof_context.public_inputs.nullifier
	);

	// Submit for on-chain verification
	println!("4. Verifying proof on-chain...");

	// Submit extrinsic
	submit_single_proof_for_verification(&quantus_client, proof_context.proof_bytes.clone())
		.await
		.expect("On-chain verification failed");

	// Find the block that executed verification
	let verify_block_hash = quantus_client
		.get_latest_block()
		.await
		.expect("Failed to get latest block hash");

	// Extract author from block digest
	let verify_block = quantus_client.client().blocks().at(verify_block_hash).await.unwrap();
	let header = verify_block.header();
	let parent_hash = header.parent_hash;
	let author = author_from_header_digest(&header.digest)
		.expect("could not decode author from pre-runtime digest");

	// Compute expected miner fee from public inputs (single proof)
	let fee_bps = proof_context.public_inputs.volume_fee_bps;
	let exit_u128 = (proof_context.public_inputs.output_amount_1 as u128) * SCALE_DOWN_FACTOR;
	let expected_miner_fee = expected_miner_fee_u128(exit_u128, fee_bps);

	assert!(expected_miner_fee > 0, "expected miner fee should be > 0");

	// Balance delta check
	let before = free_balance_at(&quantus_client, parent_hash, &author).await.unwrap();
	let after = free_balance_at(&quantus_client, verify_block_hash, &author).await.unwrap();
	let delta = after.saturating_sub(before);

	println!(
		"Miner fee check: author={:?} before={} after={} delta={} expected_miner_fee={}",
		author, before, after, delta, expected_miner_fee
	);

	assert!(
		delta >= expected_miner_fee,
		"author balance delta ({}) did not cover expected miner fee ({})",
		delta,
		expected_miner_fee
	);

	println!("\n=== Single Proof Test PASSED ===\n");
}

/// Integration test: Generate, aggregate, and verify multiple wormhole proofs on-chain
///
/// This test:
/// 1. Connects to a local Quantus node
/// 2. Uses developer wallets to fund multiple unspendable accounts
/// 3. Generates ZK proofs for each transfer (all from the same block for aggregation)
/// 4. Aggregates the proofs into a single proof
/// 5. Submits the aggregated proof for on-chain verification
/// 6. Miner fee is paid.
#[tokio::test]
#[serial]
#[ignore] // Requires running local node - run with `cargo test -- --ignored`
async fn test_aggregated_proof_on_chain_verification() {
	println!("\n=== Aggregated Proof On-Chain Verification Test ===\n");

	// Connect to local node
	println!("1. Connecting to local node at {}...", LOCAL_NODE_URL);
	let quantus_client = QuantusClient::new(LOCAL_NODE_URL)
		.await
		.expect("Failed to connect to local node");
	println!("   Connected!");

	// Setup developer wallets - use different wallets for different proofs to avoid nonce issues
	println!("2. Setting up developer wallets...");
	let keypair_alice = setup_developer_wallet("crystal_alice").await;
	let keypair_bob = setup_developer_wallet("crystal_bob").await;
	println!("   Alice address: {}", keypair_alice.to_account_id_ss58check());
	println!("   Bob address: {}", keypair_bob.to_account_id_ss58check());

	let keypairs = [&keypair_alice, &keypair_bob];
	let mut transfer_data_list = Vec::new();

	// Phase 1: Submit all transfers first
	println!("3. Submitting wormhole transfers...");
	for (i, keypair) in keypairs.iter().enumerate() {
		println!("\n   --- Transfer {} ---", i + 1);

		let secret = generate_random_secret();
		let mut exit_account = [0u8; 32];
		rng().fill_bytes(&mut exit_account);

		// Use a small funding amount (0.5 tokens each)
		let funding_amount: u128 = 500_000_000_000; // 0.5 tokens

		println!("   Funding amount: {} units (0.5 tokens)", funding_amount);
		println!("   Secret: 0x{}", hex::encode(secret));

		let transfer_data = submit_wormhole_transfer(
			&quantus_client,
			keypair,
			funding_amount,
			exit_account,
			secret,
		)
		.await
		.expect("Failed to submit transfer");

		transfer_data_list.push(transfer_data);
	}

	// Wait for all transfers to be available in storage
	println!("\n   Waiting for transfers to be confirmed...");
	tokio::time::sleep(Duration::from_secs(2)).await;

	// Phase 2: Get a common block hash and generate all proofs from it
	let common_block_hash =
		quantus_client.get_latest_block().await.expect("Failed to get latest block");
	println!("   Using common block for all proofs: {:?}", common_block_hash);

	let mut proof_contexts = Vec::new();
	println!("\n4. Generating proofs from common block...");
	for (i, transfer_data) in transfer_data_list.iter().enumerate() {
		println!("\n   --- Proof {} ---", i + 1);

		let proof_context =
			generate_proof_from_transfer(&quantus_client, transfer_data, common_block_hash)
				.await
				.expect("Failed to generate proof");

		println!(
			"   Public inputs - output_amount_1: {}, nullifier: {:?}",
			proof_context.public_inputs.output_amount_1, proof_context.public_inputs.nullifier
		);

		proof_contexts.push(proof_context);
	}

	// Aggregate proofs
	println!("\n4. Aggregating {} proofs...", proof_contexts.len());
	let aggregated_context = aggregate_proofs(
		proof_contexts,
		1, // depth
		2, // branching_factor (2^1 = 2 max proofs)
	)
	.expect("Failed to aggregate proofs");

	println!(
		"   Aggregated {} nullifiers, {} account entries",
		aggregated_context.public_inputs.nullifiers.len(),
		aggregated_context.public_inputs.account_data.len()
	);

	// Verify aggregated proof on-chain
	println!("5. Verifying aggregated proof on-chain...");

	// Submit aggregated verification
	submit_aggregated_proof_for_verification(
		&quantus_client,
		aggregated_context.proof_bytes.clone(),
	)
	.await
	.expect("On-chain aggregated verification failed");

	// Identify verification block
	let verify_block_hash = quantus_client
		.get_latest_block()
		.await
		.expect("Failed to get latest block hash");

	// Extract author
	let verify_block = quantus_client.client().blocks().at(verify_block_hash).await.unwrap();
	let header = verify_block.header();
	let parent_hash = header.parent_hash;
	let author = author_from_header_digest(&header.digest)
		.expect("could not decode author from pre-runtime digest");

	// Compute total exit amount (sum of quantized outputs) scaled up
	let fee_bps = aggregated_context.public_inputs.volume_fee_bps;
	let total_output_quantized: u128 = aggregated_context
		.public_inputs
		.account_data
		.iter()
		.map(|a| a.summed_output_amount as u128)
		.sum();

	let total_exit_u128 = total_output_quantized * SCALE_DOWN_FACTOR;
	let expected_miner_fee = expected_miner_fee_u128(total_exit_u128, fee_bps);

	assert!(expected_miner_fee > 0, "expected miner fee should be > 0");

	// Balance delta check
	let before = free_balance_at(&quantus_client, parent_hash, &author).await.unwrap();
	let after = free_balance_at(&quantus_client, verify_block_hash, &author).await.unwrap();
	let delta = after.saturating_sub(before);

	println!(
		"Miner fee check (agg): author={:?} before={} after={} delta={} expected_miner_fee={}",
		author, before, after, delta, expected_miner_fee
	);

	assert!(
		delta >= expected_miner_fee,
		"author balance delta ({}) did not cover expected miner fee ({})",
		delta,
		expected_miner_fee
	);

	println!("\n=== Aggregated Proof Test PASSED ===\n");
}

/// Integration test: Test single proof with specific exit account
///
/// This test verifies that the exit account in the proof matches what we specified.
#[tokio::test]
#[serial]
#[ignore] // Requires running local node - run with `cargo test -- --ignored`
async fn test_single_proof_exit_account_verification() {
	println!("\n=== Exit Account Verification Test ===\n");

	// Connect to local node
	println!("1. Connecting to local node...");
	let quantus_client = QuantusClient::new(LOCAL_NODE_URL)
		.await
		.expect("Failed to connect to local node");

	// Setup developer wallet
	println!("2. Setting up developer wallet...");
	let keypair = setup_developer_wallet("crystal_alice").await;

	// Generate random secret
	let secret = generate_random_secret();

	// Use Bob's address as the exit account
	let keypair_bob = setup_developer_wallet("crystal_bob").await;
	let bob_account = keypair_bob.to_account_id_ss58check();
	println!("   Using Bob's address as exit account: {}", bob_account);

	// Convert Bob's address to bytes (use from_ss58check_with_version for Quantus SS58 format)
	let (bob_account_id, _version) =
		AccountId32::from_ss58check_with_version(&bob_account).expect("Invalid SS58");
	let exit_account_bytes: [u8; 32] = bob_account_id.into();

	let funding_amount: u128 = 1_000_000_000_000;

	println!("3. Generating wormhole proof with specific exit account...");
	let proof_context = generate_wormhole_proof(
		&quantus_client,
		&keypair,
		funding_amount,
		exit_account_bytes,
		secret,
	)
	.await
	.expect("Failed to generate proof");

	// Verify the exit account in public inputs matches what we specified
	let exit_account_from_proof: [u8; 32] = proof_context
		.public_inputs
		.exit_account_1
		.as_ref()
		.try_into()
		.expect("Exit account should be 32 bytes");

	assert_eq!(
		exit_account_bytes, exit_account_from_proof,
		"Exit account in proof should match specified account"
	);
	println!("   ✅ Exit account verification passed!");

	// Submit for on-chain verification
	println!("4. Verifying proof on-chain...");
	submit_single_proof_for_verification(&quantus_client, proof_context.proof_bytes)
		.await
		.expect("On-chain verification failed");

	println!("\n=== Exit Account Verification Test PASSED ===\n");
}

/// Integration test: Verify nullifier uniqueness across proofs
///
/// This test ensures that different secrets produce different nullifiers,
/// which is critical for preventing double-spending.
#[tokio::test]
#[serial]
#[ignore] // Requires running local node - run with `cargo test -- --ignored`
async fn test_nullifier_uniqueness() {
	println!("\n=== Nullifier Uniqueness Test ===\n");

	// Connect to local node
	println!("1. Connecting to local node...");
	let quantus_client = QuantusClient::new(LOCAL_NODE_URL)
		.await
		.expect("Failed to connect to local node");

	// Setup developer wallet
	println!("2. Setting up developer wallet...");
	let keypair = setup_developer_wallet("crystal_alice").await;

	// Generate two proofs with different secrets
	let secret1 = generate_random_secret();
	let secret2 = generate_random_secret();
	assert_ne!(secret1, secret2, "Secrets should be different");

	let mut exit_account = [0u8; 32];
	rng().fill_bytes(&mut exit_account);

	let funding_amount: u128 = 500_000_000_000;

	println!("3. Generating first proof...");
	let proof1 =
		generate_wormhole_proof(&quantus_client, &keypair, funding_amount, exit_account, secret1)
			.await
			.expect("Failed to generate first proof");

	// Wait for nonce to update
	tokio::time::sleep(Duration::from_secs(2)).await;

	println!("4. Generating second proof...");
	let proof2 =
		generate_wormhole_proof(&quantus_client, &keypair, funding_amount, exit_account, secret2)
			.await
			.expect("Failed to generate second proof");

	// Verify nullifiers are different
	assert_ne!(
		proof1.public_inputs.nullifier, proof2.public_inputs.nullifier,
		"Nullifiers from different secrets should be different"
	);
	println!("   ✅ Nullifiers are unique!");
	println!("   Nullifier 1: {:?}", proof1.public_inputs.nullifier);
	println!("   Nullifier 2: {:?}", proof2.public_inputs.nullifier);

	// Verify both proofs on-chain
	println!("5. Verifying first proof on-chain...");
	submit_single_proof_for_verification(&quantus_client, proof1.proof_bytes)
		.await
		.expect("First proof verification failed");

	println!("6. Verifying second proof on-chain...");
	submit_single_proof_for_verification(&quantus_client, proof2.proof_bytes)
		.await
		.expect("Second proof verification failed");

	println!("\n=== Nullifier Uniqueness Test PASSED ===\n");
}

/// Integration test: Full end-to-end workflow with multiple aggregated proofs
///
/// This is a comprehensive test that exercises the full wormhole workflow:
/// 1. Multiple transfers from different accounts
/// 2. Multiple proof generations
/// 3. Proof aggregation
/// 4. On-chain verification of aggregated proof
#[tokio::test]
#[serial]
#[ignore] // Requires running local node - run with `cargo test -- --ignored`
async fn test_full_wormhole_workflow() {
	println!("\n=== Full Wormhole Workflow Test ===\n");

	// Connect to local node
	println!("1. Connecting to local node at {}...", LOCAL_NODE_URL);
	let quantus_client = QuantusClient::new(LOCAL_NODE_URL)
		.await
		.expect("Failed to connect to local node");
	println!("   Connected!");

	// Setup developer wallet
	println!("2. Setting up developer wallet...");
	let keypair = setup_developer_wallet("crystal_alice").await;
	println!("   Address: {}", keypair.to_account_id_ss58check());

	// Step 1: Generate and verify a single proof
	println!("\n--- Step 1: Single Proof ---");
	let secret1 = generate_random_secret();
	let mut exit1 = [0u8; 32];
	rng().fill_bytes(&mut exit1);

	let proof1 = generate_wormhole_proof(
		&quantus_client,
		&keypair,
		1_000_000_000_000, // 1 token
		exit1,
		secret1,
	)
	.await
	.expect("Failed to generate proof 1");

	println!("   Generated proof 1, verifying on-chain...");
	submit_single_proof_for_verification(&quantus_client, proof1.proof_bytes.clone())
		.await
		.expect("Proof 1 verification failed");

	// Wait for state to settle
	tokio::time::sleep(Duration::from_secs(2)).await;

	// Step 2: Submit multiple transfers for aggregation
	println!("\n--- Step 2: Submitting Transfers for Aggregation ---");
	let mut transfer_data_list = Vec::new();

	for i in 0..2 {
		println!("   Submitting transfer {}...", i + 1);
		let secret = generate_random_secret();
		let mut exit = [0u8; 32];
		rng().fill_bytes(&mut exit);

		let transfer_data = submit_wormhole_transfer(
			&quantus_client,
			&keypair,
			500_000_000_000, // 0.5 tokens
			exit,
			secret,
		)
		.await
		.unwrap_or_else(|_| panic!("Failed to submit transfer {}", i + 1));

		transfer_data_list.push(transfer_data);
	}

	// Wait for transfers to be confirmed and get a common block
	println!("   Waiting for transfers to be confirmed...");
	tokio::time::sleep(Duration::from_secs(2)).await;

	let common_block_hash =
		quantus_client.get_latest_block().await.expect("Failed to get latest block");
	println!("   Using common block for all proofs: {:?}", common_block_hash);

	// Generate all proofs from the common block
	let mut proofs_for_aggregation = Vec::new();
	for (i, transfer_data) in transfer_data_list.iter().enumerate() {
		println!("   Generating proof {}...", i + 1);
		let proof = generate_proof_from_transfer(&quantus_client, transfer_data, common_block_hash)
			.await
			.unwrap_or_else(|_| panic!("Failed to generate proof {}", i + 1));
		proofs_for_aggregation.push(proof);
	}

	// Step 3: Aggregate and verify
	println!("\n--- Step 3: Aggregation ---");
	let aggregated =
		aggregate_proofs(proofs_for_aggregation, 1, 2).expect("Failed to aggregate proofs");

	println!("   Verifying aggregated proof on-chain...");
	submit_aggregated_proof_for_verification(&quantus_client, aggregated.proof_bytes)
		.await
		.expect("Aggregated proof verification failed");

	println!("\n=== Full Wormhole Workflow Test PASSED ===\n");
}

/// Test that the fee calculation is correct
#[test]
fn test_fee_calculation_consistency() {
	// Test various amounts and verify the fee calculation
	let test_cases = [
		(1000u32, 10u32, 999u32), // 1000 * 0.999 = 999
		(10000, 10, 9990),        // 10000 * 0.999 = 9990
		(100, 10, 99),            // 100 * 0.999 = 99
		(1, 10, 0),               // 1 * 0.999 = 0 (rounds down)
		(0, 10, 0),               // 0 * 0.999 = 0
		(1000, 100, 990),         // 1% fee: 1000 * 0.99 = 990
		(1000, 0, 1000),          // 0% fee: no deduction
	];

	for (input, fee_bps, expected_output) in test_cases {
		let output = compute_output_amount(input, fee_bps);
		assert_eq!(
			output, expected_output,
			"Fee calculation failed for input={}, fee_bps={}: got {}, expected {}",
			input, fee_bps, output, expected_output
		);
	}

	println!("Fee calculation test passed!");
}

/// Test that secrets generate deterministic nullifiers
#[test]
fn test_nullifier_determinism() {
	let secret: BytesDigest = [42u8; 32].try_into().expect("valid secret");
	let transfer_count = 123u64;

	let nullifier1 = Nullifier::from_preimage(secret, transfer_count);
	let nullifier2 = Nullifier::from_preimage(secret, transfer_count);

	assert_eq!(nullifier1.hash, nullifier2.hash, "Same inputs should produce same nullifier");

	// Different transfer count should produce different nullifier
	let nullifier3 = Nullifier::from_preimage(secret, transfer_count + 1);
	assert_ne!(
		nullifier1.hash, nullifier3.hash,
		"Different transfer counts should produce different nullifiers"
	);

	println!("Nullifier determinism test passed!");
}
