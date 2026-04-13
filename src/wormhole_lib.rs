//! Wormhole Library Functions
//!
//! This module provides library-friendly functions for wormhole proof generation
//! that can be used by external crates (like quantus-sdk) without requiring
//! a chain client connection.
//!
//! These functions handle the core cryptographic operations:
//! - Computing leaf hashes for ZK Merkle proof verification
//! - Computing wormhole addresses from secrets
//! - Generating ZK proofs from raw inputs

use qp_wormhole_circuit::{
	inputs::{CircuitInputs, PrivateCircuitInputs},
	nullifier::Nullifier,
};
use qp_wormhole_inputs::PublicCircuitInputs;
use qp_wormhole_prover::WormholeProver;
use qp_zk_circuits_common::{
	utils::{digest_to_bytes, BytesDigest},
	zk_merkle::SIBLINGS_PER_LEVEL,
};
use std::path::Path;

/// Native asset id for QTU token
pub const NATIVE_ASSET_ID: u32 = 0;

/// Scale down factor for quantizing amounts (10^10 to go from 12 to 2 decimal places)
pub const SCALE_DOWN_FACTOR: u128 = 10_000_000_000;

/// Volume fee rate in basis points (10 bps = 0.1%)
pub const VOLUME_FEE_BPS: u32 = 10;

/// Result type for wormhole library operations
pub type Result<T> = std::result::Result<T, WormholeLibError>;

/// Error type for wormhole library operations
#[derive(Debug, Clone)]
pub struct WormholeLibError {
	pub message: String,
}

impl std::fmt::Display for WormholeLibError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.message)
	}
}

impl std::error::Error for WormholeLibError {}

impl From<String> for WormholeLibError {
	fn from(message: String) -> Self {
		Self { message }
	}
}

/// Input data for generating a wormhole proof.
/// All fields are raw bytes - no chain client required.
#[derive(Debug, Clone)]
pub struct ProofGenerationInput {
	/// 32-byte secret
	pub secret: [u8; 32],
	/// Transfer count (atomic counter per recipient)
	pub transfer_count: u64,
	/// Wormhole address (recipient/unspendable account) as 32 bytes
	pub wormhole_address: [u8; 32],
	/// Input amount (quantized, 2 decimals) - from ZK leaf data
	pub input_amount: u32,
	/// Block hash as 32 bytes
	pub block_hash: [u8; 32],
	/// Block number
	pub block_number: u32,
	/// Parent hash as 32 bytes
	pub parent_hash: [u8; 32],
	/// State root as 32 bytes (still needed for block hash computation)
	pub state_root: [u8; 32],
	/// Extrinsics root as 32 bytes
	pub extrinsics_root: [u8; 32],
	/// SCALE-encoded digest (variable length, padded to 110 bytes internally)
	pub digest: Vec<u8>,
	/// ZK tree root (from block header's zk_tree_root field)
	pub zk_tree_root: [u8; 32],
	/// ZK Merkle proof siblings at each level (3 siblings per level, in sorted order)
	pub zk_merkle_siblings: Vec<[[u8; 32]; SIBLINGS_PER_LEVEL]>,
	/// Position hints (0-3) for each level
	pub zk_merkle_positions: Vec<u8>,
	/// Exit account 1 as 32 bytes
	pub exit_account_1: [u8; 32],
	/// Exit account 2 as 32 bytes (use zeros for single output)
	pub exit_account_2: [u8; 32],
	/// Output amount 1 (quantized, 2 decimals)
	pub output_amount_1: u32,
	/// Output amount 2 (quantized, 2 decimals, 0 for single output)
	pub output_amount_2: u32,
	/// Volume fee in basis points
	pub volume_fee_bps: u32,
	/// Asset ID (0 for native token)
	pub asset_id: u32,
}

/// Output from proof generation
#[derive(Debug, Clone)]
pub struct ProofGenerationOutput {
	/// Generated proof as bytes
	pub proof_bytes: Vec<u8>,
	/// Nullifier as 32 bytes (available for callers who need it)
	#[allow(dead_code)]
	pub nullifier: [u8; 32],
}

/// Compute the unspendable wormhole account from a secret.
///
/// # Arguments
/// * `secret` - 32-byte secret
///
/// # Returns
/// 32-byte wormhole account address
pub fn compute_wormhole_address(secret: &[u8; 32]) -> Result<[u8; 32]> {
	let secret_digest: BytesDigest = (*secret)
		.try_into()
		.map_err(|e| WormholeLibError::from(format!("Invalid secret: {:?}", e)))?;

	let unspendable =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret_digest);

	Ok(*digest_to_bytes(unspendable.account_id))
}

/// Compute the nullifier from secret and transfer count.
///
/// # Arguments
/// * `secret` - 32-byte secret
/// * `transfer_count` - Transfer counter
///
/// # Returns
/// 32-byte nullifier
#[allow(dead_code)]
pub fn compute_nullifier(secret: &[u8; 32], transfer_count: u64) -> Result<[u8; 32]> {
	let secret_digest: BytesDigest = (*secret)
		.try_into()
		.map_err(|e| WormholeLibError::from(format!("Invalid secret: {:?}", e)))?;

	let nullifier = Nullifier::from_preimage(secret_digest, transfer_count);
	Ok(*digest_to_bytes(nullifier.hash))
}

/// Quantize a funding amount from 12 decimal places to 2 decimal places.
///
/// # Arguments
/// * `amount` - Amount in planck (12 decimals)
///
/// # Returns
/// Quantized amount (2 decimals) as u32
pub fn quantize_amount(amount: u128) -> Result<u32> {
	let quantized = amount / SCALE_DOWN_FACTOR;
	if quantized > u32::MAX as u128 {
		return Err(WormholeLibError::from(format!(
			"Quantized amount {} exceeds u32::MAX",
			quantized
		)));
	}
	Ok(quantized as u32)
}

/// Compute output amount after fee deduction.
///
/// output = input * (10000 - fee_bps) / 10000
pub fn compute_output_amount(input_amount: u32, fee_bps: u32) -> u32 {
	((input_amount as u64) * (10000 - fee_bps as u64) / 10000) as u32
}

/// Generate a wormhole proof from raw inputs.
///
/// This function takes all necessary data as raw bytes and generates a ZK proof.
/// It does not require a chain client - all data must be pre-fetched.
///
/// # Arguments
/// * `input` - All input data for proof generation (including ZK Merkle proof)
/// * `prover_bin_path` - Path to prover.bin
/// * `common_bin_path` - Path to common.bin
///
/// # Returns
/// Proof bytes and nullifier
pub fn generate_proof(
	input: &ProofGenerationInput,
	prover_bin_path: &Path,
	common_bin_path: &Path,
) -> Result<ProofGenerationOutput> {
	// Convert secret to BytesDigest
	let secret_digest: BytesDigest = input
		.secret
		.try_into()
		.map_err(|e| WormholeLibError::from(format!("Invalid secret: {:?}", e)))?;

	// Compute nullifier
	let nullifier = Nullifier::from_preimage(secret_digest, input.transfer_count);
	let nullifier_bytes = digest_to_bytes(nullifier.hash);

	// Compute unspendable account
	let unspendable =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret_digest);
	let unspendable_bytes = digest_to_bytes(unspendable.account_id);

	// Verify the wormhole address matches what we computed from the secret
	if *unspendable_bytes != input.wormhole_address {
		return Err(WormholeLibError::from(
			"Wormhole address doesn't match the computed unspendable account from secret"
				.to_string(),
		));
	}

	// Prepare digest (padded to 110 bytes)
	const DIGEST_LOGS_SIZE: usize = 110;
	let mut digest_padded = [0u8; DIGEST_LOGS_SIZE];
	let copy_len = input.digest.len().min(DIGEST_LOGS_SIZE);
	digest_padded[..copy_len].copy_from_slice(&input.digest[..copy_len]);

	// Build circuit inputs with ZK Merkle proof
	let private = PrivateCircuitInputs {
		secret: secret_digest,
		transfer_count: input.transfer_count,
		unspendable_account: unspendable_bytes,
		parent_hash: input
			.parent_hash
			.as_slice()
			.try_into()
			.map_err(|e| WormholeLibError::from(format!("Invalid parent hash: {:?}", e)))?,
		state_root: input
			.state_root
			.as_slice()
			.try_into()
			.map_err(|e| WormholeLibError::from(format!("Invalid state root: {:?}", e)))?,
		extrinsics_root: input
			.extrinsics_root
			.as_slice()
			.try_into()
			.map_err(|e| WormholeLibError::from(format!("Invalid extrinsics root: {:?}", e)))?,
		digest: digest_padded,
		input_amount: input.input_amount,
		zk_tree_root: input.zk_tree_root,
		zk_merkle_siblings: input.zk_merkle_siblings.clone(),
		zk_merkle_positions: input.zk_merkle_positions.clone(),
	};

	let public = PublicCircuitInputs {
		asset_id: input.asset_id,
		output_amount_1: input.output_amount_1,
		output_amount_2: input.output_amount_2,
		volume_fee_bps: input.volume_fee_bps,
		nullifier: nullifier_bytes,
		exit_account_1: input
			.exit_account_1
			.as_slice()
			.try_into()
			.map_err(|e| WormholeLibError::from(format!("Invalid exit account 1: {:?}", e)))?,
		exit_account_2: input
			.exit_account_2
			.as_slice()
			.try_into()
			.map_err(|e| WormholeLibError::from(format!("Invalid exit account 2: {:?}", e)))?,
		block_hash: input
			.block_hash
			.as_slice()
			.try_into()
			.map_err(|e| WormholeLibError::from(format!("Invalid block hash: {:?}", e)))?,
		block_number: input.block_number,
	};

	let circuit_inputs = CircuitInputs { public, private };

	// Load prover from pre-built bins
	let prover = WormholeProver::new_from_files(prover_bin_path, common_bin_path)
		.map_err(|e| WormholeLibError::from(format!("Failed to load prover: {}", e)))?;

	let prover_with_inputs = prover
		.commit(&circuit_inputs)
		.map_err(|e| WormholeLibError::from(format!("Failed to commit inputs: {}", e)))?;

	let proof = prover_with_inputs
		.prove()
		.map_err(|e| WormholeLibError::from(format!("Proof generation failed: {}", e)))?;

	Ok(ProofGenerationOutput { proof_bytes: proof.to_bytes(), nullifier: *nullifier_bytes })
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_quantize_amount() {
		// 1 QTU = 10^12 planck -> should quantize to 100 (1.00 with 2 decimals)
		let result = quantize_amount(1_000_000_000_000).unwrap();
		assert_eq!(result, 100);

		// 0.01 QTU = 10^10 planck -> should quantize to 1
		let result = quantize_amount(10_000_000_000).unwrap();
		assert_eq!(result, 1);
	}

	#[test]
	fn test_compute_output_amount() {
		// 100 input with 10 bps fee -> 99.9 -> 99
		let result = compute_output_amount(100, 10);
		assert_eq!(result, 99);

		// 1000 input with 10 bps fee -> 999
		let result = compute_output_amount(1000, 10);
		assert_eq!(result, 999);
	}

	#[test]
	fn test_compute_wormhole_address() {
		// Just verify it doesn't panic and returns 32 bytes
		let secret = [42u8; 32];
		let address = compute_wormhole_address(&secret).unwrap();
		assert_eq!(address.len(), 32);
		// Should be deterministic
		let address2 = compute_wormhole_address(&secret).unwrap();
		assert_eq!(address, address2);
	}
}
