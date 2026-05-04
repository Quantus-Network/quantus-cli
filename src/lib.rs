//! # Quantus CLI Library
//!
//! This library provides the core functionality for interacting with the Quantus Network.
//! It can be used as a dependency in other Rust projects that need to interact with
//! the Quantus blockchain.

pub mod bins;
pub mod chain;
pub mod cli;
pub mod collect_rewards_lib;
pub mod config;
pub mod error;
pub mod log;
pub mod subsquid;
pub mod wallet;
pub mod wormhole_lib;

// Re-export commonly used types and functions
pub use error::{QuantusError as Error, Result};

// Re-export chain client and config
pub use chain::client::{ChainConfig, QuantusClient};

// Re-export dilithium crypto
pub use qp_dilithium_crypto;

// Re-export commonly used types from sp_core and sp_runtime
pub use sp_core::crypto::AccountId32;
pub use sp_runtime::MultiAddress;

// Re-export transfer functions for library usage
pub use cli::send::{
	batch_transfer, format_balance_with_symbol, get_balance, transfer, transfer_with_nonce,
};

// Re-export multisig functions for library usage
pub use cli::multisig::{
	approve_dissolve_multisig, approve_proposal, cancel_proposal, create_multisig,
	get_multisig_info, get_proposal_info, list_proposals, parse_amount as parse_multisig_amount,
	predict_multisig_address, propose_custom, propose_transfer, MultisigInfo, ProposalInfo,
	ProposalStatus,
};

// Re-export wormhole library functions for SDK usage
pub use wormhole_lib::{
	compute_nullifier, compute_output_amount, compute_wormhole_address,
	generate_proof as generate_wormhole_proof, quantize_amount, ProofGenerationInput,
	ProofGenerationOutput, WormholeLibError, NATIVE_ASSET_ID, SCALE_DOWN_FACTOR, VOLUME_FEE_BPS,
};

// Re-export wormhole on-chain helpers for SDK usage.
// These are the on-chain side of the wormhole flow (proof aggregation, unsigned
// `verify_aggregated_proof` submission, transfer-event parsing, leaf decoding)
// that complement the off-chain proof-generation functions in `wormhole_lib`.
//
// `NativeTransferred` is the subxt-generated event type required by
// `parse_transfer_events`; we re-export it so SDK callers don't have to reach
// into `chain::quantus_subxt::api::wormhole::events::*`.
pub use chain::quantus_subxt::api::wormhole::events::NativeTransferred;
pub use cli::wormhole::{
	aggregate_proofs, at_best_block, compute_merkle_positions, decode_full_leaf_data,
	get_zk_merkle_proof, parse_transfer_events, read_proof_file,
	submit_unsigned_verify_aggregated_proof, verify_aggregated_and_get_events, write_proof_file,
	IncludedAt, TransferInfo,
};

// Re-export collect rewards library for SDK usage
pub use collect_rewards_lib::{
	collect_rewards, query_pending_transfers, query_pending_transfers_for_address,
	CollectRewardsConfig, CollectRewardsError, CollectRewardsResult, NoOpProgress, PendingTransfer,
	ProgressCallback, QueryPendingTransfersResult, WithdrawalBatch,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Get the library version
pub fn version() -> &'static str {
	VERSION
}

/// Get the library name
pub fn name() -> &'static str {
	NAME
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_version() {
		assert!(!version().is_empty());
	}

	#[test]
	fn test_name() {
		assert_eq!(name(), "quantus-cli");
	}
}
