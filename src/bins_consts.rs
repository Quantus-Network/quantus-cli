/// Filename of the marker recording which CLI version produced the bins.
/// When the CLI is upgraded this mismatches and the runtime regenerates.
/// Shared by `build.rs` and `crate::bins` via `include!`.
const VERSION_MARKER: &str = ".quantus-cli-version";

/// Filename of the manifest binding generated circuit artifacts to hashes and sizing.
/// Shared by `build.rs` and `crate::bins` via `include!`.
const MANIFEST_FILE: &str = "manifest.json";

/// Number of leaf proofs aggregated into a single batch.
///
/// 7 is optimal for mobile devices: fits in degree_bits=15 (~1.5 GB peak memory).
/// 8+ leaves require degree_bits=16 (~2.5 GB peak), limiting to 6GB+ devices.
///
/// Used by:
/// - build.rs: build-time circuit generation
/// - bins.rs: runtime lazy circuit generation  
/// - collect_rewards_lib.rs: batching proofs for aggregation
pub const DEFAULT_NUM_LEAF_PROOFS: usize = 7;

/// Number of private-batch proofs aggregated into a single public batch.
///
/// Must match the chain's pallet-wormhole build default (QP_NUM_PRIVATE_BATCH_PROOFS)
/// or on-chain verification of public batches will fail.
pub const DEFAULT_NUM_PRIVATE_BATCH_PROOFS: usize = 4;
