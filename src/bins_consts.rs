/// Filename of the marker recording which CLI version produced the bins.
/// When the CLI is upgraded this mismatches and the runtime regenerates.
/// Shared by `build.rs` and `crate::bins` via `include!`.
const VERSION_MARKER: &str = ".quantus-cli-version";

/// Filename of the manifest binding generated circuit artifacts to hashes and sizing.
/// Shared by `build.rs` and `crate::bins` via `include!`.
const MANIFEST_FILE: &str = "manifest.json";

/// Files hashed into `manifest.json` by `build.rs` and authenticated by
/// `crate::bins` at runtime. Defined once here so the two sides cannot drift
/// into a "file set mismatch" rejection of freshly built artifacts.
// No `*_prover.bin` entries: qp-wormhole-circuit-builder 4.2.0+ never emits
// them (provers rebuild circuits from source so a poisoned prover artifact
// cannot exfiltrate witness data).
const MANIFESTED_FILES: &[&str] = &[
	"verifier.bin",
	"common.bin",
	"private_batch_verifier.bin",
	"private_batch_common.bin",
	"public_batch_verifier.bin",
	"public_batch_common.bin",
	"dummy_proof.bin",
	"dummy_private_batch_proof.bin",
	"config.json",
	VERSION_MARKER,
];

/// Number of leaf proofs aggregated into a single private batch.
///
/// Matches `qp_wormhole_inputs::production::NUM_LEAF_PROOFS`. Eight is the
/// largest batch that stays at degree 15 with the rate-3 / 36-query FRI config.
///
/// Used by:
/// - build.rs: build-time circuit generation
/// - bins.rs: runtime lazy circuit generation
/// - collect_rewards_lib.rs: batching proofs for aggregation
pub const DEFAULT_NUM_LEAF_PROOFS: usize = 8;

/// Exit slots on each private batch.
///
/// Matches `qp_wormhole_inputs::production::NUM_EXIT_SLOTS`. Payouts are batch
/// witnesses, independent of how many leaves the batch verifies.
pub const DEFAULT_NUM_EXIT_SLOTS: usize = 32;

/// Number of private-batch proofs aggregated into a single public batch.
///
/// Matches `qp_wormhole_inputs::production::PUBLIC_BATCH_ARITY` (degree 19).
/// On-chain verification requires a node built from the same circuits.
pub const DEFAULT_NUM_PRIVATE_BATCH_PROOFS: usize = 89;
