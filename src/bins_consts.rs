/// Filename of the marker recording which CLI version produced the bins.
/// When the CLI is upgraded this mismatches and the runtime regenerates.
/// Shared by `build.rs` and `crate::bins` via `include!`.
pub(crate) const VERSION_MARKER: &str = ".quantus-cli-version";

/// Number of leaf proofs aggregated into a single batch (default for both
/// build-time generation and runtime lazy generation).
pub(crate) const DEFAULT_NUM_LEAF_PROOFS: usize = 16;

/// Files required for local proving, aggregation, and verifier compatibility.
pub(crate) const REQUIRED_BIN_FILES: &[&str] = &[
	"common.bin",
	"verifier.bin",
	"prover.bin",
	"dummy_proof.bin",
	"inner_common.bin",
	"inner_verifier.bin",
	"inner_prover.bin",
	"inner_targets.bin",
	"outer_common.bin",
	"outer_verifier.bin",
	"outer_prover.bin",
	"outer_targets.bin",
	"aggregated_common.bin",
	"aggregated_verifier.bin",
	"aggregated_prover.bin",
	"aggregated_targets.bin",
	"config.json",
];
