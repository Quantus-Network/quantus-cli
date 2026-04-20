/// Filename of the marker recording which CLI version produced the bins.
/// When the CLI is upgraded this mismatches and the runtime regenerates.
/// Shared by `build.rs` and `crate::bins` via `include!`.
const VERSION_MARKER: &str = ".quantus-cli-version";

/// Number of leaf proofs aggregated into a single batch (default for both
/// build-time generation and runtime lazy generation).
const DEFAULT_NUM_LEAF_PROOFS: usize = 16;
