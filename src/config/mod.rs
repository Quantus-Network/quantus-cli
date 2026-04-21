//! Configuration management module
//!
//! This module handles runtime compatibility information.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibleRuntime {
	pub spec_version: u32,
	pub transaction_version: u32,
}

/// List of runtime spec versions that this CLI is compatible with.
pub const COMPATIBLE_RUNTIME_VERSIONS: &[u32] = &[127];

/// List of transaction versions that this CLI is compatible with.
pub const COMPATIBLE_TRANSACTION_VERSIONS: &[u32] = &[2];

/// Supported runtime / transaction version pairs for the checked-in metadata snapshot.
pub const COMPATIBLE_RUNTIMES: &[CompatibleRuntime] =
	&[CompatibleRuntime { spec_version: 127, transaction_version: 2 }];

/// Check if a runtime version pair is compatible with this CLI.
pub fn is_runtime_compatible(spec_version: u32, transaction_version: u32) -> bool {
	COMPATIBLE_RUNTIMES.iter().any(|runtime| {
		runtime.spec_version == spec_version && runtime.transaction_version == transaction_version
	})
}
