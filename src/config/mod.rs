//! Runtime compatibility configuration.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibleRuntime {
	pub spec_version: u32,
	pub transaction_version: u32,
}

/// Supported runtime / transaction version pairs.
pub const COMPATIBLE_RUNTIMES: &[CompatibleRuntime] =
	&[CompatibleRuntime { spec_version: 134, transaction_version: 2 }];

/// Check whether a runtime version pair is supported by this CLI.
pub fn is_runtime_compatible(spec_version: u32, transaction_version: u32) -> bool {
	COMPATIBLE_RUNTIMES.iter().any(|runtime| {
		runtime.spec_version == spec_version && runtime.transaction_version == transaction_version
	})
}
