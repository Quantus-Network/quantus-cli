//! Configuration management module
//!
//! This module handles runtime compatibility information.

/// List of runtime spec versions that this CLI is compatible with
pub const COMPATIBLE_RUNTIME_VERSIONS: &[u32] = &[115, 116];

/// Check if a runtime version is compatible with this CLI
pub fn is_runtime_compatible(spec_version: u32) -> bool {
	COMPATIBLE_RUNTIME_VERSIONS.contains(&spec_version)
}
