//! Runtime compatibility configuration.

use crate::error::{QuantusError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibleRuntime {
	pub spec_version: u32,
	pub transaction_version: u32,
}

/// Expected runtime spec name for Quantus nodes, as declared by the runtime's
/// `RuntimeVersion { spec_name: "quantus-runtime", .. }` in the chain repo.
pub const EXPECTED_RUNTIME_SPEC_NAME: &str = "quantus-runtime";

/// Supported runtime / transaction version pairs.
pub const COMPATIBLE_RUNTIMES: &[CompatibleRuntime] = &[
	CompatibleRuntime { spec_version: 134, transaction_version: 2 },
	CompatibleRuntime { spec_version: 135, transaction_version: 2 },
	CompatibleRuntime { spec_version: 135, transaction_version: 3 },
	CompatibleRuntime { spec_version: 136, transaction_version: 3 },
	CompatibleRuntime { spec_version: 142, transaction_version: 3 },
];

/// Check whether a runtime version pair is supported by this CLI.
pub fn is_runtime_compatible(spec_version: u32, transaction_version: u32) -> bool {
	COMPATIBLE_RUNTIMES.iter().any(|runtime| {
		runtime.spec_version == spec_version && runtime.transaction_version == transaction_version
	})
}

/// Validate that a connected node's runtime identity is a supported Quantus runtime.
///
/// Rejects wrong `specName` values and version pairs outside [`COMPATIBLE_RUNTIMES`].
pub fn validate_runtime_identity(
	spec_name: &str,
	spec_version: u32,
	transaction_version: u32,
) -> Result<()> {
	if spec_name != EXPECTED_RUNTIME_SPEC_NAME ||
		!is_runtime_compatible(spec_version, transaction_version)
	{
		return Err(QuantusError::NetworkError(format!(
			"Unsupported Quantus runtime: specName={spec_name}, specVersion={spec_version}, transactionVersion={transaction_version}"
		)));
	}
	Ok(())
}

/// Parse `state_getRuntimeVersion` JSON and reject unsupported Quantus runtimes.
pub fn validate_runtime_version_value(runtime_version: &serde_json::Value) -> Result<()> {
	let spec_name = runtime_version["specName"].as_str().ok_or_else(|| {
		QuantusError::NetworkError("Failed to parse runtime spec name".to_string())
	})?;
	let spec_version = runtime_version["specVersion"]
		.as_u64()
		.ok_or_else(|| QuantusError::NetworkError("Failed to parse spec version".to_string()))?
		as u32;
	let transaction_version = runtime_version["transactionVersion"].as_u64().ok_or_else(|| {
		QuantusError::NetworkError("Failed to parse transaction version".to_string())
	})? as u32;

	validate_runtime_identity(spec_name, spec_version, transaction_version)
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn validate_runtime_identity_accepts_compatible_quantus_runtime() {
		validate_runtime_identity(EXPECTED_RUNTIME_SPEC_NAME, 136, 3)
			.expect("compatible quantus runtime must be accepted");
		validate_runtime_identity(EXPECTED_RUNTIME_SPEC_NAME, 142, 3)
			.expect("the current vesting-enabled runtime must be accepted");
	}

	/// Pinned to the spec name the real Quantus runtime declares
	/// (`spec_name: "quantus-runtime"` in the chain repo's runtime/src/lib.rs).
	/// If this fails, the identity gate rejects every real node.
	#[test]
	fn validate_runtime_identity_accepts_real_quantus_runtime_spec_name() {
		validate_runtime_identity("quantus-runtime", 136, 3)
			.expect("the real runtime spec name 'quantus-runtime' must be accepted");
	}

	#[test]
	fn validate_runtime_identity_rejects_wrong_spec_name() {
		let err = validate_runtime_identity("quantus-impersonator", 136, 3).unwrap_err();
		let msg = err.to_string();
		assert!(
			msg.contains("Unsupported Quantus runtime") && msg.contains("quantus-impersonator"),
			"expected wrong-spec-name rejection, got: {msg}"
		);
	}

	#[test]
	fn validate_runtime_identity_rejects_incompatible_runtime_versions() {
		let err =
			validate_runtime_identity(EXPECTED_RUNTIME_SPEC_NAME, 999_999, 999_999).unwrap_err();
		let msg = err.to_string();
		assert!(
			msg.contains("Unsupported Quantus runtime") &&
				msg.contains("999999") &&
				msg.contains(EXPECTED_RUNTIME_SPEC_NAME),
			"expected incompatible-version rejection, got: {msg}"
		);
	}

	#[test]
	fn validate_runtime_version_value_rejects_wrong_spec_name() {
		let value = json!({
			"specName": "polkadot",
			"specVersion": 136,
			"transactionVersion": 3,
		});
		let err = validate_runtime_version_value(&value).unwrap_err();
		assert!(
			err.to_string().contains("polkadot"),
			"expected wrong-spec-name rejection via JSON helper"
		);
	}

	#[test]
	fn validate_runtime_version_value_rejects_incompatible_runtime() {
		let value = json!({
			"specName": EXPECTED_RUNTIME_SPEC_NAME,
			"specVersion": 1,
			"transactionVersion": 1,
		});
		assert!(validate_runtime_version_value(&value).is_err());
	}
}
