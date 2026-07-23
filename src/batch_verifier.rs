//! Load private/public-batch `WormholeVerifier`s from generated circuit bins.
//!
//! `WormholeVerifier::new_from_bytes` pins artifacts to the canonical *leaf*
//! circuit via keccak256. Batch verifier bytes are sized by `QP_NUM_*` and
//! therefore cannot use that pin — the pallet uses the same deserialize +
//! profile-check path implemented here.

use crate::error::{QuantusError, Result};
use qp_plonky2_verifier::util::serialization::DefaultGateSerializer;
use qp_wormhole_aggregator::config::CircuitBinsConfig;
use qp_wormhole_verifier::{
	CircuitConfig, CommonCircuitData, VerifierCircuitData, VerifierOnlyCircuitData,
	WormholeVerifier, D, F, MIN_LEAF_SECURITY_BITS, PUBLIC_INPUTS_FELTS_LEN,
};
use std::path::Path;

/// Header felts of the private-batch PI layout (must match pallet-wormhole /
/// `PrivateBatchPublicInputs::try_from_u64_slice`).
const PRIVATE_BATCH_PI_HEADER_FELTS: usize = 8;

fn private_batch_expected_config() -> CircuitConfig {
	// Must match `qp_zk_circuits_common::circuit::wormhole_private_batch_circuit_config`.
	CircuitConfig {
		num_wires: 135,
		num_routed_wires: 60,
		..CircuitConfig::standard_recursion_zk_config()
	}
}

fn public_batch_expected_config() -> CircuitConfig {
	// Must match `qp_zk_circuits_common::circuit::wormhole_public_batch_circuit_config`.
	CircuitConfig::standard_recursion_config()
}

fn private_batch_expected_public_inputs(num_leaf_proofs: usize) -> usize {
	PRIVATE_BATCH_PI_HEADER_FELTS + num_leaf_proofs * PUBLIC_INPUTS_FELTS_LEN
}

fn public_batch_expected_public_inputs(
	num_private_batch_proofs: usize,
	num_leaf_proofs: usize,
) -> usize {
	qp_wormhole_inputs::public_batch_pi::pi_len(num_private_batch_proofs, num_leaf_proofs)
}

fn ensure_batch_verifier_profile(
	common: &CommonCircuitData<F, D>,
	expected_config: &CircuitConfig,
	expected_public_inputs: usize,
) -> std::result::Result<(), String> {
	if common.config != *expected_config {
		return Err("circuit config does not match the canonical batch circuit config".to_string());
	}
	if common.config.security_bits < MIN_LEAF_SECURITY_BITS {
		return Err(format!(
			"circuit config security_bits {} is below the minimum {}",
			common.config.security_bits, MIN_LEAF_SECURITY_BITS
		));
	}
	if common.num_public_inputs != expected_public_inputs {
		return Err(format!(
			"public-input count {} does not match the compiled batch dimensions (expected {})",
			common.num_public_inputs, expected_public_inputs
		));
	}
	Ok(())
}

fn load_batch_verifier_from_bytes(
	verifier_bytes: &[u8],
	common_bytes: &[u8],
	expected_config: &CircuitConfig,
	expected_public_inputs: usize,
	name: &str,
) -> Result<WormholeVerifier> {
	let verifier_only = VerifierOnlyCircuitData::from_bytes(verifier_bytes.to_vec()).map_err(|e| {
		QuantusError::Generic(format!("Failed to deserialize {name} verifier-only data: {e}"))
	})?;

	let common = CommonCircuitData::from_bytes(common_bytes.to_vec(), &DefaultGateSerializer)
		.map_err(|e| {
			QuantusError::Generic(format!("Failed to deserialize {name} common circuit data: {e}"))
		})?;

	if let Err(reason) =
		ensure_batch_verifier_profile(&common, expected_config, expected_public_inputs)
	{
		return Err(QuantusError::Generic(format!(
			"{name} verifier artifact rejected: {reason} \
			 (security_bits={}, num_public_inputs={}, expected_public_inputs={})",
			common.config.security_bits,
			common.num_public_inputs,
			expected_public_inputs
		)));
	}

	Ok(WormholeVerifier {
		circuit_data: VerifierCircuitData { verifier_only, common },
	})
}

fn load_batch_verifier_from_files(
	verifier_path: &Path,
	common_path: &Path,
	expected_config: &CircuitConfig,
	expected_public_inputs: usize,
	name: &str,
) -> Result<WormholeVerifier> {
	let verifier_bytes = std::fs::read(verifier_path).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to read {name} verifier {}: {e}",
			verifier_path.display()
		))
	})?;
	let common_bytes = std::fs::read(common_path).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to read {name} common {}: {e}",
			common_path.display()
		))
	})?;
	load_batch_verifier_from_bytes(
		&verifier_bytes,
		&common_bytes,
		expected_config,
		expected_public_inputs,
		name,
	)
}

/// Load the private-batch verifier from `bins_dir`, applying batch profile checks
/// (not the leaf keccak256 pin).
pub fn load_private_batch_verifier(bins_dir: &Path) -> Result<WormholeVerifier> {
	let config = CircuitBinsConfig::load(bins_dir).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to load circuit bins config from {}: {e}",
			bins_dir.display()
		))
	})?;
	load_batch_verifier_from_files(
		&bins_dir.join("private_batch_verifier.bin"),
		&bins_dir.join("private_batch_common.bin"),
		&private_batch_expected_config(),
		private_batch_expected_public_inputs(config.num_leaf_proofs),
		"private batch",
	)
}

/// Load the public-batch verifier from `bins_dir`, applying batch profile checks
/// (not the leaf keccak256 pin).
pub fn load_public_batch_verifier(bins_dir: &Path) -> Result<WormholeVerifier> {
	let config = CircuitBinsConfig::load(bins_dir).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to load circuit bins config from {}: {e}",
			bins_dir.display()
		))
	})?;
	let num_private_batch_proofs = config.num_private_batch_proofs.ok_or_else(|| {
		QuantusError::Generic(
			"Circuit binaries lack public-batch support (num_private_batch_proofs missing in config.json); regenerate them"
				.to_string(),
		)
	})?;
	load_batch_verifier_from_files(
		&bins_dir.join("public_batch_verifier.bin"),
		&bins_dir.join("public_batch_common.bin"),
		&public_batch_expected_config(),
		public_batch_expected_public_inputs(num_private_batch_proofs, config.num_leaf_proofs),
		"public batch",
	)
}


#[cfg(test)]
mod tests {
	use super::*;
	use std::path::PathBuf;

	fn bins_dir() -> PathBuf {
		// Prefer project generated-bins (dev builds); fall back to OUT_DIR copy.
		let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("generated-bins");
		if root.join("config.json").exists() {
			root
		} else {
			panic!("generated-bins missing; run a full build first");
		}
	}

	#[test]
	fn loads_private_and_public_batch_verifiers() {
		let dir = bins_dir();
		let private = load_private_batch_verifier(&dir).expect("private");
		let public = load_public_batch_verifier(&dir).expect("public");
		assert!(private.circuit_data.common.num_public_inputs > 0);
		assert!(public.circuit_data.common.num_public_inputs > 0);
		// Leaf pin path must still reject these bytes.
		let v = std::fs::read(dir.join("private_batch_verifier.bin")).unwrap();
		let c = std::fs::read(dir.join("private_batch_common.bin")).unwrap();
		let leaf_err = WormholeVerifier::new_from_bytes(&v, &c).unwrap_err();
		assert!(
			leaf_err.to_string().contains("does not match the canonical Wormhole leaf circuit"),
			"unexpected err: {leaf_err}"
		);
	}
}
