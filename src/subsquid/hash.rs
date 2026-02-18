//! Hash utilities for privacy-preserving queries.
//!
//! Uses blake3 to compute address hashes that match the Subsquid indexer.

/// Compute blake3 hash of raw address bytes and return as hex string.
///
/// This matches the hash computation done by the Subsquid indexer.
///
/// # Arguments
///
/// * `raw_address` - The raw 32-byte account ID
///
/// # Returns
///
/// The blake3 hash as a 64-character hex string
pub fn compute_address_hash(raw_address: &[u8; 32]) -> String {
	let hash = blake3::hash(raw_address);
	hex::encode(hash.as_bytes())
}

/// Get a prefix of the specified length from a hash.
///
/// # Arguments
///
/// * `hash` - The full hash as a hex string
/// * `prefix_len` - The number of hex characters to include in the prefix
///
/// # Returns
///
/// The prefix as a hex string
pub fn get_hash_prefix(hash: &str, prefix_len: usize) -> String {
	hash.chars().take(prefix_len).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	// Known test vectors - these values are verified against the TypeScript implementation
	const ZERO_BYTES_HASH: &str =
		"2ada83c1819a5372dae1238fc1ded123c8104fdaa15862aaee69428a1820fcda";
	const ONES_BYTES_HASH: &str =
		"9b34f060fbc0f0aa11f150e26519deff613277b60656f0f8356ed2261505f5c5";
	const SEQUENTIAL_BYTES_HASH: &str =
		"e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65";

	#[test]
	fn test_known_hash_vectors() {
		// These test vectors ensure Rust and TypeScript produce identical hashes
		assert_eq!(compute_address_hash(&[0u8; 32]), ZERO_BYTES_HASH);
		assert_eq!(compute_address_hash(&[0xffu8; 32]), ONES_BYTES_HASH);

		let mut sequential = [0u8; 32];
		for (i, byte) in sequential.iter_mut().enumerate() {
			*byte = i as u8;
		}
		assert_eq!(compute_address_hash(&sequential), SEQUENTIAL_BYTES_HASH);
	}

	#[test]
	fn test_hash_format() {
		let hash = compute_address_hash(&[0u8; 32]);
		assert_eq!(hash.len(), 64);
		assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[test]
	fn test_hash_determinism() {
		let address = [42u8; 32];
		assert_eq!(compute_address_hash(&address), compute_address_hash(&address));
	}

	#[test]
	fn test_different_inputs_different_hashes() {
		assert_ne!(compute_address_hash(&[1u8; 32]), compute_address_hash(&[2u8; 32]));
	}

	#[test]
	fn test_get_hash_prefix() {
		let hash = "abcdef1234567890";
		assert_eq!(get_hash_prefix(hash, 0), "");
		assert_eq!(get_hash_prefix(hash, 2), "ab");
		assert_eq!(get_hash_prefix(hash, 4), "abcd");
		assert_eq!(get_hash_prefix(hash, 100), hash); // longer than input returns full string
	}
}
