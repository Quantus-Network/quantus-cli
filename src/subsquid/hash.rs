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

/// Compute the hash prefix for a raw address with the specified prefix length.
///
/// Convenience function combining `compute_address_hash` and `get_hash_prefix`.
pub fn compute_address_prefix(raw_address: &[u8; 32], prefix_len: usize) -> String {
	let hash = compute_address_hash(raw_address);
	get_hash_prefix(&hash, prefix_len)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_compute_address_hash() {
		let address = [0u8; 32];
		let hash = compute_address_hash(&address);

		// blake3 of 32 zero bytes should produce a consistent hash
		assert_eq!(hash.len(), 64); // blake3 produces 256-bit = 64 hex chars

		// Verify it's valid hex
		assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[test]
	fn test_get_hash_prefix() {
		let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

		assert_eq!(get_hash_prefix(hash, 2), "ab");
		assert_eq!(get_hash_prefix(hash, 4), "abcd");
		assert_eq!(get_hash_prefix(hash, 8), "abcdef12");
	}

	#[test]
	fn test_get_hash_prefix_edge_cases() {
		let hash = "abcd";

		// Empty prefix
		assert_eq!(get_hash_prefix(hash, 0), "");

		// Full hash as prefix
		assert_eq!(get_hash_prefix(hash, 4), "abcd");

		// Prefix longer than hash - returns full hash
		assert_eq!(get_hash_prefix(hash, 10), "abcd");
	}

	#[test]
	fn test_compute_address_prefix() {
		let address = [1u8; 32];
		let prefix = compute_address_prefix(&address, 4);

		assert_eq!(prefix.len(), 4);
		assert!(prefix.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[test]
	fn test_hash_consistency() {
		// Same input should always produce same output
		let address = [42u8; 32];
		let hash1 = compute_address_hash(&address);
		let hash2 = compute_address_hash(&address);

		assert_eq!(hash1, hash2);
	}

	#[test]
	fn test_different_addresses_different_hashes() {
		let address1 = [1u8; 32];
		let address2 = [2u8; 32];

		let hash1 = compute_address_hash(&address1);
		let hash2 = compute_address_hash(&address2);

		assert_ne!(hash1, hash2);
	}

	#[test]
	fn test_all_zeros() {
		let address = [0u8; 32];
		let hash = compute_address_hash(&address);

		// Known hash for 32 zero bytes (blake3)
		// This value must match the TypeScript implementation
		assert_eq!(hash, "2ada83c1819a5372dae1238fc1ded123c8104fdaa15862aaee69428a1820fcda");
	}

	#[test]
	fn test_all_ones() {
		let address = [0xffu8; 32];
		let hash = compute_address_hash(&address);

		// Known hash for 32 0xff bytes (blake3)
		// This value must match the TypeScript implementation
		assert_eq!(hash, "9b34f060fbc0f0aa11f150e26519deff613277b60656f0f8356ed2261505f5c5");
	}

	#[test]
	fn test_sequential_bytes() {
		let mut address = [0u8; 32];
		for (i, byte) in address.iter_mut().enumerate() {
			*byte = i as u8;
		}
		let hash = compute_address_hash(&address);

		// Known hash for sequential bytes 0-31 (blake3)
		// This value must match the TypeScript implementation
		assert_eq!(hash, "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65");
	}

	/// Test vectors that can be used to verify cross-implementation consistency
	/// between Rust and TypeScript
	#[test]
	fn print_test_vectors() {
		let test_cases: Vec<(&str, [u8; 32])> = vec![
			("zero_bytes", [0u8; 32]),
			("ones_bytes", [0xffu8; 32]),
			("sequential", {
				let mut arr = [0u8; 32];
				for (i, byte) in arr.iter_mut().enumerate() {
					*byte = i as u8;
				}
				arr
			}),
			("all_42s", [42u8; 32]),
		];

		println!("\n=== Test Vectors for Cross-Implementation Testing ===");
		println!("Use these to verify TypeScript implementation matches:\n");

		for (name, address) in test_cases {
			let hash = compute_address_hash(&address);
			println!("{}:", name);
			println!("  input:   {}", hex::encode(address));
			println!("  hash:    {}", hash);
			println!("  prefix4: {}", get_hash_prefix(&hash, 4));
			println!("  prefix8: {}", get_hash_prefix(&hash, 8));
			println!();
		}
	}
}
