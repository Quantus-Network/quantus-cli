/// Address formatting utilities for consistent SS58 encoding
///
/// This module provides unified functions for formatting addresses in the Quantus
/// SS58 format (version 189).
use crate::error::{QuantusError, Result};
use sp_core::crypto::{Ss58AddressFormat, Ss58Codec};

/// Returns the Quantus SS58 address format (version 189)
/// This is the standard address format for Quantus Network, producing addresses with 'qz' prefix
#[inline]
pub fn quantus_ss58_format() -> Ss58AddressFormat {
	Ss58AddressFormat::custom(189)
}

/// Trait for converting AccountId32 to Quantus SS58 format
pub trait QuantusSS58 {
	fn to_quantus_ss58(&self) -> String;
}

impl QuantusSS58 for sp_core::crypto::AccountId32 {
	fn to_quantus_ss58(&self) -> String {
		self.to_ss58check_with_version(quantus_ss58_format())
	}
}

impl QuantusSS58 for subxt::ext::subxt_core::utils::AccountId32 {
	fn to_quantus_ss58(&self) -> String {
		let bytes: [u8; 32] = *self.as_ref();
		let sp_account_id = sp_core::crypto::AccountId32::from(bytes);
		sp_account_id.to_ss58check_with_version(quantus_ss58_format())
	}
}

/// Convert raw 32-byte account to Quantus SS58 format
pub fn bytes_to_quantus_ss58(bytes: &[u8; 32]) -> String {
	let sp_account_id = sp_core::crypto::AccountId32::from(*bytes);
	sp_account_id.to_ss58check_with_version(quantus_ss58_format())
}

/// Convert a byte slice to Quantus SS58 format.
pub fn slice_to_quantus_ss58(bytes: &[u8]) -> Result<String> {
	let arr: [u8; 32] = bytes
		.try_into()
		.map_err(|_| QuantusError::Generic("account must be 32 bytes".to_string()))?;
	Ok(bytes_to_quantus_ss58(&arr))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn slice_to_quantus_ss58_rejects_non_32_byte_input() {
		// #160783: malformed address buffers must not panic.
		let err = slice_to_quantus_ss58(&[0u8; 16]).expect_err("short slice must error");
		assert!(err.to_string().contains("32 bytes"), "unexpected error: {err}");
		let ok = slice_to_quantus_ss58(&[0u8; 32]).expect("32-byte slice must succeed");
		assert!(ok.starts_with("qz"));
	}
}
