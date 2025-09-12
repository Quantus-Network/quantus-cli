/// Address formatting utilities for consistent SS58 encoding
///
/// This module provides unified functions for formatting addresses in the Quantus
/// SS58 format (version 189). Since the default SS58 version is set to 189 in main.rs,
/// most conversions can use the simpler to_ss58check() method.

use sp_core::crypto::Ss58Codec;

/// Trait for converting AccountId32 to Quantus SS58 format
pub trait QuantusSS58 {
    fn to_quantus_ss58(&self) -> String;
}

impl QuantusSS58 for sp_core::crypto::AccountId32 {
    fn to_quantus_ss58(&self) -> String {
        self.to_ss58check()
    }
}

impl QuantusSS58 for subxt::ext::subxt_core::utils::AccountId32 {
    fn to_quantus_ss58(&self) -> String {
        let bytes: [u8; 32] = *self.as_ref();
        let sp_account_id = sp_core::crypto::AccountId32::from(bytes);
        sp_account_id.to_ss58check()
    }
}