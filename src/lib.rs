//! # Quantus CLI Library
//!
//! This library provides the core functionality for interacting with the Quantus Network.
//! It can be used as a dependency in other Rust projects that need to interact with
//! the Quantus blockchain.

pub mod chain;
pub mod cli;
pub mod config;
pub mod error;
pub mod log;
pub mod wallet;

// Re-export commonly used types and functions
pub use error::{QuantusError as Error, Result};

// Re-export chain client and config
pub use chain::client::{ChainConfig, QuantusClient};

// Re-export dilithium crypto
pub use dilithium_crypto;

// Re-export commonly used types from sp_core and sp_runtime
pub use sp_core::crypto::AccountId32;
pub use sp_runtime::MultiAddress;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// Get the library version
pub fn version() -> &'static str {
	VERSION
}

/// Get the library name
pub fn name() -> &'static str {
	NAME
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_version() {
		assert!(!version().is_empty());
	}

	#[test]
	fn test_name() {
		assert_eq!(name(), "quantus-cli");
	}
}
