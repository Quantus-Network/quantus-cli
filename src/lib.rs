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
