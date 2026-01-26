//! Subsquid indexer client module for privacy-preserving queries.
//!
//! This module provides a client for querying the Subsquid indexer using
//! hash prefix queries, which allows clients to retrieve their transactions
//! without revealing their exact addresses to the indexer.

mod client;
mod hash;
mod types;

pub use client::SubsquidClient;
pub use hash::{compute_address_hash, get_hash_prefix};
pub use types::*;
