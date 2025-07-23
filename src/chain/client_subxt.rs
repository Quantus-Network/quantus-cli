//! Common SubXT client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing SubXT clients
//! across all CLI SubXT modules.

use crate::{chain::types::ChainConfig, error::QuantusError, log_verbose};
use subxt::OnlineClient;

// Removed SubxtClient struct - using OnlineClient<ChainConfig> directly

/// Common SubXT client creation function
///
/// This function is used by all SubXT CLI modules to create a connection to the Quantus node.
/// It provides consistent error handling and logging across all SubXT implementations.
pub async fn create_subxt_client(
    node_url: &str,
) -> crate::error::Result<OnlineClient<ChainConfig>> {
    log_verbose!("🔗 Connecting to Quantus node with subxt: {}", node_url);

    let client = OnlineClient::<ChainConfig>::from_url(node_url)
        .await
        .map_err(|e| {
            QuantusError::NetworkError(format!("Failed to connect with subxt: {:?}", e))
        })?;

    log_verbose!("✅ Connected to Quantus node successfully with subxt!");

    Ok(client)
}

// Removed macro - no longer needed since we use functions directly
