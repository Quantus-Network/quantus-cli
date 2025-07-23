//! `quantus system-subxt` subcommand - SubXT implementation for system information
use crate::{chain::types::ChainConfig, error::QuantusError, log_print, log_verbose};
use colored::Colorize;
use subxt::OnlineClient;

/// SubXT-based system information client
pub struct SubxtSystemClient {
    client: OnlineClient<ChainConfig>,
}

impl SubxtSystemClient {
    /// Create a new SubXT system client
    pub async fn new(node_url: &str) -> crate::error::Result<Self> {
        log_verbose!("🔗 Connecting to Quantus node with subxt: {}", node_url);

        let client = OnlineClient::<ChainConfig>::from_url(node_url)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to connect with subxt: {:?}", e))
            })?;

        log_verbose!("✅ Connected to Quantus node with subxt successfully!");

        Ok(SubxtSystemClient { client })
    }

    /// Get system information using SubXT
    pub async fn get_system_info(&self) -> crate::error::Result<()> {
        log_verbose!("🔍 Querying system information with subxt...");

        // Get chain properties using SubXT
        let (token_symbol, token_decimals) = self.get_chain_properties().await?;

        // Get metadata information using SubXT
        let metadata = self.client.metadata();
        let pallets: Vec<_> = metadata.pallets().collect();

        log_print!("🏗️  Chain System Information (using subxt):");
        log_print!(
            "   💰 Token: {} ({} decimals)",
            token_symbol.bright_yellow(),
            token_decimals.to_string().bright_cyan()
        );
        log_print!("   📦 Pallets: {}", pallets.len().to_string());
        log_print!("   🔧 Runtime: Substrate-based");
        log_print!("   🌐 Network: Quantus Network");

        log_verbose!("💡 Use 'quantus metadata-subxt' to explore all available pallets and calls");

        log_verbose!("✅ System info retrieved successfully with subxt!");

        Ok(())
    }

    /// Get chain properties using SubXT
    async fn get_chain_properties(&self) -> crate::error::Result<(String, u32)> {
        log_verbose!("🔍 Querying chain properties with subxt...");

        // Query system properties using SubXT
        // For now, use the same hardcoded values as other SubXT modules
        // TODO: Implement proper system properties query when SubXT API is available
        let token_symbol = "DEV".to_string();
        let token_decimals = 9u32;

        log_verbose!(
            "📊 Chain properties: token={}, decimals={}",
            token_symbol,
            token_decimals
        );

        log_verbose!(
            "💰 Token: {} with {} decimals",
            token_symbol,
            token_decimals
        );

        Ok((token_symbol, token_decimals))
    }

    /// Get runtime version information using SubXT
    pub async fn get_runtime_version_info(&self) -> crate::error::Result<()> {
        log_verbose!("🔍 Getting runtime version with subxt...");

        let runtime_version = self.client.runtime_version();

        log_print!("🔧 Runtime Information (using subxt):");
        log_print!(
            "   📋 Spec version: {}",
            runtime_version.spec_version.to_string().bright_green()
        );
        log_print!(
            "   🔄 Transaction version: {}",
            runtime_version
                .transaction_version
                .to_string()
                .bright_yellow()
        );

        Ok(())
    }

    /// Get detailed metadata statistics using SubXT
    pub async fn get_metadata_stats(&self) -> crate::error::Result<()> {
        log_verbose!("🔍 Getting metadata statistics with subxt...");

        let metadata = self.client.metadata();
        let pallets: Vec<_> = metadata.pallets().collect();

        log_verbose!("🔍 SubXT metadata: {} pallets available", pallets.len());

        log_print!("📊 Metadata Statistics (using subxt):");
        log_print!("   📦 Total pallets: {}", pallets.len());
        log_print!("   🔗 Metadata version: SubXT (type-safe)");

        // Count calls across all pallets
        let mut total_calls = 0;
        for pallet in &pallets {
            if let Some(calls) = pallet.call_variants() {
                total_calls += calls.len();
            }
        }

        log_print!("   🎯 Total calls: {}", total_calls);
        log_print!("   ⚡ API: Type-safe SubXT");

        Ok(())
    }
}

/// Handle system-subxt command
pub async fn handle_system_subxt_command(node_url: &str) -> crate::error::Result<()> {
    log_print!("🚀 System Information (SubXT)");

    let system_client = SubxtSystemClient::new(node_url).await?;
    system_client.get_system_info().await?;

    Ok(())
}

/// Handle extended system-subxt commands with additional info
pub async fn handle_system_subxt_extended_command(
    node_url: &str,
    show_runtime: bool,
    show_metadata: bool,
) -> crate::error::Result<()> {
    log_print!("🚀 Extended System Information (SubXT)");

    let system_client = SubxtSystemClient::new(node_url).await?;

    // Basic system info
    system_client.get_system_info().await?;

    if show_runtime {
        log_print!("");
        system_client.get_runtime_version_info().await?;
    }

    if show_metadata {
        log_print!("");
        system_client.get_metadata_stats().await?;
    }

    Ok(())
}
