//! `quantus system-subxt` subcommand - SubXT implementation for system information
use crate::{chain::client, log_print, log_verbose};
use colored::Colorize;
use subxt::OnlineClient;
use crate::chain::client::ChainConfig;

/// Get system information using SubXT
pub async fn get_system_info(client: &OnlineClient<ChainConfig>) -> crate::error::Result<()> {
    log_verbose!("🔍 Querying system information with subxt...");

    // Get chain properties using SubXT
    let (token_symbol, token_decimals) = get_chain_properties(client).await?;

    // Get metadata information using SubXT
    let metadata = client.metadata();
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
async fn get_chain_properties(
    _client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<(String, u32)> {
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
pub async fn get_runtime_version_info(
    client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<()> {
    log_verbose!("🔍 Getting runtime version with subxt...");

    let runtime_version = client.runtime_version();

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
pub async fn get_metadata_stats(client: &OnlineClient<ChainConfig>) -> crate::error::Result<()> {
    log_verbose!("🔍 Getting metadata statistics with subxt...");

    let metadata = client.metadata();
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

/// Handle system-subxt command
pub async fn handle_system_subxt_command(node_url: &str) -> crate::error::Result<()> {
    log_print!("🚀 System Information (SubXT)");

    let client = client::create_subxt_client(node_url).await?;
    get_system_info(&client).await?;

    Ok(())
}

/// Handle extended system-subxt commands with additional info
pub async fn handle_system_subxt_extended_command(
    node_url: &str,
    show_runtime: bool,
    show_metadata: bool,
) -> crate::error::Result<()> {
    log_print!("🚀 Extended System Information (SubXT)");

    let client = client::create_subxt_client(node_url).await?;

    // Basic system info
    get_system_info(&client).await?;

    if show_runtime {
        log_print!("");
        get_runtime_version_info(&client).await?;
    }

    if show_metadata {
        log_print!("");
        get_metadata_stats(&client).await?;
    }

    Ok(())
}
