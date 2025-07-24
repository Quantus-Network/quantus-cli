//! `quantus system` subcommand - system information
use crate::chain::client::ChainConfig;
use crate::{chain::client, log_print, log_verbose};
use colored::Colorize;
use serde_json::Value;
use subxt::OnlineClient;

// Import ChainHead RPC API
use std::error::Error;
use subxt::backend::chain_head::ChainHeadRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::PolkadotConfig;

/// Chain native token information structure
#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub symbol: String,
    pub decimals: u8,
    pub ss58_format: Option<u8>,
}

/// Chain information from ChainHead API
#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub token: TokenInfo,
    pub chain_name: Option<String>,
    pub genesis_hash: Option<String>,
}

/// Client for retrieving token information using ChainHead RPC
pub struct ChainHeadTokenClient {
    rpc: ChainHeadRpcMethods<PolkadotConfig>,
}

impl ChainHeadTokenClient {
    /// Creates a new client from endpoint URL
    pub async fn new(url: &str) -> Result<Self, Box<dyn Error>> {
        let rpc_client = RpcClient::from_url(url).await?;
        let rpc = ChainHeadRpcMethods::<PolkadotConfig>::new(rpc_client);

        Ok(Self { rpc })
    }

    /// Gets native chain token information using ChainHead RPC
    pub async fn get_token_info(&self) -> Result<TokenInfo, Box<dyn Error>> {
        // Get system properties using chainspec_v1_properties
        let properties: serde_json::Map<String, Value> = self.rpc.chainspec_v1_properties().await?;

        // Extract token symbol
        let symbol = properties
            .get("tokenSymbol")
            .and_then(|v| v.as_str())
            .unwrap_or("UNIT") // default to UNIT if no information
            .to_string();

        // Extract decimal places
        let decimals = properties
            .get("tokenDecimals")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8; // default to 0 if no information

        // Extract SS58 format (optional)
        let ss58_format = properties
            .get("ss58Format")
            .and_then(|v| v.as_u64())
            .map(|v| v as u8);

        Ok(TokenInfo {
            symbol,
            decimals,
            ss58_format,
        })
    }

    /// Gets chain name
    pub async fn get_chain_name(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.rpc.chainspec_v1_chain_name().await?)
    }

    /// Gets genesis hash
    pub async fn get_genesis_hash(&self) -> Result<String, Box<dyn Error>> {
        let hash = self.rpc.chainspec_v1_genesis_hash().await?;
        Ok(format!("{:?}", hash)) // Format the hash for display
    }
}

/// Gets complete chain information using ChainHead API
pub async fn get_complete_chain_info(node_url: &str) -> crate::error::Result<ChainInfo> {
    log_verbose!("🚀 Getting complete chain info using ChainHead API...");

    match ChainHeadTokenClient::new(node_url).await {
        Ok(client) => {
            let token_info = client.get_token_info().await.map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "ChainHead token info failed: {:?}",
                    e
                ))
            })?;

            let chain_name = client.get_chain_name().await.ok();
            let genesis_hash = client.get_genesis_hash().await.ok();

            log_verbose!(
                "🎯 Complete chain info retrieved: token={:?}, chain={:?}",
                token_info,
                chain_name
            );

            Ok(ChainInfo {
                token: token_info,
                chain_name,
                genesis_hash,
            })
        }
        Err(e) => {
            log_verbose!("❌ ChainHead client creation failed: {:?}", e);
            Err(crate::error::QuantusError::NetworkError(format!(
                "ChainHead client failed: {:?}",
                e
            )))
        }
    }
}

/// Uses ChainHead RPC API to get chain properties (internal)
async fn get_chain_properties_with_chainhead(node_url: &str) -> crate::error::Result<TokenInfo> {
    // Use the complete chain info and extract just the token info
    match get_complete_chain_info(node_url).await {
        Ok(chain_info) => Ok(chain_info.token),
        Err(e) => Err(e),
    }
}

/// Get system information including ChainHead data
pub async fn get_system_info(
    client: &OnlineClient<ChainConfig>,
    node_url: &str,
) -> crate::error::Result<()> {
    log_verbose!("🔍 Querying system information...");

    // Get complete chain information from ChainHead API using the actual node_url
    let chain_info = get_complete_chain_info(node_url).await?;

    // Get metadata information
    let metadata = client.metadata();
    let pallets: Vec<_> = metadata.pallets().collect();

    log_print!("🏗️  Chain System Information:");
    log_print!(
        "   💰 Token: {} ({} decimals)",
        chain_info.token.symbol.bright_yellow(),
        chain_info.token.decimals.to_string().bright_cyan()
    );

    if let Some(name) = &chain_info.chain_name {
        log_print!("   🔗 Chain: {}", name.bright_green());
    }

    if let Some(hash) = &chain_info.genesis_hash {
        log_print!("   🧬 Genesis: {}...", hash[..16].bright_cyan());
    }

    log_print!("   📦 Pallets: {}", pallets.len().to_string());
    log_print!("   🔧 Runtime: Substrate-based");

    log_verbose!("💡 Use 'quantus metadata' to explore all available pallets and calls");

    log_verbose!("✅ System info retrieved successfully!");

    Ok(())
}

/// Get runtime version information
pub async fn get_runtime_version_info(
    client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<()> {
    log_verbose!("🔍 Getting runtime version...");

    let runtime_version = client.runtime_version();

    log_print!("🔧 Runtime Information:");
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

/// Get detailed metadata statistics
pub async fn get_metadata_stats(client: &OnlineClient<ChainConfig>) -> crate::error::Result<()> {
    log_verbose!("🔍 Getting metadata statistics...");

    let metadata = client.metadata();
    let pallets: Vec<_> = metadata.pallets().collect();

    log_verbose!("🔍 SubXT metadata: {} pallets available", pallets.len());

    log_print!("📊 Metadata Statistics:");
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

/// Handle system command
pub async fn handle_system_subxt_command(node_url: &str) -> crate::error::Result<()> {
    log_print!("🚀 System Information");
    let client = client::create_subxt_client(node_url).await?;
    get_system_info(&client, node_url).await?;

    Ok(())
}

/// Handle extended system commands with additional info
pub async fn handle_system_subxt_extended_command(
    node_url: &str,
    show_runtime: bool,
    show_metadata: bool,
) -> crate::error::Result<()> {
    log_print!("🚀 Extended System Information");

    let client = client::create_subxt_client(node_url).await?;

    // Basic system info
    get_system_info(&client, node_url).await?;

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
