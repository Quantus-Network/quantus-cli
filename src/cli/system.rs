//! `quantus system` subcommand - system information
use crate::{
	chain::client::{ChainConfig, QuantusClient},
	error::QuantusError,
	log_print, log_verbose,
};
use colored::Colorize;
use serde_json::Value;
use subxt::OnlineClient;

// Import ChainHead RPC API
use std::error::Error;
use subxt::{
	backend::{chain_head::ChainHeadRpcMethods, rpc::RpcClient},
	PolkadotConfig,
};

/// Maximum decimal places supported by u128 balance scaling (10^38 fits in u128).
pub const MAX_SUPPORTED_TOKEN_DECIMALS: u64 = 38;

/// Chain native token information structure
#[derive(Debug, Clone)]
pub struct TokenInfo {
	pub symbol: String,
	pub decimals: u8,
	pub ss58_format: Option<u8>,
}

/// Parse and validate chain token properties from RPC `chainspec_v1_properties`.
///
/// Fail closed: missing/out-of-range `tokenDecimals`, empty `tokenSymbol`, and
/// `ss58Format` values above 255 are rejected instead of defaulted or truncated.
pub fn parse_token_info_from_properties(
	properties: &serde_json::Map<String, Value>,
) -> crate::error::Result<TokenInfo> {
	let symbol = properties
		.get("tokenSymbol")
		.and_then(|v| v.as_str())
		.filter(|symbol| !symbol.is_empty())
		.ok_or_else(|| {
			QuantusError::NetworkError("Invalid or missing chain property tokenSymbol".to_string())
		})?
		.to_string();

	let decimals = properties
		.get("tokenDecimals")
		.and_then(|v| v.as_u64())
		.filter(|decimals| *decimals <= MAX_SUPPORTED_TOKEN_DECIMALS)
		.ok_or_else(|| {
			QuantusError::NetworkError(format!(
				"Invalid or missing chain property tokenDecimals; expected an integer between 0 and {MAX_SUPPORTED_TOKEN_DECIMALS}"
			))
		})? as u8;

	let ss58_format = properties
		.get("ss58Format")
		.map(|v| {
			v.as_u64().and_then(|format| u8::try_from(format).ok()).ok_or_else(|| {
				QuantusError::NetworkError(
					"Invalid chain property ss58Format; expected an integer between 0 and 255"
						.to_string(),
				)
			})
		})
		.transpose()?;

	Ok(TokenInfo { symbol, decimals, ss58_format })
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
		Ok(parse_token_info_from_properties(&properties)?)
	}

	/// Gets chain name
	pub async fn get_chain_name(&self) -> Result<String, Box<dyn Error>> {
		Ok(self.rpc.chainspec_v1_chain_name().await?)
	}

	/// Gets genesis hash
	pub async fn get_genesis_hash(&self) -> Result<String, Box<dyn Error>> {
		let hash = self.rpc.chainspec_v1_genesis_hash().await?;
		Ok(format!("{hash:?}")) // Format the hash for display
	}
}

/// Gets complete chain information using ChainHead API
pub async fn get_complete_chain_info(node_url: &str) -> crate::error::Result<ChainInfo> {
	match ChainHeadTokenClient::new(node_url).await {
		Ok(client) => {
			let token_info = client.get_token_info().await.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"ChainHead token info failed: {e:?}"
				))
			})?;

			let chain_name = client.get_chain_name().await.ok();
			let genesis_hash = client.get_genesis_hash().await.ok();

			Ok(ChainInfo { token: token_info, chain_name, genesis_hash })
		},
		Err(e) => {
			log_verbose!("❌ ChainHead client creation failed: {:?}", e);
			Err(crate::error::QuantusError::NetworkError(format!("ChainHead client failed: {e:?}")))
		},
	}
}

/// Get system information including ChainHead data
pub async fn get_system_info(quantus_client: &QuantusClient) -> crate::error::Result<()> {
	log_verbose!("🔍 Querying system information...");

	// Get complete chain information from ChainHead API using the actual node_url
	let chain_info = get_complete_chain_info(quantus_client.node_url()).await?;

	// Get metadata information
	let metadata = quantus_client.client().metadata();
	let pallets: Vec<_> = metadata.pallets().collect();

	log_print!("🏗️  Chain System Information:");
	log_print!(
		"   💰 Token: {} ({} decimals)",
		chain_info.token.symbol.bright_yellow(),
		chain_info.token.decimals.to_string().bright_cyan()
	);

	if let Some(ss58_format) = chain_info.token.ss58_format {
		log_print!("   🔢 SS58 Format: {}", ss58_format.to_string().bright_magenta());
	}

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

/// Get detailed chain parameters information
pub async fn get_detailed_chain_params(
	quantus_client: &crate::chain::client::QuantusClient,
	show_raw_data: bool,
) -> crate::error::Result<()> {
	log_print!("🔧 Runtime Information:");

	// Get genesis hash
	let genesis_hash = quantus_client.get_genesis_hash().await?;
	log_print!("   🧬 Genesis hash: {}", genesis_hash.to_string().bright_cyan());

	// Get runtime version
	let (spec_version, transaction_version) = quantus_client.get_runtime_version().await?;
	log_print!("   📋 Spec version: {}", spec_version.to_string().bright_green());
	log_print!("   🔄 Transaction version: {}", transaction_version.to_string().bright_yellow());

	// Get current block info
	use jsonrpsee::core::client::ClientT;
	let current_block: serde_json::Value = quantus_client
		.rpc_client()
		.request::<serde_json::Value, [(); 0]>("chain_getHeader", [])
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to fetch current block: {e:?}"
			))
		})?;

	if let Some(block_number_str) = current_block["number"].as_str() {
		if let Ok(block_number) = u64::from_str_radix(&block_number_str[2..], 16) {
			log_print!("   📦 Current block: {}", block_number.to_string().bright_blue());

			// Calculate era based on block number
			let period = 64u64;
			let phase = block_number % period;
			log_print!("   ⏰ Era: period={}, phase={}", period, phase);
			log_print!(
				"   💡 Transaction era: Era::Mortal({}, {}) or Era::Immortal",
				period,
				phase
			);
		}
	}

	// Get full runtime info
	let runtime_info: serde_json::Value = quantus_client
		.rpc_client()
		.request::<serde_json::Value, [(); 0]>("state_getRuntimeVersion", [])
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Failed to fetch runtime info: {e:?}"))
		})?;

	if show_raw_data {
		log_verbose!("📋 Full runtime info: {:?}", runtime_info);
	}

	log_print!("📋 Runtime Details:");
	log_print!(
		"   🏷️  Spec name: {}",
		runtime_info["specName"].as_str().unwrap_or("unknown").bright_magenta()
	);
	log_print!(
		"   🔧 Implementation name: {}",
		runtime_info["implName"].as_str().unwrap_or("unknown").bright_cyan()
	);
	log_print!(
		"   📦 Implementation version: {}",
		runtime_info["implVersion"].as_u64().unwrap_or(0).to_string().bright_yellow()
	);
	log_print!(
		"   ✍️  Authoring version: {}",
		runtime_info["authoringVersion"].as_u64().unwrap_or(0).to_string().bright_blue()
	);
	log_print!(
		"   🗂️  State version: {}",
		runtime_info["stateVersion"].as_u64().unwrap_or(0).to_string().bright_green()
	);
	log_print!(
		"   💻 System version: {}",
		runtime_info["systemVersion"].as_u64().unwrap_or(0).to_string().bright_red()
	);

	// Get chain properties
	let chain_props: serde_json::Value = quantus_client
		.rpc_client()
		.request::<serde_json::Value, [(); 0]>("system_properties", [])
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to fetch chain properties: {e:?}"
			))
		})?;

	if show_raw_data {
		log_verbose!("🔗 Chain properties: {:?}", chain_props);
	}

	if show_raw_data {
		log_verbose!("📦 Current block: {:?}", current_block);
	}

	// Show block details
	log_print!("📦 Block Details:");
	if let Some(parent_hash) = current_block["parentHash"].as_str() {
		log_print!("   🔗 Parent hash: {}...", parent_hash[..16].bright_cyan());
	}
	if let Some(state_root) = current_block["stateRoot"].as_str() {
		log_print!("   🗂️  State root: {}...", state_root[..16].bright_magenta());
	}
	if let Some(extrinsics_root) = current_block["extrinsicsRoot"].as_str() {
		log_print!("   📄 Extrinsics root: {}...", extrinsics_root[..16].bright_yellow());
	}

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
pub async fn handle_system_command(node_url: &str) -> crate::error::Result<()> {
	log_print!("🚀 System Information");
	let quantus_client = QuantusClient::new(node_url).await?;
	get_system_info(&quantus_client).await?;

	Ok(())
}

/// Handle extended system commands with additional info
pub async fn handle_system_extended_command(
	node_url: &str,
	show_runtime: bool,
	show_metadata: bool,
	show_rpc_methods: bool,
	verbose: bool,
) -> crate::error::Result<()> {
	log_print!("🚀 Extended System Information");

	let quantus_client = QuantusClient::new(node_url).await?;

	// Basic system info
	get_system_info(&quantus_client).await?;

	if show_runtime {
		log_print!("");
		get_detailed_chain_params(&quantus_client, verbose).await?;
	}

	if show_metadata {
		log_print!("");
		get_metadata_stats(quantus_client.client()).await?;
	}

	if show_rpc_methods {
		log_print!("");
		list_rpc_methods(&quantus_client).await?;
	}

	Ok(())
}

/// List all available JSON-RPC methods from the connected node
async fn list_rpc_methods(quantus_client: &QuantusClient) -> crate::error::Result<()> {
	use jsonrpsee::core::client::ClientT;

	log_print!("🧭 JSON-RPC Methods exposed by node:");

	let response: serde_json::Value = quantus_client
		.rpc_client()
		.request::<serde_json::Value, [(); 0]>("rpc_methods", [])
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Failed to fetch rpc_methods: {e:?}"))
		})?;

	if let Some(methods) = response.get("methods").and_then(|v| v.as_array()) {
		for method in methods {
			if let Some(name) = method.as_str() {
				log_print!("\t{}", name);
			}
		}
		if let Some(version) = response.get("version").and_then(|v| v.as_u64()) {
			log_verbose!("RPC methods schema version: {}", version);
		}
	} else if let Some(array) = response.as_array() {
		for method in array {
			if let Some(name) = method.as_str() {
				log_print!("\t{}", name);
			}
		}
	} else {
		log_print!("   (no methods returned or unexpected format)");
		log_verbose!("rpc_methods raw response: {:?}", response);
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn props(value: serde_json::Value) -> serde_json::Map<String, Value> {
		value.as_object().expect("test properties must be an object").clone()
	}

	#[test]
	fn parse_token_info_accepts_valid_properties() {
		let info = parse_token_info_from_properties(&props(json!({
			"tokenSymbol": "QUAN",
			"tokenDecimals": 12,
			"ss58Format": 42,
		})))
		.expect("valid token properties must be accepted");
		assert_eq!(info.symbol, "QUAN");
		assert_eq!(info.decimals, 12);
		assert_eq!(info.ss58_format, Some(42));
	}

	#[test]
	fn parse_token_info_rejects_missing_token_decimals() {
		let err = parse_token_info_from_properties(&props(json!({
			"tokenSymbol": "QUAN",
		})))
		.unwrap_err();
		assert!(
			err.to_string().contains("tokenDecimals"),
			"expected missing tokenDecimals rejection, got: {err}"
		);
	}

	#[test]
	fn parse_token_info_rejects_out_of_range_token_decimals() {
		let err = parse_token_info_from_properties(&props(json!({
			"tokenSymbol": "QUAN",
			"tokenDecimals": MAX_SUPPORTED_TOKEN_DECIMALS + 1,
		})))
		.unwrap_err();
		assert!(
			err.to_string().contains("tokenDecimals"),
			"expected out-of-range tokenDecimals rejection, got: {err}"
		);
	}

	#[test]
	fn parse_token_info_rejects_empty_symbol() {
		let err = parse_token_info_from_properties(&props(json!({
			"tokenSymbol": "",
			"tokenDecimals": 12,
		})))
		.unwrap_err();
		assert!(
			err.to_string().contains("tokenSymbol"),
			"expected empty symbol rejection, got: {err}"
		);
	}

	#[test]
	fn parse_token_info_rejects_ss58_format_above_255() {
		let err = parse_token_info_from_properties(&props(json!({
			"tokenSymbol": "QUAN",
			"tokenDecimals": 12,
			"ss58Format": 256,
		})))
		.unwrap_err();
		assert!(
			err.to_string().contains("ss58Format"),
			"expected ss58Format>255 rejection, got: {err}"
		);
	}

	#[test]
	fn parse_token_info_allows_missing_ss58_format() {
		let info = parse_token_info_from_properties(&props(json!({
			"tokenSymbol": "QUAN",
			"tokenDecimals": 0,
		})))
		.expect("ss58Format is optional");
		assert_eq!(info.decimals, 0);
		assert_eq!(info.ss58_format, None);
	}
}
