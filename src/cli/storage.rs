//! `quantus storage` subcommand - storage operations

use crate::{
	chain::{client::ChainConfig, quantus_subxt},
	cli::address_format::QuantusSS58,
	error::QuantusError,
	log_error, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use codec::{Decode, Encode};
use colored::Colorize;
use serde::Deserialize;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	twox_128,
};
use std::{collections::BTreeMap, str::FromStr};
use subxt::OnlineClient;

/// The `AccountData` struct, used in `AccountInfo`.
#[derive(Decode, Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct AccountData {
	pub free: u128,
	pub reserved: u128,
	pub frozen: u128,
	pub flags: u128,
}

/// The `AccountInfo` struct, reflecting the chain's state.
#[derive(Decode, Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct AccountInfo {
	pub nonce: u32,
	pub consumers: u32,
	pub providers: u32,
	pub sufficients: u32,
	pub data: AccountData,
}

/// Validate that a pallet exists in the chain metadata
fn validate_pallet_exists(
	client: &OnlineClient<ChainConfig>,
	pallet_name: &str,
) -> crate::error::Result<()> {
	let metadata = client.metadata();
	metadata.pallet_by_name(pallet_name).ok_or_else(|| {
		QuantusError::Generic(format!(
			"Pallet '{}' not found in chain metadata. Available pallets: {}",
			pallet_name,
			quantus_subxt::api::PALLETS.join(", ")
		))
	})?;
	Ok(())
}

/// Direct interaction with chain storage (Sudo required for set)
#[derive(Subcommand, Debug)]
pub enum StorageCommands {
	/// Get a storage value from a pallet.
	///
	/// This command constructs a storage key from the pallet and item names,
	/// fetches the raw value from the chain state, and prints it as a hex string.
	/// If --block is specified, queries storage at that specific block instead of latest.
	/// If no --key is provided, automatically counts all entries in the storage map.
	Get {
		/// The name of the pallet (e.g., "System").
		#[arg(long, required_unless_present = "storage_key")]
		pallet: Option<String>,

		/// The name of the storage item (e.g., "Account").
		#[arg(long, required_unless_present = "storage_key")]
		name: Option<String>,

		/// Block number to query at a specific state.
		#[arg(long)]
		block: Option<String>,

		/// Attempt to decode the value as a specific type (e.g., "u64", "accoundid",
		/// "accountinfo").
		#[arg(long)]
		decode_as: Option<String>,

		/// Storage key parameter (e.g., AccountId for System::Account)
		#[arg(long, conflicts_with = "storage_key")]
		key: Option<String>,

		/// Type of the key component (e.g., "accountid", "u64").
		#[arg(long, requires("key"))]
		key_type: Option<String>,

		/// Force counting all entries even when --key is provided (useful for debugging)
		#[arg(long, conflicts_with = "storage_key")]
		count: bool,

		/// The full, final, hex-encoded storage key, as returned by `iterate` etc
		#[arg(long, conflicts_with_all = &["pallet", "name", "key", "count"])]
		storage_key: Option<String>,
	},
	/// List all storage items in a pallet.
	///
	/// Shows all available storage items with their metadata.
	List {
		/// The name of the pallet (e.g., "System")
		#[arg(long)]
		pallet: String,

		/// Show only storage item names (no documentation)
		#[arg(long)]
		names_only: bool,
	},
	/// List all pallets that have storage items.
	///
	/// Shows all pallets with storage and optionally counts.
	ListPallets {
		/// Show counts of storage items per pallet
		#[arg(long)]
		with_counts: bool,
	},
	/// Show storage statistics and count information.
	///
	/// Displays statistics about storage usage.
	Stats {
		/// The name of the pallet (optional, shows all if not specified)
		#[arg(long)]
		pallet: Option<String>,

		/// Show detailed statistics
		#[arg(long)]
		detailed: bool,
	},
	/// Iterate through storage map entries.
	///
	/// Useful for exploring storage maps and their contents.
	Iterate {
		/// The name of the pallet (e.g., "System")
		#[arg(long)]
		pallet: String,

		/// The name of the storage item (e.g., "Account")
		#[arg(long)]
		name: String,

		/// Maximum number of entries to show (use 0 to just count)
		#[arg(long, default_value = "10")]
		limit: u32,

		/// Attempt to decode values as a specific type
		#[arg(long)]
		decode_as: Option<String>,

		/// Block number or hash to query (optional, uses latest)
		#[arg(long)]
		block: Option<String>,
	},

	/// Set a storage value on the chain.
	///
	/// This requires sudo privileges. It constructs a `system.set_storage` call
	/// and wraps it in a `sudo.sudo` extrinsic. The provided value should be
	/// a hex-encoded SCALE representation of the value.
	Set {
		/// The name of the pallet (e.g., "Scheduler")
		#[arg(long)]
		pallet: String,

		/// The name of the storage item (e.g., "LastProcessedTimestamp")
		#[arg(long)]
		name: String,

		/// The new value. Can be a plain string if --type is used, otherwise a hex string.
		#[arg(long)]
		value: String,

		/// The type of the value to be encoded (e.g., "u64", "moment", "accountid")
		#[arg(long)]
		r#type: Option<String>,

		/// The name of the wallet to sign the transaction with (must have sudo rights)
		#[arg(long)]
		wallet: String,

		/// The password for the wallet
		#[arg(long)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Get block hash from block number or parse existing hash
pub async fn resolve_block_hash(
	quantus_client: &crate::chain::client::QuantusClient,
	block_identifier: &str,
) -> crate::error::Result<subxt::utils::H256> {
	if block_identifier.starts_with("0x") {
		// It's already a hash, parse it
		subxt::utils::H256::from_str(block_identifier)
			.map_err(|e| QuantusError::Generic(format!("Invalid block hash format: {e}")))
	} else {
		// It's a block number, convert to hash
		let block_number = block_identifier.parse::<u32>().map_err(|e| {
			QuantusError::Generic(format!("Invalid block number '{block_identifier}': {e}"))
		})?;

		log_verbose!("🔍 Converting block number {} to hash...", block_number);

		use jsonrpsee::core::client::ClientT;
		let block_hash: subxt::utils::H256 = quantus_client
			.rpc_client()
			.request::<subxt::utils::H256, [u32; 1]>("chain_getBlockHash", [block_number])
			.await
			.map_err(|e| {
				QuantusError::NetworkError(format!(
					"Failed to fetch block hash for block {block_number}: {e:?}"
				))
			})?;

		log_verbose!("📦 Block {} hash: {:?}", block_number, block_hash);
		Ok(block_hash)
	}
}

/// Get raw storage value by key
pub async fn get_storage_raw(
	quantus_client: &crate::chain::client::QuantusClient,
	key: Vec<u8>,
) -> crate::error::Result<Option<Vec<u8>>> {
	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let result = storage_at.fetch_raw(key).await?;

	Ok(result)
}

/// Get raw storage value by key at specific block
pub async fn get_storage_raw_at_block(
	quantus_client: &crate::chain::client::QuantusClient,
	key: Vec<u8>,
	block_hash: subxt::utils::H256,
) -> crate::error::Result<Option<Vec<u8>>> {
	log_verbose!("🔍 Querying storage at block: {:?}", block_hash);

	let storage_at = quantus_client.client().storage().at(block_hash);

	let result = storage_at.fetch_raw(key).await?;

	Ok(result)
}

/// Set storage value using sudo (requires sudo privileges)
pub async fn set_storage_value(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	storage_key: Vec<u8>,
	value_bytes: Vec<u8>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	log_verbose!("✍️  Creating set_storage transaction...");

	// Create the System::set_storage call using RuntimeCall type alias
	let set_storage_call =
		quantus_subxt::api::Call::System(quantus_subxt::api::system::Call::set_storage {
			items: vec![(storage_key, value_bytes)],
		});

	// Wrap in Sudo::sudo call
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(set_storage_call);

	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		sudo_call,
		None,
		execution_mode,
	)
	.await?;

	log_verbose!("📋 Set storage transaction submitted: {:?}", tx_hash);

	Ok(tx_hash)
}

/// List all storage items in a pallet
pub async fn list_storage_items(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet_name: &str,
	names_only: bool,
) -> crate::error::Result<()> {
	log_print!("📋 Listing storage items for pallet: {}", pallet_name.bright_green());

	// Validate pallet exists
	validate_pallet_exists(quantus_client.client(), pallet_name)?;

	let metadata = quantus_client.client().metadata();
	let pallet = metadata.pallet_by_name(pallet_name).unwrap();

	if let Some(storage_metadata) = pallet.storage() {
		let entries = storage_metadata.entries();
		log_print!("Found {} storage items: \n", entries.len());

		for (index, entry) in entries.iter().enumerate() {
			log_print!(
				"{}. {}",
				(index + 1).to_string().bright_yellow(),
				entry.name().bright_cyan()
			);

			if !names_only {
				log_print!("   Type: {:?}", entry.entry_type());
				if !entry.docs().is_empty() {
					log_print!("   Docs: {}", entry.docs().join(" ").dimmed());
				}
				log_print!("");
			}
		}
	} else {
		log_print!("❌ Pallet '{}' has no storage items.", pallet_name.bright_red());
	}

	Ok(())
}

/// List all pallets with storage
pub async fn list_pallets_with_storage(
	quantus_client: &crate::chain::client::QuantusClient,
	with_counts: bool,
) -> crate::error::Result<()> {
	log_print!("🏛️  Listing all pallets with storage:");
	log_print!("");

	let metadata = quantus_client.client().metadata();
	let pallets: Vec<_> = metadata.pallets().collect();

	let mut storage_pallets = BTreeMap::new();

	for pallet in pallets {
		if let Some(storage_metadata) = pallet.storage() {
			let entry_count = storage_metadata.entries().len();
			storage_pallets.insert(pallet.name(), entry_count);
		}
	}

	if storage_pallets.is_empty() {
		log_print!("❌ No pallets with storage found.");
		return Ok(());
	}

	for (index, (pallet_name, count)) in storage_pallets.iter().enumerate() {
		if with_counts {
			log_print!(
				"{}. {} ({} items)",
				(index + 1).to_string().bright_yellow(),
				pallet_name.bright_green(),
				count.to_string().bright_blue()
			);
		} else {
			log_print!(
				"{}. {}",
				(index + 1).to_string().bright_yellow(),
				pallet_name.bright_green()
			);
		}
	}

	log_print!("");
	log_print!("Total: {} pallets with storage", storage_pallets.len().to_string().bright_green());

	Ok(())
}

/// Show storage statistics
pub async fn show_storage_stats(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet_name: Option<String>,
	detailed: bool,
) -> crate::error::Result<()> {
	log_print!("📊 Storage size statistics: \n");

	let metadata = quantus_client.client().metadata();

	if let Some(pallet) = pallet_name {
		// Show stats for specific pallet
		validate_pallet_exists(quantus_client.client(), &pallet)?;
		let pallet_meta = metadata.pallet_by_name(&pallet).unwrap();

		if let Some(storage_metadata) = pallet_meta.storage() {
			let entries = storage_metadata.entries();
			log_print!("Pallet: {}", pallet.bright_green());
			log_print!("Storage items: {}", entries.len().to_string().bright_blue());

			if detailed {
				log_print!("");
				log_print!("Items:");
				for (index, entry) in entries.iter().enumerate() {
					log_print!(
						"  {}. {} - {:?}",
						(index + 1).to_string().dimmed(),
						entry.name().bright_cyan(),
						entry.entry_type()
					);
				}
			}
		} else {
			log_print!("❌ Pallet '{}' has no storage items.", pallet.bright_red());
		}
	} else {
		// Show global stats
		let pallets: Vec<_> = metadata.pallets().collect();
		let mut total_storage_items = 0;
		let mut pallets_with_storage = 0;

		let mut pallet_stats = Vec::new();

		for pallet in pallets {
			if let Some(storage_metadata) = pallet.storage() {
				let entry_count = storage_metadata.entries().len();
				total_storage_items += entry_count;
				pallets_with_storage += 1;
				pallet_stats.push((pallet.name(), entry_count));
			}
		}

		log_print!("Total pallets: {}", metadata.pallets().len().to_string().bright_blue());
		log_print!("Pallets with storage: {}", pallets_with_storage.to_string().bright_green());
		log_print!("Total storage items: {}", total_storage_items.to_string().bright_yellow());

		if detailed && !pallet_stats.is_empty() {
			log_print!("");
			log_print!("Per-pallet breakdown:");

			// Sort by storage count (descending)
			pallet_stats.sort_by(|a, b| b.1.cmp(&a.1));

			for (pallet_name, count) in pallet_stats {
				log_print!(
					"  {} - {} items",
					pallet_name.bright_cyan(),
					count.to_string().bright_blue()
				);
			}
		}
	}

	Ok(())
}

/// Count storage entries using RPC calls with pagination
pub async fn count_storage_entries(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet_name: &str,
	storage_name: &str,
	block_hash: subxt::utils::H256,
) -> crate::error::Result<u32> {
	// Construct storage key prefix for the storage item
	let mut prefix = twox_128(pallet_name.as_bytes()).to_vec();
	prefix.extend(&twox_128(storage_name.as_bytes()));

	log_verbose!("🔑 Storage prefix for counting: 0x{}", hex::encode(&prefix));

	use jsonrpsee::core::client::ClientT;

	let block_hash_str = format!("{block_hash:#x}");
	let prefix_hex = format!("0x{}", hex::encode(&prefix));
	let page_size = 1000u32; // Max allowed per request
	let mut total_count = 0u32;
	let mut start_key: Option<String> = None;

	loop {
		// Use state_getKeysPaged RPC call to get keys with the prefix
		let keys: Vec<String> = quantus_client
			.rpc_client()
			.request::<Vec<String>, (String, u32, Option<String>, Option<String>)>(
				"state_getKeysPaged",
				(
					prefix_hex.clone(),           // prefix
					page_size,                    // count
					start_key.clone(),            // start_key for pagination
					Some(block_hash_str.clone()), // at block
				),
			)
			.await
			.map_err(|e| {
				QuantusError::NetworkError(format!(
					"Failed to fetch storage keys at block {block_hash:?}: {e:?}"
				))
			})?;

		let keys_count = keys.len() as u32;
		total_count += keys_count;

		log_verbose!("📊 Fetched {} keys (total: {})", keys_count, total_count);

		// If we got less than page_size keys, we're done
		if keys_count < page_size {
			break;
		}

		// Set start_key to the last key for next iteration
		start_key = keys.last().cloned();
		if start_key.is_none() {
			break;
		}
	}

	Ok(total_count)
}

/// Iterate through storage map entries with real RPC calls
pub async fn iterate_storage_entries(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet_name: &str,
	storage_name: &str,
	limit: u32,
	decode_as: Option<String>,
	block_identifier: Option<String>,
) -> crate::error::Result<()> {
	log_print!(
		"🔄 Iterating storage {}::{} (limit: {})",
		pallet_name.bright_green(),
		storage_name.bright_cyan(),
		limit.to_string().bright_yellow()
	);

	// Validate pallet exists
	validate_pallet_exists(quantus_client.client(), pallet_name)?;

	// Determine block hash to use
	let block_hash = if let Some(block_id) = block_identifier {
		resolve_block_hash(quantus_client, &block_id).await?
	} else {
		quantus_client.get_latest_block().await?
	};

	log_verbose!("📦 Using block: {:?}", block_hash);

	// Try to get storage metadata to show what type of storage this is
	let metadata = quantus_client.client().metadata();
	let pallet = metadata.pallet_by_name(pallet_name).unwrap();

	if let Some(storage_metadata) = pallet.storage() {
		if let Some(entry) = storage_metadata.entry_by_name(storage_name) {
			log_print!("📝 Storage type: {:?}", entry.entry_type());
			if !entry.docs().is_empty() {
				log_print!("📖 Docs: {}", entry.docs().join(" ").dimmed());
			}
		}
	}

	// Count total entries
	log_print!("🔢 Counting storage entries...");
	let total_count =
		count_storage_entries(quantus_client, pallet_name, storage_name, block_hash).await?;

	log_success!(
		"📊 Total entries in {}::{}: {}",
		pallet_name.bright_green(),
		storage_name.bright_cyan(),
		total_count.to_string().bright_yellow()
	);

	// If limit is 0, just show count
	if limit == 0 {
		return Ok(());
	}

	// Construct storage key prefix for the storage item
	let mut prefix = twox_128(pallet_name.as_bytes()).to_vec();
	prefix.extend(&twox_128(storage_name.as_bytes()));

	log_verbose!("🔑 Storage prefix: 0x{}", hex::encode(&prefix));

	// Use RPC to get keys with pagination
	use jsonrpsee::core::client::ClientT;

	let block_hash_str = format!("{block_hash:#x}");
	let keys: Vec<String> = quantus_client
		.rpc_client()
		.request::<Vec<String>, (String, u32, Option<String>, Option<String>)>(
			"state_getKeysPaged",
			(
				format!("0x{}", hex::encode(&prefix)),
				limit,                // limit entries
				None,                 // start_key
				Some(block_hash_str), // at block
			),
		)
		.await
		.map_err(|e| {
			QuantusError::NetworkError(format!(
				"Failed to fetch storage keys at block {block_hash:?}: {e:?}"
			))
		})?;

	if keys.is_empty() {
		log_print!("❌ No entries found.");
		return Ok(());
	}

	log_print!("📋 First {} entries:", keys.len().min(limit as usize));
	log_print!("");

	// Show first few keys and optionally their values
	for (index, key) in keys.iter().take(limit as usize).enumerate() {
		log_print!("{}. Key: {}", (index + 1).to_string().bright_yellow(), key.dimmed());

		// Optionally fetch and decode values (only for first few to avoid spam)
		if index < 3 && decode_as.is_some() {
			if let Ok(key_bytes) = hex::decode(key.strip_prefix("0x").unwrap_or(key)) {
				if let Ok(Some(value_bytes)) =
					get_storage_raw_at_block(quantus_client, key_bytes, block_hash).await
				{
					if let Some(ref decode_type) = decode_as {
						match decode_storage_value(&value_bytes, decode_type) {
							Ok(decoded_value) => {
								log_print!("   Value: {}", decoded_value.bright_green())
							},
							Err(_) => log_print!(
								"   Value: 0x{} (raw)",
								hex::encode(&value_bytes).dimmed()
							),
						}
					}
				}
			}
		}
	}

	if total_count > limit {
		log_print!("");
		log_print!(
			"... and {} more entries (use --limit 0 to just count)",
			(total_count - limit).to_string().bright_blue()
		);
	}

	Ok(())
}

/// Decode storage value based on type
fn decode_storage_value(value_bytes: &[u8], type_str: &str) -> crate::error::Result<String> {
	match type_str.to_lowercase().as_str() {
		"u32" => match u32::decode(&mut &value_bytes[..]) {
			Ok(decoded_value) => Ok(decoded_value.to_string()),
			Err(e) => Err(QuantusError::Generic(format!("Failed to decode as u32: {e}"))),
		},
		"u64" | "moment" => match u64::decode(&mut &value_bytes[..]) {
			Ok(decoded_value) => Ok(decoded_value.to_string()),
			Err(e) => Err(QuantusError::Generic(format!("Failed to decode as u64: {e}"))),
		},
		"u128" | "balance" => match u128::decode(&mut &value_bytes[..]) {
			Ok(decoded_value) => Ok(decoded_value.to_string()),
			Err(e) => Err(QuantusError::Generic(format!("Failed to decode as u128: {e}"))),
		},
		"accountid" | "accountid32" => match AccountId32::decode(&mut &value_bytes[..]) {
			Ok(account_id) => Ok(account_id.to_quantus_ss58()),
			Err(e) => Err(QuantusError::Generic(format!("Failed to decode as AccountId32: {e}"))),
		},
		"accountinfo" => match AccountInfo::decode(&mut &value_bytes[..]) {
			Ok(account_info) => Ok(format!("{account_info:#?}")),
			Err(e) => Err(QuantusError::Generic(format!("Failed to decode as AccountInfo: {e}"))),
		},
		_ => Err(QuantusError::Generic(format!(
			"Unsupported type for decoding: {type_str}. Supported types: u32, u64, moment, u128, balance, accountid, accountinfo"
		))),
	}
}

/// Get storage by a full, hex-encoded storage key.
async fn get_storage_by_storage_key(
	quantus_client: &crate::chain::client::QuantusClient,
	storage_key: String,
	block: Option<String>,
	decode_as: Option<String>,
) -> crate::error::Result<()> {
	log_print!("🗄️  Storage");

	let encoded_storage_key = encode_storage_key(&storage_key, "raw")?;

	let result = if let Some(block_id) = block {
		let block_hash = resolve_block_hash(quantus_client, &block_id).await?;
		get_storage_raw_at_block(quantus_client, encoded_storage_key, block_hash).await?
	} else {
		get_storage_raw(quantus_client, encoded_storage_key).await?
	};

	if let Some(value_bytes) = result {
		log_success!("Raw Value: 0x{}", hex::encode(&value_bytes).bright_yellow());
		if let Some(type_str) = decode_as {
			log_print!("Attempting to decode as {}...", type_str.bright_cyan());
			match decode_storage_value(&value_bytes, &type_str) {
				Ok(decoded_value) => {
					log_success!("Decoded Value: {}", decoded_value.bright_green())
				},
				Err(e) => log_error!("{}", e),
			}
		}
	} else {
		log_print!("{}", "No value found at this storage location.".dimmed());
	}

	Ok(())
}

/// Get storage by providing its pallet, name, and optional key component.
async fn get_storage_by_parts(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet: String,
	name: String,
	key: Option<String>,
	key_type: Option<String>,
	block: Option<String>,
	decode_as: Option<String>,
	count: bool,
) -> crate::error::Result<()> {
	if let Some(block_value) = &block {
		log_print!(
			"🔎 Getting storage for {}::{} at block {}",
			pallet.bright_green(),
			name.bright_cyan(),
			block_value.bright_yellow()
		);
	} else {
		log_print!(
			"🔎 Getting storage for {}::{} (latest block)",
			pallet.bright_green(),
			name.bright_cyan()
		);
	}

	if let Some(key_value) = &key {
		log_print!("🔑 With key: {}", key_value.bright_yellow());
	}

	validate_pallet_exists(quantus_client.client(), &pallet)?;

	let block_hash = if let Some(block_id) = &block {
		resolve_block_hash(quantus_client, block_id).await?
	} else {
		quantus_client.get_latest_block().await?
	};

	let entry_count = count_storage_entries(quantus_client, &pallet, &name, block_hash).await?;
	let is_storage_value = entry_count == 1;

	let should_count = count || (key.is_none() && !is_storage_value);

	if should_count {
		log_print!("🔢 Counting all entries in {}::{}", pallet.bright_green(), name.bright_cyan());

		let block_display = if let Some(ref block_id) = block {
			format!(" at block {}", block_id.bright_yellow())
		} else {
			" (latest)".to_string()
		};

		log_success!(
			"👥 Total entries{}: {}",
			block_display,
			entry_count.to_string().bright_green().bold()
		);
	} else {
		let mut storage_key = twox_128(pallet.as_bytes()).to_vec();
		storage_key.extend(&twox_128(name.as_bytes()));

		if let Some(key_value) = &key {
			if let Some(key_type_str) = &key_type {
				let key_bytes = encode_storage_key(key_value, key_type_str)?;
				storage_key.extend(key_bytes);
			} else {
				log_error!("Key type (--key-type) is required when using --key parameter");
				return Ok(());
			}
		} else if !is_storage_value {
			log_print!("🔢 This is a storage map with {} entries. Use --key to get a specific value or omit --key to count all entries.", entry_count);
			return Ok(());
		}

		let result = get_storage_raw_at_block(quantus_client, storage_key, block_hash).await?;

		if let Some(value_bytes) = result {
			log_success!("Raw Value: 0x{}", hex::encode(&value_bytes).bright_yellow());

			if let Some(type_str) = decode_as {
				log_print!("Attempting to decode as {}...", type_str.bright_cyan());
				match decode_storage_value(&value_bytes, &type_str) {
					Ok(decoded_value) => {
						log_success!("Decoded Value: {}", decoded_value.bright_green())
					},
					Err(e) => log_error!("{}", e),
				}
			}
		} else {
			log_print!("{}", "No value found at this storage location.".dimmed());
		}
	}

	Ok(())
}

/// Handle storage subxt commands
pub async fn handle_storage_command(
	command: StorageCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("🗄️  Storage");

	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		StorageCommands::Get {
			pallet,
			name,
			block,
			decode_as,
			key,
			key_type,
			count,
			storage_key,
		} => {
			if let Some(s_key) = storage_key {
				get_storage_by_storage_key(&quantus_client, s_key, block, decode_as).await
			} else {
				// Clap ensures that pallet and name are present if `storage_key` is None
				get_storage_by_parts(
					&quantus_client,
					pallet.unwrap(),
					name.unwrap(),
					key,
					key_type,
					block,
					decode_as,
					count,
				)
				.await
			}
		},
		StorageCommands::List { pallet, names_only } =>
			list_storage_items(&quantus_client, &pallet, names_only).await,
		StorageCommands::ListPallets { with_counts } =>
			list_pallets_with_storage(&quantus_client, with_counts).await,
		StorageCommands::Stats { pallet, detailed } =>
			show_storage_stats(&quantus_client, pallet, detailed).await,
		StorageCommands::Iterate { pallet, name, limit, decode_as, block } =>
			iterate_storage_entries(&quantus_client, &pallet, &name, limit, decode_as, block).await,

		StorageCommands::Set { pallet, name, value, wallet, password, password_file, r#type } => {
			log_print!("✍️  Setting storage for {}::{}", pallet.bright_green(), name.bright_cyan());
			log_print!("\n{}", "🛑 This is a SUDO operation!".bright_red().bold());

			// Validate pallet exists
			validate_pallet_exists(quantus_client.client(), &pallet)?;

			// 1. Load wallet
			let keypair =
				crate::wallet::load_keypair_from_wallet(&wallet, password, password_file)?;
			log_verbose!("🔐 Using wallet: {}", wallet.bright_green());

			// 2. Encode the value based on the --type flag
			let value_bytes = match r#type.as_deref() {
				Some("u64") | Some("moment") => value
					.parse::<u64>()
					.map_err(|e| QuantusError::Generic(format!("Invalid u64 value: {e}")))?
					.encode(),
				Some("u128") | Some("balance") => value
					.parse::<u128>()
					.map_err(|e| QuantusError::Generic(format!("Invalid u128 value: {e}")))?
					.encode(),
				Some("accountid") | Some("accountid32") => AccountId32::from_ss58check(&value)
					.map_err(|e| QuantusError::Generic(format!("Invalid AccountId value: {e:?}")))?
					.encode(),
				None => {
					// Default to hex decoding if no type is specified
					// Try to parse as H256 first, then fall back to hex decode
					if value.starts_with("0x") && value.len() == 66 {
						// 0x + 64 hex chars = 66 (32 bytes)
						// Try to parse as H256
						let h256_value = subxt::utils::H256::from_str(&value).map_err(|e| {
							QuantusError::Generic(format!("Invalid H256 value: {e}"))
						})?;
						h256_value.0.to_vec()
					} else {
						// Fall back to hex decode for other hex values
						let value_hex = value.strip_prefix("0x").unwrap_or(&value);
						hex::decode(value_hex)
							.map_err(|e| QuantusError::Generic(format!("Invalid hex value: {e}")))?
					}
				},
				Some(unsupported) =>
					return Err(QuantusError::Generic(format!(
						"Unsupported type for --type: {unsupported}"
					))),
			};

			log_verbose!("Encoded value bytes: 0x{}", hex::encode(&value_bytes).dimmed());

			// 3. Construct the storage key
			let storage_key = {
				let mut key = twox_128(pallet.as_bytes()).to_vec();
				key.extend(&twox_128(name.as_bytes()));
				key
			};

			// 4. Submit the set storage transaction
			let tx_hash = set_storage_value(
				&quantus_client,
				&keypair,
				storage_key,
				value_bytes,
				execution_mode,
			)
			.await?;

			log_print!(
				"✅ {} Set storage transaction submitted! Hash: {:?}",
				"SUCCESS".bright_green().bold(),
				tx_hash
			);

			Ok(())
		},
	}
}

/// Encode storage key parameter based on type
fn encode_storage_key(key_value: &str, key_type: &str) -> crate::error::Result<Vec<u8>> {
	use codec::Encode;
	use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

	match key_type.to_lowercase().as_str() {
		"accountid" | "accountid32" => {
			let account_id = SpAccountId32::from_ss58check(key_value).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid AccountId: {e:?}"))
			})?;
			Ok(account_id.encode())
		},
		"u64" => {
			let value = key_value
				.parse::<u64>()
				.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid u64: {e}")))?;
			Ok(value.encode())
		},
		"u128" => {
			let value = key_value
				.parse::<u128>()
				.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid u128: {e}")))?;
			Ok(value.encode())
		},
		"u32" => {
			let value = key_value
				.parse::<u32>()
				.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid u32: {e}")))?;
			Ok(value.encode())
		},
		"hex" | "raw" => {
			// For hex/raw keys, decode the hex string directly
			let value_hex = key_value.strip_prefix("0x").unwrap_or(key_value);
			hex::decode(value_hex)
				.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid hex value: {e}")))
		},
		_ => Err(crate::error::QuantusError::Generic(format!(
			"Unsupported key type: {key_type}. Supported types: accountid, u64, u128, u32, hex, raw"
		))),
	}
}
