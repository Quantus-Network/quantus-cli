use crate::{chain::client::QuantusClient, log_print, log_verbose};
use colored::Colorize;
use jsonrpsee::core::client::ClientT;
use sp_core::crypto::Ss58Codec;
use std::str::FromStr;

pub async fn handle_events_command(
	block: Option<u32>,
	block_hash: Option<String>,
	finalized: bool,
	pallet_filter: Option<String>,
	raw: bool,
	decode: bool,
	node_url: &str,
) -> crate::error::Result<()> {
	// Connect to the chain
	let quantus_client = QuantusClient::new(node_url).await?;

	// Determine which block to query based on parameters
	let (block_hash, block_number) = if let Some(block_num) = block {
		log_print!("📋 Querying events from block #{}", block_num);

		// Get block hash by number using RPC
		let hash: subxt::utils::H256 = quantus_client
			.rpc_client()
			.request::<subxt::utils::H256, [u32; 1]>("chain_getBlockHash", [block_num])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to get block hash for #{block_num}: {e:?}"
				))
			})?;
		(hash, block_num)
	} else if let Some(hash_str) = block_hash {
		log_print!("📋 Querying events from block hash: {}", hash_str);

		// Parse hash string
		let hash = subxt::utils::H256::from_str(&hash_str).map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Invalid block hash: {e}"))
		})?;

		// Get block number from hash
		let block_header: serde_json::Value = quantus_client
			.rpc_client()
			.request::<serde_json::Value, [String; 1]>("chain_getHeader", [hash_str.clone()])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to get block header for hash {hash_str}: {e:?}"
				))
			})?;

		let block_num = if let Some(block_number_str) = block_header["number"].as_str() {
			u64::from_str_radix(&block_number_str[2..], 16).map(|n| n as u32).unwrap_or(0)
		} else {
			0
		};

		(hash, block_num)
	} else if finalized {
		log_print!("📋 Querying events from finalized block");

		// Get finalized head
		let hash: subxt::utils::H256 = quantus_client
			.rpc_client()
			.request::<subxt::utils::H256, [(); 0]>("chain_getFinalizedHead", [])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to get finalized head: {e:?}"
				))
			})?;

		// Get block number from finalized head
		let block_header: serde_json::Value = quantus_client
			.rpc_client()
			.request::<serde_json::Value, [String; 1]>("chain_getHeader", [format!("0x{hash:x}")])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to get finalized block header: {e:?}"
				))
			})?;

		let block_num = if let Some(block_number_str) = block_header["number"].as_str() {
			u64::from_str_radix(&block_number_str[2..], 16).map(|n| n as u32).unwrap_or(0)
		} else {
			0
		};

		(hash, block_num)
	} else {
		// Use latest block (default)
		log_print!("📋 Querying events from latest block");

		let hash = quantus_client.get_latest_block().await?;

		// Get block number from latest block
		let block_header: serde_json::Value = quantus_client
			.rpc_client()
			.request::<serde_json::Value, [(); 0]>("chain_getHeader", [])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to get latest block header: {e:?}"
				))
			})?;

		let block_num = if let Some(block_number_str) = block_header["number"].as_str() {
			u64::from_str_radix(&block_number_str[2..], 16).map(|n| n as u32).unwrap_or(0)
		} else {
			0
		};

		(hash, block_num)
	};

	log_print!("🔮 Quantus CLI");
	log_print!("🎯 Found Block #{}", block_number);

	// Get events from the block
	let events = quantus_client.client().blocks().at(block_hash).await?.events().await?;

	log_print!("📋 Block Events:");

	let mut event_count = 0;
	let mut filtered_count = 0;

	// Iterate through all events
	for event in events.iter() {
		event_count += 1;

		let event = event.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Failed to decode event: {e:?}"))
		})?;

		// Apply pallet filter if specified
		if let Some(ref filter) = pallet_filter {
			if event.pallet_name() != filter {
				continue;
			}
		}

		filtered_count += 1;

		// Display event information
		log_print!(
			"  📌 {}.{}",
			event.pallet_name().bright_cyan(),
			event.variant_name().bright_yellow()
		);

		// Enhanced event decoding with details
		if !raw && decode {
			decode_event_details(&event)?;
		}

		// Show raw data if requested or in verbose mode
		if raw || crate::log::is_verbose() {
			log_verbose!("     📝 Raw event data: {:?}", event.field_bytes());
		}
	}

	// Summary
	log_print!("");
	if let Some(ref filter) = pallet_filter {
		log_print!(
			"📊 Summary: {} events total, {} events from {} pallet",
			event_count,
			filtered_count,
			filter.bright_cyan()
		);
	} else {
		log_print!("📊 Summary: {} events total", event_count);
	}

	if filtered_count == 0 && pallet_filter.is_some() {
		log_print!("💡 Tip: No events found for the specified pallet. Try without --pallet filter to see all events.");
	}

	log_print!("💡 Tip: Use --verbose for raw event data");
	log_print!("💡 Tip: Use --pallet <PALLET_NAME> to filter events by pallet");

	Ok(())
}

/// Decode and display detailed event information using typed events
fn decode_event_details<T: subxt::Config>(
	event: &subxt::events::EventDetails<T>,
) -> crate::error::Result<()> {
	// Use typed event decoding for all events
	if let Some(typed_message) = decode_event_typed(event) {
		log_print!("{}", typed_message);
	}

	Ok(())
}

fn decode_event_typed<T: subxt::Config>(event: &subxt::events::EventDetails<T>) -> Option<String> {
	// Get the typed event using SubXT's generated types
	let typed_event = event.as_root_event::<crate::chain::quantus_subxt::api::Event>().ok()?;

	// Format the event with improved AccountId32 display
	let formatted_event = format_event_with_ss58_addresses(&typed_event);

	// GENERIC DISPLAY: Show all events in a consistent, automatic format
	Some(format!("     📝 {}", formatted_event.bright_cyan()))
}

/// Format event string with SS58 addresses instead of raw AccountId32 bytes
fn format_event_with_ss58_addresses(event: &crate::chain::quantus_subxt::api::Event) -> String {
	let debug_str = format!("{event:?}");

	// Replace all AccountId32 patterns with SS58 addresses
	let mut result = debug_str.clone();

	// Find and replace all AccountId32 patterns
	let mut replacements = 0;
	while let Some(account_id) = extract_account_id_from_debug(&result) {
		let ss58_address = format_account_id(&account_id);
		let account_debug = format!("{account_id:?}");
		result = result.replace(&account_debug, &ss58_address);
		replacements += 1;
		if replacements > 10 {
			break;
		} // Prevent infinite loop
	}

	result
}

/// Extract AccountId32 from debug string format
fn extract_account_id_from_debug(debug_str: &str) -> Option<subxt::utils::AccountId32> {
	// Look for AccountId32 pattern in the debug string
	if let Some(start) = debug_str.find("AccountId32([") {
		if let Some(end) = debug_str[start..].find("])") {
			let bytes_str = &debug_str[start + 13..start + end]; // "AccountId32([" has 13 chars

			// Parse the bytes array
			let bytes: Vec<u8> = bytes_str
				.split(',')
				.map(|s| s.trim().parse::<u8>().ok())
				.collect::<Option<Vec<u8>>>()?;

			if bytes.len() == 32 {
				let mut account_bytes = [0u8; 32];
				account_bytes.copy_from_slice(&bytes);
				return Some(subxt::utils::AccountId32::from(account_bytes));
			}
		}
	}
	None
}

/// Convert AccountId32 to SS58 address for better readability
fn format_account_id(account_id: &subxt::utils::AccountId32) -> String {
	// Convert subxt::utils::AccountId32 to sp_core::AccountId32
	let bytes: [u8; 32] = account_id.0;
	let sp_account_id = sp_core::crypto::AccountId32::from(bytes);

	// Convert to SS58 format
	sp_account_id.to_ss58check()
}
