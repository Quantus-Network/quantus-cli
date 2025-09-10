//! `quantus block` subcommand - detailed block analysis
use crate::{
	chain::client::QuantusClient, cli::storage, error::QuantusError, log_error, log_print,
	log_success,
};
use clap::Subcommand;
use colored::Colorize;
use poseidon_resonance::PoseidonHasher;
use sp_core::crypto::Ss58Codec;
use std::str::FromStr;
use subxt::events::EventDetails;

/// Block management and analysis commands
#[derive(Subcommand, Debug)]
pub enum BlockCommands {
	/// Detailed block analysis
	Analyze {
		/// Block number to analyze
		#[arg(long)]
		number: Option<u32>,

		/// Block hash to analyze (alternative to number)
		#[arg(long)]
		hash: Option<String>,

		/// Use latest block if no number/hash specified
		#[arg(long)]
		latest: bool,

		/// Show storage statistics for this block
		#[arg(long)]
		storage: bool,

		/// Show detailed extrinsic information
		#[arg(long)]
		extrinsics: bool,

		/// Show detailed information for ALL extrinsics (not just first 3)
		#[arg(long)]
		extrinsics_details: bool,

		/// Show events from this block
		#[arg(long)]
		events: bool,

		/// Show all available information
		#[arg(long)]
		all: bool,
	},

	/// List blocks in range with summary info
	List {
		/// Start block number
		#[arg(long)]
		start: u32,
		/// End block number
		#[arg(long)]
		end: u32,
		/// Block step (default: 1)
		#[arg(long)]
		step: Option<u32>,
	},
}

/// Handle block commands
pub async fn handle_block_command(
	command: BlockCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	match command {
		BlockCommands::Analyze {
			number,
			hash,
			latest,
			storage,
			extrinsics,
			extrinsics_details,
			events,
			all,
		} =>
			handle_block_analyze_command(
				number,
				hash,
				latest,
				storage,
				extrinsics,
				extrinsics_details,
				events,
				all,
				node_url,
			)
			.await,
		BlockCommands::List { start, end, step } =>
			handle_block_list_command(start, end, step, node_url).await,
	}
}

/// Handle detailed block analysis
async fn handle_block_analyze_command(
	number: Option<u32>,
	hash: Option<String>,
	latest: bool,
	storage: bool,
	extrinsics: bool,
	extrinsics_details: bool,
	events: bool,
	all: bool,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("🔍 Block Analysis");

	let quantus_client = QuantusClient::new(node_url).await?;

	// Determine which block to analyze
	let (block_number, block_hash) = if let Some(num) = number {
		// Convert number to hash using our storage function
		let hash = storage::resolve_block_hash(&quantus_client, &num.to_string()).await?;
		(num, hash)
	} else if let Some(h) = hash {
		// Parse hash and get block number from storage
		let parsed_hash = storage::resolve_block_hash(&quantus_client, &h).await?;
		// Get block number by querying System::Number at that block
		let storage_at = quantus_client.client().storage().at(parsed_hash);
		let number_addr = crate::chain::quantus_subxt::api::storage().system().number();
		let block_num = storage_at.fetch_or_default(&number_addr).await.map_err(|e| {
			QuantusError::NetworkError(format!("Failed to get block number: {e:?}"))
		})?;
		(block_num, parsed_hash)
	} else if latest {
		// Use latest block
		let hash = quantus_client.get_latest_block().await?;
		let storage_at = quantus_client.client().storage().at(hash);
		let number_addr = crate::chain::quantus_subxt::api::storage().system().number();
		let block_num = storage_at.fetch_or_default(&number_addr).await.map_err(|e| {
			QuantusError::NetworkError(format!("Failed to get latest block number: {e:?}"))
		})?;
		(block_num, hash)
	} else {
		return Err(QuantusError::Generic("Must specify --number, --hash, or --latest".to_string()));
	};

	log_print!("📦 Block #{} - {:#x}", block_number, block_hash);
	log_print!("");

	// Get basic block information using RPC
	use jsonrpsee::core::client::ClientT;
	let block_data: serde_json::Value = quantus_client
		.rpc_client()
		.request("chain_getBlock", [format!("{block_hash:#x}")])
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Failed to get block data: {e:?}")))?;

	// Show basic block header information
	show_block_header(&block_data)?;

	// Show storage statistics if requested or --all
	if storage || all {
		show_storage_statistics(&quantus_client, block_hash).await?;
	}

	// Show events if requested or --all
	if events || all {
		show_block_events(block_number, node_url).await?;
	}

	// Show extrinsic details if requested or --all
	if extrinsics || all {
		show_extrinsic_details(&quantus_client, block_hash, &block_data).await?;
	}

	// Show detailed information for ALL extrinsics if requested (only when explicitly requested)
	if extrinsics_details {
		show_all_extrinsic_details(&quantus_client, block_hash, &block_data).await?;
	}

	log_success!("✅ Block analysis complete!");
	log_print!("💡 Use --all to see all information, or combine --storage --events --extrinsics --extrinsics-details");

	Ok(())
}

/// Show block header information
fn show_block_header(block_data: &serde_json::Value) -> crate::error::Result<()> {
	if let Some(block) = block_data.get("block") {
		if let Some(header) = block.get("header") {
			log_print!("📋 Block Header:");
			if let Some(parent_hash) = header.get("parentHash") {
				log_print!(
					"   • Parent Hash: {}",
					parent_hash.as_str().unwrap_or("unknown").bright_blue()
				);
			}
			if let Some(state_root) = header.get("stateRoot") {
				log_print!(
					"   • State Root: {}",
					state_root.as_str().unwrap_or("unknown").bright_green()
				);
			}
			if let Some(extrinsics_root) = header.get("extrinsicsRoot") {
				log_print!(
					"   • Extrinsics Root: {}",
					extrinsics_root.as_str().unwrap_or("unknown").bright_yellow()
				);
			}

			// Try to get timestamp from header if available
			if let Some(timestamp) = header.get("timestamp") {
				if let Some(timestamp_num) = timestamp.as_u64() {
					// Convert milliseconds to human readable time
					let timestamp_secs = timestamp_num / 1000;
					let datetime = chrono::DateTime::from_timestamp(timestamp_secs as i64, 0);
					if let Some(dt) = datetime {
						log_print!(
							"   • Timestamp: {} ({})",
							dt.format("%Y-%m-%d %H:%M:%S UTC").to_string().bright_cyan(),
							timestamp_num.to_string().bright_yellow()
						);
					}
				}
			}
		}

		if let Some(extrinsics) = block.get("extrinsics") {
			if let Some(extrinsics_array) = extrinsics.as_array() {
				log_print!(
					"   • Extrinsics Count: {}",
					extrinsics_array.len().to_string().bright_magenta()
				);

				// Calculate approximate block size
				let block_size = serde_json::to_string(block_data).unwrap_or_default().len();
				log_print!("   • Approximate Size: {} bytes", block_size.to_string().bright_cyan());
			}
		}
	}

	log_print!("");
	Ok(())
}

/// Show storage statistics for the block
async fn show_storage_statistics(
	quantus_client: &QuantusClient,
	block_hash: subxt::utils::H256,
) -> crate::error::Result<()> {
	log_print!("💾 Storage Statistics:");

	// Account count
	let account_count =
		storage::count_storage_entries(quantus_client, "System", "Account", block_hash).await?;
	log_print!("   • Accounts: {}", account_count.to_string().bright_green());

	// BlockHash count
	let blockhash_count =
		storage::count_storage_entries(quantus_client, "System", "BlockHash", block_hash).await?;
	log_print!("   • Block Hashes: {}", blockhash_count.to_string().bright_blue());

	// Event count
	let storage_at = quantus_client.client().storage().at(block_hash);
	let event_count_addr = crate::chain::quantus_subxt::api::storage().system().event_count();
	let event_count = storage_at
		.fetch_or_default(&event_count_addr)
		.await
		.map_err(|e| {
			log_error!("Failed to get event count: {:?}", e);
			e
		})
		.unwrap_or_default();
	log_print!("   • Events: {}", event_count.to_string().bright_yellow());

	// Try to get timestamp from Timestamp::Now storage
	let timestamp_addr = crate::chain::quantus_subxt::api::storage().timestamp().now();
	match storage_at.fetch(&timestamp_addr).await {
		Ok(Some(timestamp)) => {
			// Convert milliseconds to human readable time
			let timestamp_secs = timestamp / 1000;
			let datetime = chrono::DateTime::from_timestamp(timestamp_secs as i64, 0);
			if let Some(dt) = datetime {
				log_print!(
					"   • Block Time: {} ({})",
					dt.format("%Y-%m-%d %H:%M:%S UTC").to_string().bright_green(),
					timestamp.to_string().bright_yellow()
				);
			}
		},
		Ok(None) => {
			log_print!("   • Block Time: {}", "no timestamp".bright_yellow());
		},
		Err(_) => {
			log_print!("   • Block Time: {}", "unknown".bright_yellow());
		},
	}

	log_print!("");
	Ok(())
}

/// Show events from the block
async fn show_block_events(block_number: u32, node_url: &str) -> crate::error::Result<()> {
	log_print!("📋 Events:");

	// Use the existing events command internally
	match crate::cli::events::handle_events_command(
		Some(block_number),
		None,
		false,
		None,
		false,
		true,
		node_url,
	)
	.await
	{
		Ok(_) => {
			// Events were already printed by the events command
		},
		Err(e) => log_error!("Failed to get events: {}", e),
	}

	log_print!("");
	Ok(())
}

/// Show extrinsic details
async fn show_extrinsic_details(
	quantus_client: &QuantusClient,
	block_hash: subxt::utils::H256,
	block_data: &serde_json::Value,
) -> crate::error::Result<()> {
	if let Some(block) = block_data.get("block") {
		if let Some(extrinsics) = block.get("extrinsics") {
			if let Some(extrinsics_array) = extrinsics.as_array() {
				log_print!("🔧 Extrinsics Details:");
				log_print!(
					"   • Total Count: {}",
					extrinsics_array.len().to_string().bright_green()
				);

				// Calculate total size of all extrinsics in actual bytes
				let mut total_size_bytes = 0;
				let mut total_size_chars = 0;
				for extrinsic in extrinsics_array.iter() {
					if let Some(ext_str) = extrinsic.as_str() {
						total_size_chars += ext_str.len();
						// Convert hex string to actual bytes
						if let Some(hex_part) = ext_str.strip_prefix("0x") {
							// Remove "0x" prefix and convert hex to bytes
							if hex_part.len() % 2 == 0 {
								total_size_bytes += hex_part.len() / 2;
							} else {
								total_size_bytes += hex_part.len().div_ceil(2);
							}
						} else {
							// If not hex, assume it's already in bytes
							total_size_bytes += ext_str.len();
						}
					}
				}
				log_print!(
					"   • Total Size: {:.1} KB ({} chars)",
					total_size_bytes as f64 / 1024.0,
					total_size_chars.to_string().bright_cyan()
				);

				// Pre-fetch events and group by extrinsic index
				let events =
					quantus_client.client().blocks().at(block_hash).await?.events().await?;
				let mut events_by_ex_idx: std::collections::BTreeMap<usize, Vec<String>> =
					std::collections::BTreeMap::new();
				for ev in events.iter().flatten() {
					if let subxt::events::Phase::ApplyExtrinsic(ex_idx) = ev.phase() {
						let msg = format_event_details(&ev);
						events_by_ex_idx.entry(ex_idx as usize).or_default().push(msg);
					}
				}

				// Get extrinsics via subxt for detailed analysis
				let block = quantus_client.client().blocks().at(block_hash).await?;
				let extrinsics = block.extrinsics().await?;

				// Get parent block hash for nonce calculation
				let parent_hash = {
					use jsonrpsee::core::client::ClientT;
					let header: serde_json::Value = quantus_client
						.rpc_client()
						.request("chain_getHeader", [format!("{block_hash:#x}")])
						.await
						.map_err(|e| {
							crate::error::QuantusError::NetworkError(format!(
								"Failed to get header: {e:?}"
							))
						})?;
					let parent_hash_str = header["parentHash"].as_str().ok_or_else(|| {
						crate::error::QuantusError::NetworkError(
							"Missing parentHash in header".to_string(),
						)
					})?;
					subxt::utils::H256::from_str(parent_hash_str).map_err(|e| {
						crate::error::QuantusError::NetworkError(format!(
							"Invalid parent hash: {e:?}"
						))
					})?
				};

				// Track nonce per signer in this block
				let mut signer_nonce_tracker: std::collections::HashMap<String, u32> =
					std::collections::HashMap::new();

				// Show first 3 extrinsics with details
				for (index, extrinsic) in extrinsics_array.iter().take(3).enumerate() {
					let ext_str = extrinsic.as_str().unwrap_or("unknown");
					let (ext_size_bytes, preview, hash_hex) = summarize_extrinsic(ext_str);
					log_print!(
						"   {}. Hash: {} | Size: {} bytes | Data: {}...",
						(index + 1).to_string().bright_yellow(),
						hash_hex.bright_blue(),
						ext_size_bytes.to_string().bright_cyan(),
						preview.bright_magenta()
					);

					// Extract signer and transaction details
					if let Some(ext_details) = extrinsics.iter().nth(index) {
						if ext_details.is_signed() {
							// Extract signer and tip from events
							let mut signer_from_events: Option<String> = None;
							let mut tip_from_events: Option<u128> = None;

							if let Some(event_list) = events_by_ex_idx.get(&index) {
								for event_line in event_list {
									if event_line.contains("TransactionFeePaid") {
										// Extract signer (who field)
										if let Some(who_start) = event_line.find("who: ") {
											if let Some(who_end) =
												event_line[who_start + 5..].find(',')
											{
												let signer = &event_line
													[who_start + 5..who_start + 5 + who_end];
												signer_from_events = Some(signer.to_string());
											}
										}
										// Extract tip
										if let Some(tip_start) = event_line.find("tip: ") {
											if let Some(tip_end) =
												event_line[tip_start + 5..].find(' ')
											{
												let tip_str = &event_line
													[tip_start + 5..tip_start + 5 + tip_end];
												if let Ok(tip_val) = tip_str.parse::<u128>() {
													tip_from_events = Some(tip_val);
												}
											}
										}
									}
								}
							}

							if let Some(ref signer) = signer_from_events {
								log_print!("       • Signer: {}", signer);

								// Calculate nonce from parent block + track per signer
								if !signer_nonce_tracker.contains_key(signer) {
									let nonce = get_account_nonce_at_block(
										quantus_client,
										signer,
										parent_hash,
									)
									.await
									.unwrap_or(0);
									signer_nonce_tracker.insert(signer.clone(), nonce);
								}

								// Get current nonce for this signer (increments for each tx from
								// same signer)
								let current_nonce = *signer_nonce_tracker.get(signer).unwrap();
								log_print!("       • Nonce: {}", current_nonce);

								// Increment for next transaction from this signer
								signer_nonce_tracker.insert(signer.clone(), current_nonce + 1);
							}

							if let Some(tip) = tip_from_events {
								// Format tip nicely
								let tip_hei = tip as f64 / 1_000_000_000_000.0;
								log_print!("       • Tip: {:.6} HEI", tip_hei);
							}
						} else {
							log_print!("       • Unsigned extrinsic");
						}
					}

					// Related events (if any)
					if let Some(list) = events_by_ex_idx.get(&index) {
						for line in list {
							log_print!("       ↪ {}", line);
						}
					}
				}

				if extrinsics_array.len() > 3 {
					log_print!(
						"   ... and {} more extrinsics",
						(extrinsics_array.len() - 3).to_string().bright_blue()
					);
				}
			}
		}
	}
	log_print!("");
	Ok(())
}

/// Show detailed information for ALL extrinsics
async fn show_all_extrinsic_details(
	quantus_client: &QuantusClient,
	block_hash: subxt::utils::H256,
	block_data: &serde_json::Value,
) -> crate::error::Result<()> {
	if let Some(block) = block_data.get("block") {
		if let Some(extrinsics) = block.get("extrinsics") {
			if let Some(extrinsics_array) = extrinsics.as_array() {
				log_print!("🔧 ALL Extrinsics Details:");
				log_print!(
					"   • Total Count: {}",
					extrinsics_array.len().to_string().bright_green()
				);

				// Calculate total size of all extrinsics in actual bytes
				let mut total_size_bytes = 0;
				let mut total_size_chars = 0;
				for extrinsic in extrinsics_array.iter() {
					if let Some(ext_str) = extrinsic.as_str() {
						total_size_chars += ext_str.len();
						// Convert hex string to actual bytes
						if let Some(hex_part) = ext_str.strip_prefix("0x") {
							// Remove "0x" prefix and convert hex to bytes
							if hex_part.len() % 2 == 0 {
								total_size_bytes += hex_part.len() / 2;
							} else {
								total_size_bytes += hex_part.len().div_ceil(2);
							}
						} else {
							// If not hex, assume it's already in bytes
							total_size_bytes += ext_str.len();
						}
					}
				}
				log_print!(
					"   • Total Size: {:.1} KB ({} chars)",
					total_size_bytes as f64 / 1024.0,
					total_size_chars.to_string().bright_cyan()
				);

				// Pre-fetch events and group by extrinsic index
				let events =
					quantus_client.client().blocks().at(block_hash).await?.events().await?;
				let mut events_by_ex_idx: std::collections::BTreeMap<usize, Vec<String>> =
					std::collections::BTreeMap::new();
				for ev in events.iter().flatten() {
					if let subxt::events::Phase::ApplyExtrinsic(ex_idx) = ev.phase() {
						let msg = format_event_details(&ev);
						events_by_ex_idx.entry(ex_idx as usize).or_default().push(msg);
					}
				}

				// Get extrinsics via subxt for detailed analysis
				let block = quantus_client.client().blocks().at(block_hash).await?;
				let extrinsics = block.extrinsics().await?;

				// Get parent block hash for nonce calculation
				let parent_hash = {
					use jsonrpsee::core::client::ClientT;
					let header: serde_json::Value = quantus_client
						.rpc_client()
						.request("chain_getHeader", [format!("{block_hash:#x}")])
						.await
						.map_err(|e| {
							crate::error::QuantusError::NetworkError(format!(
								"Failed to get header: {e:?}"
							))
						})?;
					let parent_hash_str = header["parentHash"].as_str().ok_or_else(|| {
						crate::error::QuantusError::NetworkError(
							"Missing parentHash in header".to_string(),
						)
					})?;
					subxt::utils::H256::from_str(parent_hash_str).map_err(|e| {
						crate::error::QuantusError::NetworkError(format!(
							"Invalid parent hash: {e:?}"
						))
					})?
				};

				// Track nonce per signer in this block
				let mut signer_nonce_tracker: std::collections::HashMap<String, u32> =
					std::collections::HashMap::new();

				// Show all extrinsics with details
				for (index, extrinsic) in extrinsics_array.iter().enumerate() {
					let ext_str = extrinsic.as_str().unwrap_or("unknown");
					let (ext_size_bytes, preview, hash_hex) = summarize_extrinsic(ext_str);
					log_print!(
						"   {}. Hash: {} | Size: {} bytes | Data: {}...",
						(index + 1).to_string().bright_yellow(),
						hash_hex.bright_blue(),
						ext_size_bytes.to_string().bright_cyan(),
						preview.bright_magenta()
					);

					// Extract signer and transaction details
					if let Some(ext_details) = extrinsics.iter().nth(index) {
						if ext_details.is_signed() {
							// Extract signer and tip from events
							let mut signer_from_events: Option<String> = None;
							let mut tip_from_events: Option<u128> = None;

							if let Some(event_list) = events_by_ex_idx.get(&index) {
								for event_line in event_list {
									if event_line.contains("TransactionFeePaid") {
										// Extract signer (who field)
										if let Some(who_start) = event_line.find("who: ") {
											if let Some(who_end) =
												event_line[who_start + 5..].find(',')
											{
												let signer = &event_line
													[who_start + 5..who_start + 5 + who_end];
												signer_from_events = Some(signer.to_string());
											}
										}
										// Extract tip
										if let Some(tip_start) = event_line.find("tip: ") {
											if let Some(tip_end) =
												event_line[tip_start + 5..].find(' ')
											{
												let tip_str = &event_line
													[tip_start + 5..tip_start + 5 + tip_end];
												if let Ok(tip_val) = tip_str.parse::<u128>() {
													tip_from_events = Some(tip_val);
												}
											}
										}
									}
								}
							}

							if let Some(ref signer) = signer_from_events {
								log_print!("       • Signer: {}", signer);

								// Calculate nonce from parent block + track per signer
								if !signer_nonce_tracker.contains_key(signer) {
									let nonce = get_account_nonce_at_block(
										quantus_client,
										signer,
										parent_hash,
									)
									.await
									.unwrap_or(0);
									signer_nonce_tracker.insert(signer.clone(), nonce);
								}

								// Get current nonce for this signer (increments for each tx from
								// same signer)
								let current_nonce = *signer_nonce_tracker.get(signer).unwrap();
								log_print!("       • Nonce: {}", current_nonce);

								// Increment for next transaction from this signer
								signer_nonce_tracker.insert(signer.clone(), current_nonce + 1);
							}

							if let Some(tip) = tip_from_events {
								// Format tip nicely
								let tip_hei = tip as f64 / 1_000_000_000_000.0;
								log_print!("       • Tip: {:.6} HEI", tip_hei);
							}
						} else {
							log_print!("       • Unsigned extrinsic");
						}
					}

					// Related events (if any)
					if let Some(list) = events_by_ex_idx.get(&index) {
						for line in list {
							log_print!("       ↪ {}", line);
						}
					}
				}
			}
		}
	}
	log_print!("");
	Ok(())
}

/// Compute summary info for an extrinsic hex string: (size_bytes, preview, hash_hex)
fn summarize_extrinsic(ext_hex: &str) -> (usize, String, String) {
	let ext_str = ext_hex;
	let (bytes, size_bytes) = if let Some(hex_part) = ext_str.strip_prefix("0x") {
		if let Ok(decoded) = hex::decode(hex_part) {
			let size = decoded.len();
			(decoded, size)
		} else {
			(ext_str.as_bytes().to_vec(), ext_str.len())
		}
	} else {
		(ext_str.as_bytes().to_vec(), ext_str.len())
	};

	// Compute extrinsic hash using Poseidon (chain hasher)
	let h = <PoseidonHasher as sp_runtime::traits::Hash>::hash(&bytes);
	let hash_hex = format!("{h:#x}");

	let preview = if ext_str.len() > 20 { ext_str[..20].to_string() } else { ext_str.to_string() };
	(size_bytes, preview, hash_hex)
}

/// Format event details with typed decoding and nicer AccountId formatting
fn format_event_details<T: subxt::Config>(event: &EventDetails<T>) -> String {
	if let Ok(typed) = event.as_root_event::<crate::chain::quantus_subxt::api::Event>() {
		let formatted = format_event_with_ss58_addresses(&typed);
		return format!("📝 {}.{} {}", event.pallet_name(), event.variant_name(), formatted);
	}
	format!("📝 {}.{}", event.pallet_name(), event.variant_name())
}

fn format_event_with_ss58_addresses(event: &crate::chain::quantus_subxt::api::Event) -> String {
	let debug_str = format!("{event:?}");
	let mut result = debug_str.clone();
	let mut attempts = 0;
	while let Some(account_id) = extract_account_id_from_debug(&result) {
		let ss58_address = format_account_id(&account_id);
		let account_debug = format!("{account_id:?}");
		result = result.replace(&account_debug, &ss58_address);
		attempts += 1;
		if attempts > 10 {
			break;
		}
	}
	result
}

fn extract_account_id_from_debug(debug_str: &str) -> Option<subxt::utils::AccountId32> {
	if let Some(start) = debug_str.find("AccountId32([") {
		// "
		if let Some(end) = debug_str[start..].find("])") {
			let bytes_str = &debug_str[start + 13..start + end];
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

fn format_account_id(account_id: &subxt::utils::AccountId32) -> String {
	let bytes: [u8; 32] = account_id.0;
	let sp_account_id = sp_core::crypto::AccountId32::from(bytes);
	sp_account_id.to_ss58check()
}

/// Get account nonce at specific block
async fn get_account_nonce_at_block(
	quantus_client: &QuantusClient,
	account_address: &str,
	block_hash: subxt::utils::H256,
) -> crate::error::Result<u32> {
	// Parse the SS58 address to AccountId32 (sp-core)
	let account_id_sp = sp_core::crypto::AccountId32::from_ss58check(account_address)
		.map_err(|e| QuantusError::NetworkError(format!("Invalid SS58 address: {e:?}")))?;

	// Convert to subxt_core AccountId32 for storage query
	let account_bytes: [u8; 32] = *account_id_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

	// Use SubXT to query System::Account storage at specific block
	use crate::chain::quantus_subxt::api;
	let storage_addr = api::storage().system().account(account_id);
	let storage_at = quantus_client.client().storage().at(block_hash);

	let account_info = storage_at
		.fetch_or_default(&storage_addr)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Failed to fetch account info: {e:?}")))?;

	Ok(account_info.nonce)
}

/// Handle block list command
pub async fn handle_block_list_command(
	start: u32,
	end: u32,
	step: Option<u32>,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!(
		"📦 Listing blocks from {} to {}",
		start.to_string().bright_green(),
		end.to_string().bright_green()
	);

	let step = step.unwrap_or(1);
	if step > 1 {
		log_print!("📏 Step: {}", step.to_string().bright_cyan());
	}

	let quantus_client = QuantusClient::new(node_url).await?;
	list_blocks_in_range(&quantus_client, start, end, step).await
}

/// List blocks in range with summary information
async fn list_blocks_in_range(
	quantus_client: &QuantusClient,
	start: u32,
	end: u32,
	step: u32,
) -> crate::error::Result<()> {
	use jsonrpsee::core::client::ClientT;

	log_print!("🔍 Fetching block information...");

	let mut block_count = 0;
	let mut total_extrinsics = 0;
	let mut total_events = 0;
	let mut total_size = 0;
	let mut tps_values = Vec::new();
	let mut previous_timestamp: Option<u64> = None;

	// Progress indicator
	log_print!("📊 Processing {} blocks...", ((end - start) / step + 1).to_string().bright_cyan());

	// Print table header
	log_print!("");
	log_print!(
		"{:<20} {:<20} {:<12} {:<10} {:<8} {:<8}",
		"Block".bright_green().bold(),
		"Time".bright_cyan().bold(),
		"Extrinsics".bright_blue().bold(),
		"Events".bright_yellow().bold(),
		"Size".bright_magenta().bold(),
		"TPS".bright_red().bold()
	);
	log_print!(
		"{:<20} {:<20} {:<12} {:<10} {:<8} {:<8}",
		"────────────────────".bright_green(),
		"────────────────────".bright_cyan(),
		"────────────".bright_blue(),
		"──────────".bright_yellow(),
		"──────".bright_magenta(),
		"──────".bright_red()
	);

	for block_num in (start..=end).step_by(step as usize) {
		// Get block hash for this block number
		let block_hash: subxt::utils::H256 = quantus_client
			.rpc_client()
			.request::<subxt::utils::H256, [u32; 1]>("chain_getBlockHash", [block_num])
			.await
			.map_err(|e| {
				QuantusError::NetworkError(format!(
					"Failed to get block hash for block {block_num}: {e:?}"
				))
			})?;

		// Get block data
		let block_data: serde_json::Value = quantus_client
			.rpc_client()
			.request::<serde_json::Value, [String; 1]>(
				"chain_getBlock",
				[format!("{block_hash:#x}")],
			)
			.await
			.map_err(|e| {
				QuantusError::NetworkError(format!(
					"Failed to get block data for block {block_num}: {e:?}"
				))
			})?;

		// Extract basic info
		let extrinsics_count = if let Some(block) = block_data.get("block") {
			if let Some(extrinsics) = block.get("extrinsics") {
				if let Some(extrinsics_array) = extrinsics.as_array() {
					extrinsics_array.len()
				} else {
					0
				}
			} else {
				0
			}
		} else {
			0
		};

		// Get timestamp from storage
		let storage_at = quantus_client.client().storage().at(block_hash);
		let timestamp_addr = crate::chain::quantus_subxt::api::storage().timestamp().now();
		let timestamp = storage_at.fetch(&timestamp_addr).await.ok().flatten();

		// Get event count
		let event_count_addr = crate::chain::quantus_subxt::api::storage().system().event_count();
		let event_count = storage_at.fetch(&event_count_addr).await.ok().flatten().unwrap_or(0);

		// Calculate block size in KB based on actual data
		let block_size_bytes = if let Some(block) = block_data.get("block") {
			if let Some(extrinsics) = block.get("extrinsics") {
				if let Some(extrinsics_array) = extrinsics.as_array() {
					// Calculate size from actual extrinsic data
					let mut total_bytes = 0;
					for extrinsic in extrinsics_array.iter() {
						if let Some(ext_str) = extrinsic.as_str() {
							// Remove "0x" prefix and convert hex to bytes
							if let Some(hex_part) = ext_str.strip_prefix("0x") {
								if hex_part.len() % 2 == 0 {
									total_bytes += hex_part.len() / 2;
								} else {
									total_bytes += hex_part.len().div_ceil(2);
								}
							} else {
								total_bytes += ext_str.len();
							}
						}
					}
					// Add some overhead for block header (approximate)
					total_bytes + 1024 // ~1KB for header
				} else {
					0
				}
			} else {
				0
			}
		} else {
			0
		};
		let block_size_kb = block_size_bytes as f64 / 1024.0;

		// Update totals
		block_count += 1;
		total_extrinsics += extrinsics_count;
		total_events += event_count;
		total_size += block_size_bytes;

		// Calculate TPS (Transactions Per Second)
		let tps_str = match (timestamp, previous_timestamp) {
			(Some(ts), Some(prev_ts)) => {
				let time_diff_ms = ts.saturating_sub(prev_ts);
				if time_diff_ms > 0 {
					let time_diff_secs = time_diff_ms as f64 / 1000.0;
					let tps = extrinsics_count as f64 / time_diff_secs;
					tps_values.push(tps);
					format!("{:.1}", tps)
				} else {
					"N/A".to_string()
				}
			}
			_ => "N/A".to_string(),
		};


		// Display block info - always show full date
		let time_str = if let Some(ts) = timestamp {
			let timestamp_secs = ts / 1000;
			let datetime = chrono::DateTime::from_timestamp(timestamp_secs as i64, 0);
			if let Some(dt) = datetime {
				dt.format("%Y-%m-%d %H:%M:%S").to_string()
			} else {
				"unknown".to_string()
			}
		} else {
			"unknown".to_string()
		};

		log_print!(
			"📦 {:<18} {:<20} {:<12} {:<10} {:<8} {:<8}",
			format!("#{block_num}").bright_green(),
			time_str.bright_cyan(),
			extrinsics_count.to_string().bright_blue(),
			event_count.to_string().bright_yellow(),
			format!("{block_size_kb:.1}K").bright_magenta(),
			tps_str.bright_red()
		);

		// Update previous timestamp for next iteration
		previous_timestamp = timestamp.or(previous_timestamp);
	}

	// Summary
	log_print!("");
	log_print!("📊 Summary:");
	log_print!("   • Blocks processed: {}", block_count.to_string().bright_green());
	log_print!("   • Total extrinsics: {}", total_extrinsics.to_string().bright_blue());
	log_print!("   • Total events: {}", total_events.to_string().bright_yellow());
	log_print!(
		"   • Total size: {} KB",
		format!("{:.1}", total_size as f64 / 1024.0).bright_magenta()
	);
	log_print!(
		"   • Average extrinsics per block: {}",
		format!("{:.1}", total_extrinsics as f64 / block_count as f64).bright_cyan()
	);
	log_print!(
		"   • Average events per block: {}",
		format!("{:.1}", total_events as f64 / block_count as f64).bright_cyan()
	);

	// TPS Statistics
	if !tps_values.is_empty() {
		let max_tps = tps_values.iter().fold(f64::NEG_INFINITY, |a, &b| a.max(b));
		let min_tps = tps_values.iter().fold(f64::INFINITY, |a, &b| a.min(b));
		let avg_tps = tps_values.iter().sum::<f64>() / tps_values.len() as f64;

		log_print!("");
		log_print!("🚀 TPS Statistics:");
		log_print!("   • MAX TPS: {}", format!("{max_tps:.1}").bright_green().bold());
		log_print!("   • MIN TPS: {}", format!("{min_tps:.1}").bright_yellow().bold());
		log_print!("   • AVG TPS: {}", format!("{avg_tps:.1}").bright_cyan().bold());
		log_print!("   • TPS samples: {}", tps_values.len().to_string().bright_magenta());
	} else {
		log_print!("");
		log_print!(
			"🚀 TPS Statistics: No TPS data available (need at least 2 blocks with timestamps)"
		);
	}

	Ok(())
}
