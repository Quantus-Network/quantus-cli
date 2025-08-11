//! `quantus preimage` subcommand - preimage operations
use crate::{
	chain::quantus_subxt, cli::progress_spinner::wait_for_tx_confirmation, error::QuantusError,
	log_error, log_print, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use std::str::FromStr;
use subxt::utils::H256;

/// Preimage operations
#[derive(Subcommand, Debug)]
pub enum PreimageCommands {
	/// Check if a preimage exists and get its status
	#[command(name = "status")]
	Status {
		/// Preimage hash (hex format)
		#[arg(long)]
		hash: String,
	},
	/// Get preimage content
	#[command(name = "get")]
	Get {
		/// Preimage hash (hex format)
		#[arg(long)]
		hash: String,
		/// Preimage length (required for retrieval)
		#[arg(long)]
		len: u32,
	},
	/// List all preimages
	#[command(name = "list")]
	List,
	/// Request a preimage (no deposit required)
	#[command(name = "request")]
	Request {
		/// Preimage hash (hex format)
		#[arg(long)]
		hash: String,
		/// Wallet to use for the request
		#[arg(long)]
		from: String,
	},
	/// Note a preimage (requires deposit)
	#[command(name = "note")]
	Note {
		/// Preimage content (hex format)
		#[arg(long)]
		content: String,
		/// Wallet to use for the note
		#[arg(long)]
		from: String,
	},
	/// Create a preimage from WASM file (like in tech-referenda)
	#[command(name = "create")]
	Create {
		/// WASM file path
		#[arg(long)]
		wasm_file: std::path::PathBuf,
		/// Wallet to use for the preimage
		#[arg(long)]
		from: String,
		/// Password for wallet (optional)
		#[arg(long)]
		password: Option<String>,
		/// Password file path (optional)
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Handle preimage commands
pub async fn handle_preimage_command(
	command: PreimageCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		PreimageCommands::Status { hash } => {
			check_preimage_status(&quantus_client, &hash).await?;
		},
		PreimageCommands::Get { hash, len } => {
			get_preimage_content(&quantus_client, &hash, len).await?;
		},
		PreimageCommands::List => {
			list_preimages(&quantus_client).await?;
		},
		PreimageCommands::Request { hash, from } => {
			request_preimage(&quantus_client, &hash, &from).await?;
		},
		PreimageCommands::Note { content, from } => {
			note_preimage(&quantus_client, &content, &from).await?;
		},
		PreimageCommands::Create { wasm_file, from, password, password_file } => {
			create_preimage(&quantus_client, wasm_file, &from, password, password_file).await?;
		},
	}

	Ok(())
}

/// Check preimage status
async fn check_preimage_status(
	quantus_client: &crate::chain::client::QuantusClient,
	hash_str: &str,
) -> crate::error::Result<()> {
	let preimage_hash = parse_hash(hash_str)?;

	log_print!("🔍 Checking preimage status for hash: {}", hash_str.bright_cyan());

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	// Check StatusFor (old format)
	let status_addr = quantus_subxt::api::storage().preimage().status_for(preimage_hash);
	let status_result = storage_at.fetch(&status_addr).await;

	// Check RequestStatusFor (new format)
	let request_status_addr =
		quantus_subxt::api::storage().preimage().request_status_for(preimage_hash);
	let request_status_result = storage_at.fetch(&request_status_addr).await;

	log_print!("📊 Preimage Status Results:");
	log_print!("   🔗 Hash: {}", hash_str.bright_yellow());

	match status_result {
		Ok(Some(status)) => {
			log_print!("   📋 StatusFor (Old): {:?}", status);
		},
		Ok(None) => {
			log_print!("   📋 StatusFor (Old): Not found");
		},
		Err(e) => {
			log_print!("   📋 StatusFor (Old): Error - {:?}", e);
		},
	}

	match request_status_result {
		Ok(Some(request_status)) => {
			log_print!("   📋 RequestStatusFor (New): {:?}", request_status);
		},
		Ok(None) => {
			log_print!("   📋 RequestStatusFor (New): Not found");
		},
		Err(e) => {
			log_print!("   📋 RequestStatusFor (New): Error - {:?}", e);
		},
	}

	// Check if preimage content exists (we need to know the length)
	// For now, we'll try with a reasonable length
	let preimage_addr =
		quantus_subxt::api::storage().preimage().preimage_for((preimage_hash, 0u32));
	let preimage_result = storage_at.fetch(&preimage_addr).await;

	match preimage_result {
		Ok(Some(_)) => {
			log_print!("   📦 PreimageFor: Content exists (length 0)");
		},
		Ok(None) => {
			log_print!("   📦 PreimageFor: No content found (length 0)");
		},
		Err(e) => {
			log_print!("   📦 PreimageFor: Error - {:?}", e);
		},
	}

	Ok(())
}

/// Get preimage content
async fn get_preimage_content(
	quantus_client: &crate::chain::client::QuantusClient,
	hash_str: &str,
	len: u32,
) -> crate::error::Result<()> {
	let preimage_hash = parse_hash(hash_str)?;

	log_print!("📦 Getting preimage content for hash: {}", hash_str.bright_cyan());
	log_print!("   📏 Length: {} bytes", len);

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let preimage_addr = quantus_subxt::api::storage().preimage().preimage_for((preimage_hash, len));
	let preimage_result = storage_at.fetch(&preimage_addr).await;

	match preimage_result {
		Ok(Some(bounded_vec)) => {
			log_print!("✅ Preimage content found!");
			log_print!("   📏 Actual length: {} bytes", bounded_vec.0.len());

			// Convert to Vec<u8> for display
			let content: Vec<u8> = bounded_vec.0;

			// Show first 100 bytes as hex
			let preview_len = std::cmp::min(100, content.len());
			let preview = &content[..preview_len];
			log_print!("   🔍 Preview (first {} bytes):", preview_len);
			log_print!("      {}", hex::encode(preview).bright_green());

			if content.len() > preview_len {
				log_print!("   ... ({} more bytes)", content.len() - preview_len);
			}

			// Try to decode as call data
			log_verbose!("   🔧 Attempting to decode as call data...");
			log_print!("   📝 Raw content preview (first 100 bytes):");
			log_print!(
				"      {}",
				hex::encode(&content[..std::cmp::min(100, content.len())]).bright_green()
			);
		},
		Ok(None) => {
			log_error!("❌ Preimage content not found for hash {} with length {}", hash_str, len);
		},
		Err(e) => {
			log_error!("❌ Error fetching preimage content: {:?}", e);
		},
	}

	Ok(())
}

/// List all preimages
async fn list_preimages(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("📋 Listing all preimages...");

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	// Get all preimage statuses
	let status_addr = quantus_subxt::api::storage().preimage().request_status_for_iter();
	let mut status_stream = storage_at.iter(status_addr).await.map_err(|e| {
		QuantusError::Generic(format!("Failed to iterate preimage statuses: {:?}", e))
	})?;

	let mut preimage_count = 0;
	let mut unrequested_count = 0;
	let mut requested_count = 0;

	log_print!("🔍 Scanning preimage statuses...");

	while let Some(result) = status_stream.next().await {
		match result {
			Ok(key_value_pair) => {
				preimage_count += 1;

				// Extract hash from storage key
				let hash_bytes = key_value_pair.key_bytes.as_slice();
				if hash_bytes.len() >= 32 {
					let hash = sp_core::H256::from_slice(&hash_bytes[hash_bytes.len() - 32..]);

					match key_value_pair.value {
						quantus_subxt::api::runtime_types::pallet_preimage::RequestStatus::Unrequested { ticket: _, len } => {
							unrequested_count += 1;
							log_print!("   🔗 {} (Unrequested, {} bytes)", hash, len);
						},
						quantus_subxt::api::runtime_types::pallet_preimage::RequestStatus::Requested { maybe_ticket: _, count, maybe_len } => {
							requested_count += 1;
							let len_str = match maybe_len {
								Some(len) => format!("{} bytes", len),
								None => "unknown length".to_string(),
							};
							log_print!("   🔗 {} (Requested, count: {}, {})", hash, count, len_str);
						},
					}
				}
			},
			Err(e) => {
				log_verbose!("⚠️  Error reading preimage status: {:?}", e);
			},
		}
	}

	log_print!("");
	log_print!("📊 Preimage Summary:");
	log_print!("   📋 Total preimages: {}", preimage_count);
	log_print!("   📝 Unrequested: {}", unrequested_count);
	log_print!("   📋 Requested: {}", requested_count);

	if preimage_count == 0 {
		log_print!("   💡 No preimages found on chain");
	}

	Ok(())
}

/// Request a preimage (no deposit required)
async fn request_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	hash_str: &str,
	from_str: &str,
) -> crate::error::Result<()> {
	let preimage_hash = parse_hash(hash_str)?;

	log_print!("🚀 Requesting preimage for hash: {}", hash_str.bright_cyan());
	log_print!("   👤 From: {}", from_str.bright_yellow());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from_str, None, None)?;

	// Create request_preimage call
	let request_call = quantus_subxt::api::tx().preimage().request_preimage(preimage_hash);

	// Submit transaction
	let tx_hash =
		crate::cli::common::submit_transaction(quantus_client, &keypair, request_call, None)
			.await?;
	log_print!("✅ Preimage request transaction submitted: {:?}", tx_hash);

	// Wait for confirmation
	log_print!("⏳ Waiting for preimage request confirmation...");
	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	log_print!("✅ Preimage request confirmed!");

	Ok(())
}

/// Note a preimage (requires deposit)
async fn note_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	content_str: &str,
	from_str: &str,
) -> crate::error::Result<()> {
	let content = hex::decode(content_str.trim_start_matches("0x"))
		.map_err(|e| QuantusError::Generic(format!("Invalid hex content: {}", e)))?;

	log_print!("📝 Noting preimage for content length: {} bytes", content.len());
	log_print!("   👤 From: {}", from_str.bright_yellow());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from_str, None, None)?;

	// Create note_preimage call
	let note_call = quantus_subxt::api::tx().preimage().note_preimage(content);

	// Submit transaction
	let tx_hash =
		crate::cli::common::submit_transaction(quantus_client, &keypair, note_call, None).await?;
	log_print!("✅ Preimage note transaction submitted: {:?}", tx_hash);

	// Wait for confirmation
	log_print!("⏳ Waiting for preimage note confirmation...");
	let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
	log_print!("✅ Preimage note confirmed!");

	Ok(())
}

/// Create a preimage from WASM file (like in tech-referenda)
async fn create_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_file: std::path::PathBuf,
	from_str: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> crate::error::Result<()> {
	use poseidon_resonance::PoseidonHasher;

	log_print!("📦 Creating preimage from WASM file: {}", wasm_file.display());
	log_print!("   👤 From: {}", from_str.bright_yellow());

	if !wasm_file.exists() {
		return Err(QuantusError::Generic(format!("WASM file not found: {}", wasm_file.display())));
	}

	// Read WASM file
	let wasm_code = std::fs::read(&wasm_file)
		.map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {}", e)))?;

	log_print!("📊 WASM file size: {} bytes", wasm_code.len());

	// Load wallet keypair
	let keypair = crate::wallet::load_keypair_from_wallet(from_str, password, password_file)?;

	// Build a static payload for System::set_code and encode full call data (pallet + call + args)
	let set_code_payload = quantus_subxt::api::tx().system().set_code(wasm_code.clone());
	let metadata = quantus_client.client().metadata();
	let encoded_call = <_ as subxt::tx::Payload>::encode_call_data(&set_code_payload, &metadata)
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call data: {:?}", e)))?;

	log_verbose!("📝 Encoded call size: {} bytes", encoded_call.len());

	// Compute preimage hash using Poseidon (runtime uses PoseidonHasher)
	let preimage_hash: sp_core::H256 =
		<PoseidonHasher as sp_runtime::traits::Hash>::hash(&encoded_call);

	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	// Submit Preimage::note_preimage with bounded bytes
	type PreimageBytes = quantus_subxt::api::preimage::calls::types::note_preimage::Bytes;
	let bounded_bytes: PreimageBytes =
		<PreimageBytes as core::convert::TryFrom<Vec<u8>>>::try_from(encoded_call.clone())
			.map_err(|_| QuantusError::Generic("Preimage too large".to_string()))?;

	log_print!("📝 Submitting preimage...");
	let note_preimage_tx = quantus_subxt::api::tx().preimage().note_preimage(bounded_bytes);
	let preimage_tx_hash =
		crate::cli::common::submit_transaction(quantus_client, &keypair, note_preimage_tx, None)
			.await?;
	log_print!("✅ Preimage transaction submitted: {:?}", preimage_tx_hash);

	// Wait for preimage transaction confirmation
	log_print!("⏳ Waiting for preimage transaction confirmation...");
	let _ = wait_for_tx_confirmation(quantus_client.client(), preimage_tx_hash).await?;
	log_print!("✅ Preimage transaction confirmed!");

	log_print!("🎯 Preimage created successfully!");
	log_print!("   🔗 Hash: {:?}", preimage_hash);
	log_print!("   📏 Size: {} bytes", encoded_call.len());

	Ok(())
}

/// Parse hash string to H256
fn parse_hash(hash_str: &str) -> crate::error::Result<H256> {
	let hash_str = hash_str.trim_start_matches("0x");
	H256::from_str(hash_str).map_err(|e| {
		QuantusError::Generic(format!("Invalid hash format: {}. Expected 64 hex characters", e))
	})
}
