//! `quantus preimage` subcommand - preimage operations
use crate::{chain::quantus_subxt, error::QuantusError, log_error, log_print, log_verbose};
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
	/// Create a System::authorize_upgrade preimage from a WASM file
	#[command(name = "create")]
	Create {
		/// WASM file path
		#[arg(long)]
		wasm_file: std::path::PathBuf,
		/// Wallet to use for the preimage
		#[arg(long)]
		from: String,
		/// Password for wallet (optional)
		#[arg(long, hide = true)]
		password: Option<String>,
		/// Password file path (optional)
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// The subset of `Preimage::RequestStatusFor` the CLI displays.
///
/// Read dynamically: the stored ticket is a runtime-local deposit type, so the
/// generated codegen rejects this entry on any runtime that defines it differently.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PreimageStatusSnapshot {
	Unrequested { len: u32 },
	Requested { count: u32, maybe_len: Option<u32> },
}

impl PreimageStatusSnapshot {
	/// Byte length of the stored preimage, when the chain knows it.
	pub(crate) fn len(self) -> Option<u32> {
		match self {
			Self::Unrequested { len } => Some(len),
			Self::Requested { maybe_len, .. } => maybe_len,
		}
	}
}

/// Fetch `Preimage::RequestStatusFor(hash)` decoded against live metadata.
pub(crate) async fn fetch_request_status(
	quantus_client: &crate::chain::client::QuantusClient,
	hash: sp_core::H256,
	block_hash: subxt::utils::H256,
) -> crate::error::Result<Option<PreimageStatusSnapshot>> {
	use crate::cli::dynamic_decode::{field, missing, option, u32_field, uint, variant};

	let addr = subxt::dynamic::storage(
		"Preimage",
		"RequestStatusFor",
		vec![subxt::dynamic::Value::from_bytes(hash.as_bytes())],
	);
	let storage_at = quantus_client.client().storage().at(block_hash);
	let Some(thunk) = storage_at.fetch(&addr).await? else {
		return Ok(None);
	};
	let value = thunk
		.to_value()
		.map_err(|e| QuantusError::Generic(format!("Failed to decode preimage status: {e:?}")))?;

	let (name, fields) = variant(&value).ok_or_else(|| missing("RequestStatus"))?;
	let snapshot = match name {
		"Unrequested" => PreimageStatusSnapshot::Unrequested { len: u32_field(fields, "len")? },
		"Requested" => {
			let maybe_len = match field(fields, "maybe_len").and_then(option) {
				Some(Some(v)) => Some(
					u32::try_from(uint(v).ok_or_else(|| missing("maybe_len"))?)
						.map_err(|_| missing("maybe_len"))?,
				),
				Some(None) => None,
				None => return Err(missing("maybe_len")),
			};
			PreimageStatusSnapshot::Requested { count: u32_field(fields, "count")?, maybe_len }
		},
		other =>
			return Err(QuantusError::Generic(format!(
				"preimage decode: unknown RequestStatus variant `{other}`"
			))),
	};
	Ok(Some(snapshot))
}

/// Handle preimage commands
pub async fn handle_preimage_command(
	command: PreimageCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
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
			request_preimage(&quantus_client, &hash, &from, execution_mode).await?;
		},
		PreimageCommands::Note { content, from } => {
			note_preimage(&quantus_client, &content, &from, execution_mode).await?;
		},
		PreimageCommands::Create { wasm_file, from, password, password_file } => {
			create_preimage(
				&quantus_client,
				wasm_file,
				&from,
				password,
				password_file,
				execution_mode,
			)
			.await?;
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

	// Check RequestStatusFor (new format), decoded against live metadata
	let request_status_result =
		fetch_request_status(quantus_client, preimage_hash, latest_block_hash).await;

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

	let mut preimage_count = 0;
	let mut unrequested_count = 0;
	let mut requested_count = 0;

	// Iterate PreimageFor keys; extract (hash, len) from key_bytes and optionally fetch status
	let preimage_for_addr = quantus_subxt::api::storage().preimage().preimage_for_iter();
	let mut image_stream = storage_at.iter(preimage_for_addr).await.map_err(|e| {
		QuantusError::Generic(format!("Failed to iterate preimage contents: {:?}", e))
	})?;

	while let Some(result) = image_stream.next().await {
		match result {
			Ok(entry) => {
				let key = entry.key_bytes;
				if key.len() >= 36 {
					let len_le = &key[key.len() - 4..];
					let len = u32::from_le_bytes([len_le[0], len_le[1], len_le[2], len_le[3]]);
					let hash = sp_core::H256::from_slice(&key[key.len() - 36..key.len() - 4]);

					let status = fetch_request_status(quantus_client, hash, latest_block_hash)
						.await
						.ok()
						.flatten();

					preimage_count += 1;
					match status {
						Some(PreimageStatusSnapshot::Unrequested { len: status_len }) => {
							unrequested_count += 1;
							log_print!("   🔗 {} (Unrequested, {} bytes)", hash, status_len);
						},
						Some(PreimageStatusSnapshot::Requested { count, maybe_len }) => {
							requested_count += 1;
							let len_str = match maybe_len {
								Some(l) => format!("{} bytes", l),
								None => format!("{} bytes (from key)", len),
							};
							log_print!("   🔗 {} (Requested, count: {}, {})", hash, count, len_str);
						},
						None => {
							log_print!("   🔗 {} (Unknown status, {} bytes)", hash, len);
						},
					}
				}
			},
			Err(e) => log_verbose!("⚠️  Error reading preimage content entry: {:?}", e),
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
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let preimage_hash = parse_hash(hash_str)?;

	log_print!("🚀 Requesting preimage for hash: {}", hash_str.bright_cyan());
	log_print!("   👤 From: {}", from_str.bright_yellow());

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from_str, None, None)?;

	// Create request_preimage call
	let request_call = quantus_subxt::api::tx().preimage().request_preimage(preimage_hash);

	// Submit transaction
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		&signer,
		request_call,
		None,
		execution_mode,
	)
	.await?;
	log_print!("✅ Preimage request transaction submitted: {:?}", tx_hash);

	// Wait for confirmation
	log_print!("⏳ Waiting for preimage request confirmation...");
	log_print!("✅ Preimage request confirmed!");

	Ok(())
}

/// Note a preimage (requires deposit)
async fn note_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	content_str: &str,
	from_str: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let content = hex::decode(content_str.trim_start_matches("0x"))
		.map_err(|e| QuantusError::Generic(format!("Invalid hex content: {}", e)))?;

	log_print!("📝 Noting preimage for content length: {} bytes", content.len());
	log_print!("   👤 From: {}", from_str.bright_yellow());

	// Load wallet signer
	let signer = crate::wallet::load_signer_from_wallet(from_str, None, None)?;

	// Create note_preimage call
	let note_call = quantus_subxt::api::tx().preimage().note_preimage(content);

	// Submit transaction
	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		&signer,
		note_call,
		None,
		execution_mode,
	)
	.await?;
	log_print!("✅ Preimage note transaction submitted: {:?}", tx_hash);

	// Wait for confirmation
	log_print!("⏳ Waiting for preimage note confirmation...");
	log_print!("✅ Preimage note confirmed!");

	Ok(())
}

/// Create a System::authorize_upgrade preimage from a WASM file
async fn create_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_file: std::path::PathBuf,
	from_str: &str,
	password: Option<String>,
	password_file: Option<String>,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	log_print!("📦 Creating preimage from WASM file: {}", wasm_file.display());
	log_print!("   👤 From: {}", from_str.bright_yellow());

	let wasm_code = crate::cli::runtime::read_wasm_file(&wasm_file)?;
	log_print!("📊 WASM file size: {} bytes", wasm_code.len());
	let signer = crate::wallet::load_signer_from_wallet(from_str, password, password_file)?;
	let authorization = crate::cli::runtime::build_runtime_authorization(
		&quantus_client.client().metadata(),
		&wasm_code,
	)?;
	log_print!("🔐 Runtime code hash: {:?}", authorization.code_hash);
	log_print!("🔗 Preimage hash: {:?}", authorization.preimage_hash);
	crate::cli::common::submit_preimage(
		quantus_client,
		&signer,
		authorization.encoded_call,
		execution_mode,
	)
	.await?;

	log_print!("🎯 Preimage created successfully!");
	log_print!("   🔗 Hash: {:?}", authorization.preimage_hash);

	Ok(())
}

/// Parse hash string to H256
fn parse_hash(hash_str: &str) -> crate::error::Result<H256> {
	let hash_str = hash_str.trim_start_matches("0x");
	H256::from_str(hash_str).map_err(|e| {
		QuantusError::Generic(format!("Invalid hash format: {}. Expected 64 hex characters", e))
	})
}
