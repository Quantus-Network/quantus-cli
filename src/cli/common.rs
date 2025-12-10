//! Common SubXT utilities and functions shared across CLI commands
use crate::{chain::client::ChainConfig, error::Result, log_error, log_verbose};
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::{
	tx::{TxProgress, TxStatus, PartialExtrinsic},
	OnlineClient,
};

/// Resolve address - if it's a wallet name, return the wallet's address
/// If it's already an SS58 address, return it as is
pub fn resolve_address(address_or_wallet_name: &str) -> Result<String> {
	// First, try to parse as SS58 address
	if AccountId32::from_ss58check_with_version(address_or_wallet_name).is_ok() {
		// It's a valid SS58 address, return as is
		return Ok(address_or_wallet_name.to_string());
	}

	// If not a valid SS58 address, try to find it as a wallet name
	let wallet_manager = crate::wallet::WalletManager::new()?;
	if let Some(wallet_address) = wallet_manager.find_wallet_address(address_or_wallet_name)? {
		log_verbose!(
			"🔍 Found wallet '{}' with address: {}",
			address_or_wallet_name.bright_cyan(),
			wallet_address.bright_green()
		);
		return Ok(wallet_address);
	}

	// Neither a valid SS58 address nor a wallet name
	Err(crate::error::QuantusError::Generic(format!(
		"Invalid destination: '{address_or_wallet_name}' is neither a valid SS58 address nor a known wallet name"
	)))
}

/// Get fresh nonce for account from the latest block using existing QuantusClient
/// This function ensures we always get the most current nonce from the chain
/// to avoid "Transaction is outdated" errors
pub async fn get_fresh_nonce_with_client(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
) -> Result<u64> {
	let (from_account_id, _version) =
		AccountId32::from_ss58check_with_version(&from_keypair.to_account_id_ss58check()).map_err(
			|e| crate::error::QuantusError::NetworkError(format!("Invalid from address: {e:?}")),
		)?;

	// Get nonce from the latest block (best block)
	let latest_nonce = quantus_client
		.get_account_nonce_from_best_block(&from_account_id)
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to get account nonce from best block: {e:?}"
			))
		})?;

	log_verbose!("🔢 Using fresh nonce from latest block: {}", latest_nonce);

	// Compare with nonce from finalized block for debugging
	let finalized_nonce = quantus_client
		.client()
		.tx()
		.account_nonce(&from_account_id)
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to get account nonce from finalized block: {e:?}"
			))
		})?;

	if latest_nonce != finalized_nonce {
		log_verbose!(
			"⚠️  Nonce difference detected! Latest: {}, Finalized: {}",
			latest_nonce,
			finalized_nonce
		);
	}

	Ok(latest_nonce)
}

/// Get incremented nonce for retry scenarios from the latest block using existing QuantusClient
/// This is useful when a transaction fails but the chain doesn't update the nonce
pub async fn get_incremented_nonce_with_client(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	base_nonce: u64,
) -> Result<u64> {
	let (from_account_id, _version) =
		AccountId32::from_ss58check_with_version(&from_keypair.to_account_id_ss58check()).map_err(
			|e| crate::error::QuantusError::NetworkError(format!("Invalid from address: {e:?}")),
		)?;

	// Get current nonce from the latest block
	let current_nonce = quantus_client
		.get_account_nonce_from_best_block(&from_account_id)
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to get account nonce from best block: {e:?}"
			))
		})?;

	// Use the higher of current nonce or base_nonce + 1
	let incremented_nonce = std::cmp::max(current_nonce, base_nonce + 1);
	log_verbose!(
		"🔢 Using incremented nonce: {} (base: {}, current from latest block: {})",
		incremented_nonce,
		base_nonce,
		current_nonce
	);
	Ok(incremented_nonce)
}

/// Default function for transaction submission, waits until transaction is in the best block
pub async fn submit_transaction<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	call: Call,
	tip: Option<u128>,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	submit_transaction_with_finalization(quantus_client, from_keypair, call, tip, false).await
}

/// Helper function to submit transaction with an optional finalization check
pub async fn submit_transaction_with_finalization<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	call: Call,
	tip: Option<u128>,
	finalized: bool,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	let signer = from_keypair.to_subxt_signer().map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {e:?}"))
	})?;

	// Retry logic with automatic nonce management
	let mut attempt = 0;
	let mut current_nonce = None;

	loop {
		attempt += 1;

		// Get fresh nonce for each attempt, or increment if we have a previous nonce
		let nonce = if let Some(prev_nonce) = current_nonce {
			// After first failure, try with incremented nonce
			let incremented_nonce =
				get_incremented_nonce_with_client(quantus_client, from_keypair, prev_nonce).await?;
			log_verbose!(
				"🔢 Using incremented nonce from best block: {} (previous: {})",
				incremented_nonce,
				prev_nonce
			);
			incremented_nonce
		} else {
			// First attempt - get fresh nonce from best block
			let fresh_nonce = get_fresh_nonce_with_client(quantus_client, from_keypair).await?;
			log_verbose!("🔢 Using fresh nonce from best block: {}", fresh_nonce);
			fresh_nonce
		};
		current_nonce = Some(nonce);

		// Get current block for logging using latest block hash
		let latest_block_hash = quantus_client.get_latest_block().await.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Failed to get latest block: {e:?}"))
		})?;

		log_verbose!("🔗 Latest block hash: {:?}", latest_block_hash);

		// Create custom params with fresh nonce and optional tip
		use subxt::config::DefaultExtrinsicParamsBuilder;
		let mut params_builder = DefaultExtrinsicParamsBuilder::new()
			.mortal(256) // Value higher than our finalization - TODO: should come from config
			.nonce(nonce);

		if let Some(tip_amount) = tip {
			params_builder = params_builder.tip(tip_amount);
			log_verbose!("💰 Using tip: {} to increase priority", tip_amount);
		} else {
			log_verbose!("💰 No tip specified, using default priority");
		}

		// Try to get chain parameters from the client
		let genesis_hash = quantus_client.get_genesis_hash().await?;
		let (spec_version, transaction_version) = quantus_client.get_runtime_version().await?;

		log_verbose!("🔍 Chain parameters:");
		log_verbose!("   Genesis hash: {:?}", genesis_hash);
		log_verbose!("   Spec version: {}", spec_version);
		log_verbose!("   Transaction version: {}", transaction_version);

		// For now, just use the default params
		let params = params_builder.build();

		// Log transaction parameters for debugging
		log_verbose!("🔍 Transaction parameters:");
		log_verbose!("   Nonce: {}", nonce);
		log_verbose!("   Tip: {:?}", tip);
		log_verbose!("   Latest block hash: {:?}", latest_block_hash);

		// Get and log era information
		log_verbose!("   Era: Using default era from SubXT");
		log_verbose!("   Genesis hash: Using default from SubXT");
		log_verbose!("   Spec version: Using default from SubXT");

		// Log additional debugging info
		log_verbose!("🔍 Additional debugging:");
		log_verbose!("   Call type: {:?}", std::any::type_name::<Call>());

		// Submit the transaction with fresh nonce and optional tip
		match quantus_client
			.client()
			.tx()
			.sign_and_submit_then_watch(&call, &signer, params)
			.await
		{
			Ok(mut tx_progress) => {
				crate::log_verbose!("📋 Transaction submitted: {:?}", tx_progress);

				let tx_hash = tx_progress.extrinsic_hash();
				wait_tx_inclusion(&mut tx_progress, finalized).await?;

				return Ok(tx_hash);
			},
			Err(e) => {
				let error_msg = format!("{e:?}");

				// Check if it's a retryable error
				let is_retryable = error_msg.contains("Priority is too low") ||
					error_msg.contains("Transaction is outdated") ||
					error_msg.contains("Transaction is temporarily banned") ||
					error_msg.contains("Transaction has a bad signature") ||
					error_msg.contains("Invalid Transaction");

				if is_retryable && attempt < 5 {
					log_verbose!(
						"⚠️  Transaction error detected (attempt {}/5): {}",
						attempt,
						error_msg
					);

					// Exponential backoff: 2s, 4s, 8s, 16s
					let delay = std::cmp::min(2u64.pow(attempt as u32), 16);
					log_verbose!("⏳ Waiting {} seconds before retry...", delay);
					tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
					continue;
				} else {
					log_verbose!("❌ Final error after {} attempts: {}", attempt, error_msg);
					return Err(crate::error::QuantusError::NetworkError(format!(
						"Failed to submit transaction: {e:?}"
					)));
				}
			},
		}
	}
}

/// Submit transaction with manual nonce (no retry logic - use exact nonce provided)
pub async fn submit_transaction_with_nonce<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	call: Call,
	tip: Option<u128>,
	nonce: u32,
	finalized: bool,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	let signer = from_keypair.to_subxt_signer().map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {e:?}"))
	})?;

	// Get current block for logging using latest block hash
	let latest_block_hash = quantus_client.get_latest_block().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get latest block: {e:?}"))
	})?;

	log_verbose!("🔗 Latest block hash: {:?}", latest_block_hash);

	// Create custom params with manual nonce and optional tip
	use subxt::config::DefaultExtrinsicParamsBuilder;
	let mut params_builder = DefaultExtrinsicParamsBuilder::new()
		.mortal(256) // Value higher than our finalization - TODO: should come from config
		.nonce(nonce.into());

	if let Some(tip_amount) = tip {
		params_builder = params_builder.tip(tip_amount);
		log_verbose!("💰 Using tip: {}", tip_amount);
	}

	let params = params_builder.build();

	log_verbose!("🔢 Using manual nonce: {}", nonce);
	log_verbose!("📤 Submitting transaction with manual nonce...");

	// Submit the transaction with manual nonce
	match quantus_client
		.client()
		.tx()
		.sign_and_submit_then_watch(&call, &signer, params)
		.await
	{
		Ok(mut tx_progress) => {
			let tx_hash = tx_progress.extrinsic_hash();
			log_verbose!("✅ Transaction submitted successfully: {:?}", tx_hash);
			wait_tx_inclusion(&mut tx_progress, finalized).await?;
			Ok(tx_hash)
		},
		Err(e) => {
			log_error!("❌ Failed to submit transaction with manual nonce {}: {e:?}", nonce);
			Err(crate::error::QuantusError::NetworkError(format!(
				"Failed to submit transaction with nonce {nonce}: {e:?}"
			)))
		},
	}
}

/// Watch transaction until it is included in the best block or finalized
///
/// Since Quantus network is PoW, we can't use default subxt's way of waiting for finalized block as
/// it may take a long time. We wait for the transaction to be included in the best block and leave
/// it up to the user to check the status of the transaction.
async fn wait_tx_inclusion(
	tx_progress: &mut TxProgress<ChainConfig, OnlineClient<ChainConfig>>,
	finalized: bool,
) -> Result<()> {
	while let Some(Ok(status)) = tx_progress.next().await {
		crate::log_verbose!("   Transaction status: {:?}", status);
		match status {
			TxStatus::InBestBlock(block_hash) => {
				crate::log_verbose!("   Transaction included in block: {:?}", block_hash);
				if finalized {
					continue;
				} else {
					break;
				};
			},
			TxStatus::InFinalizedBlock(block_hash) => {
				crate::log_verbose!("   Transaction finalized in block: {:?}", block_hash);
				break;
			},
			TxStatus::Error { message } | TxStatus::Invalid { message } => {
				crate::log_error!("   Transaction error: {}", message);
				break;
			},
			_ => continue,
		}
	}

	Ok(())
}

/// Hardware wallet support: Create unsigned transaction ready for external signing
pub async fn create_unsigned_transaction<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	call: Call,
	tip: Option<u128>,
) -> crate::error::Result<PartialExtrinsic<ChainConfig, OnlineClient<ChainConfig>>>
where
	Call: subxt::tx::Payload,
{
	log_verbose!("🔓 Creating unsigned transaction for hardware wallet signing...");

	// Get fresh nonce for the account
	let nonce = get_fresh_nonce_with_client(quantus_client, from_keypair).await?;

	// Get current block for logging
	let latest_block_hash = quantus_client.get_latest_block().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get latest block: {e:?}"))
	})?;

	log_verbose!("🔗 Latest block hash: {:?}", latest_block_hash);

	// Create custom params with nonce and optional tip
	use subxt::config::DefaultExtrinsicParamsBuilder;
	let mut params_builder = DefaultExtrinsicParamsBuilder::new()
		.mortal(256) // Value higher than our finalization - TODO: should come from config
		.nonce(nonce);

	if let Some(tip_amount) = tip {
		params_builder = params_builder.tip(tip_amount);
		log_verbose!("💰 Using tip: {} to increase priority", tip_amount);
	} else {
		log_verbose!("💰 No tip specified, using default priority");
	}

	let params = params_builder.build();

	log_verbose!("🔢 Using nonce: {}", nonce);
	log_verbose!("📋 Transaction parameters prepared for hardware signing");

	// Create partial (unsigned) transaction
	let partial_tx = quantus_client
		.client()
		.tx()
		.create_partial_offline(&call, params)
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to create partial transaction: {e:?}"
			))
		})?;

	log_verbose!("✅ Unsigned transaction created successfully");
	Ok(partial_tx)
}

/// Hardware wallet support: Export signing payload as SCALE-encoded bytes
pub fn export_signing_payload(
	partial_tx: &PartialExtrinsic<ChainConfig, OnlineClient<ChainConfig>>,
) -> Vec<u8> {
	log_verbose!("📤 Exporting signing payload for hardware wallet...");

	// Get the signer payload (the data that needs to be signed)
	let signer_payload = partial_tx.signer_payload();

	// The payload is already SCALE-encoded and ready for signing
	let payload_bytes = signer_payload.encode();

	log_verbose!("📦 Signing payload exported: {} bytes", payload_bytes.len());
	log_verbose!("🔍 Payload hash: {:?}", sp_core::blake2_256(&payload_bytes));

	payload_bytes
}

/// Hardware wallet support: Submit transaction with externally provided signature
pub async fn submit_signed_transaction(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	partial_tx: PartialExtrinsic<ChainConfig, OnlineClient<ChainConfig>>,
	signature: &[u8],
	finalized: bool,
) -> crate::error::Result<subxt::utils::H256> {
	log_verbose!("🔐 Submitting transaction with hardware wallet signature...");

	// Convert signature bytes to the expected signature type
	let signature = <ChainConfig as subxt::Config>::Signature::decode(&mut &signature[..])
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to decode signature: {e:?}"
			))
		})?;

	// Get the account ID from the keypair
	let account_id = from_keypair.to_account_id_32();

	// Attach the signature and account ID to create the signed transaction
	let signed_tx = partial_tx.sign_with_account_and_signature(&account_id, &signature);

	log_verbose!("✅ Signature attached to transaction");

	// Submit the signed transaction
	let mut tx_progress = signed_tx.submit().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!(
			"Failed to submit signed transaction: {e:?}"
		))
	})?;

	let tx_hash = tx_progress.extrinsic_hash();
	log_verbose!("📋 Transaction submitted with hash: {:?}", tx_hash);

	// Wait for inclusion
	wait_tx_inclusion(&mut tx_progress, finalized).await?;

	Ok(tx_hash)
}

/// Hardware wallet support: Get transaction details for display/debugging
pub fn get_transaction_details(
	partial_tx: &PartialExtrinsic<ChainConfig, OnlineClient<ChainConfig>>,
	from_address: &str,
) -> serde_json::Value {
	log_verbose!("📋 Gathering transaction details for hardware wallet...");

	let signer_payload = partial_tx.signer_payload();
	let payload_bytes = signer_payload.encode();

	serde_json::json!({
		"from_address": from_address,
		"payload_length": payload_bytes.len(),
		"payload_hash": hex::encode(sp_core::blake2_256(&payload_bytes)),
		"payload_hex": hex::encode(&payload_bytes),
		"era": "Immortal", // For now, using immortal era
		"nonce_required": true,
		"tip_included": signer_payload.tip().is_some(),
		"genesis_hash": hex::encode(signer_payload.genesis_hash().as_ref()),
		"spec_version": signer_payload.spec_version(),
		"transaction_version": signer_payload.transaction_version(),
	})
}

/// Hardware wallet support: Generate QR code for signing payload
pub fn generate_qr_code_for_signing(payload_bytes: &[u8]) -> Result<String> {
	log_verbose!("📱 Generating QR code for signing payload...");

	// Encode the payload as hex for QR code
	let hex_payload = hex::encode(payload_bytes);

	// Generate QR code
	let code = qrcode::QrCode::new(hex_payload.as_bytes()).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to generate QR code: {e:?}"))
	})?;

	// Render the QR code as ASCII art
	let qr_string = code.render::<char>()
		.quiet_zone(false)
		.module_dimensions(2, 1)
		.build();

	log_verbose!("📱 QR code generated successfully ({} bytes of payload)", payload_bytes.len());

	Ok(qr_string)
}

/// Hardware wallet support: Display comprehensive hardware signing information
pub fn display_hardware_signing_info(
	partial_tx: &PartialExtrinsic<ChainConfig, OnlineClient<ChainConfig>>,
	from_address: &str,
	payload_bytes: &[u8],
	qr_code: Option<&str>,
) {
	log_info!("🔐 Hardware Wallet Signing Information");
	log_print!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
	log_print!("📤 From Address: {}", from_address.bright_cyan());
	log_print!("📦 Payload Size: {} bytes", payload_bytes.len());
	log_print!("🔍 Payload Hash: {}", hex::encode(sp_core::blake2_256(payload_bytes)).bright_yellow());
	log_print!("");

	if let Some(qr) = qr_code {
		log_print!("📱 Scan this QR code with your hardware wallet:");
		log_print!("");
		log_print!("{}", qr);
		log_print!("");
	}

	log_print!("📋 Raw Payload (hex): {}", hex::encode(payload_bytes));
	log_print!("");
	log_print!("💡 Instructions:");
	log_print!("   1. Use your hardware wallet to sign the above payload");
	log_print!("   2. The wallet should return the signature in hex format");
	log_print!("   3. Use the signature with the 'submit-signed' command");
	log_print!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}
