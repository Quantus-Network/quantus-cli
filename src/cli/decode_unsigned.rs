use crate::{
	chain::client::QuantusClient,
	cli::referenda_decode::decode_runtime_call_direct,
	error::{QuantusError, Result},
	log_print, log_success, log_verbose,
};
use codec::{Compact, Decode};
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

pub async fn handle_decode_unsigned_command(
	hex_payload: String,
	sign_and_send: Option<String>,
	signature: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
	node_url: &str,
) -> Result<()> {
	let quantus_client = QuantusClient::new(node_url).await?;

	let hex_clean = hex_payload.strip_prefix("0x").unwrap_or(&hex_payload);
	let bytes = hex::decode(hex_clean).map_err(|e| {
		QuantusError::Generic(format!("Invalid hex string: {e:?}"))
	})?;

	if bytes.is_empty() {
		return Err(QuantusError::Generic("Empty transaction payload".to_string()));
	}

	log_verbose!("Decoding {} bytes of transaction data", bytes.len());
	log_verbose!("Full hex: {}", hex::encode(&bytes));

	let mut cursor = &bytes[..];

	// 1. Version
	let version = cursor[0];
	cursor = &cursor[1..];
	log_verbose!("Version byte: 0x{:02x}", version);

	if version != 0x04 && version != 0x05 {
		// Maybe it's a raw call or something else, but we expect our custom format now
		log_print!("⚠️  Unknown version byte: 0x{:02x}. Attempting to proceed...", version);
	}

	// 2. Call Data (Length + Bytes)
	let call_length_compact: Compact<u32> = Decode::decode(&mut cursor)
		.map_err(|e| QuantusError::Generic(format!("Failed to decode call length: {e:?}")))?;
	let call_length = call_length_compact.0 as usize;

	if cursor.len() < call_length {
		return Err(QuantusError::Generic(format!("Call data truncated: need {} bytes", call_length)));
	}
	let call_data = &cursor[..call_length];
	cursor = &cursor[call_length..];
	
	log_verbose!("Call data length: {}", call_length);

	// 3. Extra Params (Length + Bytes)
	let extra_length_compact: Compact<u32> = Decode::decode(&mut cursor)
		.map_err(|e| QuantusError::Generic(format!("Failed to decode extra params length: {e:?}")))?;
	let extra_length = extra_length_compact.0 as usize;

	if cursor.len() < extra_length {
		return Err(QuantusError::Generic(format!("Extra params truncated: need {} bytes", extra_length)));
	}
	let mut extra_data = &cursor[..extra_length];
	cursor = &cursor[extra_length..];

	log_verbose!("Extra params length: {}", extra_length);

	// 4. Implicit Params (Length + Bytes)
	let implicit_length_compact: Compact<u32> = Decode::decode(&mut cursor)
		.map_err(|e| QuantusError::Generic(format!("Failed to decode implicit params length: {e:?}")))?;
	let implicit_length = implicit_length_compact.0 as usize;
	
	if cursor.len() < implicit_length {
		return Err(QuantusError::Generic(format!("Implicit params truncated: need {} bytes", implicit_length)));
	}
	let implicit_data = &cursor[..implicit_length];
	
	log_verbose!("Implicit params length: {}", implicit_length);


	// Decode Call Details
	let call_info = decode_runtime_call_direct(call_data)?;

	// Decode Extra Details (Nonce, Tip)
	// Extra params structure depends on the chain config.
	// Typically: Era (2 bytes usually) | Nonce (Compact) | Tip (Compact)
	// We need to try to decode them sequentially.
	
	let mut nonce: Option<u32> = None;
	let mut tip: Option<u128> = None;

	// Try to skip Era (usually first)
	// Era is Def: CheckMortality
	// Then Nonce: CheckNonce
	// Then Tip: ChargeTransactionPayment
	
	// Era is likely 1 or 2 bytes. 
	// Compact<u32> for Nonce.
	// Compact<u128> for Tip.
	
	if !extra_data.is_empty() {
		// Heuristic: try to skip era. Era::Immortal is 1 byte (0x00). Mortal is 2 bytes.
		// Let's look at first byte.
		let first_byte = extra_data[0];
		if first_byte == 0 {
			extra_data = &extra_data[1..]; // Immortal
		} else {
			// Mortal? 2 bytes?
			if extra_data.len() >= 2 {
				extra_data = &extra_data[2..]; 
			}
		}
		
		// Now try Nonce
		if let Ok(n) = <Compact<u32> as Decode>::decode(&mut extra_data) {
			nonce = Some(n.0);
			
			// Now try Tip
			if let Ok(t) = <Compact<u128> as Decode>::decode(&mut extra_data) {
				tip = Some(t.0);
			}
		}
	}

	// Display
	let (symbol, decimals) = crate::cli::send::get_chain_properties(&quantus_client).await?;

	log_print!("{}", "📋 Transaction Details".bright_cyan().bold());
	log_print!("");
	log_print!("{}  {}", "Version:".dimmed(), format!("0x{:02x}", version).bright_green());
	
	if let Some(n) = nonce {
		log_print!("{}  {}", "Nonce:".dimmed(), n.to_string().bright_yellow());
	}
	if let Some(t) = tip {
		let formatted_tip = crate::cli::send::format_balance(t, decimals);
		log_print!("{}  {} {}", "Tip:".dimmed(), formatted_tip.bright_yellow(), symbol.bright_green());
	}
	log_print!("");
	log_print!("{}", "📞 Call Information".bright_cyan().bold());
	log_print!("{}", call_info);

	if let Some(from_address) = extract_from_address(implicit_data) {
		log_print!("");
		log_print!("{}  {}", "From:".dimmed(), from_address.bright_cyan());
	}

	if let Some(to_address) = extract_to_address(call_data) {
		log_print!("{}  {}", "dest:".dimmed(), to_address.bright_green());
	}

	if let Some(amount) = extract_amount(call_data, decimals) {
		log_print!("{}  {} {}", "value:".dimmed(), amount.bright_yellow(), symbol.bright_green());
	}

	if let Some(wallet_name) = sign_and_send {
		log_print!("");
		log_print!("{}", "🔐 Signing and sending transaction...".bright_cyan().bold());

		let keypair = crate::wallet::load_keypair_from_wallet(&wallet_name, password, password_file)?;

		let nonce_value = nonce.ok_or_else(|| {
			QuantusError::Generic("Cannot sign transaction: nonce not found in payload".to_string())
		})?;

		let reconstructed_call = reconstruct_call_from_data(call_data)?;

		sign_and_submit_transaction(
			&quantus_client,
			&keypair,
			reconstructed_call,
			nonce_value,
			tip,
		).await?;
	} else if let Some(signature_hex) = signature {
		log_print!("");
		log_print!("{}", "🔐 Submitting pre-signed transaction...".bright_cyan().bold());

		let signature_bytes = hex::decode(signature_hex.strip_prefix("0x").unwrap_or(&signature_hex))
			.map_err(|e| QuantusError::Generic(format!("Invalid signature hex: {e:?}")))?;

		// Extract account ID from implicit data
		let account_id = extract_account_id_from_implicit(implicit_data)?;

		let reconstructed_call = reconstruct_call_from_data(call_data)?;

		submit_pre_signed_transaction(
			&quantus_client,
			reconstructed_call,
			&signature_bytes,
			&account_id,
			nonce,
			tip,
		).await?;
	}

	Ok(())
}

fn extract_from_address(implicit_data: &[u8]) -> Option<String> {
	if implicit_data.len() >= 32 {
		let account_bytes: [u8; 32] = match implicit_data[..32].try_into() {
			Ok(bytes) => bytes,
			Err(_) => return None,
		};
		let account_id = SpAccountId32::from(account_bytes);
		let ss58 = account_id.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));
		return Some(ss58);
	}
	None
}

fn extract_to_address(call_data: &[u8]) -> Option<String> {
	if call_data.len() < 3 {
		return None;
	}

	let pallet_index = call_data[0];
	let call_index = call_data[1];

	if pallet_index == 2 && call_index == 0 {
		if call_data.len() < 36 {
			return None;
		}

		let multiaddress_variant = call_data[2];
		if multiaddress_variant == 0x00 {
			let account_bytes: [u8; 32] = match call_data[3..35].try_into() {
				Ok(bytes) => bytes,
				Err(_) => return None,
			};
			let account_id = SpAccountId32::from(account_bytes);
			let ss58 = account_id.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189));
			return Some(ss58);
		}
	}

	None
}

fn extract_amount(call_data: &[u8], decimals: u8) -> Option<String> {
	if call_data.len() < 3 {
		return None;
	}

	let pallet_index = call_data[0];
	let call_index = call_data[1];

	if pallet_index == 2 && call_index == 0 {
		if call_data.len() < 36 {
			return None;
		}

		let multiaddress_variant = call_data[2];
		if multiaddress_variant == 0x00 {
			if call_data.len() < 36 {
				return None;
			}

			let mut amount_cursor = &call_data[35..];
			match <Compact<u128> as Decode>::decode(&mut amount_cursor) {
				Ok(amount_compact) => {
					let amount = amount_compact.0;
					return Some(crate::cli::send::format_balance(amount, decimals));
				},
				Err(_) => {},
			}
		}
	}

	None
}

fn reconstruct_call_from_data(call_data: &[u8]) -> Result<subxt::tx::DefaultPayload<crate::chain::quantus_subxt::api::balances::calls::types::TransferAllowDeath>> {
	if call_data.len() < 3 {
		return Err(QuantusError::Generic("Call data too short".to_string()));
	}

	let pallet_index = call_data[0];
	let call_index = call_data[1];

	if pallet_index == 2 && call_index == 0 {
		if call_data.len() < 36 {
			return Err(QuantusError::Generic("Call data too short for balances transfer".to_string()));
		}

		let mut args_cursor = &call_data[2..];
		
		// Decode MultiAddress (Dest)
		let dest: subxt::ext::subxt_core::utils::MultiAddress<subxt::ext::subxt_core::utils::AccountId32, ()> = 
			Decode::decode(&mut args_cursor)
			.map_err(|e| QuantusError::Generic(format!("Failed to decode destination: {e:?}")))?;
			
		// Decode Amount
		let amount_compact: Compact<u128> = Decode::decode(&mut args_cursor)
			.map_err(|e| QuantusError::Generic(format!("Failed to decode amount: {e:?}")))?;
		let amount = amount_compact.0;

		let transfer_call = crate::chain::quantus_subxt::api::tx().balances().transfer_allow_death(
			dest,
			amount,
		);

		return Ok(transfer_call);
	}

	Err(QuantusError::Generic(format!(
		"Unsupported call type: pallet={}, call={}. Only balances::transfer_allow_death is supported",
		pallet_index, call_index
	)))
}

fn extract_account_id_from_implicit(implicit_data: &[u8]) -> Result<subxt::ext::subxt_core::utils::AccountId32> {
	if implicit_data.len() >= 32 {
		let account_bytes: [u8; 32] = implicit_data[..32].try_into()
			.map_err(|_| QuantusError::Generic("Invalid account ID length in implicit data".to_string()))?;
		Ok(subxt::ext::subxt_core::utils::AccountId32::from(account_bytes))
	} else {
		Err(QuantusError::Generic("Implicit data too short for account ID".to_string()))
	}
}

async fn sign_and_submit_transaction(
	quantus_client: &QuantusClient,
	keypair: &crate::wallet::QuantumKeyPair,
	call: subxt::tx::DefaultPayload<crate::chain::quantus_subxt::api::balances::calls::types::TransferAllowDeath>,
	nonce: u32,
	tip: Option<u128>,
) -> Result<()> {
	log_verbose!("Reconstructed call: {:?}", call);
	log_verbose!("Using nonce from payload: {}", nonce);

	// Submit immediately without waiting for confirmation - just return the hash
	let tx_hash = crate::cli::common::submit_transaction_immediately_with_nonce(
		quantus_client,
		keypair,
		call,
		tip,
		nonce,
	)
	.await?;

	log_success!("✅ Transaction submitted successfully: {:?}", tx_hash);

	Ok(())
}

async fn submit_pre_signed_transaction(
	quantus_client: &QuantusClient,
	call: subxt::tx::DefaultPayload<crate::chain::quantus_subxt::api::balances::calls::types::TransferAllowDeath>,
	signature_bytes: &[u8],
	account_id: &subxt::ext::subxt_core::utils::AccountId32,
	nonce: Option<u32>,
	tip: Option<u128>,
) -> Result<()> {
	log_print!("⚠️  Hardware wallet pre-signed transaction submission is not yet implemented.");
	log_print!("   The --signature parameter was added but the submission logic needs to be completed.");
	log_print!("   Currently, the code tries to sign the transaction again locally, which causes signature validation to fail.");
	log_print!("");
	log_print!("   To complete hardware wallet support:");
	log_print!("   1. Parse the unsigned payload to extract signing data");
	log_print!("   2. Manually construct the SCALE-encoded extrinsic with the hardware wallet signature");
	log_print!("   3. Submit the raw extrinsic bytes to the chain");
	log_print!("");

	Err(QuantusError::Generic("Hardware wallet pre-signed transaction submission not implemented yet".to_string()))
}
