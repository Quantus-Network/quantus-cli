//! Decoding utilities for referendum proposals

use crate::error::QuantusError;
use codec::Decode;
use colored::Colorize;

/// Decode preimage call data into human-readable format
pub async fn decode_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	hash: &subxt::utils::H256,
	len: u32,
) -> crate::error::Result<String> {
	// Fetch preimage from storage
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let preimage_addr = crate::chain::quantus_subxt::api::storage()
		.preimage()
		.preimage_for((*hash, len));

	let preimage_result = storage_at.fetch(&preimage_addr).await;

	let content = match preimage_result {
		Ok(Some(bounded_vec)) => bounded_vec.0,
		Ok(None) =>
			return Err(QuantusError::Generic(format!("Preimage not found for hash {:?}", hash))),
		Err(e) => return Err(QuantusError::Generic(format!("Error fetching preimage: {:?}", e))),
	};

	// Decode using direct Decode trait (RuntimeCall implements it via DecodeAsType derive)
	decode_runtime_call_direct(&content)
}

/// Decode RuntimeCall directly using Decode trait
fn decode_runtime_call_direct(data: &[u8]) -> crate::error::Result<String> {
	// First, let's try to understand the call structure by reading indices
	if data.len() < 3 {
		return Err(QuantusError::Generic("Call data too short".to_string()));
	}

	let pallet_index = data[0];
	let inner_index = data[1];
	let call_index = data[2];

	match (pallet_index, inner_index, call_index) {
		// System pallet (0, 0, X)
		// Special case: if call_index looks like Compact (high value like 0xe8),
		// it might be remark (call 0) where the call index byte is omitted
		(0, 0, idx) if idx > 100 => {
			// Likely remark (call 0) with Compact-encoded Vec starting at byte 2
			decode_system_remark_no_index(&data[2..])
		},
		(0, 0, _) => decode_system_call(&data[2..]),

		// TreasuryPallet (18, 5, X) where X is any spend variant (11, 15, 19, etc.)
		// Different indices represent different value ranges/encodings
		(18, 5, _) => decode_treasury_spend_call(&data[3..]),

		// Unknown
		_ => Ok(format!(
			"   {}  {} {} {}\n   {}  {} bytes\n   {}:\n   {}",
			"Call Indices:".dimmed(),
			pallet_index,
			inner_index,
			call_index,
			"Args:".dimmed(),
			data.len() - 3,
			"Raw Hex".dimmed(),
			hex::encode(&data[3..]).bright_green()
		)),
	}
}

/// Decode System::remark when call index byte is omitted (call 0)
fn decode_system_remark_no_index(args: &[u8]) -> crate::error::Result<String> {
	// args starts directly with Compact-encoded Vec<u8>
	let mut cursor = args;
	let remark_bytes: Vec<u8> = Vec::decode(&mut cursor)
		.map_err(|e| QuantusError::Generic(format!("Failed to decode remark: {:?}", e)))?;
	let remark_str = String::from_utf8_lossy(&remark_bytes);

	Ok(format!(
		"   {}  {}\n   {}  {}\n   {}:\n     {} \"{}\"",
		"Pallet:".dimmed(),
		"System".bright_cyan(),
		"Call:".dimmed(),
		"remark".bright_yellow(),
		"Parameters".dimmed(),
		"message:".dimmed(),
		remark_str.bright_green()
	))
}

/// Decode System pallet calls
fn decode_system_call(data_from_call: &[u8]) -> crate::error::Result<String> {
	if data_from_call.is_empty() {
		return Err(QuantusError::Generic("Empty system call data".to_string()));
	}

	let call_index = data_from_call[0];
	let args = &data_from_call[1..];

	match call_index {
		0 => {
			// remark - standard Vec<u8>
			let mut cursor = args;
			let remark_bytes: Vec<u8> = Vec::decode(&mut cursor)
				.map_err(|e| QuantusError::Generic(format!("Failed to decode remark: {:?}", e)))?;
			let remark_str = String::from_utf8_lossy(&remark_bytes);

			Ok(format!(
				"   {}  {}\n   {}  {}\n   {}:\n     {} \"{}\"",
				"Pallet:".dimmed(),
				"System".bright_cyan(),
				"Call:".dimmed(),
				"remark".bright_yellow(),
				"Parameters".dimmed(),
				"message:".dimmed(),
				remark_str.bright_green()
			))
		},
		1 => {
			// remark_with_event - has different encoding, try decoding from byte 1
			let remark_str = if args.len() > 1 {
				String::from_utf8_lossy(&args[1..])
			} else {
				String::from_utf8_lossy(args)
			};

			Ok(format!(
				"   {}  {}\n   {}  {}\n   {}:\n     {} \"{}\"",
				"Pallet:".dimmed(),
				"System".bright_cyan(),
				"Call:".dimmed(),
				"remark_with_event".bright_yellow(),
				"Parameters".dimmed(),
				"message:".dimmed(),
				remark_str.bright_green()
			))
		},
		7 => {
			// set_code
			Ok(format!(
				"   {}  {}\n   {}  {} {}\n   {}  {}",
				"Pallet:".dimmed(),
				"System".bright_cyan(),
				"Call:".dimmed(),
				"set_code".bright_yellow(),
				"(Runtime Upgrade)".dimmed(),
				"Parameters:".dimmed(),
				"<WASM binary>".bright_green()
			))
		},
		_ => Ok(format!(
			"   {}  {}\n   {}  {} (index {})",
			"Pallet:".dimmed(),
			"System".bright_cyan(),
			"Call:".dimmed(),
			"unknown".yellow(),
			call_index
		)),
	}
}

/// Decode TreasuryPallet::spend call arguments
/// The amount is stored as variable-length u128 in little-endian
fn decode_treasury_spend_call(args: &[u8]) -> crate::error::Result<String> {
	use sp_core::crypto::Ss58Codec;

	crate::log_verbose!("Decoding treasury spend, args length: {} bytes", args.len());
	crate::log_verbose!("Args hex: {}", hex::encode(args));

	if args.len() < 34 {
		return Err(QuantusError::Generic(format!(
			"Args too short for treasury spend: {} bytes (expected 40-42)",
			args.len()
		)));
	}

	// Structure (discovered through empirical analysis):
	// - asset_kind: Box<()> = 0 bytes (unit type has no encoding)
	// - amount: u128 = variable bytes (7-8 bytes typically) as little-endian
	// - beneficiary: Box<MultiAddress::Id(AccountId32)> = 32 bytes (no variant byte!)
	// - valid_from: Option<u32> = 1 byte (0x00 for None)

	// The amount length varies based on the value:
	// - Small values (< 256TB): 7 bytes
	// - Larger values: 8+ bytes
	// Total length is typically 40 bytes (7+32+1) or 42 bytes (8+32+1) or similar

	// Calculate amount bytes length: total - 32 (beneficiary) - 1 (valid_from)
	let amount_bytes_len = args.len() - 32 - 1;
	if amount_bytes_len > 16 || amount_bytes_len < 1 {
		return Err(QuantusError::Generic(format!(
			"Invalid amount bytes length: {}",
			amount_bytes_len
		)));
	}

	// Decode amount: first N bytes as little-endian u128
	let mut amount_bytes_extended = [0u8; 16];
	amount_bytes_extended[..amount_bytes_len].copy_from_slice(&args[..amount_bytes_len]);
	let amount = u128::from_le_bytes(amount_bytes_extended);

	// Decode beneficiary: starts after amount bytes, 32 bytes
	let beneficiary_start = amount_bytes_len;
	let account_bytes: [u8; 32] = args[beneficiary_start..beneficiary_start + 32]
		.try_into()
		.map_err(|_| QuantusError::Generic("Failed to extract beneficiary bytes".to_string()))?;
	let sp_account = sp_core::crypto::AccountId32::from(account_bytes);
	let ss58 = sp_account.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(42));
	let beneficiary_str = format!("{} ({}...{})", ss58, &ss58[..8], &ss58[ss58.len() - 6..]);

	// Decode valid_from: last byte
	let valid_from_byte = args[args.len() - 1];
	let valid_from_str = if valid_from_byte == 0 {
		"None (immediate)".to_string()
	} else {
		format!("Some (byte: 0x{:02x})", valid_from_byte)
	};

	// Format amount in QUAN (1 QUAN = 10^12)
	let quan = amount as f64 / 1_000_000_000_000.0;

	Ok(format!(
		"   {}  {}\n   {}  {}\n   {}:\n     {} {} {} ({} raw)\n     {} {}\n     {} {}\n\n   {}  {}",
		"Pallet:".dimmed(),
		"TreasuryPallet".bright_cyan(),
		"Call:".dimmed(),
		"spend".bright_yellow(),
		"Parameters".dimmed(),
		"amount:".dimmed(),
		quan.to_string().bright_green().bold(),
		"QUAN".bright_green(),
		amount,
		"beneficiary:".dimmed(),
		beneficiary_str.bright_green(),
		"valid_from:".dimmed(),
		valid_from_str.bright_green(),
		"💡 Info:".cyan(),
		"Vote YES if you approve this Treasury spend, NO to reject.".cyan()
	))
}
