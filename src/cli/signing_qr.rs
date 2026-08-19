//! `quantus signing-qr` — print a signing request and stop there.
//!
//! The signing flow in [`crate::cli::cold_signing`] shows the same QR, then
//! waits to scan the signature back and submit it. This command is the first
//! half on its own: point it at an address, get the QR, scan it with the device
//! under test. Nothing is submitted and no wallet has to be imported first,
//! which is what makes it usable for checking how a signer displays a call.
use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::{
		cold_signing::{build_raw_signer_payload, capture_tx_context},
		common::resolve_address_with_subxt_account_id,
		send::parse_amount,
	},
	error::{QuantusError, Result},
	log_print, log_success, log_verbose,
	qr::{display_ur_until_enter, render_ur_frames, SignRequest},
};
use colored::Colorize;
use subxt::client::OfflineClientT;

/// Builds the request for [`from`] and prints it as a QR.
///
/// The call is a sample transfer unless `call_data` names one, so any call the
/// signer might have to display can be checked by passing its bytes.
pub async fn handle_signing_qr_command(
	from: String,
	to: Option<String>,
	amount: String,
	call_data: Option<String>,
	tip: Option<String>,
	nonce: Option<u32>,
	node_url: &str,
) -> Result<()> {
	let (signer_address, signer_account) = resolve_address_with_subxt_account_id(&from)?;

	let client = QuantusClient::new(node_url).await?;
	let tip = match tip {
		Some(ref value) => parse_amount(&client, value).await?,
		None => 0,
	};
	let account = sp_core::crypto::AccountId32::new(signer_account.0);
	let context = capture_tx_context(&client, &account, tip, nonce).await?;
	let state = client.client().client_state();

	let raw_payload = match call_data {
		Some(ref hex_call) => {
			let mut raw = decode_call_data(hex_call)?;
			// The same extensions build_raw_signer_payload appends to a typed
			// call, for bytes that are already a call.
			raw.extend_from_slice(&build_raw_signer_payload(&state, &EmptyCall, &context)?);
			raw
		},
		None => {
			let destination = match to {
				Some(ref address) => resolve_address_with_subxt_account_id(address)?.1,
				None => signer_account,
			};
			let value = parse_amount(&client, &amount).await?;
			let call = quantus_subxt::api::tx().balances().transfer_allow_death(
				subxt::ext::subxt_core::utils::MultiAddress::Id(destination),
				value,
			);
			build_raw_signer_payload(&state, &call, &context)?
		},
	};

	let request = SignRequest::new(signer_address.clone(), raw_payload.clone());
	let parts = quantus_ur::encode_bytes(&request.encode())
		.map_err(|e| QuantusError::Generic(format!("Failed to UR-encode the request: {e:?}")))?;

	log_print!("");
	log_print!("{}", "Signing request".bright_cyan().bold());
	log_print!("   Signer:  {}", signer_address.bright_cyan());
	log_print!("   Nonce:   {}", context.nonce);
	log_print!("   Payload: {} bytes", raw_payload.len());
	log_verbose!("   Payload hex: 0x{}", hex::encode(&raw_payload));
	log_print!("");
	// Reuses the signing flow's own display, so a request too big for one frame
	// animates here exactly as it does when the CLI is really asking to be signed.
	display_ur_until_enter(
		&render_ur_frames(&parts)?,
		"📱 Scan this QR with the signer under test, then press Enter here…",
	)
	.await?;
	log_success!("Nothing was submitted: this prints the request and stops.");
	Ok(())
}

/// A call with no bytes of its own, so [`build_raw_signer_payload`] can be used
/// for its extensions alone when the call is supplied as raw bytes.
struct EmptyCall;

impl subxt::tx::Payload for EmptyCall {
	fn encode_call_data_to(
		&self,
		_metadata: &subxt::Metadata,
		_out: &mut Vec<u8>,
	) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
		Ok(())
	}
}

fn decode_call_data(call_data: &str) -> Result<Vec<u8>> {
	let bytes = hex::decode(call_data.trim().trim_start_matches("0x"))
		.map_err(|e| QuantusError::Generic(format!("Call data is not hex: {e}")))?;
	if bytes.len() < 2 {
		return Err(QuantusError::Generic(
			"Call data must be at least a pallet and call index".to_string(),
		));
	}
	Ok(bytes)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn call_data_is_read_with_or_without_the_hex_prefix() {
		assert_eq!(decode_call_data("0x0200").unwrap(), vec![0x02, 0x00]);
		assert_eq!(decode_call_data(" 0200 ").unwrap(), vec![0x02, 0x00]);
	}

	#[test]
	fn call_data_shorter_than_an_index_pair_is_refused() {
		for input in ["", "0x", "0x02", "nothex"] {
			assert!(decode_call_data(input).is_err(), "call data {input:?} was accepted");
		}
	}
}
