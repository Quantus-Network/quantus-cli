use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::common::{create_unsigned_transaction, display_hardware_signing_info, export_signing_payload, generate_qr_code_for_signing, get_transaction_details, submit_signed_transaction},
	error::Result,
	log_error, log_info, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;

/// Hardware wallet commands for airgapped signing
#[derive(Subcommand, Debug)]
pub enum HardwareCommands {
	/// Create an unsigned transaction ready for hardware wallet signing
	CreateUnsigned {
		/// The recipient's account address or wallet name
		#[arg(short, long)]
		to: String,

		/// Amount to send (e.g., "10", "10.5", "0.0001")
		#[arg(short, long)]
		amount: String,

		/// Wallet name to send from
		#[arg(short, long)]
		from: String,

		/// Optional tip amount to prioritize the transaction (e.g., "1", "0.5")
		#[arg(long)]
		tip: Option<String>,

		/// Generate QR code for airgapped signing (default: true)
		#[arg(long, default_value = "true")]
		qr: bool,

		/// Export transaction details as JSON instead of displaying
		#[arg(long)]
		json: bool,
	},

	/// Submit a transaction signed by hardware wallet
	SubmitSigned {
		/// The recipient's account address or wallet name
		#[arg(short, long)]
		to: String,

		/// Amount that was sent (for verification)
		#[arg(short, long)]
		amount: String,

		/// Wallet name to send from
		#[arg(short, long)]
		from: String,

		/// Signature from hardware wallet (hex-encoded)
		#[arg(short, long)]
		signature: String,

		/// Optional tip amount that was used (for verification)
		#[arg(long)]
		tip: Option<String>,

		/// Wait for transaction finalization instead of just best block inclusion
		#[arg(long)]
		finalized: bool,
	},
}

/// Handle hardware wallet commands
pub async fn handle_hardware_command(command: HardwareCommands, node_url: &str) -> Result<()> {
	match command {
		HardwareCommands::CreateUnsigned { to, amount, from, tip, qr, json } => {
			handle_create_unsigned(to, amount, from, tip, qr, json, node_url).await
		},
		HardwareCommands::SubmitSigned { to, amount, from, signature, tip, finalized } => {
			handle_submit_signed(to, amount, from, signature, tip, finalized, node_url).await
		},
	}
}

/// Create unsigned transaction for hardware wallet signing
async fn handle_create_unsigned(
	to: String,
	amount: String,
	from: String,
	tip: Option<String>,
	generate_qr: bool,
	json_output: bool,
	node_url: &str,
) -> Result<()> {
	log_info!("🔓 Creating unsigned transaction for hardware wallet...");

	// Create quantus client
	let quantus_client = QuantusClient::new(node_url).await?;

	// Parse amount
	let (raw_amount, formatted_amount) = crate::cli::send::validate_and_format_amount(&quantus_client, &amount).await?;

	// Resolve addresses
	let resolved_to = crate::cli::common::resolve_address(&to)?;
	let keypair = crate::wallet::load_keypair_from_wallet(&from, None, None)?;
	let from_address = keypair.to_account_id_ss58check();

	log_verbose!("🚀 Creating transfer of {} from {} to {}", formatted_amount, from_address.bright_cyan(), resolved_to.bright_green());

	// Parse tip if provided
	let tip_amount = if let Some(tip_str) = tip {
		let (_, decimals) = crate::cli::send::get_chain_properties(&quantus_client).await?;
		Some(crate::cli::send::parse_amount_with_decimals(&tip_str, decimals)?)
	} else {
		None
	};

	// Create the transfer call
	let to_account_id_sp = sp_core::crypto::AccountId32::from_ss58check(&resolved_to)
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Invalid destination address: {e:?}"))
		})?;
	let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
	let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

	let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id),
		raw_amount,
	);

	// Create unsigned transaction
	let partial_tx = create_unsigned_transaction(&quantus_client, &keypair, transfer_call, tip_amount).await?;

	// Export signing payload
	let payload_bytes = export_signing_payload(&partial_tx);

	// Get transaction details
	let details = get_transaction_details(&partial_tx, &from_address);

	if json_output {
		// Output as JSON for external tools
		let mut json_output = details.as_object().unwrap().clone();
		json_output.insert("qr_code".to_string(), if generate_qr {
			let qr = generate_qr_code_for_signing(&payload_bytes)?;
			serde_json::Value::String(qr)
		} else {
			serde_json::Value::Null
		});
		log_print!("{}", serde_json::to_string_pretty(&json_output)?);
	} else {
		// Display human-readable information
		let qr_code = if generate_qr {
			Some(generate_qr_code_for_signing(&payload_bytes)?)
		} else {
			None
		};

		display_hardware_signing_info(&partial_tx, &from_address, &payload_bytes, qr_code.as_deref());
	}

	log_success!("✅ Unsigned transaction created successfully!");
	log_info!("💡 Next step: Sign the payload with your hardware wallet and use 'quantus hardware submit-signed' to submit");

	Ok(())
}

/// Submit transaction signed by hardware wallet
async fn handle_submit_signed(
	to: String,
	amount: String,
	from: String,
	signature_hex: String,
	tip: Option<String>,
	finalized: bool,
	node_url: &str,
) -> Result<()> {
	log_info!("🔐 Submitting transaction signed by hardware wallet...");

	// Create quantus client
	let quantus_client = QuantusClient::new(node_url).await?;

	// Parse amount
	let (raw_amount, formatted_amount) = crate::cli::send::validate_and_format_amount(&quantus_client, &amount).await?;

	// Resolve addresses
	let resolved_to = crate::cli::common::resolve_address(&to)?;
	let keypair = crate::wallet::load_keypair_from_wallet(&from, None, None)?;
	let from_address = keypair.to_account_id_ss58check();

	log_verbose!("🚀 Submitting transfer of {} from {} to {}", formatted_amount, from_address.bright_cyan(), resolved_to.bright_green());

	// Parse tip if provided
	let tip_amount = if let Some(tip_str) = tip {
		let (_, decimals) = crate::cli::send::get_chain_properties(&quantus_client).await?;
		Some(crate::cli::send::parse_amount_with_decimals(&tip_str, decimals)?)
	} else {
		None
	};

	// Decode signature
	let signature_bytes = hex::decode(&signature_hex).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Invalid signature hex: {e:?}"))
	})?;

	// Create the transfer call (same as in create-unsigned)
	let to_account_id_sp = sp_core::crypto::AccountId32::from_ss58check(&resolved_to)
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Invalid destination address: {e:?}"))
		})?;
	let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
	let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

	let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id),
		raw_amount,
	);

	// Create unsigned transaction (to get the exact same partial transaction)
	let partial_tx = create_unsigned_transaction(&quantus_client, &keypair, transfer_call, tip_amount).await?;

	// Submit signed transaction
	let tx_hash = submit_signed_transaction(&quantus_client, &keypair, partial_tx, &signature_bytes, finalized).await?;

	log_print!("✅ {} Transaction submitted! Hash: {:?}", "SUCCESS".bright_green().bold(), tx_hash);
	log_success!("🎉 {} Hardware wallet transaction completed!", "FINISHED".bright_green().bold());

	Ok(())
}