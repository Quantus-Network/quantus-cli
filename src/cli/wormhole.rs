use crate::{error::Result, log_print, log_success};
use clap::Subcommand;
use colored::Colorize;
use hex;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use sp_core::crypto::{AccountId32, Ss58Codec};

use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::utils::felts_to_bytes;

/// Wormhole commands
#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
	/// Generate a new wormhole address and secret
	GenerateAddress,

	/// Spend funds from a wormhole address
	Spend {
		/// The hex-encoded secret key for the wormhole address
		#[arg(long)]
		secret: String,

		/// Recipient's on-chain address
		#[arg(short, long)]
		to: String,

		/// Amount to send (e.g., "10", "10.5", "0.0001")
		#[arg(short, long)]
		amount: String,

		/// Wallet name to sign the bridge transaction
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Handle wormhole commands
pub async fn handle_wormhole_command(command: WormholeCommands) -> Result<()> {
	match command {
		WormholeCommands::GenerateAddress => {
			log_print!("Generating new wormhole address...");

			let wormhole_pair = WormholePair::generate_new().map_err(|e| {
				crate::error::QuantusError::Generic(format!("Wormhole generation error: {:?}", e))
			})?;

			// The on-chain address for funding MUST be the unspendable account derived
			// from the secret key. The ZK proof verifies transfers to this address.
			let unspendable_account = UnspendableAccount::from_secret(&wormhole_pair.secret);
			let account_id_bytes: [u8; 32] = felts_to_bytes(&unspendable_account.account_id)
				.try_into()
				.expect("Failed to convert Vec<u8> to [u8; 32]");
			let account_id: AccountId32 = account_id_bytes.into();

			log_print!("{}", "XXXXXXXXXXXXXXX Quantus Wormhole Details XXXXXXXXXXXXXXXXX".yellow());
			log_print!(
				"{}: {}",
				"On-chain Address".green(),
				account_id.to_ss58check().bright_cyan()
			);
			log_print!(
				"{}: 0x{}",
				"Wormhole Address".green(),
				hex::encode(wormhole_pair.address).bright_cyan()
			);
			log_print!(
				"{}: 0x{}",
				"Secret Key      ".green(),
				hex::encode(wormhole_pair.secret).bright_cyan()
			);
			log_print!(
				"{}",
				"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".yellow()
			);

			log_success!("Wormhole address generated successfully!");
		},
		WormholeCommands::Spend {
			secret: _,
			to: _,
			amount: _,
			from: _,
			password: _,
			password_file: _,
		} => {
			log_print!("🚀 Initiating wormhole spend...");
		},
	}
	Ok(())
}
