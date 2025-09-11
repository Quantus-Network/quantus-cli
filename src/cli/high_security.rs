use crate::{
	chain::quantus_subxt, cli::progress_spinner::wait_for_tx_confirmation, log_error, log_print,
	log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

/// High-Security (Reversible) commands
#[derive(Subcommand, Debug)]
pub enum HighSecurityCommands {
	/// Set High-Security (reversibility) for an account
	Set {
		/// Interceptor account (SS58 or wallet name)
		#[arg(long)]
		interceptor: String,

		/// Delay in blocks (mutually exclusive with --delay-ms)
		#[arg(long, conflicts_with = "delay_ms")]
		delay_blocks: Option<u32>,

		/// Delay in milliseconds (mutually exclusive with --delay-blocks)
		#[arg(long, conflicts_with = "delay_blocks")]
		delay_ms: Option<u64>,

		/// Wallet name to sign with
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Handle high security commands
pub async fn handle_high_security_command(
	command: HighSecurityCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		HighSecurityCommands::Set {
			interceptor,
			delay_blocks,
			delay_ms,
			from,
			password,
			password_file,
		} => {
			log_print!("🛡️  Set High Security");
			log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

			// Resolve interceptor: allow wallet name or SS58 address
			let interceptor_resolved = crate::cli::common::resolve_address(&interceptor)?;
			let interceptor_sp =
				SpAccountId32::from_ss58check(&interceptor_resolved).map_err(|e| {
					crate::error::QuantusError::Generic(format!(
						"Invalid interceptor address '{interceptor_resolved}': {e:?}"
					))
				})?;
			let interceptor_bytes: [u8; 32] = *interceptor_sp.as_ref();
			let interceptor_subxt =
				subxt::ext::subxt_core::utils::AccountId32::from(interceptor_bytes);

			// Build delay enum for set_high_security
			use quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay as HsDelay;
			let delay_value = match (delay_blocks, delay_ms) {
				(Some(blocks), None) => HsDelay::BlockNumber(blocks),
				(None, Some(ms)) => HsDelay::Timestamp(ms),
				(None, None) => {
					log_error!("❌ You must specify either --delay-blocks or --delay-ms");
					return Err(crate::error::QuantusError::Generic(
						"Missing delay parameter".to_string(),
					));
				},
				(Some(_), Some(_)) =>
					unreachable!("clap conflicts_with ensures these are mutually exclusive"),
			};

			log_verbose!("✍️  Creating set_high_security extrinsic...");

			// Current generated metadata expects (delay, interceptor, recoverer).
			// Use recoverer = interceptor for zero-delay self-recovery flow.
			let tx_call = quantus_subxt::api::tx().reversible_transfers().set_high_security(
				delay_value,
				interceptor_subxt.clone(),
				interceptor_subxt,
			);

			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &keypair, tx_call, None)
					.await?;

			log_success!("✅ SUCCESS High security set! Hash: 0x{}", hex::encode(tx_hash.as_ref()));

			let success = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			if success {
				log_success!("🎉 FINISHED High security configuration confirmed on-chain");
			} else {
				log_error!("❌ Transaction failed or not included");
			}

			Ok(())
		},
	}
}
