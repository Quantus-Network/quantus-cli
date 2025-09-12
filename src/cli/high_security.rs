use crate::{
	chain::quantus_subxt, cli::{address_format::QuantusSS58, progress_spinner::wait_for_tx_confirmation}, log_error, log_print,
	log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

/// High-Security (Reversible) commands
#[derive(Subcommand, Debug)]
pub enum HighSecurityCommands {
	/// Check High-Security status for an account
	Status {
		/// Account address to check (SS58 or wallet name)
		#[arg(long)]
		account: String,
	},

	/// Set High-Security (reversibility) for an account
	Set {
		/// Interceptor account (SS58 or wallet name)
		#[arg(long)]
		interceptor: String,

		/// Delay in blocks (mutually exclusive with --delay-seconds)
		#[arg(long, conflicts_with = "delay_seconds")]
		delay_blocks: Option<u32>,

		/// Delay in seconds (mutually exclusive with --delay-blocks)
		#[arg(long, conflicts_with = "delay_blocks")]
		delay_seconds: Option<u64>,

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
		HighSecurityCommands::Status { account } => {
			log_print!("🔍 Checking High Security Status");

			// Resolve account address
			let resolved_account = crate::cli::common::resolve_address(&account)?;
			let account_id_sp = SpAccountId32::from_ss58check(&resolved_account).map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Invalid account address '{resolved_account}': {e:?}"
				))
			})?;
			let account_id_bytes: [u8; 32] = *account_id_sp.as_ref();
			let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_id_bytes);

			// Convert account to Quantus SS58 format
			let account_ss58 = account_id.to_quantus_ss58();

			// Query storage
			let storage_addr = quantus_subxt::api::storage()
				.reversible_transfers()
				.high_security_accounts(account_id);
			let latest = quantus_client.get_latest_block().await?;
			let value = quantus_client
				.client()
				.storage()
				.at(latest)
				.fetch(&storage_addr)
				.await
				.map_err(|e| {
					crate::error::QuantusError::NetworkError(format!("Fetch error: {e:?}"))
				})?;

			log_print!("📋 Account: {}", account_ss58.bright_cyan());

			if let Some(high_security_data) = value {
				log_success!("✅ High Security: ENABLED");

				// Convert interceptor to Quantus SS58 format
				let interceptor_ss58 = high_security_data.interceptor.to_quantus_ss58();

				log_print!("🛡️  Guardian/Interceptor: {}", interceptor_ss58.bright_green());

				// Format delay display
				match high_security_data.delay {
					quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp::BlockNumber(blocks) => {
						log_print!("⏱️  Delay: {} blocks", blocks.to_string().bright_yellow());
					},
					quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp::Timestamp(ms) => {
						let seconds = ms / 1000;
						log_print!("⏱️  Delay: {} seconds", seconds.to_string().bright_yellow());
					},
				}
			} else {
				log_print!("❌ High Security: DISABLED");
				log_print!("💡 This account does not have high-security reversibility enabled.");
			}

			Ok(())
		},

		HighSecurityCommands::Set {
			interceptor,
			delay_blocks,
			delay_seconds,
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
			let delay_value = match (delay_blocks, delay_seconds) {
				(Some(blocks), None) => HsDelay::BlockNumber(blocks),
				(None, Some(seconds)) => HsDelay::Timestamp(seconds * 1000), // Convert seconds to milliseconds
				(None, None) => {
					log_error!("❌ You must specify either --delay-blocks or --delay-seconds");
					return Err(crate::error::QuantusError::Generic(
						"Missing delay parameter".to_string(),
					));
				},
				(Some(_), Some(_)) =>
					unreachable!("clap conflicts_with ensures these are mutually exclusive"),
			};

			log_verbose!("✍️  Creating set_high_security extrinsic...");

			// Current generated metadata expects (delay, interceptor).
			let tx_call = quantus_subxt::api::tx().reversible_transfers().set_high_security(
				delay_value,
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
