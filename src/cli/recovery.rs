use crate::{
	chain::quantus_subxt,
	cli::{common::resolve_address, progress_spinner::wait_for_tx_confirmation},
	log_print, log_success,
};
use clap::Subcommand;
// no colored output needed here
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

/// Recovery-related commands
#[derive(Subcommand, Debug)]
pub enum RecoveryCommands {
	/// Initiate recovery (rescuer starts)
	Initiate {
		/// Rescuer wallet name
		#[arg(long)]
		rescuer: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Password for rescuer wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Vouch for a recovery attempt (friend)
	Vouch {
		/// Friend wallet name (who vouches)
		#[arg(long)]
		friend: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Rescuer account (SS58 or wallet name)
		#[arg(long)]
		rescuer: String,
		/// Password for friend wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Claim recovery (rescuer claims after threshold and delay)
	Claim {
		/// Rescuer wallet name
		#[arg(long)]
		rescuer: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Password for rescuer wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Call as recovered (rescuer makes a call on behalf of lost)
	AsRecovered {
		/// Rescuer wallet name
		#[arg(long)]
		rescuer: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// High-level: balances.transfer_all
		#[arg(long, conflicts_with = "call")]
		balances_transfer_all: bool,
		/// Destination for transfer_all
		#[arg(long, requires = "balances_transfer_all")]
		dest: Option<String>,
		/// Keep alive for transfer_all
		#[arg(long, requires = "balances_transfer_all")]
		keep_alive: Option<bool>,
		/// Generic: hex-encoded SCALE RuntimeCall
		#[arg(long, conflicts_with = "balances_transfer_all")]
		call: Option<String>,
		/// Password for rescuer wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Close an active recovery (lost account stops a malicious attempt)
	Close {
		/// Lost wallet name (the recoverable account)
		#[arg(long)]
		lost: String,
		/// Rescuer account (SS58 or wallet name)
		#[arg(long)]
		rescuer: String,
		/// Password for lost wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Cancel recovered proxy (rescuer disables their own proxy)
	CancelProxy {
		/// Rescuer wallet name
		#[arg(long)]
		rescuer: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Password for rescuer wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Query: active recovery info
	Active {
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Rescuer account (SS58 or wallet name)
		#[arg(long)]
		rescuer: String,
	},

	/// Query: proxy-of (rescuer -> lost)
	ProxyOf {
		/// Rescuer account (SS58 or wallet name)
		#[arg(long)]
		rescuer: String,
	},

	/// Query: recovery config (recoverable)
	Config {
		/// Account to query (SS58 or wallet name)
		#[arg(long)]
		account: String,
	},
}

pub async fn handle_recovery_command(
	command: RecoveryCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		RecoveryCommands::Initiate { rescuer, lost, password, password_file } => {
			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;
			let lost_resolved = resolve_address(&lost)?;
			let lost_id_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_id_bytes: [u8; 32] = *lost_id_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_id_bytes);
			let call = quantus_subxt::api::tx()
				.recovery()
				.initiate_recovery(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id));
			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &rescuer_key, call, None)
					.await?;
			log_success!("✅ Initiate recovery submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			Ok(())
		},

		RecoveryCommands::Vouch { friend, lost, rescuer, password, password_file } => {
			let friend_key =
				crate::wallet::load_keypair_from_wallet(&friend, password, password_file)?;
			let lost_resolved = resolve_address(&lost)?;
			let rescuer_resolved = resolve_address(&rescuer)?;
			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_bytes: [u8; 32] = *lost_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_bytes);
			let rescuer_sp = SpAccountId32::from_ss58check(&rescuer_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid rescuer address: {e:?}"))
			})?;
			let rescuer_bytes: [u8; 32] = *rescuer_sp.as_ref();
			let rescuer_id = subxt::ext::subxt_core::utils::AccountId32::from(rescuer_bytes);
			let call = quantus_subxt::api::tx().recovery().vouch_recovery(
				subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id),
				subxt::ext::subxt_core::utils::MultiAddress::Id(rescuer_id),
			);
			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &friend_key, call, None)
					.await?;
			log_success!("✅ Vouch submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			Ok(())
		},

		RecoveryCommands::Claim { rescuer, lost, password, password_file } => {
			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;
			let lost_resolved = resolve_address(&lost)?;
			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_bytes: [u8; 32] = *lost_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_bytes);
			let call = quantus_subxt::api::tx()
				.recovery()
				.claim_recovery(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id));
			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &rescuer_key, call, None)
					.await?;
			log_success!("✅ Claim submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			Ok(())
		},

		RecoveryCommands::AsRecovered {
			rescuer,
			lost,
			balances_transfer_all,
			dest,
			keep_alive,
			call,
			password,
			password_file,
		} => {
			use quantus_subxt::api::runtime_types::pallet_balances::pallet::Call as BalancesCall;

			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;
			let lost_resolved = resolve_address(&lost)?;
			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_bytes: [u8; 32] = *lost_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_bytes);

			let inner_call: quantus_subxt::api::Call = if balances_transfer_all {
				let dest_str = dest.ok_or_else(|| {
					crate::error::QuantusError::Generic(
						"--dest is required with --balances-transfer-all".to_string(),
					)
				})?;
				let dest_resolved = resolve_address(&dest_str)?;
				let dest_sp = SpAccountId32::from_ss58check(&dest_resolved).map_err(|e| {
					crate::error::QuantusError::Generic(format!("Invalid dest address: {e:?}"))
				})?;
				let dest_bytes: [u8; 32] = *dest_sp.as_ref();
				let dest_id = subxt::ext::subxt_core::utils::AccountId32::from(dest_bytes);
				let keep = keep_alive.unwrap_or(false);
				quantus_subxt::api::Call::Balances(BalancesCall::transfer_all {
					dest: subxt::ext::subxt_core::utils::MultiAddress::Id(dest_id),
					keep_alive: keep,
				})
			} else if let Some(_hex_call) = call {
				return Err(crate::error::QuantusError::Generic(
					"--call (hex RuntimeCall) not yet supported; use --balances-transfer-all"
						.to_string(),
				));
			} else {
				return Err(crate::error::QuantusError::Generic(
					"Provide either --balances-transfer-all or --call".to_string(),
				));
			};

			let call = quantus_subxt::api::tx()
				.recovery()
				.as_recovered(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id), inner_call);

			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &rescuer_key, call, None)
					.await?;
			log_success!("✅ as_recovered submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			Ok(())
		},

		RecoveryCommands::Close { lost, rescuer, password, password_file } => {
			let lost_key = crate::wallet::load_keypair_from_wallet(&lost, password, password_file)?;
			let rescuer_resolved = resolve_address(&rescuer)?;
			let rescuer_sp = SpAccountId32::from_ss58check(&rescuer_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid rescuer address: {e:?}"))
			})?;
			let rescuer_bytes: [u8; 32] = *rescuer_sp.as_ref();
			let rescuer_id = subxt::ext::subxt_core::utils::AccountId32::from(rescuer_bytes);
			let call = quantus_subxt::api::tx()
				.recovery()
				.close_recovery(subxt::ext::subxt_core::utils::MultiAddress::Id(rescuer_id));
			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &lost_key, call, None)
					.await?;
			log_success!("✅ close_recovery submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			Ok(())
		},

		RecoveryCommands::CancelProxy { rescuer, lost, password, password_file } => {
			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;
			let lost_resolved = resolve_address(&lost)?;
			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_bytes: [u8; 32] = *lost_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_bytes);
			let call = quantus_subxt::api::tx()
				.recovery()
				.cancel_recovered(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id));
			let tx_hash =
				crate::cli::common::submit_transaction(&quantus_client, &rescuer_key, call, None)
					.await?;
			log_success!("✅ cancel_recovered submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			let _ = wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
			Ok(())
		},

		RecoveryCommands::Active { lost, rescuer } => {
			let lost_resolved = resolve_address(&lost)?;
			let rescuer_resolved = resolve_address(&rescuer)?;
			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_bytes: [u8; 32] = *lost_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_bytes);
			let rescuer_sp = SpAccountId32::from_ss58check(&rescuer_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid rescuer address: {e:?}"))
			})?;
			let rescuer_bytes: [u8; 32] = *rescuer_sp.as_ref();
			let rescuer_id = subxt::ext::subxt_core::utils::AccountId32::from(rescuer_bytes);
			let storage_addr =
				quantus_subxt::api::storage().recovery().active_recoveries(lost_id, rescuer_id);
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
			if let Some(active) = value {
				log_print!(
					"{}",
					serde_json::json!({
						"created": active.created,
						"deposit": active.deposit,
						"friends_vouched": active.friends.0.len(),
					})
				);
			} else {
				log_print!("{}", serde_json::json!({"active": false}));
			}
			Ok(())
		},

		RecoveryCommands::ProxyOf { rescuer } => {
			let rescuer_resolved = resolve_address(&rescuer)?;
			let rescuer_sp = SpAccountId32::from_ss58check(&rescuer_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid rescuer address: {e:?}"))
			})?;
			let rescuer_bytes: [u8; 32] = *rescuer_sp.as_ref();
			let rescuer_id = subxt::ext::subxt_core::utils::AccountId32::from(rescuer_bytes);
			let storage_addr = quantus_subxt::api::storage().recovery().proxy(rescuer_id);
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
			if let Some(lost_id) = value {
				log_print!("{}", serde_json::json!({"lost": format!("{}", lost_id)}));
			} else {
				log_print!("{}", serde_json::json!({"lost": null}));
			}
			Ok(())
		},

		RecoveryCommands::Config { account } => {
			let account_resolved = resolve_address(&account)?;
			let account_sp = SpAccountId32::from_ss58check(&account_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid account address: {e:?}"))
			})?;
			let account_bytes: [u8; 32] = *account_sp.as_ref();
			let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);
			let storage_addr = quantus_subxt::api::storage().recovery().recoverable(account_id);
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
			if let Some(cfg) = value {
				log_print!(
					"{}",
					serde_json::json!({
						"delay_period": cfg.delay_period,
						"deposit": cfg.deposit,
						"friends": cfg.friends.0.iter().map(|f| format!("{}", f)).collect::<Vec<_>>(),
						"threshold": cfg.threshold,
					})
				);
			} else {
				log_print!("{}", serde_json::json!({"recoverable": false}));
			}
			Ok(())
		},
	}
}
