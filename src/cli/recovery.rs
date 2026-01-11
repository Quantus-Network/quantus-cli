use crate::{
	chain::quantus_subxt, cli::common::resolve_address, log_error, log_print, log_success,
};
use clap::Subcommand;
// no colored output needed here
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

// Base unit (QUAN) decimals for amount conversions
const QUAN_DECIMALS: u128 = 1_000_000_000_000; // 10^12

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

	/// Recover all funds from the lost account to a destination
	RecoverAll {
		/// Rescuer wallet name
		#[arg(long)]
		rescuer: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Destination to receive the recovered funds
		#[arg(long)]
		dest: String,
		/// Keep the lost account alive
		#[arg(long, default_value_t = true)]
		keep_alive: bool,
		/// Password for rescuer wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Recover a specific amount (in QUAN units) from the lost account to destination
	RecoverAmount {
		/// Rescuer wallet name
		#[arg(long)]
		rescuer: String,
		/// Lost account (SS58 or wallet name)
		#[arg(long)]
		lost: String,
		/// Destination to receive the recovered funds
		#[arg(long)]
		dest: String,
		/// Amount in QUAN (human units) - multiplied by chain decimals
		#[arg(long, value_name = "AMOUNT_QUAN")]
		amount_quan: u128,
		/// Keep the lost account alive
		#[arg(long, default_value_t = true)]
		keep_alive: bool,
		/// Password for rescuer wallet
		#[arg(short, long)]
		password: Option<String>,
		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
}

pub async fn handle_recovery_command(
	command: RecoveryCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		RecoveryCommands::Initiate { rescuer, lost, password, password_file } => {
			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;
			let rescuer_addr = rescuer_key.to_account_id_ss58check();
			log_print!("🔑 Rescuer: {}", rescuer);
			log_print!("🔑 Rescuer address: {}", rescuer_addr);
			let lost_resolved = resolve_address(&lost)?;
			let lost_id_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let lost_id_bytes: [u8; 32] = *lost_id_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_id_bytes);
			let call = quantus_subxt::api::tx()
				.recovery()
				.initiate_recovery(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id));

			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&rescuer_key,
				call,
				None,
				execution_mode,
			)
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to submit initiate_recovery transaction: {e}"
				))
			})?;
			log_success!("✅ Initiate recovery submitted successfully {:?}", tx_hash);
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
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&friend_key,
				call,
				None,
				execution_mode,
			)
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to submit vouch_recovery transaction: {e}"
				))
			})?;
			log_success!("✅ Vouch submitted successfully {:?}", tx_hash);
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
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&rescuer_key,
				call,
				None,
				execution_mode,
			)
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to submit claim_recovery transaction: {e}"
				))
			})?;

			log_success!("✅ Claim submitted successfully {:?}", tx_hash);
		},

		RecoveryCommands::RecoverAll {
			rescuer,
			lost,
			dest,
			keep_alive,
			password,
			password_file,
		} => {
			use quantus_subxt::api::runtime_types::pallet_balances::pallet::Call as BalancesCall;

			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;
			let rescuer_addr = rescuer_key.to_account_id_ss58check();
			log_print!("🔑 Rescuer: {}", rescuer);
			log_print!("🔑 Rescuer address: {}", rescuer_addr);

			let lost_resolved = resolve_address(&lost)?;
			let dest_resolved = resolve_address(&dest)?;
			log_print!("🆘 Lost input: {} -> {}", lost, lost_resolved);
			log_print!("🎯 Dest input: {} -> {}", dest, dest_resolved);
			log_print!("🛟 keep_alive: {}", keep_alive);

			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let dest_sp = SpAccountId32::from_ss58check(&dest_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid dest address: {e:?}"))
			})?;

			let lost_id_bytes: [u8; 32] = *lost_sp.as_ref();
			let dest_id_bytes: [u8; 32] = *dest_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_id_bytes);
			let dest_id = subxt::ext::subxt_core::utils::AccountId32::from(dest_id_bytes);

			// Check proxy mapping for rescuer
			let rescuer_sp = SpAccountId32::from_ss58check(&rescuer_addr).map_err(|e| {
				crate::error::QuantusError::Generic(format!(
					"Invalid rescuer address from wallet: {e:?}"
				))
			})?;
			let rescuer_id_bytes: [u8; 32] = *rescuer_sp.as_ref();
			let rescuer_id = subxt::ext::subxt_core::utils::AccountId32::from(rescuer_id_bytes);
			let proxy_storage = quantus_subxt::api::storage().recovery().proxy(rescuer_id);
			let latest = quantus_client.get_latest_block().await?;
			let proxy_result =
				quantus_client.client().storage().at(latest).fetch(&proxy_storage).await;
			let proxy_of = match proxy_result {
				Ok(Some(proxy)) => {
					log_print!("🧩 Proxy mapping: rescuer proxies -> {}", format!("{}", proxy));
					Some(proxy)
				},
				Ok(None) => {
					log_error!(
						"❌ No proxy mapping found for rescuer - recovery not set up properly"
					);
					return Err(crate::error::QuantusError::Generic(
						"Rescuer has no proxy mapping. Recovery process may not be properly set up.".to_string()
					));
				},
				Err(e) => {
					log_error!("❌ Proxy mapping fetch error: {:?}", e);
					return Err(crate::error::QuantusError::NetworkError(format!(
						"Failed to check proxy mapping: {e:?}"
					)));
				},
			};

			// Validate that the proxy points to the correct lost account
			if let Some(proxy) = proxy_of {
				let proxy_addr = format!("{proxy}");
				if proxy_addr != lost_resolved {
					log_error!(
						"❌ Proxy mismatch! Rescuer proxies {} but we're trying to recover {}",
						proxy_addr,
						lost_resolved
					);
					return Err(crate::error::QuantusError::Generic(format!(
						"Proxy mismatch: rescuer proxies {proxy_addr} but target is {lost_resolved}"
					)));
				}
				log_print!("✅ Proxy validation successful");
			}

			let inner_call = quantus_subxt::api::Call::Balances(BalancesCall::transfer_all {
				dest: subxt::ext::subxt_core::utils::MultiAddress::Id(dest_id),
				keep_alive,
			});
			log_print!("🧱 Inner call: Balances.transfer_all(keep_alive={})", keep_alive);

			let call = quantus_subxt::api::tx()
				.recovery()
				.as_recovered(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id), inner_call);

			let tx_hash = match crate::cli::common::submit_transaction(
				&quantus_client,
				&rescuer_key,
				call,
				None,
				execution_mode,
			)
			.await
			{
				Ok(h) => h,
				Err(e) => {
					log_error!("❌ Submit error (recover_all): {:?}", e);
					return Err(e);
				},
			};
			log_success!("✅ recover_all submitted successfully {:?}", tx_hash);
		},

		RecoveryCommands::RecoverAmount {
			rescuer,
			lost,
			dest,
			amount_quan,
			keep_alive,
			password,
			password_file,
		} => {
			use quantus_subxt::api::runtime_types::pallet_balances::pallet::Call as BalancesCall;

			let rescuer_key =
				crate::wallet::load_keypair_from_wallet(&rescuer, password, password_file)?;

			let rescuer_addr = rescuer_key.to_account_id_ss58check();
			log_print!("🔑 Rescuer: {}", rescuer);
			log_print!("🔑 Rescuer address: {}", rescuer_addr);

			let lost_resolved = resolve_address(&lost)?;
			let dest_resolved = resolve_address(&dest)?;
			log_print!("🆘 Lost input: {} -> {}", lost, lost_resolved);
			log_print!("🎯 Dest input: {} -> {}", dest, dest_resolved);
			log_print!("💵 amount_quan: {} (QUAN_DECIMALS={})", amount_quan, QUAN_DECIMALS);
			log_print!("🛟 keep_alive: {}", keep_alive);

			let lost_sp = SpAccountId32::from_ss58check(&lost_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid lost address: {e:?}"))
			})?;
			let dest_sp = SpAccountId32::from_ss58check(&dest_resolved).map_err(|e| {
				crate::error::QuantusError::Generic(format!("Invalid dest address: {e:?}"))
			})?;

			let lost_id_bytes: [u8; 32] = *lost_sp.as_ref();
			let dest_id_bytes: [u8; 32] = *dest_sp.as_ref();
			let lost_id = subxt::ext::subxt_core::utils::AccountId32::from(lost_id_bytes);
			let dest_id = subxt::ext::subxt_core::utils::AccountId32::from(dest_id_bytes);

			let amount_plancks = amount_quan.saturating_mul(QUAN_DECIMALS);
			log_print!("💵 amount_plancks: {}", amount_plancks);

			let latest = quantus_client.get_latest_block().await?;

			// Check account balance before attempting transfer
			log_print!("💰 Checking lost account balance...");
			let balance_result = quantus_client
				.client()
				.storage()
				.at(latest)
				.fetch(&quantus_subxt::api::storage().system().account(lost_id.clone()))
				.await;

			let account_info = match balance_result {
				Ok(Some(info)) => info,
				Ok(None) => {
					log_error!("❌ Lost account not found in storage");
					return Err(crate::error::QuantusError::Generic(
						"Lost account not found in storage".to_string(),
					));
				},
				Err(e) => {
					log_error!("❌ Failed to fetch account balance: {:?}", e);
					return Err(crate::error::QuantusError::NetworkError(format!(
						"Failed to fetch account balance: {e:?}"
					)));
				},
			};

			let available_balance = account_info.data.free;
			log_print!("💰 Available balance: {} plancks", available_balance);

			if available_balance < amount_plancks {
				log_error!(
					"❌ Insufficient funds! Account has {} plancks but needs {} plancks",
					available_balance,
					amount_plancks
				);
				return Err(crate::error::QuantusError::Generic(format!(
					"Insufficient funds: account has {available_balance} plancks but transfer requires {amount_plancks} plancks"
				)));
			}

			log_print!("✅ Balance validation successful - sufficient funds available");

			let inner_call =
				quantus_subxt::api::Call::Balances(BalancesCall::transfer_keep_alive {
					dest: subxt::ext::subxt_core::utils::MultiAddress::Id(dest_id),
					value: amount_plancks,
				});

			let call = quantus_subxt::api::tx()
				.recovery()
				.as_recovered(subxt::ext::subxt_core::utils::MultiAddress::Id(lost_id), inner_call);

			let tx_hash = match crate::cli::common::submit_transaction(
				&quantus_client,
				&rescuer_key,
				call,
				None,
				execution_mode,
			)
			.await
			{
				Ok(h) => h,
				Err(e) => {
					log_error!("❌ Submit error (recover_amount): {:?}", e);
					return Err(e);
				},
			};
			log_success!("✅ recover_amount submitted successfully {:?}", tx_hash);
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
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&lost_key,
				call,
				None,
				execution_mode,
			)
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to submit close_recovery transaction: {e}"
				))
			})?;

			log_print!("📋 Transaction submitted: 0x{}", hex::encode(tx_hash.as_ref()));
			log_success!("✅ close_recovery submitted successfully");
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
			let tx_hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&rescuer_key,
				call,
				None,
				execution_mode,
			)
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to submit cancel_recovered transaction: {e}"
				))
			})?;

			log_success!("✅ cancel_recovered submitted successfully {:?}", tx_hash);
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
						"friends": cfg.friends.0.iter().map(|f| format!("{f}")).collect::<Vec<_>>(),
						"threshold": cfg.threshold,
					})
				);
			} else {
				log_print!("{}", serde_json::json!({"recoverable": false}));
			}
		},
	};

	Ok(())
}
