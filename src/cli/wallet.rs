//! `quantus wallet` subcommand - wallet operations
use crate::{
	chain::quantus_subxt,
	cli::address_format::QuantusSS58,
	error::QuantusError,
	log_error, log_print, log_success, log_verbose,
	wallet::{password::get_mnemonic_from_user, WalletManager, DEFAULT_DERIVATION_PATH},
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};
use std::io::{self, Write};

/// Wallet management commands
#[derive(Subcommand, Debug)]
pub enum WalletCommands {
	/// Create a new wallet with quantum-safe keys
	Create {
		/// Wallet name
		#[arg(short, long)]
		name: String,

		/// Password to encrypt the wallet (optional, will prompt if not provided)
		#[arg(short, long)]
		password: Option<String>,

		/// Derivation path (default: m/44'/189189'/0'/0/0)
		#[arg(short = 'd', long, default_value = DEFAULT_DERIVATION_PATH)]
		derivation_path: String,

		/// Disable HD derivation (use master seed directly, like quantus-node --no-derivation)
		#[arg(long)]
		no_derivation: bool,
	},

	/// View wallet information
	View {
		/// Wallet name to view
		#[arg(short, long)]
		name: Option<String>,

		/// Show all wallets if no name specified
		#[arg(short, long)]
		all: bool,
	},

	/// Export wallet (private key or mnemonic)
	Export {
		/// Wallet name to export
		#[arg(short, long)]
		name: String,

		/// Password to decrypt the wallet (optional, will prompt if not provided)
		#[arg(short, long)]
		password: Option<String>,

		/// Export format: mnemonic, private-key
		#[arg(short, long, default_value = "mnemonic")]
		format: String,
	},

	/// Import wallet from mnemonic phrase
	Import {
		/// Wallet name
		#[arg(short, long)]
		name: String,

		/// Mnemonic phrase (24 words, will prompt if not provided)
		#[arg(short, long)]
		mnemonic: Option<String>,

		/// Password to encrypt the wallet (optional, will prompt if not provided)
		#[arg(short, long)]
		password: Option<String>,

		/// Derivation path (default: m/44'/189189'/0'/0/0)
		#[arg(short = 'd', long, default_value = DEFAULT_DERIVATION_PATH)]
		derivation_path: String,

		/// Disable HD derivation (use master seed directly, like quantus-node --no-derivation)
		#[arg(long)]
		no_derivation: bool,
	},

	/// Create wallet from 32-byte seed
	FromSeed {
		/// Wallet name
		#[arg(short, long)]
		name: String,

		/// 32-byte seed in hex format (64 hex characters)
		#[arg(short, long)]
		seed: String,

		/// Password to encrypt the wallet (optional, will prompt if not provided)
		#[arg(short, long)]
		password: Option<String>,
	},

	/// List all wallets
	List,

	/// Delete a wallet
	Delete {
		/// Wallet name to delete
		#[arg(short, long)]
		name: String,

		/// Skip confirmation prompt
		#[arg(short, long)]
		force: bool,
	},

	/// Get the nonce (transaction count) of an account
	Nonce {
		/// Account address to query (optional, uses wallet address if not provided)
		#[arg(short, long)]
		address: Option<String>,

		/// Wallet name (used for address if --address not provided)
		#[arg(short, long, required_unless_present("address"))]
		wallet: Option<String>,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,
	},
}

/// Get the nonce (transaction count) of an account
pub async fn get_account_nonce(
	quantus_client: &crate::chain::client::QuantusClient,
	account_address: &str,
) -> crate::error::Result<u32> {
	log_verbose!("#️⃣ Querying nonce for account: {}", account_address.bright_green());

	// Parse the SS58 address to AccountId32 (sp-core)
	let (account_id_sp, _) = SpAccountId32::from_ss58check_with_version(account_address)
		.map_err(|e| QuantusError::NetworkError(format!("Invalid SS58 address: {e:?}")))?;

	log_verbose!("🔍 SP Account ID: {:?}", account_id_sp);

	// Convert to subxt_core AccountId32 for storage query
	let account_bytes: [u8; 32] = *account_id_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

	log_verbose!("🔍 SubXT Account ID: {:?}", account_id);

	// Use SubXT to query System::Account storage directly (like send_subxt.rs)
	use quantus_subxt::api;
	let storage_addr = api::storage().system().account(account_id);

	// Get the latest block hash to read from the latest state (not finalized)
	let latest_block_hash = quantus_client.get_latest_block().await?;

	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let account_info = storage_at
		.fetch_or_default(&storage_addr)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Failed to fetch account info: {e:?}")))?;

	log_verbose!("✅ Account info retrieved with storage query!");
	log_verbose!("🔢 Nonce: {}", account_info.nonce);

	Ok(account_info.nonce)
}

/// Fetch high-security status from chain for an account (SS58). Returns None if disabled or on
/// error.
async fn fetch_high_security_status(
	quantus_client: &crate::chain::client::QuantusClient,
	account_ss58: &str,
) -> crate::error::Result<Option<(String, String)>> {
	use quantus_subxt::api::runtime_types::qp_scheduler::BlockNumberOrTimestamp;

	let (account_id_sp, _) = SpAccountId32::from_ss58check_with_version(account_ss58)
		.map_err(|e| QuantusError::Generic(format!("Invalid SS58 for HS lookup: {e:?}")))?;
	let account_bytes: [u8; 32] = *account_id_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

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
		.map_err(|e| QuantusError::NetworkError(format!("Fetch HS storage: {e:?}")))?;

	let Some(data) = value else {
		return Ok(None);
	};

	let interceptor_ss58 = data.interceptor.to_quantus_ss58();
	let delay_str = match data.delay {
		BlockNumberOrTimestamp::BlockNumber(blocks) => format!("{} blocks", blocks),
		BlockNumberOrTimestamp::Timestamp(ms) => format!("{} seconds", ms / 1000),
	};
	Ok(Some((interceptor_ss58, delay_str)))
}

/// Fetch list of accounts for which this account is guardian (interceptor_index).
/// Returns an empty vec when the storage entry is absent (`None`), and an error on failure.
async fn fetch_guardian_for_list(
	quantus_client: &crate::chain::client::QuantusClient,
	account_ss58: &str,
) -> crate::error::Result<Vec<String>> {
	let account_id_sp = SpAccountId32::from_ss58check(account_ss58)
		.map_err(|e| QuantusError::Generic(format!("Invalid SS58 for interceptor_index: {e:?}")))?;
	let account_bytes: [u8; 32] = *account_id_sp.as_ref();
	let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

	let storage_addr = quantus_subxt::api::storage()
		.reversible_transfers()
		.interceptor_index(account_id);
	let latest = quantus_client.get_latest_block().await?;
	let value = quantus_client
		.client()
		.storage()
		.at(latest)
		.fetch(&storage_addr)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("Fetch interceptor_index: {e:?}")))?;

	let list = value
		.map(|bounded| bounded.0.iter().map(|a| a.to_quantus_ss58()).collect())
		.unwrap_or_default();
	Ok(list)
}

/// For each entrusted account (SS58), count pending reversible transfers by sender. Returns (total,
/// per-account list).
async fn fetch_pending_transfers_for_guardian(
	quantus_client: &crate::chain::client::QuantusClient,
	entrusted_ss58: &[String],
) -> crate::error::Result<(u32, Vec<(String, u32)>)> {
	let latest = quantus_client.get_latest_block().await?;
	let storage = quantus_client.client().storage().at(latest);
	let mut total = 0u32;
	let mut per_account = Vec::with_capacity(entrusted_ss58.len());

	for ss58 in entrusted_ss58 {
		let account_id_sp = SpAccountId32::from_ss58check(ss58).map_err(|e| {
			QuantusError::Generic(format!("Invalid SS58 for pending lookup: {e:?}"))
		})?;
		let account_bytes: [u8; 32] = *account_id_sp.as_ref();
		let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

		let addr = quantus_subxt::api::storage()
			.reversible_transfers()
			.pending_transfers_by_sender(account_id);
		let value = storage.fetch(&addr).await.map_err(|e| {
			QuantusError::NetworkError(format!("Fetch pending_transfers_by_sender: {e:?}"))
		})?;

		let count = value.map(|bounded| bounded.0.len() as u32).unwrap_or(0);
		total += count;
		per_account.push((ss58.clone(), count));
	}

	Ok((total, per_account))
}

/// Handle wallet commands
pub async fn handle_wallet_command(
	command: WalletCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	match command {
		WalletCommands::Create { name, password, derivation_path, no_derivation } => {
			log_print!("🔐 Creating new quantum wallet...");

			let wallet_manager = WalletManager::new()?;

			// Choose creation method based on flags
			let result = if no_derivation {
				// Use master seed directly (like quantus-node --no-derivation)
				wallet_manager.create_wallet_no_derivation(&name, password.as_deref()).await
			} else if derivation_path == DEFAULT_DERIVATION_PATH {
				wallet_manager.create_wallet(&name, password.as_deref()).await
			} else {
				wallet_manager
					.create_wallet_with_derivation_path(
						&name,
						password.as_deref(),
						&derivation_path,
					)
					.await
			};

			match result {
				Ok(wallet_info) => {
					log_success!("Wallet name: {}", name.bright_green());
					log_success!("Address: {}", wallet_info.address.bright_cyan());
					log_success!("Key type: {}", wallet_info.key_type.bright_yellow());
					log_success!(
						"Derivation path: {}",
						wallet_info.derivation_path.bright_magenta()
					);
					log_success!(
						"Created: {}",
						wallet_info.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()
					);
					log_success!("✅ Wallet created successfully!");
				},
				Err(e) => {
					log_error!("{}", format!("❌ Failed to create wallet: {e}").red());
					return Err(e);
				},
			}

			Ok(())
		},

		WalletCommands::View { name, all } => {
			log_print!("👁️  Viewing wallet information...");

			let wallet_manager = WalletManager::new()?;

			if all {
				// Show all wallets (same as list command but with different header)
				match wallet_manager.list_wallets() {
					Ok(wallets) =>
						if wallets.is_empty() {
							log_print!("{}", "No wallets found.".dimmed());
						} else {
							log_print!("All wallets ({}):\n", wallets.len());

							for (i, wallet) in wallets.iter().enumerate() {
								log_print!(
									"{}. {}",
									(i + 1).to_string().bright_yellow(),
									wallet.name.bright_green()
								);
								log_print!("   Address: {}", wallet.address.bright_cyan());
								log_print!("   Type: {}", wallet.key_type.bright_yellow());
								log_print!(
									"   Derivation Path: {}",
									wallet.derivation_path.bright_magenta()
								);
								log_print!(
									"   Created: {}",
									wallet
										.created_at
										.format("%Y-%m-%d %H:%M:%S UTC")
										.to_string()
										.dimmed()
								);
								if i < wallets.len() - 1 {
									log_print!();
								}
							}
						},
					Err(e) => {
						log_error!("{}", format!("❌ Failed to view wallets: {e}").red());
						return Err(e);
					},
				}
			} else if let Some(wallet_name) = name {
				// Show specific wallet details
				match wallet_manager.get_wallet(&wallet_name, None) {
					Ok(Some(wallet_info)) => {
						log_print!("Wallet Details:\n");
						log_print!("Name: {}", wallet_info.name.bright_green());
						log_print!("Address: {}", wallet_info.address.bright_cyan());
						log_print!("Key Type: {}", wallet_info.key_type.bright_yellow());
						log_print!(
							"Derivation Path: {}",
							wallet_info.derivation_path.bright_magenta()
						);
						log_print!(
							"Created: {}",
							wallet_info
								.created_at
								.format("%Y-%m-%d %H:%M:%S UTC")
								.to_string()
								.dimmed()
						);

						if wallet_info.address.contains("[") {
							log_print!(
								"\n{}",
								"💡 To see the full address, use the export command with password"
									.dimmed()
							);
						}

						// High-Security status and Guardian-for list from chain (optional; don't
						// fail view if node unavailable)
						if !wallet_info.address.contains("[") {
							if let Ok(quantus_client) =
								crate::chain::client::QuantusClient::new(node_url).await
							{
								match fetch_high_security_status(
									&quantus_client,
									&wallet_info.address,
								)
								.await
								{
									Ok(Some((interceptor_ss58, delay_str))) => {
										log_print!(
											"\n🛡️  High Security: {}",
											"ENABLED".bright_green().bold()
										);
										log_print!(
											"   Guardian/Interceptor: {}",
											interceptor_ss58.bright_cyan()
										);
										log_print!("   Delay: {}", delay_str.bright_yellow());
									},
									Ok(None) => {
										log_print!("\n🛡️  High Security: {}", "DISABLED".dimmed());
									},
									Err(e) => {
										log_verbose!("High Security status skipped: {}", e);
										log_print!(
											"\n{}",
											"💡 Run quantus high-security status --account <address> to check on-chain"
												.dimmed()
										);
									},
								}

								// Guardian for: accounts that have this wallet as their interceptor
								if let Ok(entrusted) =
									fetch_guardian_for_list(&quantus_client, &wallet_info.address)
										.await
								{
									if entrusted.is_empty() {
										log_print!("🛡️  Guardian for: {}", "none".dimmed());
									} else {
										log_print!(
											"\n🛡️  Guardian for: {} account(s)",
											entrusted.len().to_string().bright_green()
										);
										for (i, addr) in entrusted.iter().enumerate() {
											log_print!("   {}. {}", i + 1, addr.bright_cyan());
										}
										// Pending reversible transfers that this guardian can
										// intercept
										if let Ok((total, per_account)) =
											fetch_pending_transfers_for_guardian(
												&quantus_client,
												&entrusted,
											)
											.await
										{
											if total > 0 {
												log_print!(
													"\n   {} {} pending transfer(s) you can intercept",
													"⚠️".bright_yellow(),
													total.to_string().bright_yellow().bold()
												);
												for (addr, count) in per_account {
													if count > 0 {
														log_print!(
															"      from {}: {}",
															addr.bright_cyan(),
															count
														);
													}
												}
												log_print!("   {}", "Use: quantus reversible cancel --tx-id <id> --from <you>".dimmed());
											}
										}
									}
								}
							} else {
								log_verbose!(
									"Could not connect to node; High Security status skipped."
								);
							}
						}
					},
					Ok(None) => {
						log_error!("{}", format!("❌ Wallet '{wallet_name}' not found").red());
						log_print!(
							"Use {} to see available wallets",
							"quantus wallet list".bright_green()
						);
					},
					Err(e) => {
						log_error!("{}", format!("❌ Failed to view wallet: {e}").red());
						return Err(e);
					},
				}
			} else {
				log_print!(
					"{}",
					"Please specify a wallet name with --name or use --all to show all wallets"
						.yellow()
				);
				log_print!("Examples:");
				log_print!("  {}", "quantus wallet view --name my-wallet".bright_green());
				log_print!("  {}", "quantus wallet view --all".bright_green());
			}

			Ok(())
		},

		WalletCommands::Export { name, password, format } => {
			log_print!("📤 Exporting wallet...");

			if format.to_lowercase() != "mnemonic" {
				log_error!("Only 'mnemonic' export format is currently supported.");
				return Err(crate::error::QuantusError::Generic(
					"Export format not supported".to_string(),
				));
			}

			let wallet_manager = WalletManager::new()?;

			match wallet_manager.export_mnemonic(&name, password.as_deref()) {
				Ok(mnemonic) => {
					log_success!("✅ Wallet exported successfully!");
					log_print!("\nYour secret mnemonic phrase:");
					log_print!("{}", "--------------------------------------------------".dimmed());
					log_print!("{}", mnemonic.bright_yellow());
					log_print!("{}", "--------------------------------------------------".dimmed());
					log_print!(
                        "\n{}",
                        "⚠️  Keep this phrase safe and secret. Anyone with this phrase can access your funds."
                            .bright_red()
                    );
				},
				Err(e) => {
					log_error!("{}", format!("❌ Failed to export wallet: {e}").red());
					return Err(e);
				},
			}

			Ok(())
		},

		WalletCommands::Import { name, mnemonic, password, derivation_path, no_derivation } => {
			log_print!("📥 Importing wallet...");

			let wallet_manager = WalletManager::new()?;

			// Get mnemonic from user if not provided
			let mnemonic_phrase =
				if let Some(mnemonic) = mnemonic { mnemonic } else { get_mnemonic_from_user()? };

			// Get password from user if not provided
			let final_password =
				crate::wallet::password::get_wallet_password(&name, password, None)?;

			// Choose import method based on flags
			let result = if no_derivation {
				// Use master seed directly (like quantus-node --no-derivation)
				wallet_manager
					.import_wallet_no_derivation(&name, &mnemonic_phrase, Some(&final_password))
					.await
			} else if derivation_path == DEFAULT_DERIVATION_PATH {
				wallet_manager
					.import_wallet(&name, &mnemonic_phrase, Some(&final_password))
					.await
			} else {
				wallet_manager
					.import_wallet_with_derivation_path(
						&name,
						&mnemonic_phrase,
						Some(&final_password),
						&derivation_path,
					)
					.await
			};

			match result {
				Ok(wallet_info) => {
					log_success!("Wallet name: {}", name.bright_green());
					log_success!("Address: {}", wallet_info.address.bright_cyan());
					log_success!("Key type: {}", wallet_info.key_type.bright_yellow());
					log_success!(
						"Derivation path: {}",
						wallet_info.derivation_path.bright_magenta()
					);
					log_success!(
						"Imported: {}",
						wallet_info.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()
					);
					log_success!("✅ Wallet imported successfully!");
				},
				Err(e) => {
					log_error!("{}", format!("❌ Failed to import wallet: {e}").red());
					return Err(e);
				},
			}

			Ok(())
		},

		WalletCommands::FromSeed { name, seed, password } => {
			log_print!("🌱 Creating wallet from seed...");

			let wallet_manager = WalletManager::new()?;

			// Get password from user if not provided
			let final_password =
				crate::wallet::password::get_wallet_password(&name, password, None)?;

			match wallet_manager
				.create_wallet_from_seed(&name, &seed, Some(&final_password))
				.await
			{
				Ok(wallet_info) => {
					log_success!("Wallet name: {}", name.bright_green());
					log_success!("Address: {}", wallet_info.address.bright_cyan());
					log_success!("Key type: {}", wallet_info.key_type.bright_yellow());
					log_success!(
						"Created: {}",
						wallet_info.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()
					);
					log_success!("✅ Wallet created from seed successfully!");
				},
				Err(e) => {
					log_error!("{}", format!("❌ Failed to create wallet from seed: {e}").red());
					return Err(e);
				},
			}

			Ok(())
		},

		WalletCommands::List => {
			log_print!("📋 Listing all wallets...");

			let wallet_manager = WalletManager::new()?;

			match wallet_manager.list_wallets() {
				Ok(wallets) =>
					if wallets.is_empty() {
						log_print!("{}", "No wallets found.".dimmed());
						log_print!(
							"Create a new wallet with: {}",
							"quantus wallet create --name <name>".bright_green()
						);
					} else {
						log_print!("Found {} wallet(s):\n", wallets.len());

						for (i, wallet) in wallets.iter().enumerate() {
							log_print!(
								"{}. {}",
								(i + 1).to_string().bright_yellow(),
								wallet.name.bright_green()
							);
							log_print!("   Address: {}", wallet.address.bright_cyan());
							log_print!("   Type: {}", wallet.key_type.bright_yellow());
							log_print!(
								"   Created: {}",
								wallet
									.created_at
									.format("%Y-%m-%d %H:%M:%S UTC")
									.to_string()
									.dimmed()
							);
							if i < wallets.len() - 1 {
								log_print!();
							}
						}

						log_print!(
							"\n{}",
							"💡 Use 'quantus wallet view --name <wallet>' to see full details"
								.dimmed()
						);
					},
				Err(e) => {
					log_error!("{}", format!("❌ Failed to list wallets: {e}").red());
					return Err(e);
				},
			}

			Ok(())
		},

		WalletCommands::Delete { name, force } => {
			log_print!("🗑️  Deleting wallet...");

			let wallet_manager = WalletManager::new()?;

			// Check if wallet exists first
			match wallet_manager.get_wallet(&name, None) {
				Ok(Some(wallet_info)) => {
					// Show wallet info before deletion
					log_print!("Wallet to delete:");
					log_print!("  Name: {}", wallet_info.name.bright_green());
					log_print!("  Address: {}", wallet_info.address.bright_cyan());
					log_print!("  Type: {}", wallet_info.key_type.bright_yellow());
					log_print!(
						"  Created: {}",
						wallet_info.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()
					);

					// Confirmation prompt unless --force is used
					if !force {
						log_print!("\n{}", "⚠️  This action cannot be undone!".bright_red());
						log_print!("Type the wallet name to confirm deletion:");

						print!("Confirm wallet name: ");
						io::stdout().flush().unwrap();

						let mut input = String::new();
						io::stdin().read_line(&mut input).unwrap();
						let input = input.trim();

						if input != name {
							log_print!(
								"{}",
								"❌ Wallet name doesn't match. Deletion cancelled.".red()
							);
							return Ok(());
						}
					}

					// Perform deletion
					match wallet_manager.delete_wallet(&name) {
						Ok(true) => {
							log_success!("✅ Wallet '{}' deleted successfully!", name);
						},
						Ok(false) => {
							log_error!("{}", format!("❌ Wallet '{name}' was not found").red());
						},
						Err(e) => {
							log_error!("{}", format!("❌ Failed to delete wallet: {e}").red());
							return Err(e);
						},
					}
				},
				Ok(None) => {
					log_error!("{}", format!("❌ Wallet '{name}' not found").red());
					log_print!(
						"Use {} to see available wallets",
						"quantus wallet list".bright_green()
					);
				},
				Err(e) => {
					log_error!("{}", format!("❌ Failed to check wallet: {e}").red());
					return Err(e);
				},
			}

			Ok(())
		},

		WalletCommands::Nonce { address, wallet, password } => {
			log_print!("🔢 Querying account nonce...");

			let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

			// Determine which address to query
			let target_address = match (address, wallet) {
				(Some(addr), _) => {
					// Validate the provided address
					SpAccountId32::from_ss58check(&addr)
						.map_err(|e| QuantusError::Generic(format!("Invalid address: {e:?}")))?;
					addr
				},
				(None, Some(wallet_name)) => {
					// Load wallet and get its address
					let keypair =
						crate::wallet::load_keypair_from_wallet(&wallet_name, password, None)?;
					keypair.to_account_id_ss58check()
				},
				(None, None) => {
					// This case should be prevented by clap's `required_unless_present`
					unreachable!("Either --address or --wallet must be provided");
				},
			};

			log_print!("Account: {}", target_address.bright_cyan());

			match get_account_nonce(&quantus_client, &target_address).await {
				Ok(nonce) => {
					log_success!("Nonce: {}", nonce.to_string().bright_green());
				},
				Err(e) => {
					log_print!("❌ Failed to get nonce: {}", e);
					return Err(e);
				},
			}

			Ok(())
		},
	}
}
