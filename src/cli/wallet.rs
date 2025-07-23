//! `quantus wallet` subcommand - wallet operations
use crate::chain::client::ChainConfig;
use crate::{
    chain::client,
    chain::quantus_subxt,
    error::QuantusError,
    log_error, log_print, log_success, log_verbose,
    wallet::{password::get_mnemonic_from_user, WalletManager},
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::io::{self, Write};
use subxt::OnlineClient;

/// Wallet management commands
#[derive(Subcommand, Debug)]
pub enum WalletSubxtCommands {
    /// Create a new wallet with quantum-safe keys
    Create {
        /// Wallet name
        #[arg(short, long)]
        name: String,

        /// Password to encrypt the wallet (optional, will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,
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
    client: &OnlineClient<ChainConfig>,
    account_address: &str,
) -> crate::error::Result<u32> {
    log_verbose!(
        "#️⃣ Querying nonce for account: {}",
        account_address.bright_green()
    );

    // Parse the SS58 address to AccountId32 (sp-core)
    let account_id_sp = AccountId32::from_ss58check(account_address)
        .map_err(|e| QuantusError::NetworkError(format!("Invalid SS58 address: {:?}", e)))?;

    log_verbose!("🔍 SP Account ID: {:?}", account_id_sp);

    // Convert to subxt_core AccountId32 for storage query
    let account_bytes: [u8; 32] = *account_id_sp.as_ref();
    let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

    log_verbose!("🔍 SubXT Account ID: {:?}", account_id);

    // Use SubXT to query System::Account storage directly (like send_subxt.rs)
    use quantus_subxt::api;
    let storage_addr = api::storage().system().account(account_id);

    let storage_at =
        client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

    let account_info = storage_at
        .fetch_or_default(&storage_addr)
        .await
        .map_err(|e| {
            QuantusError::NetworkError(format!("Failed to fetch account info: {:?}", e))
        })?;

    log_verbose!("✅ Account info retrieved with storage query!");
    log_verbose!("🔢 Nonce: {}", account_info.nonce);

    Ok(account_info.nonce)
}

/// Handle wallet commands
pub async fn handle_wallet_subxt_command(
    command: WalletSubxtCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    match command {
        WalletSubxtCommands::Create { name, password } => {
            log_print!("🔐 Creating new quantum wallet...");

            let wallet_manager = WalletManager::new()?;

            match wallet_manager
                .create_wallet(&name, password.as_deref())
                .await
            {
                Ok(wallet_info) => {
                    log_success!("Wallet name: {}", name.bright_green());
                    log_success!("Address: {}", wallet_info.address.bright_cyan());
                    log_success!("Key type: {}", wallet_info.key_type.bright_yellow());
                    log_success!(
                        "Created: {}",
                        wallet_info
                            .created_at
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                            .dimmed()
                    );
                    log_success!("✅ Wallet created successfully!");
                }
                Err(e) => {
                    log_error!("{}", format!("❌ Failed to create wallet: {}", e).red());
                    return Err(e);
                }
            }

            Ok(())
        }

        WalletSubxtCommands::View { name, all } => {
            log_print!("👁️  Viewing wallet information...");

            let wallet_manager = WalletManager::new()?;

            if all {
                // Show all wallets (same as list command but with different header)
                match wallet_manager.list_wallets() {
                    Ok(wallets) => {
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
                        }
                    }
                    Err(e) => {
                        log_error!("{}", format!("❌ Failed to view wallets: {}", e).red());
                        return Err(e);
                    }
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
                    }
                    Ok(None) => {
                        log_error!("{}", format!("❌ Wallet '{}' not found", wallet_name).red());
                        log_print!(
                            "Use {} to see available wallets",
                            "quantus wallet list".bright_green()
                        );
                    }
                    Err(e) => {
                        log_error!("{}", format!("❌ Failed to view wallet: {}", e).red());
                        return Err(e);
                    }
                }
            } else {
                log_print!(
                    "{}",
                    "Please specify a wallet name with --name or use --all to show all wallets"
                        .yellow()
                );
                log_print!("Examples:");
                log_print!(
                    "  {}",
                    "quantus wallet view --name my-wallet".bright_green()
                );
                log_print!("  {}", "quantus wallet view --all".bright_green());
            }

            Ok(())
        }

        WalletSubxtCommands::Export { name, format } => {
            log_print!("📤 Exporting wallet...");
            log_print!("Wallet: {}", name.bright_green());
            log_print!("Format: {}", format.bright_yellow());
            log_print!("{}", "✅ Export completed! (STUB)".green());
            Ok(())
        }

        WalletSubxtCommands::Import {
            name,
            mnemonic,
            password,
        } => {
            log_print!("📥 Importing wallet...");

            let wallet_manager = WalletManager::new()?;

            // Get mnemonic from user if not provided
            let mnemonic_phrase = if let Some(mnemonic) = mnemonic {
                mnemonic
            } else {
                get_mnemonic_from_user()?
            };

            // Get password from user if not provided
            let final_password =
                crate::wallet::password::get_wallet_password(&name, password, None)?;

            match wallet_manager
                .import_wallet(&name, &mnemonic_phrase, Some(&final_password))
                .await
            {
                Ok(wallet_info) => {
                    log_success!("Wallet name: {}", name.bright_green());
                    log_success!("Address: {}", wallet_info.address.bright_cyan());
                    log_success!("Key type: {}", wallet_info.key_type.bright_yellow());
                    log_success!(
                        "Imported: {}",
                        wallet_info
                            .created_at
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                            .dimmed()
                    );
                    log_success!("✅ Wallet imported successfully!");
                }
                Err(e) => {
                    log_error!("{}", format!("❌ Failed to import wallet: {}", e).red());
                    return Err(e);
                }
            }

            Ok(())
        }

        WalletSubxtCommands::List => {
            log_print!("📋 Listing all wallets...");

            let wallet_manager = WalletManager::new()?;

            match wallet_manager.list_wallets() {
                Ok(wallets) => {
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
                    }
                }
                Err(e) => {
                    log_error!("{}", format!("❌ Failed to list wallets: {}", e).red());
                    return Err(e);
                }
            }

            Ok(())
        }

        WalletSubxtCommands::Delete { name, force } => {
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
                        wallet_info
                            .created_at
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                            .dimmed()
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
                        }
                        Ok(false) => {
                            log_error!("{}", format!("❌ Wallet '{}' was not found", name).red());
                        }
                        Err(e) => {
                            log_error!("{}", format!("❌ Failed to delete wallet: {}", e).red());
                            return Err(e);
                        }
                    }
                }
                Ok(None) => {
                    log_error!("{}", format!("❌ Wallet '{}' not found", name).red());
                    log_print!(
                        "Use {} to see available wallets",
                        "quantus wallet list".bright_green()
                    );
                }
                Err(e) => {
                    log_error!("{}", format!("❌ Failed to check wallet: {}", e).red());
                    return Err(e);
                }
            }

            Ok(())
        }

        WalletSubxtCommands::Nonce {
            address,
            wallet,
            password,
        } => {
            log_print!("🔢 Querying account nonce...");

            let client = client::create_subxt_client(node_url).await?;

            // Determine which address to query
            let target_address = match (address, wallet) {
                (Some(addr), _) => {
                    // Validate the provided address
                    AccountId32::from_ss58check(&addr)
                        .map_err(|e| QuantusError::Generic(format!("Invalid address: {:?}", e)))?;
                    addr
                }
                (None, Some(wallet_name)) => {
                    // Load wallet and get its address
                    let keypair =
                        crate::wallet::load_keypair_from_wallet(&wallet_name, password, None)?;
                    keypair.to_account_id_ss58check()
                }
                (None, None) => {
                    // This case should be prevented by clap's `required_unless_present`
                    unreachable!("Either --address or --wallet must be provided");
                }
            };

            log_print!("Account: {}", target_address.bright_cyan());

            match get_account_nonce(&client, &target_address).await {
                Ok(nonce) => {
                    log_success!("Nonce: {}", nonce.to_string().bright_green());
                }
                Err(e) => {
                    log_print!("❌ Failed to get nonce: {}", e);
                    return Err(e);
                }
            }

            Ok(())
        }
    }
}
