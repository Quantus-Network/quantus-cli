use crate::{log_error, log_print, log_success, wallet::WalletManager};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::io::{self, Write};

/// Wallet subcommands
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

/// Handle wallet commands
pub async fn handle_wallet_command(
    command: WalletCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    match command {
        WalletCommands::Create { name, password } => {
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

        WalletCommands::View { name, all } => {
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

        WalletCommands::Export { name, format } => {
            log_print!("📤 Exporting wallet...");
            log_print!("Wallet: {}", name.bright_green());
            log_print!("Format: {}", format.bright_yellow());
            log_print!("{}", "✅ Export completed! (STUB)".green());
            Ok(())
        }

        WalletCommands::Import {
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
                log_print!("Please enter your 24-word mnemonic phrase:");
                // For now, we'll require the mnemonic to be provided via command line
                // In a real implementation, you'd want to prompt securely for this
                return Err(crate::error::QuantusError::Generic(
                    "Mnemonic phrase is required. Please provide it with --mnemonic flag."
                        .to_string(),
                )
                .into());
            };

            match wallet_manager
                .import_wallet(&name, &mnemonic_phrase, password.as_deref())
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

        WalletCommands::List => {
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

        WalletCommands::Nonce {
            address,
            wallet,
            password,
        } => {
            log_print!("🔢 Querying account nonce...");

            let chain_client = crate::chain::client::ChainClient::new(node_url).await?;

            // Determine which address to query
            let target_address = match (address, wallet) {
                (Some(addr), _) => {
                    // Validate the provided address, though get_account_nonce will also do it
                    AccountId32::from_ss58check(&addr).map_err(|e| {
                        crate::error::QuantusError::Generic(format!("Invalid address: {:?}", e))
                    })?;
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

            match chain_client.get_account_nonce(&target_address).await {
                Ok(nonce) => {
                    log_success!("Nonce: {}", nonce.to_string().bright_green());
                }
                Err(e) => {
                    log_error!("❌ Failed to get nonce: {}", e);
                    return Err(e);
                }
            }

            Ok(())
        }
    }
}
