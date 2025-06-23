use crate::{log_error, log_print, log_success, wallet::WalletManager};
use clap::Subcommand;
use colored::Colorize;

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
}

/// Handle wallet commands
pub async fn handle_wallet_command(
    command: WalletCommands,
    _node_url: &str,
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
            log_print!("Wallet: {}", name.bright_green());
            log_print!(
                "Force: {}",
                if force { "Yes" } else { "No" }.bright_yellow()
            );
            log_print!("{}", "✅ Wallet deleted! (STUB)".green());
            Ok(())
        }
    }
}
