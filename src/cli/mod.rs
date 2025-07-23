use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;

pub mod generic_call_subxt;
pub mod metadata_subxt;
pub mod progress_spinner;
pub mod reversible_subxt;
pub mod runtime_subxt;
pub mod scheduler_subxt;
pub mod send_subxt;
pub mod storage_subxt;
pub mod system_subxt;
pub mod tech_collective_subxt;
pub mod wallet_subxt;

/// Main CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Wallet management commands
    #[command(subcommand)]
    Wallet(wallet_subxt::WalletSubxtCommands),

    /// Send tokens to another account
    Send {
        /// The recipient's account address
        #[arg(short, long)]
        to: String,

        /// Amount to send (e.g., "10", "10.5", "0.0001")
        #[arg(short, long)]
        amount: String,

        /// Wallet name to send from
        #[arg(short, long)]
        from: String,

        /// Password for the wallet (or use environment variables)
        #[arg(short, long)]
        password: Option<String>,

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
    },

    /// Reversible transfer commands
    #[command(subcommand)]
    Reversible(reversible_subxt::ReversibleSubxtCommands),

    /// Scheduler commands
    #[command(subcommand)]
    Scheduler(scheduler_subxt::SchedulerSubxtCommands),

    /// Direct interaction with chain storage (Sudo required for set)
    #[command(subcommand)]
    Storage(storage_subxt::StorageSubxtCommands),

    /// Tech Collective management commands
    #[command(subcommand)]
    TechCollective(tech_collective_subxt::TechCollectiveSubxtCommands),

    /// Runtime management commands (requires root/sudo permissions)
    #[command(subcommand)]
    Runtime(runtime_subxt::RuntimeSubxtCommands),

    /// Generic extrinsic call - call ANY pallet function!
    Call {
        /// Pallet name (e.g., "Balances")
        #[arg(long)]
        pallet: String,

        /// Call/function name (e.g., "transfer_allow_death")
        #[arg(short, long)]
        call: String,

        /// Arguments as JSON array (e.g., '["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "1000000000000"]')
        #[arg(short, long)]
        args: Option<String>,

        /// Wallet name to sign with
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,

        /// Read password from file
        #[arg(long)]
        password_file: Option<String>,

        /// Optional tip amount to prioritize the transaction
        #[arg(long)]
        tip: Option<String>,

        /// Create offline extrinsic without submitting
        #[arg(long)]
        offline: bool,

        /// Output the call as hex-encoded data only
        #[arg(long)]
        call_data_only: bool,
    },

    /// Query account balance
    Balance {
        /// Account address to query (SS58 format)
        #[arg(short, long)]
        address: String,
    },

    /// Developer utilities and testing tools
    #[command(subcommand)]
    Developer(DeveloperCommands),

    /// Query system information
    System {
        /// Show runtime version information
        #[arg(long)]
        runtime: bool,

        /// Show metadata statistics
        #[arg(long)]
        metadata: bool,
    },

    /// Explore chain metadata and available pallets/calls
    Metadata {
        /// Skip displaying documentation for calls
        #[arg(long)]
        no_docs: bool,

        /// Show only metadata statistics
        #[arg(long)]
        stats_only: bool,
    },

    /// Show version information
    Version,
}

/// Developer subcommands
#[derive(Subcommand, Debug)]
pub enum DeveloperCommands {
    /// Create standard test wallets (crystal_alice, crystal_bob, crystal_charlie)
    CreateTestWallets,
}

/// Execute a CLI command
pub async fn execute_command(command: Commands, node_url: &str) -> crate::error::Result<()> {
    match command {
        Commands::Wallet(wallet_cmd) => {
            wallet_subxt::handle_wallet_subxt_command(wallet_cmd, node_url).await
        }
        Commands::Send {
            from,
            to,
            amount,
            password,
            password_file,
        } => {
            send_subxt::handle_send_subxt_command(
                from,
                to,
                &amount,
                node_url,
                password,
                password_file,
            )
            .await
        }
        Commands::Reversible(reversible_cmd) => {
            reversible_subxt::handle_reversible_subxt_command(reversible_cmd, node_url).await
        }
        Commands::Scheduler(scheduler_cmd) => {
            scheduler_subxt::handle_scheduler_subxt_command(scheduler_cmd, node_url).await
        }
        Commands::Storage(storage_cmd) => {
            storage_subxt::handle_storage_subxt_command(storage_cmd, node_url).await
        }
        Commands::TechCollective(tech_collective_cmd) => {
            tech_collective_subxt::handle_tech_collective_subxt_command(
                tech_collective_cmd,
                node_url,
            )
            .await
        }
        Commands::Runtime(runtime_cmd) => {
            runtime_subxt::handle_runtime_subxt_command(runtime_cmd, node_url).await
        }
        Commands::Call {
            pallet,
            call,
            args,
            from,
            password,
            password_file,
            tip,
            offline,
            call_data_only,
        } => {
            handle_generic_call_subxt_command(
                pallet,
                call,
                args,
                from,
                password,
                password_file,
                tip,
                offline,
                call_data_only,
                node_url,
            )
            .await
        }
        Commands::Balance { address } => {
            let client = crate::chain::client_subxt::create_subxt_client(node_url).await?;
            let balance = send_subxt::get_balance(&client, &address).await?;
            let formatted_balance =
                send_subxt::format_balance_with_symbol(&client, balance).await?;
            log_print!("💰 Balance: {}", formatted_balance);
            Ok(())
        }
        Commands::Developer(dev_cmd) => match dev_cmd {
            DeveloperCommands::CreateTestWallets => {
                let _ = crate::cli::handle_developer_command(
                    DeveloperCommands::CreateTestWallets,
                    node_url,
                )
                .await;
                Ok(())
            }
        },
        Commands::System { runtime, metadata } => {
            if runtime || metadata {
                system_subxt::handle_system_subxt_extended_command(node_url, runtime, metadata)
                    .await
            } else {
                system_subxt::handle_system_subxt_command(node_url).await
            }
        }
        Commands::Metadata {
            no_docs,
            stats_only,
        } => metadata_subxt::handle_metadata_subxt_command(node_url, no_docs, stats_only).await,
        Commands::Version => {
            log_print!("CLI Version: Quantus CLI v{}", env!("CARGO_PKG_VERSION"));

            let client = crate::chain::client_subxt::create_subxt_client(node_url).await?;
            let runtime_version = runtime_subxt::get_runtime_version(&client).await?;
            log_print!(
                "Runtime Version: spec_version: {}, impl_version: {}",
                runtime_version.spec_version,
                runtime_version.impl_version
            );
            Ok(())
        }
    }
}

/// Handle generic extrinsic call command using SubXT
async fn handle_generic_call_subxt_command(
    pallet: String,
    call: String,
    args: Option<String>,
    from: String,
    _password: Option<String>,
    _password_file: Option<String>,
    tip: Option<String>,
    offline: bool,
    call_data_only: bool,
    node_url: &str,
) -> crate::error::Result<()> {
    // For now, we only support live submission (not offline or call-data-only)
    if offline {
        log_error!("❌ Offline mode is not yet implemented");
        log_print!("💡 Currently only live submission is supported");
        return Ok(());
    }

    if call_data_only {
        log_error!("❌ Call-data-only mode is not yet implemented");
        log_print!("💡 Currently only live submission is supported");
        return Ok(());
    }

    let args_vec = if let Some(args_str) = args {
        serde_json::from_str(&args_str).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid JSON for arguments: {}", e))
        })?
    } else {
        vec![]
    };

    generic_call_subxt::execute_generic_call_subxt(&pallet, &call, args_vec, &from, tip, node_url)
        .await
}

/// Handle developer subcommands
pub async fn handle_developer_command(
    command: DeveloperCommands,
    _node_url: &str,
) -> crate::error::Result<()> {
    match command {
        DeveloperCommands::CreateTestWallets => {
            use crate::wallet::WalletManager;

            log_print!(
                "🧪 {} Creating standard test wallets...",
                "DEVELOPER".bright_magenta().bold()
            );
            log_print!("");

            let wallet_manager = WalletManager::new()?;

            // Standard test wallets with well-known names
            let test_wallets = vec![
                ("crystal_alice", "Alice's test wallet for development"),
                ("crystal_bob", "Bob's test wallet for development"),
                ("crystal_charlie", "Charlie's test wallet for development"),
            ];

            let mut created_count = 0;

            for (name, description) in test_wallets {
                log_verbose!("Creating wallet: {}", name.bright_green());

                // Create wallet with a default password for testing
                match wallet_manager.create_developer_wallet(name).await {
                    Ok(wallet_info) => {
                        log_success!("✅ Created {}", name.bright_green());
                        log_success!("   Address: {}", wallet_info.address.bright_cyan());
                        log_success!("   Description: {}", description.dimmed());
                        created_count += 1;
                    }
                    Err(e) => {
                        log_error!("❌ Failed to create {}: {}", name.bright_red(), e);
                    }
                }
            }

            log_print!("");
            log_success!("🎉 Test wallet creation complete!");
            log_success!(
                "   Created: {} wallets",
                created_count.to_string().bright_green()
            );
            log_print!("");
            log_print!(
                "💡 {} You can now use these wallets:",
                "TIP".bright_blue().bold()
            );
            log_print!("   quantus send --from crystal_alice --to <address> --amount 1000");
            log_print!("   quantus send --from crystal_bob --to <address> --amount 1000");
            log_print!("   quantus send --from crystal_charlie --to <address> --amount 1000");
            log_print!("");

            Ok(())
        }
    }
}
