use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;

pub mod generic_call;
pub mod generic_call_subxt;
pub mod metadata_subxt;
pub mod progress_spinner;
pub mod reversible;
pub mod reversible_subxt;
pub mod runtime;
pub mod runtime_subxt;
pub mod scheduler;
pub mod scheduler_subxt;
pub mod send;
pub mod send_subxt;
pub mod storage;
pub mod storage_subxt;
pub mod system_subxt;
pub mod tech_collective;
pub mod tech_collective_subxt;
pub mod wallet;
pub mod wallet_subxt;

/// Main CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Wallet management commands
    #[command(subcommand)]
    Wallet(wallet::WalletCommands),

    /// Wallet management using subxt (POC) - alternative implementation using pure subxt
    #[command(subcommand)]
    WalletSubxt(wallet_subxt::WalletSubxtCommands),

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

    /// Send tokens using subxt (POC) - alternative implementation using pure subxt
    SendSubxt {
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
    Reversible(reversible::ReversibleCommands),

    /// Reversible transfer commands using subxt (POC) - alternative implementation using pure subxt
    #[command(subcommand)]
    ReversibleSubxt(reversible_subxt::ReversibleSubxtCommands),

    /// Scheduler commands
    #[command(subcommand)]
    Scheduler(scheduler::SchedulerCommands),

    /// Scheduler commands using subxt (POC) - alternative implementation using pure subxt
    #[command(subcommand)]
    SchedulerSubxt(scheduler_subxt::SchedulerSubxtCommands),

    /// Direct interaction with chain storage (Sudo required for set)
    #[command(subcommand)]
    Storage(storage::StorageCommands),

    /// Direct interaction with chain storage using subxt (POC) - alternative implementation using pure subxt
    #[command(subcommand)]
    StorageSubxt(storage_subxt::StorageSubxtCommands),

    /// Tech Collective management commands
    #[command(subcommand)]
    TechCollective(tech_collective::TechCollectiveCommands),

    /// Tech Collective management commands using subxt (POC) - alternative implementation using pure subxt
    #[command(subcommand)]
    TechCollectiveSubxt(tech_collective_subxt::TechCollectiveSubxtCommands),

    /// Runtime management commands (requires root/sudo permissions)
    #[command(subcommand)]
    Runtime(runtime::RuntimeCommands),

    /// Runtime management commands using subxt (POC) - alternative implementation using pure subxt
    #[command(subcommand)]
    RuntimeSubxt(runtime_subxt::RuntimeSubxtCommands),

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

    /// Generic extrinsic call using subxt (POC) - call ANY pallet function with pure subxt!
    CallSubxt {
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

    /// Query account balance using subxt (POC) - alternative implementation using pure subxt
    BalanceSubxt {
        /// Account address to query (SS58 format)
        #[arg(short, long)]
        address: String,
    },

    /// Developer utilities and testing tools
    #[command(subcommand)]
    Developer(DeveloperCommands),

    /// Query system information
    System,

    /// Query system information using subxt (POC) - alternative implementation using pure subxt
    SystemSubxt {
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
    },

    /// Explore chain metadata using subxt (POC) - alternative implementation using pure subxt
    MetadataSubxt {
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
        Commands::Wallet(wallet_cmd) => wallet::handle_wallet_command(wallet_cmd, node_url).await,
        Commands::WalletSubxt(wallet_subxt_cmd) => {
            wallet_subxt::handle_wallet_subxt_command(wallet_subxt_cmd, node_url).await
        }
        Commands::Send {
            from,
            to,
            amount,
            password,
            password_file,
        } => send::handle_send_command(from, to, &amount, node_url, password, password_file).await,
        Commands::SendSubxt {
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
            reversible::handle_reversible_command(reversible_cmd, node_url).await
        }
        Commands::ReversibleSubxt(reversible_subxt_cmd) => {
            reversible_subxt::handle_reversible_subxt_command(reversible_subxt_cmd, node_url).await
        }
        Commands::Scheduler(scheduler_cmd) => {
            scheduler::handle_scheduler_command(scheduler_cmd, node_url).await
        }
        Commands::SchedulerSubxt(scheduler_subxt_cmd) => {
            scheduler_subxt::handle_scheduler_subxt_command(scheduler_subxt_cmd, node_url).await
        }
        Commands::Storage(storage_cmd) => {
            storage::handle_storage_command(storage_cmd, node_url).await
        }
        Commands::StorageSubxt(storage_subxt_cmd) => {
            storage_subxt::handle_storage_subxt_command(storage_subxt_cmd, node_url).await
        }
        Commands::TechCollective(tech_collective_cmd) => {
            tech_collective::handle_tech_collective_command(tech_collective_cmd, node_url).await
        }
        Commands::TechCollectiveSubxt(tech_collective_subxt_cmd) => {
            tech_collective_subxt::handle_tech_collective_subxt_command(
                tech_collective_subxt_cmd,
                node_url,
            )
            .await
        }
        Commands::Runtime(runtime_cmd) => {
            runtime::handle_runtime_command(runtime_cmd, node_url).await
        }
        Commands::RuntimeSubxt(runtime_subxt_cmd) => {
            runtime_subxt::handle_runtime_subxt_command(runtime_subxt_cmd, node_url).await
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
            handle_generic_call_command(
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
        Commands::CallSubxt {
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
            let chain_client = crate::chain::client::ChainClient::new(node_url).await?;
            let balance = chain_client.get_balance(&address).await?;
            let formatted_balance = chain_client.format_balance_with_symbol(balance).await?;
            log_print!("💰 Balance: {}", formatted_balance);
            Ok(())
        }
        Commands::BalanceSubxt { address } => {
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
        Commands::System => {
            let chain_client = crate::chain::client::ChainClient::new(node_url).await?;
            chain_client.get_system_info().await
        }
        Commands::SystemSubxt { runtime, metadata } => {
            if runtime || metadata {
                system_subxt::handle_system_subxt_extended_command(node_url, runtime, metadata)
                    .await
            } else {
                system_subxt::handle_system_subxt_command(node_url).await
            }
        }
        Commands::Metadata { no_docs } => {
            let chain_client = crate::chain::client::ChainClient::new(node_url).await?;
            chain_client.explore_chain_metadata(no_docs).await
        }
        Commands::MetadataSubxt {
            no_docs,
            stats_only,
        } => metadata_subxt::handle_metadata_subxt_command(node_url, no_docs, stats_only).await,
        Commands::Version => {
            log_print!("CLI Version: Quantus CLI v{}", env!("CARGO_PKG_VERSION"));

            let chain_client = crate::chain::client::ChainClient::new(node_url).await?;
            let node_version = chain_client.get_node_version().await?;
            log_print!("Node Version: {}", node_version);

            // You might need to implement get_runtime_version in your ChainClient
            match chain_client.get_runtime_version().await {
                Ok(runtime_version) => {
                    log_print!("Runtime Version: {}", runtime_version);
                }
                Err(e) => {
                    log_error!("Failed to get runtime version: {}", e);
                }
            }
            Ok(())
        }
    }
}

/// Handle generic extrinsic call command
async fn handle_generic_call_command(
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

    let chain_client = crate::chain::client::ChainClient::new(node_url).await?;

    generic_call::execute_generic_call(&chain_client, &pallet, &call, args_vec, &from, tip).await
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
        log_error!("❌ Offline mode is not yet implemented in SubXT version");
        log_print!("💡 Currently only live submission is supported");
        return Ok(());
    }

    if call_data_only {
        log_error!("❌ Call-data-only mode is not yet implemented in SubXT version");
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
