use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;

pub mod address_format;
pub mod batch;
pub mod block;
pub mod cold_signing;
pub mod common;
pub mod events;
pub mod exercise;
pub mod generic_call;
pub mod high_security;
pub mod metadata;
pub mod multisend;
pub mod multisig;
pub mod preimage;
pub mod recovery;
pub mod reversible;
pub mod runtime;
pub mod scheduler;
pub mod send;
pub mod storage;
pub mod system;
pub mod tech_collective;
pub mod tech_referenda;
pub mod transfers;
pub mod treasury;
pub mod update;
pub mod wallet;
pub mod wormhole;

/// Main CLI commands
#[derive(Subcommand, Debug)]
pub enum Commands {
	/// Wallet management commands
	#[command(subcommand)]
	Wallet(wallet::WalletCommands),

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
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Optional tip amount to prioritize the transaction (e.g., "1", "0.5")
		#[arg(long)]
		tip: Option<String>,

		/// Manual nonce override (use with caution - must be exact next nonce for account)
		#[arg(long)]
		nonce: Option<u32>,
	},

	/// Batch transfer commands and configuration
	#[command(subcommand)]
	Batch(batch::BatchCommands),

	/// Reversible transfer commands
	#[command(subcommand)]
	Reversible(reversible::ReversibleCommands),

	/// High-Security commands (reversible account settings)
	#[command(subcommand)]
	HighSecurity(high_security::HighSecurityCommands),

	/// Recovery commands
	#[command(subcommand)]
	Recovery(recovery::RecoveryCommands),

	/// Multisig commands (multi-signature wallets)
	#[command(subcommand)]
	Multisig(multisig::MultisigCommands),

	/// Scheduler commands
	#[command(subcommand)]
	Scheduler(scheduler::SchedulerCommands),

	/// Direct interaction with chain storage (read-only)
	#[command(subcommand)]
	Storage(storage::StorageCommands),

	/// Tech Collective management commands
	#[command(subcommand)]
	TechCollective(tech_collective::TechCollectiveCommands),

	/// Preimage management commands
	#[command(subcommand)]
	Preimage(preimage::PreimageCommands),

	/// Tech Referenda management commands (for runtime upgrade proposals)
	#[command(subcommand)]
	TechReferenda(tech_referenda::TechReferendaCommands),

	/// Treasury account info
	#[command(subcommand)]
	Treasury(treasury::TreasuryCommands),

	/// Privacy-preserving transfer queries via Subsquid indexer
	#[command(subcommand)]
	Transfers(transfers::TransfersCommands),

	/// Runtime management commands (via governance where required)
	#[command(subcommand)]
	Runtime(runtime::RuntimeCommands),

	/// Generic extrinsic call - call ANY pallet function!
	Call {
		/// Pallet name (e.g., "Balances")
		#[arg(long)]
		pallet: String,

		/// Call/function name (e.g., "transfer_allow_death")
		#[arg(short, long)]
		call: String,

		/// Arguments as JSON array (e.g., '["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
		/// "1000000000000"]')
		#[arg(short, long)]
		args: Option<String>,

		/// Wallet name to sign with
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long, hide = true)]
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

	/// Run the chain exercise suite against a live node
	Exercise(exercise::ExerciseArgs),

	/// Query events from blocks
	Events {
		/// Block number to query events from (full support)
		#[arg(long)]
		block: Option<u32>,

		/// Block hash to query events from (full support)
		#[arg(long)]
		block_hash: Option<String>,

		/// Query events from latest block
		#[arg(long)]
		latest: bool,

		/// Query events from finalized block (full support)
		#[arg(long)]
		finalized: bool,

		/// Filter events by pallet name (e.g., "Balances")
		#[arg(long)]
		pallet: Option<String>,

		/// Show raw event data
		#[arg(long)]
		raw: bool,

		/// Disable event decoding (decoding is enabled by default)
		#[arg(long)]
		no_decode: bool,
	},

	/// Query system information
	System {
		/// Show runtime version information
		#[arg(long)]
		runtime: bool,

		/// Show metadata statistics
		#[arg(long)]
		metadata: bool,

		/// Show available JSON-RPC methods exposed by the node
		#[arg(long)]
		rpc_methods: bool,
	},

	/// Explore chain metadata and available pallets/calls
	Metadata {
		/// Skip displaying documentation for calls
		#[arg(long)]
		no_docs: bool,

		/// Show only metadata statistics
		#[arg(long)]
		stats_only: bool,

		/// Filter by specific pallet name
		#[arg(long)]
		pallet: Option<String>,
	},

	/// Show version information
	Version,

	/// Update the CLI to the latest release
	Update {
		/// Only check whether a newer version is available (don't install)
		#[arg(long)]
		check: bool,

		/// Skip the confirmation prompt
		#[arg(long, short = 'y')]
		yes: bool,

		/// Install a specific version instead of the latest (e.g. "1.5.0")
		#[arg(long)]
		version: Option<String>,
	},

	/// Check compatibility with the connected node
	CompatibilityCheck,

	/// Block management and analysis commands
	#[command(subcommand)]
	Block(block::BlockCommands),

	/// Wormhole proof generation and verification
	#[command(subcommand)]
	Wormhole(wormhole::WormholeCommands),

	/// Send random amounts to multiple addresses (total is distributed randomly)
	Multisend {
		/// Wallet name to send from
		#[arg(short, long)]
		from: String,

		/// File containing addresses (JSON array: ["addr1", "addr2", ...])
		#[arg(long, conflicts_with = "addresses")]
		addresses_file: Option<String>,

		/// Comma-separated list of recipient addresses
		#[arg(long, value_delimiter = ',', conflicts_with = "addresses_file")]
		addresses: Option<Vec<String>>,

		/// Total amount to distribute across all recipients (e.g., "1000", "100.5")
		#[arg(long)]
		total: String,

		/// Minimum amount per recipient (e.g., "10", "1.5")
		#[arg(long)]
		min: String,

		/// Maximum amount per recipient (e.g., "100", "50.5")
		#[arg(long)]
		max: String,

		/// Password for the wallet (or use environment variables)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Optional tip amount to prioritize the transaction (e.g., "1", "0.5")
		#[arg(long)]
		tip: Option<String>,

		/// Skip confirmation prompt (for scripting)
		#[arg(long, short = 'y')]
		yes: bool,
	},
}

/// Developer subcommands
#[derive(Subcommand, Debug)]
pub enum DeveloperCommands {
	/// Create standard test wallets (crystal_alice, crystal_bob, crystal_charlie)
	CreateTestWallets,

	/// Simulate the cold-wallet side of QR signing using a local hot wallet.
	/// Reads a sign-request UR, signs it per the cold-wallet protocol, and
	/// emits the response UR. Unlike real devices, no genesis-hash allowlist
	/// is enforced, so it works against dev nodes.
	#[command(hide = true)]
	ColdSignSim {
		/// Hot wallet that plays the cold wallet's role
		#[arg(long)]
		wallet: String,

		/// File with the request UR parts, one per line (polls until complete; stdin if omitted)
		#[arg(long)]
		request_file: Option<String>,

		/// File to write the response UR parts to (stdout if omitted)
		#[arg(long)]
		response_file: Option<String>,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
}

/// Execute a CLI command
pub async fn execute_command(
	command: Commands,
	node_url: &str,
	verbose: bool,
	execution_mode: common::ExecutionMode,
) -> crate::error::Result<()> {
	match command {
		Commands::Wallet(wallet_cmd) => wallet::handle_wallet_command(wallet_cmd, node_url).await,
		Commands::Send { from, to, amount, password, password_file, tip, nonce } =>
			send::handle_send_command(
				from,
				to,
				&amount,
				node_url,
				password,
				password_file,
				tip,
				nonce,
				execution_mode,
			)
			.await,
		Commands::Batch(batch_cmd) =>
			batch::handle_batch_command(batch_cmd, node_url, execution_mode).await,
		Commands::Reversible(reversible_cmd) =>
			reversible::handle_reversible_command(reversible_cmd, node_url, execution_mode).await,
		Commands::HighSecurity(hs_cmd) =>
			high_security::handle_high_security_command(hs_cmd, node_url, execution_mode).await,
		Commands::Recovery(recovery_cmd) =>
			recovery::handle_recovery_command(recovery_cmd, node_url, execution_mode).await,
		Commands::Multisig(multisig_cmd) =>
			multisig::handle_multisig_command(multisig_cmd, node_url, execution_mode).await,
		Commands::Scheduler(scheduler_cmd) =>
			scheduler::handle_scheduler_command(scheduler_cmd, node_url, execution_mode).await,
		Commands::Storage(storage_cmd) =>
			storage::handle_storage_command(storage_cmd, node_url, execution_mode).await,
		Commands::TechCollective(tech_collective_cmd) =>
			tech_collective::handle_tech_collective_command(
				tech_collective_cmd,
				node_url,
				execution_mode,
			)
			.await,
		Commands::Preimage(preimage_cmd) =>
			preimage::handle_preimage_command(preimage_cmd, node_url, execution_mode).await,
		Commands::TechReferenda(tech_referenda_cmd) =>
			tech_referenda::handle_tech_referenda_command(
				tech_referenda_cmd,
				node_url,
				execution_mode,
			)
			.await,
		Commands::Treasury(treasury_cmd) =>
			treasury::handle_treasury_command(treasury_cmd, node_url, execution_mode).await,
		Commands::Transfers(transfers_cmd) =>
			transfers::handle_transfers_command(transfers_cmd, node_url).await,
		Commands::Runtime(runtime_cmd) =>
			runtime::handle_runtime_command(runtime_cmd, node_url, execution_mode).await,
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
		} =>
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
				execution_mode,
			)
			.await,
		Commands::Balance { address } => {
			let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

			// Resolve address (could be wallet name or SS58 address)
			let resolved_address = common::resolve_address(&address)?;

			let account_data = send::get_account_data(&quantus_client, &resolved_address).await?;
			let (symbol, decimals) = send::get_chain_properties(&quantus_client).await?;

			let free_fmt = send::format_balance(account_data.free, decimals);
			let reserved_fmt = send::format_balance(account_data.reserved, decimals);
			let frozen_fmt = send::format_balance(account_data.frozen, decimals);

			log_print!("💰 {} {}", "Balance".bright_green().bold(), resolved_address.bright_cyan());
			log_print!("   Free:     {} {}", free_fmt.bright_green(), symbol);
			log_print!("   Reserved: {} {}", reserved_fmt.bright_yellow(), symbol);
			log_print!("   Frozen:   {} {}", frozen_fmt.bright_red(), symbol);
			Ok(())
		},
		Commands::Developer(dev_cmd) => handle_developer_command(dev_cmd).await,
		Commands::Exercise(exercise_args) =>
			exercise::handle_exercise_command(exercise_args, node_url).await,
		Commands::Events { block, block_hash, latest: _, finalized, pallet, raw, no_decode } =>
			events::handle_events_command(
				block, block_hash, finalized, pallet, raw, !no_decode, node_url,
			)
			.await,
		Commands::System { runtime, metadata, rpc_methods } => {
			if runtime || metadata || rpc_methods {
				system::handle_system_extended_command(
					node_url,
					runtime,
					metadata,
					rpc_methods,
					verbose,
				)
				.await
			} else {
				system::handle_system_command(node_url).await
			}
		},
		Commands::Metadata { no_docs, stats_only, pallet } =>
			metadata::handle_metadata_command(node_url, no_docs, stats_only, pallet).await,
		Commands::Version => {
			log_print!("CLI Version: Quantus CLI v{}", env!("CARGO_PKG_VERSION"));
			Ok(())
		},
		Commands::Update { check, yes, version } =>
			update::handle_update_command(check, yes, version).await,
		Commands::CompatibilityCheck => handle_compatibility_check(node_url).await,
		Commands::Block(block_cmd) => block::handle_block_command(block_cmd, node_url).await,
		Commands::Wormhole(wormhole_cmd) =>
			wormhole::handle_wormhole_command(wormhole_cmd, node_url).await,
		Commands::Multisend {
			from,
			addresses_file,
			addresses,
			total,
			min,
			max,
			password,
			password_file,
			tip,
			yes,
		} =>
			multisend::handle_multisend_command(
				from,
				node_url,
				addresses_file,
				addresses,
				total,
				min,
				max,
				password,
				password_file,
				tip,
				yes,
				execution_mode,
			)
			.await,
	}
}

/// Handle generic extrinsic call command
#[allow(clippy::too_many_arguments)]
async fn handle_generic_call_command(
	pallet: String,
	call: String,
	args: Option<String>,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	tip: Option<String>,
	offline: bool,
	call_data_only: bool,
	node_url: &str,
	execution_mode: common::ExecutionMode,
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

	let signer = crate::wallet::load_signer_from_wallet(&from, password, password_file)?;

	let args_vec = if let Some(args_str) = args {
		serde_json::from_str(&args_str).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid JSON for arguments: {e}"))
		})?
	} else {
		vec![]
	};

	generic_call::handle_generic_call(
		&pallet,
		&call,
		args_vec,
		&signer,
		tip,
		node_url,
		execution_mode,
	)
	.await
}

/// Handle developer subcommands
pub async fn handle_developer_command(command: DeveloperCommands) -> crate::error::Result<()> {
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
					},
					Err(e) => {
						log_error!("❌ Failed to create {}: {}", name.bright_red(), e);
					},
				}
			}

			log_print!("");
			log_success!("🎉 Test wallet creation complete!");
			log_success!("   Created: {} wallets", created_count.to_string().bright_green());
			log_print!("");
			log_print!("💡 {} You can now use these wallets:", "TIP".bright_blue().bold());
			log_print!("   quantus send --from crystal_alice --to <address> --amount 1000");
			log_print!("   quantus send --from crystal_bob --to <address> --amount 1000");
			log_print!("   quantus send --from crystal_charlie --to <address> --amount 1000");
			log_print!("");

			Ok(())
		},
		DeveloperCommands::ColdSignSim {
			wallet,
			request_file,
			response_file,
			password,
			password_file,
		} =>
			cold_signing::handle_cold_sign_sim(
				wallet,
				request_file,
				response_file,
				password,
				password_file,
			)
			.await,
	}
}

/// Handle compatibility check command
async fn handle_compatibility_check(node_url: &str) -> crate::error::Result<()> {
	log_print!("🔍 Compatibility Check");
	log_print!("🔗 Connecting to: {}", node_url.bright_cyan());
	log_print!("");

	// Connect without the runtime identity gate: this command exists precisely to
	// diagnose nodes the rest of the CLI refuses to talk to.
	let quantus_client =
		crate::chain::client::QuantusClient::new_without_runtime_check(node_url).await?;

	// Fetch the raw runtime version so we can inspect the spec name too.
	use jsonrpsee::core::client::ClientT;
	let runtime_version: serde_json::Value = quantus_client
		.rpc_client()
		.request::<serde_json::Value, [(); 0]>("state_getRuntimeVersion", [])
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to fetch runtime version: {e:?}"
			))
		})?;
	let spec_name = runtime_version["specName"].as_str().unwrap_or("<missing>").to_string();
	let spec_version = runtime_version["specVersion"].as_u64().unwrap_or(0) as u32;
	let impl_version = runtime_version["implVersion"].as_u64().unwrap_or(0) as u32;
	let transaction_version = runtime_version["transactionVersion"].as_u64().unwrap_or(0) as u32;

	// Chain info is best-effort: an incompatible node may not support the ChainHead API.
	let chain_info = system::get_complete_chain_info(node_url).await.ok();

	log_print!("📋 Version Information:");
	log_print!("   • CLI Version: {}", env!("CARGO_PKG_VERSION").bright_green());
	log_print!("   • Runtime Spec Name: {}", spec_name.bright_cyan());
	log_print!("   • Runtime Spec Version: {}", spec_version.to_string().bright_yellow());
	log_print!("   • Runtime Impl Version: {}", impl_version.to_string().bright_blue());
	log_print!("   • Transaction Version: {}", transaction_version.to_string().bright_magenta());

	if let Some(name) = chain_info.as_ref().and_then(|info| info.chain_name.as_ref()) {
		log_print!("   • Chain Name: {}", name.bright_cyan());
	}

	log_print!("");

	// Check compatibility
	let name_matches = spec_name == crate::config::EXPECTED_RUNTIME_SPEC_NAME;
	let version_compatible =
		crate::config::is_runtime_compatible(spec_version, transaction_version);

	log_print!("🔍 Compatibility Analysis:");
	log_print!("   • Expected spec name: {}", crate::config::EXPECTED_RUNTIME_SPEC_NAME);
	log_print!("   • Supported runtime/transaction pairs:");
	for runtime in crate::config::COMPATIBLE_RUNTIMES {
		log_print!("     - spec {} / tx {}", runtime.spec_version, runtime.transaction_version);
	}
	log_print!("   • Current Spec Name: {spec_name}");
	log_print!("   • Current Runtime Version: {spec_version}");
	log_print!("   • Current Transaction Version: {transaction_version}");

	if name_matches && version_compatible {
		log_success!("✅ COMPATIBLE - This CLI version supports the connected node");
		log_print!("   • All features should work correctly");
		log_print!("   • You can safely use all CLI commands");
	} else if !name_matches {
		log_error!("❌ INCOMPATIBLE - The connected node is not running a Quantus runtime");
		log_print!(
			"   • Runtime identifies as '{}', expected '{}'",
			spec_name,
			crate::config::EXPECTED_RUNTIME_SPEC_NAME
		);
		log_print!("   • All other CLI commands will refuse to talk to this node");
	} else {
		log_error!("❌ INCOMPATIBLE - This CLI version may not work with the connected node");
		log_print!("   • The runtime version pair is not in this CLI's supported list");
		log_print!("   • Some features may not work correctly");
		log_print!("   • Consider updating the CLI or connecting to a compatible node");
	}

	log_print!("");
	log_print!("💡 Tip: Use 'quantus version' for quick version check");
	log_print!("💡 Tip: Use 'quantus system --runtime' for detailed system info");

	Ok(())
}
