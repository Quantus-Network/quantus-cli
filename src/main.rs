/*!
 * Quantus CLI - Command line interface for the Quantus Network
 *
 * A modern, user-friendly CLI for interacting with the Quantus blockchain,
 * featuring built-in wallet management and simplified chain operations.
 */

use clap::Parser;
use colored::Colorize;

mod bins;
mod chain;
mod cli;
mod collect_rewards_lib;
mod config;
mod error;
mod log;
mod subsquid;
mod version_check;
mod wallet;
mod wormhole_lib;

use cli::Commands;
use error::QuantusError;

#[derive(Parser)]
#[command(name = "quantus")]
#[command(author = "Quantus Network")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Command line interface for the Quantus Network", long_about = None)]
#[command(arg_required_else_help = true)]
struct Cli {
	#[command(subcommand)]
	command: Commands,

	/// Enable verbose logging
	#[arg(short, long, global = true)]
	verbose: bool,

	/// Node endpoint URL
	#[arg(long, global = true, default_value = "ws://127.0.0.1:9944")]
	node_url: String,

	/// Wait for transaction finalization before returning
	/// Implies `--wait-for-transaction`
	/// NOTE: waiting for finalized transaction may take a while in PoW chain
	#[arg(long, global = true, default_value = "false")]
	finalized_tx: bool,

	/// Wait for transaction inclusion in a best block before returning
	/// Default: false
	#[arg(long, global = true, default_value = "false")]
	wait_for_transaction: bool,
}

#[tokio::main]
async fn main() -> Result<(), QuantusError> {
	sp_core::crypto::set_default_ss58_version(sp_core::crypto::Ss58AddressFormat::custom(189));
	let cli = Cli::parse();

	// Set up our custom logging
	log::set_verbose(cli.verbose);

	// Print welcome message
	log_print!("{}", "🔮 Quantus CLI".bright_cyan().bold());
	log_verbose!("{}", "Connecting to the quantum future...".dimmed());
	log_verbose!("");

	// Display warning about finalization
	if cli.finalized_tx {
		log_print!("⚠️ Warning: Waiting for finalized block may take a while in PoW chain.");
	}

	// Create execution mode from CLI args
	let execution_mode = cli::common::ExecutionMode {
		finalized: cli.finalized_tx,
		wait_for_transaction: cli.wait_for_transaction,
	};

	// Kick off the update check in the background so it runs concurrently with
	// the command and doesn't add latency. It's best-effort and never fails.
	// Skip it for the `update` command, which performs its own version check.
	let update_check = if matches!(cli.command, Commands::Update { .. }) {
		None
	} else {
		Some(tokio::spawn(version_check::notify_if_update_available()))
	};

	// Execute the command with timing
	let start_time = std::time::Instant::now();
	let result =
		cli::execute_command(cli.command, &cli.node_url, cli.verbose, execution_mode).await;
	let elapsed = start_time.elapsed();

	match result {
		Ok(_) => {
			log_verbose!("");
			log_verbose!("Command executed successfully!");
			log_print!("⏱️  Completed in {:.2}s", elapsed.as_secs_f64());
			finish_update_check(update_check).await;
			Ok(())
		},
		Err(e) => {
			log_error!("{}", e);
			log_print!("⏱️  Failed after {:.2}s", elapsed.as_secs_f64());
			finish_update_check(update_check).await;
			std::process::exit(1);
		},
	}
}

/// Wait for the background update check to finish so its notice (if any) is
/// printed after the command output. Bounded by a short timeout so a slow
/// network can never hold up the CLI.
async fn finish_update_check(handle: Option<tokio::task::JoinHandle<()>>) {
	if let Some(handle) = handle {
		let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
	}
}
