/*!
 * Quantus CLI - Command line interface for the Quantus Network
 *
 * A modern, user-friendly CLI for interacting with the Quantus blockchain,
 * featuring built-in wallet management and simplified chain operations.
 */

use clap::Parser;
use colored::Colorize;

mod chain;
mod cli;
mod config;
mod error;
mod log;
mod subsquid;
mod wallet;

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

	/// Transaction finalization
	/// NOTE: waiting for finalized transaction may take a while in PoW chain
	#[arg(long, global = true, default_value = "false")]
	finalized_tx: bool,

	/// Wait for transaction validation/inclusion before returning
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
			Ok(())
		},
		Err(e) => {
			log_error!("{}", e);
			log_print!("⏱️  Failed after {:.2}s", elapsed.as_secs_f64());
			std::process::exit(1);
		},
	}
}
