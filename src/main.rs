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
mod wallet;

use cli::Commands;
use error::QuantusError;

#[derive(Parser)]
#[command(name = "quantus")]
#[command(author = "Quantus Network")]
#[command(version = "0.1.0")]
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

    // Execute the command
    match cli::execute_command(cli.command, &cli.node_url).await {
        Ok(_) => {
            log_verbose!("");
            log_verbose!("Command executed successfully!");
            Ok(())
        }
        Err(e) => {
            log_error!("{}", e);
            std::process::exit(1);
        }
    }
}
