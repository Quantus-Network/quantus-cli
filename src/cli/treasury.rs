//! `quantus treasury` subcommand - manage Treasury
use crate::{chain::quantus_subxt, log_print};
use clap::Subcommand;
use colored::Colorize;

/// Treasury management commands
#[derive(Subcommand, Debug)]
pub enum TreasuryCommands {
	/// Check current Treasury balance
	Balance,

	/// Get Treasury configuration  
	Config,

	/// Show Treasury information and how to spend from it
	Info,
}

/// Handle treasury commands
pub async fn handle_treasury_command(
	command: TreasuryCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		TreasuryCommands::Balance => get_treasury_balance(&quantus_client).await,
		TreasuryCommands::Config => get_config(&quantus_client).await,
		TreasuryCommands::Info => show_treasury_info().await,
	}
}

/// Get current Treasury balance
async fn get_treasury_balance(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("💰 Treasury Balance");
	log_print!("");

	// Get Treasury account ID
	// PalletId("py/trsry") converts to account using "modl" prefix
	let mut full_data = [0u8; 32];
	full_data[0..4].copy_from_slice(b"modl");
	full_data[4..12].copy_from_slice(b"py/trsry");
	let treasury_account = subxt::utils::AccountId32(full_data);

	// Query balance
	let addr = quantus_subxt::api::storage().system().account(treasury_account.clone());

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	let account_info = storage_at.fetch(&addr).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic("Treasury account not found".to_string())
	})?;

	let free_balance = account_info.data.free;
	let reserved_balance = account_info.data.reserved;

	let formatted_free_balance =
		crate::cli::send::format_balance_with_symbol(quantus_client, free_balance).await?;
	let formatted_reserved_balance =
		crate::cli::send::format_balance_with_symbol(quantus_client, reserved_balance).await?;

	log_print!("💰 Free Balance: {}", formatted_free_balance);
	log_print!("💰 Reserved: {}", formatted_reserved_balance);
	log_print!("📍 Treasury Account: {}", treasury_account.to_string().bright_yellow());

	Ok(())
}

/// Get Treasury configuration
async fn get_config(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("⚙️  Treasury Configuration");
	log_print!("");

	let constants = quantus_client.client().constants();

	// Get SpendPeriod
	if let Ok(spend_period) =
		constants.at(&quantus_subxt::api::constants().treasury_pallet().spend_period())
	{
		log_print!("⏰ Spend Period: {} blocks", spend_period.to_string().bright_cyan());
		let hours = spend_period as f64 * 3.0 / 3600.0; // Assuming 3 sec blocks
		log_print!("   (~{:.1} hours)", hours);
	}

	// Get Burn percentage
	if let Ok(burn) = constants.at(&quantus_subxt::api::constants().treasury_pallet().burn()) {
		log_print!("🔥 Burn: {:?}", burn);
	}

	// Get MaxApprovals
	if let Ok(max_approvals) =
		constants.at(&quantus_subxt::api::constants().treasury_pallet().max_approvals())
	{
		log_print!("📊 Max Approvals: {}", max_approvals.to_string().bright_yellow());
	}

	// Get PayoutPeriod
	if let Ok(payout_period) =
		constants.at(&quantus_subxt::api::constants().treasury_pallet().payout_period())
	{
		log_print!("💸 Payout Period: {} blocks", payout_period.to_string().bright_green());
		let days = payout_period as f64 * 3.0 / 86400.0; // Assuming 3 sec blocks
		log_print!("   (~{:.1} days)", days);
	}

	Ok(())
}

/// Show Treasury information
async fn show_treasury_info() -> crate::error::Result<()> {
	log_print!("💰 Treasury Information");
	log_print!("");
	log_print!("The Treasury is a pot of funds collected through:");
	log_print!("   • Transaction fees");
	log_print!("   • Slashing");
	log_print!("   • Other network mechanisms");
	log_print!("");
	log_print!("📋 {} To spend from Treasury:", "HOW TO USE".bright_cyan().bold());
	log_print!("");
	log_print!(
		"1. {} Create a spending proposal using Referenda:",
		"Treasury Tracks".bright_yellow().bold()
	);
	log_print!("   • Track 2: Treasury Small Spender (< certain amount)");
	log_print!("   • Track 3: Treasury Medium Spender");
	log_print!("   • Track 4: Treasury Big Spender");
	log_print!("   • Track 5: Treasury Treasurer (highest amounts)");
	log_print!("");
	log_print!(
		"2. {} Submit referendum with Treasury spend call:",
		"Example".bright_green().bold()
	);
	log_print!(
		"   quantus referenda submit-remark --message \"Treasury spend: 1000 QUAN to Alice\""
	);
	log_print!("   --from <YOUR_WALLET> --password <PASSWORD>");
	log_print!("");
	log_print!("   Note: Use appropriate origin for treasury tracks");
	log_print!("");
	log_print!("3. {} Community votes on the proposal", "Voting".bright_magenta().bold());
	log_print!("");
	log_print!("4. {} If approved, funds are paid automatically", "Execution".bright_blue().bold());
	log_print!("");
	log_print!("💡 {}", "Useful Commands:".bright_cyan().bold());
	log_print!("   quantus treasury balance     - Check Treasury balance");
	log_print!("   quantus treasury config      - View Treasury configuration");
	log_print!("   quantus referenda config     - View available tracks");
	log_print!("");

	Ok(())
}
