//! `quantus treasury` subcommand – Treasury account info
//!
//! The chain Treasury is a single account that receives a configurable portion of mining rewards.
//! This command shows the treasury account and its balance.
use crate::{chain::quantus_subxt, cli::address_format::QuantusSS58, log_print};
use clap::Subcommand;
use colored::Colorize;

/// Treasury commands
#[derive(Subcommand, Debug)]
pub enum TreasuryCommands {
	/// Show Treasury account and balance
	Info,
}

/// Handle treasury commands
pub async fn handle_treasury_command(
	command: TreasuryCommands,
	node_url: &str,
	_execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		TreasuryCommands::Info => show_treasury_info(&quantus_client).await,
	}
}

/// Show Treasury account, portion and balance
async fn show_treasury_info(
	quantus_client: &crate::chain::client::QuantusClient,
) -> crate::error::Result<()> {
	log_print!("💰 Treasury");
	log_print!("");

	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage_at = quantus_client.client().storage().at(latest_block_hash);

	// Treasury account from pallet storage (receives mining rewards)
	let treasury_account_addr = quantus_subxt::api::storage().treasury_pallet().treasury_account();
	let treasury_account = storage_at.fetch(&treasury_account_addr).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic("Treasury account not set in storage".to_string())
	})?;

	// Portion of mining rewards that goes to treasury (0–100)
	let portion_addr = quantus_subxt::api::storage().treasury_pallet().treasury_portion();
	let portion = storage_at.fetch(&portion_addr).await?.unwrap_or(0);

	// Account balance
	let account_storage = quantus_subxt::api::storage().system().account(treasury_account.clone());
	let account_info = storage_at.fetch(&account_storage).await?.ok_or_else(|| {
		crate::error::QuantusError::Generic("Treasury account not found in system".to_string())
	})?;

	let free = account_info.data.free;
	let reserved = account_info.data.reserved;

	let formatted_free = crate::cli::send::format_balance_with_symbol(quantus_client, free).await?;
	let formatted_reserved =
		crate::cli::send::format_balance_with_symbol(quantus_client, reserved).await?;

	let account_ss58 = treasury_account.to_quantus_ss58();
	log_print!("📍 Account: {}", account_ss58.bright_yellow());
	log_print!("📊 Reward portion: {}%", portion.to_string().bright_cyan());
	log_print!("💰 Free: {}", formatted_free);
	log_print!("💰 Reserved: {}", formatted_reserved);

	Ok(())
}
