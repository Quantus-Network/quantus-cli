//! Privacy-preserving transfer queries via Subsquid indexer.
//!
//! This module provides commands for querying transfers using hash prefix queries,
//! which allows clients to retrieve their transactions without revealing their
//! exact addresses to the indexer.

use crate::error::{QuantusError, Result};
use crate::subsquid::{compute_address_hash, get_hash_prefix, SubsquidClient, TransferQueryParams};
use crate::wallet::WalletManager;
use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};

/// Transfers subcommands
#[derive(Subcommand, Debug)]
pub enum TransfersCommands {
	/// Query transfers for your wallet addresses using privacy-preserving hash prefix queries
	Query {
		/// Subsquid indexer URL (e.g., "https://indexer.quantus.com/graphql")
		#[arg(long)]
		subsquid_url: String,

		/// Hash prefix length in hex characters (1-64).
		/// Shorter = more privacy but more noise, longer = less privacy but fewer false positives.
		/// Default: 4 (1/65536 of address space per prefix)
		#[arg(long, default_value = "4")]
		prefix_len: usize,

		/// Only show transfers after this block number
		#[arg(long)]
		after_block: Option<u32>,

		/// Only show transfers before this block number
		#[arg(long)]
		before_block: Option<u32>,

		/// Minimum transfer amount (in smallest unit, e.g., planck)
		#[arg(long)]
		min_amount: Option<u128>,

		/// Maximum number of results (default: 100, max: 1000)
		#[arg(long, default_value = "100")]
		limit: u32,

		/// Specific wallet name to query for (if not provided, queries all wallets)
		#[arg(long)]
		wallet: Option<String>,

		/// Show raw transfer data as JSON
		#[arg(long)]
		json: bool,
	},

	/// Compute the hash prefix for an address (for debugging/testing)
	HashAddress {
		/// The address to hash (SS58 format)
		address: String,

		/// Prefix length to display
		#[arg(long, default_value = "4")]
		prefix_len: usize,
	},
}

/// Handle transfers commands
pub async fn handle_transfers_command(cmd: TransfersCommands) -> Result<()> {
	match cmd {
		TransfersCommands::Query {
			subsquid_url,
			prefix_len,
			after_block,
			before_block,
			min_amount,
			limit,
			wallet,
			json,
		} => {
			handle_query_command(
				subsquid_url,
				prefix_len,
				after_block,
				before_block,
				min_amount,
				limit,
				wallet,
				json,
			)
			.await
		},
		TransfersCommands::HashAddress { address, prefix_len } => {
			handle_hash_address_command(&address, prefix_len)
		},
	}
}

/// Handle the query subcommand
#[allow(clippy::too_many_arguments)]
async fn handle_query_command(
	subsquid_url: String,
	prefix_len: usize,
	after_block: Option<u32>,
	before_block: Option<u32>,
	min_amount: Option<u128>,
	limit: u32,
	wallet_name: Option<String>,
	json_output: bool,
) -> Result<()> {
	// Validate prefix length
	if prefix_len == 0 || prefix_len > 64 {
		return Err(QuantusError::Generic("Prefix length must be between 1 and 64".to_string()));
	}

	// Load wallet addresses
	let wallet_manager = WalletManager::new()?;
	let wallets = wallet_manager.list_wallets()?;

	if wallets.is_empty() {
		log_error!("No wallets found. Create a wallet first with 'quantus wallet create'");
		return Ok(());
	}

	// Filter to specific wallet if requested
	let wallets_to_query: Vec<_> = if let Some(name) = &wallet_name {
		wallets.into_iter().filter(|w| w.name == *name).collect()
	} else {
		wallets
	};

	if wallets_to_query.is_empty() {
		log_error!("No matching wallet found");
		return Ok(());
	}

	// Convert SS58 addresses to raw account IDs
	let mut raw_addresses: Vec<[u8; 32]> = Vec::new();
	for wallet in &wallets_to_query {
		let account_id = AccountId32::from_ss58check(&wallet.address).map_err(|e| {
			QuantusError::Generic(format!("Invalid address {}: {}", wallet.address, e))
		})?;
		raw_addresses.push(account_id.into());
	}

	if !json_output {
		log_print!("{}", "Privacy-Preserving Transfer Query".bright_cyan().bold());
		log_print!("");
		log_print!(
			"  Querying for {} wallet(s) with prefix length {}",
			wallets_to_query.len().to_string().bright_yellow(),
			prefix_len.to_string().bright_yellow()
		);
		log_print!(
			"  Privacy level: ~1/{} of address space per query",
			(1u64 << (prefix_len * 4)).to_string().bright_green()
		);
		log_print!("");
	}

	// Create Subsquid client
	let client = SubsquidClient::new(subsquid_url)?;

	// Build query params
	let mut params = TransferQueryParams::new().with_limit(limit);
	if let Some(block) = after_block {
		params = params.with_after_block(block);
	}
	if let Some(block) = before_block {
		params = params.with_before_block(block);
	}
	if let Some(amount) = min_amount {
		params = params.with_min_amount(amount);
	}

	// Query transfers
	let transfers =
		client.query_transfers_for_addresses(&raw_addresses, prefix_len, params).await?;

	if json_output {
		// Output as JSON
		let json = serde_json::to_string_pretty(&transfers)
			.map_err(|e| QuantusError::Generic(format!("Failed to serialize transfers: {}", e)))?;
		println!("{}", json);
	} else {
		// Display formatted output
		if transfers.is_empty() {
			log_print!("No transfers found for your addresses.");
		} else {
			log_success!("Found {} transfers:", transfers.len().to_string().bright_green());
			log_print!("");

			for transfer in &transfers {
				// Determine if this is incoming or outgoing
				let our_address_hashes: std::collections::HashSet<String> =
					raw_addresses.iter().map(compute_address_hash).collect();

				let is_incoming = our_address_hashes.contains(&transfer.to_hash);
				let is_outgoing = our_address_hashes.contains(&transfer.from_hash);

				let direction = match (is_incoming, is_outgoing) {
					(true, true) => "SELF".bright_blue(),
					(true, false) => "IN".bright_green(),
					(false, true) => "OUT".bright_red(),
					(false, false) => "???".dimmed(), // Shouldn't happen
				};

				// Parse and format amount
				let amount: u128 = transfer.amount.parse().unwrap_or(0);
				let formatted_amount = format_planck_amount(amount);

				log_print!(
					"  [{}] {} | Block {} | {} | {} -> {}",
					direction,
					&transfer.timestamp[..19], // Truncate to YYYY-MM-DDTHH:MM:SS
					transfer.block_height.to_string().bright_yellow(),
					formatted_amount.bright_cyan(),
					truncate_address(&transfer.from_id),
					truncate_address(&transfer.to_id),
				);

				if let Some(hash) = &transfer.extrinsic_hash {
					log_verbose!("       Extrinsic: {}", hash.dimmed());
				}
			}
		}
	}

	Ok(())
}

/// Handle the hash-address subcommand
fn handle_hash_address_command(address: &str, prefix_len: usize) -> Result<()> {
	// Parse the SS58 address
	let account_id = AccountId32::from_ss58check(address)
		.map_err(|e| QuantusError::Generic(format!("Invalid address: {}", e)))?;

	let raw_address: [u8; 32] = account_id.into();
	let full_hash = compute_address_hash(&raw_address);
	let prefix = get_hash_prefix(&full_hash, prefix_len);

	log_print!("{}", "Address Hash Information".bright_cyan().bold());
	log_print!("");
	log_print!("  Address:     {}", address.bright_yellow());
	log_print!("  Full Hash:   {}", full_hash.dimmed());
	log_print!("  Prefix ({}): {}", prefix_len, prefix.bright_green().bold());
	log_print!("");
	log_print!(
		"  Privacy: With prefix length {}, your query will match ~1/{} of all addresses",
		prefix_len,
		(1u64 << (prefix_len * 4)).to_string().bright_cyan()
	);

	Ok(())
}

/// Format a planck amount to a human-readable string
fn format_planck_amount(planck: u128) -> String {
	// Assuming 12 decimal places (standard for Substrate chains)
	let decimals = 12u32;
	let divisor = 10u128.pow(decimals);
	let whole = planck / divisor;
	let frac = planck % divisor;

	if frac == 0 {
		format!("{} DEV", whole)
	} else {
		// Format with up to 4 decimal places
		let frac_str = format!("{:012}", frac);
		let trimmed = frac_str.trim_end_matches('0');
		let display_frac = if trimmed.len() > 4 { &trimmed[..4] } else { trimmed };
		format!("{}.{} DEV", whole, display_frac)
	}
}

/// Truncate an address for display
fn truncate_address(address: &str) -> String {
	if address.len() > 16 {
		format!("{}...{}", &address[..8], &address[address.len() - 6..])
	} else {
		address.to_string()
	}
}
