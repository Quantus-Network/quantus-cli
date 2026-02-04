//! Multisend command - send random amounts to multiple addresses
//!
//! Distributes a total amount across multiple recipients with random amounts,
//! subject to min/max constraints per recipient.

use crate::{
	chain::client::QuantusClient,
	cli::{
		common::{resolve_address, ExecutionMode},
		send::{
			batch_transfer, format_balance, format_balance_with_symbol, get_balance,
			get_chain_properties, parse_amount,
		},
	},
	error::{QuantusError, Result},
	log_info, log_print, log_success, log_verbose,
};
use colored::Colorize;
use rand::{seq::SliceRandom, Rng};
use std::{
	fs,
	io::{self, Write},
};

/// Generate a random distribution of amounts across n recipients.
///
/// Each amount will be in the range [min, max] and all amounts will sum to exactly `total`.
///
/// # Algorithm
/// 1. Start everyone at the minimum amount
/// 2. Randomly distribute the remaining amount (total - n*min) across recipients
/// 3. Shuffle the final amounts to avoid bias toward earlier recipients
///
/// # Errors
/// Returns an error if the constraints are unsatisfiable:
/// - `n * min > total` (not enough total to give everyone the minimum)
/// - `n * max < total` (can't fit the total even with everyone at maximum)
pub fn generate_random_distribution(
	n: usize,
	total: u128,
	min: u128,
	max: u128,
) -> Result<Vec<u128>> {
	if n == 0 {
		return Err(QuantusError::Generic("Cannot distribute to zero recipients".to_string()));
	}

	if min > max {
		return Err(QuantusError::Generic(format!(
			"Minimum amount ({}) cannot be greater than maximum amount ({})",
			min, max
		)));
	}

	let n_u128 = n as u128;
	let min_possible = n_u128.saturating_mul(min);
	let max_possible = n_u128.saturating_mul(max);

	if total < min_possible {
		return Err(QuantusError::Generic(format!(
			"Cannot distribute {} among {} recipients with min={}. \
			 Minimum required total: {}",
			total, n, min, min_possible
		)));
	}

	if total > max_possible {
		return Err(QuantusError::Generic(format!(
			"Cannot distribute {} among {} recipients with max={}. \
			 Maximum possible total: {}",
			total, n, max, max_possible
		)));
	}

	// Start everyone at the minimum
	let mut amounts: Vec<u128> = vec![min; n];
	let mut remaining = total - min_possible;

	// Randomly distribute the remaining amount
	let mut rng = rand::rng();

	while remaining > 0 {
		// Find recipients who can still receive more
		let eligible_indices: Vec<usize> = amounts
			.iter()
			.enumerate()
			.filter(|(_, &amt)| amt < max)
			.map(|(i, _)| i)
			.collect();

		if eligible_indices.is_empty() {
			// This shouldn't happen if our math is correct, but safety first
			break;
		}

		// Pick a random eligible recipient
		let recipient_idx = eligible_indices[rng.random_range(0..eligible_indices.len())];
		let headroom = max - amounts[recipient_idx];

		// Add a random amount (at least 1, at most headroom or remaining)
		let max_addition = headroom.min(remaining);
		let amount_to_add = if max_addition == 1 { 1 } else { rng.random_range(1..=max_addition) };

		amounts[recipient_idx] += amount_to_add;
		remaining -= amount_to_add;
	}

	// Shuffle to avoid any bias from the distribution order
	amounts.shuffle(&mut rng);

	// Sanity check
	let sum: u128 = amounts.iter().sum();
	debug_assert_eq!(sum, total, "Distribution sum mismatch");

	Ok(amounts)
}

/// Load addresses from a JSON file.
///
/// Expected format: `["addr1", "addr2", "addr3"]`
pub fn load_addresses_from_file(file_path: &str) -> Result<Vec<String>> {
	let content = fs::read_to_string(file_path).map_err(|e| {
		QuantusError::Generic(format!("Failed to read addresses file '{}': {}", file_path, e))
	})?;

	let addresses: Vec<String> = serde_json::from_str(&content).map_err(|e| {
		QuantusError::Generic(format!(
			"Failed to parse addresses file '{}'. Expected JSON array of strings: {}",
			file_path, e
		))
	})?;

	if addresses.is_empty() {
		return Err(QuantusError::Generic("Addresses file is empty".to_string()));
	}

	Ok(addresses)
}

/// Handle the multisend command
#[allow(clippy::too_many_arguments)]
pub async fn handle_multisend_command(
	from_wallet: String,
	node_url: &str,
	addresses_file: Option<String>,
	addresses_inline: Option<Vec<String>>,
	total_str: String,
	min_str: String,
	max_str: String,
	password: Option<String>,
	password_file: Option<String>,
	tip: Option<String>,
	skip_confirmation: bool,
	execution_mode: ExecutionMode,
) -> Result<()> {
	// Connect to chain
	let quantus_client = QuantusClient::new(node_url).await?;
	let (symbol, decimals) = get_chain_properties(&quantus_client).await?;

	// Parse addresses from file or inline
	let raw_addresses = if let Some(file_path) = addresses_file {
		load_addresses_from_file(&file_path)?
	} else if let Some(addrs) = addresses_inline {
		if addrs.is_empty() {
			return Err(QuantusError::Generic(
				"No addresses provided. Use --addresses or --addresses-file".to_string(),
			));
		}
		addrs
	} else {
		return Err(QuantusError::Generic(
			"No addresses provided. Use --addresses or --addresses-file".to_string(),
		));
	};

	// Resolve all addresses (could be wallet names or SS58 addresses)
	let mut resolved_addresses = Vec::with_capacity(raw_addresses.len());
	for addr in &raw_addresses {
		let resolved = resolve_address(addr)?;
		resolved_addresses.push(resolved);
	}

	let n = resolved_addresses.len();
	log_verbose!("Resolved {} addresses", n);

	// Parse amounts
	let total = parse_amount(&quantus_client, &total_str).await?;
	let min = parse_amount(&quantus_client, &min_str).await?;
	let max = parse_amount(&quantus_client, &max_str).await?;

	log_verbose!("Parsed amounts - total: {}, min: {}, max: {}", total, min, max);

	// Generate random distribution
	let amounts = generate_random_distribution(n, total, min, max)?;

	// Create transfers list
	let transfers: Vec<(String, u128)> =
		resolved_addresses.iter().cloned().zip(amounts.iter().cloned()).collect();

	// Display preview
	log_print!("");
	log_print!("{} Multisend Preview", "===".bright_cyan().bold());
	log_print!("");
	log_print!(
		"  Total amount:  {}",
		format!("{} {}", format_balance(total, decimals), symbol).bright_yellow().bold()
	);
	log_print!("  Recipients:    {}", n.to_string().bright_green());
	log_print!("  Min per recipient: {} {}", format_balance(min, decimals), symbol);
	log_print!("  Max per recipient: {} {}", format_balance(max, decimals), symbol);
	log_print!("");

	// Display table header
	log_print!("  {:>3} | {:<50} | {:>20}", "#".dimmed(), "Address".dimmed(), "Amount".dimmed());
	log_print!("  {:-<3}-+-{:-<50}-+-{:-<20}", "", "", "");

	// Display each transfer
	for (i, (addr, amount)) in transfers.iter().enumerate() {
		let formatted_amount = format!("{} {}", format_balance(*amount, decimals), symbol);

		// Truncate address for display if needed
		let display_addr = if addr.len() > 50 {
			format!("{}...{}", &addr[..24], &addr[addr.len() - 23..])
		} else {
			addr.clone()
		};

		log_print!(
			"  {:>3} | {:<50} | {:>20}",
			(i + 1).to_string().bright_white(),
			display_addr.bright_cyan(),
			formatted_amount.bright_yellow()
		);
	}

	// Display total line
	log_print!("  {:-<3}-+-{:-<50}-+-{:-<20}", "", "", "");
	let total_formatted = format!("{} {}", format_balance(total, decimals), symbol);
	log_print!(
		"  {:>3} | {:<50} | {:>20}",
		"",
		"Total".bold(),
		total_formatted.bright_green().bold()
	);
	log_print!("");

	// Prompt for confirmation unless --yes is passed
	if !skip_confirmation {
		print!("Proceed with this transaction? (yes/no): ");
		io::stdout().flush().unwrap();

		let mut input = String::new();
		io::stdin().read_line(&mut input).unwrap();

		if input.trim().to_lowercase() != "yes" {
			log_print!("Multisend cancelled.");
			return Ok(());
		}
		log_print!("");
	}

	// Send the transaction
	log_info!("Preparing multisend transaction...");

	// Load wallet
	let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;
	let from_account_id = keypair.to_account_id_ss58check();

	// Check balance
	let balance = get_balance(&quantus_client, &from_account_id).await?;
	let estimated_fee = 50_000_000_000u128; // Rough estimate for batch

	if balance < total + estimated_fee {
		let formatted_balance = format_balance_with_symbol(&quantus_client, balance).await?;
		let formatted_needed =
			format_balance_with_symbol(&quantus_client, total + estimated_fee).await?;
		return Err(QuantusError::Generic(format!(
			"Insufficient balance. Have: {}, Need: {} (including estimated fees)",
			formatted_balance, formatted_needed
		)));
	}

	// Parse tip if provided
	let tip_amount = if let Some(tip_str) = tip {
		Some(parse_amount(&quantus_client, &tip_str).await?)
	} else {
		None
	};

	// Submit batch transaction
	let tx_hash =
		batch_transfer(&quantus_client, &keypair, transfers, tip_amount, execution_mode).await?;

	log_print!(
		"{} Multisend transaction submitted! Hash: {:?}",
		"SUCCESS".bright_green().bold(),
		tx_hash
	);

	log_success!("{} Multisend transaction confirmed!", "FINISHED".bright_green().bold());

	// Show updated balance
	let new_balance = get_balance(&quantus_client, &from_account_id).await?;
	let formatted_new_balance = format_balance_with_symbol(&quantus_client, new_balance).await?;
	log_print!("New balance: {}", formatted_new_balance.bright_yellow());

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_generate_random_distribution_basic() {
		let amounts = generate_random_distribution(5, 1000, 100, 300).unwrap();
		assert_eq!(amounts.len(), 5);
		assert_eq!(amounts.iter().sum::<u128>(), 1000);
		for &amt in &amounts {
			assert!(amt >= 100 && amt <= 300, "Amount {} out of range", amt);
		}
	}

	#[test]
	fn test_generate_random_distribution_exact_min() {
		// Total equals n * min, so everyone gets exactly min
		let amounts = generate_random_distribution(4, 400, 100, 200).unwrap();
		assert_eq!(amounts.len(), 4);
		assert_eq!(amounts.iter().sum::<u128>(), 400);
		for &amt in &amounts {
			assert_eq!(amt, 100);
		}
	}

	#[test]
	fn test_generate_random_distribution_exact_max() {
		// Total equals n * max, so everyone gets exactly max
		let amounts = generate_random_distribution(4, 800, 100, 200).unwrap();
		assert_eq!(amounts.len(), 4);
		assert_eq!(amounts.iter().sum::<u128>(), 800);
		for &amt in &amounts {
			assert_eq!(amt, 200);
		}
	}

	#[test]
	fn test_generate_random_distribution_single_recipient() {
		let amounts = generate_random_distribution(1, 500, 100, 600).unwrap();
		assert_eq!(amounts.len(), 1);
		assert_eq!(amounts[0], 500);
	}

	#[test]
	fn test_generate_random_distribution_total_too_small() {
		let result = generate_random_distribution(5, 400, 100, 200);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("Minimum required"));
	}

	#[test]
	fn test_generate_random_distribution_total_too_large() {
		let result = generate_random_distribution(5, 1500, 100, 200);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("Maximum possible"));
	}

	#[test]
	fn test_generate_random_distribution_min_greater_than_max() {
		let result = generate_random_distribution(5, 1000, 300, 100);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("cannot be greater than"));
	}

	#[test]
	fn test_generate_random_distribution_zero_recipients() {
		let result = generate_random_distribution(0, 1000, 100, 200);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("zero recipients"));
	}

	#[test]
	fn test_distribution_randomness() {
		// Run multiple times and check that we get different distributions
		let mut seen_distributions = std::collections::HashSet::new();
		for _ in 0..10 {
			let amounts = generate_random_distribution(5, 1000, 100, 300).unwrap();
			seen_distributions.insert(format!("{:?}", amounts));
		}
		// With 5 recipients and a decent range, we should see some variety
		// (though this isn't guaranteed - it's probabilistic)
		assert!(seen_distributions.len() > 1, "Expected multiple different distributions");
	}
}
