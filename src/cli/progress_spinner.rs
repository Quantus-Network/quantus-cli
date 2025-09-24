use crate::{chain::client::ChainConfig, error::Result};
use colored::Colorize;
use rand::rand_core::block;
use std::io::{self, Write};
use subxt::{blocks, OnlineClient};
use tokio::time::Instant;

/// Simple progress spinner for showing waiting status
pub struct ProgressSpinner {
	chars: Vec<char>,
	current: usize,
	start_time: Instant,
}

impl Default for ProgressSpinner {
	fn default() -> Self {
		Self::new()
	}
}

impl ProgressSpinner {
	pub fn new() -> Self {
		Self { chars: vec!['|', '/', '-', '\\'], current: 0, start_time: Instant::now() }
	}

	pub fn tick(&mut self) {
		let elapsed = self.start_time.elapsed().as_secs();
		print!(
			"\r🔗 Waiting for confirmation... {} ({}s)",
			self.chars[self.current].to_string().bright_blue(),
			elapsed
		);
		io::stdout().flush().unwrap();
		self.current = (self.current + 1) % self.chars.len();
	}
}

/// Common function to wait for transaction finalization using ProgressSpinner
pub async fn wait_for_tx_confirmation(
	_client: &OnlineClient<ChainConfig>,
	_tx_hash: subxt::utils::H256,
) -> Result<bool> {
	// Use ProgressSpinner to show waiting progress
	let mut spinner = ProgressSpinner::new();

	// For now, we use a simple delay approach similar to substrate-api-client
	for _ in 0..30 {
		spinner.tick();
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	}

	// Clear the spinner line and add newline
	println!();

	use crate::log_verbose;
	log_verbose!("✅ Transaction likely finalized (after 30s delay)");
	Ok(true)
}
