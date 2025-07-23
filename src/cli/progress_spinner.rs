use crate::chain::client_subxt::ChainConfig;
use crate::error::Result;
use colored::Colorize;
use std::io::{self, Write};
use subxt::OnlineClient;
use tokio::time::Instant;

/// Simple progress spinner for showing waiting status
pub struct ProgressSpinner {
    chars: Vec<char>,
    current: usize,
    start_time: Instant,
}

impl ProgressSpinner {
    pub fn new() -> Self {
        Self {
            chars: vec!['|', '/', '-', '\\'],
            current: 0,
            start_time: Instant::now(),
        }
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
pub async fn wait_for_finalization(
    _client: &OnlineClient<ChainConfig>,
    _tx_hash: subxt::utils::H256,
) -> Result<bool> {
    // Use ProgressSpinner to show waiting progress
    let mut spinner = ProgressSpinner::new();

    // For now, we use a simple delay approach similar to substrate-api-client
    // TODO: Implement proper finalization watching using SubXT events
    for _ in 0..6 {
        spinner.tick();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Clear the spinner line and add newline
    println!();

    use crate::log_verbose;
    log_verbose!("✅ Transaction likely finalized (after 6s delay)");
    Ok(true)
}
