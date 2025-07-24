use crate::chain::client::ChainConfig;
use crate::{chain::quantus_subxt, error::Result, log_print, log_success};
use clap::Subcommand;
use subxt::OnlineClient;

/// Scheduler-related commands
#[derive(Subcommand, Debug)]
pub enum SchedulerSubxtCommands {
    /// Get the last processed timestamp from the scheduler
    GetLastProcessedTimestamp,
}

/// Get the last processed timestamp from the scheduler
pub async fn get_last_processed_timestamp(
    client: &OnlineClient<ChainConfig>,
) -> Result<Option<u64>> {
    use quantus_subxt::api;

    log_print!("🕒 Getting last processed timestamp from the scheduler");

    // Build the storage key for Scheduler::LastProcessedTimestamp
    let storage_addr = api::storage().scheduler().last_processed_timestamp();

    let storage_at = client.storage().at_latest().await.map_err(|e| {
        crate::error::QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
    })?;

    let timestamp = storage_at.fetch(&storage_addr).await.map_err(|e| {
        crate::error::QuantusError::NetworkError(format!(
            "Failed to fetch last processed timestamp: {:?}",
            e
        ))
    })?;

    Ok(timestamp)
}

/// Handle scheduler commands
pub async fn handle_scheduler_subxt_command(
    command: SchedulerSubxtCommands,
    node_url: &str,
) -> Result<()> {
    log_print!("🗓️  Scheduler");

    let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

    match command {
        SchedulerSubxtCommands::GetLastProcessedTimestamp => {
            match get_last_processed_timestamp(quantus_client.client()).await? {
                Some(timestamp) => {
                    log_success!("🎉 Last processed timestamp: {}", timestamp);
                }
                None => {
                    log_print!(
                        "🤷 No last processed timestamp found. The scheduler may not have run yet."
                    );
                }
            }
            Ok(())
        }
    }
}
