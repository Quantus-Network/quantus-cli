//! `quantus metadata-subxt` subcommand - SubXT implementation for metadata exploration
use crate::{chain::types::ChainConfig, error::QuantusError, log_print, log_verbose};
use colored::Colorize;
use subxt::OnlineClient;

/// SubXT-based metadata exploration client
pub struct SubxtMetadataClient {
    client: OnlineClient<ChainConfig>,
}

impl SubxtMetadataClient {
    /// Create a new SubXT metadata client
    pub async fn new(node_url: &str) -> crate::error::Result<Self> {
        log_verbose!("🔗 Connecting to Quantus node with subxt: {}", node_url);

        let client = OnlineClient::<ChainConfig>::from_url(node_url)
            .await
            .map_err(|e| {
                QuantusError::NetworkError(format!("Failed to connect with subxt: {:?}", e))
            })?;

        log_verbose!("✅ Connected to Quantus node successfully with subxt!");

        Ok(Self { client })
    }

    /// Explore chain metadata and display all available pallets and calls using SubXT
    pub async fn explore_chain_metadata(&self, no_docs: bool) -> crate::error::Result<()> {
        log_verbose!("🔍 Exploring chain metadata with subxt...");

        let metadata = self.client.metadata();
        let pallets: Vec<_> = metadata.pallets().collect();

        log_print!(
            "{}",
            "🏛️  Available Pallets & Calls (SubXT)".bold().underline()
        );
        log_print!("");

        for pallet in pallets.iter() {
            log_print!("- Pallet: {}", pallet.name().bold().bright_blue());

            // Print calls
            if let Some(calls) = pallet.call_variants() {
                log_print!("\t- Calls ({}):", calls.len());
                if !no_docs {
                    for call_variant in calls {
                        log_print!("\t\t- {}", call_variant.name);
                        let docs = &call_variant.docs;
                        if !docs.is_empty() {
                            log_print!("      {}", docs.join("\n      ").italic().dimmed());
                        }
                    }
                } else {
                    for call_variant in calls {
                        log_print!("\t\t- {}", call_variant.name);
                    }
                }
            } else {
                log_print!("\t\t- No calls in this pallet.");
            }

            // Show storage items - SubXT has different API
            if let Some(storage_metadata) = pallet.storage() {
                let entries = storage_metadata.entries();
                log_print!("\t- Storage ({}):", entries.len());
                for entry in entries {
                    log_print!("\t\t- Name: {}", entry.name());

                    if !no_docs {
                        log_verbose!("\t\t- Type: {:?}", entry.entry_type());
                        if !entry.docs().is_empty() {
                            log_verbose!(
                                "\t\t- Docs: {}",
                                entry.docs().join("\n      ").italic().dimmed()
                            );
                        }
                    }
                }
            } else {
                log_print!("\t- Storage (0):");
            }

            log_print!("");
        }

        // Add a summary at the end
        log_print!("{}", "🔍 Exploration Complete (SubXT)".bold());
        log_print!("Found {} pallets.", pallets.len());

        Ok(())
    }

    /// Get basic metadata statistics using SubXT
    pub async fn get_metadata_stats(&self) -> crate::error::Result<()> {
        log_verbose!("🔍 Getting metadata statistics with subxt...");

        let metadata = self.client.metadata();
        let pallets: Vec<_> = metadata.pallets().collect();

        log_print!("📊 Metadata Statistics (SubXT):");
        log_print!("   📦 Total pallets: {}", pallets.len());
        log_print!("   🔗 API: Type-safe SubXT");

        // Count calls across all pallets
        let mut total_calls = 0;
        let mut total_storage = 0;

        for pallet in &pallets {
            if let Some(calls) = pallet.call_variants() {
                total_calls += calls.len();
            }
            if let Some(storage_metadata) = pallet.storage() {
                total_storage += storage_metadata.entries().len();
            }
        }

        log_print!("   🎯 Total calls: {}", total_calls);
        log_print!("   💾 Total storage items: {}", total_storage);

        Ok(())
    }
}

/// Handle metadata-subxt command execution
pub async fn handle_metadata_subxt_command(
    node_url: &str,
    no_docs: bool,
    stats_only: bool,
) -> crate::error::Result<()> {
    let client = SubxtMetadataClient::new(node_url).await?;

    if stats_only {
        client.get_metadata_stats().await
    } else {
        client.explore_chain_metadata(no_docs).await
    }
}
