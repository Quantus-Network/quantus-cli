//! `quantus metadata` subcommand - metadata exploration
use crate::{chain::client::ChainConfig, log_print, log_verbose};
use colored::Colorize;
use subxt::OnlineClient;

/// Explore chain metadata and display all available pallets and calls
pub async fn explore_chain_metadata(
	client: &OnlineClient<ChainConfig>,
	no_docs: bool,
	pallet_filter: Option<String>,
) -> crate::error::Result<()> {
	log_verbose!("🔍 Exploring chain metadata...");

	let metadata = client.metadata();
	let all_pallets: Vec<_> = metadata.pallets().collect();

	// Filter pallets if pallet_filter is provided
	let pallets: Vec<_> = if let Some(filter) = &pallet_filter {
		all_pallets
			.into_iter()
			.filter(|pallet| pallet.name().to_lowercase() == filter.to_lowercase())
			.collect()
	} else {
		all_pallets
	};

	if pallets.is_empty() {
		if let Some(filter) = pallet_filter {
			log_print!("❌ Pallet '{}' not found.", filter.bright_red());
			log_print!("Available pallets:");
			let all_pallets: Vec<_> = metadata.pallets().collect();
			for pallet in all_pallets {
				log_print!("  - {}", pallet.name().bright_blue());
			}
			return Ok(());
		}
	}

	if pallet_filter.is_some() {
		log_print!(
			"{}",
			format!("🏛️  Pallet Documentation: {}", pallets[0].name()).bold().underline()
		);
	} else {
		log_print!("{}", "🏛️  Available Pallets & Calls".bold().underline());
	}
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
	log_print!("{}", "🔍 Exploration Complete".bold());
	log_print!("Found {} pallets.", pallets.len());

	Ok(())
}

/// Get basic metadata statistics
pub async fn get_metadata_stats(client: &OnlineClient<ChainConfig>) -> crate::error::Result<()> {
	log_verbose!("🔍 Getting metadata statistics...");

	let metadata = client.metadata();
	let pallets: Vec<_> = metadata.pallets().collect();

	log_print!("📊 Metadata Statistics:");
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

/// Handle metadata command execution
pub async fn handle_metadata_command(
	node_url: &str,
	no_docs: bool,
	stats_only: bool,
	pallet_filter: Option<String>,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	if stats_only {
		get_metadata_stats(quantus_client.client()).await
	} else {
		explore_chain_metadata(quantus_client.client(), no_docs, pallet_filter).await
	}
}
