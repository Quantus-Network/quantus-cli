//! `quantus runtime` subcommand - runtime management
use crate::{
	chain::quantus_subxt, error::QuantusError, log_print, log_success, log_verbose,
	wallet::QuantumKeyPair,
};
use clap::Subcommand;
use colored::Colorize;

use crate::chain::client::ChainConfig;
use std::{fs, path::PathBuf};
use subxt::OnlineClient;

#[derive(Subcommand, Debug)]
pub enum RuntimeCommands {
	/// Propose a runtime upgrade using a WASM file (via Tech Referenda; creates preimage first)
	Update {
		/// Path to the runtime WASM file
		#[arg(short, long)]
		wasm_file: PathBuf,

		/// Wallet name to sign with (must be allowed to submit Tech Referenda)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Force the update without confirmation
		#[arg(long)]
		force: bool,
	},

	/// Compare local WASM file with current runtime
	Compare {
		/// Path to the runtime WASM file to compare
		#[arg(short, long)]
		wasm_file: PathBuf,
	},
}

/// Propose runtime upgrade via Tech Referenda (no sudo pallet)
pub async fn update_runtime(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_code: Vec<u8>,
	from_keypair: &QuantumKeyPair,
	force: bool,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	log_verbose!("🔄 Updating runtime...");

	log_print!("📋 Current runtime version:");
	log_print!("   • Use 'quantus system --runtime' to see current version");
	log_print!("📋 Upgrade path:");
	log_print!("   • This submits a Tech Referendum with Root origin (not an immediate root call)");

	// Show confirmation prompt unless force is used
	if !force {
		log_print!("");
		log_print!(
			"⚠️  {} {}",
			"WARNING:".bright_red().bold(),
			"Runtime update is a critical operation!"
		);
		log_print!("   • This will submit a governance proposal to upgrade the runtime");
		log_print!("   • If approved and enacted, all nodes will need to upgrade to stay in sync");
		log_print!("   • Governance operations cannot be easily reversed");
		log_print!("");

		// Simple confirmation prompt
		print!("Do you want to proceed with the runtime update? (yes/no): ");
		use std::io::{self, Write};
		io::stdout().flush().unwrap();

		let mut input = String::new();
		io::stdin().read_line(&mut input).unwrap();

		if input.trim().to_lowercase() != "yes" {
			log_print!("❌ Runtime update cancelled");
			return Err(QuantusError::Generic("Runtime update cancelled".to_string()));
		}
	}

	// Build a static payload for System::set_code and encode full call data (pallet + call + args)
	use sp_runtime::traits::{BlakeTwo256, Hash};
	let set_code_payload = quantus_subxt::api::tx().system().set_code(wasm_code.clone());
	let metadata = quantus_client.client().metadata();
	let encoded_call = <_ as subxt::tx::Payload>::encode_call_data(&set_code_payload, &metadata)
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call data: {:?}", e)))?;

	log_print!("📡 Submitting runtime upgrade proposal (preimage + referendum)...");
	log_print!("⏳ This may take longer than usual due to WASM size...");
	log_verbose!("📝 Encoded call size: {} bytes", encoded_call.len());

	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(&encoded_call);
	log_print!("🔗 Preimage hash: {:?}", preimage_hash);

	// Submit Preimage::note_preimage with bounded bytes
	type PreimageBytes = quantus_subxt::api::preimage::calls::types::note_preimage::Bytes;
	let bounded_bytes: PreimageBytes = encoded_call.clone();

	log_print!("📝 Submitting preimage...");
	let note_preimage_tx = quantus_subxt::api::tx().preimage().note_preimage(bounded_bytes);
	let preimage_tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		note_preimage_tx,
		None,
		execution_mode,
	)
	.await?;
	log_success!("✅ Preimage transaction submitted: {:?}", preimage_tx_hash);

	// Build TechReferenda::submit call using Lookup preimage reference
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::sp_runtime::traits::BlakeTwo256,
		>;

	let preimage_hash_subxt: subxt::utils::H256 = preimage_hash;
	let proposal: ProposalBounded =
		ProposalBounded::Lookup { hash: preimage_hash_subxt, len: encoded_call.len() as u32 };

	let raw_origin_root =
		quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root;
	let origin_caller =
		quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(raw_origin_root);

	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			0u32,
		);

	log_print!("🔧 Creating TechReferenda::submit call...");
	let submit_call =
		quantus_subxt::api::tx()
			.tech_referenda()
			.submit(origin_caller, proposal, enactment);

	if !execution_mode.finalized {
		log_print!(
			"💡 Note: Waiting for best block (not finalized) due to PoW chain characteristics"
		);
	}

	let tx_hash = crate::cli::common::submit_transaction(
		quantus_client,
		from_keypair,
		submit_call,
		None,
		execution_mode,
	)
	.await?;

	log_success!(
		"✅ SUCCESS Runtime upgrade proposal submitted! Hash: 0x{}",
		hex::encode(tx_hash)
	);

	Ok(tx_hash)
}

/// Runtime version information structure (internal use)
#[derive(Debug, Clone)]
pub struct RuntimeVersionInfo {
	pub spec_version: u32,
	pub impl_version: u32,
	pub transaction_version: u32,
}

/// Get runtime version information (internal use)
pub async fn get_runtime_version(
	client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<RuntimeVersionInfo> {
	log_verbose!("🔍 Getting runtime version...");

	let runtime_version = client.runtime_version();

	// SubXT RuntimeVersion only has spec_version and transaction_version
	// We'll use defaults for missing fields
	Ok(RuntimeVersionInfo {
		spec_version: runtime_version.spec_version,
		impl_version: 1, // Default impl version since not available in SubXT
		transaction_version: runtime_version.transaction_version,
	})
}

/// Calculate WASM file hash
pub async fn calculate_wasm_hash(wasm_code: &[u8]) -> crate::error::Result<String> {
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	hasher.update(wasm_code);
	let local_hash = hasher.finalize();

	Ok(format!("0x{}", hex::encode(local_hash)))
}

/// Handle runtime subxt command
pub async fn handle_runtime_command(
	command: RuntimeCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		RuntimeCommands::Update { wasm_file, from, password, password_file, force } => {
			log_print!("🚀 Runtime Management");
			log_print!("🔄 Runtime Update");
			log_print!("   📂 WASM file: {}", wasm_file.display().to_string().bright_cyan());
			log_print!("   🔑 Signed by: {}", from.bright_yellow());

			// Check if WASM file exists
			if !wasm_file.exists() {
				return Err(QuantusError::Generic(format!(
					"WASM file not found: {}",
					wasm_file.display()
				)));
			}

			// Check file extension
			if let Some(ext) = wasm_file.extension() {
				if ext != "wasm" {
					log_print!("⚠️  Warning: File doesn't have .wasm extension");
				}
			}

			// Load keypair
			let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

			// Read WASM file
			log_verbose!("📖 Reading WASM file...");
			let wasm_code = fs::read(&wasm_file)
				.map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {e}")))?;

			log_print!("📊 WASM file size: {} bytes", wasm_code.len());

			// Update runtime
			update_runtime(&quantus_client, wasm_code, &keypair, force, execution_mode).await?;

			log_success!("🎉 Runtime update completed!");
			log_print!(
				"💡 Note: It may take a few moments for the new runtime version to be reflected."
			);
			log_print!("💡 Use 'quantus runtime check-version' to verify the new version.");

			Ok(())
		},

		RuntimeCommands::Compare { wasm_file } => {
			log_print!("🚀 Runtime Management");
			log_print!("🔍 Comparing WASM file with current runtime...");
			log_print!("   📂 Local file: {}", wasm_file.display().to_string().bright_cyan());

			// Check if WASM file exists
			if !wasm_file.exists() {
				return Err(QuantusError::Generic(format!(
					"WASM file not found: {}",
					wasm_file.display()
				)));
			}

			// Read local WASM file
			let local_wasm = fs::read(&wasm_file)
				.map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {e}")))?;

			log_print!("📊 Local WASM size: {} bytes", local_wasm.len());

			// Get current runtime version
			let current_version = get_runtime_version(quantus_client.client()).await?;
			log_print!("📋 Current chain runtime:");
			log_print!("   • Spec version: {}", current_version.spec_version);
			log_print!("   • Impl version: {}", current_version.impl_version);
			log_print!("   • Transaction version: {}", current_version.transaction_version);

			// Calculate hash of local file
			let local_hash = calculate_wasm_hash(&local_wasm).await?;
			log_print!("🔐 Local WASM SHA256: {}", local_hash.bright_blue());

			// Try to get runtime hash from chain
			if let Ok(Some(chain_runtime_hash)) = quantus_client.get_runtime_hash().await {
				log_print!("🔐 Chain runtime hash: {}", chain_runtime_hash.bright_yellow());

				// Compare hashes
				if local_hash == chain_runtime_hash {
					log_success!("✅ Runtime hashes match! The WASM file is identical to the current runtime.");
				} else {
					log_print!("⚠️  Runtime hashes differ. The WASM file is different from the current runtime.");
				}
			} else {
				log_print!("💡 Chain runtime hash not available for comparison");
			}

			// Try to extract version from filename
			let filename = wasm_file.file_name().unwrap().to_string_lossy();
			log_verbose!("🔍 Parsing filename: {}", filename);

			if let Some(version_str) = filename.split('-').nth(2) {
				log_verbose!("🔍 Version part: {}", version_str);
				if let Some(version_num) = version_str.split('.').next() {
					log_verbose!("🔍 Version number: {}", version_num);
					// Remove 'v' prefix if present
					let clean_version = version_num.trim_start_matches('v');
					log_verbose!("🔍 Clean version: {}", clean_version);
					if let Ok(wasm_version) = clean_version.parse::<u32>() {
						log_print!("📋 Version comparison:");
						log_print!(
							"   • Local WASM version: {}",
							wasm_version.to_string().bright_green()
						);
						log_print!(
							"   • Chain runtime version: {}",
							current_version.spec_version.to_string().bright_yellow()
						);

						match wasm_version.cmp(&current_version.spec_version) {
							std::cmp::Ordering::Equal => {
								log_success!("✅ Versions match! The WASM file is compatible with the current runtime.");
							},
							std::cmp::Ordering::Greater => {
								log_print!("🔄 The WASM file is newer than the current runtime.");
								log_print!("   • This would be an upgrade");
							},
							std::cmp::Ordering::Less => {
								log_print!("⚠️  The WASM file is older than the current runtime.");
								log_print!("   • This would be a downgrade");
							},
						}
					} else {
						log_print!("⚠️  Could not parse version number from filename");
					}
				} else {
					log_print!("⚠️  Could not extract version number from filename");
				}
			} else {
				log_print!("⚠️  Could not extract version from filename format");
			}

			log_print!("💡 Use 'quantus system --runtime' for detailed runtime information");

			Ok(())
		},
	}
}
