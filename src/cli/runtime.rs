//! `quantus runtime` subcommand - runtime management
use crate::cli::progress_spinner::wait_for_tx_confirmation;
use crate::{
    chain::quantus_subxt, error::QuantusError, log_print, log_success, log_verbose,
    wallet::QuantumKeyPair,
};
use clap::Subcommand;
use colored::Colorize;

use crate::chain::client::ChainConfig;
use std::fs;
use std::path::PathBuf;
use subxt::OnlineClient;

#[derive(Subcommand, Debug)]
pub enum RuntimeCommands {
    /// Update the runtime using a WASM file (requires root permissions)
    Update {
        /// Path to the runtime WASM file
        #[arg(short, long)]
        wasm_file: PathBuf,

        /// Wallet name to sign with (must have root/sudo permissions)
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

/// Update runtime with sudo wrapper
pub async fn update_runtime(
    quantus_client: &crate::chain::client::QuantusClient,
    wasm_code: Vec<u8>,
    from_keypair: &QuantumKeyPair,
    force: bool,
) -> crate::error::Result<subxt::utils::H256> {
    log_verbose!("🔄 Updating runtime...");

    log_print!("📋 Current runtime version:");
    log_print!("   • Use 'quantus system --runtime' to see current version");

    // Show confirmation prompt unless force is used
    if !force {
        log_print!("");
        log_print!(
            "⚠️  {} {}",
            "WARNING:".bright_red().bold(),
            "Runtime update is a critical operation!"
        );
        log_print!("   • This will update the blockchain runtime immediately");
        log_print!("   • All nodes will need to upgrade to stay in sync");
        log_print!("   • This operation cannot be easily reversed");
        log_print!("");

        // Simple confirmation prompt
        print!("Do you want to proceed with the runtime update? (yes/no): ");
        use std::io::{self, Write};
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        if input.trim().to_lowercase() != "yes" {
            log_print!("❌ Runtime update cancelled");
            return Err(QuantusError::Generic(
                "Runtime update cancelled".to_string(),
            ));
        }
    }

    // Create the System::set_code call using RuntimeCall type alias
    let set_code_call =
        quantus_subxt::api::Call::System(quantus_subxt::api::system::Call::set_code {
            code: wasm_code,
        });

    // Wrap with sudo for root permissions
    let sudo_call = quantus_subxt::api::tx().sudo().sudo(set_code_call);

    // Submit transaction
    log_print!("📡 Submitting runtime update transaction...");
    log_print!("⏳ This may take longer than usual due to WASM size...");

    let tx_hash =
        crate::cli::common::submit_transaction(quantus_client, from_keypair, sudo_call, None)
            .await?;

    log_success!(
        "✅ SUCCESS Runtime update transaction submitted! Hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Wait for finalization
    wait_for_tx_confirmation(quantus_client.client(), tx_hash).await?;
    log_success!("✅ 🎉 FINISHED Runtime update completed!");

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
) -> crate::error::Result<()> {
    let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

    match command {
        RuntimeCommands::Update {
            wasm_file,
            from,
            password,
            password_file,
            force,
        } => {
            log_print!("🚀 Runtime Management");
            log_print!("🔄 Runtime Update");
            log_print!(
                "   📂 WASM file: {}",
                wasm_file.display().to_string().bright_cyan()
            );
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
                .map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {}", e)))?;

            log_print!("📊 WASM file size: {} bytes", wasm_code.len());

            // Update runtime
            update_runtime(&quantus_client, wasm_code, &keypair, force).await?;

            log_success!("🎉 Runtime update completed!");
            log_print!(
                "💡 Note: It may take a few moments for the new runtime version to be reflected."
            );
            log_print!("💡 Use 'quantus runtime check-version' to verify the new version.");

            Ok(())
        }

        RuntimeCommands::Compare { wasm_file } => {
            log_print!("🚀 Runtime Management");
            log_print!("🔍 Comparing WASM file with current runtime...");
            log_print!(
                "   📂 Local file: {}",
                wasm_file.display().to_string().bright_cyan()
            );

            // Check if WASM file exists
            if !wasm_file.exists() {
                return Err(QuantusError::Generic(format!(
                    "WASM file not found: {}",
                    wasm_file.display()
                )));
            }

            // Read local WASM file
            let local_wasm = fs::read(&wasm_file)
                .map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {}", e)))?;

            log_print!("📊 Local WASM size: {} bytes", local_wasm.len());

            // Get current runtime version
            let current_version = get_runtime_version(quantus_client.client()).await?;
            log_print!("📋 Current chain runtime:");
            log_print!("   • Spec version: {}", current_version.spec_version);
            log_print!("   • Impl version: {}", current_version.impl_version);
            log_print!(
                "   • Transaction version: {}",
                current_version.transaction_version
            );

            // Calculate hash of local file
            let local_hash = calculate_wasm_hash(&local_wasm).await?;
            log_print!("🔐 Local WASM SHA256: {}", local_hash.bright_blue());

            // Try to get runtime hash from chain
            if let Ok(Some(chain_runtime_hash)) = quantus_client.get_runtime_hash().await {
                log_print!(
                    "🔐 Chain runtime hash: {}",
                    chain_runtime_hash.bright_yellow()
                );

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

                        if wasm_version == current_version.spec_version {
                            log_success!("✅ Versions match! The WASM file is compatible with the current runtime.");
                        } else if wasm_version > current_version.spec_version {
                            log_print!("🔄 The WASM file is newer than the current runtime.");
                            log_print!("   • This would be an upgrade");
                        } else {
                            log_print!("⚠️  The WASM file is older than the current runtime.");
                            log_print!("   • This would be a downgrade");
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
        }
    }
}
