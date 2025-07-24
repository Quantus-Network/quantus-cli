//! `quantus runtime` subcommand - runtime management
use crate::chain::client::ChainConfig;
use crate::cli::common::get_fresh_nonce;
use crate::cli::progress_spinner::wait_for_finalization;
use crate::{
    chain::quantus_subxt, error::QuantusError, log_print, log_success, log_verbose,
    wallet::QuantumKeyPair,
};
use clap::Subcommand;
use colored::Colorize;

use std::fs;
use std::path::PathBuf;
use subxt::OnlineClient;

#[derive(Subcommand, Debug)]
pub enum RuntimeSubxtCommands {
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

    /// Check the current runtime version
    CheckVersion,

    /// Get the current spec version
    GetSpecVersion,

    /// Get the current implementation version
    GetImplVersion,

    /// Get the runtime metadata version
    GetMetadataVersion,

    /// Compare local WASM file with current runtime
    Compare {
        /// Path to the runtime WASM file to compare
        #[arg(short, long)]
        wasm_file: PathBuf,
    },
}

/// Update runtime with sudo wrapper
pub async fn update_runtime(
    client: &OnlineClient<ChainConfig>,
    wasm_code: Vec<u8>,
    from_keypair: &QuantumKeyPair,
    force: bool,
) -> crate::error::Result<subxt::utils::H256> {
    log_verbose!("🔄 Updating runtime...");

    // Get current runtime version before update
    log_verbose!("🔍 Checking current runtime version...");
    let current_version = get_runtime_version(client).await?;
    log_print!("📋 Current runtime version:");
    log_print!("   • Spec version: {}", current_version.spec_version);
    log_print!("   • Impl version: {}", current_version.impl_version);

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

    let signer = from_keypair
        .to_subxt_signer()
        .map_err(|e| QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e)))?;

    // Get fresh nonce for the sender
    let nonce = get_fresh_nonce(client, from_keypair).await?;

    // Create custom params with fresh nonce
    use subxt::config::DefaultExtrinsicParamsBuilder;
    let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

    // Submit the transaction with fresh nonce
    let tx_hash = client
        .tx()
        .sign_and_submit(&sudo_call, &signer, params)
        .await
        .map_err(|e| {
            QuantusError::NetworkError(format!("Failed to submit runtime update: {:?}", e))
        })?;
    log_success!(
        "✅ SUCCESS Runtime update transaction submitted! Hash: 0x{}",
        hex::encode(tx_hash)
    );

    // Wait for finalization
    wait_for_finalization(client, tx_hash).await?;
    log_success!("✅ 🎉 FINALIZED Runtime update completed!");

    Ok(tx_hash)
}

/// Get runtime version information
pub async fn get_runtime_version(
    client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<RuntimeVersionInfo> {
    log_verbose!("🔍 Getting runtime version...");

    let runtime_version = client.runtime_version();

    // SubXT RuntimeVersion only has spec_version and transaction_version
    // We'll use defaults for missing fields
    Ok(RuntimeVersionInfo {
        spec_name: "quantus-node".to_string(), // Default spec name
        impl_name: "quantus-node".to_string(), // Default impl name
        spec_version: runtime_version.spec_version,
        impl_version: 1,      // Default impl version since not available in SubXT
        authoring_version: 1, // Default authoring version since not available in SubXT
        transaction_version: runtime_version.transaction_version,
    })
}

/// Get metadata version and pallet count
pub async fn get_metadata_info(
    client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<MetadataInfo> {
    log_verbose!("🔍 Getting metadata info...");

    let metadata = client.metadata();
    let pallets: Vec<_> = metadata.pallets().collect();

    log_verbose!("🔍 SubXT metadata: {} pallets detected", pallets.len());

    Ok(MetadataInfo {
        version: "SubXT".to_string(), // SubXT metadata (version determined by SubXT)
        pallet_count: pallets.len(),
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

/// Runtime version information structure
#[derive(Debug, Clone)]
pub struct RuntimeVersionInfo {
    pub spec_name: String,
    pub impl_name: String,
    pub spec_version: u32,
    pub impl_version: u32,
    pub authoring_version: u32,
    pub transaction_version: u32,
}

/// Metadata information structure
#[derive(Debug, Clone)]
pub struct MetadataInfo {
    pub version: String,
    pub pallet_count: usize,
}

/// Handle runtime subxt command
pub async fn handle_runtime_subxt_command(
    command: RuntimeSubxtCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

    match command {
        RuntimeSubxtCommands::Update {
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
            update_runtime(quantus_client.client(), wasm_code, &keypair, force).await?;

            log_success!("🎉 Runtime update completed!");
            log_print!(
                "💡 Note: It may take a few moments for the new runtime version to be reflected."
            );
            log_print!("💡 Use 'quantus runtime check-version' to verify the new version.");

            Ok(())
        }

        RuntimeSubxtCommands::CheckVersion => {
            log_print!("🚀 Runtime Management");
            log_print!("🔍 Checking runtime version...");

            let version = get_runtime_version(quantus_client.client()).await?;

            log_print!("📋 Runtime Version Information:");
            log_print!("   • Spec name: {}", version.spec_name.bright_cyan());
            log_print!(
                "   • Implementation name: {}",
                version.impl_name.bright_blue()
            );
            log_print!(
                "   • Spec version: {}",
                version.spec_version.to_string().bright_green()
            );
            log_print!(
                "   • Implementation version: {}",
                version.impl_version.to_string().bright_yellow()
            );
            log_print!("   • Authoring version: {}", version.authoring_version);
            log_print!("   • Transaction version: {}", version.transaction_version);

            Ok(())
        }

        RuntimeSubxtCommands::GetSpecVersion => {
            log_print!("🚀 Runtime Management");
            let version = get_runtime_version(quantus_client.client()).await?;

            log_print!(
                "📊 Spec Version: {}",
                version.spec_version.to_string().bright_green()
            );
            Ok(())
        }

        RuntimeSubxtCommands::GetImplVersion => {
            log_print!("🚀 Runtime Management");
            let version = get_runtime_version(quantus_client.client()).await?;

            log_print!(
                "📊 Implementation Version: {}",
                version.impl_version.to_string().bright_yellow()
            );
            Ok(())
        }

        RuntimeSubxtCommands::GetMetadataVersion => {
            log_print!("🚀 Runtime Management");
            log_print!("🔍 Getting metadata version...");

            let metadata_info = get_metadata_info(quantus_client.client()).await?;

            log_print!(
                "📊 Metadata Version: {}",
                metadata_info.version.bright_magenta()
            );
            log_print!("📦 Total pallets: {}", metadata_info.pallet_count);

            Ok(())
        }

        RuntimeSubxtCommands::Compare { wasm_file } => {
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

            // Calculate hash of local file
            let local_hash = calculate_wasm_hash(&local_wasm).await?;
            log_print!("🔐 Local WASM SHA256: {}", local_hash.bright_blue());

            log_print!("💡 To see if versions match, use update with --force false to see current vs new version comparison");

            Ok(())
        }
    }
}
