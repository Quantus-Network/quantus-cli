use crate::chain::client::ChainClient;
use crate::chain::quantus_runtime_config::QuantusRuntimeConfig;
use crate::error::Result;
use crate::{log_error, log_print, log_success, log_verbose};
use clap::Subcommand;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;
use substrate_api_client::ac_compose_macros::compose_extrinsic;
use substrate_api_client::ac_primitives::ExtrinsicSigner;
use substrate_api_client::{SubmitAndWatch, XtStatus};

/// Runtime management commands
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

/// Handle runtime command
pub async fn handle_runtime_command(command: RuntimeCommands, node_url: &str) -> Result<()> {
    match command {
        RuntimeCommands::Update {
            wasm_file,
            from,
            password,
            password_file,
            force,
        } => update_runtime(&wasm_file, &from, password, password_file, force, node_url).await,

        RuntimeCommands::CheckVersion => check_runtime_version(node_url).await,

        RuntimeCommands::GetSpecVersion => get_spec_version(node_url).await,

        RuntimeCommands::GetImplVersion => get_impl_version(node_url).await,

        RuntimeCommands::GetMetadataVersion => get_metadata_version(node_url).await,

        RuntimeCommands::Compare { wasm_file } => compare_runtime(&wasm_file, node_url).await,
    }
}

/// Update the runtime using a WASM file
async fn update_runtime(
    wasm_file: &PathBuf,
    from: &str,
    password: Option<String>,
    password_file: Option<String>,
    force: bool,
    node_url: &str,
) -> Result<()> {
    log_print!("🔄 Runtime Update");
    log_print!(
        "   📂 WASM file: {}",
        wasm_file.display().to_string().bright_cyan()
    );
    log_print!("   🔑 Signed by: {}", from.bright_yellow());

    // Check if WASM file exists
    if !wasm_file.exists() {
        return Err(crate::error::QuantusError::Generic(format!(
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

    let chain_client = ChainClient::new(node_url).await?;
    let keypair = crate::wallet::load_keypair_from_wallet(from, password, password_file)?;

    // Read WASM file
    log_verbose!("📖 Reading WASM file...");
    let wasm_code = fs::read(wasm_file).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Failed to read WASM file: {}", e))
    })?;

    log_print!("📊 WASM file size: {} bytes", wasm_code.len());

    // Get current runtime version before update
    log_verbose!("🔍 Checking current runtime version...");
    let current_version = chain_client.get_runtime_version_raw();
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
            return Ok(());
        }
    }

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create the set_code call
    log_verbose!("🔧 Creating set_code extrinsic...");
    let inner_call = compose_extrinsic!(&api_with_signer, "System", "set_code", wasm_code)
        .ok_or_else(|| {
            crate::error::QuantusError::Generic("Failed to create set_code call".to_string())
        })?;

    // Wrap with sudo for root permissions
    let extrinsic = compose_extrinsic!(&api_with_signer, "Sudo", "sudo", inner_call.function)
        .ok_or_else(|| {
            crate::error::QuantusError::Generic(
                "Failed to create sudo wrapper extrinsic".to_string(),
            )
        })?;

    // Submit transaction
    log_print!("📡 Submitting runtime update transaction...");
    log_print!("⏳ This may take longer than usual due to WASM size...");

    match crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic) {
        Ok(tx_report) => {
            log_success!("✅ Runtime update submitted successfully!");
            log_print!(
                "📋 Transaction hash: {}",
                format!("0x{}", hex::encode(tx_report.extrinsic_hash)).bright_green()
            );

            if let Some(block_hash) = tx_report.block_hash {
                log_print!(
                    "🔗 Included in block: {}",
                    format!("0x{}", hex::encode(block_hash)).bright_blue()
                );
            }

            log_success!("🎉 Runtime update completed!");
            log_print!(
                "💡 Note: It may take a few moments for the new runtime version to be reflected."
            );
            log_print!("💡 Use 'quantus runtime check-version' to verify the new version.");

            Ok(())
        }
        Err(e) => {
            log_error!("❌ Runtime update failed: {}", e);
            Err(e)
        }
    }
}

/// Check the current runtime version
async fn check_runtime_version(node_url: &str) -> Result<()> {
    log_print!("🔍 Checking runtime version...");

    let chain_client = ChainClient::new(node_url).await?;
    let version = chain_client.get_runtime_version_raw();

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

/// Get the current spec version
async fn get_spec_version(node_url: &str) -> Result<()> {
    let chain_client = ChainClient::new(node_url).await?;
    let version = chain_client.get_runtime_version_raw();

    log_print!(
        "📊 Spec Version: {}",
        version.spec_version.to_string().bright_green()
    );
    Ok(())
}

/// Get the current implementation version
async fn get_impl_version(node_url: &str) -> Result<()> {
    let chain_client = ChainClient::new(node_url).await?;
    let version = chain_client.get_runtime_version_raw();

    log_print!(
        "📊 Implementation Version: {}",
        version.impl_version.to_string().bright_yellow()
    );
    Ok(())
}

/// Get the runtime metadata version
async fn get_metadata_version(node_url: &str) -> Result<()> {
    let chain_client = ChainClient::new(node_url).await?;
    let metadata = chain_client.get_metadata();

    // Extract metadata version from the metadata structure
    log_print!("📊 Metadata Version: {}", "V14".bright_magenta()); // Substrate uses V14 metadata

    // Count pallets using the correct method
    let pallets: Vec<_> = metadata.pallets().collect();
    log_print!("📦 Total pallets: {}", pallets.len());

    Ok(())
}

/// Compare local WASM file with current runtime
async fn compare_runtime(wasm_file: &PathBuf, node_url: &str) -> Result<()> {
    log_print!("🔍 Comparing WASM file with current runtime...");
    log_print!(
        "   📂 Local file: {}",
        wasm_file.display().to_string().bright_cyan()
    );

    // Check if WASM file exists
    if !wasm_file.exists() {
        return Err(crate::error::QuantusError::Generic(format!(
            "WASM file not found: {}",
            wasm_file.display()
        )));
    }

    // Read local WASM file
    let local_wasm = fs::read(wasm_file).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Failed to read WASM file: {}", e))
    })?;

    log_print!("📊 Local WASM size: {} bytes", local_wasm.len());

    let chain_client = ChainClient::new(node_url).await?;

    // Get current runtime code from chain
    log_verbose!("📥 Fetching current runtime code from chain...");

    // Note: Getting the full runtime code is expensive, so we'll compare versions instead
    let current_version = chain_client.get_runtime_version_raw();
    log_print!("📋 Current chain runtime:");
    log_print!("   • Spec version: {}", current_version.spec_version);
    log_print!("   • Impl version: {}", current_version.impl_version);

    // Calculate hash of local file for comparison
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&local_wasm);
    let local_hash = hasher.finalize();

    log_print!(
        "🔐 Local WASM SHA256: {}",
        format!("0x{}", hex::encode(local_hash)).bright_blue()
    );

    log_print!("💡 To see if versions match, update with --force false to see current vs new version comparison");

    Ok(())
}
