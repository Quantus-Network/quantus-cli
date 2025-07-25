use crate::{chain::client::ChainClient, error::Result, log_print, log_success};
use clap::Subcommand;
use colored::Colorize;
use dilithium_crypto::traits::WormholeAddress;
use hex;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_runtime::traits::IdentifyAccount;
use std::process::{Command, Stdio};
use substrate_api_client::ac_compose_macros::compose_extrinsic;
use wormhole_circuit::cli_data::WormholeData;

/// Wormhole commands
#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
    /// Generate a new wormhole address and secret
    GenerateAddress,

    /// Spend funds from a wormhole address
    Spend {
        /// The hex-encoded secret key for the wormhole address
        #[arg(long)]
        secret: String,

        /// Recipient's on-chain address
        #[arg(short, long)]
        to: String,

        /// Amount to send (e.g., "10", "10.5", "0.0001")
        #[arg(short, long)]
        amount: String,

        /// Wallet name to sign the bridge transaction
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,

        /// Read password from file
        #[arg(long)]
        password_file: Option<String>,
    },
}

/// Handle wormhole commands
pub async fn handle_wormhole_command(command: WormholeCommands, node_url: &str) -> Result<()> {
    match command {
        WormholeCommands::GenerateAddress => {
            log_print!("Generating new wormhole address...");

            let wormhole_pair = WormholePair::generate_new().map_err(|e| {
                crate::error::QuantusError::Generic(format!("Wormhole generation error: {:?}", e))
            })?;

            // Convert wormhole address to account ID using WormholeAddress type
            let wormhole_address = WormholeAddress(wormhole_pair.address);
            let account_id: AccountId32 = wormhole_address.into_account();

            log_print!(
                "{}",
                "XXXXXXXXXXXXXXX Quantus Wormhole Details XXXXXXXXXXXXXXXXX".yellow()
            );
            log_print!(
                "{}: {}",
                "On-chain Address".green(),
                account_id.to_ss58check().bright_cyan()
            );
            log_print!(
                "{}: 0x{}",
                "Wormhole Address".green(),
                hex::encode(wormhole_pair.address).bright_cyan()
            );
            log_print!(
                "{}: 0x{}",
                "Secret Key      ".green(),
                hex::encode(wormhole_pair.secret).bright_cyan()
            );
            log_print!(
                "{}",
                "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".yellow()
            );

            log_success!("Wormhole address generated successfully!");
        }
        WormholeCommands::Spend {
            secret,
            to,
            amount: amount_str,
            from,
            password,
            password_file,
        } => {
            log_print!("🚀 Initiating wormhole spend...");

            let chain_client = ChainClient::new(node_url).await?;

            // Step 1: Parse and validate inputs
            let clean_secret = secret.strip_prefix("0x").unwrap_or(&secret);
            let secret_bytes = hex::decode(clean_secret)
                .map_err(|_| crate::error::QuantusError::InvalidHexSecret)?;

            let secret_array: [u8; 32] = secret_bytes
                .clone()
                .try_into()
                .map_err(|v: Vec<u8>| crate::error::QuantusError::InvalidSecretLength(v.len()))?;

            // Generate wormhole pair from secret and derive addresses
            let wormhole_pair = WormholePair::generate_pair_from_secret(&secret_array);
            let wormhole_address = WormholeAddress(wormhole_pair.address);
            let wormhole_account: AccountId32 = wormhole_address.into_account();

            let (amount_u128, formatted_amount) =
                chain_client.validate_and_format_amount(&amount_str).await?;

            // Load the signing wallet
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            log_print!("🔗 Wormhole Spend Details:",);
            log_print!(
                "   Wormhole Address: {}",
                wormhole_account.to_ss58check().bright_yellow()
            );
            log_print!("   To Destination: {}", to.bright_green());
            log_print!("   Amount: {}", formatted_amount.bright_cyan());
            log_print!(
                "   Signed by: {}",
                keypair.to_account_id_ss58check().bright_blue()
            );

            // Step 2: Transfer funds to the wormhole's on-chain address
            log_print!("📤 Step 1: Transferring funds to wormhole address...");

            let tx_report = chain_client
                .transfer(&keypair, &wormhole_account.to_ss58check(), amount_u128)
                .await?;

            log_success!("Transfer submitted!",);
            log_print!(
                "📍 Transaction hash: {}",
                tx_report.extrinsic_hash.to_string().bright_blue()
            );

            // Per team confirmation, we can use the InBlock status for the proof.
            // No finalization wait is needed.
            let inclusion_block_hash = tx_report.block_hash.ok_or_else(|| {
                crate::error::QuantusError::Generic(
                    "Transaction report did not include a block hash. This should not happen."
                        .to_string(),
                )
            })?;

            log_print!(
                "📦 Transaction included in block: {}",
                inclusion_block_hash.to_string().bright_blue()
            );

            // Step 2: Get storage proof from the inclusion block
            log_print!("🔍 Step 2: Fetching storage proof from the chain...");
            let (state_root, storage_key, storage_proof) = chain_client
                .get_storage_proof_at_block(&wormhole_account, inclusion_block_hash)
                .await?;

            log_success!("Storage proof fetched successfully!");
            log_print!(
                "   State Root: 0x{}",
                hex::encode(state_root.as_ref()).bright_yellow()
            );
            log_print!(
                "   Storage Key: 0x{}",
                hex::encode(&storage_key).bright_cyan()
            );
            log_print!(
                "   Storage Proof Length: {}",
                storage_proof.len().to_string().bright_magenta()
            );
            for (i, proof_node) in storage_proof.iter().enumerate() {
                log_print!(
                    "   Proof Node {}: 0x{}",
                    i,
                    hex::encode(proof_node).bright_cyan()
                );
            }

            // Step 4: Generate ZK proof using wormhole prover
            log_print!("🔐 Step 3: Generating zero-knowledge proof...");

            // Create the simple data struct to pass to the prover CLI
            let wormhole_data = WormholeData {
                secret_hex: secret.clone(),
                wormhole_address_ss58: wormhole_account.to_ss58check(),
                exit_address_ss58: to.clone(),
                funding_amount: amount_u128,
                state_root_hex: hex::encode(state_root.as_ref()),
                storage_key_hex: Some(hex::encode(&storage_key)),
                storage_proof_hex: storage_proof
                    .iter()
                    .map(|bytes| hex::encode(bytes))
                    .collect(),
            };

            log_print!("🔍 Debug: Wormhole data being sent to prover:");
            log_print!(
                "   Storage Proof Hex Length: {}",
                wormhole_data.storage_proof_hex.len()
            );
            for (i, proof_hex) in wormhole_data.storage_proof_hex.iter().enumerate() {
                log_print!("   Proof Hex {}: {}", i, proof_hex);
            }

            // Serialize the data to JSON
            let data_json = serde_json::to_string(&wormhole_data).map_err(|e| {
                crate::error::QuantusError::Generic(format!(
                    "Failed to serialize wormhole data: {:?}",
                    e
                ))
            })?;

            log_print!("🔍 Debug: JSON being sent to prover:");
            log_print!("   {}", data_json);

            // Execute the wormhole-prover-cli as a subprocess
            let output = Command::new("wormhole-prover-cli")
                .arg("--data-json")
                .arg(data_json)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| {
                    crate::error::QuantusError::Generic(format!(
                        "Failed to execute prover CLI: {:?}",
                        e
                    ))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(crate::error::QuantusError::WormholeProofGeneration(
                    format!("Prover CLI failed: {}", stderr),
                ));
            }

            // The last line of stdout should be the hex-encoded proof
            let stdout = String::from_utf8_lossy(&output.stdout);
            let proof_hex = stdout.lines().last().unwrap_or("").trim();

            if proof_hex.is_empty() {
                return Err(crate::error::QuantusError::WormholeProofGeneration(
                    "Prover CLI did not produce a proof".to_string(),
                ));
            }

            let proof_bytes = hex::decode(proof_hex).map_err(|e| {
                crate::error::QuantusError::WormholeProofGeneration(format!(
                    "Failed to decode proof from hex: {:?}",
                    e
                ))
            })?;

            log_success!("✅ Zero-knowledge proof generated successfully!");

            // Step 5: Submit proof via unsigned extrinsic
            log_print!("📡 Step 4: Submitting proof for verification...");

            // Create the wormhole_verify_proof extrinsic
            let api = chain_client.get_api();
            let extrinsic = compose_extrinsic!(api, "Wormhole", "verify_proof", proof_bytes)
                .ok_or_else(|| {
                    crate::error::QuantusError::WormholeUnsignedExtrinsic(
                        "Failed to create wormhole_verify_proof extrinsic".to_string(),
                    )
                })?;

            // Submit the unsigned extrinsic using the macro
            let proof_tx_report = crate::submit_unsigned_extrinsic!(chain_client, extrinsic)?;

            log_success!(
                "✅ Proof verification submitted in block {}!",
                proof_tx_report
                    .block_hash
                    .unwrap_or_default()
                    .to_string()
                    .bright_blue()
            );

            log_success!("🎉 Wormhole spend completed successfully!");
            log_print!("💰 Funds have been spent from wormhole address");
        }
    }
    Ok(())
}
