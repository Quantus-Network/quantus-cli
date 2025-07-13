use crate::{chain::client::ChainClient, error::Result, log_error, log_print, log_success};
use clap::Subcommand;
use colored::Colorize;
use dilithium_crypto::traits::WormholeAddress;
use hex;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_runtime::traits::IdentifyAccount;
use substrate_api_client::ac_compose_macros::compose_extrinsic;

use wormhole_circuit::inputs::{
    BytesDigest, CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs,
};
use wormhole_prover::WormholeProver;

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

            log_print!("✅ Transfer to wormhole submitted!",);
            log_print!(
                "📍 Transaction hash: {}",
                tx_report.extrinsic_hash.to_string().bright_blue()
            );

            // Wait for finalization
            let success = chain_client
                .wait_for_finalization(&tx_report.extrinsic_hash.to_string())
                .await?;

            if !success {
                return Err(crate::error::QuantusError::Generic(
                    "Transfer to wormhole failed to finalize".to_string(),
                ));
            }

            log_success!("🎉 Transfer to wormhole confirmed!");

            // Step 3: Generate ZK proof using wormhole prover
            log_print!("🔐 Step 2: Generating zero-knowledge proof...");

            // Create circuit inputs for the prover
            let circuit_inputs =
                create_circuit_inputs(&secret_bytes, &wormhole_account, &to, amount_u128)?;

            // Generate the proof using the wormhole prover
            let prover = WormholeProver::default();
            let proof = prover
                .commit(&circuit_inputs)
                .map_err(|e| crate::error::QuantusError::WormholeProver(format!("{:?}", e)))?
                .prove()
                .map_err(|e| {
                    crate::error::QuantusError::WormholeProofGeneration(format!("{:?}", e))
                })?;

            let proof_bytes = proof.to_bytes();

            log_success!("✅ Zero-knowledge proof generated successfully!");

            // Step 4: Submit proof via unsigned extrinsic
            log_print!("📡 Step 3: Submitting proof for verification...");

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

            log_print!("✅ Proof verification submitted!",);
            log_print!(
                "📍 Proof transaction hash: {}",
                proof_tx_report.extrinsic_hash.to_string().bright_blue()
            );

            // Wait for proof verification finalization
            let proof_success = chain_client
                .wait_for_finalization(&proof_tx_report.extrinsic_hash.to_string())
                .await?;

            if proof_success {
                log_success!("🎉 Wormhole spend completed successfully!");
                log_print!("💰 Funds have been spent from wormhole address");
            } else {
                log_error!("❌ Proof verification failed to finalize");
            }
        }
    }
    Ok(())
}

/// Create circuit inputs for the wormhole prover
fn create_circuit_inputs(
    secret: &[u8],
    wormhole_account: &AccountId32,
    exit_account: &str,
    funding_amount: u128,
) -> Result<CircuitInputs> {
    // Parse exit account
    let exit_account_id = AccountId32::from_ss58check(exit_account).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid exit account: {:?}", e))
    })?;

    // Create nullifier from secret and transfer count (0 for first transfer)
    let nullifier = wormhole_circuit::nullifier::Nullifier::from_preimage(secret, 0);

    // Create storage proof (simplified - in practice this would be fetched from the chain)
    let storage_proof = wormhole_circuit::storage_proof::ProcessedStorageProof::new(
        vec![], // proof nodes
        vec![], // proof values
    )
    .map_err(|e| crate::error::QuantusError::WormholeStorageProof(format!("{:?}", e)))?;

    // Create unspendable account from secret
    let unspendable_account =
        wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret);

    let inputs = CircuitInputs {
        public: PublicCircuitInputs {
            funding_amount,
            nullifier: nullifier.hash.into(),
            root_hash: [0u8; 32].into(), // Simplified - would be actual root hash
            exit_account: BytesDigest::try_from(exit_account_id.as_ref() as &[u8]).map_err(
                |_| {
                    crate::error::QuantusError::Generic(
                        "Failed to convert exit account to BytesDigest".to_string(),
                    )
                },
            )?,
        },
        private: PrivateCircuitInputs {
            secret: secret.to_vec(),
            storage_proof,
            transfer_count: 0, // First transfer
            funding_account: BytesDigest::try_from(wormhole_account.as_ref() as &[u8]).map_err(
                |_| {
                    crate::error::QuantusError::Generic(
                        "Failed to convert wormhole account to BytesDigest".to_string(),
                    )
                },
            )?,
            unspendable_account: unspendable_account.account_id.into(),
        },
    };

    Ok(inputs)
}
