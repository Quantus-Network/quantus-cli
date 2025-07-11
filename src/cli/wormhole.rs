use crate::{
    chain::client::ChainClient, error::Result, log_error, log_print, log_success,
    wallet::QuantumKeyPair,
};
use clap::Subcommand;
use colored::Colorize;
use dilithium_crypto::traits::WormholeAddress;
use hex;
use rusty_crystals_dilithium::ml_dsa_87::Keypair as DilithiumKeypair;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_runtime::traits::IdentifyAccount;

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
        } => {
            log_print!("Initiating spend from wormhole address...");

            let chain_client = ChainClient::new(node_url).await?;

            let clean_secret = secret.strip_prefix("0x").unwrap_or(&secret);
            let secret_bytes = hex::decode(clean_secret)
                .map_err(|_| crate::error::QuantusError::InvalidHexSecret)?;

            let secret_array: [u8; 32] = secret_bytes
                .try_into()
                .map_err(|v: Vec<u8>| crate::error::QuantusError::InvalidSecretLength(v.len()))?;

            let wormhole_pair = WormholePair::generate_pair_from_secret(&secret_array);

            let dilithium_keypair = DilithiumKeypair::generate(Some(&wormhole_pair.secret));
            let keypair = QuantumKeyPair::from_dilithium_keypair(&dilithium_keypair);

            let from_account: AccountId32 = WormholeAddress(wormhole_pair.address).into_account();

            log_print!(
                "Spending from: {}",
                from_account.to_ss58check().bright_yellow()
            );

            let (amount_u128, formatted_amount) =
                chain_client.validate_and_format_amount(&amount_str).await?;

            log_print!(
                "Sending {} to {}...",
                formatted_amount.bright_cyan(),
                to.bright_green()
            );

            let tx_report = chain_client.transfer(&keypair, &to, amount_u128).await?;

            log_print!(
                "✅ {} Transaction submitted!",
                "SUCCESS".bright_green().bold()
            );
            log_print!(
                "📍 Transaction hash: {}",
                tx_report.extrinsic_hash.to_string().bright_blue()
            );

            let success = chain_client
                .wait_for_finalization(&tx_report.extrinsic_hash.to_string())
                .await?;

            if success {
                log_success!(
                    "🎉 {} Transaction confirmed!",
                    "FINALIZED".bright_green().bold()
                );
                // Show updated balance
                let new_balance = chain_client
                    .get_balance(&from_account.to_ss58check())
                    .await?;
                let formatted_new_balance =
                    chain_client.format_balance_with_symbol(new_balance).await?;
                log_print!("💰 New balance: {}", formatted_new_balance.bright_yellow());
            } else {
                log_error!("Transaction failed to finalize.");
            }
        }
    }
    Ok(())
}
