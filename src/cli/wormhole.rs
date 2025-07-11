use crate::{cli::send, error::Result, log_print, log_success};
use clap::Subcommand;
use colored::Colorize;
use dilithium_crypto::traits::WormholeAddress;
use hex;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_runtime::traits::IdentifyAccount;

// TODO: This should be replaced with the config.
const WORMHOLE_BRIDGE_ACCOUNT: &str = "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2"; // crystal_bob

/// Wormhole commands
#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
    /// Generate a new wormhole address and secret
    GenerateAddress,

    /// Spend funds via the wormhole bridge
    Spend {
        /// Wallet name to send from
        #[arg(short, long)]
        from: String,

        /// Amount to send (e.g., "10", "10.5", "0.0001")
        #[arg(short, long)]
        amount: String,

        /// Password for the wallet (or use environment variables)
        #[arg(short, long)]
        password: Option<String>,

        /// Read password from file (for scripting)
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
            from,
            amount,
            password,
            password_file,
        } => {
            log_print!(
                "Initiating wormhole spend to bridge account: {}",
                WORMHOLE_BRIDGE_ACCOUNT.bright_yellow()
            );
            send::handle_send_command(
                from,
                WORMHOLE_BRIDGE_ACCOUNT.to_string(),
                &amount,
                node_url,
                password,
                password_file,
            )
            .await?;

            log_success!("Wormhole transfer initiated successfully!");
            log_print!(
                "{}",
                "Note: A relayer will now pick up this transaction to complete the transfer on the destination chain."
                    .dimmed()
            );
        }
    }
    Ok(())
}
