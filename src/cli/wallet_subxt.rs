//! `quantus wallet-subxt` subcommand - SubXT implementation for wallet operations
use crate::{
    chain::client_subxt, chain::quantus_subxt, chain::types::ChainConfig, error::QuantusError,
    log_print, log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::OnlineClient;

/// Get the nonce (transaction count) of an account using SubXT
pub async fn get_account_nonce(
    client: &OnlineClient<ChainConfig>,
    account_address: &str,
) -> crate::error::Result<u32> {
    log_verbose!(
        "#️⃣ Querying nonce for account with subxt: {}",
        account_address.bright_green()
    );

    // Parse the SS58 address to AccountId32 (sp-core)
    let account_id_sp = AccountId32::from_ss58check(account_address)
        .map_err(|e| QuantusError::NetworkError(format!("Invalid SS58 address: {:?}", e)))?;

    log_verbose!("🔍 SP Account ID: {:?}", account_id_sp);

    // Convert to subxt_core AccountId32 for storage query
    let account_bytes: [u8; 32] = *account_id_sp.as_ref();
    let account_id = subxt::ext::subxt_core::utils::AccountId32::from(account_bytes);

    log_verbose!("🔍 SubXT Account ID: {:?}", account_id);

    // Use SubXT to query System::Account storage directly (like send_subxt.rs)
    use quantus_subxt::api;
    let storage_addr = api::storage().system().account(account_id);

    let storage_at =
        client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

    let account_info = storage_at
        .fetch_or_default(&storage_addr)
        .await
        .map_err(|e| {
            QuantusError::NetworkError(format!("Failed to fetch account info: {:?}", e))
        })?;

    log_verbose!("✅ Account info retrieved with subxt storage query!");
    log_verbose!("🔢 Nonce: {}", account_info.nonce);

    Ok(account_info.nonce)
}

/// Wallet management commands using SubXT
#[derive(Subcommand, Debug)]
pub enum WalletSubxtCommands {
    /// Get the nonce (transaction count) of an account using subxt
    Nonce {
        /// Account address to query (optional, uses wallet address if not provided)
        #[arg(short, long)]
        address: Option<String>,

        /// Wallet name (used for address if --address not provided)
        #[arg(short, long, required_unless_present("address"))]
        wallet: Option<String>,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,
    },
}

/// Handle wallet-subxt commands
pub async fn handle_wallet_subxt_command(
    command: WalletSubxtCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    match command {
        WalletSubxtCommands::Nonce {
            address,
            wallet,
            password,
        } => {
            log_print!("🔢 Querying account nonce (using subxt)...");

            let client = client_subxt::create_subxt_client(node_url).await?;

            // Determine which address to query
            let target_address = match (address, wallet) {
                (Some(addr), _) => {
                    // Validate the provided address
                    AccountId32::from_ss58check(&addr)
                        .map_err(|e| QuantusError::Generic(format!("Invalid address: {:?}", e)))?;
                    addr
                }
                (None, Some(wallet_name)) => {
                    // Load wallet and get its address
                    let keypair =
                        crate::wallet::load_keypair_from_wallet(&wallet_name, password, None)?;
                    keypair.to_account_id_ss58check()
                }
                (None, None) => {
                    // This case should be prevented by clap's `required_unless_present`
                    unreachable!("Either --address or --wallet must be provided");
                }
            };

            log_print!("Account: {}", target_address.bright_cyan());

            match get_account_nonce(&client, &target_address).await {
                Ok(nonce) => {
                    log_success!("Nonce: {}", nonce.to_string().bright_green());
                }
                Err(e) => {
                    log_print!("❌ Failed to get nonce: {}", e);
                    return Err(e);
                }
            }

            Ok(())
        }
    }
}
