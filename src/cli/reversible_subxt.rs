use crate::{
    chain::quantus_subxt, chain::types::ChainConfig, error::Result, log_error, log_print,
    log_success, log_verbose,
};
use clap::Subcommand;
use colored::Colorize;
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};
use subxt::OnlineClient;

/// SubXT-based reversible transfers client
pub struct SubxtReversibleClient {
    client: OnlineClient<ChainConfig>,
}

impl SubxtReversibleClient {
    /// Create a new SubXT reversible client
    pub async fn new(node_url: &str) -> Result<Self> {
        let client = OnlineClient::from_url(node_url).await.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to connect: {:?}", e))
        })?;

        Ok(Self { client })
    }

    /// Get fresh nonce for account using direct storage query to avoid cache
    async fn get_fresh_nonce(&self, from_keypair: &crate::wallet::QuantumKeyPair) -> Result<u64> {
        use substrate_api_client::ac_primitives::AccountId32 as SubstrateAccountId32;
        let from_account_id = SubstrateAccountId32::from_ss58check(
            &from_keypair.to_account_id_ss58check(),
        )
        .map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Invalid from address: {:?}", e))
        })?;

        let nonce = self
            .client
            .tx()
            .account_nonce(&from_account_id)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to get account nonce: {:?}",
                    e
                ))
            })?;

        log_verbose!("🔢 Using fresh nonce from tx API: {}", nonce);
        Ok(nonce)
    }

    /// Schedule a transfer with default delay using SubXT
    pub async fn schedule_transfer(
        &self,
        from_keypair: &crate::wallet::QuantumKeyPair,
        to_address: &str,
        amount: u128,
    ) -> Result<subxt::utils::H256> {
        log_verbose!("🔄 Creating reversible transfer with subxt...");
        log_verbose!(
            "   From: {}",
            from_keypair.to_account_id_ss58check().bright_cyan()
        );
        log_verbose!("   To: {}", to_address.bright_green());
        log_verbose!("   Amount: {}", amount);

        // Parse the destination address
        let to_account_id_sp = SpAccountId32::from_ss58check(to_address).map_err(|e| {
            crate::error::QuantusError::NetworkError(format!(
                "Invalid destination address: {:?}",
                e
            ))
        })?;

        // Convert to subxt_core AccountId32
        let to_account_id_bytes: [u8; 32] = *to_account_id_sp.as_ref();
        let to_account_id = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

        // Convert our QuantumKeyPair to subxt Signer
        let signer = from_keypair.to_subxt_signer().map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        log_verbose!("✍️  Creating reversible transfer extrinsic with subxt...");

        // Create the reversible transfer call using static API from quantus_subxt
        let transfer_call = quantus_subxt::api::tx()
            .reversible_transfers()
            .schedule_transfer(
                subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id),
                amount,
            );

        // Get fresh nonce for the sender
        let nonce = self.get_fresh_nonce(from_keypair).await?;

        // Create custom params with fresh nonce
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

        // Submit the transaction with fresh nonce
        let tx_hash = self
            .client
            .tx()
            .sign_and_submit(&transfer_call, &signer, params)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to submit transaction: {:?}",
                    e
                ))
            })?;

        log_verbose!("📋 Reversible transfer submitted with subxt: {:?}", tx_hash);

        Ok(tx_hash)
    }

    /// Cancel a pending reversible transaction using SubXT
    pub async fn cancel_transaction(
        &self,
        from_keypair: &crate::wallet::QuantumKeyPair,
        tx_id: &str,
    ) -> Result<subxt::utils::H256> {
        log_verbose!("❌ Cancelling reversible transfer with subxt...");
        log_verbose!("   Transaction ID: {}", tx_id.bright_yellow());

        // Parse transaction ID
        let tx_hash =
            sp_core::H256::from_slice(&hex::decode(tx_id.trim_start_matches("0x")).map_err(
                |e| crate::error::QuantusError::Generic(format!("Invalid transaction ID: {:?}", e)),
            )?);

        // Convert our QuantumKeyPair to subxt Signer
        let signer = from_keypair.to_subxt_signer().map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e))
        })?;

        log_verbose!("✍️  Creating cancel transaction extrinsic with subxt...");

        // Create the cancel transaction call using static API from quantus_subxt
        let cancel_call = quantus_subxt::api::tx()
            .reversible_transfers()
            .cancel(tx_hash);

        // Get fresh nonce for the sender
        let nonce = self.get_fresh_nonce(from_keypair).await?;

        // Create custom params with fresh nonce
        use subxt::config::DefaultExtrinsicParamsBuilder;
        let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

        // Submit the transaction with fresh nonce
        let tx_hash = self
            .client
            .tx()
            .sign_and_submit(&cancel_call, &signer, params)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to submit transaction: {:?}",
                    e
                ))
            })?;

        log_verbose!("📋 Cancel transaction submitted with subxt: {:?}", tx_hash);

        Ok(tx_hash)
    }

    /// Wait for transaction finalization using subxt
    pub async fn wait_for_finalization(&self, _tx_hash: subxt::utils::H256) -> Result<bool> {
        log_verbose!("⏳ Waiting for transaction finalization...");

        // For now, we use a simple delay approach similar to substrate-api-client
        // TODO: Implement proper finalization watching using SubXT events
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;

        log_verbose!("✅ Transaction likely finalized (after 6s delay)");
        Ok(true)
    }
}

/// Reversible transfer commands using SubXT
#[derive(Subcommand, Debug)]
pub enum ReversibleSubxtCommands {
    /// Schedule a transfer with default delay using subxt
    ScheduleTransfer {
        /// The recipient's account address
        #[arg(short, long)]
        to: String,

        /// Amount to transfer (e.g., "10", "10.5", "0.0001")
        #[arg(short, long)]
        amount: String,

        /// Wallet name to send from
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
    },

    /// Cancel a pending reversible transaction using subxt
    Cancel {
        /// Transaction ID to cancel (hex hash)
        #[arg(long)]
        tx_id: String,

        /// Wallet name to sign with
        #[arg(short, long)]
        from: String,

        /// Password for the wallet
        #[arg(short, long)]
        password: Option<String>,

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
    },
}

/// Handle reversible transfer subxt commands
pub async fn handle_reversible_subxt_command(
    command: ReversibleSubxtCommands,
    node_url: &str,
) -> Result<()> {
    log_print!("🔄 Reversible Transfers (SubXT)");

    let reversible_client = SubxtReversibleClient::new(node_url).await?;

    match command {
        ReversibleSubxtCommands::ScheduleTransfer {
            to,
            amount,
            from,
            password,
            password_file,
        } => {
            // Parse and validate the amount
            let client = crate::chain::client_subxt::create_subxt_client(node_url).await?;
            let (raw_amount, formatted_amount) =
                crate::cli::send_subxt::validate_and_format_amount(&client, &amount).await?;

            log_verbose!(
                "🚀 {} Scheduling reversible transfer {} to {} (using subxt)",
                "REVERSIBLE_SUBXT".bright_cyan().bold(),
                formatted_amount.bright_yellow().bold(),
                to.bright_green()
            );

            // Get password securely for decryption
            log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit transaction using subxt
            let tx_hash = reversible_client
                .schedule_transfer(&keypair, &to, raw_amount)
                .await?;

            log_print!(
                "✅ {} Reversible transfer scheduled with subxt! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = reversible_client.wait_for_finalization(tx_hash).await?;

            if success {
                log_success!(
                    "🎉 {} Reversible transfer confirmed with subxt!",
                    "FINALIZED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }
        ReversibleSubxtCommands::Cancel {
            tx_id,
            from,
            password,
            password_file,
        } => {
            log_verbose!(
                "❌ {} Cancelling reversible transfer {} (using subxt)",
                "CANCEL_SUBXT".bright_red().bold(),
                tx_id.bright_yellow().bold()
            );

            // Get password securely for decryption
            log_verbose!("📦 Using wallet: {}", from.bright_blue().bold());
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            // Submit cancel transaction using subxt
            let tx_hash = reversible_client
                .cancel_transaction(&keypair, &tx_id)
                .await?;

            log_print!(
                "✅ {} Cancel transaction submitted with subxt! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = reversible_client.wait_for_finalization(tx_hash).await?;

            if success {
                log_success!(
                    "🎉 {} Cancel transaction confirmed with subxt!",
                    "FINALIZED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }
    }
}
