//! `quantus storage-subxt` subcommand - SubXT implementation
use crate::chain::client::ChainConfig;
use crate::cli::common::get_fresh_nonce;
use crate::cli::progress_spinner::wait_for_finalization;
use crate::{
    chain::client, chain::quantus_subxt, error::QuantusError, log_error, log_print,
    log_success, log_verbose,
};
use clap::Subcommand;
use codec::{Decode, Encode};
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::twox_128;
use subxt::OnlineClient;

/// Direct interaction with chain storage using SubXT (Sudo required for set)
#[derive(Subcommand, Debug)]
pub enum StorageSubxtCommands {
    /// Get a storage value from a pallet using subxt.
    ///
    /// This command constructs a storage key from the pallet and item names,
    /// fetches the raw value from the chain state, and prints it as a hex string.
    Get {
        /// The name of the pallet (e.g., "Scheduler")
        #[arg(long)]
        pallet: String,

        /// The name of the storage item (e.g., "LastProcessedTimestamp")
        #[arg(long)]
        name: String,

        /// Attempt to decode the value as a specific type (e.g., "u64", "AccountId")
        #[arg(long)]
        decode_as: Option<String>,
    },
    /// Set a storage value on the chain using subxt.
    ///
    /// This requires sudo privileges. It constructs a `system.set_storage` call
    /// and wraps it in a `sudo.sudo` extrinsic. The provided value should be
    /// a hex-encoded SCALE representation of the value.
    Set {
        /// The name of the pallet (e.g., "Scheduler")
        #[arg(long)]
        pallet: String,

        /// The name of the storage item (e.g., "LastProcessedTimestamp")
        #[arg(long)]
        name: String,

        /// The new value. Can be a plain string if --type is used, otherwise a hex string.
        #[arg(long)]
        value: String,

        /// The type of the value to be encoded (e.g., "u64", "moment", "accountid")
        #[arg(long)]
        r#type: Option<String>,

        /// The name of the wallet to sign the transaction with (must have sudo rights)
        #[arg(long)]
        wallet: String,

        /// The password for the wallet
        #[arg(long)]
        password: Option<String>,

        /// Read password from file (for scripting)
        #[arg(long)]
        password_file: Option<String>,
    },
}

/// Get raw storage value by key
pub async fn get_storage_raw(
    client: &OnlineClient<ChainConfig>,
    key: Vec<u8>,
) -> crate::error::Result<Option<Vec<u8>>> {
    let storage_at =
        client.storage().at_latest().await.map_err(|e| {
            QuantusError::NetworkError(format!("Failed to access storage: {:?}", e))
        })?;

    let result = storage_at
        .fetch_raw(key)
        .await
        .map_err(|e| QuantusError::NetworkError(format!("Failed to fetch storage: {:?}", e)))?;

    Ok(result)
}

/// Set storage value using sudo (requires sudo privileges)
pub async fn set_storage_value(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &crate::wallet::QuantumKeyPair,
    storage_key: Vec<u8>,
    value_bytes: Vec<u8>,
) -> crate::error::Result<subxt::utils::H256> {
    log_verbose!("✍️  Creating set_storage transaction with subxt...");

    // Convert our QuantumKeyPair to subxt Signer
    let signer = from_keypair
        .to_subxt_signer()
        .map_err(|e| QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e)))?;

    // Create the System::set_storage call using RuntimeCall type alias
    let set_storage_call =
        quantus_subxt::api::Call::System(quantus_subxt::api::system::Call::set_storage {
            items: vec![(storage_key, value_bytes)],
        });

    // Wrap in Sudo::sudo call
    let sudo_call = quantus_subxt::api::tx().sudo().sudo(set_storage_call);

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
            QuantusError::NetworkError(format!("Failed to submit transaction: {:?}", e))
        })?;

    log_verbose!(
        "📋 Set storage transaction submitted with subxt: {:?}",
        tx_hash
    );

    Ok(tx_hash)
}

/// Handle storage subxt commands
pub async fn handle_storage_subxt_command(
    command: StorageSubxtCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    log_print!("🗄️  Storage (SubXT)");

    let client = client::create_subxt_client(node_url).await?;

    match command {
        StorageSubxtCommands::Get {
            pallet,
            name,
            decode_as,
        } => {
            log_print!(
                "🔎 Getting storage for {}::{} (using subxt)",
                pallet.bright_green(),
                name.bright_cyan()
            );

            // Construct the storage key
            let mut key = twox_128(pallet.as_bytes()).to_vec();
            key.extend(&twox_128(name.as_bytes()));

            let result = get_storage_raw(&client, key).await?;

            if let Some(value_bytes) = result {
                log_success!("Raw Value: 0x{}", hex::encode(&value_bytes).bright_yellow());

                if let Some(type_str) = decode_as {
                    log_print!("Attempting to decode as {}...", type_str.bright_cyan());
                    match type_str.to_lowercase().as_str() {
                        "u64" | "moment" => match u64::decode(&mut &value_bytes[..]) {
                            Ok(decoded_value) => {
                                log_success!(
                                    "Decoded Value: {}",
                                    decoded_value.to_string().bright_green()
                                )
                            }
                            Err(e) => log_error!("Failed to decode as u64: {}", e),
                        },
                        "u128" | "balance" => match u128::decode(&mut &value_bytes[..]) {
                            Ok(decoded_value) => {
                                log_success!(
                                    "Decoded Value: {}",
                                    decoded_value.to_string().bright_green()
                                )
                            }
                            Err(e) => log_error!("Failed to decode as u128: {}", e),
                        },
                        "accountid" | "accountid32" => {
                            match AccountId32::decode(&mut &value_bytes[..]) {
                                Ok(account_id) => log_success!(
                                    "Decoded Value: {}",
                                    account_id.to_ss58check().bright_green()
                                ),
                                Err(e) => log_error!("Failed to decode as AccountId32: {}", e),
                            }
                        }
                        _ => {
                            log_error!("Unsupported type for --decode-as: {}", type_str);
                            log_print!("Supported types: u64, moment, u128, balance, accountid");
                        }
                    }
                }
            } else {
                log_print!("{}", "No value found at this storage location.".dimmed());
            }

            Ok(())
        }
        StorageSubxtCommands::Set {
            pallet,
            name,
            value,
            wallet,
            password,
            password_file,
            r#type,
        } => {
            log_print!(
                "✍️  Setting storage for {}::{} (using subxt)",
                pallet.bright_green(),
                name.bright_cyan()
            );
            log_print!("\n{}", "🛑 This is a SUDO operation!".bright_red().bold());

            // 1. Load wallet
            let keypair =
                crate::wallet::load_keypair_from_wallet(&wallet, password, password_file)?;
            log_verbose!("🔐 Using wallet: {}", wallet.bright_green());

            // 2. Encode the value based on the --type flag
            let value_bytes = match r#type.as_deref() {
                Some("u64") | Some("moment") => value
                    .parse::<u64>()
                    .map_err(|e| QuantusError::Generic(format!("Invalid u64 value: {}", e)))?
                    .encode(),
                Some("u128") | Some("balance") => value
                    .parse::<u128>()
                    .map_err(|e| QuantusError::Generic(format!("Invalid u128 value: {}", e)))?
                    .encode(),
                Some("accountid") | Some("accountid32") => AccountId32::from_ss58check(&value)
                    .map_err(|e| {
                        QuantusError::Generic(format!("Invalid AccountId value: {:?}", e))
                    })?
                    .encode(),
                None => {
                    // Default to hex decoding if no type is specified
                    let value_hex = value.strip_prefix("0x").unwrap_or(&value);
                    hex::decode(value_hex)
                        .map_err(|e| QuantusError::Generic(format!("Invalid hex value: {}", e)))?
                }
                Some(unsupported) => {
                    return Err(QuantusError::Generic(format!(
                        "Unsupported type for --type: {}",
                        unsupported
                    )))
                }
            };

            log_verbose!(
                "Encoded value bytes: 0x{}",
                hex::encode(&value_bytes).dimmed()
            );

            // 3. Construct the storage key
            let storage_key = {
                let mut key = twox_128(pallet.as_bytes()).to_vec();
                key.extend(&twox_128(name.as_bytes()));
                key
            };

            // 4. Submit the set storage transaction using subxt
            let tx_hash = set_storage_value(&client, &keypair, storage_key, value_bytes).await?;

            log_print!(
                "✅ {} Set storage transaction submitted with subxt! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = wait_for_finalization(&client, tx_hash).await?;

            if success {
                log_success!(
                    "🎉 {} Set storage transaction confirmed with subxt!",
                    "FINALIZED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }
    }
}
