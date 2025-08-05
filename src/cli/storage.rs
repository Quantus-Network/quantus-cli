//! `quantus storage` subcommand - storage operations
use crate::chain::client::ChainConfig;
use crate::cli::progress_spinner::wait_for_finalization;
use crate::{
    chain::quantus_subxt, error::QuantusError, log_error, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use codec::{Decode, Encode};
use colored::Colorize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::twox_128;
use std::str::FromStr;
use subxt::OnlineClient;

/// Validate that a pallet exists in the chain metadata
fn validate_pallet_exists(
    client: &OnlineClient<ChainConfig>,
    pallet_name: &str,
) -> crate::error::Result<()> {
    let metadata = client.metadata();
    metadata.pallet_by_name(pallet_name).ok_or_else(|| {
        QuantusError::Generic(format!(
            "Pallet '{}' not found in chain metadata. Available pallets: {}",
            pallet_name,
            quantus_subxt::api::PALLETS.join(", ")
        ))
    })?;
    Ok(())
}

/// Direct interaction with chain storage (Sudo required for set)
#[derive(Subcommand, Debug)]
pub enum StorageCommands {
    /// Get a storage value from a pallet.
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
        _decode_as: Option<String>,

        /// Storage key parameter (e.g., AccountId for System::Account)
        #[arg(long)]
        key: Option<String>,

        /// Type of the key parameter (e.g., "accountid", "u64")
        #[arg(long)]
        key_type: Option<String>,
    },
    /// Set a storage value on the chain.
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
    quantus_client: &crate::chain::client::QuantusClient,
    key: Vec<u8>,
) -> crate::error::Result<Option<Vec<u8>>> {
    // Get the latest block hash to read from the latest state (not finalized)
    let latest_block_hash = quantus_client.get_latest_block().await?;

    let storage_at = quantus_client.client().storage().at(latest_block_hash);

    let result = storage_at
        .fetch_raw(key)
        .await
        .map_err(|e| QuantusError::NetworkError(format!("Failed to fetch storage: {:?}", e)))?;

    Ok(result)
}

/// Set storage value using sudo (requires sudo privileges)
pub async fn set_storage_value(
    quantus_client: &crate::chain::client::QuantusClient,
    from_keypair: &crate::wallet::QuantumKeyPair,
    storage_key: Vec<u8>,
    value_bytes: Vec<u8>,
) -> crate::error::Result<subxt::utils::H256> {
    log_verbose!("✍️  Creating set_storage transaction...");

    // Create the System::set_storage call using RuntimeCall type alias
    let set_storage_call =
        quantus_subxt::api::Call::System(quantus_subxt::api::system::Call::set_storage {
            items: vec![(storage_key, value_bytes)],
        });

    // Wrap in Sudo::sudo call
    let sudo_call = quantus_subxt::api::tx().sudo().sudo(set_storage_call);

    let tx_hash =
        crate::cli::common::submit_transaction(quantus_client, from_keypair, sudo_call, None)
            .await?;

    log_verbose!("📋 Set storage transaction submitted: {:?}", tx_hash);

    Ok(tx_hash)
}

/// Handle storage subxt commands
pub async fn handle_storage_command(
    command: StorageCommands,
    node_url: &str,
) -> crate::error::Result<()> {
    log_print!("🗄️  Storage");

    let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

    match command {
        StorageCommands::Get {
            pallet,
            name,
            _decode_as,
            key,
            key_type,
        } => {
            log_print!(
                "🔎 Getting storage for {}::{}",
                pallet.bright_green(),
                name.bright_cyan()
            );

            if let Some(key_value) = &key {
                log_print!("🔑 With key: {}", key_value.bright_yellow());
            }

            // Validate pallet exists
            validate_pallet_exists(quantus_client.client(), &pallet)?;

            // Construct the storage key for all storage items
            let mut storage_key = twox_128(pallet.as_bytes()).to_vec();
            storage_key.extend(&twox_128(name.as_bytes()));

            // Add key parameter if provided
            if let Some(key_value) = key {
                if let Some(key_type_str) = key_type {
                    let key_bytes = encode_storage_key(&key_value, &key_type_str)?;
                    storage_key.extend(key_bytes);
                } else {
                    log_error!("Key type (--key-type) is required when using --key parameter");
                    return Ok(());
                }
            }

            let result = get_storage_raw(&quantus_client, storage_key).await?;

            if let Some(value_bytes) = result {
                log_success!("Raw Value: 0x{}", hex::encode(&value_bytes).bright_yellow());

                if let Some(type_str) = _decode_as {
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
        StorageCommands::Set {
            pallet,
            name,
            value,
            wallet,
            password,
            password_file,
            r#type,
        } => {
            log_print!(
                "✍️  Setting storage for {}::{}",
                pallet.bright_green(),
                name.bright_cyan()
            );
            log_print!("\n{}", "🛑 This is a SUDO operation!".bright_red().bold());

            // Validate pallet exists
            validate_pallet_exists(quantus_client.client(), &pallet)?;

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
                    // Try to parse as H256 first, then fall back to hex decode
                    if value.starts_with("0x") && value.len() == 66 {
                        // 0x + 64 hex chars = 66
                        // Try to parse as H256
                        let h256_value = subxt::utils::H256::from_str(&value).map_err(|e| {
                            QuantusError::Generic(format!("Invalid H256 value: {}", e))
                        })?;
                        h256_value.0.to_vec()
                    } else {
                        // Fall back to hex decode for other hex values
                        let value_hex = value.strip_prefix("0x").unwrap_or(&value);
                        hex::decode(value_hex).map_err(|e| {
                            QuantusError::Generic(format!("Invalid hex value: {}", e))
                        })?
                    }
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

            // 4. Submit the set storage transaction
            let tx_hash =
                set_storage_value(&quantus_client, &keypair, storage_key, value_bytes).await?;

            log_print!(
                "✅ {} Set storage transaction submitted! Hash: {:?}",
                "SUCCESS".bright_green().bold(),
                tx_hash
            );

            let success = wait_for_finalization(quantus_client.client(), tx_hash).await?;

            if success {
                log_success!(
                    "🎉 {} Set storage transaction confirmed!",
                    "FINISHED".bright_green().bold()
                );
            } else {
                log_error!("Transaction failed!");
            }

            Ok(())
        }
    }
}

/// Encode storage key parameter based on type
fn encode_storage_key(key_value: &str, key_type: &str) -> crate::error::Result<Vec<u8>> {
    use codec::Encode;
    use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58Codec};

    match key_type.to_lowercase().as_str() {
        "accountid" | "accountid32" => {
            let account_id = SpAccountId32::from_ss58check(key_value).map_err(|e| {
                crate::error::QuantusError::Generic(format!("Invalid AccountId: {:?}", e))
            })?;
            Ok(account_id.encode())
        }
        "u64" => {
            let value = key_value
                .parse::<u64>()
                .map_err(|e| crate::error::QuantusError::Generic(format!("Invalid u64: {}", e)))?;
            Ok(value.encode())
        }
        "u128" => {
            let value = key_value
                .parse::<u128>()
                .map_err(|e| crate::error::QuantusError::Generic(format!("Invalid u128: {}", e)))?;
            Ok(value.encode())
        }
        "u32" => {
            let value = key_value
                .parse::<u32>()
                .map_err(|e| crate::error::QuantusError::Generic(format!("Invalid u32: {}", e)))?;
            Ok(value.encode())
        }
        _ => Err(crate::error::QuantusError::Generic(format!(
            "Unsupported key type: {}. Supported types: accountid, u64, u128, u32",
            key_type
        ))),
    }
}
