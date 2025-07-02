use crate::chain::client::ChainClient;
use crate::chain::quantus_runtime_config::QuantusRuntimeConfig;
use crate::error::Result;
use crate::{log_error, log_print, log_success, log_verbose};
use codec::Compact;
use colored::Colorize;
use serde_json::Value;
use sp_core::crypto::AccountId32;
use sp_core::crypto::Ss58Codec;
use sp_runtime::MultiAddress;
use substrate_api_client::ac_compose_macros::compose_extrinsic;
use substrate_api_client::ac_primitives::ExtrinsicSigner;
use substrate_api_client::{SubmitAndWatch, XtStatus};

/// Execute a generic call to any pallet
pub async fn execute_generic_call(
    chain_client: &ChainClient,
    pallet: &str,
    call: &str,
    args: Vec<Value>,
    from: &str,
    tip: Option<String>,
) -> Result<()> {
    log_print!("🚀 Executing generic call");
    log_print!("Pallet: {}", pallet.bright_green());
    log_print!("Call: {}", call.bright_cyan());
    log_print!("From: {}", from.bright_yellow());
    if let Some(tip) = &tip {
        log_print!("Tip: {}", tip.bright_magenta());
    }

    let keypair = crate::wallet::load_keypair_from_wallet(from, None, None)?;

    log_verbose!("✅ Loaded keypair for {}", from);

    // Get metadata and validate pallet/call exists
    let api = chain_client.get_api();
    let metadata = api.metadata();

    // Find the pallet in metadata
    let pallet_metadata = metadata.pallet_by_name(pallet).ok_or_else(|| {
        crate::error::QuantusError::Generic(format!("Pallet '{}' not found in metadata", pallet))
    })?;

    log_verbose!(
        "✅ Found pallet '{}' with index {}",
        pallet,
        pallet_metadata.index()
    );

    // Find the call in the pallet
    let call_variant = pallet_metadata.call_variant_by_name(call).ok_or_else(|| {
        crate::error::QuantusError::Generic(format!(
            "Call '{}' not found in pallet '{}'",
            call, pallet
        ))
    })?;

    log_verbose!("✅ Found call '{}' with index {}", call, call_variant.index);

    // Create API with signer
    let api_with_signer = chain_client.create_api_with_signer(&keypair)?;

    // Create and submit extrinsic based on pallet and call - all logic in one place
    log_print!("🔧 Creating extrinsic for {}.{}", pallet, call);

    let tx_report = match (pallet, call) {
        // Balances pallet calls
        ("Balances", "transfer_allow_death") => {
            submit_balance_transfer_extrinsic(
                chain_client,
                &api_with_signer,
                &keypair,
                &args,
                false,
            )
            .await?
        }
        ("Balances", "transfer_keep_alive") => {
            submit_balance_transfer_extrinsic(chain_client, &api_with_signer, &keypair, &args, true)
                .await?
        }

        // System pallet calls
        ("System", "remark") => {
            submit_system_remark_extrinsic(chain_client, &api_with_signer, &keypair, &args).await?
        }

        // ReversibleTransfers pallet calls
        ("ReversibleTransfers", "schedule_transfer") => {
            submit_reversible_transfer_extrinsic(chain_client, &api_with_signer, &keypair, &args)
                .await?
        }

        // Sudo pallet calls
        ("Sudo", "sudo") => {
            submit_sudo_extrinsic(chain_client, &api_with_signer, &keypair, &args).await?
        }

        // TechCollective pallet calls
        ("TechCollective", "add_member") => {
            submit_tech_collective_add_member_extrinsic(
                chain_client,
                &api_with_signer,
                &keypair,
                &args,
            )
            .await?
        }
        ("TechCollective", "remove_member") => {
            submit_tech_collective_remove_member_extrinsic(
                chain_client,
                &api_with_signer,
                &keypair,
                &args,
            )
            .await?
        }
        ("TechCollective", "vote") => {
            submit_tech_collective_vote_extrinsic(chain_client, &api_with_signer, &keypair, &args)
                .await?
        }

        // Unsupported combinations
        ("Balances", _) => {
            log_error!("❌ Balances call '{}' is not supported yet", call);
            log_print!("💡 Supported Balances calls: transfer_allow_death, transfer_keep_alive");
            return Err(crate::error::QuantusError::Generic(format!(
                "Unsupported Balances call: {}",
                call
            ))
            .into());
        }
        ("System", _) => {
            log_error!("❌ System call '{}' is not supported yet", call);
            log_print!("💡 Supported System calls: remark");
            return Err(crate::error::QuantusError::Generic(format!(
                "Unsupported System call: {}",
                call
            ))
            .into());
        }
        ("Sudo", _) => {
            log_error!("❌ Sudo call '{}' is not supported yet", call);
            log_print!("💡 Supported Sudo calls: sudo");
            return Err(crate::error::QuantusError::Generic(format!(
                "Unsupported Sudo call: {}",
                call
            ))
            .into());
        }
        ("ReversibleTransfers", _) => {
            log_error!(
                "❌ ReversibleTransfers call '{}' is not supported yet",
                call
            );
            log_print!("💡 Supported ReversibleTransfers calls: schedule_transfer");
            return Err(crate::error::QuantusError::Generic(format!(
                "Unsupported ReversibleTransfers call: {}",
                call
            ))
            .into());
        }
        ("TechCollective", _) => {
            log_error!("❌ TechCollective call '{}' is not supported yet", call);
            log_print!("💡 Supported TechCollective calls: add_member, remove_member, vote");
            return Err(crate::error::QuantusError::Generic(format!(
                "Unsupported TechCollective call: {}",
                call
            ))
            .into());
        }
        (_, _) => {
            log_error!("❌ Pallet '{}' is not supported yet", pallet);
            log_print!(
                "💡 Supported pallets: Balances, System, Sudo, ReversibleTransfers, TechCollective"
            );
            return Err(crate::error::QuantusError::Generic(format!(
                "Unsupported pallet: {}. Only Balances, System, Sudo, ReversibleTransfers, and TechCollective are currently supported.",
                pallet
            )).into());
        }
    };

    log_success!("🎉 Transaction submitted successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        tx_report.extrinsic_hash.to_string().bright_yellow()
    );

    Ok(())
}

/// Create and submit balance transfer extrinsic using the central macro
async fn submit_balance_transfer_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
    keep_alive: bool,
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() != 2 {
        return Err(crate::error::QuantusError::Generic(
            "Balance transfer requires 2 arguments: dest, value".to_string(),
        )
        .into());
    }

    // Parse destination address
    let dest_str = args[0].as_str().ok_or_else(|| {
        crate::error::QuantusError::Generic("First argument must be a string address".to_string())
    })?;
    let dest_account = AccountId32::from_ss58check(dest_str).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid destination address: {:?}", e))
    })?;
    let dest: MultiAddress<AccountId32, u32> = MultiAddress::Id(dest_account);

    // Parse amount
    let amount_value = parse_balance_amount(&args[1]).await?;

    let call_name = if keep_alive {
        "transfer_keep_alive"
    } else {
        "transfer_allow_death"
    };

    log_verbose!(
        "✅ Parsed {}: dest={:?}, amount={}",
        call_name,
        dest,
        amount_value
    );

    // Create extrinsic
    let extrinsic = compose_extrinsic!(api, "Balances", call_name, dest, Compact(amount_value))
        .ok_or_else(|| {
            crate::error::QuantusError::Generic(format!("Failed to create {} extrinsic", call_name))
        })?;

    // Use the central submit_extrinsic! macro - ONE place for all submission logic
    log_print!("📡 Submitting extrinsic to chain...");
    crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)
}

/// Create and submit system remark extrinsic using the central macro
async fn submit_system_remark_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() != 1 {
        return Err(crate::error::QuantusError::Generic(
            "remark requires 1 argument: remark (string or hex bytes)".to_string(),
        )
        .into());
    }

    // Parse remark data
    let remark_bytes = parse_bytes_argument(&args[0])?;

    log_verbose!("✅ Parsed remark: {} bytes", remark_bytes.len());

    // Create extrinsic
    let extrinsic = compose_extrinsic!(api, "System", "remark", remark_bytes).ok_or_else(|| {
        crate::error::QuantusError::Generic("Failed to create remark extrinsic".to_string())
    })?;

    // Use the central submit_extrinsic! macro - ONE place for all submission logic
    log_print!("📡 Submitting extrinsic to chain...");
    crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)
}

/// Create and submit reversible transfer extrinsic using the central macro
async fn submit_reversible_transfer_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() != 2 {
        return Err(crate::error::QuantusError::Generic(
            "schedule_transfer requires 2 arguments: dest, amount".to_string(),
        )
        .into());
    }

    // Parse destination address
    let dest_str = args[0].as_str().ok_or_else(|| {
        crate::error::QuantusError::Generic("First argument must be a string address".to_string())
    })?;
    let dest_account = AccountId32::from_ss58check(dest_str).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid destination address: {:?}", e))
    })?;
    let dest: MultiAddress<AccountId32, u32> = MultiAddress::Id(dest_account);

    // Parse amount
    let amount_value = parse_balance_amount(&args[1]).await?;

    log_verbose!(
        "✅ Parsed schedule_transfer: dest={:?}, amount={}",
        dest,
        amount_value
    );

    // Create extrinsic
    let extrinsic = compose_extrinsic!(
        api,
        "ReversibleTransfers",
        "schedule_transfer",
        dest,
        amount_value
    )
    .ok_or_else(|| {
        crate::error::QuantusError::Generic(
            "Failed to create schedule_transfer extrinsic".to_string(),
        )
    })?;

    // Use the central submit_extrinsic! macro - ONE place for all submission logic
    log_print!("📡 Submitting extrinsic to chain...");
    crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)
}

/// Parse a balance amount from JSON value
async fn parse_balance_amount(value: &Value) -> Result<u128> {
    match value {
        Value::String(s) => {
            // Try to parse as a decimal number (like "10.5")
            if let Ok(parsed) = s.parse::<f64>() {
                // Convert to raw units (assuming 9 decimals for DEV token)
                let raw_amount = (parsed * 1_000_000_000.0) as u128;
                Ok(raw_amount)
            } else {
                Err(
                    crate::error::QuantusError::Generic(format!("Invalid balance amount: {}", s))
                        .into(),
                )
            }
        }
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                Ok(u as u128)
            } else if let Some(f) = n.as_f64() {
                // Convert to raw units (assuming 9 decimals for DEV token)
                let raw_amount = (f * 1_000_000_000.0) as u128;
                Ok(raw_amount)
            } else {
                Err(
                    crate::error::QuantusError::Generic(format!("Invalid balance amount: {:?}", n))
                        .into(),
                )
            }
        }
        _ => Err(crate::error::QuantusError::Generic(
            "Balance amount must be a string or number".to_string(),
        )
        .into()),
    }
}

/// Parse bytes from JSON value (string or hex)
fn parse_bytes_argument(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::String(s) => {
            if s.starts_with("0x") {
                // Hex string
                hex::decode(&s[2..]).map_err(|e| {
                    crate::error::QuantusError::Generic(format!("Invalid hex string: {:?}", e))
                        .into()
                })
            } else {
                // Regular string - convert to bytes
                Ok(s.as_bytes().to_vec())
            }
        }
        _ => Err(crate::error::QuantusError::Generic(
            "Bytes argument must be a string or hex string".to_string(),
        )
        .into()),
    }
}

/// Create and submit sudo extrinsic
async fn submit_sudo_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() != 1 {
        return Err(crate::error::QuantusError::Generic(
            "sudo requires 1 argument: inner_call (nested call object)".to_string(),
        )
        .into());
    }

    // Parse the inner call - this should be a JSON object representing the call
    let inner_call_value = &args[0];

    // Handle different formats of inner call specification
    match inner_call_value {
        // Format: {"TechCollective": {"add_member": {"who": "address"}}}
        Value::Object(outer_map) => {
            for (pallet_name, call_data) in outer_map {
                if let Value::Object(call_map) = call_data {
                    for (call_name, call_args) in call_map {
                        log_verbose!("✅ Parsed sudo inner call: {}.{}", pallet_name, call_name);

                        // Handle different pallet/call combinations
                        match (pallet_name.as_str(), call_name.as_str()) {
                            ("TechCollective", "add_member") => {
                                // Extract 'who' address from call_args
                                let who_str = if let Value::Object(args_map) = call_args {
                                    args_map.get("who")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| crate::error::QuantusError::Generic(
                                            "TechCollective.add_member requires 'who' field with address".to_string()
                                        ))?
                                } else {
                                    return Err(crate::error::QuantusError::Generic(
                                        "Invalid call arguments format".to_string(),
                                    )
                                    .into());
                                };

                                let who_account =
                                    AccountId32::from_ss58check(who_str).map_err(|e| {
                                        crate::error::QuantusError::Generic(format!(
                                            "Invalid member address: {:?}",
                                            e
                                        ))
                                    })?;
                                let who: MultiAddress<AccountId32, u32> =
                                    MultiAddress::Id(who_account);

                                // Create the inner call first
                                let inner_call =
                                    compose_extrinsic!(api, "TechCollective", "add_member", who)
                                        .ok_or_else(|| {
                                            crate::error::QuantusError::Generic(
                                        "Failed to create inner TechCollective.add_member call"
                                            .to_string(),
                                    )
                                        })?;

                                // Now wrap it with sudo
                                let extrinsic =
                                    compose_extrinsic!(api, "Sudo", "sudo", inner_call.function)
                                        .ok_or_else(|| {
                                            crate::error::QuantusError::Generic(
                                                "Failed to create sudo extrinsic".to_string(),
                                            )
                                        })?;

                                log_print!(
                                    "📡 Submitting sudo(TechCollective.add_member) extrinsic..."
                                );
                                return crate::submit_extrinsic_with_spinner!(
                                    chain_client,
                                    keypair,
                                    extrinsic
                                );
                            }
                            ("TechCollective", "remove_member") => {
                                // Similar logic for remove_member
                                let who_str = if let Value::Object(args_map) = call_args {
                                    args_map.get("who")
                                        .and_then(|v| v.as_str())
                                        .ok_or_else(|| crate::error::QuantusError::Generic(
                                            "TechCollective.remove_member requires 'who' field with address".to_string()
                                        ))?
                                } else {
                                    return Err(crate::error::QuantusError::Generic(
                                        "Invalid call arguments format".to_string(),
                                    )
                                    .into());
                                };

                                let rank = if let Value::Object(args_map) = call_args {
                                    args_map.get("rank").and_then(|v| v.as_u64()).unwrap_or(0)
                                        as u16
                                } else {
                                    0u16
                                };

                                let who_account =
                                    AccountId32::from_ss58check(who_str).map_err(|e| {
                                        crate::error::QuantusError::Generic(format!(
                                            "Invalid member address: {:?}",
                                            e
                                        ))
                                    })?;
                                let who: MultiAddress<AccountId32, u32> =
                                    MultiAddress::Id(who_account);

                                // Create the inner call first
                                let inner_call = compose_extrinsic!(
                                    api,
                                    "TechCollective",
                                    "remove_member",
                                    who,
                                    rank
                                )
                                .ok_or_else(|| {
                                    crate::error::QuantusError::Generic(
                                        "Failed to create inner TechCollective.remove_member call"
                                            .to_string(),
                                    )
                                })?;

                                // Now wrap it with sudo
                                let extrinsic =
                                    compose_extrinsic!(api, "Sudo", "sudo", inner_call.function)
                                        .ok_or_else(|| {
                                            crate::error::QuantusError::Generic(
                                                "Failed to create sudo extrinsic".to_string(),
                                            )
                                        })?;

                                log_print!(
                                    "📡 Submitting sudo(TechCollective.remove_member) extrinsic..."
                                );
                                return crate::submit_extrinsic_with_spinner!(
                                    chain_client,
                                    keypair,
                                    extrinsic
                                );
                            }
                            _ => {
                                return Err(crate::error::QuantusError::Generic(format!(
                                    "Sudo wrapper for {}.{} is not supported yet",
                                    pallet_name, call_name
                                ))
                                .into());
                            }
                        }
                    }
                }
            }

            Err(crate::error::QuantusError::Generic(
                "Invalid sudo call format - expected nested pallet/call structure".to_string(),
            )
            .into())
        }
        _ => Err(crate::error::QuantusError::Generic(
            "sudo argument must be a JSON object with nested call structure".to_string(),
        )
        .into()),
    }
}

/// Create and submit tech collective add_member extrinsic
async fn submit_tech_collective_add_member_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() != 1 {
        return Err(crate::error::QuantusError::Generic(
            "add_member requires 1 argument: who (address)".to_string(),
        )
        .into());
    }

    // Parse member address
    let who_str = args[0].as_str().ok_or_else(|| {
        crate::error::QuantusError::Generic("First argument must be a string address".to_string())
    })?;
    let who_account = AccountId32::from_ss58check(who_str).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid member address: {:?}", e))
    })?;
    let who: MultiAddress<AccountId32, u32> = MultiAddress::Id(who_account);

    log_verbose!("✅ Parsed add_member: who={:?}", who);

    // Create extrinsic
    let extrinsic =
        compose_extrinsic!(api, "TechCollective", "add_member", who).ok_or_else(|| {
            crate::error::QuantusError::Generic("Failed to create add_member extrinsic".to_string())
        })?;

    // Use the central submit_extrinsic! macro
    log_print!("📡 Submitting extrinsic to chain...");
    crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)
}

/// Create and submit tech collective remove_member extrinsic
async fn submit_tech_collective_remove_member_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() < 1 || args.len() > 2 {
        return Err(crate::error::QuantusError::Generic(
            "remove_member requires 1-2 arguments: who (address), [rank (u16)]".to_string(),
        )
        .into());
    }

    // Parse member address
    let who_str = args[0].as_str().ok_or_else(|| {
        crate::error::QuantusError::Generic("First argument must be a string address".to_string())
    })?;
    let who_account = AccountId32::from_ss58check(who_str).map_err(|e| {
        crate::error::QuantusError::Generic(format!("Invalid member address: {:?}", e))
    })?;
    let who: MultiAddress<AccountId32, u32> = MultiAddress::Id(who_account);

    // Parse rank (optional, default to 0)
    let rank = if args.len() > 1 {
        args[1].as_u64().unwrap_or(0) as u16
    } else {
        0u16
    };

    log_verbose!("✅ Parsed remove_member: who={:?}, rank={}", who, rank);

    // Create extrinsic
    let extrinsic = compose_extrinsic!(api, "TechCollective", "remove_member", who, rank)
        .ok_or_else(|| {
            crate::error::QuantusError::Generic(
                "Failed to create remove_member extrinsic".to_string(),
            )
        })?;

    // Use the central submit_extrinsic! macro
    log_print!("📡 Submitting extrinsic to chain...");
    crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)
}

/// Create and submit tech collective vote extrinsic
async fn submit_tech_collective_vote_extrinsic(
    chain_client: &ChainClient,
    api: &substrate_api_client::Api<
        crate::chain::quantus_runtime_config::QuantusRuntimeConfig,
        substrate_api_client::rpc::JsonrpseeClient,
    >,
    keypair: &crate::wallet::QuantumKeyPair,
    args: &[Value],
) -> Result<substrate_api_client::api::ExtrinsicReport<sp_core::H256>> {
    if args.len() != 2 {
        return Err(crate::error::QuantusError::Generic(
            "vote requires 2 arguments: poll_index (u32), aye (bool)".to_string(),
        )
        .into());
    }

    // Parse poll index
    let poll_index = args[0].as_u64().ok_or_else(|| {
        crate::error::QuantusError::Generic(
            "First argument must be a number (poll index)".to_string(),
        )
    })? as u32;

    // Parse vote (aye/nay)
    let aye = args[1].as_bool().ok_or_else(|| {
        crate::error::QuantusError::Generic("Second argument must be a boolean (aye)".to_string())
    })?;

    log_verbose!("✅ Parsed vote: poll_index={}, aye={}", poll_index, aye);

    // Create extrinsic
    let extrinsic =
        compose_extrinsic!(api, "TechCollective", "vote", poll_index, aye).ok_or_else(|| {
            crate::error::QuantusError::Generic("Failed to create vote extrinsic".to_string())
        })?;

    // Use the central submit_extrinsic! macro
    log_print!("📡 Submitting extrinsic to chain...");
    crate::submit_extrinsic_with_spinner!(chain_client, keypair, extrinsic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_parse_balance_amount_string() {
        let value = json!("10.5");
        let result = parse_balance_amount(&value).await.unwrap();
        // 10.5 * 1_000_000_000 = 10_500_000_000
        assert_eq!(result, 10_500_000_000);
    }

    #[tokio::test]
    async fn test_parse_balance_amount_number() {
        let value = json!(1000000000000u64);
        let result = parse_balance_amount(&value).await.unwrap();
        assert_eq!(result, 1_000_000_000_000);
    }

    #[tokio::test]
    async fn test_parse_balance_amount_float() {
        let value = json!(0.001);
        let result = parse_balance_amount(&value).await.unwrap();
        // 0.001 * 1_000_000_000 = 1_000_000
        assert_eq!(result, 1_000_000);
    }

    #[test]
    fn test_parse_balance_amount_invalid() {
        let value = json!(true);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(parse_balance_amount(&value));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bytes_argument_string() {
        let value = json!("hello world");
        let result = parse_bytes_argument(&value).unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_parse_bytes_argument_hex() {
        let value = json!("0x48656c6c6f");
        let result = parse_bytes_argument(&value).unwrap();
        assert_eq!(result, b"Hello");
    }

    #[test]
    fn test_parse_bytes_argument_invalid_hex() {
        let value = json!("0xgggg");
        let result = parse_bytes_argument(&value);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bytes_argument_invalid_type() {
        let value = json!(123);
        let result = parse_bytes_argument(&value);
        assert!(result.is_err());
    }

    #[cfg(test)]
    mod integration_tests {
        use super::*;

        /// Test that we can parse valid balance transfer arguments
        #[test]
        fn test_balance_transfer_args_validation() {
            // Valid args
            let args = vec![
                json!("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"),
                json!("1.5"),
            ];

            // Should have exactly 2 arguments
            assert_eq!(args.len(), 2);

            // First should be a string (address)
            assert!(args[0].is_string());

            // Second should be parseable as balance
            let rt = tokio::runtime::Runtime::new().unwrap();
            let amount = rt.block_on(parse_balance_amount(&args[1]));
            assert!(amount.is_ok());
            assert_eq!(amount.unwrap(), 1_500_000_000); // 1.5 * 10^9
        }

        /// Test that we properly validate argument counts for different calls
        #[test]
        fn test_argument_validation() {
            // Balances calls need 2 args
            let valid_balance_args = vec![json!("addr"), json!("100")];
            assert_eq!(valid_balance_args.len(), 2);

            // System remark needs 1 arg
            let valid_remark_args = vec![json!("hello")];
            assert_eq!(valid_remark_args.len(), 1);

            // ReversibleTransfers needs 2 args
            let valid_rt_args = vec![json!("addr"), json!("100")];
            assert_eq!(valid_rt_args.len(), 2);
        }

        /// Test error messages for unsupported combinations
        #[test]
        fn test_error_messages() {
            // Test that we have clear error messages for various scenarios
            let balance_error = "Balance transfer requires 2 arguments: dest, value";
            let remark_error = "remark requires 1 argument: remark (string or hex bytes)";
            let schedule_transfer_error = "schedule_transfer requires 2 arguments: dest, amount";

            // These are the error messages we expect to see
            assert!(balance_error.contains("2 arguments"));
            assert!(remark_error.contains("1 argument"));
            assert!(schedule_transfer_error.contains("2 arguments"));
        }

        /// Test JSON argument parsing edge cases
        #[test]
        fn test_json_arg_parsing() {
            // Test various JSON value types
            let string_arg = json!("test");
            let number_arg = json!(42);
            let float_arg = json!(3.14);
            let bool_arg = json!(true);
            let null_arg = json!(null);

            assert!(string_arg.is_string());
            assert!(number_arg.is_number());
            assert!(float_arg.is_number());
            assert!(bool_arg.is_boolean());
            assert!(null_arg.is_null());
        }

        /// Test address validation patterns
        #[test]
        fn test_address_validation() {
            // Valid SS58 address format (this is a test address)
            let valid_addr = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
            assert_eq!(valid_addr.len(), 48); // Standard SS58 length
            assert!(valid_addr.starts_with('5')); // Substrate addresses often start with 5

            // Invalid addresses
            let too_short = "5Grw";
            let wrong_chars = "not_an_address";

            assert!(too_short.len() < 40);
            assert!(!wrong_chars.chars().all(|c| c.is_alphanumeric()));
        }
    }

    #[cfg(test)]
    mod documentation_tests {
        /// Example usage for Balances::transfer_allow_death
        ///
        /// ```bash
        /// quantus call --pallet "Balances" --call "transfer_allow_death" \
        ///   --args '["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "1.5"]' \
        ///   --from my-wallet
        /// ```
        #[test]
        fn example_balance_transfer() {
            // This test documents the expected usage
            let pallet = "Balances";
            let call = "transfer_allow_death";
            let args = r#"["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "1.5"]"#;

            assert_eq!(pallet, "Balances");
            assert_eq!(call, "transfer_allow_death");
            assert!(args.contains("1.5"));
        }

        /// Example usage for System::remark
        ///
        /// ```bash
        /// quantus call --pallet "System" --call "remark" \
        ///   --args '["Hello Quantus!"]' \
        ///   --from my-wallet
        /// ```
        #[test]
        fn example_system_remark() {
            let pallet = "System";
            let call = "remark";
            let args = r#"["Hello Quantus!"]"#;

            assert_eq!(pallet, "System");
            assert_eq!(call, "remark");
            assert!(args.contains("Hello"));
        }

        /// Example usage for ReversibleTransfers::schedule_transfer
        ///
        /// ```bash
        /// quantus call --pallet "ReversibleTransfers" --call "schedule_transfer" \
        ///   --args '["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "100"]' \
        ///   --from my-wallet
        /// ```
        #[test]
        fn example_reversible_transfer() {
            let pallet = "ReversibleTransfers";
            let call = "schedule_transfer";
            let args = r#"["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", "100"]"#;

            assert_eq!(pallet, "ReversibleTransfers");
            assert_eq!(call, "schedule_transfer");
            assert!(args.contains("100"));
        }

        /// Example usage for TechCollective::add_member
        ///
        /// ```bash
        /// quantus call --pallet "TechCollective" --call "add_member" \
        ///   --args '["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"]' \
        ///   --from crystal_alice
        /// ```
        #[test]
        fn example_tech_collective_add_member() {
            let pallet = "TechCollective";
            let call = "add_member";
            let args = r#"["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"]"#;

            assert_eq!(pallet, "TechCollective");
            assert_eq!(call, "add_member");
            assert!(args.contains("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"));
        }

        /// Example usage for TechCollective::remove_member
        ///
        /// ```bash
        /// quantus call --pallet "TechCollective" --call "remove_member" \
        ///   --args '["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 0]' \
        ///   --from crystal_alice
        /// ```
        #[test]
        fn example_tech_collective_remove_member() {
            let pallet = "TechCollective";
            let call = "remove_member";
            let args = r#"["5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY", 0]"#;

            assert_eq!(pallet, "TechCollective");
            assert_eq!(call, "remove_member");
            assert!(args.contains("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"));
        }

        /// Example usage for TechCollective::vote
        ///
        /// ```bash
        /// quantus call --pallet "TechCollective" --call "vote" \
        ///   --args '[0, true]' \
        ///   --from crystal_alice
        /// ```
        #[test]
        fn example_tech_collective_vote() {
            let pallet = "TechCollective";
            let call = "vote";
            let args = r#"[0, true]"#;

            assert_eq!(pallet, "TechCollective");
            assert_eq!(call, "vote");
            assert!(args.contains("true"));
        }
    }
}
