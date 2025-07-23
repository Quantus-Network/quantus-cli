//! `quantus call-subxt` subcommand - SubXT implementation for generic pallet calls
use crate::chain::client::ChainConfig;
use crate::cli::common::get_fresh_nonce;
use crate::{
    chain::client, chain::quantus_subxt, error::QuantusError, log_error, log_print,
    log_success, log_verbose, wallet::QuantumKeyPair,
};
use colored::Colorize;
use serde_json::Value;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::OnlineClient;

/// Execute a generic call to any pallet using SubXT
pub async fn execute_generic_call(
    client: &OnlineClient<ChainConfig>,
    pallet: &str,
    call: &str,
    args: Vec<Value>,
    from_keypair: &QuantumKeyPair,
    tip: Option<String>,
) -> crate::error::Result<subxt::utils::H256> {
    log_print!("🚀 Executing generic call (using subxt)");
    log_print!("Pallet: {}", pallet.bright_green());
    log_print!("Call: {}", call.bright_cyan());
    log_print!(
        "From: {}",
        from_keypair.to_account_id_ss58check().bright_yellow()
    );
    if let Some(tip) = &tip {
        log_print!("Tip: {}", tip.bright_magenta());
    }

    // Convert our QuantumKeyPair to subxt Signer
    let _signer = from_keypair
        .to_subxt_signer()
        .map_err(|e| QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e)))?;

    // Validate pallet/call exists in metadata
    let metadata = client.metadata();
    let pallet_metadata = metadata.pallet_by_name(pallet).ok_or_else(|| {
        QuantusError::Generic(format!("Pallet '{}' not found in metadata", pallet))
    })?;

    log_verbose!(
        "✅ Found pallet '{}' with index {}",
        pallet,
        pallet_metadata.index()
    );

    // Find the call in the pallet
    let call_metadata = pallet_metadata.call_variant_by_name(call).ok_or_else(|| {
        QuantusError::Generic(format!("Call '{}' not found in pallet '{}'", call, pallet))
    })?;

    log_verbose!(
        "✅ Found call '{}' with index {}",
        call,
        call_metadata.index
    );

    // Create and submit extrinsic based on pallet and call
    log_print!("🔧 Creating extrinsic for {}.{} with subxt", pallet, call);

    let tx_hash = match (pallet, call) {
        // Balances pallet calls
        ("Balances", "transfer_allow_death") => {
            submit_balance_transfer(client, from_keypair, &args, false).await?
        }
        ("Balances", "transfer_keep_alive") => {
            submit_balance_transfer(client, from_keypair, &args, true).await?
        }

        // System pallet calls
        ("System", "remark") => submit_system_remark(client, from_keypair, &args).await?,

        // Sudo pallet calls
        ("Sudo", "sudo") => submit_sudo_call(client, from_keypair, &args).await?,

        // TechCollective pallet calls
        ("TechCollective", "add_member") => {
            submit_tech_collective_add_member(client, from_keypair, &args).await?
        }
        ("TechCollective", "remove_member") => {
            submit_tech_collective_remove_member(client, from_keypair, &args).await?
        }
        ("TechCollective", "vote") => {
            submit_tech_collective_vote(client, from_keypair, &args).await?
        }

        // ReversibleTransfers pallet calls
        ("ReversibleTransfers", "schedule_transfer") => {
            submit_reversible_transfer(client, from_keypair, &args).await?
        }

        // Scheduler pallet calls
        ("Scheduler", "schedule") => submit_scheduler_schedule(client, from_keypair, &args).await?,
        ("Scheduler", "cancel") => submit_scheduler_cancel(client, from_keypair, &args).await?,

        // Generic fallback for unknown calls
        (_, _) => {
            log_error!(
                "❌ Pallet '{}' or call '{}' is not supported yet in SubXT implementation",
                pallet,
                call
            );
            log_print!("💡 Supported pallets in SubXT:");
            log_print!("   • Balances: transfer_allow_death, transfer_keep_alive");
            log_print!("   • System: remark");
            log_print!("   • Sudo: sudo");
            log_print!("   • TechCollective: add_member, remove_member, vote");
            log_print!("   • ReversibleTransfers: schedule_transfer");
            log_print!("   • Scheduler: schedule, cancel");
            log_print!("💡 For other calls, use the original 'quantus call' command");
            return Err(QuantusError::Generic(format!(
                "Unsupported pallet/call combination in SubXT: {}.{}",
                pallet, call
            )));
        }
    };

    log_success!("🎉 SubXT transaction submitted successfully!");
    log_print!(
        "📋 Transaction hash: {}",
        format!("0x{}", hex::encode(tx_hash)).bright_yellow()
    );

    Ok(tx_hash)
}

/// Submit balance transfer using SubXT
async fn submit_balance_transfer(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    args: &[Value],
    keep_alive: bool,
) -> crate::error::Result<subxt::utils::H256> {
    if args.len() != 2 {
        return Err(QuantusError::Generic(
            "Balances transfer requires 2 arguments: [to_address, amount]".to_string(),
        ));
    }

    let to_address = args[0].as_str().ok_or_else(|| {
        QuantusError::Generic("First argument must be a string (to_address)".to_string())
    })?;

    let amount: u128 = args[1].as_str().unwrap_or("0").parse().map_err(|_| {
        QuantusError::Generic("Second argument must be a number (amount)".to_string())
    })?;

    // Convert to AccountId32
    let to_account_id = AccountId32::from_ss58check(to_address)
        .map_err(|e| QuantusError::Generic(format!("Invalid to_address: {:?}", e)))?;

    // Convert to subxt_core AccountId32
    let to_account_id_bytes: [u8; 32] = *to_account_id.as_ref();
    let to_account_id_subxt = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

    // Create and submit the transfer call
    if keep_alive {
        let transfer_call = quantus_subxt::api::tx().balances().transfer_keep_alive(
            subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
            amount,
        );
        submit_transaction(client, from_keypair, transfer_call).await
    } else {
        let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
            subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
            amount,
        );
        submit_transaction(client, from_keypair, transfer_call).await
    }
}

/// Submit system remark using SubXT
async fn submit_system_remark(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    if args.len() != 1 {
        return Err(QuantusError::Generic(
            "System remark requires 1 argument: [remark]".to_string(),
        ));
    }

    let remark = args[0]
        .as_str()
        .ok_or_else(|| QuantusError::Generic("Argument must be a string (remark)".to_string()))?;

    let remark_call = quantus_subxt::api::tx()
        .system()
        .remark(remark.as_bytes().to_vec());

    submit_transaction(client, from_keypair, remark_call).await
}

/// Submit sudo call using SubXT
async fn submit_sudo_call(
    _client: &OnlineClient<ChainConfig>,
    _from_keypair: &QuantumKeyPair,
    _args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    // For now, this is a placeholder - sudo calls need the inner call to be constructed
    log_error!("❌ Sudo calls through generic call-subxt are complex - use specific sudo wrappers");
    log_print!("💡 Use dedicated subxt commands that already wrap calls in sudo");
    Err(QuantusError::Generic(
        "Sudo calls not supported in generic call-subxt - use specific commands".to_string(),
    ))
}

/// Submit tech collective add member using SubXT
async fn submit_tech_collective_add_member(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    if args.len() != 1 {
        return Err(QuantusError::Generic(
            "TechCollective add_member requires 1 argument: [member_address]".to_string(),
        ));
    }

    let member_address = args[0].as_str().ok_or_else(|| {
        QuantusError::Generic("Argument must be a string (member_address)".to_string())
    })?;

    let member_account_id = AccountId32::from_ss58check(member_address)
        .map_err(|e| QuantusError::Generic(format!("Invalid member_address: {:?}", e)))?;

    // Convert to subxt_core AccountId32
    let member_account_id_bytes: [u8; 32] = *member_account_id.as_ref();
    let member_account_id_subxt =
        subxt::ext::subxt_core::utils::AccountId32::from(member_account_id_bytes);

    // Wrap in sudo for privileged operation
    let sudo_call = quantus_subxt::api::tx()
        .sudo()
        .sudo(quantus_subxt::api::Call::TechCollective(
            quantus_subxt::api::tech_collective::Call::add_member {
                who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id_subxt),
            },
        ));

    submit_transaction(client, from_keypair, sudo_call).await
}

/// Submit tech collective remove member using SubXT
async fn submit_tech_collective_remove_member(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    if args.len() != 1 {
        return Err(QuantusError::Generic(
            "TechCollective remove_member requires 1 argument: [member_address]".to_string(),
        ));
    }

    let member_address = args[0].as_str().ok_or_else(|| {
        QuantusError::Generic("Argument must be a string (member_address)".to_string())
    })?;

    let member_account_id = AccountId32::from_ss58check(member_address)
        .map_err(|e| QuantusError::Generic(format!("Invalid member_address: {:?}", e)))?;

    // Convert to subxt_core AccountId32
    let member_account_id_bytes: [u8; 32] = *member_account_id.as_ref();
    let member_account_id_subxt =
        subxt::ext::subxt_core::utils::AccountId32::from(member_account_id_bytes);

    // Wrap in sudo for privileged operation
    let sudo_call = quantus_subxt::api::tx()
        .sudo()
        .sudo(quantus_subxt::api::Call::TechCollective(
            quantus_subxt::api::tech_collective::Call::remove_member {
                who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id_subxt),
                min_rank: 0, // Default rank
            },
        ));

    submit_transaction(client, from_keypair, sudo_call).await
}

/// Submit tech collective vote using SubXT
async fn submit_tech_collective_vote(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    if args.len() != 2 {
        return Err(QuantusError::Generic(
            "TechCollective vote requires 2 arguments: [referendum_index, aye]".to_string(),
        ));
    }

    let referendum_index: u32 = args[0].as_u64().unwrap_or(0) as u32;
    let aye = args[1].as_bool().unwrap_or(false);

    let vote_call = quantus_subxt::api::tx()
        .tech_collective()
        .vote(referendum_index, aye);

    submit_transaction(client, from_keypair, vote_call).await
}

/// Submit reversible transfer using SubXT
async fn submit_reversible_transfer(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    if args.len() != 2 {
        return Err(QuantusError::Generic(
            "ReversibleTransfers schedule_transfer requires 2 arguments: [to_address, amount]"
                .to_string(),
        ));
    }

    let to_address = args[0].as_str().ok_or_else(|| {
        QuantusError::Generic("First argument must be a string (to_address)".to_string())
    })?;

    let amount: u128 = args[1].as_str().unwrap_or("0").parse().map_err(|_| {
        QuantusError::Generic("Second argument must be a number (amount)".to_string())
    })?;

    let to_account_id = AccountId32::from_ss58check(to_address)
        .map_err(|e| QuantusError::Generic(format!("Invalid to_address: {:?}", e)))?;

    // Convert to subxt_core AccountId32
    let to_account_id_bytes: [u8; 32] = *to_account_id.as_ref();
    let to_account_id_subxt = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

    let schedule_call = quantus_subxt::api::tx()
        .reversible_transfers()
        .schedule_transfer(
            subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
            amount,
        );

    submit_transaction(client, from_keypair, schedule_call).await
}

/// Submit scheduler schedule using SubXT
async fn submit_scheduler_schedule(
    _client: &OnlineClient<ChainConfig>,
    _from_keypair: &QuantumKeyPair,
    _args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    log_error!("❌ Scheduler calls through generic call-subxt are complex");
    log_print!("💡 Use dedicated scheduler-subxt commands for complex scheduling");
    Err(QuantusError::Generic(
        "Scheduler calls not supported in generic call-subxt - use scheduler-subxt commands"
            .to_string(),
    ))
}

/// Submit scheduler cancel using SubXT
async fn submit_scheduler_cancel(
    _client: &OnlineClient<ChainConfig>,
    _from_keypair: &QuantumKeyPair,
    _args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
    log_error!("❌ Scheduler calls through generic call-subxt are complex");
    log_print!("💡 Use dedicated scheduler-subxt commands for scheduling operations");
    Err(QuantusError::Generic(
        "Scheduler calls not supported in generic call-subxt - use scheduler-subxt commands"
            .to_string(),
    ))
}

/// Helper function to submit transaction with nonce management
async fn submit_transaction<Call>(
    client: &OnlineClient<ChainConfig>,
    from_keypair: &QuantumKeyPair,
    call: Call,
) -> crate::error::Result<subxt::utils::H256>
where
    Call: subxt::tx::Payload,
{
    let signer = from_keypair
        .to_subxt_signer()
        .map_err(|e| QuantusError::NetworkError(format!("Failed to convert keypair: {:?}", e)))?;

    // Get fresh nonce for the sender
    let nonce = get_fresh_nonce(client, from_keypair).await?;

    // Create custom params with fresh nonce
    use subxt::config::DefaultExtrinsicParamsBuilder;
    let params = DefaultExtrinsicParamsBuilder::new().nonce(nonce).build();

    // Submit the transaction with fresh nonce
    let tx_hash = client
        .tx()
        .sign_and_submit(&call, &signer, params)
        .await
        .map_err(|e| {
            QuantusError::NetworkError(format!("Failed to submit transaction: {:?}", e))
        })?;

    log_verbose!("📋 Transaction submitted with subxt: {:?}", tx_hash);

    Ok(tx_hash)
}

/// Execute a generic call using SubXT
pub async fn execute_generic_call_subxt(
    pallet: &str,
    call: &str,
    args: Vec<Value>,
    from: &str,
    tip: Option<String>,
    node_url: &str,
) -> crate::error::Result<()> {
    log_print!("🚀 Generic Call (SubXT)");

    let client = client::create_subxt_client(node_url).await?;
    let keypair = crate::wallet::load_keypair_from_wallet(from, None, None)?;

    execute_generic_call(&client, pallet, call, args, &keypair, tip).await?;

    Ok(())
}
