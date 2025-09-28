//! `quantus call` subcommand - generic pallet calls
use crate::{
	chain::quantus_subxt, error::QuantusError, log_error, log_print, log_success, log_verbose,
	wallet::QuantumKeyPair,
};
use colored::Colorize;
use serde_json::Value;
use sp_core::crypto::{AccountId32, Ss58Codec};

/// Execute a generic call to any pallet
pub async fn execute_generic_call(
	quantus_client: &crate::chain::client::QuantusClient,
	pallet: &str,
	call: &str,
	args: Vec<Value>,
	from_keypair: &QuantumKeyPair,
	tip: Option<String>,
) -> crate::error::Result<subxt::utils::H256> {
	log_print!("🚀 Executing generic call");
	log_print!("Pallet: {}", pallet.bright_green());
	log_print!("Call: {}", call.bright_cyan());
	log_print!("From: {}", from_keypair.to_account_id_ss58check().bright_yellow());
	if let Some(tip) = &tip {
		log_print!("Tip: {}", tip.bright_magenta());
	}

	// Convert our QuantumKeyPair to subxt Signer
	let _signer = from_keypair
		.to_subxt_signer()
		.map_err(|e| QuantusError::NetworkError(format!("Failed to convert keypair: {e:?}")))?;

	// Validate pallet/call exists in metadata
	let metadata = quantus_client.client().metadata();
	let pallet_metadata = metadata
		.pallet_by_name(pallet)
		.ok_or_else(|| QuantusError::Generic(format!("Pallet '{pallet}' not found in metadata")))?;

	log_verbose!("✅ Found pallet '{}' with index {}", pallet, pallet_metadata.index());

	// Find the call in the pallet
	let call_metadata = pallet_metadata.call_variant_by_name(call).ok_or_else(|| {
		QuantusError::Generic(format!("Call '{call}' not found in pallet '{pallet}'"))
	})?;

	log_verbose!("✅ Found call '{}' with index {}", call, call_metadata.index);

	// Parse tip amount if provided
	let tip_amount = if let Some(tip_str) = &tip { tip_str.parse::<u128>().ok() } else { None };

	// Create and submit extrinsic based on pallet and call
	log_print!("🔧 Creating extrinsic for {}.{}", pallet, call);

	let tx_hash = match (pallet, call) {
		// Balances pallet calls
		("Balances", "transfer_allow_death") =>
			submit_balance_transfer(quantus_client, from_keypair, &args, false, tip_amount).await?,
		("Balances", "transfer_keep_alive") =>
			submit_balance_transfer(quantus_client, from_keypair, &args, true, tip_amount).await?,

		// System pallet calls
		("System", "remark") =>
			submit_system_remark(quantus_client, from_keypair, &args, tip_amount).await?,

		// Sudo pallet calls
		("Sudo", "sudo") => submit_sudo_call(quantus_client, from_keypair, &args).await?,

		// TechCollective pallet calls
		("TechCollective", "add_member") =>
			submit_tech_collective_add_member(quantus_client, from_keypair, &args).await?,
		("TechCollective", "remove_member") =>
			submit_tech_collective_remove_member(quantus_client, from_keypair, &args).await?,
		("TechCollective", "vote") =>
			submit_tech_collective_vote(quantus_client, from_keypair, &args).await?,

		// ReversibleTransfers pallet calls
		("ReversibleTransfers", "schedule_transfer") =>
			submit_reversible_transfer(quantus_client, from_keypair, &args).await?,

		// Scheduler pallet calls
		("Scheduler", "schedule") =>
			submit_scheduler_schedule(quantus_client, from_keypair, &args).await?,
		("Scheduler", "cancel") =>
			submit_scheduler_cancel(quantus_client, from_keypair, &args).await?,

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
				"Unsupported pallet/call combination in SubXT: {pallet}.{call}"
			)));
		},
	};

	log_success!("🎉 SubXT transaction submitted successfully!");
	log_print!("📋 Transaction hash: {}", format!("0x{}", hex::encode(tx_hash)).bright_yellow());

	Ok(tx_hash)
}

/// Submit balance transfer
async fn submit_balance_transfer(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &QuantumKeyPair,
	args: &[Value],
	keep_alive: bool,
	tip: Option<u128>,
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
	let (to_account_id, _) = AccountId32::from_ss58check_with_version(to_address)
		.map_err(|e| QuantusError::Generic(format!("Invalid to_address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let to_account_id_bytes: [u8; 32] = *to_account_id.as_ref();
	let to_account_id_subxt = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

	// Create and submit the transfer call
	if keep_alive {
		let transfer_call = quantus_subxt::api::tx().balances().transfer_keep_alive(
			subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
			amount,
		);
		crate::cli::common::submit_transaction(quantus_client, from_keypair, transfer_call, tip)
			.await
	} else {
		let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
			subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
			amount,
		);
		crate::cli::common::submit_transaction(quantus_client, from_keypair, transfer_call, tip)
			.await
	}
}

/// Submit system remark
async fn submit_system_remark(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &QuantumKeyPair,
	args: &[Value],
	tip: Option<u128>,
) -> crate::error::Result<subxt::utils::H256> {
	if args.len() != 1 {
		return Err(QuantusError::Generic(
			"System remark requires 1 argument: [remark]".to_string(),
		));
	}

	let remark = args[0]
		.as_str()
		.ok_or_else(|| QuantusError::Generic("Argument must be a string (remark)".to_string()))?;

	let remark_call = quantus_subxt::api::tx().system().remark(remark.as_bytes().to_vec());

	crate::cli::common::submit_transaction(quantus_client, from_keypair, remark_call, tip).await
}

/// Submit sudo call
async fn submit_sudo_call(
	_quantus_client: &crate::chain::client::QuantusClient,
	_from_keypair: &QuantumKeyPair,
	_args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
	// For now, this is a placeholder - sudo calls need the inner call to be constructed
	log_error!("❌ Sudo calls through generic call are complex - use specific sudo wrappers");
	log_print!("💡 Use dedicated subxt commands that already wrap calls in sudo");
	Err(QuantusError::Generic(
		"Sudo calls not supported in generic call - use specific commands".to_string(),
	))
}

/// Submit tech collective add member
async fn submit_tech_collective_add_member(
	quantus_client: &crate::chain::client::QuantusClient,
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

	let (member_account_id, _) = AccountId32::from_ss58check_with_version(member_address)
		.map_err(|e| QuantusError::Generic(format!("Invalid member_address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let member_account_id_bytes: [u8; 32] = *member_account_id.as_ref();
	let member_account_id_subxt =
		subxt::ext::subxt_core::utils::AccountId32::from(member_account_id_bytes);

	// Wrap in sudo for privileged operation
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(quantus_subxt::api::Call::TechCollective(
		quantus_subxt::api::tech_collective::Call::add_member {
			who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id_subxt),
		},
	));

	crate::cli::common::submit_transaction(quantus_client, from_keypair, sudo_call, None).await
}

/// Submit tech collective remove member
async fn submit_tech_collective_remove_member(
	quantus_client: &crate::chain::client::QuantusClient,
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

	let (member_account_id, _) = AccountId32::from_ss58check_with_version(member_address)
		.map_err(|e| QuantusError::Generic(format!("Invalid member_address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let member_account_id_bytes: [u8; 32] = *member_account_id.as_ref();
	let member_account_id_subxt =
		subxt::ext::subxt_core::utils::AccountId32::from(member_account_id_bytes);

	// Wrap in sudo for privileged operation
	let sudo_call = quantus_subxt::api::tx().sudo().sudo(quantus_subxt::api::Call::TechCollective(
		quantus_subxt::api::tech_collective::Call::remove_member {
			who: subxt::ext::subxt_core::utils::MultiAddress::Id(member_account_id_subxt),
			min_rank: 0, // Default rank
		},
	));

	crate::cli::common::submit_transaction(quantus_client, from_keypair, sudo_call, None).await
}

/// Submit tech collective vote
async fn submit_tech_collective_vote(
	quantus_client: &crate::chain::client::QuantusClient,
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

	let vote_call = quantus_subxt::api::tx().tech_collective().vote(referendum_index, aye);

	crate::cli::common::submit_transaction(quantus_client, from_keypair, vote_call, None).await
}

/// Submit reversible transfer
async fn submit_reversible_transfer(
	quantus_client: &crate::chain::client::QuantusClient,
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

	let (to_account_id, _) = AccountId32::from_ss58check_with_version(to_address)
		.map_err(|e| QuantusError::Generic(format!("Invalid to_address: {e:?}")))?;

	// Convert to subxt_core AccountId32
	let to_account_id_bytes: [u8; 32] = *to_account_id.as_ref();
	let to_account_id_subxt = subxt::ext::subxt_core::utils::AccountId32::from(to_account_id_bytes);

	let schedule_call = quantus_subxt::api::tx().reversible_transfers().schedule_transfer(
		subxt::ext::subxt_core::utils::MultiAddress::Id(to_account_id_subxt),
		amount,
	);

	crate::cli::common::submit_transaction(quantus_client, from_keypair, schedule_call, None).await
}

/// Submit scheduler schedule
async fn submit_scheduler_schedule(
	_quantus_client: &crate::chain::client::QuantusClient,
	_from_keypair: &QuantumKeyPair,
	_args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
	log_error!("❌ Scheduler calls through generic call are complex");
	log_print!("💡 Use dedicated scheduler commands for complex scheduling");
	Err(QuantusError::Generic(
		"Scheduler calls not supported in generic call - use scheduler commands".to_string(),
	))
}

/// Submit scheduler cancel
async fn submit_scheduler_cancel(
	_quantus_client: &crate::chain::client::QuantusClient,
	_from_keypair: &QuantumKeyPair,
	_args: &[Value],
) -> crate::error::Result<subxt::utils::H256> {
	log_error!("❌ Scheduler calls through generic call are complex");
	log_print!("💡 Use dedicated scheduler commands for scheduling operations");
	Err(QuantusError::Generic(
		"Scheduler calls not supported in generic call - use scheduler commands".to_string(),
	))
}

/// Handle generic call command execution
pub async fn handle_generic_call(
	pallet: &str,
	call: &str,
	args: Vec<Value>,
	keypair: &QuantumKeyPair,
	tip: Option<String>,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("🚀 Generic Call");

	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	execute_generic_call(&quantus_client, pallet, call, args, keypair, tip).await?;

	Ok(())
}
