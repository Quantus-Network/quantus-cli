//! Reversible-transfer scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_expect_failure, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use rand::Rng;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "schedule_and_cancel", schedule_and_cancel(ctx));
	exercise_step!(report, phase, "schedule_with_delay", schedule_with_delay(ctx));
	exercise_step!(report, phase, "set_high_security", set_high_security(ctx));
	exercise_step!(report, phase, "guardian_recover_funds", guardian_recover_funds(ctx));
	exercise_step!(
		report,
		phase,
		"execute_transfer_wrong_origin",
		execute_transfer_wrong_origin(ctx)
	);
	Ok(())
}

async fn pending_ids(
	ctx: &ExerciseCtx,
	sender: &crate::wallet::QuantumKeyPair,
) -> Result<Vec<subxt::utils::H256>> {
	let account = account_id_of(sender)?;
	let addr = quantus_subxt::api::storage()
		.reversible_transfers()
		.pending_transfers_by_sender(account);
	let latest = ctx.client.get_latest_block().await?;
	let value = ctx.client.client().storage().at(latest).fetch(&addr).await?;
	Ok(value.map(|bounded| bounded.0).unwrap_or_default())
}

async fn schedule_and_cancel(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[2].clone();
	let recipient = ctx.fresh_keypair()?.try_to_account_id_ss58check()?;
	let amount = ctx.unit;

	crate::cli::reversible::schedule_transfer_with_delay(
		&ctx.client,
		&sender,
		&recipient,
		amount,
		50,
		true,
		ctx.wait_mode(),
	)
	.await?;

	let ids = pending_ids(ctx, &sender).await?;
	if ids.is_empty() {
		return Err(QuantusError::Generic(
			"scheduled transfer not found in PendingTransfersBySender".to_string(),
		));
	}
	let tx_id = ids[ids.len() - 1];

	let cancel_call = quantus_subxt::api::tx().reversible_transfers().cancel(tx_id);
	submit_ok(ctx, &sender, cancel_call).await?;

	let ids_after = pending_ids(ctx, &sender).await?;
	if ids_after.contains(&tx_id) {
		return Err(QuantusError::Generic(format!(
			"cancelled transfer {tx_id:?} still listed as pending"
		)));
	}
	Ok(format!("scheduled reversible transfer {tx_id:?} then cancelled it, storage verified"))
}

async fn schedule_with_delay(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[2].clone();
	let recipient = ctx.fresh_keypair()?.try_to_account_id_ss58check()?;
	let delay_blocks = 50u64;

	crate::cli::reversible::schedule_transfer_with_delay(
		&ctx.client,
		&sender,
		&recipient,
		ctx.unit,
		delay_blocks,
		true, // delay in blocks
		ctx.wait_mode(),
	)
	.await?;

	let ids = pending_ids(ctx, &sender).await?;
	if ids.is_empty() {
		return Err(QuantusError::Generic(
			"delayed transfer not found in PendingTransfersBySender".to_string(),
		));
	}
	Ok(format!(
		"scheduled reversible transfer with {delay_blocks}-block delay ({} now pending)",
		ids.len()
	))
}

async fn set_high_security(ctx: &mut ExerciseCtx) -> Result<String> {
	// High-security is sticky; use a dedicated account.
	let account = ctx.fresh_keypair()?;
	let account_ss58 = account.try_to_account_id_ss58check()?;

	let funder = ctx.eph[3].clone();
	crate::cli::send::transfer(
		&ctx.client,
		&funder,
		&account_ss58,
		10 * ctx.unit,
		None,
		ctx.wait_mode(),
	)
	.await?;

	let guardian = account_id_of(&ctx.alice)?;
	use quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay;
	let call = quantus_subxt::api::tx()
		.reversible_transfers()
		.set_high_security(Delay::BlockNumber(10), guardian);
	submit_ok(ctx, &account, call).await?;

	let addr = quantus_subxt::api::storage()
		.reversible_transfers()
		.high_security_accounts(account_id_of(&account)?);
	let latest = ctx.client.get_latest_block().await?;
	let value = ctx.client.client().storage().at(latest).fetch(&addr).await?;
	match value {
		Some(data) =>
			if data.guardian != account_id_of(&ctx.alice)? {
				return Err(QuantusError::Generic(
					"high-security guardian in storage does not match alice".to_string(),
				));
			},
		None =>
			return Err(QuantusError::Generic(
				"high-security storage entry missing after set_high_security".to_string(),
			)),
	}

	let recipient = ctx.fresh_keypair()?.try_to_account_id_ss58check()?;
	crate::cli::reversible::schedule_transfer(
		&ctx.client,
		&account,
		&recipient,
		ctx.unit,
		ctx.wait_mode(),
	)
	.await?;

	let ids = pending_ids(ctx, &account).await?;
	let Some(&tx_id) = ids.last() else {
		return Err(QuantusError::Generic(
			"HS default-delay transfer not found in PendingTransfersBySender".to_string(),
		));
	};

	let cancel_call = quantus_subxt::api::tx().reversible_transfers().cancel(tx_id);
	submit_ok(ctx, &ctx.alice.clone(), cancel_call).await?;

	let ids_after = pending_ids(ctx, &account).await?;
	if ids_after.contains(&tx_id) {
		return Err(QuantusError::Generic(format!(
			"guardian-cancelled transfer {tx_id:?} still listed as pending"
		)));
	}

	Ok("high-security enabled (alice as guardian), default-delay transfer scheduled, \
		 guardian cancelled it, storage verified"
		.to_string())
}

/// Guardian seizes a compromised high-security account via `recover_funds`:
/// pending transfers are cancelled and the whole balance is swept to the guardian.
async fn guardian_recover_funds(ctx: &mut ExerciseCtx) -> Result<String> {
	// High-security is sticky; use a dedicated account.
	let account = ctx.fresh_keypair()?;
	let account_ss58 = account.try_to_account_id_ss58check()?;

	let funder = ctx.eph[3].clone();
	crate::cli::send::transfer(
		&ctx.client,
		&funder,
		&account_ss58,
		20 * ctx.unit,
		None,
		ctx.wait_mode(),
	)
	.await?;

	let guardian = account_id_of(&ctx.alice)?;
	use quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay;
	let enroll = quantus_subxt::api::tx()
		.reversible_transfers()
		.set_high_security(Delay::BlockNumber(50), guardian);
	submit_ok(ctx, &account, enroll).await?;

	// Leave a pending transfer behind so recovery also exercises the
	// cancel-all-pending-holds path.
	let recipient = ctx.fresh_keypair()?.try_to_account_id_ss58check()?;
	crate::cli::reversible::schedule_transfer(
		&ctx.client,
		&account,
		&recipient,
		ctx.unit,
		ctx.wait_mode(),
	)
	.await?;
	if pending_ids(ctx, &account).await?.is_empty() {
		return Err(QuantusError::Generic(
			"pending transfer missing before recover_funds".to_string(),
		));
	}

	let recover =
		quantus_subxt::api::tx().reversible_transfers().recover_funds(account_id_of(&account)?);
	submit_ok(ctx, &ctx.alice.clone(), recover).await?;

	let pending_after = pending_ids(ctx, &account).await?;
	if !pending_after.is_empty() {
		return Err(QuantusError::Generic(format!(
			"recover_funds left {} pending transfer(s) behind",
			pending_after.len()
		)));
	}
	let balance_after = ctx.free_balance(&account_ss58).await?;
	if balance_after != 0 {
		return Err(QuantusError::Generic(format!(
			"recover_funds left a free balance of {balance_after} on the recovered account"
		)));
	}
	Ok("guardian recovered high-security account: pending transfer seized, \
	    full balance swept to guardian, storage verified"
		.to_string())
}

/// `execute_transfer` is only dispatchable by the pallet's own scheduler origin;
/// an external signed call must be rejected.
async fn execute_transfer_wrong_origin(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[2].clone();
	let tx_id = subxt::utils::H256::from(ctx.rng.random::<[u8; 32]>());
	let call = quantus_subxt::api::tx().reversible_transfers().execute_transfer(tx_id);
	submit_expect_failure(ctx, &sender, call, &["InvalidSchedulerOrigin", "PendingTxNotFound"])
		.await
}
