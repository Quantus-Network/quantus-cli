//! Expected rejection scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_expect_failure, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "transfer_over_balance", transfer_over_balance(ctx));
	exercise_step!(report, phase, "transfer_below_ed", transfer_below_ed(ctx));
	exercise_step!(report, phase, "transfer_overflow_amount", transfer_overflow_amount(ctx));
	exercise_step!(report, phase, "malformed_address", malformed_address(ctx));
	exercise_step!(report, phase, "stale_nonce", stale_nonce(ctx));
	exercise_step!(report, phase, "reversible_delay_too_short", reversible_delay_too_short(ctx));
	exercise_step!(
		report,
		phase,
		"reversible_default_delay_not_hs",
		reversible_default_delay_not_hs(ctx)
	);
	exercise_step!(report, phase, "high_security_self_guardian", high_security_self_guardian(ctx));
	exercise_step!(report, phase, "scheduler_calls_disabled", scheduler_calls_disabled(ctx));
	exercise_step!(report, phase, "removed_pallets_absent", removed_pallets_absent(ctx));
	Ok(())
}

fn transfer_call(
	to: crate::cli::common::SubxtAccountId32,
	amount: u128,
) -> impl subxt::tx::Payload {
	quantus_subxt::api::tx()
		.balances()
		.transfer_allow_death(subxt::ext::subxt_core::utils::MultiAddress::Id(to), amount)
}

async fn transfer_over_balance(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[0].clone();
	let recipient = ctx.fresh_keypair()?;
	let balance = ctx.free_balance(&sender.try_to_account_id_ss58check()?).await?;
	let call = transfer_call(account_id_of(&recipient)?, balance.saturating_mul(2));
	submit_expect_failure(ctx, &sender, call, &["FundsUnavailable", "InsufficientBalance"]).await
}

async fn transfer_below_ed(ctx: &mut ExerciseCtx) -> Result<String> {
	if ctx.existential_deposit <= 1 {
		return Ok("existential deposit <= 1, below-ED case not applicable".to_string());
	}
	let sender = ctx.eph[0].clone();
	let recipient = ctx.fresh_keypair()?;
	let call = transfer_call(account_id_of(&recipient)?, ctx.existential_deposit - 1);
	submit_expect_failure(ctx, &sender, call, &["BelowMinimum", "ExistentialDeposit"]).await
}

async fn transfer_overflow_amount(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[1].clone();
	let recipient = ctx.fresh_keypair()?;
	let call = transfer_call(account_id_of(&recipient)?, u128::MAX);
	submit_expect_failure(
		ctx,
		&sender,
		call,
		&["FundsUnavailable", "Arithmetic", "InsufficientBalance"],
	)
	.await
}

async fn malformed_address(_ctx: &mut ExerciseCtx) -> Result<String> {
	match crate::cli::common::resolve_address("definitely-not-an-address-🦀") {
		Err(e) => Ok(format!("rejected client-side as expected: {e}")),
		Ok(resolved) => Err(QuantusError::Generic(format!(
			"malformed address unexpectedly resolved to {resolved}"
		))),
	}
}

async fn stale_nonce(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[0].clone();
	let account = sender.try_to_account_id_32()?;
	let current_nonce = ctx.client.get_account_nonce_from_best_block(&account).await?;
	if current_nonce == 0 {
		return Err(QuantusError::Generic(
			"expected eph[0] to have used nonces already".to_string(),
		));
	}
	let recipient = ctx.fresh_keypair()?;
	let call = transfer_call(account_id_of(&recipient)?, ctx.test_unit);
	match crate::cli::common::submit_transaction_with_nonce(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(sender.clone()),
		call,
		None,
		0,
		ctx.wait_mode(),
	)
	.await
	{
		Ok(hash) => Err(QuantusError::Generic(format!(
			"stale-nonce transaction unexpectedly accepted ({hash:?})"
		))),
		Err(e) => {
			let msg = e.to_string();
			if msg.contains("Stale") || msg.contains("outdated") || msg.contains("Invalid") {
				Ok("stale nonce rejected as expected".to_string())
			} else {
				Err(QuantusError::Generic(format!("unexpected stale-nonce error: {msg}")))
			}
		},
	}
}

async fn reversible_delay_too_short(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[2].clone();
	let recipient = ctx.fresh_keypair()?;
	use quantus_subxt::api::reversible_transfers::calls::types::schedule_transfer_with_delay::Delay;
	let call = quantus_subxt::api::tx().reversible_transfers().schedule_transfer_with_delay(
		subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&recipient)?),
		ctx.test_unit,
		Delay::BlockNumber(1),
	);
	submit_expect_failure(ctx, &sender, call, &["DelayTooShort"]).await
}

async fn reversible_default_delay_not_hs(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[2].clone();
	let recipient = ctx.fresh_keypair()?;
	let call = quantus_subxt::api::tx().reversible_transfers().schedule_transfer(
		subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&recipient)?),
		ctx.test_unit,
	);
	submit_expect_failure(ctx, &sender, call, &["AccountNotHighSecurity"]).await
}

async fn high_security_self_guardian(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[3].clone();
	use quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay;
	let call = quantus_subxt::api::tx()
		.reversible_transfers()
		.set_high_security(Delay::BlockNumber(10), account_id_of(&sender)?);
	submit_expect_failure(ctx, &sender, call, &["GuardianCannotBeSelf"]).await
}

async fn scheduler_calls_disabled(ctx: &mut ExerciseCtx) -> Result<String> {
	// Canary: Scheduler dispatchables are disabled in metadata.
	let metadata = ctx.client.client().metadata();
	let scheduler = metadata
		.pallet_by_name("Scheduler")
		.ok_or_else(|| QuantusError::Generic("Scheduler pallet missing entirely".to_string()))?;
	let call_count = scheduler.call_variants().map(|v| v.len()).unwrap_or(0);
	if call_count == 0 {
		Ok("Scheduler exposes no dispatchable calls, as expected".to_string())
	} else {
		Err(QuantusError::Generic(format!(
			"Scheduler unexpectedly exposes {call_count} dispatchable calls"
		)))
	}
}

async fn removed_pallets_absent(ctx: &mut ExerciseCtx) -> Result<String> {
	let metadata = ctx.client.client().metadata();
	for name in ["Referenda", "ConvictionVoting", "Sudo"] {
		if metadata.pallet_by_name(name).is_some() {
			return Err(QuantusError::Generic(format!(
				"pallet {name} unexpectedly present in runtime metadata"
			)));
		}
	}
	Ok("Referenda, ConvictionVoting and Sudo remain absent from the runtime".to_string())
}
