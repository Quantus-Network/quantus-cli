//! Utility pallet scenarios.
//!
//! `batch_all` is the pallet's only dispatchable, and it backs every CLI batch
//! transfer. Both halves of its contract are exercised: all items apply on
//! success, and none apply when any item fails.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{
			account_id_of, submit_expect_failure, submit_ok, ExerciseCtx, INSUFFICIENT_FUNDS_ERRORS,
		},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use quantus_subxt::api::runtime_types::{
	pallet_balances::pallet::Call as BalancesCall, quantus_runtime::RuntimeCall,
};
use subxt::ext::subxt_core::utils::MultiAddress;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "batch_all_applies_every_item", batch_all_applies(ctx));
	exercise_step!(report, phase, "batch_all_rolls_back_on_failure", batch_all_rolls_back(ctx));
	Ok(())
}

fn transfer_call(dest: crate::cli::common::SubxtAccountId32, value: u128) -> RuntimeCall {
	RuntimeCall::Balances(BalancesCall::transfer_allow_death {
		dest: MultiAddress::Id(dest),
		value,
	})
}

/// Every item of a successful `batch_all` must apply.
async fn batch_all_applies(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[0].clone();
	let first = ctx.fresh_keypair()?;
	let second = ctx.fresh_keypair()?;
	let first_ss58 = first.try_to_account_id_ss58check()?;
	let second_ss58 = second.try_to_account_id_ss58check()?;
	let amount = ctx.test_unit;

	let calls = vec![
		transfer_call(account_id_of(&first)?, amount),
		transfer_call(account_id_of(&second)?, amount),
	];
	let call = quantus_subxt::api::tx().utility().batch_all(calls);
	submit_ok(ctx, &sender, call).await?;

	for (ss58, label) in [(&first_ss58, "first"), (&second_ss58, "second")] {
		let balance = ctx.free_balance(ss58).await?;
		if balance != amount {
			return Err(QuantusError::Generic(format!(
				"batch_all {label} item not applied: recipient has {balance}, expected {amount}"
			)));
		}
	}
	Ok("Utility::batch_all applied both transfers and both were verified".to_string())
}

/// `batch_all` is atomic: a failing item must roll back the items before it.
async fn batch_all_rolls_back(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[1].clone();
	let good = ctx.fresh_keypair()?;
	let good_ss58 = good.try_to_account_id_ss58check()?;
	let doomed = ctx.fresh_keypair()?;
	// Twice what the sender holds. An amount near `u128::MAX` underflows the balance
	// arithmetic instead, which is a different failure than the one asserted below.
	let beyond_balance = ctx
		.free_balance(&sender.try_to_account_id_ss58check()?)
		.await?
		.saturating_mul(2);

	let calls = vec![
		transfer_call(account_id_of(&good)?, ctx.test_unit),
		transfer_call(account_id_of(&doomed)?, beyond_balance),
	];
	let call = quantus_subxt::api::tx().utility().batch_all(calls);
	// The extrinsic must be included and fail on the second item. Anything else
	// (an RPC error, a pool rejection) would leave the balance at zero too, so
	// the dispatch error is checked before the balance is read as evidence.
	let rejection = submit_expect_failure(ctx, &sender, call, INSUFFICIENT_FUNDS_ERRORS).await?;

	let good_balance = ctx.free_balance(&good_ss58).await?;
	if good_balance != 0 {
		return Err(QuantusError::Generic(format!(
			"batch_all did not roll back: recipient has {good_balance}, expected 0"
		)));
	}
	Ok(format!(
		"Utility::batch_all rolled back the successful item when a later item failed ({rejection})"
	))
}
