//! Utility pallet scenarios: force_batch, if_else, as_derivative.
//!
//! `Utility::batch` is covered by the fuzz phase and `batch_all` backs every
//! CLI batch transfer; `dispatch_as`, `dispatch_as_fallible`, and `with_weight`
//! are root-only and unreachable from the outside.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use codec::Encode;
use quantus_subxt::api::runtime_types::{
	pallet_balances::pallet::Call as BalancesCall, quantus_runtime::RuntimeCall,
};
use subxt::ext::subxt_core::utils::MultiAddress;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "force_batch_partial_failure", force_batch_partial(ctx));
	exercise_step!(report, phase, "if_else_fallback", if_else_fallback(ctx));
	exercise_step!(report, phase, "as_derivative", as_derivative(ctx));
	Ok(())
}

fn transfer_call(dest: crate::cli::common::SubxtAccountId32, value: u128) -> RuntimeCall {
	RuntimeCall::Balances(BalancesCall::transfer_allow_death {
		dest: MultiAddress::Id(dest),
		value,
	})
}

/// An impossible transfer amount, guaranteeing the call fails while staying
/// syntactically valid.
const ABSURD_AMOUNT: u128 = u128::MAX / 2;

/// `force_batch` keeps executing after an item fails; the good item must land.
async fn force_batch_partial(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[0].clone();
	let good_recipient = ctx.fresh_keypair()?;
	let good_ss58 = good_recipient.try_to_account_id_ss58check()?;
	let failing_recipient = ctx.fresh_keypair()?;
	let amount = ctx.unit;

	let calls = vec![
		transfer_call(account_id_of(&good_recipient)?, amount),
		transfer_call(account_id_of(&failing_recipient)?, ABSURD_AMOUNT),
	];
	let call = quantus_subxt::api::tx().utility().force_batch(calls);
	submit_ok(ctx, &sender, call).await?;

	let good_balance = ctx.free_balance(&good_ss58).await?;
	if good_balance != amount {
		return Err(QuantusError::Generic(format!(
			"force_batch good item not applied: recipient has {good_balance}, expected {amount}"
		)));
	}
	let failing_balance =
		ctx.free_balance(&failing_recipient.try_to_account_id_ss58check()?).await?;
	if failing_balance != 0 {
		return Err(QuantusError::Generic(format!(
			"force_batch failing item unexpectedly transferred {failing_balance}"
		)));
	}
	Ok("Utility::force_batch survived a failing item; good transfer verified".to_string())
}

/// `if_else` dispatches the fallback when the main call fails.
async fn if_else_fallback(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[1].clone();
	let recipient = ctx.fresh_keypair()?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = ctx.unit;

	let main = transfer_call(account_id_of(&recipient)?, ABSURD_AMOUNT);
	let fallback = transfer_call(account_id_of(&recipient)?, amount);
	let call = quantus_subxt::api::tx().utility().if_else(main, fallback);
	submit_ok(ctx, &sender, call).await?;

	let balance = ctx.free_balance(&recipient_ss58).await?;
	if balance != amount {
		return Err(QuantusError::Generic(format!(
			"if_else fallback not applied: recipient has {balance}, expected {amount}"
		)));
	}
	Ok("Utility::if_else main call failed, fallback transfer executed and verified".to_string())
}

/// Derivative (pseudonym) account of `who` at `index`, as computed by
/// `pallet_utility::derivative_account_id`.
fn derivative_account(
	who: &crate::cli::common::SubxtAccountId32,
	index: u16,
) -> crate::cli::common::SubxtAccountId32 {
	let who_bytes: &[u8; 32] = who.as_ref();
	let entropy = sp_core::hashing::blake2_256(&(b"modlpy/utilisuba", who_bytes, index).encode());
	crate::cli::common::SubxtAccountId32::from(entropy)
}

fn to_ss58(account: &crate::cli::common::SubxtAccountId32) -> String {
	use sp_core::crypto::Ss58Codec;
	let bytes: [u8; 32] = *account.as_ref();
	sp_core::crypto::AccountId32::from(bytes)
		.to_ss58check_with_version(sp_core::crypto::Ss58AddressFormat::custom(189))
}

/// `as_derivative` must dispatch the inner call from the caller's derivative
/// account, not from the caller itself.
async fn as_derivative(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[2].clone();
	let index: u16 = 42;
	let derivative = derivative_account(&account_id_of(&sender)?, index);
	let derivative_ss58 = to_ss58(&derivative);

	// The derivative account has to hold the funds the inner call moves.
	let funding = 5 * ctx.unit;
	crate::cli::send::transfer(
		&ctx.client,
		&sender,
		&derivative_ss58,
		funding,
		None,
		ctx.wait_mode(),
	)
	.await?;

	let recipient = ctx.fresh_keypair()?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = 2 * ctx.unit;
	let inner = transfer_call(account_id_of(&recipient)?, amount);
	let call = quantus_subxt::api::tx().utility().as_derivative(index, inner);
	submit_ok(ctx, &sender, call).await?;

	let received = ctx.free_balance(&recipient_ss58).await?;
	if received != amount {
		return Err(QuantusError::Generic(format!(
			"as_derivative transfer not applied: recipient has {received}, expected {amount}"
		)));
	}
	let derivative_after = ctx.free_balance(&derivative_ss58).await?;
	if derivative_after != funding - amount {
		return Err(QuantusError::Generic(format!(
			"derivative account balance is {derivative_after}, expected {} — the inner \
			 call did not draw from the derivative account",
			funding - amount
		)));
	}
	Ok(format!(
		"Utility::as_derivative (index {index}) transferred from the derivative account; \
		 both balances verified"
	))
}
