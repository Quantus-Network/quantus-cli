//! Balances happy-path scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
	wallet::DilithiumScheme,
};
use subxt::ext::subxt_core::utils::MultiAddress;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "single_transfer", single_transfer(ctx));
	exercise_step!(report, phase, "batch_transfer", batch_transfer(ctx));
	exercise_step!(report, phase, "transfer_with_tip", transfer_with_tip(ctx));
	exercise_step!(report, phase, "transfer_manual_nonce", transfer_manual_nonce(ctx));
	exercise_step!(report, phase, "remark_with_event", remark_with_event(ctx));
	exercise_step!(report, phase, "transfer_keep_alive", transfer_keep_alive(ctx));
	exercise_step!(report, phase, "transfer_all", transfer_all(ctx));
	exercise_step!(report, phase, "burn", burn(ctx));
	exercise_step!(report, phase, "upgrade_accounts", upgrade_accounts(ctx));
	exercise_step!(
		report,
		phase,
		"scheme_ml_dsa_65_transfer",
		scheme_transfer(ctx, DilithiumScheme::MlDsa65)
	);
	exercise_step!(
		report,
		phase,
		"scheme_ml_dsa_87_transfer",
		scheme_transfer(ctx, DilithiumScheme::MlDsa87)
	);
	Ok(())
}

async fn scheme_transfer(ctx: &mut ExerciseCtx, scheme: DilithiumScheme) -> Result<String> {
	let sender = ctx.eph.iter().find(|k| k.scheme == scheme).cloned().ok_or_else(|| {
		QuantusError::Generic(format!("no ephemeral account with scheme {scheme}"))
	})?;
	let recipient = ctx.fresh_keypair_with_scheme(scheme)?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = ctx.test_unit;
	let before = ctx.free_balance(&recipient_ss58).await?;
	crate::cli::send::transfer(
		&ctx.client,
		&sender,
		&recipient_ss58,
		amount,
		None,
		ctx.wait_mode(),
	)
	.await?;
	let after = ctx.free_balance(&recipient_ss58).await?;
	if after != before + amount {
		return Err(QuantusError::Generic(format!(
			"{scheme} recipient balance mismatch: before {before}, after {after}, expected +{amount}"
		)));
	}
	Ok(format!("{scheme} sender signed transfer; recipient balance verified"))
}

async fn single_transfer(ctx: &mut ExerciseCtx) -> Result<String> {
	let recipient = ctx.fresh_keypair()?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = ctx.test_unit;

	let sender = ctx.eph[0].clone();
	let before = ctx.free_balance(&recipient_ss58).await?;
	crate::cli::send::transfer(
		&ctx.client,
		&sender,
		&recipient_ss58,
		amount,
		None,
		ctx.wait_mode(),
	)
	.await?;
	let after = ctx.free_balance(&recipient_ss58).await?;
	if after != before + amount {
		return Err(QuantusError::Generic(format!(
			"recipient balance mismatch: before {before}, after {after}, expected +{amount}"
		)));
	}
	Ok(format!("transferred {amount} raw units to fresh account, balance verified"))
}

async fn batch_transfer(ctx: &mut ExerciseCtx) -> Result<String> {
	let n = 3usize;
	let mut recipients = Vec::with_capacity(n);
	for _ in 0..n {
		recipients.push(ctx.fresh_keypair()?.try_to_account_id_ss58check()?);
	}
	let amount = ctx.test_unit / 2;
	let transfers: Vec<(String, u128)> = recipients.iter().map(|r| (r.clone(), amount)).collect();

	let sender = ctx.eph[0].clone();
	crate::cli::send::batch_transfer(&ctx.client, &sender, transfers, None, ctx.wait_mode())
		.await?;

	for recipient in &recipients {
		let balance = ctx.free_balance(recipient).await?;
		if balance != amount {
			return Err(QuantusError::Generic(format!(
				"batch recipient {recipient} has balance {balance}, expected {amount}"
			)));
		}
	}
	Ok(format!("Utility::batch of {n} transfers included, all balances verified"))
}

async fn transfer_with_tip(ctx: &mut ExerciseCtx) -> Result<String> {
	let recipient = ctx.fresh_keypair()?.try_to_account_id_ss58check()?;
	let amount = ctx.test_unit;
	let tip = ctx.test_unit / 10;
	let sender = ctx.eph[1].clone();
	crate::cli::send::transfer(
		&ctx.client,
		&sender,
		&recipient,
		amount,
		Some(tip),
		ctx.wait_mode(),
	)
	.await?;
	let balance = ctx.free_balance(&recipient).await?;
	if balance != amount {
		return Err(QuantusError::Generic(format!(
			"tipped transfer recipient balance {balance}, expected {amount}"
		)));
	}
	Ok(format!("transfer with tip {tip} included and verified"))
}

async fn transfer_manual_nonce(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[1].clone();
	let account = sender.try_to_account_id_32()?;
	let nonce = ctx.client.get_account_nonce_from_best_block(&account).await?;
	let recipient = ctx.fresh_keypair()?.try_to_account_id_ss58check()?;
	crate::cli::send::transfer_with_nonce(
		&ctx.client,
		&sender,
		&recipient,
		ctx.test_unit,
		None,
		Some(nonce as u32),
		ctx.wait_mode(),
	)
	.await?;
	Ok(format!("transfer with explicit nonce {nonce} included"))
}

async fn remark_with_event(ctx: &mut ExerciseCtx) -> Result<String> {
	let payload: [u8; 16] = rand::Rng::random(&mut ctx.rng);
	let call = quantus_subxt::api::tx().system().remark_with_event(payload.to_vec());
	let sender = ctx.eph[0].clone();
	let hash = submit_ok(ctx, &sender, call).await?;
	Ok(format!("System::remark_with_event included ({hash:?})"))
}

async fn transfer_keep_alive(ctx: &mut ExerciseCtx) -> Result<String> {
	let recipient = ctx.fresh_keypair()?;
	let recipient_id = account_id_of(&recipient)?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = ctx.test_unit;

	let sender = ctx.eph[1].clone();
	let call = quantus_subxt::api::tx()
		.balances()
		.transfer_keep_alive(MultiAddress::Id(recipient_id), amount);
	submit_ok(ctx, &sender, call).await?;

	let balance = ctx.free_balance(&recipient_ss58).await?;
	if balance != amount {
		return Err(QuantusError::Generic(format!(
			"transfer_keep_alive recipient balance {balance}, expected {amount}"
		)));
	}
	Ok("Balances::transfer_keep_alive included, recipient balance verified".to_string())
}

/// `transfer_all(keep_alive: false)` must empty and reap the sending account.
async fn transfer_all(ctx: &mut ExerciseCtx) -> Result<String> {
	// Dedicated sender so reaping it does not disturb the shared ephemeral accounts.
	let sender = ctx.fresh_keypair()?;
	let sender_ss58 = sender.try_to_account_id_ss58check()?;
	let funder = ctx.eph[1].clone();
	crate::cli::send::transfer(
		&ctx.client,
		&funder,
		&sender_ss58,
		20 * ctx.test_unit,
		None,
		ctx.wait_mode(),
	)
	.await?;

	let recipient = ctx.fresh_keypair()?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let call = quantus_subxt::api::tx()
		.balances()
		.transfer_all(MultiAddress::Id(account_id_of(&recipient)?), false);
	submit_ok(ctx, &sender, call).await?;

	let sender_after = ctx.free_balance(&sender_ss58).await?;
	if sender_after != 0 {
		return Err(QuantusError::Generic(format!(
			"transfer_all left {sender_after} on the sender, expected the account to be emptied"
		)));
	}
	let recipient_after = ctx.free_balance(&recipient_ss58).await?;
	if recipient_after == 0 {
		return Err(QuantusError::Generic("transfer_all recipient received nothing".to_string()));
	}
	Ok(format!(
		"Balances::transfer_all emptied the sender; recipient received {recipient_after} raw units"
	))
}

/// `burn` destroys funds from the caller, reducing total issuance.
async fn burn(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[0].clone();
	let sender_ss58 = sender.try_to_account_id_ss58check()?;
	let amount = ctx.test_unit;

	let before = ctx.free_balance(&sender_ss58).await?;
	let call = quantus_subxt::api::tx().balances().burn(amount, true);
	submit_ok(ctx, &sender, call).await?;
	let after = ctx.free_balance(&sender_ss58).await?;

	// The exact fee is unknown; the delta must cover at least the burned amount.
	let delta = before.saturating_sub(after);
	if delta < amount {
		return Err(QuantusError::Generic(format!(
			"burn of {amount} only reduced the sender balance by {delta}"
		)));
	}
	Ok(format!("Balances::burn destroyed {amount} raw units (balance delta {delta} incl. fee)"))
}

/// `upgrade_accounts` is permissionless maintenance; a no-op call must still dispatch.
async fn upgrade_accounts(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = ctx.eph[1].clone();
	let target = account_id_of(&ctx.bob)?;
	let call = quantus_subxt::api::tx().balances().upgrade_accounts(vec![target]);
	let hash = submit_ok(ctx, &sender, call).await?;
	Ok(format!("Balances::upgrade_accounts included ({hash:?})"))
}
