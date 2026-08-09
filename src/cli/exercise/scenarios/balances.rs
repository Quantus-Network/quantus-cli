//! Balances happy-path scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
	wallet::DilithiumScheme,
};

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "single_transfer", single_transfer(ctx));
	exercise_step!(report, phase, "batch_transfer", batch_transfer(ctx));
	exercise_step!(report, phase, "transfer_with_tip", transfer_with_tip(ctx));
	exercise_step!(report, phase, "transfer_manual_nonce", transfer_manual_nonce(ctx));
	exercise_step!(report, phase, "remark_with_event", remark_with_event(ctx));
	exercise_step!(report, phase, "scheme_ml_dsa_65_transfer", scheme_transfer(ctx, DilithiumScheme::MlDsa65));
	exercise_step!(report, phase, "scheme_ml_dsa_87_transfer", scheme_transfer(ctx, DilithiumScheme::MlDsa87));
	Ok(())
}

async fn scheme_transfer(ctx: &mut ExerciseCtx, scheme: DilithiumScheme) -> Result<String> {
	let sender = ctx
		.eph
		.iter()
		.find(|k| k.scheme == scheme)
		.cloned()
		.ok_or_else(|| {
			QuantusError::Generic(format!("no ephemeral account with scheme {scheme}"))
		})?;
	let recipient = ctx.fresh_keypair_with_scheme(scheme)?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = ctx.unit;
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
	let amount = ctx.unit;

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
	let amount = ctx.unit / 2;
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
	let amount = ctx.unit;
	let tip = ctx.unit / 10;
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
		ctx.unit,
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
