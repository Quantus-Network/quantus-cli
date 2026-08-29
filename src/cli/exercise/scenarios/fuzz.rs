//! Seeded fuzz loop; failures are reproducible with `--seed`.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use rand::Rng;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	let iterations = ctx.fuzz_iterations;
	crate::log_status!("🎲 Fuzzing with seed {} ({} iterations)", ctx.seed, iterations);
	for i in 0..iterations {
		let name = format!("iteration_{i:03}");
		exercise_step!(report, phase, &name, fuzz_once(ctx));
	}
	Ok(())
}

fn is_clean_rejection(msg: &str) -> bool {
	// Submit failures now surface as QuantusError::Subxt (Display: "SubXT error: …"),
	// not the old Generic wrapper that contained "Failed to submit transaction".
	const NEEDLES: &[&str] = &[
		"Transaction execution failed",
		"Transaction invalid",
		"Transaction error",
		"Transaction dropped",
		"Failed to submit transaction",
		"Invalid Transaction",
		"Transaction has a bad signature",
		"Priority is too low",
		"Transaction is outdated",
		"Transaction is temporarily banned",
		"Inability to pay some fees",
	];
	NEEDLES.iter().any(|needle| msg.contains(needle))
}

fn classify(result: crate::error::Result<subxt::utils::H256>, what: &str) -> Result<String> {
	match result {
		Ok(hash) => Ok(format!("{what}: included ({hash:?})")),
		Err(e) => {
			let msg = e.to_string();
			if is_clean_rejection(&msg) {
				let first = msg.lines().next().unwrap_or(&msg).to_string();
				Ok(format!("{what}: cleanly rejected ({first})"))
			} else {
				Err(QuantusError::Generic(format!("{what}: unclean failure: {msg}")))
			}
		},
	}
}

async fn fuzz_once(ctx: &mut ExerciseCtx) -> Result<String> {
	match ctx.rng.random_range(0..4u8) {
		0 => fuzz_transfer(ctx).await,
		1 => fuzz_remark(ctx).await,
		2 => fuzz_batch(ctx).await,
		_ => fuzz_reversible(ctx).await,
	}
}

fn random_amount(ctx: &mut ExerciseCtx) -> u128 {
	let ed = ctx.existential_deposit;
	match ctx.rng.random_range(0..7u8) {
		0 => 0,
		1 => 1,
		2 => ed.saturating_sub(1),
		3 => ed,
		4 => ed.saturating_add(1),
		5 => ctx.rng.random_range(1..=100) * ctx.test_unit,
		_ => u128::MAX,
	}
}

fn random_recipient(ctx: &mut ExerciseCtx) -> Result<crate::cli::common::SubxtAccountId32> {
	let choice = ctx.rng.random_range(0..3u8);
	Ok(match choice {
		0 => {
			let idx = ctx.rng.random_range(0..ctx.eph.len());
			account_id_of(&ctx.eph[idx])?
		},
		1 => account_id_of(&ctx.fresh_keypair()?)?,
		_ => account_id_of(&ctx.eph[0])?,
	})
}

fn random_sender(ctx: &mut ExerciseCtx) -> crate::wallet::QuantumKeyPair {
	let idx = ctx.rng.random_range(0..ctx.eph.len());
	ctx.eph[idx].clone()
}

async fn fuzz_transfer(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = random_sender(ctx);
	let to = random_recipient(ctx)?;
	let amount = random_amount(ctx);
	let call = quantus_subxt::api::tx()
		.balances()
		.transfer_allow_death(subxt::ext::subxt_core::utils::MultiAddress::Id(to), amount);
	let result = crate::cli::common::submit_transaction(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(sender.clone()),
		call,
		None,
		ctx.wait_mode(),
	)
	.await;
	classify(result, &format!("transfer of {amount}"))
}

async fn fuzz_remark(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = random_sender(ctx);
	let len = ctx.rng.random_range(0..8192usize);
	let mut payload = vec![0u8; len];
	ctx.rng.fill(payload.as_mut_slice());
	let call = quantus_subxt::api::tx().system().remark(payload);
	let result = crate::cli::common::submit_transaction(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(sender.clone()),
		call,
		None,
		ctx.wait_mode(),
	)
	.await;
	classify(result, &format!("remark of {len} bytes"))
}

async fn fuzz_batch(ctx: &mut ExerciseCtx) -> Result<String> {
	use quantus_subxt::api::runtime_types::{
		pallet_balances::pallet::Call as BalancesCall, quantus_runtime::RuntimeCall,
	};
	let sender = random_sender(ctx);
	let n = ctx.rng.random_range(1..=20usize);
	let mut calls = Vec::with_capacity(n);
	for _ in 0..n {
		let to = random_recipient(ctx)?;
		let amount = random_amount(ctx);
		calls.push(RuntimeCall::Balances(BalancesCall::transfer_allow_death {
			dest: subxt::ext::subxt_core::utils::MultiAddress::Id(to),
			value: amount,
		}));
	}
	let call = quantus_subxt::api::tx().utility().batch_all(calls);
	let result = crate::cli::common::submit_transaction(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(sender.clone()),
		call,
		None,
		ctx.wait_mode(),
	)
	.await;
	// Batch succeeds even when inner calls fail.
	classify(result, &format!("batch of {n} transfers"))
}

async fn fuzz_reversible(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = random_sender(ctx);
	let to = random_recipient(ctx)?;
	let amount = random_amount(ctx);
	use quantus_subxt::api::reversible_transfers::calls::types::schedule_transfer_with_delay::Delay;
	let delay = match ctx.rng.random_range(0..5u8) {
		0 => Delay::BlockNumber(0),
		1 => Delay::BlockNumber(1),
		2 => Delay::BlockNumber(ctx.rng.random_range(2..1000)),
		3 => Delay::Timestamp(ctx.rng.random_range(0..100_000)),
		_ => Delay::BlockNumber(u32::MAX),
	};
	let call = quantus_subxt::api::tx().reversible_transfers().schedule_transfer_with_delay(
		subxt::ext::subxt_core::utils::MultiAddress::Id(to),
		amount,
		delay,
	);
	let result = crate::cli::common::submit_transaction(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(sender.clone()),
		call,
		None,
		ctx.wait_mode(),
	)
	.await;
	classify(result, &format!("reversible transfer of {amount}"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn classify_treats_subxt_pool_rejections_as_clean() {
		// Submit failures now Display as "SubXT error: …" without the old
		// "Failed to submit transaction" wrapper text.
		let err = QuantusError::Generic(
			"SubXT error: RpcError: Invalid Transaction: Custom error: 0".to_string(),
		);
		// Use NetworkError-shaped text that still contains the SubXT Display form.
		let result: crate::error::Result<subxt::utils::H256> = Err(err);
		let out = classify(result, "transfer").expect("pool rejection is clean");
		assert!(out.contains("cleanly rejected"), "got: {out}");
	}

	#[test]
	fn classify_treats_connection_failures_as_unclean() {
		let result: crate::error::Result<subxt::utils::H256> =
			Err(QuantusError::NetworkError("connection reset by peer".to_string()));
		let err = classify(result, "transfer").expect_err("network failure is unclean");
		assert!(err.to_string().contains("unclean failure"), "got: {err}");
	}
}
