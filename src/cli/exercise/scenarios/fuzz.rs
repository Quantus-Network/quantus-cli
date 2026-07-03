//! Seeded fuzz loop. Each iteration draws a random action (transfers with
//! boundary amounts, random-size remarks, random batches, random reversible
//! delays) from the shared RNG. The invariant asserted for every iteration is
//! that the node responds and the transaction either executes successfully or
//! is rejected with a cleanly decoded error — anything else (hang, stream
//! ending, undecodable failure) fails the step. The seed is logged so any
//! failure is reproducible with `--seed`.

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

/// Outcome classifier: clean success or clean rejection both pass.
fn classify(result: crate::error::Result<subxt::utils::H256>, what: &str) -> Result<String> {
	match result {
		Ok(hash) => Ok(format!("{what}: included ({hash:?})")),
		Err(e) => {
			let msg = e.to_string();
			let clean = msg.contains("Transaction execution failed") ||
				msg.contains("Transaction invalid") ||
				msg.contains("Transaction error") ||
				msg.contains("Transaction dropped") ||
				msg.contains("Failed to submit transaction");
			if clean {
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
		5 => ctx.rng.random_range(1..=100) * ctx.unit,
		_ => u128::MAX,
	}
}

fn random_recipient(ctx: &mut ExerciseCtx) -> Result<crate::cli::common::SubxtAccountId32> {
	let choice = ctx.rng.random_range(0..3u8);
	Ok(match choice {
		// Existing funded account.
		0 => {
			let idx = ctx.rng.random_range(0..ctx.eph.len());
			account_id_of(&ctx.eph[idx])
		},
		// Brand new account.
		1 => account_id_of(&ctx.fresh_keypair()?),
		// Self-transfer.
		_ => account_id_of(&ctx.eph[0]),
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
	let result =
		crate::cli::common::submit_transaction(&ctx.client, &sender, call, None, ctx.wait_mode())
			.await;
	classify(result, &format!("transfer of {amount}"))
}

async fn fuzz_remark(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = random_sender(ctx);
	let len = ctx.rng.random_range(0..8192usize);
	let mut payload = vec![0u8; len];
	ctx.rng.fill(payload.as_mut_slice());
	let call = quantus_subxt::api::tx().system().remark(payload);
	let result =
		crate::cli::common::submit_transaction(&ctx.client, &sender, call, None, ctx.wait_mode())
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
	let call = quantus_subxt::api::tx().utility().batch(calls);
	let result =
		crate::cli::common::submit_transaction(&ctx.client, &sender, call, None, ctx.wait_mode())
			.await;
	// Utility::batch itself succeeds even when inner calls fail (it emits
	// BatchInterrupted), so both outcomes are legitimate here.
	classify(result, &format!("batch of {n} transfers"))
}

async fn fuzz_reversible(ctx: &mut ExerciseCtx) -> Result<String> {
	let sender = random_sender(ctx);
	let to = random_recipient(ctx)?;
	let amount = random_amount(ctx);
	use quantus_subxt::api::reversible_transfers::calls::types::schedule_transfer_with_delay::Delay;
	// Mix of too-short, sane, and absurd delays in both units.
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
	let result =
		crate::cli::common::submit_transaction(&ctx.client, &sender, call, None, ctx.wait_mode())
			.await;
	classify(result, &format!("reversible transfer of {amount}"))
}
