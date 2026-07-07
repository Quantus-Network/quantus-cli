//! Runtime upgrade via tech-referenda set_code (requires fast-governance node).

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::path::Path;
use subxt::tx::Payload;

pub async fn run(
	ctx: &mut ExerciseCtx,
	report: &mut Report,
	phase: &str,
	wasm_path: &Path,
	timeout_secs: u64,
) -> Result<()> {
	exercise_step!(
		report,
		phase,
		"governance_set_code",
		governance_set_code(ctx, wasm_path, timeout_secs)
	);
	Ok(())
}

async fn governance_set_code(
	ctx: &mut ExerciseCtx,
	wasm_path: &Path,
	timeout_secs: u64,
) -> Result<String> {
	let (spec_before, _) = ctx.client.get_runtime_version().await?;

	let wasm = std::fs::read(wasm_path).map_err(|e| {
		QuantusError::Generic(format!("failed to read WASM {}: {e}", wasm_path.display()))
	})?;
	crate::log_status!(
		"⬆️  Upgrade phase: proposing set_code with {} ({} bytes), current spec {}",
		wasm_path.display(),
		wasm.len(),
		spec_before
	);

	let set_code = quantus_subxt::api::tx().system().set_code(wasm);
	let encoded = set_code
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode set_code: {e:?}")))?;
	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let call_len = encoded.len() as u32;
	crate::cli::common::submit_preimage(&ctx.client, &ctx.alice, encoded, ctx.wait_mode()).await?;

	let latest = ctx.client.get_latest_block().await?;
	let count_addr = quantus_subxt::api::storage().tech_referenda().referendum_count();
	let index = ctx.client.client().storage().at(latest).fetch(&count_addr).await?.unwrap_or(0);

	let submit_call =
		crate::cli::exercise::scenarios::governance::build_submit_call(preimage_hash, call_len);
	let alice = ctx.alice.clone();
	submit_ok(ctx, &alice, submit_call).await?;
	crate::log_status!("⬆️  Referendum #{index} submitted");

	let deposit_call = quantus_subxt::api::tx().tech_referenda().place_decision_deposit(index);
	submit_ok(ctx, &alice, deposit_call).await?;

	for voter in [ctx.alice.clone(), ctx.bob.clone(), ctx.charlie.clone()] {
		crate::cli::tech_collective::vote_on_referendum(
			&ctx.client,
			&voter,
			index,
			true,
			ctx.wait_mode(),
		)
		.await?;
	}
	crate::log_status!("⬆️  Decision deposit placed and 3 aye votes cast; waiting for enactment…");

	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
	loop {
		tokio::time::sleep(std::time::Duration::from_secs(6)).await;
		let (spec_now, _) = ctx.client.get_runtime_version().await?;
		if spec_now > spec_before {
			let refund_decision =
				quantus_subxt::api::tx().tech_referenda().refund_decision_deposit(index);
			let refund_submission =
				quantus_subxt::api::tx().tech_referenda().refund_submission_deposit(index);
			let refund_result_a = submit_ok(ctx, &alice, refund_decision).await;
			let refund_result_b = submit_ok(ctx, &alice, refund_submission).await;
			let refunds = match (refund_result_a, refund_result_b) {
				(Ok(_), Ok(_)) => "deposits refunded",
				_ => "deposit refund not yet available (referendum bookkeeping pending)",
			};
			return Ok(format!(
				"runtime upgraded via referendum #{index}: spec {spec_before} → {spec_now}; {refunds}"
			));
		}
		if std::time::Instant::now() > deadline {
			let info_addr =
				quantus_subxt::api::storage().tech_referenda().referendum_info_for(index);
			let latest = ctx.client.get_latest_block().await?;
			let info = ctx.client.client().storage().at(latest).fetch(&info_addr).await?;
			return Err(QuantusError::Generic(format!(
				"spec version still {spec_before} after {timeout_secs}s; referendum #{index} \
				 state: {info:?}. Is the node built with the fast-governance feature and the \
				 WASM spec_version higher than {spec_before}?"
			)));
		}
	}
}
