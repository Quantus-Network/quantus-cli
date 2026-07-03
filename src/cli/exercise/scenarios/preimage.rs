//! Preimage scenarios: note a preimage and verify its on-chain status, plus a
//! canary asserting `request_preimage` stays Root-gated.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{submit_expect_failure, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use sp_runtime::traits::{BlakeTwo256, Hash};
use subxt::tx::Payload;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "note_and_verify", note_and_verify(ctx));
	exercise_step!(report, phase, "request_requires_root", request_requires_root(ctx));
	Ok(())
}

/// Encode a unique-per-run remark call to use as preimage content.
fn unique_remark_call_data(ctx: &mut ExerciseCtx) -> Result<Vec<u8>> {
	let marker: [u8; 24] = rand::Rng::random(&mut ctx.rng);
	let remark = quantus_subxt::api::tx().system().remark(marker.to_vec());
	remark
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode remark call: {e:?}")))
}

async fn note_and_verify(ctx: &mut ExerciseCtx) -> Result<String> {
	let encoded = unique_remark_call_data(ctx)?;
	let expected_hash: sp_core::H256 = BlakeTwo256::hash(&encoded);

	let keypair = ctx.eph[3].clone();
	crate::cli::common::submit_preimage(&ctx.client, &keypair, encoded, ctx.wait_mode()).await?;

	let status_addr = quantus_subxt::api::storage().preimage().request_status_for(expected_hash);
	let latest = ctx.client.get_latest_block().await?;
	let status = ctx.client.client().storage().at(latest).fetch(&status_addr).await?;
	match status {
		Some(_) => Ok(format!("preimage {expected_hash:?} noted and visible in RequestStatusFor")),
		None => Err(QuantusError::Generic(format!(
			"preimage {expected_hash:?} not found in storage after note_preimage"
		))),
	}
}

async fn request_requires_root(ctx: &mut ExerciseCtx) -> Result<String> {
	// Preimage::request_preimage has ManagerOrigin = Root; a signed call must be
	// rejected. If a runtime upgrade ever loosens this, the suite fails here.
	let encoded = unique_remark_call_data(ctx)?;
	let hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let call = quantus_subxt::api::tx().preimage().request_preimage(hash);
	let keypair = ctx.eph[3].clone();
	submit_expect_failure(ctx, &keypair, call, &["BadOrigin"]).await
}
