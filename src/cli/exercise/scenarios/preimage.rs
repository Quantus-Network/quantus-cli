//! Preimage scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{submit_expect_failure, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use sp_runtime::traits::{BlakeTwo256, Hash};
use subxt::tx::Payload;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "note_and_verify", note_and_verify(ctx));
	exercise_step!(report, phase, "unnote_preimage", unnote_preimage(ctx));
	exercise_step!(report, phase, "ensure_updated", ensure_updated(ctx));
	exercise_step!(report, phase, "request_requires_root", request_requires_root(ctx));
	exercise_step!(report, phase, "unrequest_requires_root", unrequest_requires_root(ctx));
	Ok(())
}

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

async fn preimage_status_exists(ctx: &ExerciseCtx, hash: sp_core::H256) -> Result<bool> {
	let status_addr = quantus_subxt::api::storage().preimage().request_status_for(hash);
	let latest = ctx.client.get_latest_block().await?;
	Ok(ctx.client.client().storage().at(latest).fetch(&status_addr).await?.is_some())
}

/// Note a preimage, then clear it with `unnote_preimage` and verify the
/// status entry is gone (deposit returned to the noter).
async fn unnote_preimage(ctx: &mut ExerciseCtx) -> Result<String> {
	let encoded = unique_remark_call_data(ctx)?;
	let hash: sp_core::H256 = BlakeTwo256::hash(&encoded);

	let keypair = ctx.eph[3].clone();
	crate::cli::common::submit_preimage(&ctx.client, &keypair, encoded, ctx.wait_mode()).await?;
	if !preimage_status_exists(ctx, hash).await? {
		return Err(QuantusError::Generic(format!(
			"preimage {hash:?} missing from storage before unnote"
		)));
	}

	let call = quantus_subxt::api::tx().preimage().unnote_preimage(hash);
	submit_ok(ctx, &keypair, call).await?;

	if preimage_status_exists(ctx, hash).await? {
		return Err(QuantusError::Generic(format!(
			"preimage {hash:?} still in RequestStatusFor after unnote_preimage"
		)));
	}
	Ok(format!("preimage {hash:?} noted then unnoted, storage entry cleared"))
}

/// `ensure_updated` is permissionless bulk maintenance; on an already-modern
/// preimage it performs no migration but must still dispatch successfully.
async fn ensure_updated(ctx: &mut ExerciseCtx) -> Result<String> {
	let encoded = unique_remark_call_data(ctx)?;
	let hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let keypair = ctx.eph[3].clone();
	crate::cli::common::submit_preimage(&ctx.client, &keypair, encoded, ctx.wait_mode()).await?;

	let call = quantus_subxt::api::tx().preimage().ensure_updated(vec![hash]);
	submit_ok(ctx, &keypair, call).await?;

	// Clean up the noted preimage so reruns start fresh.
	let unnote = quantus_subxt::api::tx().preimage().unnote_preimage(hash);
	submit_ok(ctx, &keypair, unnote).await?;
	Ok(format!("Preimage::ensure_updated dispatched for already-modern {hash:?}"))
}

async fn request_requires_root(ctx: &mut ExerciseCtx) -> Result<String> {
	let encoded = unique_remark_call_data(ctx)?;
	let hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let call = quantus_subxt::api::tx().preimage().request_preimage(hash);
	let keypair = ctx.eph[3].clone();
	submit_expect_failure(ctx, &keypair, call, &["BadOrigin"]).await
}

/// `unrequest_preimage` is manager-origin only, like `request_preimage`.
async fn unrequest_requires_root(ctx: &mut ExerciseCtx) -> Result<String> {
	let encoded = unique_remark_call_data(ctx)?;
	let hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let call = quantus_subxt::api::tx().preimage().unrequest_preimage(hash);
	let keypair = ctx.eph[3].clone();
	submit_expect_failure(ctx, &keypair, call, &["BadOrigin"]).await
}
