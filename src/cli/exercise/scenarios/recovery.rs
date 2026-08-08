//! Recovery scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_expect_failure, ExerciseCtx},
	},
	error::Result,
	exercise_step,
};

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "config_reads", config_reads(ctx));
	exercise_step!(report, phase, "initiate_not_recoverable", initiate_not_recoverable(ctx));
	Ok(())
}

async fn config_reads(ctx: &mut ExerciseCtx) -> Result<String> {
	let alice = account_id_of(&ctx.alice)?;
	let latest = ctx.client.get_latest_block().await?;
	let storage_at = ctx.client.client().storage().at(latest);

	let recoverable = storage_at
		.fetch(&quantus_subxt::api::storage().recovery().recoverable(alice.clone()))
		.await?;
	let proxy = storage_at.fetch(&quantus_subxt::api::storage().recovery().proxy(alice)).await?;

	Ok(format!(
		"recovery storage decodes: alice recoverable={}, proxy={}",
		recoverable.is_some(),
		proxy.is_some()
	))
}

async fn initiate_not_recoverable(ctx: &mut ExerciseCtx) -> Result<String> {
	let lost = account_id_of(&ctx.bob)?;
	let call = quantus_subxt::api::tx()
		.recovery()
		.initiate_recovery(subxt::ext::subxt_core::utils::MultiAddress::Id(lost));
	let rescuer = ctx.eph[0].clone();
	submit_expect_failure(ctx, &rescuer, call, &["NotRecoverable"]).await
}
