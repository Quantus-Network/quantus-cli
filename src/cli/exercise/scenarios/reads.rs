//! Read-only sanity checks: runtime version, metadata, storage, blocks,
//! events, treasury and high-security status. These verify that all decode
//! paths still work — especially valuable after a runtime upgrade.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{report::Report, runner::ExerciseCtx},
	error::{QuantusError, Result},
	exercise_step,
};

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	// In the post-upgrade re-run the chain is on the candidate runtime, whose
	// spec version is by construction *newer* than anything pinned in
	// COMPATIBLE_RUNTIMES (the upgrade phase requires a spec bump). Requiring
	// table membership there would fail every successful upgrade run.
	let post_upgrade = phase.starts_with("post-upgrade:");
	exercise_step!(report, phase, "runtime_version", runtime_version(ctx, post_upgrade));
	exercise_step!(report, phase, "metadata_pallets", metadata_pallets(ctx));
	exercise_step!(report, phase, "chain_properties", chain_properties(ctx));
	exercise_step!(report, phase, "latest_block_and_events", latest_block_and_events(ctx));
	exercise_step!(report, phase, "treasury_info", treasury_info(ctx));
	exercise_step!(report, phase, "high_security_status", high_security_status(ctx));
	exercise_step!(report, phase, "scheduler_agenda", scheduler_agenda(ctx));
	exercise_step!(report, phase, "account_balances", account_balances(ctx));
	Ok(())
}

async fn runtime_version(ctx: &ExerciseCtx, post_upgrade: bool) -> Result<String> {
	let (spec, tx) = ctx.client.get_runtime_version().await?;
	let compatible = crate::config::is_runtime_compatible(spec, tx);
	if compatible {
		return Ok(format!("spec {spec} / tx {tx}, compatible with CLI bindings"));
	}
	if post_upgrade {
		// The candidate runtime is expected to be absent from the table; the
		// rest of the re-run verifies the checked-in bindings still work
		// against it. A transaction_version change, however, invalidates the
		// signing payload and must be flagged.
		if crate::config::COMPATIBLE_RUNTIMES.iter().any(|r| r.transaction_version == tx) {
			return Ok(format!(
				"spec {spec} / tx {tx}: candidate runtime not in the compatibility table \
				 (expected after an upgrade); tx version unchanged"
			));
		}
		return Err(QuantusError::Generic(format!(
			"candidate runtime changed transaction_version to {tx}, which is not in the \
			 CLI compatibility table; signed extrinsics from this CLI are invalid against it"
		)));
	}
	Err(QuantusError::Generic(format!(
		"runtime spec {spec} / tx {tx} is not in the CLI compatibility table"
	)))
}

async fn metadata_pallets(ctx: &ExerciseCtx) -> Result<String> {
	let metadata = ctx.client.client().metadata();
	let pallets: Vec<String> = metadata.pallets().map(|p| p.name().to_string()).collect();
	if pallets.is_empty() {
		return Err(QuantusError::Generic("metadata contains no pallets".to_string()));
	}
	for required in ["System", "Balances", "ReversibleTransfers", "Multisig", "TechReferenda"] {
		if !pallets.iter().any(|p| p == required) {
			return Err(QuantusError::Generic(format!("pallet {required} missing from metadata")));
		}
	}
	Ok(format!("{} pallets exposed: {}", pallets.len(), pallets.join(", ")))
}

async fn chain_properties(ctx: &ExerciseCtx) -> Result<String> {
	let (symbol, decimals) = crate::cli::send::get_chain_properties(&ctx.client).await?;
	Ok(format!("token {symbol} with {decimals} decimals"))
}

async fn latest_block_and_events(ctx: &ExerciseCtx) -> Result<String> {
	let latest_hash = ctx.client.get_latest_block().await?;
	let block = ctx.client.client().blocks().at(latest_hash).await?;
	let number = block.number();
	let extrinsics = block.extrinsics().await?;
	let events = ctx.client.client().events().at(latest_hash).await?;
	let mut decoded = 0usize;
	for event in events.iter() {
		event?;
		decoded += 1;
	}
	Ok(format!("block #{number}: {} extrinsics, {decoded} events decoded", extrinsics.len()))
}

async fn treasury_info(ctx: &ExerciseCtx) -> Result<String> {
	let latest = ctx.client.get_latest_block().await?;
	let storage_at = ctx.client.client().storage().at(latest);

	let account_addr = quantus_subxt::api::storage().treasury_pallet().treasury_account();
	let account = storage_at
		.fetch(&account_addr)
		.await?
		.ok_or_else(|| QuantusError::Generic("treasury account not set".to_string()))?;

	let portion_addr = quantus_subxt::api::storage().treasury_pallet().treasury_portion();
	let portion = storage_at.fetch(&portion_addr).await?.map(|p| p.0).unwrap_or(0);

	let balance_addr = quantus_subxt::api::storage().system().account(account);
	let info = storage_at.fetch_or_default(&balance_addr).await?;

	Ok(format!(
		"portion {:.2}%, free balance {} raw units",
		portion as f64 / 10_000.0,
		info.data.free
	))
}

async fn high_security_status(ctx: &ExerciseCtx) -> Result<String> {
	let alice = crate::cli::exercise::runner::account_id_of(&ctx.alice);
	let addr = quantus_subxt::api::storage()
		.reversible_transfers()
		.high_security_accounts(alice);
	let latest = ctx.client.get_latest_block().await?;
	let value = ctx.client.client().storage().at(latest).fetch(&addr).await?;
	Ok(match value {
		Some(_) => "alice has high-security enabled".to_string(),
		None => "alice has high-security disabled (expected default)".to_string(),
	})
}

async fn scheduler_agenda(ctx: &ExerciseCtx) -> Result<String> {
	// The scheduler pallet has no dispatchables, but its storage must decode.
	let timestamp = crate::cli::scheduler::get_last_processed_timestamp(&ctx.client).await?;
	Ok(format!("scheduler last processed timestamp: {timestamp:?}"))
}

async fn account_balances(ctx: &ExerciseCtx) -> Result<String> {
	let alice_ss58 = ctx.alice.to_account_id_ss58check();
	let balance = ctx.free_balance(&alice_ss58).await?;
	if balance == 0 {
		return Err(QuantusError::Generic(
			"alice has zero balance; is this a dev chain with the standard genesis?".to_string(),
		));
	}
	Ok(format!("alice free balance: {balance} raw units"))
}
