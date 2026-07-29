//! Wormhole smoke tests (CPU-heavy; use `--skip wormhole` on debug builds).
//!
//! Covers:
//! - private-batch multiround
//! - public-batch multiround
//! - collect-rewards via known deposits (no Subsquid)
//! - spent-nullifier filtering / retry after collect

use crate::{
	chain::quantus_subxt::api::wormhole as wormhole_api,
	cli::{
		address_format::bytes_to_quantus_ss58,
		exercise::{report::Report, runner::ExerciseCtx},
		send::transfer,
		wormhole::{decode_full_leaf_data, get_zk_merkle_proof},
	},
	collect_rewards_lib::{
		collect_rewards_from_known, CollectKnownTransfersConfig, KnownTransfer, NoOpProgress,
		WormholeCredential,
	},
	error::{QuantusError, Result},
	exercise_step, log_verbose, wormhole_lib,
};
use rand::RngCore;
use std::{collections::HashSet, time::Duration};
use tokio::time::sleep;

/// How many recent blocks to scan for a deposit's `NativeTransferred` event.
const INCLUSION_SCAN_BLOCKS: u32 = 60;
const INCLUSION_POLL_INTERVAL_MS: u64 = 500;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "multiround", multiround(ctx));
	exercise_step!(report, phase, "multiround_public", multiround_public(ctx));
	exercise_step!(report, phase, "collect_rewards", collect_rewards_happy_path(ctx));
	exercise_step!(
		report,
		phase,
		"collect_rewards_spent_filter",
		collect_rewards_spent_filter(ctx)
	);
	Ok(())
}

async fn multiround(ctx: &mut ExerciseCtx) -> Result<String> {
	let command = crate::cli::wormhole::WormholeCommands::Multiround {
		num_proofs: 5,
		rounds: 5,
		amount: 50.0,
		wallet: "crystal_alice".to_string(),
		password: Some(String::new()),
		password_file: None,
		keep_files: false,
		output_dir: "/tmp/wormhole_exercise".to_string(),
		dry_run: false,
		public: false,
	};
	crate::cli::wormhole::handle_wormhole_command(command, &ctx.node_url).await?;
	Ok("wormhole multiround (5 rounds, 5 proofs each) completed".to_string())
}

async fn multiround_public(ctx: &mut ExerciseCtx) -> Result<String> {
	let command = crate::cli::wormhole::WormholeCommands::Multiround {
		num_proofs: 2,
		rounds: 2,
		amount: 20.0,
		wallet: "crystal_alice".to_string(),
		password: Some(String::new()),
		password_file: None,
		keep_files: false,
		output_dir: "/tmp/wormhole_exercise_public".to_string(),
		dry_run: false,
		public: true,
	};
	crate::cli::wormhole::handle_wormhole_command(command, &ctx.node_url).await?;
	Ok("wormhole public-batch multiround (2 rounds, 2 proofs each) completed".to_string())
}

/// Fund two deposits, collect both, assert withdrawal succeeded.
async fn collect_rewards_happy_path(ctx: &mut ExerciseCtx) -> Result<String> {
	let secret = random_secret(ctx);
	let mut seen_leaves = HashSet::new();
	let deposits =
		fund_wormhole_deposits(ctx, &secret, 2, ctx.unit, &mut seen_leaves).await?;
	let dest = ctx.eph[0].to_account_id_ss58check();
	let before = ctx.free_balance(&dest).await?;

	let result = run_collect_known(ctx, &secret, &dest, deposits.clone(), None).await?;
	if result.total_withdrawn == 0 || result.batches.is_empty() {
		return Err(QuantusError::Generic(format!(
			"collect-rewards withdrew nothing (transfers_processed={}, batches={})",
			result.transfers_processed,
			result.batches.len()
		)));
	}

	let after = ctx.free_balance(&dest).await?;
	if after <= before {
		return Err(QuantusError::Generic(format!(
			"destination balance did not increase after collect ({before} -> {after})"
		)));
	}

	Ok(format!(
		"collected {} planck from {} deposits into {} batch(es)",
		result.total_withdrawn,
		deposits.len(),
		result.batches.len()
	))
}

/// Collect, then retry with spent nullifiers still in the candidate list.
///
/// 1. Fund 2 deposits and withdraw them.
/// 2. Fund 2 more to the same wormhole address.
/// 3. Dry-run with all 4 known transfers — spent ones must be filtered (2 remain).
/// 4. Collect the 2 fresh deposits.
/// 5. Collect all 4 again — nothing left.
async fn collect_rewards_spent_filter(ctx: &mut ExerciseCtx) -> Result<String> {
	let secret = random_secret(ctx);
	let dest = ctx.eph[1].to_account_id_ss58check();
	let mut seen_leaves = HashSet::new();

	let initial =
		fund_wormhole_deposits(ctx, &secret, 2, ctx.unit, &mut seen_leaves).await?;
	let first = run_collect_known(ctx, &secret, &dest, initial.clone(), None)
		.await
		.map_err(|e| QuantusError::Generic(format!("initial collect failed: {e}")))?;
	if first.total_withdrawn == 0 || first.transfers_processed != 2 {
		return Err(QuantusError::Generic(format!(
			"initial collect expected 2 transfers processed, got withdrawn={} transfers_processed={}",
			first.total_withdrawn, first.transfers_processed
		)));
	}

	// Prove UsedNullifiers is observable via the same key encoding collect-rewards uses.
	assert_nullifiers_spent(&ctx.client, &secret, &initial).await?;

	let more = fund_wormhole_deposits(ctx, &secret, 2, ctx.unit, &mut seen_leaves).await?;
	let mut all = initial;
	all.extend(more.clone());

	// Dry-run exercises on-chain UsedNullifiers filtering without submitting.
	let filtered = run_collect_known(ctx, &secret, &dest, all.clone(), Some(true))
		.await
		.map_err(|e| QuantusError::Generic(format!("mixed spent/unspent dry-run failed: {e}")))?;
	if filtered.transfers_processed != 2 {
		return Err(QuantusError::Generic(format!(
			"dry-run over mixed spent/unspent list expected 2 remaining transfers, got {}",
			filtered.transfers_processed
		)));
	}

	let second = run_collect_known(ctx, &secret, &dest, more, None)
		.await
		.map_err(|e| QuantusError::Generic(format!("fresh-deposit collect failed: {e}")))?;
	if second.total_withdrawn == 0 || second.transfers_processed != 2 {
		return Err(QuantusError::Generic(format!(
			"fresh-deposit collect expected 2 transfers processed, got \
			 withdrawn={} transfers_processed={}",
			second.total_withdrawn, second.transfers_processed
		)));
	}

	let third = run_collect_known(ctx, &secret, &dest, all, None)
		.await
		.map_err(|e| QuantusError::Generic(format!("final spent retry failed: {e}")))?;
	if third.total_withdrawn != 0 || third.transfers_processed != 0 || !third.batches.is_empty() {
		return Err(QuantusError::Generic(format!(
			"expected empty collect after all nullifiers spent, got withdrawn={} \
			 transfers_processed={} batches={}",
			third.total_withdrawn,
			third.transfers_processed,
			third.batches.len()
		)));
	}

	Ok(format!(
		"spent-nullifier filter ok: initial withdrew {}, dry-run kept 2 unspent, \
		 fresh collect withdrew {}, final retry collected nothing",
		first.total_withdrawn, second.total_withdrawn
	))
}

fn random_secret(ctx: &mut ExerciseCtx) -> [u8; 32] {
	let mut secret = [0u8; 32];
	ctx.rng.fill_bytes(&mut secret);
	secret
}

async fn run_collect_known(
	ctx: &ExerciseCtx,
	secret: &[u8; 32],
	destination: &str,
	transfers: Vec<KnownTransfer>,
	dry_run: Option<bool>,
) -> Result<crate::collect_rewards_lib::CollectRewardsResult> {
	let bins_dir = crate::bins::ensure_bins_dir()
		.map_err(|e| QuantusError::Generic(format!("Failed to resolve bins dir: {e}")))?
		.to_string_lossy()
		.into_owned();

	let config = CollectKnownTransfersConfig {
		credential: WormholeCredential::Secret { hex: hex::encode(secret) },
		destination_address: destination.to_string(),
		node_url: ctx.node_url.clone(),
		bins_dir,
		amount: None,
		dry_run: dry_run.unwrap_or(false),
		at_block: None,
	};

	collect_rewards_from_known(config, transfers, &NoOpProgress)
		.await
		.map_err(|e| QuantusError::Generic(e.message))
}

/// Deposit `count` transfers of `amount_each` to the wormhole address for `secret`.
///
/// `seen_leaves` is shared across calls so later deposits to the same address are not
/// confused with earlier `NativeTransferred` events still in the recent block window.
async fn fund_wormhole_deposits(
	ctx: &ExerciseCtx,
	secret: &[u8; 32],
	count: usize,
	amount_each: u128,
	seen_leaves: &mut HashSet<u64>,
) -> Result<Vec<KnownTransfer>> {
	let wh_addr = wormhole_lib::compute_wormhole_address(secret)
		.map_err(|e| QuantusError::Generic(e.message))?;
	let wh_ss58 = bytes_to_quantus_ss58(&wh_addr);

	let mut known = Vec::with_capacity(count);
	for _ in 0..count {
		transfer(&ctx.client, &ctx.alice, &wh_ss58, amount_each, None, ctx.wait_mode()).await?;

		let (block_hash, event) =
			wait_for_native_transferred(&ctx.client, &wh_addr, seen_leaves).await?;
		seen_leaves.insert(event.leaf_index);

		// Nullifier checks must use the leaf's transfer_count (what the circuit burns).
		// Prefer that over the event field so UsedNullifiers lookups stay consistent.
		let merkle = get_zk_merkle_proof(&ctx.client, event.leaf_index, block_hash).await?;
		let (_to, leaf_transfer_count, _asset_id, leaf_amount) =
			decode_full_leaf_data(&merkle.leaf_data)?;

		known.push(KnownTransfer {
			leaf_index: event.leaf_index,
			transfer_count: leaf_transfer_count,
			amount: leaf_amount,
		});
	}
	Ok(known)
}

/// Fail if spent deposits are not visible in on-chain `UsedNullifiers` (best block).
async fn assert_nullifiers_spent(
	client: &crate::chain::client::QuantusClient,
	secret: &[u8; 32],
	spent: &[KnownTransfer],
) -> Result<()> {
	use crate::chain::quantus_subxt;

	let best = client.get_latest_block().await?;
	let storage = client.client().storage().at(best);

	let mut missing = Vec::new();
	for t in spent {
		let nullifier = wormhole_lib::compute_nullifier(secret, t.transfer_count)
			.map_err(|e| QuantusError::Generic(e.message))?;
		let key = quantus_subxt::api::storage().wormhole().used_nullifiers(nullifier);
		let used = storage
			.fetch(&key)
			.await
			.map_err(|e| QuantusError::NetworkError(format!("UsedNullifiers fetch: {e}")))?;
		if !matches!(used, Some(true)) {
			missing.push(format!(
				"leaf={} tc={} nullifier=0x{} used={:?}",
				t.leaf_index,
				t.transfer_count,
				hex::encode(nullifier),
				used
			));
		}
	}

	if !missing.is_empty() {
		return Err(QuantusError::Generic(format!(
			"after successful collect, UsedNullifiers missing: {}",
			missing.join("; ")
		)));
	}

	Ok(())
}

/// Poll recent blocks until a new `NativeTransferred` to `wh_addr` appears.
/// Returns `(inclusion_block_hash, event)`.
async fn wait_for_native_transferred(
	client: &crate::chain::client::QuantusClient,
	wh_addr: &[u8; 32],
	seen_leaves: &HashSet<u64>,
) -> Result<(subxt::utils::H256, wormhole_api::events::NativeTransferred)> {
	use jsonrpsee::core::client::ClientT;
	use subxt::utils::H256;

	let start = std::time::Instant::now();
	let timeout = Duration::from_secs(60);

	loop {
		let best = client.get_latest_block().await?;
		let best_number = client
			.client()
			.blocks()
			.at(best)
			.await
			.map_err(|e| QuantusError::NetworkError(format!("blocks().at(best): {e:?}")))?
			.header()
			.number;
		// Always re-scan a trailing window (including the current tip). Advancing a
		// watermark past `best_number` can skip the inclusion block when the transfer
		// lands in that block after an earlier empty pass.
		let scan_from = best_number.saturating_sub(INCLUSION_SCAN_BLOCKS);

		for n in scan_from..=best_number {
			let hash: Option<H256> =
				client.rpc_client().request("chain_getBlockHash", [n]).await.map_err(|e| {
					QuantusError::NetworkError(format!("chain_getBlockHash({n}): {e:?}"))
				})?;
			let Some(block_hash) = hash else { continue };
			let events = match client.client().events().at(block_hash).await {
				Ok(e) => e,
				Err(e) => {
					log_verbose!(
						"wait_for_native_transferred: events().at(#{n} {block_hash:?}) failed: {e:?}"
					);
					continue;
				},
			};
			for ev in events.find::<wormhole_api::events::NativeTransferred>().flatten() {
				if &ev.to.0 == wh_addr && !seen_leaves.contains(&ev.leaf_index) {
					return Ok((block_hash, ev));
				}
			}
		}

		if start.elapsed() > timeout {
			return Err(QuantusError::Generic(format!(
				"Timed out waiting for NativeTransferred to 0x{} after {:.1}s",
				hex::encode(wh_addr),
				start.elapsed().as_secs_f64()
			)));
		}
		sleep(Duration::from_millis(INCLUSION_POLL_INTERVAL_MS)).await;
	}
}
