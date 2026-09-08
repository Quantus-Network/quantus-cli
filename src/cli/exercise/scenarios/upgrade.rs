//! Runtime upgrade via tech-referenda (requires fast-governance node).
//!
//! Both modes drive the production upgrade pipeline: a referendum approves a 34-byte
//! `system.authorize_upgrade` hash and the full code is then supplied by anyone via
//! `system.apply_authorized_upgrade`. `system.set_code` is not used — the code blob
//! exceeds `TechReferenda::MaxProposalSize`, so it could never be a real proposal.
//!
//! Two modes:
//! - `Authorize(wasm)`: a real upgrade via `system.authorize_upgrade`; requires a candidate WASM
//!   with a higher `spec_version` and verifies the spec bump.
//! - `SelfNoop`: fetches the current on-chain `:code` and re-installs it.
//!   `frame_system::can_set_code` would reject the identical blob (`SpecVersionNeedsToIncrease`),
//!   so `authorize_upgrade_without_checks` is used instead; the version-comparison logic itself is
//!   trivial and not worth building a bumped WASM for. This proves the whole upgrade pipeline —
//!   referendum with Root origin, enactment, authorization, code storage write — and success is
//!   detected via the `System::CodeUpdated` event since the spec version stays the same.

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
use std::path::PathBuf;
use subxt::tx::Payload;

pub enum UpgradeMode {
	/// Real upgrade: `system.authorize_upgrade` for the candidate WASM's hash,
	/// then `apply_authorized_upgrade` with the blob itself.
	Authorize(PathBuf),
	/// No-op self-upgrade: re-install the current on-chain code via
	/// `authorize_upgrade_without_checks` + `apply_authorized_upgrade`.
	SelfNoop,
}

pub async fn run(
	ctx: &mut ExerciseCtx,
	report: &mut Report,
	phase: &str,
	mode: UpgradeMode,
	timeout_secs: u64,
) -> Result<()> {
	match mode {
		UpgradeMode::Authorize(wasm_path) => {
			exercise_step!(
				report,
				phase,
				"governance_authorize_upgrade",
				governance_authorize_upgrade(ctx, &wasm_path, timeout_secs)
			);
		},
		UpgradeMode::SelfNoop => {
			exercise_step!(
				report,
				phase,
				"governance_self_upgrade",
				governance_self_upgrade(ctx, timeout_secs)
			);
		},
	}
	Ok(())
}

/// Note `encoded_call` as a preimage and drive it through a Root-origin
/// tech-referendum: submit, place the decision deposit, and vote aye with the
/// three dev genesis accounts. Returns the referendum index.
async fn submit_root_referendum(ctx: &mut ExerciseCtx, encoded_call: Vec<u8>) -> Result<u32> {
	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(&encoded_call);
	let call_len = encoded_call.len() as u32;
	crate::cli::common::submit_preimage(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(ctx.alice.clone()),
		encoded_call,
		ctx.wait_mode(),
	)
	.await?;

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

	// Cast all three ayes in parallel. Under `fast-governance` the decision
	// window is only 2 blocks; waiting for inclusion between sequential votes
	// lets the poll close mid-loop (`TechCollective::NotPolling`).
	cast_collective_ayes(ctx, index).await?;
	crate::log_status!("⬆️  Decision deposit placed and 3 aye votes cast; waiting for enactment…");
	Ok(index)
}

/// Vote aye from alice/bob/charlie concurrently. A `NotPolling` error is
/// tolerated when the referendum has already been approved (confirm period
/// elapsed between the parallel submissions).
async fn cast_collective_ayes(ctx: &ExerciseCtx, index: u32) -> Result<()> {
	let client = &ctx.client;
	let alice = ctx.alice.clone();
	let bob = ctx.bob.clone();
	let charlie = ctx.charlie.clone();
	let mode = ctx.wait_mode();

	let alice = crate::wallet::WalletSigner::Hot(alice);
	let bob = crate::wallet::WalletSigner::Hot(bob);
	let charlie = crate::wallet::WalletSigner::Hot(charlie);
	let (r_a, r_b, r_c) = tokio::join!(
		crate::cli::tech_collective::vote_on_referendum(client, &alice, index, true, mode),
		crate::cli::tech_collective::vote_on_referendum(client, &bob, index, true, mode),
		crate::cli::tech_collective::vote_on_referendum(client, &charlie, index, true, mode),
	);

	let mut failures = Vec::new();
	for (who, result) in [("alice", r_a), ("bob", r_b), ("charlie", r_c)] {
		if let Err(e) = result {
			failures.push((who, e));
		}
	}
	if failures.is_empty() {
		return Ok(());
	}

	if referendum_is_approved(ctx, index).await? {
		crate::log_status!(
			"⬆️  Referendum #{index} already approved; ignoring {} vote(s) that raced the close \
			 ({})",
			failures.len(),
			failures
				.iter()
				.map(|(who, e)| format!("{who}: {e}"))
				.collect::<Vec<_>>()
				.join("; ")
		);
		return Ok(());
	}

	let detail = failures
		.into_iter()
		.map(|(who, e)| format!("{who}: {e}"))
		.collect::<Vec<_>>()
		.join("; ");
	Err(QuantusError::Generic(format!(
		"collective aye votes failed on referendum #{index} (and it is not yet approved): {detail}"
	)))
}

async fn referendum_is_approved(ctx: &ExerciseCtx, index: u32) -> Result<bool> {
	use crate::cli::tech_referenda::{fetch_referendum, ReferendumSnapshot};
	let latest = ctx.client.get_latest_block().await?;
	Ok(matches!(
		fetch_referendum(&ctx.client, index, latest).await?,
		Some(ReferendumSnapshot::Approved(..))
	))
}

/// Best-effort refund of the referendum's submission and decision deposits.
async fn refund_deposits(ctx: &mut ExerciseCtx, index: u32) -> &'static str {
	let alice = ctx.alice.clone();
	let refund_decision = quantus_subxt::api::tx().tech_referenda().refund_decision_deposit(index);
	let refund_submission =
		quantus_subxt::api::tx().tech_referenda().refund_submission_deposit(index);
	let refund_result_a = submit_ok(ctx, &alice, refund_decision).await;
	let refund_result_b = submit_ok(ctx, &alice, refund_submission).await;
	match (refund_result_a, refund_result_b) {
		(Ok(_), Ok(_)) => "deposits refunded",
		_ => "deposit refund not yet available (referendum bookkeeping pending)",
	}
}

async fn referendum_state(ctx: &ExerciseCtx, index: u32) -> Result<String> {
	let latest = ctx.client.get_latest_block().await?;
	let info = crate::cli::tech_referenda::fetch_referendum(&ctx.client, index, latest).await?;
	Ok(format!("{info:?}"))
}

async fn governance_authorize_upgrade(
	ctx: &mut ExerciseCtx,
	wasm_path: &std::path::Path,
	timeout_secs: u64,
) -> Result<String> {
	let (spec_before, _) = ctx.client.get_runtime_version().await?;

	let wasm = std::fs::read(wasm_path).map_err(|e| {
		QuantusError::Generic(format!("failed to read WASM {}: {e}", wasm_path.display()))
	})?;
	let code_hash: sp_core::H256 = BlakeTwo256::hash(&wasm);
	crate::log_status!(
		"⬆️  Upgrade phase: authorizing {} ({} bytes, hash {code_hash:?}), current spec {}",
		wasm_path.display(),
		wasm.len(),
		spec_before
	);

	let authorize = quantus_subxt::api::tx().system().authorize_upgrade(code_hash);
	let encoded = authorize
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode authorize_upgrade: {e:?}")))?;
	let index = submit_root_referendum(ctx, encoded).await?;

	let authorized_addr = quantus_subxt::api::storage().system().authorized_upgrade();
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
	loop {
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;
		let latest = ctx.client.get_latest_block().await?;
		if let Some(authorized) =
			ctx.client.client().storage().at(latest).fetch(&authorized_addr).await?
		{
			if authorized.code_hash != code_hash {
				return Err(QuantusError::Generic(format!(
					"unexpected authorized upgrade hash: {:?} (expected {code_hash:?})",
					authorized.code_hash
				)));
			}
			break;
		}
		if std::time::Instant::now() > deadline {
			let info = referendum_state(ctx, index).await?;
			return Err(QuantusError::Generic(format!(
				"upgrade not authorized within {timeout_secs}s; referendum #{index} state: \
				 {info}. Is the node built with the fast-governance feature?"
			)));
		}
	}
	crate::log_status!("⬆️  Upgrade authorized on-chain; applying the code blob…");

	let apply = quantus_subxt::api::tx().system().apply_authorized_upgrade(wasm);
	let alice = ctx.alice.clone();
	submit_ok(ctx, &alice, apply).await?;

	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
	loop {
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;
		let (spec_now, _) = ctx.client.get_runtime_version().await?;
		if spec_now > spec_before {
			let refunds = refund_deposits(ctx, index).await;
			return Ok(format!(
				"runtime upgraded via referendum #{index} (authorize_upgrade + \
				 apply_authorized_upgrade): spec {spec_before} → {spec_now}; {refunds}"
			));
		}
		if std::time::Instant::now() > deadline {
			return Err(QuantusError::Generic(format!(
				"apply_authorized_upgrade was included but the spec version is still \
				 {spec_before} after {timeout_secs}s; is the WASM spec_version higher?"
			)));
		}
	}
}

/// Re-install the current on-chain runtime: a Root referendum authorizes the
/// code hash (`authorize_upgrade_without_checks`), then the full code is
/// supplied with `apply_authorized_upgrade`.
async fn governance_self_upgrade(ctx: &mut ExerciseCtx, timeout_secs: u64) -> Result<String> {
	let (spec, _) = ctx.client.get_runtime_version().await?;

	let latest = ctx.client.get_latest_block().await?;
	let code = ctx
		.client
		.client()
		.storage()
		.at(latest)
		.fetch_raw(b":code".to_vec())
		.await?
		.ok_or_else(|| QuantusError::Generic(":code storage entry not found".to_string()))?;
	let code_hash: sp_core::H256 = BlakeTwo256::hash(&code);
	crate::log_status!(
		"⬆️  Self-upgrade phase: re-installing the current runtime ({} bytes, spec {}, hash \
		 {code_hash:?})",
		code.len(),
		spec
	);

	let authorize = quantus_subxt::api::tx().system().authorize_upgrade_without_checks(code_hash);
	let encoded = authorize.encode_call_data(&ctx.client.client().metadata()).map_err(|e| {
		QuantusError::Generic(format!("failed to encode authorize_upgrade_without_checks: {e:?}"))
	})?;
	let index = submit_root_referendum(ctx, encoded).await?;

	// Wait for enactment: the authorization shows up in System::AuthorizedUpgrade.
	let authorized_addr = quantus_subxt::api::storage().system().authorized_upgrade();
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
	loop {
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;
		let latest = ctx.client.get_latest_block().await?;
		if let Some(authorized) =
			ctx.client.client().storage().at(latest).fetch(&authorized_addr).await?
		{
			if authorized.code_hash != code_hash {
				return Err(QuantusError::Generic(format!(
					"unexpected authorized upgrade hash: {:?} (expected {code_hash:?})",
					authorized.code_hash
				)));
			}
			break;
		}
		if std::time::Instant::now() > deadline {
			let info = referendum_state(ctx, index).await?;
			return Err(QuantusError::Generic(format!(
				"upgrade not authorized within {timeout_secs}s; referendum #{index} state: \
				 {info}. Is the node built with the fast-governance feature?"
			)));
		}
	}
	crate::log_status!("⬆️  Upgrade authorized on-chain; applying the code blob…");

	// The spec version will not change, so the code write is detected via the
	// System::CodeUpdated event; start watching from before apply is submitted.
	let mut last_seen = ctx.client.get_latest_block().await?;
	let apply = quantus_subxt::api::tx().system().apply_authorized_upgrade(code);
	let alice = ctx.alice.clone();
	submit_ok(ctx, &alice, apply).await?;

	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
	loop {
		if let Some(block_hash) = find_code_updated_since(ctx, &mut last_seen).await? {
			let (spec_after, _) = ctx.client.get_runtime_version().await?;
			if spec_after != spec {
				return Err(QuantusError::Generic(format!(
					"no-op self-upgrade unexpectedly changed the spec version: {spec} → {spec_after}"
				)));
			}
			let refunds = refund_deposits(ctx, index).await;
			return Ok(format!(
				"current runtime (spec {spec}) re-installed via referendum #{index} \
				 (authorize_upgrade_without_checks + apply_authorized_upgrade); \
				 System::CodeUpdated observed in block {block_hash:?}; {refunds}"
			));
		}
		if std::time::Instant::now() > deadline {
			return Err(QuantusError::Generic(format!(
				"apply_authorized_upgrade was included but no System::CodeUpdated event was \
				 observed within {timeout_secs}s"
			)));
		}
		tokio::time::sleep(std::time::Duration::from_secs(3)).await;
	}
}

/// Scan every block from (but excluding) `last_seen` up to the current best
/// block for a `System::CodeUpdated` event, walking parent hashes so no block
/// is skipped between polls. Advances `last_seen` to the scanned tip.
async fn find_code_updated_since(
	ctx: &ExerciseCtx,
	last_seen: &mut subxt::utils::H256,
) -> Result<Option<subxt::utils::H256>> {
	let tip = ctx.client.get_latest_block().await?;
	if tip == *last_seen {
		return Ok(None);
	}

	// Newest-first walk back to last_seen. The cap guards against reorgs on the
	// PoW chain where last_seen may no longer be an ancestor of the new tip.
	let mut chain = Vec::new();
	let mut cursor = tip;
	while cursor != *last_seen && chain.len() < 64 {
		chain.push(cursor);
		cursor = ctx.client.client().blocks().at(cursor).await?.header().parent_hash;
	}

	for block_hash in chain.into_iter().rev() {
		let at_block = ctx.client.at_block(block_hash).await?;
		let events = at_block.client().blocks().at(block_hash).await?.events().await?;
		if events
			.find_first::<quantus_subxt::api::system::events::CodeUpdated>()
			.map_err(|e| QuantusError::Generic(format!("failed to decode events: {e:?}")))?
			.is_some()
		{
			*last_seen = tip;
			return Ok(Some(block_hash));
		}
	}
	*last_seen = tip;
	Ok(None)
}
