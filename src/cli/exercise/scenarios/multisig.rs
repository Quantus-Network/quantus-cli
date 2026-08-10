//! Multisig lifecycle.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use subxt::tx::Payload;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "lifecycle", lifecycle(ctx));
	exercise_step!(report, phase, "expired_proposal_cleanup", expired_proposal_cleanup(ctx));
	Ok(())
}

async fn lifecycle(ctx: &mut ExerciseCtx) -> Result<String> {
	let signer_a = ctx.eph[0].clone();
	let signer_b = ctx.eph[1].clone();
	let signer_c = ctx.eph[2].clone();
	let signers =
		vec![account_id_of(&signer_a)?, account_id_of(&signer_b)?, account_id_of(&signer_c)?];
	let threshold = 2u32;
	let nonce: u64 = rand::Rng::random(&mut ctx.rng);

	let create_call =
		quantus_subxt::api::tx()
			.multisig()
			.create_multisig(signers.clone(), threshold, nonce);
	submit_ok(ctx, &signer_a, create_call).await?;
	let multisig_ss58 =
		crate::cli::multisig::predict_multisig_address(signers.clone(), threshold, nonce);

	let multisig_id = crate::cli::common::resolve_to_subxt_account_id(&multisig_ss58)?;
	let info = crate::cli::multisig::get_multisig_info(&ctx.client, multisig_id.clone())
		.await?
		.ok_or_else(|| {
			QuantusError::Generic(format!("multisig {multisig_ss58} not found after creation"))
		})?;
	if info.threshold != threshold || info.signers.len() != 3 {
		return Err(QuantusError::Generic(format!(
			"multisig config mismatch: threshold {}, {} signers",
			info.threshold,
			info.signers.len()
		)));
	}

	crate::cli::send::transfer(
		&ctx.client,
		&signer_a,
		&multisig_ss58,
		20 * ctx.unit,
		None,
		ctx.wait_mode(),
	)
	.await?;

	let recipient = ctx.fresh_keypair()?;
	let recipient_ss58 = recipient.try_to_account_id_ss58check()?;
	let amount = 2 * ctx.unit;
	let inner = quantus_subxt::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&recipient)?),
		amount,
	);
	let call_data = inner
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode inner call: {e:?}")))?;

	let expiry = current_block(ctx).await? + 100;
	let propose_call = quantus_subxt::api::tx().multisig().propose(
		multisig_id.clone(),
		quantus_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
			call_data.clone(),
		),
		expiry,
	);
	submit_ok(ctx, &signer_a, propose_call).await?;
	let proposal_id = latest_proposal_id(ctx, &multisig_id).await?;

	let approve_call = quantus_subxt::api::tx().multisig().approve(
		multisig_id.clone(),
		proposal_id,
		quantus_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
			call_data.clone(),
		),
	);
	submit_ok(ctx, &signer_b, approve_call).await?;

	let execute_call =
		quantus_subxt::api::tx().multisig().execute(multisig_id.clone(), proposal_id);
	submit_ok(ctx, &signer_c, execute_call).await?;

	let recipient_balance = ctx.free_balance(&recipient_ss58).await?;
	if recipient_balance != amount {
		return Err(QuantusError::Generic(format!(
			"multisig payout mismatch: recipient has {recipient_balance}, expected {amount}"
		)));
	}

	let propose_again = quantus_subxt::api::tx().multisig().propose(
		multisig_id.clone(),
		quantus_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec(call_data),
		expiry,
	);
	submit_ok(ctx, &signer_a, propose_again).await?;
	let second_id = latest_proposal_id(ctx, &multisig_id).await?;
	let cancel_call = quantus_subxt::api::tx().multisig().cancel(multisig_id.clone(), second_id);
	submit_ok(ctx, &signer_a, cancel_call).await?;

	let remaining = crate::cli::multisig::list_proposals(&ctx.client, multisig_id).await?;
	if remaining.iter().any(|p| p.id == second_id) {
		return Err(QuantusError::Generic(format!(
			"cancelled proposal #{second_id} still present in storage"
		)));
	}

	Ok(format!(
		"2-of-3 multisig {multisig_ss58}: created, funded, proposal #{proposal_id} \
		 approved+executed (payout verified), proposal #{second_id} cancelled"
	))
}

/// Expired proposals must be removable by any signer (`remove_expired`) and
/// reclaimable in bulk by their proposer (`claim_deposits`).
async fn expired_proposal_cleanup(ctx: &mut ExerciseCtx) -> Result<String> {
	let signer_a = ctx.eph[0].clone();
	let signer_b = ctx.eph[1].clone();
	let signer_c = ctx.eph[2].clone();
	let signers =
		vec![account_id_of(&signer_a)?, account_id_of(&signer_b)?, account_id_of(&signer_c)?];
	let threshold = 2u32;
	let nonce: u64 = rand::Rng::random(&mut ctx.rng);

	let create_call =
		quantus_subxt::api::tx()
			.multisig()
			.create_multisig(signers.clone(), threshold, nonce);
	submit_ok(ctx, &signer_a, create_call).await?;
	let multisig_ss58 =
		crate::cli::multisig::predict_multisig_address(signers.clone(), threshold, nonce);
	let multisig_id = crate::cli::common::resolve_to_subxt_account_id(&multisig_ss58)?;

	// Two proposals with a near-immediate expiry; they are never approved.
	let inner = quantus_subxt::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&signer_a)?),
		ctx.unit,
	);
	let call_data = inner
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode inner call: {e:?}")))?;

	let expiry = current_block(ctx).await? + 3;
	for proposer in [&signer_a, &signer_b] {
		let propose_call = quantus_subxt::api::tx().multisig().propose(
			multisig_id.clone(),
			quantus_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
				call_data.clone(),
			),
			expiry,
		);
		submit_ok(ctx, proposer, propose_call).await?;
	}
	let proposals = crate::cli::multisig::list_proposals(&ctx.client, multisig_id.clone()).await?;
	if proposals.len() != 2 {
		return Err(QuantusError::Generic(format!(
			"expected 2 pending proposals before expiry, found {}",
			proposals.len()
		)));
	}
	let first_id = proposals.iter().map(|p| p.id).min().expect("checked non-empty");
	let second_id = proposals.iter().map(|p| p.id).max().expect("checked non-empty");

	// Wait until the chain is past the expiry block.
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
	while current_block(ctx).await? <= expiry {
		if std::time::Instant::now() > deadline {
			return Err(QuantusError::Generic(format!(
				"chain did not pass expiry block {expiry} within 120s"
			)));
		}
		tokio::time::sleep(std::time::Duration::from_secs(2)).await;
	}

	// Any signer (here signer_c, not the proposer) may sweep an expired proposal.
	let remove_call = quantus_subxt::api::tx()
		.multisig()
		.remove_expired(multisig_id.clone(), first_id);
	submit_ok(ctx, &signer_c, remove_call).await?;

	// The proposer reclaims deposits from all remaining expired proposals.
	let claim_call = quantus_subxt::api::tx().multisig().claim_deposits(multisig_id.clone());
	submit_ok(ctx, &signer_b, claim_call).await?;

	let remaining = crate::cli::multisig::list_proposals(&ctx.client, multisig_id).await?;
	if !remaining.is_empty() {
		return Err(QuantusError::Generic(format!(
			"{} expired proposal(s) still in storage after cleanup",
			remaining.len()
		)));
	}
	Ok(format!(
		"expired proposals cleaned up: #{first_id} via remove_expired (non-proposer signer), \
		 #{second_id} via claim_deposits (proposer), storage verified"
	))
}

async fn current_block(ctx: &ExerciseCtx) -> Result<u32> {
	let latest = ctx.client.get_latest_block().await?;
	Ok(ctx.client.client().blocks().at(latest).await?.number())
}

async fn latest_proposal_id(
	ctx: &ExerciseCtx,
	multisig_id: &crate::cli::common::SubxtAccountId32,
) -> Result<u32> {
	let proposals = crate::cli::multisig::list_proposals(&ctx.client, multisig_id.clone()).await?;
	proposals
		.iter()
		.map(|p| p.id)
		.max()
		.ok_or_else(|| QuantusError::Generic("no proposals found after propose".to_string()))
}
