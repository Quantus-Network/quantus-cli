//! Multisig lifecycle: create a 2-of-3, fund it, propose a transfer, approve,
//! execute, verify the recipient balance, then propose + cancel a second one.

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
	Ok(())
}

async fn lifecycle(ctx: &mut ExerciseCtx) -> Result<String> {
	let signer_a = ctx.eph[0].clone();
	let signer_b = ctx.eph[1].clone();
	let signer_c = ctx.eph[2].clone();
	let signers =
		vec![account_id_of(&signer_a), account_id_of(&signer_b), account_id_of(&signer_c)];
	let threshold = 2u32;
	// Random nonce so repeated runs against the same chain produce fresh multisigs.
	let nonce: u64 = rand::Rng::random(&mut ctx.rng);

	// Create the multisig and derive its address deterministically.
	let create_call =
		quantus_subxt::api::tx()
			.multisig()
			.create_multisig(signers.clone(), threshold, nonce);
	submit_ok(ctx, &signer_a, create_call).await?;
	let multisig_ss58 =
		crate::cli::multisig::predict_multisig_address(signers.clone(), threshold, nonce);

	// Verify it exists on-chain.
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

	// Fund the multisig so it can pay out the proposed transfer.
	crate::cli::send::transfer(
		&ctx.client,
		&signer_a,
		&multisig_ss58,
		20 * ctx.unit,
		None,
		ctx.wait_mode(),
	)
	.await?;

	// Propose a transfer to a fresh recipient (inner call encoded via metadata,
	// so pallet/call indices always match the connected runtime).
	let recipient = ctx.fresh_keypair()?;
	let recipient_ss58 = recipient.to_account_id_ss58check();
	let amount = 2 * ctx.unit;
	let inner = quantus_subxt::api::tx().balances().transfer_allow_death(
		subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&recipient)),
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

	// Second approval reaches the 2-of-3 threshold.
	let approve_call =
		quantus_subxt::api::tx().multisig().approve(multisig_id.clone(), proposal_id);
	submit_ok(ctx, &signer_b, approve_call).await?;

	// Execute and verify the recipient got paid.
	let execute_call =
		quantus_subxt::api::tx().multisig().execute(multisig_id.clone(), proposal_id);
	submit_ok(ctx, &signer_c, execute_call).await?;

	let recipient_balance = ctx.free_balance(&recipient_ss58).await?;
	if recipient_balance != amount {
		return Err(QuantusError::Generic(format!(
			"multisig payout mismatch: recipient has {recipient_balance}, expected {amount}"
		)));
	}

	// Propose a second transfer and cancel it.
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

async fn current_block(ctx: &ExerciseCtx) -> Result<u32> {
	let latest = ctx.client.get_latest_block().await?;
	Ok(ctx.client.client().blocks().at(latest).await?.number())
}

/// Highest proposal id currently in storage for the multisig; assumes the most
/// recent `propose` we submitted created it.
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
