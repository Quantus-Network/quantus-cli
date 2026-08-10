//! Tech-collective and tech-referenda scenarios.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_expect_failure, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use sp_runtime::traits::{BlakeTwo256, Hash};
use subxt::tx::Payload;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "membership_reads", membership_reads(ctx));
	exercise_step!(report, phase, "referendum_flow", referendum_flow(ctx));
	exercise_step!(report, phase, "referendum_metadata", referendum_metadata(ctx));
	exercise_step!(report, phase, "cleanup_poll", cleanup_poll(ctx));
	exercise_step!(report, phase, "add_member_requires_root", add_member_requires_root(ctx));
	Ok(())
}

async fn membership_reads(ctx: &mut ExerciseCtx) -> Result<String> {
	let alice_ss58 = ctx.alice.try_to_account_id_ss58check()?;
	let is_member = crate::cli::tech_collective::is_member(&ctx.client, &alice_ss58).await?;
	if !is_member {
		return Err(QuantusError::Generic(
			"alice is not a tech-collective member; expected dev genesis membership".to_string(),
		));
	}
	let count = crate::cli::tech_collective::get_member_count(&ctx.client).await?.unwrap_or(0);
	let members = crate::cli::tech_collective::get_member_list(&ctx.client).await?;
	if members.len() != count as usize {
		return Err(QuantusError::Generic(format!(
			"member list length {} does not match MemberCount {count}",
			members.len()
		)));
	}
	Ok(format!("alice is a member; collective has {count} rank-0 members"))
}

async fn referendum_flow(ctx: &mut ExerciseCtx) -> Result<String> {
	let latest = ctx.client.get_latest_block().await?;
	let storage_at = ctx.client.client().storage().at(latest);

	let portion_addr = quantus_subxt::api::storage().treasury_pallet().treasury_portion();
	let current_portion = storage_at.fetch(&portion_addr).await?.map(|p| p.0).unwrap_or(0);

	let portion =
		quantus_subxt::api::runtime_types::sp_arithmetic::per_things::Permill(current_portion);
	let inner = quantus_subxt::api::tx().treasury_pallet().set_treasury_portion(portion);
	let encoded = inner
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode call: {e:?}")))?;
	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let call_len = encoded.len() as u32;

	crate::cli::common::submit_preimage(&ctx.client, &ctx.alice, encoded, ctx.wait_mode()).await?;

	let count_addr = quantus_subxt::api::storage().tech_referenda().referendum_count();
	let index = storage_at.fetch(&count_addr).await?.unwrap_or(0);

	let submit_call = build_submit_call(preimage_hash, call_len);
	let alice = ctx.alice.clone();
	submit_ok(ctx, &alice, submit_call).await?;

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

	use quantus_subxt::api::runtime_types::pallet_referenda::types::ReferendumInfo;
	let info_addr = quantus_subxt::api::storage().tech_referenda().referendum_info_for(index);
	let latest = ctx.client.get_latest_block().await?;
	let info = ctx
		.client
		.client()
		.storage()
		.at(latest)
		.fetch(&info_addr)
		.await?
		.ok_or_else(|| QuantusError::Generic(format!("referendum #{index} not found")))?;

	match info {
		ReferendumInfo::Ongoing(status) => {
			if status.tally.ayes < 3 {
				return Err(QuantusError::Generic(format!(
					"expected 3 aye votes on referendum #{index}, tally shows {}",
					status.tally.ayes
				)));
			}
			Ok(format!(
				"referendum #{index} submitted, deposit placed, 3 aye votes tallied (ongoing)"
			))
		},
		ReferendumInfo::Approved(..) => Ok(format!(
			"referendum #{index} submitted, voted, and already approved (fast-governance node)"
		)),
		other => Err(QuantusError::Generic(format!(
			"referendum #{index} in unexpected state: {other:?}"
		))),
	}
}

pub fn build_submit_call(preimage_hash: sp_core::H256, call_len: u32) -> impl subxt::tx::Payload {
	type ProposalBounded =
		quantus_subxt::api::runtime_types::frame_support::traits::preimages::Bounded<
			quantus_subxt::api::runtime_types::quantus_runtime::RuntimeCall,
			quantus_subxt::api::runtime_types::sp_runtime::traits::BlakeTwo256,
		>;
	let proposal: ProposalBounded = ProposalBounded::Lookup { hash: preimage_hash, len: call_len };
	let origin_caller = quantus_subxt::api::runtime_types::quantus_runtime::OriginCaller::system(
		quantus_subxt::api::runtime_types::frame_support::dispatch::RawOrigin::Root,
	);
	let enactment =
		quantus_subxt::api::runtime_types::frame_support::traits::schedule::DispatchTime::After(
			0u32,
		);
	quantus_subxt::api::tx()
		.tech_referenda()
		.submit(origin_caller, proposal, enactment)
}

/// Submit a bare referendum (no decision deposit, so it deterministically stays
/// ongoing even on fast-governance nodes) and drive `set_metadata` plus the
/// user-callable refund guards against it.
async fn referendum_metadata(ctx: &mut ExerciseCtx) -> Result<String> {
	// Proposal preimage for the referendum itself.
	let marker: [u8; 24] = rand::Rng::random(&mut ctx.rng);
	let remark = quantus_subxt::api::tx().system().remark(marker.to_vec());
	let encoded = remark
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode remark call: {e:?}")))?;
	let proposal_hash: sp_core::H256 = BlakeTwo256::hash(&encoded);
	let call_len = encoded.len() as u32;
	crate::cli::common::submit_preimage(&ctx.client, &ctx.alice, encoded, ctx.wait_mode()).await?;

	let latest = ctx.client.get_latest_block().await?;
	let count_addr = quantus_subxt::api::storage().tech_referenda().referendum_count();
	let index = ctx.client.client().storage().at(latest).fetch(&count_addr).await?.unwrap_or(0);

	let alice = ctx.alice.clone();
	submit_ok(ctx, &alice, build_submit_call(proposal_hash, call_len)).await?;

	// Metadata must reference an on-chain preimage.
	let metadata: [u8; 32] = rand::Rng::random(&mut ctx.rng);
	let metadata_hash: sp_core::H256 = BlakeTwo256::hash(&metadata);
	crate::cli::common::submit_preimage(
		&ctx.client,
		&ctx.alice,
		metadata.to_vec(),
		ctx.wait_mode(),
	)
	.await?;

	let set = quantus_subxt::api::tx()
		.tech_referenda()
		.set_metadata(index, Some(metadata_hash));
	submit_ok(ctx, &alice, set).await?;

	let metadata_addr = quantus_subxt::api::storage().tech_referenda().metadata_of(index);
	let latest = ctx.client.get_latest_block().await?;
	let stored = ctx.client.client().storage().at(latest).fetch(&metadata_addr).await?;
	if stored != Some(metadata_hash) {
		return Err(QuantusError::Generic(format!(
			"metadata for referendum #{index} is {stored:?}, expected {metadata_hash:?}"
		)));
	}

	let clear = quantus_subxt::api::tx().tech_referenda().set_metadata(index, None);
	submit_ok(ctx, &alice, clear).await?;
	let latest = ctx.client.get_latest_block().await?;
	if ctx.client.client().storage().at(latest).fetch(&metadata_addr).await?.is_some() {
		return Err(QuantusError::Generic(format!(
			"metadata for referendum #{index} still present after clearing"
		)));
	}

	// User-callable refunds must reject cleanly while the referendum is open:
	// no decision deposit was placed, and the submission deposit is not
	// refundable before the referendum closes.
	let refund_decision = quantus_subxt::api::tx().tech_referenda().refund_decision_deposit(index);
	submit_expect_failure(ctx, &alice, refund_decision, &["NoDeposit"]).await?;
	let refund_submission =
		quantus_subxt::api::tx().tech_referenda().refund_submission_deposit(index);
	submit_expect_failure(ctx, &alice, refund_submission, &["BadStatus"]).await?;

	Ok(format!(
		"referendum #{index}: metadata set and cleared (storage verified); \
		 refund_decision_deposit and refund_submission_deposit rejected while open"
	))
}

/// `cleanup_poll` is permissionless: it must reject ongoing polls and dispatch
/// as a no-op for polls that are not ongoing.
async fn cleanup_poll(ctx: &mut ExerciseCtx) -> Result<String> {
	let latest = ctx.client.get_latest_block().await?;
	let count_addr = quantus_subxt::api::storage().tech_referenda().referendum_count();
	let count = ctx.client.client().storage().at(latest).fetch(&count_addr).await?.unwrap_or(0);

	// The bare referendum from referendum_metadata (or referendum_flow) is ongoing.
	let sender = ctx.eph[0].clone();
	if count > 0 {
		let ongoing = quantus_subxt::api::tx().tech_collective().cleanup_poll(count - 1, 10);
		submit_expect_failure(ctx, &sender, ongoing, &["Ongoing"]).await?;
	}

	// A never-created poll index is not ongoing; cleanup dispatches as a paid no-op.
	let call = quantus_subxt::api::tx().tech_collective().cleanup_poll(count + 1_000, 10);
	submit_ok(ctx, &sender, call).await?;
	Ok(format!(
		"cleanup_poll rejected for ongoing poll #{} and dispatched for a non-ongoing index",
		count.saturating_sub(1)
	))
}

async fn add_member_requires_root(ctx: &mut ExerciseCtx) -> Result<String> {
	let intruder = ctx.fresh_keypair()?;
	let call = quantus_subxt::api::tx()
		.tech_collective()
		.add_member(subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&intruder)?));
	let alice = ctx.alice.clone();
	submit_expect_failure(ctx, &alice, call, &["BadOrigin"]).await
}
