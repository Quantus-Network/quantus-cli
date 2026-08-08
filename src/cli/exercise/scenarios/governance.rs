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

	crate::cli::common::submit_preimage(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(ctx.alice.clone()),
		encoded,
		ctx.wait_mode(),
	)
	.await?;

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
			&crate::wallet::WalletSigner::Hot(voter.clone()),
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

async fn add_member_requires_root(ctx: &mut ExerciseCtx) -> Result<String> {
	let intruder = ctx.fresh_keypair()?;
	let call = quantus_subxt::api::tx()
		.tech_collective()
		.add_member(subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&intruder)?));
	let alice = ctx.alice.clone();
	submit_expect_failure(ctx, &alice, call, &["BadOrigin"]).await
}
