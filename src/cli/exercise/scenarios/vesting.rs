//! Vesting lifecycle: admin calls via the treasury multisig, permissionless claims.
//!
//! The Vesting pallet's admin origin is Root or `Signed(treasury)`. On dev chains
//! the treasury is the well-known 2-of-3 Alice/Bob/Charlie multisig (nonce 0), so
//! this scenario registers that multisig in the Multisig pallet if needed and
//! dispatches `create_schedule` / `retarget_schedule` / `end_schedule` through the
//! propose → approve → execute flow. Assertions are made against chain state (pot
//! and beneficiary balances, schedule storage) rather than the execute result.
//! On chains whose treasury is not that multisig the admin steps are skipped.

use crate::{
	chain::quantus_subxt,
	cli::{
		address_format::QuantusSS58,
		common::SubxtAccountId32,
		exercise::{
			report::Report,
			runner::{account_id_of, submit_expect_failure, submit_ok, ExerciseCtx},
		},
	},
	error::{QuantusError, Result},
	exercise_step,
};
use subxt::tx::Payload;

const TREASURY_MULTISIG_THRESHOLD: u32 = 2;
const TREASURY_MULTISIG_NONCE: u64 = 0;
const HOUR_MS: u64 = 60 * 60 * 1_000;
const DAY_MS: u64 = 24 * HOUR_MS;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "constants_and_schedules", constants_and_schedules(ctx));
	exercise_step!(report, phase, "claim_missing_schedule", claim_missing_schedule(ctx));
	exercise_step!(report, phase, "create_requires_admin_origin", create_requires_admin(ctx));
	let started = std::time::Instant::now();
	match dev_treasury(&ctx.client, &ctx.alice, &ctx.bob, &ctx.charlie).await {
		Ok(Some(treasury)) => {
			exercise_step!(
				report,
				phase,
				"admin_create_and_claim",
				admin_create_and_claim(ctx, &treasury)
			);
			exercise_step!(report, phase, "retarget_and_end", retarget_and_end(ctx, &treasury));
		},
		Ok(None) =>
			for step in ["admin_create_and_claim", "retarget_and_end"] {
				report.record_skip(
					phase,
					step,
					"the chain's treasury is unset or not the dev Alice/Bob/Charlie multisig, \
					 so Signed(treasury) admin calls cannot be dispatched",
				);
			},
		Err(e) => report.record(phase, "dev_treasury_check", started.elapsed(), Err(e)),
	}
	Ok(())
}

/// Read constants, `NextScheduleId` and the schedules map; sanity-check invariants.
async fn constants_and_schedules(ctx: &mut ExerciseCtx) -> Result<String> {
	let constants = ctx.client.client().constants();
	let payout_quantum =
		constants.at(&quantus_subxt::api::constants().vesting().payout_quantum())?;
	let minimum_payout =
		constants.at(&quantus_subxt::api::constants().vesting().minimum_payout())?;
	let min_claim_interval =
		constants.at(&quantus_subxt::api::constants().vesting().min_claim_interval())?;

	if payout_quantum == 0 || minimum_payout < payout_quantum {
		return Err(QuantusError::Generic(format!(
			"implausible vesting constants: quantum {payout_quantum}, minimum {minimum_payout}"
		)));
	}

	let next_id = next_schedule_id(ctx).await?;
	let schedules = crate::cli::vesting::fetch_all_schedules(&ctx.client).await?;
	for (id, schedule) in &schedules {
		if *id >= next_id {
			return Err(QuantusError::Generic(format!(
				"schedule id {id} >= NextScheduleId {next_id}"
			)));
		}
		if schedule.total % payout_quantum != 0 {
			return Err(QuantusError::Generic(format!(
				"schedule {id} total {} is not quantum-aligned",
				schedule.total
			)));
		}
	}

	Ok(format!(
		"quantum {payout_quantum}, minimum payout {minimum_payout}, claim interval {min_claim_interval}ms; \
		 {} schedule(s), next id {next_id}",
		schedules.len()
	))
}

async fn claim_missing_schedule(ctx: &mut ExerciseCtx) -> Result<String> {
	let claimer = ctx.eph[0].clone();
	let call = quantus_subxt::api::tx().vesting().claim(u64::MAX);
	submit_expect_failure(ctx, &claimer, call, &["NoSchedule"]).await
}

async fn create_requires_admin(ctx: &mut ExerciseCtx) -> Result<String> {
	let now = chain_now_ms(ctx).await?;
	let beneficiary = account_id_of(&ctx.eph[0])?;
	let call = quantus_subxt::api::tx().vesting().create_schedule(
		beneficiary,
		now,
		now,
		now + DAY_MS,
		5 * ctx.test_unit,
	);
	// A plain signed origin is not the treasury; only Root or Signed(treasury) may create.
	let intruder = ctx.eph[1].clone();
	submit_expect_failure(ctx, &intruder, call, &["BadOrigin"]).await
}

/// Create a fully-vested schedule through the treasury multisig, then claim it
/// permissionlessly from a third party and verify the beneficiary got paid.
async fn admin_create_and_claim(
	ctx: &mut ExerciseCtx,
	treasury: &SubxtAccountId32,
) -> Result<String> {
	ensure_treasury_multisig(ctx, treasury).await?;
	let total = schedule_total(&ctx.client, ctx.test_unit)?;
	let target = treasury_funding(&ctx.client, ctx.test_unit, ctx.existential_deposit)?;
	fund_treasury(ctx, treasury, target).await?;

	let now = chain_now_ms(ctx).await?;
	let beneficiary = ctx.eph[0].clone();
	let beneficiary_ss58 = beneficiary.try_to_account_id_ss58check()?;
	let pot_ss58 = pot_account_ss58();

	let id_before = next_schedule_id(ctx).await?;
	let pot_before = ctx.free_balance(&pot_ss58).await?;

	// Fully vested in the past: everything is claimable in one payout.
	let create = quantus_subxt::api::tx().vesting().create_schedule(
		account_id_of(&beneficiary)?,
		now - 2 * HOUR_MS,
		now - 2 * HOUR_MS,
		now - HOUR_MS,
		total,
	);
	admin_dispatch(ctx, treasury, &create).await?;

	let schedule_id = id_before;
	let schedule = crate::cli::vesting::fetch_schedule(&ctx.client, schedule_id)
		.await?
		.ok_or_else(|| {
			QuantusError::Generic(format!(
				"schedule {schedule_id} missing after multisig create_schedule executed"
			))
		})?;
	if schedule.beneficiary != account_id_of(&beneficiary)? || schedule.total != total {
		return Err(QuantusError::Generic(format!(
			"created schedule mismatch: beneficiary {}, total {}",
			schedule.beneficiary.to_quantus_ss58(),
			schedule.total
		)));
	}
	let pot_after_create = ctx.free_balance(&pot_ss58).await?;
	if pot_after_create != pot_before + total {
		return Err(QuantusError::Generic(format!(
			"pot balance went {pot_before} -> {pot_after_create}, expected +{total} from create"
		)));
	}

	// Permissionless claim by Charlie; the payout must go to the stored beneficiary.
	let beneficiary_before = ctx.free_balance(&beneficiary_ss58).await?;
	let charlie = ctx.charlie.clone();
	submit_ok(ctx, &charlie, quantus_subxt::api::tx().vesting().claim(schedule_id)).await?;
	let beneficiary_after = ctx.free_balance(&beneficiary_ss58).await?;
	let delta = beneficiary_after.saturating_sub(beneficiary_before);
	if delta != total {
		return Err(QuantusError::Generic(format!(
			"claim paid {delta} to beneficiary, expected the full {total}"
		)));
	}

	// A fully claimed schedule stays in storage with claimed == total; further
	// claims must be rejected.
	let claimed = crate::cli::vesting::fetch_schedule(&ctx.client, schedule_id)
		.await?
		.ok_or_else(|| {
			QuantusError::Generic(format!("schedule {schedule_id} vanished after full claim"))
		})?;
	if claimed.claimed != total {
		return Err(QuantusError::Generic(format!(
			"schedule {schedule_id} records claimed {} after full payout, expected {total}",
			claimed.claimed
		)));
	}
	let reclaim = quantus_subxt::api::tx().vesting().claim(schedule_id);
	submit_expect_failure(ctx, &charlie, reclaim, &["NothingToClaim", "ClaimTooSoon"]).await?;

	Ok(format!(
		"schedule #{schedule_id} created via treasury multisig, {total} claimed \
		 permissionlessly to the beneficiary, re-claim rejected"
	))
}

/// Create a future schedule, verify it is unclaimable, retarget it, then end it
/// early and verify the pot returns the unvested funds.
async fn retarget_and_end(ctx: &mut ExerciseCtx, treasury: &SubxtAccountId32) -> Result<String> {
	ensure_treasury_multisig(ctx, treasury).await?;
	let total = schedule_total(&ctx.client, ctx.test_unit)?;
	let target = treasury_funding(&ctx.client, ctx.test_unit, ctx.existential_deposit)?;
	fund_treasury(ctx, treasury, target).await?;

	let now = chain_now_ms(ctx).await?;
	let pot_ss58 = pot_account_ss58();
	let id_before = next_schedule_id(ctx).await?;
	let pot_before = ctx.free_balance(&pot_ss58).await?;

	// Vesting starts tomorrow: nothing is claimable, ending returns everything.
	let create = quantus_subxt::api::tx().vesting().create_schedule(
		account_id_of(&ctx.eph[1])?,
		now + DAY_MS,
		now + DAY_MS,
		now + 2 * DAY_MS,
		total,
	);
	admin_dispatch(ctx, treasury, &create).await?;
	let schedule_id = id_before;
	if crate::cli::vesting::fetch_schedule(&ctx.client, schedule_id).await?.is_none() {
		return Err(QuantusError::Generic(format!(
			"schedule {schedule_id} missing after multisig create_schedule executed"
		)));
	}

	let claimer = ctx.eph[0].clone();
	let early_claim = quantus_subxt::api::tx().vesting().claim(schedule_id);
	submit_expect_failure(ctx, &claimer, early_claim, &["NothingToClaim"]).await?;

	// Retarget to a different beneficiary; nothing is claimable so no payout settles.
	let new_beneficiary = account_id_of(&ctx.eph[2])?;
	let retarget = quantus_subxt::api::tx()
		.vesting()
		.retarget_schedule(schedule_id, new_beneficiary.clone());
	admin_dispatch(ctx, treasury, &retarget).await?;
	let retargeted = crate::cli::vesting::fetch_schedule(&ctx.client, schedule_id)
		.await?
		.ok_or_else(|| {
			QuantusError::Generic(format!("schedule {schedule_id} vanished after retarget"))
		})?;
	if retargeted.beneficiary != new_beneficiary {
		return Err(QuantusError::Generic(format!(
			"retarget did not change beneficiary: still {}",
			retargeted.beneficiary.to_quantus_ss58()
		)));
	}
	if retargeted.claimed != 0 {
		return Err(QuantusError::Generic(format!(
			"retarget settled an unexpected payout of {}",
			retargeted.claimed
		)));
	}

	// End early: zero vested, so the pot returns the full total to the treasury.
	let end = quantus_subxt::api::tx().vesting().end_schedule(schedule_id);
	admin_dispatch(ctx, treasury, &end).await?;
	if crate::cli::vesting::fetch_schedule(&ctx.client, schedule_id).await?.is_some() {
		return Err(QuantusError::Generic(format!(
			"schedule {schedule_id} still present after end_schedule"
		)));
	}
	let pot_after = ctx.free_balance(&pot_ss58).await?;
	if pot_after != pot_before {
		return Err(QuantusError::Generic(format!(
			"pot balance went {pot_before} -> {pot_after}; expected create (+{total}) and \
			 end_schedule (-{total}) to cancel out"
		)));
	}

	Ok(format!(
		"schedule #{schedule_id}: pre-start claim rejected, retargeted to a new beneficiary, \
		 ended early with the full {total} returned to the treasury"
	))
}

// --- helpers -----------------------------------------------------------------

async fn chain_now_ms(ctx: &ExerciseCtx) -> Result<u64> {
	let latest = ctx.client.get_latest_block().await?;
	let storage = ctx.client.client().storage().at(latest);
	let addr = quantus_subxt::api::storage().timestamp().now();
	Ok(storage.fetch_or_default(&addr).await?)
}

async fn next_schedule_id(ctx: &ExerciseCtx) -> Result<u64> {
	let latest = ctx.client.get_latest_block().await?;
	let storage = ctx.client.client().storage().at(latest);
	let addr = quantus_subxt::api::storage().vesting().next_schedule_id();
	Ok(storage.fetch_or_default(&addr).await?)
}

/// The chain's treasury account, if it is the well-known dev 2-of-3 Alice/Bob/Charlie
/// multisig (nonce 0) the admin steps can sign for; `None` when it is unset or different.
pub async fn dev_treasury(
	client: &crate::chain::client::QuantusClient,
	alice: &crate::wallet::QuantumKeyPair,
	bob: &crate::wallet::QuantumKeyPair,
	charlie: &crate::wallet::QuantumKeyPair,
) -> Result<Option<SubxtAccountId32>> {
	let latest = client.get_latest_block().await?;
	let storage = client.client().storage().at(latest);
	let addr = quantus_subxt::api::storage().treasury_pallet().treasury_account();
	let Some(treasury) = storage.fetch(&addr).await? else {
		return Ok(None);
	};
	let signers = vec![account_id_of(alice)?, account_id_of(bob)?, account_id_of(charlie)?];
	let predicted = crate::cli::multisig::predict_multisig_address(
		signers,
		TREASURY_MULTISIG_THRESHOLD,
		TREASURY_MULTISIG_NONCE,
	);
	Ok((predicted == treasury.to_quantus_ss58()).then_some(treasury))
}

/// The vesting pot: `PalletId(b"qvesting")` via `into_account_truncating`,
/// i.e. `b"modl" ++ b"qvesting" ++ zero padding`.
fn pot_account_ss58() -> String {
	let mut bytes = [0u8; 32];
	bytes[..4].copy_from_slice(b"modl");
	bytes[4..12].copy_from_slice(b"qvesting");
	SubxtAccountId32::from(bytes).to_quantus_ss58()
}

/// Make sure the dev treasury multisig (validated by [`dev_treasury`]) is registered in
/// the Multisig pallet so it can dispatch `Signed(treasury)` admin calls.
async fn ensure_treasury_multisig(
	ctx: &mut ExerciseCtx,
	treasury: &SubxtAccountId32,
) -> Result<()> {
	if crate::cli::multisig::get_multisig_info(&ctx.client, treasury.clone())
		.await?
		.is_none()
	{
		let signers = vec![
			account_id_of(&ctx.alice)?,
			account_id_of(&ctx.bob)?,
			account_id_of(&ctx.charlie)?,
		];
		let alice = ctx.alice.clone();
		let create = quantus_subxt::api::tx().multisig().create_multisig(
			signers,
			TREASURY_MULTISIG_THRESHOLD,
			TREASURY_MULTISIG_NONCE,
		);
		ctx.submit_budgeted(&alice, create, 0).await?;
		if crate::cli::multisig::get_multisig_info(&ctx.client, treasury.clone())
			.await?
			.is_none()
		{
			return Err(QuantusError::Generic(
				"treasury multisig still unregistered after create_multisig".to_string(),
			));
		}
	}
	Ok(())
}

/// Top the treasury up from Alice so `create_schedule` can move funds into the pot.
/// Smallest schedule the chain accepts at the suite's test scale: at least `MinimumPayout`,
/// rounded up to a whole `PayoutQuantum` so the pallet's alignment check passes.
pub fn schedule_total(
	client: &crate::chain::client::QuantusClient,
	test_unit: u128,
) -> Result<u128> {
	let constants = client.client().constants();
	let payout_quantum =
		constants.at(&quantus_subxt::api::constants().vesting().payout_quantum())?;
	let minimum_payout =
		constants.at(&quantus_subxt::api::constants().vesting().minimum_payout())?;
	if payout_quantum == 0 {
		return Err(QuantusError::Generic("vesting PayoutQuantum is zero".to_string()));
	}
	Ok((5 * test_unit).max(minimum_payout).div_ceil(payout_quantum) * payout_quantum)
}

/// Balance the treasury multisig is topped up to. Unlike the other dedicated accounts this one
/// is a multisig and is not swept back, so it stays spent for the rest of the run.
pub fn treasury_funding(
	client: &crate::chain::client::QuantusClient,
	test_unit: u128,
	existential_deposit: u128,
) -> Result<u128> {
	Ok(4 * schedule_total(client, test_unit)? + existential_deposit)
}

/// Top the treasury multisig up to `target_free`, charged against the run budget.
async fn fund_treasury(
	ctx: &mut ExerciseCtx,
	treasury: &SubxtAccountId32,
	target_free: u128,
) -> Result<()> {
	let treasury_ss58 = treasury.to_quantus_ss58();
	let free = ctx.free_balance(&treasury_ss58).await?;
	if free >= target_free {
		return Ok(());
	}
	ctx.fund_from_root(&treasury_ss58, target_free - free).await
}

/// Dispatch a call as `Signed(treasury)` through the multisig pallet:
/// Alice proposes, Bob approves (reaching the 2-of-3 threshold), Charlie executes.
async fn admin_dispatch<Call: Payload>(
	ctx: &mut ExerciseCtx,
	treasury: &SubxtAccountId32,
	call: &Call,
) -> Result<()> {
	let call_data = call
		.encode_call_data(&ctx.client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("failed to encode admin call: {e:?}")))?;

	let latest = ctx.client.get_latest_block().await?;
	let expiry = ctx.client.client().blocks().at(latest).await?.number() + 100;

	let alice = ctx.alice.clone();
	let propose = quantus_subxt::api::tx().multisig().propose(
		treasury.clone(),
		quantus_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
			call_data.clone(),
		),
		expiry,
	);
	ctx.submit_budgeted(&alice, propose, 0).await?;

	let proposals = crate::cli::multisig::list_proposals(&ctx.client, treasury.clone()).await?;
	let proposal_id = proposals
		.iter()
		.filter(|p| p.call_data == call_data)
		.map(|p| p.id)
		.max()
		.ok_or_else(|| {
			QuantusError::Generic("treasury proposal not found after propose".to_string())
		})?;

	let bob = ctx.bob.clone();
	let approve = quantus_subxt::api::tx().multisig().approve(
		treasury.clone(),
		proposal_id,
		quantus_subxt::api::runtime_types::bounded_collections::bounded_vec::BoundedVec(
			call_data.clone(),
		),
	);
	ctx.submit_budgeted(&bob, approve, 0).await?;

	let charlie = ctx.charlie.clone();
	let execute = quantus_subxt::api::tx().multisig().execute(
		treasury.clone(),
		proposal_id,
		crate::cli::multisig::decode_proposal_call(&call_data)?,
	);
	ctx.submit_budgeted(&charlie, execute, 0).await?;
	Ok(())
}
