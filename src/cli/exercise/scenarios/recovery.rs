//! Recovery scenarios: full social-recovery lifecycle plus negative checks.

use crate::{
	chain::quantus_subxt,
	cli::exercise::{
		report::Report,
		runner::{account_id_of, submit_expect_failure, submit_ok, ExerciseCtx},
	},
	error::{QuantusError, Result},
	exercise_step,
	wallet::QuantumKeyPair,
};
use subxt::ext::subxt_core::utils::MultiAddress;

/// Dedicated accounts the lifecycle funds: the lost account, the rescuer and one friend.
pub const LIFECYCLE_ACCOUNTS: u128 = 3;

/// What each of those accounts needs, sized from the chain's own recovery deposits (the config
/// deposit for one friend, and the rescuer's recovery deposit) so the phase fits the run budget
/// on any chain. All of it is swept back to the root account once the deposits are released.
pub fn account_funding(
	client: &crate::chain::client::QuantusClient,
	existential_deposit: u128,
	test_unit: u128,
) -> Result<u128> {
	let constants = client.client().constants();
	let config_deposit = constants
		.at(&quantus_subxt::api::constants().recovery().config_deposit_base())?
		.saturating_add(
			constants.at(&quantus_subxt::api::constants().recovery().friend_deposit_factor())?,
		);
	let recovery_deposit =
		constants.at(&quantus_subxt::api::constants().recovery().recovery_deposit())?;
	Ok(config_deposit
		.max(recovery_deposit)
		.saturating_add(existential_deposit)
		.saturating_add(20 * test_unit))
}

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "config_reads", config_reads(ctx));
	exercise_step!(report, phase, "initiate_not_recoverable", initiate_not_recoverable(ctx));
	exercise_step!(report, phase, "full_lifecycle", full_lifecycle(ctx));
	Ok(())
}

async fn config_reads(ctx: &mut ExerciseCtx) -> Result<String> {
	let root = account_id_of(&ctx.root)?;
	let latest = ctx.client.get_latest_block().await?;
	let storage_at = ctx.client.client().storage().at(latest);

	let recoverable = storage_at
		.fetch(&quantus_subxt::api::storage().recovery().recoverable(root.clone()))
		.await?;
	let proxy = storage_at.fetch(&quantus_subxt::api::storage().recovery().proxy(root)).await?;

	Ok(format!(
		"recovery storage decodes: root recoverable={}, proxy={}",
		recoverable.is_some(),
		proxy.is_some()
	))
}

async fn initiate_not_recoverable(ctx: &mut ExerciseCtx) -> Result<String> {
	let lost = account_id_of(&ctx.bob)?;
	let call = quantus_subxt::api::tx().recovery().initiate_recovery(MultiAddress::Id(lost));
	let rescuer = ctx.eph[0].clone();
	submit_expect_failure(ctx, &rescuer, call, &["NotRecoverable"]).await
}

/// Whether `who` currently has a recovery `Proxy` entry pointing at some account.
async fn has_proxy(ctx: &ExerciseCtx, who: &QuantumKeyPair) -> Result<bool> {
	let account = account_id_of(who)?;
	let latest = ctx.client.get_latest_block().await?;
	let storage_at = ctx.client.client().storage().at(latest);
	Ok(storage_at
		.fetch(&quantus_subxt::api::storage().recovery().proxy(account))
		.await?
		.is_some())
}

/// create → initiate → vouch → claim → as_recovered → cancel_recovered →
/// close_recovery → poke_deposit → remove_recovery, with storage checks.
async fn full_lifecycle(ctx: &mut ExerciseCtx) -> Result<String> {
	// Dedicated accounts so recovery deposits/config never collide with the
	// shared ephemeral senders used by other phases.
	let lost = ctx.fresh_keypair()?;
	let rescuer = ctx.fresh_keypair()?;
	let friend = ctx.fresh_keypair()?;

	let funding = account_funding(&ctx.client, ctx.existential_deposit, ctx.test_unit)?;
	let transfers = vec![
		(lost.try_to_account_id_ss58check()?, funding),
		(rescuer.try_to_account_id_ss58check()?, funding),
		(friend.try_to_account_id_ss58check()?, funding),
	];
	ctx.batch_fund_from_root(transfers).await?;

	let lost_id = account_id_of(&lost)?;
	let rescuer_id = account_id_of(&rescuer)?;
	let friend_id = account_id_of(&friend)?;

	// 1. Make `lost` recoverable: one friend, threshold 1, no claim delay.
	let create = quantus_subxt::api::tx()
		.recovery()
		.create_recovery(vec![friend_id.clone()], 1, 0);
	submit_ok(ctx, &lost, create).await?;

	// 2. Rescuer starts recovery; 3. friend vouches.
	let initiate = quantus_subxt::api::tx()
		.recovery()
		.initiate_recovery(MultiAddress::Id(lost_id.clone()));
	submit_ok(ctx, &rescuer, initiate).await?;

	let vouch = quantus_subxt::api::tx()
		.recovery()
		.vouch_recovery(MultiAddress::Id(lost_id.clone()), MultiAddress::Id(rescuer_id.clone()));
	submit_ok(ctx, &friend, vouch).await?;

	// 4. Threshold met and delay elapsed (0 blocks): claim the account.
	let claim = quantus_subxt::api::tx()
		.recovery()
		.claim_recovery(MultiAddress::Id(lost_id.clone()));
	submit_ok(ctx, &rescuer, claim).await?;

	if !has_proxy(ctx, &rescuer).await? {
		return Err(QuantusError::Generic(
			"claim_recovery succeeded but no recovery proxy entry exists".to_string(),
		));
	}

	// 5. Dispatch as the recovered account: move funds out of `lost`.
	// The rescuer signs and pays fees, so the *lost* account's balance is the
	// one that changes by exactly the transferred amount.
	let drained = 10 * ctx.test_unit;
	let lost_ss58 = lost.try_to_account_id_ss58check()?;
	let lost_before = ctx.free_balance(&lost_ss58).await?;
	let inner = {
		use quantus_subxt::api::runtime_types::{
			pallet_balances::pallet::Call as BalancesCall, quantus_runtime::RuntimeCall,
		};
		RuntimeCall::Balances(BalancesCall::transfer_allow_death {
			dest: MultiAddress::Id(rescuer_id.clone()),
			value: drained,
		})
	};
	let as_recovered = quantus_subxt::api::tx()
		.recovery()
		.as_recovered(MultiAddress::Id(lost_id.clone()), inner);
	submit_ok(ctx, &rescuer, as_recovered).await?;

	let lost_after = ctx.free_balance(&lost_ss58).await?;
	if lost_after != lost_before - drained {
		return Err(QuantusError::Generic(format!(
			"as_recovered transfer not reflected: lost account went {lost_before} -> {lost_after}, expected -{drained}"
		)));
	}

	// 6. Rescuer gives up proxy access.
	let cancel = quantus_subxt::api::tx()
		.recovery()
		.cancel_recovered(MultiAddress::Id(lost_id.clone()));
	submit_ok(ctx, &rescuer, cancel).await?;
	if has_proxy(ctx, &rescuer).await? {
		return Err(QuantusError::Generic(
			"cancel_recovered succeeded but the proxy entry is still present".to_string(),
		));
	}

	// 7. Owner closes the (claimed) recovery attempt and collects the deposit.
	let close = quantus_subxt::api::tx()
		.recovery()
		.close_recovery(MultiAddress::Id(rescuer_id.clone()));
	submit_ok(ctx, &lost, close).await?;

	// 8. Deposit poke is a paid no-op when nothing changed; must still dispatch.
	let poke = quantus_subxt::api::tx().recovery().poke_deposit(None);
	submit_ok(ctx, &lost, poke).await?;

	// 9. Remove the recovery configuration entirely.
	let remove = quantus_subxt::api::tx().recovery().remove_recovery();
	submit_ok(ctx, &lost, remove).await?;

	let latest = ctx.client.get_latest_block().await?;
	let recoverable = ctx
		.client
		.client()
		.storage()
		.at(latest)
		.fetch(&quantus_subxt::api::storage().recovery().recoverable(lost_id))
		.await?;
	if recoverable.is_some() {
		return Err(QuantusError::Generic(
			"remove_recovery succeeded but the recovery config is still present".to_string(),
		));
	}

	// All deposits are released by now; hand the funding back to the run budget.
	for account in [&lost, &rescuer, &friend] {
		ctx.sweep_to_root(account).await?;
	}

	Ok("full recovery lifecycle: create, initiate, vouch, claim, as_recovered \
	    (funds drained), cancel_recovered, close, poke_deposit, remove — storage verified"
		.to_string())
}
