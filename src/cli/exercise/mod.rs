//! `quantus exercise` — live-node smoke/fuzz suite for CI.

pub mod report;
pub mod runner;
pub mod scenarios;

use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	error::{QuantusError, Result},
	wallet::{DilithiumScheme, QuantumKeyPair},
};
use clap::Args;
use rand::SeedableRng;
use report::Report;
use runner::ExerciseCtx;
use std::path::PathBuf;

/// Divisor applied to every *discretionary* token amount the scenarios move (transfers, multisig
/// funding, …) so the suite runs on a small budget. Fixed, chain-imposed amounts (existential
/// deposit, recovery/multisig/vesting/governance deposits) are read from the chain and never
/// scaled — nor is the wormhole amount, which the chain puts a floor under.
pub(crate) const DISCRETIONARY_SCALE: u128 = 100;

/// Discretionary `test_unit`s an ephemeral account is expected to move across all phases. The
/// largest single draws are the dedicated-account fundings (20 each in balances, reversible and
/// multisig) and the fuzz loop, whose random amounts reach 100 `test_unit`s.
const TEST_UNITS_PER_ACCOUNT: u128 = 300;
/// Multisig proposals an ephemeral account makes across the run; each reserves a deposit
/// (returned on execute or cancel) and pays the proposal and multisig fees.
const MULTISIG_PROPOSALS_PER_ACCOUNT: u128 = 2;
/// Budget cap applied when `--total-amount` is not given.
const DEFAULT_TOTAL_AMOUNT: f64 = 500.0;

#[derive(Args, Debug)]
pub struct ExerciseArgs {
	/// Phases to run (default: all except upgrade; pass --upgrade-wasm to enable it).
	#[arg(long, value_delimiter = ',')]
	pub phases: Option<Vec<Phase>>,

	/// Phases to skip.
	#[arg(long, value_delimiter = ',')]
	pub skip: Option<Vec<Phase>>,

	#[arg(long, default_value_t = 25)]
	pub fuzz_iterations: u32,

	/// Reproducible fuzz seed (default: random).
	#[arg(long)]
	pub seed: Option<u64>,

	/// Candidate runtime WASM; enables the upgrade phase (fast-governance node only).
	#[arg(long)]
	pub upgrade_wasm: Option<PathBuf>,

	/// Self-upgrade smoke test: re-install the current on-chain runtime via
	/// `authorize_upgrade_without_checks` + `apply_authorized_upgrade` (the
	/// blob is too large for a referendum Lookup). Enables the upgrade phase;
	/// requires a fast-governance node. Does not re-run other phases afterwards
	/// (the runtime is unchanged).
	#[arg(long, conflicts_with = "upgrade_wasm")]
	pub self_upgrade: bool,

	#[arg(long, default_value_t = 900)]
	pub upgrade_timeout_secs: u64,

	#[arg(long, default_value_t = 4)]
	pub ephemeral_accounts: usize,

	/// Wallet name to fund the exercise from. Defaults to the built-in `crystal_alice` dev
	/// account (genesis-funded on `--dev` nodes). Supply a wallet of your own to run against
	/// a public testnet. The `governance` and `upgrade` phases always sign with the dev genesis
	/// accounts (skip them on chains where those are unfunded), and vesting's admin steps skip
	/// themselves when the chain's treasury is not the dev multisig.
	#[arg(long)]
	pub root_account: Option<String>,

	/// Password for the `--root-account` wallet (or set `QUANTUS_WALLET_PASSWORD_<NAME>`).
	#[arg(long)]
	pub root_password: Option<String>,

	/// Read the `--root-account` password from a file.
	#[arg(long)]
	pub root_password_file: Option<String>,

	/// Hard cap, in whole tokens, on what the run may draw from the root account (default 500).
	/// It is a ceiling, not an allocation: every root-paid transfer, deposit and estimated fee
	/// is reserved against it before submission, sweeps free it up again, and the run fails
	/// rather than exceeding it. Specifying it drops the `governance` phase (unless explicitly
	/// listed in --phases): its chain-fixed deposits dwarf any sensible cap and it is slow on
	/// live testnets. When `governance`/`upgrade` do run, their dev-account spend is exempt.
	#[arg(long)]
	pub total_amount: Option<f64>,

	#[arg(long)]
	pub fail_fast: bool,

	/// Emit the final report as JSON.
	#[arg(long)]
	pub json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Phase {
	Reads,
	Balances,
	Utility,
	Reversible,
	Multisig,
	Recovery,
	Preimage,
	Governance,
	Vesting,
	Negative,
	Fuzz,
	Wormhole,
	Upgrade,
}

impl Phase {
	fn default_set() -> Vec<Phase> {
		vec![
			Phase::Reads,
			Phase::Balances,
			Phase::Utility,
			Phase::Reversible,
			Phase::Multisig,
			Phase::Recovery,
			Phase::Preimage,
			Phase::Governance,
			Phase::Vesting,
			Phase::Negative,
			Phase::Fuzz,
			Phase::Wormhole,
		]
	}

	fn label(self) -> &'static str {
		match self {
			Phase::Reads => "reads",
			Phase::Balances => "balances",
			Phase::Utility => "utility",
			Phase::Reversible => "reversible",
			Phase::Multisig => "multisig",
			Phase::Recovery => "recovery",
			Phase::Preimage => "preimage",
			Phase::Governance => "governance",
			Phase::Vesting => "vesting",
			Phase::Negative => "negative",
			Phase::Fuzz => "fuzz",
			Phase::Wormhole => "wormhole",
			Phase::Upgrade => "upgrade",
		}
	}
}

pub async fn handle_exercise_command(args: ExerciseArgs, node_url: &str) -> Result<()> {
	let seed = args.seed.unwrap_or_else(rand::random);
	let mut selected = args.phases.clone().unwrap_or_else(Phase::default_set);
	if (args.upgrade_wasm.is_some() || args.self_upgrade) && !selected.contains(&Phase::Upgrade) {
		selected.push(Phase::Upgrade);
	}
	if let Some(skip) = &args.skip {
		selected.retain(|p| !skip.contains(p));
	}
	// A capped run drops governance: its chain-fixed deposits dwarf any sensible cap and it is
	// slow on live testnets. An explicit --phases listing overrides.
	let governance_dropped = args.total_amount.is_some() &&
		args.phases.is_none() &&
		selected.contains(&Phase::Governance);
	if governance_dropped {
		selected.retain(|p| *p != Phase::Governance);
	}
	if selected.contains(&Phase::Upgrade) && args.upgrade_wasm.is_none() && !args.self_upgrade {
		return Err(QuantusError::Generic(
			"the upgrade phase requires --upgrade-wasm <path> or --self-upgrade".to_string(),
		));
	}

	// Silence per-transaction CLI output; the exercise report owns the output.
	struct QuietGuard;
	impl Drop for QuietGuard {
		fn drop(&mut self) {
			crate::log::set_quiet(false);
		}
	}
	crate::log::set_quiet(true);
	let _quiet_guard = QuietGuard;

	crate::log_status!("🏋️  Quantus chain exercise suite");
	crate::log_status!("   Node: {node_url}");
	crate::log_status!("   Seed: {seed}");
	crate::log_status!(
		"   Phases: {}",
		selected.iter().map(|p| p.label()).collect::<Vec<_>>().join(", ")
	);

	let client = QuantusClient::new(node_url).await?;
	let (spec_version, _) = client.get_runtime_version().await?;
	let mut report = Report::new(node_url, seed, spec_version, args.fail_fast);
	if governance_dropped {
		report.record_skip(
			"governance",
			"phase",
			"dropped because --total-amount is set; pass --phases governance to force it",
		);
	}

	let mut ctx = match setup(client, node_url, seed, &args, &selected, &mut report).await {
		Ok(ctx) => ctx,
		Err(e) => {
			report.record("setup", "setup", std::time::Duration::ZERO, Err(e));
			finish(&report, &args)?;
			return Err(QuantusError::Generic("setup failed".to_string()));
		},
	};

	run_phases(&mut ctx, &mut report, &selected, "").await?;

	if selected.contains(&Phase::Upgrade) && !report.should_abort() {
		let mode = match args.upgrade_wasm.clone() {
			Some(wasm) => scenarios::upgrade::UpgradeMode::SetCode(wasm),
			None => scenarios::upgrade::UpgradeMode::SelfNoop,
		};
		let is_real_upgrade = matches!(mode, scenarios::upgrade::UpgradeMode::SetCode(_));
		let before = ctx.free_balance(&ctx.root_ss58).await?;
		scenarios::upgrade::run(&mut ctx, &mut report, "upgrade", mode, args.upgrade_timeout_secs)
			.await?;
		note_exempt_spend(&mut ctx, before).await?;

		// Only a real set_code upgrade changes the runtime; the self-upgrade
		// no-op re-installs the same blob, so a post-upgrade re-run would just
		// burn time without covering any new code path.
		if is_real_upgrade {
			let upgrade_ok = report
				.steps
				.iter()
				.filter(|s| s.phase == "upgrade")
				.all(|s| s.status == report::StepStatus::Passed);
			if upgrade_ok {
				crate::log_status!("🔁 Re-running phases against the upgraded runtime…");
				ctx.client = QuantusClient::new(node_url).await?;
				let rerun: Vec<Phase> =
					selected.iter().copied().filter(|p| *p != Phase::Upgrade).collect();
				run_phases(&mut ctx, &mut report, &rerun, "post-upgrade:").await?;
			} else {
				report.record_skip(
					"post-upgrade",
					"rerun",
					"skipped because the upgrade phase failed",
				);
			}
		}
	}

	let exempt_note = if ctx.budget_exempt > 0 {
		format!(" (plus {} exempt governance/upgrade spend)", ctx.budget_exempt)
	} else {
		String::new()
	};
	let spend = match ctx.budget_spent().await {
		Ok(spent) if spent > ctx.budget => Err(QuantusError::Generic(format!(
			"root account {} overspent: {spent} raw units drawn against the --total-amount cap \
			 of {}{exempt_note}",
			ctx.root_ss58, ctx.budget
		))),
		Ok(spent) => Ok(format!(
			"root account {} is down {spent} raw units of the {} allowed by \
			 --total-amount{exempt_note}",
			ctx.root_ss58, ctx.budget
		)),
		Err(e) => Err(e),
	};
	report.record("budget", "root_account_spend", std::time::Duration::ZERO, spend);

	finish(&report, &args)?;
	if report.has_failures() {
		return Err(QuantusError::Generic(format!(
			"{} exercise scenario(s) failed",
			report.count(report::StepStatus::Failed)
		)));
	}
	Ok(())
}

async fn run_phases(
	ctx: &mut ExerciseCtx,
	report: &mut Report,
	phases: &[Phase],
	prefix: &str,
) -> Result<()> {
	for phase in phases {
		if report.should_abort() {
			break;
		}
		let label = format!("{prefix}{}", phase.label());
		match phase {
			Phase::Reads => scenarios::reads::run(ctx, report, &label).await?,
			Phase::Balances => scenarios::balances::run(ctx, report, &label).await?,
			Phase::Utility => scenarios::utility::run(ctx, report, &label).await?,
			Phase::Reversible => scenarios::reversible::run(ctx, report, &label).await?,
			Phase::Multisig => scenarios::multisig::run(ctx, report, &label).await?,
			Phase::Recovery => scenarios::recovery::run(ctx, report, &label).await?,
			Phase::Preimage => scenarios::preimage::run(ctx, report, &label).await?,
			Phase::Governance => {
				let before = ctx.free_balance(&ctx.root_ss58).await?;
				scenarios::governance::run(ctx, report, &label).await?;
				note_exempt_spend(ctx, before).await?;
			},
			Phase::Vesting => scenarios::vesting::run(ctx, report, &label).await?,
			Phase::Negative => scenarios::negative::run(ctx, report, &label).await?,
			Phase::Fuzz => scenarios::fuzz::run(ctx, report, &label).await?,
			Phase::Wormhole => scenarios::wormhole::run(ctx, report, &label).await?,
			Phase::Upgrade => {},
		}
	}
	Ok(())
}

/// Exempt whatever the root account lost since `before` from the budget: the governance and
/// upgrade phases spend chain-fixed deposits the cap deliberately does not cover.
async fn note_exempt_spend(ctx: &mut ExerciseCtx, before: u128) -> Result<()> {
	let after = ctx.free_balance(&ctx.root_ss58).await?;
	ctx.budget_exempt = ctx.budget_exempt.saturating_add(before.saturating_sub(after));
	Ok(())
}

fn finish(report: &Report, args: &ExerciseArgs) -> Result<()> {
	report.render_summary();
	if args.json {
		println!("{}", report.render_json()?);
	}
	Ok(())
}

async fn setup(
	client: QuantusClient,
	node_url: &str,
	seed: u64,
	args: &ExerciseArgs,
	phases: &[Phase],
	report: &mut Report,
) -> Result<ExerciseCtx> {
	let started = std::time::Instant::now();

	let (symbol, decimals) = crate::cli::send::get_chain_properties(&client).await?;
	let unit = 10u128.pow(decimals as u32);
	let ed_addr = quantus_subxt::api::constants().balances().existential_deposit();
	let existential_deposit = client.client().constants().at(&ed_addr)?;

	let test_unit = unit / DISCRETIONARY_SCALE;

	// Dev genesis identities, kept distinct from the funding account: governance, upgrade and
	// the vesting treasury multisig are tied to them regardless of who funds the run.
	let alice = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::crystal_alice());
	let bob = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::dilithium_bob());
	let charlie = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::crystal_charlie());

	// Resolve the funding ("root") account. Defaults to dev Alice; a custom wallet can be
	// supplied for public-testnet runs.
	let (root, root_name) = match &args.root_account {
		Some(name) => {
			let password = crate::wallet::password::get_wallet_password(
				name,
				args.root_password.clone(),
				args.root_password_file.clone(),
			)?;
			let manager = crate::wallet::WalletManager::new()?;
			let wallet_data = manager.load_wallet(name, &password)?;
			(wallet_data.keypair.clone(), name.clone())
		},
		None => {
			// Dev scenarios load crystal_* wallets by name from disk.
			ensure_dev_wallets_on_disk().await?;
			(alice.clone(), "crystal_alice".to_string())
		},
	};

	let count = args.ephemeral_accounts.max(4);
	let total_tokens = args.total_amount.unwrap_or(DEFAULT_TOTAL_AMOUNT);
	let total_budget = (total_tokens * unit as f64).round() as u128;

	// The scaled discretionary base must stay above the existential deposit: the batch
	// scenario creates fresh accounts holding `test_unit / 2`, which would be reaped below ED.
	if test_unit == 0 || test_unit / 2 < existential_deposit {
		return Err(QuantusError::Generic(format!(
			"chain unit ({unit}) is too small relative to the existential deposit \
			 ({existential_deposit}) for the built-in test scale (÷{DISCRETIONARY_SCALE})"
		)));
	}

	// Fund each ephemeral account with what it actually needs — the deposits and fees the chain
	// charges it, plus its scaled discretionary spend — rather than a share of the budget, so
	// --total-amount stays a ceiling the run never has to reach.
	let constants = client.client().constants();
	let per_proposal = constants
		.at(&quantus_subxt::api::constants().multisig().proposal_deposit())?
		.saturating_add(constants.at(&quantus_subxt::api::constants().multisig().proposal_fee())?)
		.saturating_add(constants.at(&quantus_subxt::api::constants().multisig().multisig_fee())?);
	let funding_per_account = existential_deposit
		.saturating_mul(2)
		.saturating_add(test_unit.saturating_mul(TEST_UNITS_PER_ACCOUNT))
		.saturating_add(per_proposal.saturating_mul(MULTISIG_PROPOSALS_PER_ACCOUNT));
	let ephemeral_total = funding_per_account.saturating_mul(count as u128);
	if ephemeral_total > total_budget {
		return Err(QuantusError::Generic(format!(
			"--total-amount {total_tokens} is too low: funding {count} ephemeral accounts needs \
			 {ephemeral_total} raw units ({funding_per_account} each to cover pallet deposits \
			 and fees)"
		)));
	}
	let reserve = total_budget.saturating_sub(ephemeral_total);

	// Phases that fund dedicated accounts have to fit in what is left. `locked` never comes
	// back during the run and so accumulates; `returned` is swept back to the root account when
	// the phase ends, so only the largest of those has to fit at once. Checked here to fail in
	// setup with a number to act on rather than part-way through. Governance is absent: its
	// dev-account spend is exempt from the budget.
	let mut locked = 0u128;
	let mut returned = 0u128;
	let mut culprits: Vec<&str> = Vec::new();
	if phases.contains(&Phase::Vesting) &&
		scenarios::vesting::dev_treasury(&client, &alice, &bob, &charlie)
			.await?
			.is_some()
	{
		locked = locked.saturating_add(scenarios::vesting::treasury_funding(
			&client,
			test_unit,
			existential_deposit,
		)?);
		culprits.push("vesting");
	}
	if phases.contains(&Phase::Recovery) {
		let recovery =
			scenarios::recovery::account_funding(&client, existential_deposit, test_unit)?
				.saturating_mul(scenarios::recovery::LIFECYCLE_ACCOUNTS);
		returned = returned.max(recovery);
		culprits.push("recovery");
	}
	if phases.contains(&Phase::Wormhole) {
		returned = returned.max(scenarios::wormhole::required_funding(unit));
		culprits.push("wormhole");
	}
	let phase_needs = locked.saturating_add(returned);
	if reserve < phase_needs {
		return Err(QuantusError::Generic(format!(
			"--total-amount {total_tokens} leaves {reserve} raw units after funding the \
			 ephemeral accounts, but the {} phase(s) need {phase_needs} ({locked} held for the \
			 whole run, {returned} borrowed and swept back); raise --total-amount or skip phases",
			culprits.join("/")
		)));
	}

	// Preflight: fail early with a clear message if the funder can't pay, instead of a raw
	// "Inability to pay some fees" RPC rejection mid-run.
	let root_ss58 = root.try_to_account_id_ss58check()?;
	let root_balance = crate::cli::send::get_balance(&client, &root_ss58).await?;
	if root_balance < total_budget {
		return Err(QuantusError::Generic(format!(
			"root account {root_name} ({root_ss58}) holds {root_balance} raw units but \
			 --total-amount needs {total_budget}; fund it or lower --total-amount"
		)));
	}

	report.record(
		"setup",
		"connect_and_wallets",
		started.elapsed(),
		Ok(format!(
			"connected to {node_url}; token {symbol} ({decimals} decimals), ED {existential_deposit}; \
			 funder {root_name} ({root_balance} raw), budget {total_budget}: {funding_per_account} \
			 to each of {count} accounts, {reserve} reserve"
		)),
	);

	let started = std::time::Instant::now();
	let rng = rand::rngs::StdRng::seed_from_u64(seed);
	let mut ctx = ExerciseCtx {
		client,
		node_url: node_url.to_string(),
		root,
		alice,
		bob,
		charlie,
		eph: Vec::new(),
		root_ss58,
		root_start_balance: root_balance,
		budget: total_budget,
		budget_exempt: 0,
		unit,
		test_unit,
		existential_deposit,
		rng,
		seed,
		fuzz_iterations: args.fuzz_iterations,
	};

	let funding_result = fund_ephemeral_accounts(&mut ctx, count, funding_per_account).await;
	report.record("setup", "fund_ephemeral_accounts", started.elapsed(), funding_result);
	if report.has_failures() {
		return Err(QuantusError::Generic("setup failed while funding accounts".to_string()));
	}
	Ok(ctx)
}

async fn ensure_dev_wallets_on_disk() -> Result<()> {
	let manager = crate::wallet::WalletManager::new()?;
	for name in ["crystal_alice", "crystal_bob", "crystal_charlie"] {
		match manager.create_developer_wallet(name).await {
			Ok(_) => {},
			Err(crate::error::QuantusError::Wallet(crate::error::WalletError::AlreadyExists)) => {},
			Err(e) => return Err(e),
		}
	}
	Ok(())
}

async fn fund_ephemeral_accounts(
	ctx: &mut ExerciseCtx,
	count: usize,
	funding_per_account: u128,
) -> Result<String> {
	let mut addresses = Vec::with_capacity(count);
	let mut scheme_65 = 0usize;
	let mut scheme_87 = 0usize;
	// Alternate schemes so funded senders exercise both ML-DSA-65 and ML-DSA-87 signing.
	for i in 0..count {
		let scheme = if i % 2 == 0 { DilithiumScheme::MlDsa65 } else { DilithiumScheme::MlDsa87 };
		match scheme {
			DilithiumScheme::MlDsa65 => scheme_65 += 1,
			DilithiumScheme::MlDsa87 => scheme_87 += 1,
		}
		let keypair = ctx.fresh_keypair_with_scheme(scheme)?;
		addresses.push(keypair.try_to_account_id_ss58check()?);
		ctx.eph.push(keypair);
	}

	// Seeded keypairs are deterministic; assert on the funding delta, not absolute balance.
	let mut balances_before = Vec::with_capacity(count);
	for address in &addresses {
		balances_before.push(ctx.free_balance(address).await?);
	}

	let transfers: Vec<(String, u128)> =
		addresses.iter().map(|a| (a.clone(), funding_per_account)).collect();
	ctx.batch_fund_from_root(transfers).await?;

	let mut reused = 0usize;
	for (address, before) in addresses.iter().zip(&balances_before) {
		let after = ctx.free_balance(address).await?;
		let delta = after.saturating_sub(*before);
		if delta != funding_per_account {
			return Err(QuantusError::Generic(format!(
				"ephemeral account {address} balance went {before} -> {after} \
				 (delta {delta}), expected a funding delta of {funding_per_account}"
			)));
		}
		if *before > 0 {
			reused += 1;
		}
	}
	let note = if reused > 0 {
		format!(" ({reused} had leftover balances from a previous run with this seed)")
	} else {
		String::new()
	};
	Ok(format!(
		"derived and funded {count} ephemeral accounts with {funding_per_account} raw units each \
		 ({scheme_65}× ml-dsa-65, {scheme_87}× ml-dsa-87){note}"
	))
}
