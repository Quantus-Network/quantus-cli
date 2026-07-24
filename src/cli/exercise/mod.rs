//! `quantus exercise` — live-node smoke/fuzz suite for CI.

pub mod report;
pub mod runner;
pub mod scenarios;

use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	error::{QuantusError, Result},
	wallet::QuantumKeyPair,
};
use clap::Args;
use rand::SeedableRng;
use report::Report;
use runner::ExerciseCtx;
use std::path::PathBuf;

/// Divisor applied to every *discretionary* token amount used by the scenarios (transfers,
/// multisig funding, wormhole amount, …) so the suite can run on a small budget. Fixed,
/// chain-imposed amounts (existential deposit, multisig/preimage/governance deposits) are
/// read from the chain and never scaled.
pub(crate) const DISCRETIONARY_SCALE: u128 = 100;

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

	#[arg(long, default_value_t = 900)]
	pub upgrade_timeout_secs: u64,

	#[arg(long, default_value_t = 4)]
	pub ephemeral_accounts: usize,

	/// Wallet name to fund the exercise from. Defaults to the built-in `crystal_alice` dev
	/// account (genesis-funded on `--dev` nodes). Supply a wallet of your own to run against
	/// a public testnet. The `governance` phase still relies on the dev genesis accounts, so
	/// pass `--skip governance` when using a custom root account.
	#[arg(long)]
	pub root_account: Option<String>,

	/// Password for the `--root-account` wallet (or set `QUANTUS_WALLET_PASSWORD_<NAME>`).
	#[arg(long)]
	pub root_password: Option<String>,

	/// Read the `--root-account` password from a file.
	#[arg(long)]
	pub root_password_file: Option<String>,

	/// Total budget, in whole tokens, drawn from the root account to fund the ephemeral test
	/// accounts (split evenly across them). Fixed chain deposits (existential deposit,
	/// multisig/preimage deposits) are covered on top and are not scaled; discretionary test
	/// transfers are scaled down internally so a small budget suffices.
	#[arg(long, default_value_t = 40.0)]
	pub total_amount: f64,

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
	Reversible,
	Multisig,
	Recovery,
	Preimage,
	Governance,
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
			Phase::Reversible,
			Phase::Multisig,
			Phase::Recovery,
			Phase::Preimage,
			Phase::Governance,
			Phase::Negative,
			Phase::Fuzz,
			Phase::Wormhole,
		]
	}

	fn label(self) -> &'static str {
		match self {
			Phase::Reads => "reads",
			Phase::Balances => "balances",
			Phase::Reversible => "reversible",
			Phase::Multisig => "multisig",
			Phase::Recovery => "recovery",
			Phase::Preimage => "preimage",
			Phase::Governance => "governance",
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
	if args.upgrade_wasm.is_some() && !selected.contains(&Phase::Upgrade) {
		selected.push(Phase::Upgrade);
	}
	if let Some(skip) = &args.skip {
		selected.retain(|p| !skip.contains(p));
	}
	if selected.contains(&Phase::Upgrade) && args.upgrade_wasm.is_none() {
		return Err(QuantusError::Generic(
			"the upgrade phase requires --upgrade-wasm <path>".to_string(),
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

	let mut ctx = match setup(client, node_url, seed, &args, &mut report).await {
		Ok(ctx) => ctx,
		Err(e) => {
			report.record("setup", "setup", std::time::Duration::ZERO, Err(e));
			finish(&report, &args)?;
			return Err(QuantusError::Generic("setup failed".to_string()));
		},
	};

	run_phases(&mut ctx, &mut report, &selected, "").await?;

	if selected.contains(&Phase::Upgrade) && !report.should_abort() {
		let wasm = args.upgrade_wasm.clone().expect("checked above");
		scenarios::upgrade::run(&mut ctx, &mut report, "upgrade", &wasm, args.upgrade_timeout_secs)
			.await?;

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
			report.record_skip("post-upgrade", "rerun", "skipped because the upgrade phase failed");
		}
	}

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
			Phase::Reversible => scenarios::reversible::run(ctx, report, &label).await?,
			Phase::Multisig => scenarios::multisig::run(ctx, report, &label).await?,
			Phase::Recovery => scenarios::recovery::run(ctx, report, &label).await?,
			Phase::Preimage => scenarios::preimage::run(ctx, report, &label).await?,
			Phase::Governance => scenarios::governance::run(ctx, report, &label).await?,
			Phase::Negative => scenarios::negative::run(ctx, report, &label).await?,
			Phase::Fuzz => scenarios::fuzz::run(ctx, report, &label).await?,
			Phase::Wormhole => scenarios::wormhole::run(ctx, report, &label).await?,
			Phase::Upgrade => {},
		}
	}
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
	report: &mut Report,
) -> Result<ExerciseCtx> {
	let started = std::time::Instant::now();

	let (symbol, decimals) = crate::cli::send::get_chain_properties(&client).await?;
	let unit = 10u128.pow(decimals as u32);
	let ed_addr = quantus_subxt::api::constants().balances().existential_deposit();
	let existential_deposit = client.client().constants().at(&ed_addr)?;

	let test_unit = unit / DISCRETIONARY_SCALE;

	let bob = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::dilithium_bob());
	let charlie = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::crystal_charlie());

	// Resolve the funding ("root") account. Defaults to the built-in crystal_alice dev
	// account; a custom wallet can be supplied for public-testnet runs.
	let (alice, root_name, root_password) = match &args.root_account {
		Some(name) => {
			let password = crate::wallet::password::get_wallet_password(
				name,
				args.root_password.clone(),
				args.root_password_file.clone(),
			)?;
			let manager = crate::wallet::WalletManager::new()?;
			let wallet_data = manager.load_wallet(name, &password)?;
			(wallet_data.keypair, name.clone(), password)
		},
		None => {
			// Wormhole loads the dev wallet by name from disk.
			ensure_dev_wallets_on_disk().await?;
			(
				QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::crystal_alice()),
				"crystal_alice".to_string(),
				String::new(),
			)
		},
	};

	let count = args.ephemeral_accounts.max(4);
	let total_budget = (args.total_amount * unit as f64).round() as u128;
	let funding_per_account = total_budget.checked_div(count as u128).unwrap_or(0);

	// The scaled discretionary base must stay above the existential deposit: the batch
	// scenario creates fresh accounts holding `test_unit / 2`, which would be reaped below ED.
	if test_unit == 0 || test_unit / 2 < existential_deposit {
		return Err(QuantusError::Generic(format!(
			"chain unit ({unit}) is too small relative to the existential deposit \
			 ({existential_deposit}) for the built-in test scale (÷{DISCRETIONARY_SCALE})"
		)));
	}
	// Each ephemeral account must also cover fixed deposits (multisig, preimage) plus its
	// scaled discretionary spend and fees. Guard against an obviously-too-small budget.
	let min_per_account = existential_deposit
		.saturating_mul(2)
		.saturating_add(test_unit.saturating_mul(30));
	if funding_per_account < min_per_account {
		return Err(QuantusError::Generic(format!(
			"--total-amount {} is too low: only {funding_per_account} raw units per account \
			 across {count} accounts (need at least {min_per_account} each to cover deposits)",
			args.total_amount
		)));
	}

	// Preflight: fail early with a clear message if the funder can't pay, instead of a raw
	// "Inability to pay some fees" RPC rejection mid-run.
	let root_ss58 = alice.to_account_id_ss58check();
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
			 funder {root_name} ({root_balance} raw), funding {count} accounts with {funding_per_account} each"
		)),
	);

	let started = std::time::Instant::now();
	let rng = rand::rngs::StdRng::seed_from_u64(seed);
	let mut ctx = ExerciseCtx {
		client,
		node_url: node_url.to_string(),
		alice,
		bob,
		charlie,
		eph: Vec::new(),
		test_unit,
		existential_deposit,
		root_name,
		root_password,
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
	for _ in 0..count {
		let keypair = ctx.fresh_keypair()?;
		addresses.push(keypair.to_account_id_ss58check());
		ctx.eph.push(keypair);
	}

	// Seeded keypairs are deterministic; assert on the funding delta, not absolute balance.
	let mut balances_before = Vec::with_capacity(count);
	for address in &addresses {
		balances_before.push(ctx.free_balance(address).await?);
	}

	let transfers: Vec<(String, u128)> =
		addresses.iter().map(|a| (a.clone(), funding_per_account)).collect();
	crate::cli::send::batch_transfer(
		&ctx.client,
		&ctx.alice.clone(),
		transfers,
		None,
		ctx.wait_mode(),
	)
	.await?;

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
		"derived and funded {count} ephemeral accounts with {funding_per_account} raw units each{note}"
	))
}
