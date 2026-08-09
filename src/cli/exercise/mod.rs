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
			Phase::Vesting => scenarios::vesting::run(ctx, report, &label).await?,
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

	let alice = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::crystal_alice());
	let bob = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::dilithium_bob());
	let charlie = QuantumKeyPair::from_resonance_pair(&qp_dilithium_crypto::crystal_charlie());

	// Wormhole loads dev wallets by name from disk.
	ensure_dev_wallets_on_disk().await?;

	report.record(
		"setup",
		"connect_and_wallets",
		started.elapsed(),
		Ok(format!(
			"connected to {node_url}; token {symbol} ({decimals} decimals), ED {existential_deposit}"
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
		unit,
		existential_deposit,
		rng,
		seed,
		fuzz_iterations: args.fuzz_iterations,
	};

	let count = args.ephemeral_accounts.max(4);
	let funding_result = fund_ephemeral_accounts(&mut ctx, count).await;
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

async fn fund_ephemeral_accounts(ctx: &mut ExerciseCtx, count: usize) -> Result<String> {
	let funding_per_account = 1_000 * ctx.unit;
	let mut addresses = Vec::with_capacity(count);
	let mut scheme_65 = 0usize;
	let mut scheme_87 = 0usize;
	// Alternate schemes so funded senders exercise both ML-DSA-65 and ML-DSA-87 signing.
	for i in 0..count {
		let scheme =
			if i % 2 == 0 { DilithiumScheme::MlDsa65 } else { DilithiumScheme::MlDsa87 };
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
		"derived and funded {count} ephemeral accounts with 1000 tokens each \
		 ({scheme_65}× ml-dsa-65, {scheme_87}× ml-dsa-87){note}"
	))
}
