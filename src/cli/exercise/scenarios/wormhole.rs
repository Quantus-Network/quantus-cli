//! Wormhole multiround smoke test (CPU-heavy; use `--skip wormhole` on debug builds).

use crate::{
	cli::exercise::{report::Report, runner::ExerciseCtx},
	error::{QuantusError, Result},
	exercise_step,
	wallet::{DilithiumScheme, WalletManager},
};

/// Whole tokens the multiround partitions across its proofs. Not scaled by
/// `DISCRETIONARY_SCALE`: each round re-partitions the amount across `num_proofs` and deducts
/// fees, so a scaled-down amount rounds an output below the on-chain minimum in a later round
/// and emits no transfer event. The amount exits back to the wallet and is swept to the root
/// account afterwards, so the run only borrows it.
const MULTIROUND_AMOUNT_TOKENS: f64 = 50.0;

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	// Split the two runs across both signature schemes *and* both wormhole
	// extrinsics: the private run submits Wormhole::verify_private_batch, the
	// public run wraps each round in a public batch and submits
	// Wormhole::verify_public_batch.
	exercise_step!(
		report,
		phase,
		"multiround_private_ml_dsa_65",
		multiround(ctx, DilithiumScheme::MlDsa65, false)
	);
	exercise_step!(
		report,
		phase,
		"multiround_public_ml_dsa_87",
		multiround(ctx, DilithiumScheme::MlDsa87, true)
	);
	Ok(())
}

async fn multiround(
	ctx: &mut ExerciseCtx,
	scheme: DilithiumScheme,
	public: bool,
) -> Result<String> {
	// Dev wallets (crystal_*) have no mnemonic; wormhole HD derivation requires one.
	let wallet_name = format!("exercise_wormhole_{}_{}", scheme, ctx.seed);
	let manager = WalletManager::new()?;
	// Clear leftovers from a previous interrupted run (Ok(false) if absent).
	manager.delete_wallet(&wallet_name).map_err(|e| {
		QuantusError::Generic(format!(
			"failed to clear leftover exercise wallet {wallet_name}: {e}"
		))
	})?;

	let info = manager
		.create_wallet_with_scheme(
			&wallet_name,
			None,
			crate::wallet::default_derivation_path(scheme),
			scheme,
		)
		.await?;

	let run_result = async {
		ctx.fund_from_root(&info.address, required_funding(ctx.unit)).await?;
		run_multiround_command(ctx, &wallet_name, scheme, public).await
	}
	.await;

	// The multiround exits back to this wallet, so return what is left to the root account
	// before the wallet is deleted — otherwise the funding is stranded and the budget is gone.
	let sweep_result = async {
		let wallet = manager.load_wallet(&wallet_name, "")?;
		ctx.sweep_to_root(&wallet.keypair).await
	}
	.await;
	let run_result = combine(run_result, sweep_result, "failed to sweep the exercise wallet");

	let delete_result = manager.delete_wallet(&wallet_name).map(|_| ());
	combine(run_result, delete_result, &format!("failed to delete exercise wallet {wallet_name}"))
}

/// Keep `primary`'s outcome, but never lose a cleanup failure.
fn combine(primary: Result<String>, cleanup: Result<()>, what: &str) -> Result<String> {
	match (primary, cleanup) {
		(Ok(msg), Ok(())) => Ok(msg),
		(Ok(_), Err(e)) =>
			Err(QuantusError::Generic(format!("wormhole exercise succeeded but {what}: {e}"))),
		(Err(e), Ok(())) => Err(e),
		(Err(e), Err(cleanup_err)) =>
			Err(QuantusError::Generic(format!("{e}; also {what}: {cleanup_err}"))),
	}
}

/// Raw units the wormhole wallet has to hold: the multiround amount plus headroom for the
/// per-round haircut and the transaction fees of every round.
pub fn required_funding(unit: u128) -> u128 {
	((MULTIROUND_AMOUNT_TOKENS * unit as f64) as u128).saturating_add(2 * unit)
}

async fn run_multiround_command(
	ctx: &ExerciseCtx,
	wallet_name: &str,
	scheme: DilithiumScheme,
	public: bool,
) -> Result<String> {
	let command = crate::cli::wormhole::WormholeCommands::Multiround {
		num_proofs: 5,
		rounds: 5,
		amount: MULTIROUND_AMOUNT_TOKENS,
		wallet: wallet_name.to_string(),
		password: None,
		password_file: None,
		keep_files: false,
		output_dir: format!("/tmp/wormhole_exercise_{}_{}", scheme, ctx.seed),
		dry_run: false,
		public,
	};
	crate::cli::wormhole::handle_wormhole_command(command, &ctx.node_url, ctx.wait_mode()).await?;
	let extrinsic = if public { "verify_public_batch" } else { "verify_private_batch" };
	Ok(format!("wormhole multiround ({scheme}; 5 rounds, 5 proofs each, {extrinsic}) completed"))
}
