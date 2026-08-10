//! Wormhole multiround smoke test (CPU-heavy; use `--skip wormhole` on debug builds).

use crate::{
	cli::exercise::{report::Report, runner::ExerciseCtx},
	error::{QuantusError, Result},
	exercise_step,
	wallet::{DilithiumScheme, WalletManager},
};

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

async fn multiround(ctx: &mut ExerciseCtx, scheme: DilithiumScheme, public: bool) -> Result<String> {
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
			crate::wallet::DEFAULT_DERIVATION_PATH,
			scheme,
		)
		.await?;

	let run_result = async {
		let funding = 500 * ctx.unit;
		crate::cli::send::transfer(
			&ctx.client,
			&ctx.alice,
			&info.address,
			funding,
			None,
			ctx.wait_mode(),
		)
		.await?;
		run_multiround_command(ctx, &wallet_name, scheme, public).await
	}
	.await;

	let delete_result = manager.delete_wallet(&wallet_name);
	match (run_result, delete_result) {
		(Ok(msg), Ok(_)) => Ok(msg),
		(Ok(_), Err(e)) => Err(QuantusError::Generic(format!(
			"wormhole exercise succeeded but failed to delete wallet {wallet_name}: {e}"
		))),
		(Err(e), Ok(_)) => Err(e),
		(Err(e), Err(del_e)) => Err(QuantusError::Generic(format!(
			"{e}; also failed to delete exercise wallet {wallet_name}: {del_e}"
		))),
	}
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
		amount: 50.0,
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
