//! Wormhole multiround smoke test (CPU-heavy; use `--skip wormhole` on debug builds).

use crate::{
	cli::exercise::{report::Report, runner::ExerciseCtx},
	error::Result,
	exercise_step,
};

pub async fn run(ctx: &mut ExerciseCtx, report: &mut Report, phase: &str) -> Result<()> {
	exercise_step!(report, phase, "multiround", multiround(ctx));
	Ok(())
}

async fn multiround(ctx: &mut ExerciseCtx) -> Result<String> {
	// NOT scaled by DISCRETIONARY_SCALE: the wormhole round-trips this amount back to the
	// funding wallet and draws it from the root account (funded independently of
	// --total-amount), so shrinking it buys nothing. Small amounts are actively harmful —
	// each round re-partitions across `num_proofs` and deducts fees, so a scaled-down amount
	// rounds an output below the on-chain minimum in a later round and emits no transfer
	// event ("No transfer event found"). 50 DEV is the proven value.
	let command = crate::cli::wormhole::WormholeCommands::Multiround {
		num_proofs: 5,
		rounds: 5,
		amount: 50.0,
		wallet: ctx.root_name.clone(),
		password: Some(ctx.root_password.clone()),
		password_file: None,
		keep_files: false,
		output_dir: "/tmp/wormhole_exercise".to_string(),
		dry_run: false,
		public: false,
	};
	crate::cli::wormhole::handle_wormhole_command(command, &ctx.node_url).await?;
	Ok("wormhole multiround (5 rounds, 5 proofs each) completed".to_string())
}
