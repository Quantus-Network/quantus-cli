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
	// Round-trips a small amount through the bridge and back; scaled like the other
	// discretionary amounts so the suite stays cheap.
	let amount = 50.0 / crate::cli::exercise::DISCRETIONARY_SCALE as f64;
	let command = crate::cli::wormhole::WormholeCommands::Multiround {
		num_proofs: 5,
		rounds: 5,
		amount,
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
