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
	let command = crate::cli::wormhole::WormholeCommands::Multiround {
		num_proofs: 5,
		rounds: 5,
		amount: 50.0,
		wallet: "crystal_alice".to_string(),
		password: Some(String::new()),
		password_file: None,
		keep_files: false,
		output_dir: "/tmp/wormhole_exercise".to_string(),
		dry_run: false,
	};
	crate::cli::wormhole::handle_wormhole_command(command, &ctx.node_url).await?;
	Ok("wormhole multiround (5 rounds, 5 proofs each) completed".to_string())
}
