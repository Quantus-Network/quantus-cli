//! Result collection and rendering for the exercise suite.

use colored::Colorize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
	Passed,
	Failed,
	Skipped,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
	pub phase: String,
	pub name: String,
	pub status: StepStatus,
	pub detail: String,
	pub duration_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct Report {
	pub node_url: String,
	pub seed: u64,
	pub spec_version: u32,
	pub steps: Vec<StepResult>,
	#[serde(skip)]
	pub fail_fast: bool,
}

impl Report {
	pub fn new(node_url: &str, seed: u64, spec_version: u32, fail_fast: bool) -> Self {
		Self { node_url: node_url.to_string(), seed, spec_version, steps: Vec::new(), fail_fast }
	}

	/// Record the outcome of a step. `Ok(detail)` marks it passed, `Err` failed.
	pub fn record(
		&mut self,
		phase: &str,
		name: &str,
		elapsed: std::time::Duration,
		result: crate::error::Result<String>,
	) {
		let (status, detail) = match result {
			Ok(detail) => (StepStatus::Passed, detail),
			Err(e) => (StepStatus::Failed, e.to_string()),
		};
		self.push(phase, name, status, detail, elapsed.as_millis());
	}

	pub fn record_skip(&mut self, phase: &str, name: &str, reason: &str) {
		self.push(phase, name, StepStatus::Skipped, reason.to_string(), 0);
	}

	fn push(&mut self, phase: &str, name: &str, status: StepStatus, detail: String, ms: u128) {
		let icon = match status {
			StepStatus::Passed => "✅",
			StepStatus::Failed => "❌",
			StepStatus::Skipped => "⏭️ ",
		};
		crate::log_status!(
			"{} [{}] {} — {} ({}ms)",
			icon,
			phase.bright_blue(),
			name.bold(),
			truncate(&detail, 160),
			ms
		);
		self.steps.push(StepResult {
			phase: phase.to_string(),
			name: name.to_string(),
			status,
			detail,
			duration_ms: ms,
		});
	}

	pub fn count(&self, status: StepStatus) -> usize {
		self.steps.iter().filter(|s| s.status == status).count()
	}

	pub fn has_failures(&self) -> bool {
		self.count(StepStatus::Failed) > 0
	}

	/// True when fail-fast is enabled and something already failed.
	pub fn should_abort(&self) -> bool {
		self.fail_fast && self.has_failures()
	}

	pub fn render_summary(&self) {
		let passed = self.count(StepStatus::Passed);
		let failed = self.count(StepStatus::Failed);
		let skipped = self.count(StepStatus::Skipped);

		crate::log_status!("");
		crate::log_status!("{}", "================ Exercise Summary ================".bold());
		crate::log_status!("   Node: {}   Seed: {}", self.node_url.bright_cyan(), self.seed);
		crate::log_status!(
			"   {} passed, {} failed, {} skipped ({} total)",
			passed.to_string().bright_green(),
			failed.to_string().bright_red(),
			skipped.to_string().bright_yellow(),
			self.steps.len()
		);
		if failed > 0 {
			crate::log_status!("");
			crate::log_status!("{}", "Failed steps:".bright_red().bold());
			for step in self.steps.iter().filter(|s| s.status == StepStatus::Failed) {
				crate::log_status!(
					"   ❌ [{}] {} — {}",
					step.phase.bright_blue(),
					step.name.bold(),
					truncate(&step.detail, 300)
				);
			}
		}
		crate::log_status!("{}", "==================================================".bold());
	}

	pub fn render_json(&self) -> crate::error::Result<String> {
		serde_json::to_string_pretty(self).map_err(Into::into)
	}
}

fn truncate(s: &str, max: usize) -> String {
	let single_line = s.replace('\n', " ");
	if single_line.chars().count() <= max {
		single_line
	} else {
		let cut: String = single_line.chars().take(max).collect();
		format!("{cut}…")
	}
}
