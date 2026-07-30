//! Shared context and helpers for exercise scenarios.

use crate::{
	chain::client::QuantusClient,
	cli::common::{ExecutionMode, SubxtAccountId32},
	error::{QuantusError, Result},
	wallet::QuantumKeyPair,
};
use rand::{rngs::StdRng, Rng};

pub struct ExerciseCtx {
	pub client: QuantusClient,
	pub node_url: String,
	pub alice: QuantumKeyPair,
	pub bob: QuantumKeyPair,
	pub charlie: QuantumKeyPair,
	pub eph: Vec<QuantumKeyPair>,
	pub unit: u128,
	pub existential_deposit: u128,
	pub rng: StdRng,
	pub seed: u64,
	pub fuzz_iterations: u32,
}

impl ExerciseCtx {
	pub fn wait_mode(&self) -> ExecutionMode {
		ExecutionMode { finalized: false, wait_for_transaction: true }
	}

	pub fn fresh_keypair(&mut self) -> Result<QuantumKeyPair> {
		let seed: [u8; 32] = self.rng.random();
		let pair = qp_dilithium_crypto::types::DilithiumPair::from_seed(&seed)
			.map_err(|e| QuantusError::Generic(format!("Failed to derive keypair: {e:?}")))?;
		Ok(QuantumKeyPair::from_resonance_pair(&pair))
	}

	pub async fn free_balance(&self, ss58: &str) -> Result<u128> {
		crate::cli::send::get_balance(&self.client, ss58).await
	}
}

pub fn account_id_of(keypair: &QuantumKeyPair) -> SubxtAccountId32 {
	let account = keypair.to_account_id_32();
	let bytes: [u8; 32] = *account.as_ref();
	SubxtAccountId32::from(bytes)
}

pub async fn submit_ok<Call>(
	ctx: &ExerciseCtx,
	from: &QuantumKeyPair,
	call: Call,
) -> Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	crate::cli::common::submit_transaction(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(from.clone()),
		call,
		None,
		ctx.wait_mode(),
	)
	.await
}

pub async fn submit_expect_failure<Call>(
	ctx: &ExerciseCtx,
	from: &QuantumKeyPair,
	call: Call,
	expected_fragments: &[&str],
) -> Result<String>
where
	Call: subxt::tx::Payload,
{
	match crate::cli::common::submit_transaction(
		&ctx.client,
		&crate::wallet::WalletSigner::Hot(from.clone()),
		call,
		None,
		ctx.wait_mode(),
	)
	.await
	{
		Ok(hash) => Err(QuantusError::Generic(format!(
			"expected rejection but transaction succeeded ({hash:?})"
		))),
		Err(e) => {
			let msg = e.to_string();
			if expected_fragments.is_empty() ||
				expected_fragments.iter().any(|frag| msg.contains(frag))
			{
				Ok(format!("rejected as expected: {}", first_line(&msg)))
			} else {
				Err(QuantusError::Generic(format!(
					"rejected with unexpected error (wanted one of {expected_fragments:?}): {msg}"
				)))
			}
		},
	}
}

fn first_line(msg: &str) -> &str {
	msg.lines().next().unwrap_or(msg)
}

#[macro_export]
macro_rules! exercise_step {
	($report:expr, $phase:expr, $name:expr, $fut:expr) => {{
		let __started = std::time::Instant::now();
		let __result = $fut.await;
		$report.record($phase, $name, __started.elapsed(), __result);
		if $report.should_abort() {
			return Ok(());
		}
	}};
}
