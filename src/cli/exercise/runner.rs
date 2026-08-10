//! Shared context and helpers for exercise scenarios.

use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::common::{ExecutionMode, SubxtAccountId32},
	error::{QuantusError, Result},
	wallet::{DilithiumScheme, QuantumKeyPair},
};
use rand::{rngs::StdRng, Rng};

pub struct ExerciseCtx {
	pub client: QuantusClient,
	pub node_url: String,
	/// Funding account the whole budget is drawn from (`--root-account`, default dev Alice).
	pub root: QuantumKeyPair,
	/// Dev genesis identities; the governance, upgrade and vesting-admin flows need them
	/// regardless of which account funds the run.
	pub alice: QuantumKeyPair,
	pub bob: QuantumKeyPair,
	pub charlie: QuantumKeyPair,
	pub eph: Vec<QuantumKeyPair>,
	/// SS58 of the root (funding) account.
	pub root_ss58: String,
	/// Root balance at the start of the run; spend is measured as the drop from it.
	pub root_start_balance: u128,
	/// `--total-amount` in raw units: the hard cap on what the run may draw from the root
	/// account. Anything swept back frees the budget up again.
	pub budget: u128,
	/// Root spend excluded from the cap: the governance and upgrade phases run on chain-fixed
	/// deposits far beyond any sensible cap, so their draw is measured and exempted.
	pub budget_exempt: u128,
	/// One whole token in raw units. Only for the wormhole amount, which the chain puts a floor
	/// under; everything else is either a chain constant or scaled to `test_unit`.
	pub unit: u128,
	/// Scaled-down base for discretionary test amounts (`unit / DISCRETIONARY_SCALE`) spent by
	/// the budgeted ephemeral accounts. Fixed chain amounts (existential deposit, pallet
	/// deposits) are never derived from this.
	pub test_unit: u128,
	pub existential_deposit: u128,
	pub rng: StdRng,
	pub seed: u64,
	pub fuzz_iterations: u32,
}

impl ExerciseCtx {
	pub fn wait_mode(&self) -> ExecutionMode {
		ExecutionMode { finalized: false, wait_for_transaction: true }
	}

	/// Raw units drawn from the root account so far, net of anything swept back to it and of
	/// the exempt governance/upgrade draw. Fees the root account pays and deposits it has
	/// reserved count as spend.
	pub async fn budget_spent(&self) -> Result<u128> {
		let current = self.free_balance(&self.root_ss58).await?;
		Ok(self.root_start_balance.saturating_sub(current).saturating_sub(self.budget_exempt))
	}

	/// Refuse to draw more than `--total-amount` from the root account. Fails here, with the
	/// numbers, rather than mid-scenario on an "Inability to pay some fees" rejection.
	pub async fn reserve(&self, amount: u128) -> Result<()> {
		let spent = self.budget_spent().await?;
		if spent.saturating_add(amount) > self.budget {
			return Err(QuantusError::Generic(format!(
				"--total-amount exhausted: {spent} of {} raw units already drawn from the root \
				 account and this step needs {amount} more; raise --total-amount or skip phases",
				self.budget
			)));
		}
		Ok(())
	}

	/// Submit `call` signed by `from`. When `from` is the root account, the estimated fee plus
	/// `reserved` (the value and deposits the call will draw from it) is reserved against the
	/// budget first, keeping `--total-amount` a hard cap.
	pub async fn submit_budgeted<Call>(
		&self,
		from: &QuantumKeyPair,
		call: Call,
		reserved: u128,
	) -> Result<subxt::utils::H256>
	where
		Call: subxt::tx::Payload,
	{
		if from.try_to_account_id_ss58check()? == self.root_ss58 {
			let fee =
				crate::cli::send::estimate_transaction_partial_fee(&self.client, from, &call, None)
					.await?;
			self.reserve(reserved.saturating_add(fee)).await?;
		}
		submit_ok(self, from, call).await
	}

	/// Root-signed submission with fee and `reserved` charged against the run budget.
	pub async fn submit_from_root<Call>(
		&self,
		call: Call,
		reserved: u128,
	) -> Result<subxt::utils::H256>
	where
		Call: subxt::tx::Payload,
	{
		self.submit_budgeted(&self.root, call, reserved).await
	}

	/// Transfer from the root account against the run budget.
	pub async fn fund_from_root(&self, dest_ss58: &str, amount: u128) -> Result<()> {
		self.batch_fund_from_root(vec![(dest_ss58.to_string(), amount)]).await
	}

	/// Batched [`Self::fund_from_root`], charged against the budget (with its fee) as one total.
	pub async fn batch_fund_from_root(&self, transfers: Vec<(String, u128)>) -> Result<()> {
		let total = transfers.iter().map(|(_, amount)| amount).sum();
		let call = crate::cli::send::build_batch_transfer_call(&transfers)?;
		self.submit_from_root(call, total).await?;
		Ok(())
	}

	/// Empty `who` back into the root account, returning what it held to the budget. Reaps the
	/// account, so only call it once the scenario is done with it.
	pub async fn sweep_to_root(&self, who: &QuantumKeyPair) -> Result<()> {
		// Nothing to give back — the account was never funded, or a failed step already emptied
		// it. `transfer_all` would only fail on a non-existent account.
		if self.free_balance(&who.try_to_account_id_ss58check()?).await? == 0 {
			return Ok(());
		}
		let call = quantus_subxt::api::tx().balances().transfer_all(
			subxt::ext::subxt_core::utils::MultiAddress::Id(account_id_of(&self.root)?),
			false,
		);
		submit_ok(self, who, call).await?;
		Ok(())
	}

	/// Fresh keypair using an explicit Dilithium scheme.
	pub fn fresh_keypair_with_scheme(&mut self, scheme: DilithiumScheme) -> Result<QuantumKeyPair> {
		let seed: [u8; 32] = self.rng.random();
		match scheme {
			DilithiumScheme::MlDsa65 => {
				let pair =
					qp_dilithium_crypto::types::Dilithium65Pair::from_seed(&seed).map_err(|e| {
						QuantusError::Generic(format!("Failed to derive keypair: {e:?}"))
					})?;
				Ok(QuantumKeyPair::from_dilithium65_pair(&pair))
			},
			DilithiumScheme::MlDsa87 => {
				let pair =
					qp_dilithium_crypto::types::Dilithium87Pair::from_seed(&seed).map_err(|e| {
						QuantusError::Generic(format!("Failed to derive keypair: {e:?}"))
					})?;
				Ok(QuantumKeyPair::from_resonance_pair(&pair))
			},
		}
	}

	/// Fresh keypair alternating schemes from the seed bytes (both 65 and 87 get exercise
	/// coverage).
	pub fn fresh_keypair(&mut self) -> Result<QuantumKeyPair> {
		let seed: [u8; 32] = self.rng.random();
		let scheme = if seed[0].is_multiple_of(2) {
			DilithiumScheme::MlDsa65
		} else {
			DilithiumScheme::MlDsa87
		};
		match scheme {
			DilithiumScheme::MlDsa65 => {
				let pair =
					qp_dilithium_crypto::types::Dilithium65Pair::from_seed(&seed).map_err(|e| {
						QuantusError::Generic(format!("Failed to derive keypair: {e:?}"))
					})?;
				Ok(QuantumKeyPair::from_dilithium65_pair(&pair))
			},
			DilithiumScheme::MlDsa87 => {
				let pair =
					qp_dilithium_crypto::types::Dilithium87Pair::from_seed(&seed).map_err(|e| {
						QuantusError::Generic(format!("Failed to derive keypair: {e:?}"))
					})?;
				Ok(QuantumKeyPair::from_resonance_pair(&pair))
			},
		}
	}

	pub async fn free_balance(&self, ss58: &str) -> Result<u128> {
		crate::cli::send::get_balance(&self.client, ss58).await
	}
}

pub fn account_id_of(keypair: &QuantumKeyPair) -> Result<SubxtAccountId32> {
	let account = keypair.try_to_account_id_32()?;
	let bytes: [u8; 32] = *account.as_ref();
	Ok(SubxtAccountId32::from(bytes))
}

pub async fn submit_ok<Call>(
	ctx: &ExerciseCtx,
	from: &QuantumKeyPair,
	call: Call,
) -> Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	crate::cli::common::submit_transaction(&ctx.client, from, call, None, ctx.wait_mode()).await
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
	match crate::cli::common::submit_transaction(&ctx.client, from, call, None, ctx.wait_mode())
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
