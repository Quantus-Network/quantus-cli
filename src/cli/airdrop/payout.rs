//! Operator side of the airdrop: pull unpaid recorded claims into a manifest,
//! review and approve it, pay it as one atomic `utility.batch_all`, then mark
//! every reward paid on the claim server. Each step is its own command and the
//! manifest file carries the state between them.

use super::{
	format_hundredths, format_server_error, get_json, http_client, http_err, now_unix,
	parse_account_id,
};
use crate::{
	chain::client::QuantusClient,
	cli::{
		cold_signing::{MAX_COLD_PAYLOAD, MORTALITY_BLOCKS},
		common::{self, ExecutionMode},
		send, wormhole,
	},
	error::{QuantusError, Result},
	log_error, log_print, log_success, log_verbose,
	wallet::{self, password, WalletSigner},
};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::{
	collections::{BTreeMap, HashMap},
	path::{Path, PathBuf},
};
use subxt::tx::Payload;

const MANIFEST_VERSION: u32 = 1;
const ADMIN_TOKEN_ENV: &str = "AIRDROP_ADMIN_TOKEN";
const RECORDED: &str = "recorded";
/// Transaction extensions added to the call bytes in a cold-wallet payload.
const COLD_PAYLOAD_OVERHEAD: usize = 128;
/// The submit path anchors its mortality a few blocks after `Payment::anchor_block`
/// is recorded; recovery only declares a batch expired past this extra margin.
const ANCHOR_SLACK_BLOCKS: u64 = 16;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum State {
	Pulled,
	Approved,
	Paying,
	Paid,
	Marked,
}

impl State {
	fn label(self) -> &'static str {
		match self {
			Self::Pulled => "pulled",
			Self::Approved => "approved",
			Self::Paying => "paying",
			Self::Paid => "paid",
			Self::Marked => "marked",
		}
	}

	fn next_step(self) -> &'static str {
		match self {
			Self::Pulled => "approve it with `quantus airdrop review --approve`",
			Self::Approved => "pay it with `quantus airdrop pay`",
			Self::Paying => "run `quantus airdrop pay --recover` to learn whether the batch landed",
			Self::Paid => "run `quantus airdrop mark-paid`",
			Self::Marked => "it is finished",
		}
	}
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Reward {
	address: String,
	amount_hundredths: u64,
}

/// One `transfer_allow_death` in the batch: every reward claimed to the same account.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
struct Transfer {
	to: String,
	amount_hundredths: u64,
	rewards: Vec<Reward>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Payment {
	signer: String,
	nonce: u64,
	anchor_block: u64,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	tx_hash: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	block_hash: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	paid_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Manifest {
	version: u32,
	server: String,
	pulled_at: i64,
	state: State,
	total_hundredths: u64,
	transfers: Vec<Transfer>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	approved_sha256: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	payment: Option<Payment>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	marked: Vec<String>,
}

impl Manifest {
	fn load(path: &Path) -> Result<Self> {
		let text = std::fs::read_to_string(path)
			.map_err(|e| QuantusError::Generic(format!("read manifest {}: {e}", path.display())))?;
		let manifest: Self = serde_json::from_str(&text).map_err(|e| {
			QuantusError::Generic(format!("parse manifest {}: {e}", path.display()))
		})?;
		if manifest.version != MANIFEST_VERSION {
			return Err(QuantusError::Generic(format!(
				"manifest {} is version {}, this CLI writes version {MANIFEST_VERSION}",
				path.display(),
				manifest.version
			)));
		}
		Ok(manifest)
	}

	/// Temp write + rename: a crash never leaves a truncated manifest behind.
	fn save(&self, path: &Path) -> Result<()> {
		let json = serde_json::to_string_pretty(self)
			.map_err(|e| QuantusError::Generic(format!("serialize manifest: {e}")))?;
		let tmp = path.with_extension("json.tmp");
		std::fs::write(&tmp, json)?;
		std::fs::rename(&tmp, path)?;
		Ok(())
	}

	fn addresses(&self) -> impl Iterator<Item = &str> {
		self.transfers.iter().flat_map(|t| t.rewards.iter().map(|r| r.address.as_str()))
	}

	fn ensure_state(&self, expected: State) -> Result<()> {
		if self.state == expected {
			return Ok(());
		}
		Err(QuantusError::Generic(format!(
			"manifest is '{}', not '{}'; {}",
			self.state.label(),
			expected.label(),
			self.state.next_step()
		)))
	}

	fn ensure_approved(&self) -> Result<()> {
		self.ensure_state(State::Approved)?;
		if self.approved_sha256.as_deref() == Some(transfers_sha256(&self.transfers)?.as_str()) {
			return Ok(());
		}
		Err(QuantusError::Generic(
			"manifest transfers changed after approval; re-run `quantus airdrop review --approve`"
				.into(),
		))
	}

	fn payment(&self) -> Result<&Payment> {
		self.payment.as_ref().ok_or_else(|| {
			QuantusError::Generic(format!(
				"manifest is '{}' but has no payment record",
				self.state.label()
			))
		})
	}
}

#[derive(Deserialize)]
struct UnpaidResponse {
	rows: Vec<UnpaidRow>,
}

#[derive(Clone, Deserialize)]
struct UnpaidRow {
	address: String,
	claim_account: Option<String>,
	amount_hundredths: u64,
	status: String,
}

async fn fetch_unpaid(server: &str) -> Result<Vec<UnpaidRow>> {
	let wire: UnpaidResponse = get_json(server, "unpaid").await?;
	Ok(wire.rows)
}

/// Group recorded claims by payout account, deterministically ordered.
/// Unclaimed rows have no destination and are skipped.
fn aggregate(rows: &[UnpaidRow], limit: Option<usize>) -> Result<Vec<Transfer>> {
	let mut by_account: BTreeMap<&str, Vec<Reward>> = BTreeMap::new();
	for row in rows.iter().filter(|r| r.status == RECORDED) {
		let to = row.claim_account.as_deref().ok_or_else(|| {
			QuantusError::Generic(format!("recorded claim {} has no claim_account", row.address))
		})?;
		by_account.entry(to).or_default().push(Reward {
			address: row.address.clone(),
			amount_hundredths: row.amount_hundredths,
		});
	}
	let mut transfers = Vec::with_capacity(by_account.len());
	for (to, mut rewards) in by_account {
		rewards.sort_by(|a, b| a.address.cmp(&b.address));
		let amount_hundredths = sum_hundredths(rewards.iter().map(|r| r.amount_hundredths))?;
		transfers.push(Transfer { to: to.to_string(), amount_hundredths, rewards });
	}
	if let Some(limit) = limit {
		transfers.truncate(limit);
	}
	if transfers.is_empty() {
		return Err(QuantusError::Generic("no recorded unpaid claims to pay".into()));
	}
	Ok(transfers)
}

fn sum_hundredths(mut amounts: impl Iterator<Item = u64>) -> Result<u64> {
	amounts
		.try_fold(0u64, |acc, a| acc.checked_add(a))
		.ok_or_else(|| QuantusError::Generic("payout total overflows".into()))
}

/// Every manifest reward must still be an unpaid recorded claim with the same
/// destination and amount; anything else means the server moved on since pull.
fn drift_problems(transfers: &[Transfer], rows: &[UnpaidRow]) -> Vec<String> {
	let live: HashMap<&str, &UnpaidRow> = rows
		.iter()
		.filter(|r| r.status == RECORDED)
		.map(|r| (r.address.as_str(), r))
		.collect();
	let mut problems = Vec::new();
	for transfer in transfers {
		for reward in &transfer.rewards {
			match live.get(reward.address.as_str()) {
				None =>
					problems.push(format!("{}: no longer an unpaid recorded claim", reward.address)),
				Some(row) if row.claim_account.as_deref() != Some(transfer.to.as_str()) => problems
					.push(format!(
						"{}: destination changed to {}",
						reward.address,
						row.claim_account.as_deref().unwrap_or("none")
					)),
				Some(row) if row.amount_hundredths != reward.amount_hundredths =>
					problems.push(format!(
						"{}: amount changed {} -> {} QUAN",
						reward.address,
						format_hundredths(reward.amount_hundredths),
						format_hundredths(row.amount_hundredths)
					)),
				Some(_) => {},
			}
		}
	}
	problems
}

async fn ensure_no_drift(manifest: &Manifest) -> Result<()> {
	let rows = fetch_unpaid(&manifest.server).await?;
	let problems = drift_problems(&manifest.transfers, &rows);
	if problems.is_empty() {
		log_success!("Server still lists every manifest reward as unpaid");
		return Ok(());
	}
	for problem in &problems {
		log_error!("{problem}");
	}
	Err(QuantusError::Generic(format!(
		"{} reward(s) changed on the server since this manifest was pulled; pull a fresh one",
		problems.len()
	)))
}

fn transfers_sha256(transfers: &[Transfer]) -> Result<String> {
	let bytes = serde_json::to_vec(transfers)
		.map_err(|e| QuantusError::Generic(format!("serialize transfers: {e}")))?;
	Ok(hex::encode(Sha256::digest(bytes)))
}

/// Two live manifests could pay the same rewards twice, so a new pull waits
/// until every manifest in the directory is fully marked.
fn ensure_no_open_manifest(dir: &Path) -> Result<()> {
	for entry in std::fs::read_dir(dir)? {
		let path = entry?.path();
		if path.extension().and_then(|e| e.to_str()) != Some("json") {
			continue;
		}
		let manifest = match Manifest::load(&path) {
			Ok(manifest) => manifest,
			Err(e) => {
				log_verbose!("Ignoring {}: {e}", path.display());
				continue;
			},
		};
		if manifest.state != State::Marked {
			return Err(QuantusError::Generic(format!(
				"{} is still '{}'; {} before pulling again",
				path.display(),
				manifest.state.label(),
				manifest.state.next_step()
			)));
		}
	}
	Ok(())
}

fn print_manifest(manifest: &Manifest) {
	let pulled = chrono::DateTime::from_timestamp(manifest.pulled_at, 0)
		.map(|t| t.to_rfc3339())
		.unwrap_or_else(|| manifest.pulled_at.to_string());
	log_print!(
		"Manifest state {}  server {}  pulled {pulled}",
		manifest.state.label().bright_yellow(),
		manifest.server
	);
	for transfer in &manifest.transfers {
		log_print!(
			"  {}  {} QUAN  ({} reward{})",
			transfer.to.bright_cyan(),
			format_hundredths(transfer.amount_hundredths),
			transfer.rewards.len(),
			if transfer.rewards.len() == 1 { "" } else { "s" }
		);
	}
	log_print!(
		"{} transfer(s) covering {} snapshot reward(s), {} QUAN total",
		manifest.transfers.len(),
		manifest.addresses().count(),
		format_hundredths(manifest.total_hundredths).bright_green()
	);
	if let Some(payment) = &manifest.payment {
		log_print!(
			"Payment: signer {}  nonce {}  anchor block #{}  tx {}  block {}",
			payment.signer,
			payment.nonce,
			payment.anchor_block,
			payment.tx_hash.as_deref().unwrap_or("pending"),
			payment.block_hash.as_deref().unwrap_or("pending")
		);
	}
	if !manifest.marked.is_empty() {
		log_print!(
			"Marked paid on the server: {} of {}",
			manifest.marked.len(),
			manifest.addresses().count()
		);
	}
}

pub(super) async fn handle_pull(
	server: String,
	out: Option<PathBuf>,
	limit: Option<usize>,
) -> Result<()> {
	let pulled_at = now_unix()?;
	let out = out.unwrap_or_else(|| PathBuf::from(format!("airdrop-payout-{pulled_at}.json")));
	if out.exists() {
		return Err(QuantusError::Generic(format!(
			"{} already exists; manifests are never overwritten",
			out.display()
		)));
	}
	let dir = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
	ensure_no_open_manifest(dir)?;

	let rows = fetch_unpaid(&server).await?;
	let recorded = rows.iter().filter(|r| r.status == RECORDED).count();
	let transfers = aggregate(&rows, limit)?;
	let total_hundredths = sum_hundredths(transfers.iter().map(|t| t.amount_hundredths))?;
	let manifest = Manifest {
		version: MANIFEST_VERSION,
		server,
		pulled_at,
		state: State::Pulled,
		total_hundredths,
		transfers,
		approved_sha256: None,
		payment: None,
		marked: Vec::new(),
	};
	manifest.save(&out)?;
	print_manifest(&manifest);
	log_print!(
		"Server: {recorded} recorded claim(s) unpaid, {} unclaimed row(s) skipped",
		rows.len() - recorded
	);
	log_success!("Wrote {}", out.display());
	log_print!("Next: quantus airdrop review --manifest {} --approve", out.display());
	Ok(())
}

async fn chain_transfers(
	client: &QuantusClient,
	manifest: &Manifest,
) -> Result<Vec<(String, u128)>> {
	let (_, decimals) = send::get_chain_properties(client).await?;
	manifest
		.transfers
		.iter()
		.map(|t| {
			let amount = send::parse_amount_with_decimals(
				&format_hundredths(t.amount_hundredths),
				decimals,
			)?;
			Ok((t.to.clone(), amount))
		})
		.collect()
}

fn encode_call(client: &QuantusClient, call: &impl Payload) -> Result<Vec<u8>> {
	call.encode_call_data(&client.client().metadata())
		.map_err(|e| QuantusError::Generic(format!("encode batch call: {e}")))
}

fn fits_cold_payload(call_len: usize) -> bool {
	call_len + COLD_PAYLOAD_OVERHEAD <= MAX_COLD_PAYLOAD
}

pub(super) async fn handle_review(
	node_url: &str,
	manifest_path: PathBuf,
	approve: bool,
) -> Result<()> {
	let mut manifest = Manifest::load(&manifest_path)?;
	print_manifest(&manifest);
	if !matches!(manifest.state, State::Pulled | State::Approved) {
		log_print!("Next: {}", manifest.state.next_step());
		return Ok(());
	}
	ensure_no_drift(&manifest).await?;

	let client = QuantusClient::new(node_url).await?;
	let transfers = chain_transfers(&client, &manifest).await?;
	let call_len = encode_call(&client, &send::build_batch_transfer_call(&transfers)?)?.len();
	log_print!(
		"Batch call: {} transfer(s), {call_len} bytes, {}",
		transfers.len(),
		if fits_cold_payload(call_len) {
			"fits a cold-wallet QR payload".to_string()
		} else {
			format!("too large for a cold wallet ({MAX_COLD_PAYLOAD} bytes); pull with --limit")
		}
	);

	if approve {
		manifest.approved_sha256 = Some(transfers_sha256(&manifest.transfers)?);
		manifest.state = State::Approved;
		manifest.save(&manifest_path)?;
		log_success!("Approved {}", manifest_path.display());
		log_print!(
			"Next: quantus airdrop pay --manifest {} --from <wallet>",
			manifest_path.display()
		);
	} else if manifest.state == State::Approved {
		manifest.ensure_approved()?;
		log_print!("Manifest is approved. Next: {}", manifest.state.next_step());
	} else {
		log_print!("Re-run with --approve to approve this manifest for payment.");
	}
	Ok(())
}

async fn block_number(client: &QuantusClient, hash: subxt::utils::H256) -> Result<u64> {
	Ok(client.client().blocks().at(hash).await?.header().number as u64)
}

pub(super) async fn handle_pay(
	node_url: &str,
	manifest_path: PathBuf,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	recover: bool,
) -> Result<()> {
	let mut manifest = Manifest::load(&manifest_path)?;
	let client = QuantusClient::new(node_url).await?;
	if recover {
		return recover_payment(&client, &mut manifest, &manifest_path).await;
	}
	manifest.ensure_approved()?;
	ensure_no_drift(&manifest).await?;

	let signer = wallet::load_signer_from_wallet(&from, password, password_file)?;
	let from_ss58 = signer.try_account_id_ss58check()?;
	let transfers = chain_transfers(&client, &manifest).await?;
	send::validate_batch_transfer_request(&client, &signer, &transfers).await?;
	let call = send::build_batch_transfer_call(&transfers)?;
	let call_len = encode_call(&client, &call)?.len();
	if matches!(signer, WalletSigner::Cold { .. }) && !fits_cold_payload(call_len) {
		return Err(QuantusError::Generic(format!(
			"batch call is {call_len} bytes, too large for cold-wallet signing ({MAX_COLD_PAYLOAD} max); pull with --limit"
		)));
	}
	let total = transfers
		.iter()
		.try_fold(0u128, |acc, (_, amount)| send::checked_add(acc, *amount, "payout total"))?;
	let balance = send::get_balance(&client, &from_ss58).await?;
	send::ensure_balance_covers_call(
		&client,
		&signer,
		&call,
		balance,
		total,
		None,
		"airdrop payout",
	)
	.await?;

	let account = AccountId32::from_ss58check_with_version(&from_ss58)
		.map_err(|e| QuantusError::Generic(format!("invalid signer address {from_ss58}: {e:?}")))?
		.0;
	let nonce = client.get_account_nonce_from_best_block(&account).await?;
	let anchor_block = block_number(&client, client.get_latest_block().await?).await?;
	manifest.payment = Some(Payment {
		signer: from_ss58.clone(),
		nonce,
		anchor_block,
		tx_hash: None,
		block_hash: None,
		paid_at: None,
	});
	manifest.state = State::Paying;
	manifest.save(&manifest_path)?;
	log_print!(
		"Paying {} transfer(s), {} QUAN, from {} in one atomic batch…",
		transfers.len(),
		format_hundredths(manifest.total_hundredths).bright_green(),
		from_ss58.bright_cyan()
	);

	let mode = ExecutionMode { finalized: true, wait_for_transaction: true };
	match common::submit_transaction_with_inclusion_block(&client, &signer, call, None, mode).await
	{
		Ok((tx_hash, included_in)) =>
			record_paid(&mut manifest, &manifest_path, tx_hash, included_in),
		Err(e) => {
			log_error!("Payment did not complete: {e}");
			log_print!(
				"Manifest left in state 'paying'. Before anything else run: quantus airdrop pay --manifest {} --from {from} --recover",
				manifest_path.display()
			);
			Err(e)
		},
	}
}

fn record_paid(
	manifest: &mut Manifest,
	path: &Path,
	tx_hash: subxt::utils::H256,
	block_hash: Option<subxt::utils::H256>,
) -> Result<()> {
	let paid_at = now_unix()?;
	let payment = manifest
		.payment
		.as_mut()
		.ok_or_else(|| QuantusError::Generic("payment finished without a payment record".into()))?;
	payment.tx_hash = Some(format!("{tx_hash:#x}"));
	payment.block_hash = block_hash.map(|h| format!("{h:#x}"));
	payment.paid_at = Some(paid_at);
	manifest.state = State::Paid;
	manifest.save(path)?;
	log_success!("Batch finalized: {tx_hash:#x}");
	log_print!("Next: quantus airdrop mark-paid --manifest {}", path.display());
	Ok(())
}

fn reset_to_approved(manifest: &mut Manifest, path: &Path) -> Result<()> {
	manifest.payment = None;
	manifest.state = State::Approved;
	manifest.save(path)?;
	log_print!("Nothing was paid. Manifest is back to 'approved'; re-run `quantus airdrop pay`.");
	Ok(())
}

/// After an interrupted `pay`: look for the exact batch (same signer, same
/// call bytes) in the finalized blocks it could have landed in.
async fn recover_payment(
	client: &QuantusClient,
	manifest: &mut Manifest,
	path: &Path,
) -> Result<()> {
	manifest.ensure_state(State::Paying)?;
	let payment = manifest.payment()?.clone();
	let transfers = chain_transfers(client, manifest).await?;
	let expected_call = encode_call(client, &send::build_batch_transfer_call(&transfers)?)?;
	// SCALE `MultiAddress::Id(account)`, as `ExtrinsicDetails::address_bytes` returns it.
	let mut expected_signer = vec![0u8];
	expected_signer.extend_from_slice(&parse_account_id(&payment.signer)?);

	let finalized = wormhole::at_finalized_block(client).await?;
	let finalized_number = finalized.header().number as u64;
	let expiry = payment.anchor_block + MORTALITY_BLOCKS + ANCHOR_SLACK_BLOCKS;
	let last = finalized_number.min(expiry);
	log_print!(
		"Scanning finalized blocks #{}..=#{last} for the batch signed by {}",
		payment.anchor_block,
		payment.signer
	);
	for number in payment.anchor_block..=last {
		let block_hash = client.get_block_hash(number).await?;
		let extrinsics = client.client().blocks().at(block_hash).await?.extrinsics().await?;
		let Some(ext) = extrinsics.iter().find(|e| {
			e.address_bytes() == Some(expected_signer.as_slice()) && e.call_bytes() == expected_call
		}) else {
			continue;
		};
		let tx_hash = ext.hash();
		log_print!("Found batch {tx_hash:#x} in finalized block #{number}");
		return match common::check_execution_success(client.client(), &block_hash, &tx_hash).await {
			Ok(()) => record_paid(manifest, path, tx_hash, Some(block_hash)),
			Err(e) => {
				log_error!("The batch was included but reverted: {e}");
				reset_to_approved(manifest, path)
			},
		};
	}
	if finalized_number > expiry {
		log_print!(
			"No batch found and its mortality window has passed; it can no longer be included."
		);
		return reset_to_approved(manifest, path);
	}
	Err(QuantusError::Generic(format!(
		"batch not found in finalized blocks yet; it could still land until block #{expiry} (finalized head is #{finalized_number}). Re-run --recover later"
	)))
}

enum MarkOutcome {
	Marked,
	AlreadyMarked,
	Failed(String),
}

fn mark_outcome(status: reqwest::StatusCode, body: &str) -> MarkOutcome {
	if status.is_success() {
		MarkOutcome::Marked
	} else if status == reqwest::StatusCode::CONFLICT {
		MarkOutcome::AlreadyMarked
	} else {
		MarkOutcome::Failed(format_server_error(status, body))
	}
}

fn admin_token(file: Option<String>) -> Result<String> {
	if let Some(path) = file {
		return password::read_secret_file(&path, "admin token");
	}
	std::env::var(ADMIN_TOKEN_ENV).map_err(|_| {
		QuantusError::Generic(format!("provide --admin-token-file or set {ADMIN_TOKEN_ENV}"))
	})
}

pub(super) async fn handle_mark_paid(
	manifest_path: PathBuf,
	admin_token_file: Option<String>,
) -> Result<()> {
	let mut manifest = Manifest::load(&manifest_path)?;
	if manifest.state == State::Marked {
		log_print!("Every reward in {} is already marked paid.", manifest_path.display());
		return Ok(());
	}
	manifest.ensure_state(State::Paid)?;
	let payment = manifest.payment()?;
	let tx_hash = payment.tx_hash.clone().ok_or_else(|| {
		QuantusError::Generic("manifest is 'paid' but has no transaction hash".into())
	})?;
	let paid_at = payment.paid_at;
	let token = admin_token(admin_token_file)?;
	let client = http_client()?;
	let url = format!("{}/mark-paid", manifest.server.trim_end_matches('/'));
	let pending: Vec<String> = manifest
		.addresses()
		.filter(|a| !manifest.marked.iter().any(|m| m == a))
		.map(str::to_string)
		.collect();
	log_print!("Marking {} address(es) paid by {tx_hash}", pending.len());

	let mut failed = 0usize;
	for address in pending {
		let body = serde_json::json!({ "address": address, "paid_at": paid_at });
		let response = client
			.post(&url)
			.bearer_auth(&token)
			.json(&body)
			.send()
			.await
			.map_err(http_err)?;
		let status = response.status();
		let text = response.text().await.map_err(http_err)?;
		match mark_outcome(status, &text) {
			MarkOutcome::Marked => log_success!("{address} marked paid"),
			MarkOutcome::AlreadyMarked => log_print!("{address} was already marked paid"),
			MarkOutcome::Failed(message) => {
				log_error!("{address}: {message}");
				failed += 1;
				continue;
			},
		}
		manifest.marked.push(address);
		manifest.save(&manifest_path)?;
	}
	if failed > 0 {
		return Err(QuantusError::Generic(format!(
			"{failed} address(es) not marked; re-run mark-paid to retry them"
		)));
	}
	manifest.state = State::Marked;
	manifest.save(&manifest_path)?;
	log_success!("All {} address(es) marked paid", manifest.marked.len());
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn row(address: &str, to: Option<&str>, amount: u64, status: &str) -> UnpaidRow {
		UnpaidRow {
			address: address.into(),
			claim_account: to.map(Into::into),
			amount_hundredths: amount,
			status: status.into(),
		}
	}

	fn rows() -> Vec<UnpaidRow> {
		vec![
			row("qzB", Some("qzDest2"), 300, RECORDED),
			row("qzA", Some("qzDest1"), 150, RECORDED),
			row("qzC", None, 10, "unclaimed"),
			row("qzD", Some("qzDest1"), 50, RECORDED),
		]
	}

	fn manifest(transfers: Vec<Transfer>) -> Manifest {
		Manifest {
			version: MANIFEST_VERSION,
			server: "http://server".into(),
			pulled_at: 0,
			state: State::Pulled,
			total_hundredths: transfers.iter().map(|t| t.amount_hundredths).sum(),
			transfers,
			approved_sha256: None,
			payment: None,
			marked: Vec::new(),
		}
	}

	#[test]
	fn aggregate_groups_recorded_claims_by_destination() {
		let transfers = aggregate(&rows(), None).unwrap();
		assert_eq!(transfers.len(), 2);
		assert_eq!(transfers[0].to, "qzDest1");
		assert_eq!(transfers[0].amount_hundredths, 200);
		assert_eq!(
			transfers[0].rewards.iter().map(|r| r.address.as_str()).collect::<Vec<_>>(),
			["qzA", "qzD"]
		);
		assert_eq!(transfers[1].to, "qzDest2");
		assert_eq!(aggregate(&rows(), Some(1)).unwrap().len(), 1);
	}

	#[test]
	fn aggregate_rejects_empty_and_destinationless_claims() {
		assert!(aggregate(&[row("qzC", None, 10, "unclaimed")], None).is_err());
		assert!(aggregate(&[row("qzE", None, 10, RECORDED)], None).is_err());
	}

	#[test]
	fn drift_reports_paid_moved_and_changed_rewards() {
		let transfers = aggregate(&rows(), None).unwrap();
		assert!(drift_problems(&transfers, &rows()).is_empty());
		let live = vec![
			row("qzB", Some("qzDest2"), 301, RECORDED),
			row("qzA", Some("qzOther"), 150, RECORDED),
		];
		let problems = drift_problems(&transfers, &live);
		assert_eq!(problems.len(), 3, "{problems:?}");
		assert!(problems.iter().any(|p| p.starts_with("qzA: destination changed")));
		assert!(problems.iter().any(|p| p.starts_with("qzB: amount changed")));
		assert!(problems.iter().any(|p| p.starts_with("qzD: no longer")));
	}

	#[test]
	fn approval_hash_pins_the_transfers() {
		let mut m = manifest(aggregate(&rows(), None).unwrap());
		m.state = State::Approved;
		m.approved_sha256 = Some(transfers_sha256(&m.transfers).unwrap());
		m.ensure_approved().unwrap();
		m.transfers[0].amount_hundredths += 1;
		assert!(m.ensure_approved().is_err());
		m.state = State::Pulled;
		assert!(m.ensure_approved().unwrap_err().to_string().contains("not 'approved'"));
	}

	#[test]
	fn open_manifest_blocks_a_new_pull() {
		let dir = tempfile::tempdir().unwrap();
		std::fs::write(dir.path().join("notes.json"), "{\"unrelated\": true}").unwrap();
		ensure_no_open_manifest(dir.path()).unwrap();

		let mut m = manifest(aggregate(&rows(), None).unwrap());
		m.state = State::Paid;
		m.save(&dir.path().join("payout.json")).unwrap();
		let err = ensure_no_open_manifest(dir.path()).unwrap_err().to_string();
		assert!(err.contains("still 'paid'"), "{err}");

		m.state = State::Marked;
		m.save(&dir.path().join("payout.json")).unwrap();
		ensure_no_open_manifest(dir.path()).unwrap();
		assert_eq!(Manifest::load(&dir.path().join("payout.json")).unwrap().state, State::Marked);
	}

	#[test]
	fn mark_outcome_treats_conflict_as_already_marked() {
		assert!(matches!(mark_outcome(reqwest::StatusCode::OK, ""), MarkOutcome::Marked));
		assert!(matches!(
			mark_outcome(
				reqwest::StatusCode::CONFLICT,
				"{\"error\":\"address already marked paid\"}"
			),
			MarkOutcome::AlreadyMarked
		));
		match mark_outcome(reqwest::StatusCode::NOT_FOUND, "{\"error\":\"no claim\"}") {
			MarkOutcome::Failed(msg) => assert_eq!(msg, "server 404 Not Found: no claim"),
			_ => panic!("404 must fail"),
		}
	}

	#[test]
	fn cold_payload_budget() {
		assert!(fits_cold_payload(MAX_COLD_PAYLOAD - COLD_PAYLOAD_OVERHEAD));
		assert!(!fits_cold_payload(MAX_COLD_PAYLOAD - COLD_PAYLOAD_OVERHEAD + 1));
	}
}
