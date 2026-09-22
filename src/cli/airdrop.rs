use crate::{
	cli::{
		address_format::bytes_to_quantus_ss58, common::resolve_address_with_subxt_account_id,
		wormhole::parse_secret_hex,
	},
	error::{QuantusError, Result, WalletError},
	log_error, log_print, log_success, log_verbose,
	wallet::{keystore::WalletType, password, DilithiumScheme, QuantumKeyPair, WalletManager},
};
use clap::Subcommand;
use colored::Colorize;
use nam_tiny_hderive::bip32::ExtendedPrivKey;
use qp_ownership_circuit::{CircuitInputs, Secret};
use qp_poseidon_core_v09 as v09;
use qp_rusty_crystals_dilithium::{fips202, ml_dsa_87::SecretKey, packing, params, poly, polyvec};
use qp_rusty_crystals_hdwallet::{
	generate_wormhole_from_seed, mnemonic_to_seed, SensitiveBytes64, QUANTUS_WORMHOLE_CHAIN_ID,
};
use qp_zk_circuits_common::utils::BytesDigest;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::{collections::HashMap, path::PathBuf, time::Duration};

const CLAIM_CONTEXT: &[u8] = b"qp-airdrop-claim-v1";
const CLAIM_TTL_SECS: i64 = 10 * 60;
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";
const HD_WORMHOLE_INDEXES: std::ops::RangeInclusive<usize> = 0..=16;
const CLAIMABLE_WORMHOLE_SCHEME: &str = "wormhole-rate8-compact";
/// BIP44 coin type for Dilithium keys (the wormhole coin type is 189189189').
const DILITHIUM_CHAIN_ID: &str = "189189'";

#[derive(Subcommand, Debug)]
pub enum AirdropCommands {
	/// Show snapshot rows owned by this wallet or wormhole secret
	Check {
		/// Claim server base URL
		#[arg(long, default_value = DEFAULT_SERVER)]
		server: String,

		/// Hot wallet used to derive Dilithium (and HD wormhole) addresses
		#[arg(long, short)]
		wallet: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// File with a 32-byte hex wormhole secret (chmod 600)
		#[arg(long)]
		wormhole_secret_file: Option<PathBuf>,

		/// Paste a 32-byte hex wormhole secret at a hidden prompt (secrets
		/// are never accepted on argv)
		#[arg(long)]
		wormhole_secret_prompt: bool,

		/// HD wormhole address index, scanned across every branch/round
		/// (default: scan indexes 0..=16)
		#[arg(long)]
		wormhole_index: Option<usize>,

		/// Highest Dilithium account index scanned per historical keygen
		/// family (m/44'/189189'/N'/…). Raise if the wallet was created with
		/// a higher account; the wallet's own stored derivation path is
		/// always scanned.
		#[arg(long, default_value_t = 8)]
		scan_accounts: u32,

		/// Highest wormhole branch/round component scanned
		/// (m/44'/189189189'/0'/N'/index'). Raise if `wormhole multiround`
		/// was run with more than this many rounds.
		#[arg(long, default_value_t = 8)]
		scan_rounds: usize,
	},

	/// Prove ownership and submit claims. Amounts come from the snapshot.
	Claim {
		/// Claim server base URL
		#[arg(long, default_value = DEFAULT_SERVER)]
		server: String,

		/// Hot wallet that signs Dilithium claims and/or derives HD wormhole secrets
		#[arg(long, short)]
		wallet: Option<String>,

		/// Destination for the payout (wallet name or SS58). Defaults to --wallet.
		#[arg(long, short)]
		to: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// File with a 32-byte hex wormhole secret (chmod 600)
		#[arg(long)]
		wormhole_secret_file: Option<PathBuf>,

		/// Paste a 32-byte hex wormhole secret at a hidden prompt (secrets
		/// are never accepted on argv)
		#[arg(long)]
		wormhole_secret_prompt: bool,

		/// HD wormhole address index, scanned across every branch/round
		/// (default: scan indexes 0..=16)
		#[arg(long)]
		wormhole_index: Option<usize>,

		/// Highest Dilithium account index scanned per historical keygen
		/// family (m/44'/189189'/N'/…). Raise if the wallet was created with
		/// a higher account; the wallet's own stored derivation path is
		/// always scanned.
		#[arg(long, default_value_t = 8)]
		scan_accounts: u32,

		/// Highest wormhole branch/round component scanned
		/// (m/44'/189189189'/0'/N'/index'). Raise if `wormhole multiround`
		/// was run with more than this many rounds.
		#[arg(long, default_value_t = 8)]
		scan_rounds: usize,

		/// Print matches and signed/proved payloads without POSTing
		#[arg(long)]
		dry_run: bool,
	},

	/// Pay recorded (claimed but unpaid) rewards with batch transfers and
	/// mark them paid on the claim server. Requires the server admin token.
	Pay {
		/// Claim server base URL
		#[arg(long, default_value = DEFAULT_SERVER)]
		server: String,

		/// Wallet that funds the payouts (hot or cold)
		#[arg(long, short)]
		from: String,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,

		/// Admin token (unsupported on argv; use --admin-token-file or
		/// QUANTUS_AIRDROP_ADMIN_TOKEN)
		#[arg(long, hide = true)]
		admin_token: Option<String>,

		/// File with the claim server admin token (chmod 600). Falls back to
		/// the QUANTUS_AIRDROP_ADMIN_TOKEN environment variable.
		#[arg(long)]
		admin_token_file: Option<String>,

		/// Pay only this rewarded address (repeatable). Errors if the
		/// address has no recorded unpaid claim.
		#[arg(long)]
		only: Vec<String>,

		/// Pay at most this many claims this run (e.g. 1 to test the flow
		/// end-to-end before paying the rest)
		#[arg(long)]
		limit: Option<usize>,

		/// Max transfers per batch extrinsic (default: the chain's safe
		/// batch limit)
		#[arg(long)]
		batch_size: Option<u32>,

		/// Optional tip amount per batch to prioritize inclusion (e.g. "0.5")
		#[arg(long)]
		tip: Option<String>,

		/// Skip the interactive review confirmation
		#[arg(long)]
		yes: bool,

		/// Show the payout plan without submitting or marking anything paid
		#[arg(long)]
		dry_run: bool,
	},
}

pub async fn handle_airdrop_command(
	command: AirdropCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<()> {
	match command {
		AirdropCommands::Check {
			server,
			wallet,
			password,
			password_file,
			wormhole_secret_file,
			wormhole_secret_prompt,
			wormhole_index,
			scan_accounts,
			scan_rounds,
		} =>
			handle_check(
				server,
				wallet,
				password,
				password_file,
				wormhole_secret_file,
				wormhole_secret_prompt,
				ScanWindow { wormhole_index, accounts: scan_accounts, rounds: scan_rounds },
			)
			.await,
		AirdropCommands::Claim {
			server,
			wallet,
			to,
			password,
			password_file,
			wormhole_secret_file,
			wormhole_secret_prompt,
			wormhole_index,
			scan_accounts,
			scan_rounds,
			dry_run,
		} =>
			handle_claim(
				server,
				wallet,
				to,
				password,
				password_file,
				wormhole_secret_file,
				wormhole_secret_prompt,
				ScanWindow { wormhole_index, accounts: scan_accounts, rounds: scan_rounds },
				dry_run,
			)
			.await,
		AirdropCommands::Pay {
			server,
			from,
			password,
			password_file,
			admin_token,
			admin_token_file,
			only,
			limit,
			batch_size,
			tip,
			yes,
			dry_run,
		} =>
			handle_pay(
				server,
				from,
				password,
				password_file,
				AdminTokenSource { argv: admin_token, file: admin_token_file },
				PayoutSelection { only, limit },
				batch_size,
				tip,
				yes,
				dry_run,
				node_url,
				execution_mode,
			)
			.await,
	}
}

/// How far the deterministic recovery scan reaches. The defaults cover every
/// path the app or this CLI ever created on its own; the flags exist for
/// wallets that used custom accounts or extra multiround rounds.
#[derive(Clone, Copy)]
struct ScanWindow {
	/// Pin the wormhole address index (None: scan 0..=16).
	wormhole_index: Option<usize>,
	/// Highest Dilithium account index per historical keygen family.
	accounts: u32,
	/// Highest wormhole branch/round component.
	rounds: usize,
}

async fn handle_check(
	server: String,
	wallet: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
	wormhole_secret_file: Option<PathBuf>,
	wormhole_secret_prompt: bool,
	scan: ScanWindow,
) -> Result<()> {
	let snapshot = fetch_snapshot(&server).await?;
	let credentials = collect_credentials(
		wallet.as_deref(),
		password,
		password_file,
		wormhole_secret_file.as_deref(),
		wormhole_secret_prompt,
		scan,
	)?;
	if credentials.dilithium.is_none() && credentials.wormhole_secrets.is_empty() {
		return Err(QuantusError::Generic(
			"provide --wallet, --wormhole-secret-file, and/or --wormhole-secret-prompt".into(),
		));
	}

	let matches = find_matches(&snapshot, &credentials);
	print_snapshot_header(&snapshot);
	print_matches(&matches);
	Ok(())
}

async fn handle_claim(
	server: String,
	wallet: Option<String>,
	to: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
	wormhole_secret_file: Option<PathBuf>,
	wormhole_secret_prompt: bool,
	scan: ScanWindow,
	dry_run: bool,
) -> Result<()> {
	let credentials = collect_credentials(
		wallet.as_deref(),
		password,
		password_file,
		wormhole_secret_file.as_deref(),
		wormhole_secret_prompt,
		scan,
	)?;
	if credentials.dilithium.is_none() && credentials.wormhole_secrets.is_empty() {
		return Err(QuantusError::Generic(
			"provide --wallet, --wormhole-secret-file, and/or --wormhole-secret-prompt".into(),
		));
	}

	let claim_account = resolve_claim_account(to.as_deref(), &credentials)?;
	let snapshot = fetch_snapshot(&server).await?;
	let matches = find_matches(&snapshot, &credentials);

	print_snapshot_header(&snapshot);
	print_matches(&matches);
	log_print!(
		"Payout destination: {}",
		address_with_checkphrase(&bytes_to_quantus_ss58(&claim_account))
	);

	if matches.is_empty() {
		log_print!("No snapshot addresses to claim.");
		return Ok(());
	}

	let client = http_client()?;
	let mut claimed = 0u64;
	let mut recorded = 0usize;
	let mut skipped = 0usize;
	let mut failed = 0usize;
	for found in &matches {
		match submit_claim(&client, &server, found, &claim_account, &credentials, dry_run).await {
			Ok(ClaimOutcome::Recorded { amount_hundredths }) => {
				recorded += 1;
				claimed = claimed.saturating_add(amount_hundredths);
			},
			Ok(ClaimOutcome::Skipped) => skipped += 1,
			Err(e) => {
				log_error!("Failed {}: {e}", found.ss58);
				failed += 1;
			},
		}
	}
	finish_claims(dry_run, claimed, recorded, skipped, failed)
}

/// Print the batch summary. Any submission failure makes the command fail so
/// unattended callers see a non-zero exit; intentionally skipped schemes do
/// not.
fn finish_claims(
	dry_run: bool,
	claimed_hundredths: u64,
	recorded: usize,
	skipped: usize,
	failed: usize,
) -> Result<()> {
	if dry_run {
		log_print!(
			"Dry run finished. Would submit {recorded} claim(s); {skipped} skipped; {failed} failed."
		);
	} else if failed == 0 {
		log_success!(
			"Recorded {} QTC across {recorded} claim(s); {skipped} skipped.",
			format_hundredths(claimed_hundredths)
		);
	} else {
		log_print!(
			"Recorded {} QTC across {recorded} claim(s); {skipped} skipped; {failed} failed.",
			format_hundredths(claimed_hundredths)
		);
	}
	if failed > 0 {
		return Err(QuantusError::Generic(format!("{failed} claim submission(s) failed")));
	}
	Ok(())
}

/// One `/unpaid` row from the claim server. `status` is `recorded` (claimed,
/// awaiting payout) or `unclaimed` (snapshot row nobody has claimed).
#[derive(Clone, Debug, Deserialize)]
struct UnpaidRow {
	address: String,
	claim_account: Option<String>,
	amount_hundredths: u64,
	kind: String,
	scheme: Option<String>,
	verified_at: Option<i64>,
	status: String,
}

#[derive(Debug, Deserialize)]
struct UnpaidResponse {
	rows: Vec<UnpaidRow>,
}

/// A recorded claim awaiting payout: pay `claim_account` on chain, then mark
/// the rewarded `address` paid on the server.
#[derive(Clone, Debug)]
struct Payout {
	address: String,
	claim_account: String,
	amount_hundredths: u64,
	scheme: String,
	verified_at: Option<i64>,
}

fn recorded_payouts(rows: Vec<UnpaidRow>) -> Result<Vec<Payout>> {
	let mut payouts = Vec::new();
	for row in rows {
		if row.status != "recorded" {
			continue;
		}
		let scheme = row.scheme.unwrap_or(row.kind);
		let claim_account = row.claim_account.ok_or_else(|| {
			QuantusError::Generic(format!("recorded claim {} has no claim account", row.address))
		})?;
		if row.amount_hundredths == 0 {
			continue;
		}
		payouts.push(Payout {
			address: row.address,
			claim_account,
			amount_hundredths: row.amount_hundredths,
			scheme,
			verified_at: row.verified_at,
		});
	}
	Ok(payouts)
}

/// Destination address with its human checkphrase so the operator can
/// verify it against the recipient out of band.
fn address_with_checkphrase(address: &str) -> String {
	format!(
		"{} [{}]",
		address.bright_green(),
		crate::wallet::checkphrase::checkphrase(address).bright_blue()
	)
}

/// Which recorded claims this run pays: an optional address allowlist
/// (`--only`, repeatable) and an optional cap (`--limit`).
struct PayoutSelection {
	only: Vec<String>,
	limit: Option<usize>,
}

fn select_payouts(mut payouts: Vec<Payout>, selection: &PayoutSelection) -> Result<Vec<Payout>> {
	if !selection.only.is_empty() {
		for wanted in &selection.only {
			if !payouts.iter().any(|p| &p.address == wanted) {
				return Err(QuantusError::Generic(format!(
					"--only {wanted} has no recorded unpaid claim"
				)));
			}
		}
		payouts.retain(|p| selection.only.contains(&p.address));
	}
	if let Some(limit) = selection.limit {
		if limit == 0 {
			return Err(QuantusError::Generic("--limit must be at least 1".into()));
		}
		payouts.truncate(limit);
	}
	Ok(payouts)
}

/// Snapshot amounts are hundredths of a QTC; the chain wants raw units.
fn hundredths_to_raw(amount_hundredths: u64, decimals: u8) -> Result<u128> {
	let scale = decimals.checked_sub(2).ok_or_else(|| {
		QuantusError::Generic(format!(
			"chain has {decimals} decimal(s); cannot represent hundredths of a QTC"
		))
	})?;
	let unit = 10u128
		.checked_pow(u32::from(scale))
		.ok_or_else(|| QuantusError::Generic("decimal scale overflow".into()))?;
	u128::from(amount_hundredths)
		.checked_mul(unit)
		.ok_or_else(|| QuantusError::Generic("payout amount overflow".into()))
}

/// Where the mark-paid bearer token may come from. Raw argv values are
/// rejected like passwords are.
struct AdminTokenSource {
	argv: Option<String>,
	file: Option<String>,
}

/// The mark-paid admin token, from a chmod-600 file or the
/// QUANTUS_AIRDROP_ADMIN_TOKEN environment variable. Required before any
/// payment goes out so a paid claim can always be marked.
fn load_admin_token(source: &AdminTokenSource) -> Result<String> {
	if source.argv.is_some() {
		return Err(QuantusError::Generic(
			"Passing the admin token with --admin-token is not supported (argv is visible in \
			 process listings); use --admin-token-file or QUANTUS_AIRDROP_ADMIN_TOKEN"
				.to_string(),
		));
	}
	if let Some(path) = &source.file {
		return Ok(password::read_secret_file(path, "admin token")?.trim().to_string());
	}
	if let Ok(token) = std::env::var("QUANTUS_AIRDROP_ADMIN_TOKEN") {
		let token = token.trim().to_string();
		if !token.is_empty() {
			return Ok(token);
		}
	}
	Err(QuantusError::Generic(
		"provide --admin-token-file or set QUANTUS_AIRDROP_ADMIN_TOKEN; the token is required \
		 up front so every paid claim can be marked paid"
			.into(),
	))
}

fn format_verified_at(verified_at: Option<i64>) -> String {
	match verified_at.and_then(|t| chrono::DateTime::from_timestamp(t, 0)) {
		Some(when) => when.format("%Y-%m-%d %H:%M UTC").to_string(),
		None => "-".to_string(),
	}
}

fn confirm_payout(total: &str, accounts: usize, batches: usize, from: &str) -> Result<()> {
	use std::io::Write;
	print!("Pay {total} QTC to {accounts} account(s) in {batches} batch(es) from '{from}'? [y/N] ");
	std::io::stdout()
		.flush()
		.map_err(|e| QuantusError::Generic(format!("Failed to flush confirmation prompt: {e}")))?;
	let mut response = String::new();
	std::io::stdin()
		.read_line(&mut response)
		.map_err(|e| QuantusError::Generic(format!("Failed to read confirmation: {e}")))?;
	let response = response.trim().to_lowercase();
	if response != "y" && response != "yes" {
		return Err(QuantusError::Generic("Payout aborted".into()));
	}
	Ok(())
}

async fn fetch_unpaid(client: &reqwest::Client, server: &str) -> Result<UnpaidResponse> {
	let url = format!("{}/unpaid", server.trim_end_matches('/'));
	let response = client.get(&url).send().await.map_err(http_err)?;
	let status = response.status();
	let text = response.text().await.map_err(http_err)?;
	if !status.is_success() {
		return Err(QuantusError::Generic(format_server_error(status, &text)));
	}
	serde_json::from_str(&text).map_err(|e| QuantusError::Generic(format!("unpaid JSON: {e}")))
}

/// Addresses we paid that the server still lists on `/unpaid` (any status).
fn addresses_still_listed(rows: &[UnpaidRow], paid: &[String]) -> Vec<String> {
	rows.iter()
		.map(|row| &row.address)
		.filter(|a| paid.contains(a))
		.cloned()
		.collect()
}

async fn mark_paid(
	client: &reqwest::Client,
	server: &str,
	admin_token: &str,
	address: &str,
) -> Result<()> {
	let url = format!("{}/mark-paid", server.trim_end_matches('/'));
	let response = client
		.post(&url)
		.bearer_auth(admin_token)
		.json(&serde_json::json!({ "address": address }))
		.send()
		.await
		.map_err(http_err)?;
	let status = response.status();
	if status.is_success() {
		return Ok(());
	}
	let text = response.text().await.map_err(http_err)?;
	if status == reqwest::StatusCode::CONFLICT {
		// Already marked (e.g. a concurrent operator); the payout stands.
		log_verbose!("{address} was already marked paid");
		return Ok(());
	}
	Err(QuantusError::Generic(format_server_error(status, &text)))
}

#[allow(clippy::too_many_arguments)]
async fn handle_pay(
	server: String,
	from: String,
	password: Option<String>,
	password_file: Option<String>,
	admin_token_source: AdminTokenSource,
	selection: PayoutSelection,
	batch_size: Option<u32>,
	tip: Option<String>,
	yes: bool,
	dry_run: bool,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> Result<()> {
	let client = http_client()?;
	let unpaid = fetch_unpaid(&client, &server).await?;
	let unclaimed = unpaid.rows.iter().filter(|r| r.status == "unclaimed").count();
	let recorded = recorded_payouts(unpaid.rows)?;
	if recorded.is_empty() {
		log_print!(
			"No recorded claims awaiting payout ({unclaimed} snapshot row(s) remain unclaimed)."
		);
		return Ok(());
	}
	let pending = recorded.len();
	let payouts = select_payouts(recorded, &selection)?;
	if payouts.len() < pending {
		log_print!(
			"Paying {} of {pending} pending claim(s) this run (--only/--limit).",
			payouts.len()
		);
	}

	// Review.
	let mut total_hundredths: u64 = 0;
	log_print!("{} recorded claim(s) awaiting payout:", payouts.len());
	for payout in &payouts {
		total_hundredths = total_hundredths
			.checked_add(payout.amount_hundredths)
			.ok_or_else(|| QuantusError::Generic("payout total overflow".into()))?;
		log_print!(
			"  {}  →  {}  {} QTC  {}  (verified {})",
			payout.address.bright_cyan(),
			address_with_checkphrase(&payout.claim_account),
			format_hundredths(payout.amount_hundredths),
			payout.scheme,
			format_verified_at(payout.verified_at),
		);
	}
	let total = format_hundredths(total_hundredths);
	log_print!(
		"Total: {} QTC to {} account(s); {} snapshot row(s) remain unclaimed.",
		total.bright_yellow(),
		payouts.len(),
		unclaimed
	);

	// Plan batches against the chain's limits.
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;
	let (_, decimals) = crate::cli::send::get_chain_properties(&quantus_client).await?;
	let (safe_limit, _) = crate::cli::send::get_batch_limits(&quantus_client).await?;
	let per_batch = match batch_size {
		Some(0) => return Err(QuantusError::Generic("--batch-size must be at least 1".into())),
		Some(size) if size > safe_limit => {
			log_print!("--batch-size {size} exceeds the chain's safe limit; using {safe_limit}.");
			safe_limit as usize
		},
		Some(size) => size as usize,
		None => safe_limit as usize,
	};
	let mut transfers = Vec::with_capacity(payouts.len());
	for payout in &payouts {
		transfers.push((
			payout.claim_account.clone(),
			hundredths_to_raw(payout.amount_hundredths, decimals)?,
		));
	}
	let batches = transfers.len().div_ceil(per_batch);
	log_print!("Plan: {batches} batch extrinsic(s) of up to {per_batch} transfer(s) each.");

	if dry_run {
		for (index, chunk) in payouts.chunks(per_batch).enumerate() {
			log_print!("Batch {}/{batches}:", index + 1);
			for payout in chunk {
				log_print!(
					"  {} ← {} QTC",
					address_with_checkphrase(&payout.claim_account),
					format_hundredths(payout.amount_hundredths)
				);
			}
		}
		log_print!("Dry run finished. Nothing was submitted or marked paid.");
		return Ok(());
	}

	// The token is loaded before anything is paid so a completed payout can
	// always be marked on the server (re-running an unmarked payout would
	// double-pay).
	let admin_token = load_admin_token(&admin_token_source)?;

	if !yes {
		confirm_payout(&total, payouts.len(), batches, &from)?;
	}

	let signer = crate::wallet::load_signer_from_wallet(&from, password, password_file)?;
	crate::cli::send::validate_batch_transfer_request(&quantus_client, &signer, &transfers).await?;

	let tip_amount = match tip {
		Some(tip_str) => {
			let (value, _) =
				crate::cli::send::validate_and_format_amount(&quantus_client, &tip_str).await?;
			Some(value)
		},
		None => None,
	};
	let per_batch_tip = crate::cli::send::effective_tip_amount(tip_amount);
	let submit_tip = crate::cli::send::positive_tip_amount(tip_amount);

	let from_account = signer.try_account_id_ss58check()?;
	let balance = crate::cli::send::get_balance(&quantus_client, &from_account).await?;
	let total_amount = transfers.iter().try_fold(0u128, |acc, (_, amount)| {
		crate::cli::send::checked_add(acc, *amount, "payout total")
	})?;
	let total_tips = per_batch_tip
		.checked_mul(batches as u128)
		.ok_or_else(|| QuantusError::Generic("tip total overflow".into()))?;
	let exact_required =
		crate::cli::send::checked_add(total_amount, total_tips, "required payout balance")?;
	// Fee estimation covers the first batch; later batches add fees on top,
	// so this is a floor, not a guarantee.
	let first_chunk = &transfers[..per_batch.min(transfers.len())];
	let first_call = crate::cli::send::build_batch_transfer_call(first_chunk)?;
	crate::cli::send::ensure_balance_covers_call(
		&quantus_client,
		&signer,
		&first_call,
		balance,
		exact_required,
		submit_tip,
		"payout",
	)
	.await?;

	// Never mark a claim paid before its transfer is in a block.
	let wait_mode =
		crate::cli::common::ExecutionMode { wait_for_transaction: true, ..execution_mode };

	let mut paid_rows = 0usize;
	let mut paid_hundredths = 0u64;
	let mut unmarked = Vec::new();
	for (index, (payout_chunk, transfer_chunk)) in
		payouts.chunks(per_batch).zip(transfers.chunks(per_batch)).enumerate()
	{
		log_print!(
			"Submitting batch {}/{batches} ({} transfer(s))…",
			index + 1,
			transfer_chunk.len()
		);
		let call = crate::cli::send::build_batch_transfer_call(transfer_chunk)?;
		let tx_hash = crate::cli::send::submit_prebuilt_batch_transfer_call(
			&quantus_client,
			&signer,
			transfer_chunk,
			call,
			tip_amount,
			wait_mode,
		)
		.await
		.map_err(|e| {
			QuantusError::Generic(format!(
				"batch {}/{batches} failed ({e}); {paid_rows} row(s) from earlier batches were \
				 paid and marked, nothing from this batch was paid — re-run to continue",
				index + 1
			))
		})?;
		log_success!("Batch {}/{batches} in block: {:?}", index + 1, tx_hash);
		for payout in payout_chunk {
			if let Err(e) = mark_paid(&client, &server, &admin_token, &payout.address).await {
				log_error!("mark-paid failed for {}: {e}", payout.address);
				unmarked.push(payout.address.clone());
			}
			paid_rows += 1;
			paid_hundredths = paid_hundredths.saturating_add(payout.amount_hundredths);
		}
	}

	log_success!(
		"Paid {} QTC across {paid_rows} claim(s) in {batches} batch(es).",
		format_hundredths(paid_hundredths)
	);
	if !unmarked.is_empty() {
		log_error!(
			"{} payout(s) were PAID but not marked on the server — mark them before running \
			 pay again or they will be paid twice:",
			unmarked.len()
		);
		for address in &unmarked {
			log_error!("  {address}");
		}
		return Err(QuantusError::Generic(format!(
			"{} mark-paid call(s) failed after payment",
			unmarked.len()
		)));
	}

	// Re-fetch /unpaid and verify every paid address is gone from the list;
	// anything still listed would be paid again on the next run.
	let paid_addresses: Vec<String> = payouts.iter().map(|p| p.address.clone()).collect();
	let still_listed =
		addresses_still_listed(&fetch_unpaid(&client, &server).await?.rows, &paid_addresses);
	if still_listed.is_empty() {
		log_success!(
			"Server verification: none of the {} paid address(es) remain on /unpaid.",
			paid_addresses.len()
		);
		return Ok(());
	}
	log_error!(
		"{} paid address(es) still appear on /unpaid — resolve on the server before running \
		 pay again or they will be paid twice:",
		still_listed.len()
	);
	for address in &still_listed {
		log_error!("  {address}");
	}
	Err(QuantusError::Generic(format!(
		"{} paid address(es) are still listed unpaid by the server",
		still_listed.len()
	)))
}

/// Move-only wormhole spend secret. Zeroized on drop; Debug never prints it.
struct SpendSecret([u8; 32]);

impl SpendSecret {
	fn bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

impl Drop for SpendSecret {
	fn drop(&mut self) {
		crate::wallet::keystore::zeroize_bytes(&mut self.0);
	}
}

impl std::fmt::Debug for SpendSecret {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("SpendSecret(<redacted>)")
	}
}

struct Credentials {
	dilithium: Option<QuantumKeyPair>,
	/// AccountId of the unlocked wallet, kept so the default `--to` never
	/// reopens the wallet (which would lose `--password-file`).
	wallet_account: Option<[u8; 32]>,
	wormhole_secrets: Vec<(SpendSecret, String)>,
	/// Stretched BIP39 seed (self-zeroizing), kept so historical Dilithium
	/// keypairs can be re-derived at claim time instead of holding every
	/// candidate secret key in memory.
	hd_seed: Option<SensitiveBytes64>,
	/// The wallet's stored derivation path: custom `--derivation-path`
	/// imports can sit outside the scanned account window, so this exact
	/// path is scanned under every keygen era too.
	wallet_derivation_path: Option<String>,
	/// Highest Dilithium account index to scan per keygen family.
	scan_accounts: u32,
}

fn collect_credentials(
	wallet: Option<&str>,
	password: Option<String>,
	password_file: Option<String>,
	wormhole_secret_file: Option<&std::path::Path>,
	wormhole_secret_prompt: bool,
	scan: ScanWindow,
) -> Result<Credentials> {
	let mut wormhole_secrets = Vec::new();
	let mut dilithium = None;
	let mut wallet_account = None;
	let mut hd_seed = None;
	let mut wallet_derivation_path = None;

	if let Some(name) = wallet {
		let (keypair, mnemonic, derivation_path) =
			load_wallet_material(name, password, password_file)?;
		wallet_account = Some(*keypair.try_to_account_id_32()?.as_ref());
		wallet_derivation_path = derivation_path;
		if keypair.scheme != DilithiumScheme::MlDsa87 {
			log_print!(
				"Wallet '{}' is {:?}; Dilithium airdrop claims require ML-DSA-87.",
				name,
				keypair.scheme
			);
		} else {
			dilithium = Some(keypair);
		}
		if let Some(mnemonic) = mnemonic {
			// Stretch the BIP39 seed once; `mnemonic_to_seed` consumes and
			// zeroizes the mnemonic string.
			let mut seed = SensitiveBytes64::zeroed();
			mnemonic_to_seed(mnemonic, None, &mut seed)
				.map_err(|e| QuantusError::Generic(format!("invalid mnemonic: {e:?}")))?;
			wormhole_secrets.extend(derive_hd_wormhole_secrets(
				&seed,
				scan.wormhole_index,
				scan.rounds,
			)?);
			hd_seed = Some(seed);
		} else {
			log_verbose!("Wallet '{}' has no mnemonic; HD derivation skipped", name);
		}
	}

	if let Some(path) = wormhole_secret_file {
		let secret = read_wormhole_secret(path)?;
		wormhole_secrets.push((secret, path.display().to_string()));
	}

	if wormhole_secret_prompt {
		wormhole_secrets.push((prompt_wormhole_secret()?, "pasted secret".to_string()));
	}

	Ok(Credentials {
		dilithium,
		wallet_account,
		wormhole_secrets,
		hd_seed,
		wallet_derivation_path,
		scan_accounts: scan.accounts,
	})
}

fn load_wallet_material(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<(QuantumKeyPair, Option<String>, Option<String>)> {
	let wallet_manager = WalletManager::new()?;
	if wallet_manager.wallet_type(wallet_name)? == Some(WalletType::Cold) {
		return Err(WalletError::ColdWalletNoKeys(wallet_name.to_string()).into());
	}
	let wallet_password = password::get_wallet_password(wallet_name, password, password_file)?;
	let mut wallet_data = wallet_manager.load_wallet(wallet_name, &wallet_password)?;
	let mnemonic = wallet_data.take_mnemonic();
	let derivation_path = Some(wallet_data.derivation_path.clone());
	Ok((wallet_data.take_keypair(), mnemonic, derivation_path))
}

fn derive_hd_wormhole_secrets(
	seed: &SensitiveBytes64,
	wormhole_index: Option<usize>,
	scan_rounds: usize,
) -> Result<Vec<(SpendSecret, String)>> {
	let indexes: Vec<usize> = match wormhole_index {
		Some(index) => vec![index],
		None => HD_WORMHOLE_INDEXES.collect(),
	};
	let mut out = Vec::new();
	// Current "Dilithium seed" tree.
	for branch in 0..=scan_rounds {
		for &index in &indexes {
			let path = format!("m/44'/{}/0'/{}'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, branch, index);
			let pair = generate_wormhole_from_seed(seed, &path)
				.map_err(|e| QuantusError::Generic(format!("HD derivation failed: {e:?}")))?;
			out.push((SpendSecret(*pair.secret().as_bytes()), format!("hd {path}")));
		}
	}
	// Pre-March-2026 "Bitcoin seed" tree: same paths, different master HMAC
	// key, so every entropy differs. The app's first wormhole address also
	// used the master node's own key (hdwallet 1.0.0 `generate_wormhole_pair`),
	// hence path "m".
	let mut legacy_paths = vec!["m".to_string()];
	for branch in 0..=scan_rounds {
		for &index in &indexes {
			legacy_paths
				.push(format!("m/44'/{}/0'/{}'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, branch, index));
		}
	}
	for path in legacy_paths {
		let entropy = ExtendedPrivKey::derive(seed.as_bytes(), path.as_str())
			.map_err(|e| {
				QuantusError::Generic(format!("BIP32 derivation failed at {path}: {e:?}"))
			})?
			.secret();
		out.push((SpendSecret(entropy), format!("bitcoin-seed {path}")));
	}
	Ok(out)
}

// ---------------------------------------------------------------------------
// Historical ML-DSA-87 keygens
// ---------------------------------------------------------------------------
//
// The address-hash schemes below cover how a *public key* became an
// AccountId. The public key produced from the same mnemonic changed too:
//
// 1. pre Nov 2025 (qp-rusty-crystals-dilithium < 2.0.0): keygen expanded SHAKE256(seed[..32]) with
//    no domain separation. Wallets were non-HD (`Keypair::generate(seed64)`, which absorbed only
//    the first 32 bytes) or, after the multiple-accounts feature, HD at m/44'/189189'/N'/0/0 under
//    the BIP32 master HMAC key "Bitcoin seed" with a soft tail.
// 2. Nov 2025 (dilithium 2.0.0): FIPS 204 keygen, SHAKE256(seed ‖ K ‖ L) absorbing the whole input.
//    Same "Bitcoin seed" paths; the non-HD account went from an effective 32-byte input to the full
//    64-byte seed.
// 3. Feb 2026 (this CLI): default path hardened to m/44'/189189'/0'/0'/0'; --no-derivation wallets
//    became the BIP32 child at m/44'/189189'/0'.
// 4. Mar 2026 (hdwallet 2.1.0): the BIP32 master HMAC key became "Dilithium seed" (hardened-only),
//    changing every HD key again; the non-HD legacy account became FIPS keygen over seed64[..32].
//    This is the current scheme.
//
// Matching therefore derives candidate keypairs for every era and hashes
// each candidate public key under every address scheme.

/// Secret-key bytes that wipe themselves on drop.
struct SecretKeyBytes(Vec<u8>);

impl Drop for SecretKeyBytes {
	fn drop(&mut self) {
		crate::wallet::keystore::zeroize_bytes(&mut self.0);
	}
}

struct HistoricalKeypair {
	public: Vec<u8>,
	secret: SecretKeyBytes,
}

/// Every mnemonic→ML-DSA-87-keypair scheme a snapshot key may have used.
/// Ids are parsed by [`derive_historical_dilithium`]: `v1`/`fips` selects the
/// seed expansion, and the source is `seed` (the 64-byte BIP39 seed),
/// `seed32` (its first half, the chain's `from_seed`), `bip32:<path>`
/// ("Bitcoin seed" BIP32 entropy), or `hd:<path>` (current "Dilithium seed"
/// derivation).
///
/// `wallet_path` is the wallet's stored derivation path: a custom
/// `--derivation-path` import can sit outside the account window, so the
/// exact path is scanned under every era too.
fn dilithium_keygen_ids(scan_accounts: u32, wallet_path: Option<&str>) -> Vec<String> {
	let mut ids = vec![
		// Era 1 non-HD (absorbs seed64[..32]); era 2 non-HD; era 4 legacy.
		"v1:seed".to_string(),
		"fips:seed".to_string(),
		"fips:seed32".to_string(),
	];
	for account in 0..=scan_accounts {
		// Era 1 and era 2 app/CLI accounts (soft tail), era 3 CLI hardened
		// default and --no-derivation account child, era 4 current HD.
		ids.push(format!("v1:bip32:m/44'/{DILITHIUM_CHAIN_ID}/{account}'/0/0"));
		ids.push(format!("fips:bip32:m/44'/{DILITHIUM_CHAIN_ID}/{account}'/0/0"));
		ids.push(format!("fips:bip32:m/44'/{DILITHIUM_CHAIN_ID}/{account}'/0'/0'"));
		ids.push(format!("fips:bip32:m/44'/{DILITHIUM_CHAIN_ID}/{account}'"));
		ids.push(format!("fips:hd:m/44'/{DILITHIUM_CHAIN_ID}/{account}'/0'/0'"));
	}
	// "m/" (or "m") is the non-HD marker, covered by the seed ids above.
	if let Some(path) = wallet_path.map(|p| p.trim_end_matches('/')) {
		if path != "m" && !path.is_empty() {
			for id in [
				format!("v1:bip32:{path}"),
				format!("fips:bip32:{path}"),
				format!("fips:hd:{path}"),
			] {
				if !ids.contains(&id) {
					ids.push(id);
				}
			}
		}
	}
	ids
}

/// Derive the ML-DSA-87 keypair for a historical keygen id from the BIP39
/// seed. The secret key comes back in a self-wiping buffer; intermediate
/// entropy buffers are wiped before returning.
fn derive_historical_dilithium(seed: &SensitiveBytes64, id: &str) -> Result<HistoricalKeypair> {
	let (expansion, source) = id
		.split_once(':')
		.ok_or_else(|| QuantusError::Generic(format!("malformed keygen id {id:?}")))?;
	let v1 = match expansion {
		"v1" => true,
		"fips" => false,
		_ => return Err(QuantusError::Generic(format!("unknown keygen era in {id:?}"))),
	};
	if source == "seed" {
		return Ok(mldsa87_keypair(seed.as_bytes(), v1));
	}
	if source == "seed32" {
		return Ok(mldsa87_keypair(&seed.as_bytes()[..32], v1));
	}
	if let Some(path) = source.strip_prefix("bip32:") {
		let mut entropy = ExtendedPrivKey::derive(seed.as_bytes(), path)
			.map_err(|e| {
				QuantusError::Generic(format!("BIP32 derivation failed at {path}: {e:?}"))
			})?
			.secret();
		let keypair = mldsa87_keypair(&entropy, v1);
		crate::wallet::keystore::zeroize_bytes(&mut entropy);
		return Ok(keypair);
	}
	if let Some(path) = source.strip_prefix("hd:") {
		if v1 {
			return Err(QuantusError::Generic(format!(
				"keygen id {id:?} is inconsistent: no v1-era wallet used the Dilithium-seed tree"
			)));
		}
		let keypair = qp_rusty_crystals_hdwallet::ml_dsa_87::derive_key_from_seed(seed, path)
			.map_err(|e| QuantusError::Generic(format!("HD derivation failed at {path}: {e:?}")))?;
		// `to_bytes` returns a `Zeroizing` buffer, wiped when it drops here.
		let secret = SecretKeyBytes(keypair.secret().to_bytes().to_vec());
		return Ok(HistoricalKeypair { public: keypair.public().to_bytes().to_vec(), secret });
	}
	Err(QuantusError::Generic(format!("unknown keygen source in {id:?}")))
}

/// ML-DSA-87 key generation with a selectable seed expansion, built from the
/// current crate's public primitives (its `keypair_var` is not public, and
/// the historical crates' own keygens copy the seed into heap buffers they
/// free unscrubbed). `v1` selects the pre-FIPS expansion — SHAKE256 over the
/// first 32 seed bytes with no `K ‖ L` domain suffix; otherwise the FIPS 204
/// expansion absorbs the whole seed plus the suffix. Byte-equality of both
/// keypairs with the shipped dilithium 1.0.3 / 2.0.0 keygens is pinned by
/// golden vectors in the tests.
fn mldsa87_keypair(seed: &[u8], v1: bool) -> HistoricalKeypair {
	use crate::wallet::keystore::zeroize_bytes;
	use params::{
		ml_dsa_87::{ETA, K, L, PUBLICKEYBYTES, SECRETKEYBYTES},
		CRHBYTES, SEEDBYTES, TR_BYTES,
	};
	use polyvec::Polyvec;

	debug_assert!(seed.len() == 32 || seed.len() == 64);
	let mut seedbuf = [0u8; 2 * SEEDBYTES + CRHBYTES];
	if v1 {
		// The v1 expansion reads exactly SEEDBYTES from its input.
		fips202::shake256(&mut seedbuf, &seed[..SEEDBYTES]);
	} else {
		let mut preimage = [0u8; 64 + 2];
		preimage[..seed.len()].copy_from_slice(seed);
		preimage[seed.len()] = K as u8;
		preimage[seed.len() + 1] = L as u8;
		fips202::shake256(&mut seedbuf, &preimage[..seed.len() + 2]);
		zeroize_bytes(&mut preimage);
	}

	let mut rho = [0u8; SEEDBYTES];
	rho.copy_from_slice(&seedbuf[..SEEDBYTES]);
	let mut rhoprime = [0u8; CRHBYTES];
	rhoprime.copy_from_slice(&seedbuf[SEEDBYTES..SEEDBYTES + CRHBYTES]);
	let mut key = [0u8; SEEDBYTES];
	key.copy_from_slice(&seedbuf[SEEDBYTES + CRHBYTES..]);
	zeroize_bytes(&mut seedbuf);

	let mut s1 = Polyvec::<L>::default();
	for (i, p) in s1.vec.iter_mut().enumerate() {
		poly::uniform_eta::<ETA>(p, &rhoprime, i as u16);
	}
	let mut s2 = Polyvec::<K>::default();
	for (i, p) in s2.vec.iter_mut().enumerate() {
		poly::uniform_eta::<ETA>(p, &rhoprime, (L + i) as u16);
	}
	zeroize_bytes(&mut rhoprime);

	let mut s1hat = s1.clone();
	polyvec::ntt(&mut s1hat);
	let mut t1 = Polyvec::<K>::default();
	polyvec::matrix_pointwise_montgomery_streamed(&mut t1, &rho, &s1hat);
	polyvec::reduce(&mut t1);
	polyvec::invntt_tomont(&mut t1);
	polyvec::add(&mut t1, &s2);
	polyvec::caddq(&mut t1);
	let mut t0 = Polyvec::<K>::default();
	polyvec::power2round(&mut t1, &mut t0);

	let mut pk = [0u8; PUBLICKEYBYTES];
	packing::pack_pk::<K, PUBLICKEYBYTES>(&mut pk, &rho, &t1);
	let mut tr = [0u8; TR_BYTES];
	fips202::shake256(&mut tr, &pk);
	let mut sk = [0u8; SECRETKEYBYTES];
	packing::pack_sk::<K, L, ETA, SECRETKEYBYTES>(&mut sk, &rho, &tr, &key, &t0, &s1, &s2);
	zeroize_bytes(&mut key);

	// s1, s2, t0, and s1hat wipe themselves on drop (Polyvec is
	// ZeroizeOnDrop); the packed sk moves into a self-wiping buffer and its
	// stack copy is scrubbed here.
	let secret = SecretKeyBytes(sk.to_vec());
	zeroize_bytes(&mut sk);
	HistoricalKeypair { public: pk.to_vec(), secret }
}

/// Read a pasted wormhole secret from a hidden terminal prompt, for users who
/// hold only the raw secret (no mnemonic or seed) and no secret file. Argv is
/// visible in process listings and shell history, so the secret is never
/// accepted as a command-line value.
fn prompt_wormhole_secret() -> Result<SpendSecret> {
	log_print!("{}", "Paste wormhole secret (64 hex chars; input is hidden)".bright_yellow());
	let mut hex_str = rpassword::read_password()
		.map_err(|e| QuantusError::Generic(format!("Failed to read secret: {e}")))?;
	let parsed = parse_secret_hex(&hex_str);
	crate::wallet::keystore::zeroize_string(&mut hex_str);
	parsed.map(SpendSecret).map_err(QuantusError::Generic)
}

fn read_wormhole_secret(path: &std::path::Path) -> Result<SpendSecret> {
	let mut hex_str = password::read_secret_file(
		path.to_str()
			.ok_or_else(|| QuantusError::Generic("secret path is not UTF-8".into()))?,
		"secret",
	)?;
	let parsed = parse_secret_hex(&hex_str);
	crate::wallet::keystore::zeroize_string(&mut hex_str);
	parsed.map(SpendSecret).map_err(QuantusError::Generic)
}

fn resolve_claim_account(to: Option<&str>, credentials: &Credentials) -> Result<[u8; 32]> {
	if let Some(to) = to {
		let (_, account) = resolve_address_with_subxt_account_id(to)?;
		return Ok(*account.as_ref());
	}
	if let Some(account) = credentials.wallet_account {
		return Ok(account);
	}
	Err(QuantusError::Generic("--to is required when claiming without --wallet".into()))
}

#[derive(Clone, Debug)]
struct SnapshotFile {
	version: u32,
	sha256: String,
	rows: Vec<SnapshotRow>,
	by_account: HashMap<[u8; 32], SnapshotRow>,
}

#[derive(Clone, Debug, Deserialize)]
struct SnapshotRow {
	address: String,
	account: String,
	amount_hundredths: u64,
	testnets: Vec<String>,
	kind: String,
}

#[derive(Deserialize)]
struct SnapshotWire {
	version: u32,
	sha256: String,
	rows: Vec<SnapshotRow>,
}

#[derive(Clone, Debug)]
struct FoundReward {
	account: [u8; 32],
	ss58: String,
	amount_hundredths: u64,
	testnets: Vec<String>,
	kind: String,
	scheme: &'static str,
	source: RewardSource,
}

/// Where the matching key came from. Holds an index into
/// `Credentials::wormhole_secrets` (or a keygen id re-derivable from
/// `Credentials::hd_seed`) rather than a copy of the secret.
#[derive(Clone, Debug)]
enum RewardSource {
	Dilithium,
	DilithiumHistorical { keygen: String },
	Wormhole { secret_index: usize, label: String },
}

fn find_matches(snapshot: &SnapshotFile, credentials: &Credentials) -> Vec<FoundReward> {
	let mut found = Vec::new();
	if let Some(keypair) = &credentials.dilithium {
		for scheme in DilithiumHash::ALL {
			let address = scheme.derive(&keypair.public_key);
			if let Some(row) = snapshot.by_account.get(&address) {
				found.push(FoundReward {
					account: address,
					ss58: row.address.clone(),
					amount_hundredths: row.amount_hundredths,
					testnets: row.testnets.clone(),
					kind: row.kind.clone(),
					scheme: scheme.id(),
					source: RewardSource::Dilithium,
				});
			}
		}
	}
	// Dilithium keys under every historical keygen era. Current-era
	// candidates can duplicate a wallet-keypair match above; the
	// (account, scheme) dedupe below keeps the wallet-based one.
	if let Some(seed) = &credentials.hd_seed {
		for id in dilithium_keygen_ids(
			credentials.scan_accounts,
			credentials.wallet_derivation_path.as_deref(),
		) {
			let keypair = match derive_historical_dilithium(seed, &id) {
				Ok(keypair) => keypair,
				Err(e) => {
					// A path an era's tree cannot express (e.g. the wallet's
					// stored soft path under the hardened-only current tree)
					// had no wallet in that era; skip the candidate.
					log_verbose!("keygen {id} skipped: {e}");
					continue;
				},
			};
			for scheme in DilithiumHash::ALL {
				let address = scheme.derive(&keypair.public);
				if let Some(row) = snapshot.by_account.get(&address) {
					found.push(FoundReward {
						account: address,
						ss58: row.address.clone(),
						amount_hundredths: row.amount_hundredths,
						testnets: row.testnets.clone(),
						kind: row.kind.clone(),
						scheme: scheme.id(),
						source: RewardSource::DilithiumHistorical { keygen: id.clone() },
					});
				}
			}
		}
	}
	for (secret_index, (secret, label)) in credentials.wormhole_secrets.iter().enumerate() {
		for scheme in WormholeHash::ALL {
			let derived = scheme.derive(secret.bytes());
			if let Some(row) = snapshot.by_account.get(&derived.address) {
				found.push(FoundReward {
					account: derived.address,
					ss58: row.address.clone(),
					amount_hundredths: row.amount_hundredths,
					testnets: row.testnets.clone(),
					kind: row.kind.clone(),
					scheme: scheme.id(),
					source: RewardSource::Wormhole { secret_index, label: label.clone() },
				});
			}
		}
	}
	// Stable sort: within one (address, scheme) the push order above is kept,
	// so dedup retains the wallet-keypair match over a historical keygen one.
	found.sort_by(|a, b| a.ss58.cmp(&b.ss58).then(a.scheme.cmp(b.scheme)));
	found.dedup_by(|a, b| a.account == b.account && a.scheme == b.scheme);
	found
}

fn print_snapshot_header(snapshot: &SnapshotFile) {
	log_print!(
		"Snapshot v{} ({}) — {} rewarded addresses",
		snapshot.version,
		&snapshot.sha256[..snapshot.sha256.len().min(12)],
		snapshot.rows.len()
	);
}

fn print_matches(matches: &[FoundReward]) {
	if matches.is_empty() {
		log_print!("No airdrop addresses found for the supplied credentials.");
		return;
	}
	log_print!("{} snapshot match(es):", matches.len());
	for found in matches {
		let claimable = match &found.source {
			RewardSource::Dilithium | RewardSource::DilithiumHistorical { .. } => true,
			RewardSource::Wormhole { .. } => found.scheme == CLAIMABLE_WORMHOLE_SCHEME,
		};
		let note = if claimable { "claimable" } else { "not claimable yet" };
		log_print!(
			"  {}  {} QTC  {}  {} ({})  [{}]",
			found.ss58.bright_cyan(),
			format_hundredths(found.amount_hundredths),
			found.testnets.join(","),
			found.scheme,
			found.kind,
			note
		);
	}
}

enum ClaimOutcome {
	Recorded { amount_hundredths: u64 },
	Skipped,
}

async fn submit_claim(
	client: &reqwest::Client,
	server: &str,
	found: &FoundReward,
	claim_account: &[u8; 32],
	credentials: &Credentials,
	dry_run: bool,
) -> Result<ClaimOutcome> {
	let body = match &found.source {
		RewardSource::Dilithium => {
			let keypair = credentials.dilithium.as_ref().ok_or_else(|| {
				QuantusError::Generic("Dilithium match without a loaded wallet".into())
			})?;
			ClaimBody::Dilithium(build_dilithium_claim(
				&keypair.public_key,
				&keypair.private_key,
				found.account,
				*claim_account,
			)?)
		},
		RewardSource::DilithiumHistorical { keygen } => {
			let seed = credentials.hd_seed.as_ref().ok_or_else(|| {
				QuantusError::Generic("historical Dilithium match without a wallet mnemonic".into())
			})?;
			// Re-derive the era's keypair; the secret key wipes on drop.
			let keypair = derive_historical_dilithium(seed, keygen)?;
			ClaimBody::Dilithium(build_dilithium_claim(
				&keypair.public,
				&keypair.secret.0,
				found.account,
				*claim_account,
			)?)
		},
		RewardSource::Wormhole { secret_index, label } => {
			if found.scheme != CLAIMABLE_WORMHOLE_SCHEME {
				log_print!(
					"Skipping {} ({}) from {label}: server only accepts {CLAIMABLE_WORMHOLE_SCHEME}",
					found.ss58,
					found.scheme
				);
				return Ok(ClaimOutcome::Skipped);
			}
			let (secret, _) = credentials.wormhole_secrets.get(*secret_index).ok_or_else(|| {
				QuantusError::Generic("wormhole secret index out of range".into())
			})?;
			log_print!("Proving wormhole ownership for {}…", found.ss58.bright_cyan());
			ClaimBody::Wormhole(build_wormhole_claim(secret, *claim_account).await?)
		},
	};

	if dry_run {
		let json = serde_json::to_string_pretty(&body)
			.map_err(|e| QuantusError::Generic(format!("claim JSON: {e}")))?;
		log_print!("Dry run: would POST {} ({}):", found.ss58, found.scheme);
		log_print!("{json}");
		return Ok(ClaimOutcome::Recorded { amount_hundredths: found.amount_hundredths });
	}

	let url = format!("{}/claim", server.trim_end_matches('/'));
	let response = client.post(&url).json(&body).send().await.map_err(http_err)?;
	let status = response.status();
	let text = response.text().await.map_err(http_err)?;
	if !status.is_success() {
		return Err(QuantusError::Generic(format_server_error(status, &text)));
	}
	let recorded: ClaimResponse = serde_json::from_str(&text)
		.map_err(|e| QuantusError::Generic(format!("claim JSON: {e}")))?;
	log_success!(
		"Recorded {} → {} ({} QTC)",
		recorded.address.bright_cyan(),
		address_with_checkphrase(&recorded.claim_account),
		format_hundredths(recorded.amount_hundredths)
	);
	Ok(ClaimOutcome::Recorded { amount_hundredths: recorded.amount_hundredths })
}

fn build_dilithium_claim(
	public_key: &[u8],
	secret_key: &[u8],
	address: [u8; 32],
	claim_account: [u8; 32],
) -> Result<DilithiumClaimBody> {
	let expiry_unix = now_unix()?.saturating_add(CLAIM_TTL_SECS);
	let msg = claim_message(&address, &claim_account, expiry_unix);
	let secret = SecretKey::from_bytes(secret_key)
		.map_err(|_| QuantusError::Generic("invalid ML-DSA-87 secret key".into()))?;
	let signature = secret
		.sign(&msg, Some(CLAIM_CONTEXT), None)
		.map_err(|e| QuantusError::Generic(format!("ML-DSA sign failed: {e}")))?;
	let scheme = DilithiumHash::ALL
		.iter()
		.find(|s| s.derive(public_key) == address)
		.ok_or_else(|| QuantusError::Generic("could not identify Dilithium hash scheme".into()))?;
	Ok(DilithiumClaimBody {
		scheme: scheme.id().to_string(),
		address: bytes_to_quantus_ss58(&address),
		claim_account: bytes_to_quantus_ss58(&claim_account),
		public_key: hex::encode(public_key),
		signature: hex::encode(signature),
		expiry_unix,
	})
}

async fn build_wormhole_claim(
	secret: &SpendSecret,
	claim_account: [u8; 32],
) -> Result<WormholeClaimBody> {
	// `Secret::new` zeroizes its source, so this stack copy is scrubbed even
	// though it outlives the call (unlike `Secret::try_from`, which leaves
	// the source bytes intact).
	let mut secret_bytes = *secret.bytes();
	let secret = Secret::new(&mut secret_bytes)
		.map_err(|e| QuantusError::Generic(format!("invalid wormhole secret: {e:?}")))?;
	let claim = BytesDigest::try_from(claim_account.as_slice())
		.map_err(|e| QuantusError::Generic(format!("invalid claim account: {e:?}")))?;
	let inputs = CircuitInputs::from_secret(secret, claim);
	let proof = tokio::task::spawn_blocking(move || {
		let prover = qp_ownership_prover::build_fresh().commit(&inputs)?;
		prover.prove()
	})
	.await
	.map_err(|e| QuantusError::Generic(format!("ownership prover task failed: {e}")))?
	.map_err(|e| QuantusError::Generic(format!("ownership proof failed: {e}")))?;
	Ok(WormholeClaimBody {
		proof_kind: "wormhole_rate8".into(),
		proof: hex::encode(proof.to_bytes()),
	})
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ClaimBody {
	Dilithium(DilithiumClaimBody),
	Wormhole(WormholeClaimBody),
}

#[derive(Serialize)]
struct DilithiumClaimBody {
	scheme: String,
	address: String,
	claim_account: String,
	public_key: String,
	signature: String,
	expiry_unix: i64,
}

#[derive(Serialize)]
struct WormholeClaimBody {
	proof_kind: String,
	proof: String,
}

#[derive(Deserialize)]
struct ClaimResponse {
	address: String,
	claim_account: String,
	amount_hundredths: u64,
}

#[derive(Deserialize)]
struct ErrorBody {
	error: String,
}

async fn fetch_snapshot(server: &str) -> Result<SnapshotFile> {
	let url = format!("{}/snapshot", server.trim_end_matches('/'));
	log_verbose!("GET {url}");
	let response = http_client()?.get(&url).send().await.map_err(http_err)?;
	let status = response.status();
	let text = response.text().await.map_err(http_err)?;
	if !status.is_success() {
		return Err(QuantusError::Generic(format_server_error(status, &text)));
	}
	let wire: SnapshotWire = serde_json::from_str(&text)
		.map_err(|e| QuantusError::Generic(format!("snapshot JSON: {e}")))?;
	let mut by_account = HashMap::new();
	for row in &wire.rows {
		let account = parse_account_id(&row.account).or_else(|_| parse_account_id(&row.address))?;
		by_account.insert(account, row.clone());
	}
	Ok(SnapshotFile { version: wire.version, sha256: wire.sha256, rows: wire.rows, by_account })
}

fn parse_account_id(s: &str) -> Result<[u8; 32]> {
	let s = s.trim();
	if s.starts_with("qz") {
		let (account, _) = AccountId32::from_ss58check_with_version(s)
			.map_err(|e| QuantusError::Generic(format!("invalid SS58 {s}: {e:?}")))?;
		return Ok(*account.as_ref());
	}
	let hex_str = s.strip_prefix("0x").unwrap_or(s);
	let bytes = hex::decode(hex_str)
		.map_err(|e| QuantusError::Generic(format!("invalid account hex: {e}")))?;
	bytes.try_into().map_err(|b: Vec<u8>| {
		QuantusError::Generic(format!("account must be 32 bytes, got {}", b.len()))
	})
}

fn http_client() -> Result<reqwest::Client> {
	reqwest::Client::builder()
		.timeout(Duration::from_secs(120))
		.build()
		.map_err(|e| QuantusError::Generic(format!("HTTP client: {e}")))
}

fn http_err(e: reqwest::Error) -> QuantusError {
	QuantusError::NetworkError(e.to_string())
}

fn format_server_error(status: reqwest::StatusCode, body: &str) -> String {
	if let Ok(err) = serde_json::from_str::<ErrorBody>(body) {
		format!("server {status}: {}", err.error)
	} else {
		format!("server {status}: {}", body.trim())
	}
}

fn format_hundredths(amount: u64) -> String {
	format!("{}.{:02}", amount / 100, amount % 100)
}

fn now_unix() -> Result<i64> {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.map_err(|e| QuantusError::Generic(format!("system clock: {e}")))
}

fn claim_message(address: &[u8; 32], claim_account: &[u8; 32], expiry_unix: i64) -> [u8; 72] {
	let mut msg = [0u8; 72];
	msg[..32].copy_from_slice(address);
	msg[32..64].copy_from_slice(claim_account);
	msg[64..].copy_from_slice(&expiry_unix.to_be_bytes());
	msg
}

#[derive(Clone, Copy, Debug)]
enum DilithiumHash {
	V08Padded,
	V091Padded,
	V09Padded,
	V10Padded,
	Rate8HashBytes,
}

impl DilithiumHash {
	const ALL: &'static [Self] = &[
		Self::V08Padded,
		Self::V091Padded,
		Self::V09Padded,
		Self::V10Padded,
		Self::Rate8HashBytes,
	];

	fn id(self) -> &'static str {
		match self {
			Self::V08Padded => "dilithium-v08-padded",
			Self::V091Padded => "dilithium-v091-padded",
			Self::V09Padded => "dilithium-v09-padded",
			Self::V10Padded => "dilithium-v10-padded",
			Self::Rate8HashBytes => "dilithium-rate8-hash-bytes",
		}
	}

	fn derive(self, public_key: &[u8]) -> [u8; 32] {
		match self {
			Self::V08Padded => hash_padded_legacy(public_key, 8, 73),
			Self::V091Padded => hash_padded_legacy(public_key, 4, 188),
			Self::V09Padded => hash_padded_v09(public_key),
			Self::V10Padded => hash_padded_v10(public_key),
			Self::Rate8HashBytes => qp_poseidon_core::hash_bytes(public_key),
		}
	}
}

#[derive(Clone, Copy, Debug)]
enum WormholeHash {
	V09Injective,
	Rate4Compact,
	Rate8Compact,
	Rate4Injective,
	Rate8Injective,
}

impl WormholeHash {
	const ALL: &'static [Self] = &[
		Self::V09Injective,
		Self::Rate4Compact,
		Self::Rate8Compact,
		Self::Rate4Injective,
		Self::Rate8Injective,
	];

	fn id(self) -> &'static str {
		match self {
			Self::V09Injective => "wormhole-v09-injective",
			Self::Rate4Compact => "wormhole-rate4-compact",
			Self::Rate8Compact => "wormhole-rate8-compact",
			Self::Rate4Injective => "wormhole-rate4-injective",
			Self::Rate8Injective => "wormhole-rate8-injective",
		}
	}

	fn derive(self, secret: &[u8; 32]) -> DerivedWormhole {
		if matches!(self, Self::V09Injective) {
			return derive_v09(secret);
		}
		let salt = injective4(b"wormhole");
		// Full capacity up front: growing the buffer after secret felts are
		// written would free the old block unscrubbed. injective4 of a
		// 32-byte secret is exactly 9 felts; compact8 is 4.
		let mut preimage =
			SensitiveFelts::with_capacity(qp_poseidon_core::Goldilocks::ZERO, salt.len() + 9);
		for felt in salt {
			preimage.push(felt);
		}
		match self {
			Self::V09Injective => unreachable!("handled above"),
			Self::Rate4Injective | Self::Rate8Injective => {
				for word in injective4_secret_words(secret) {
					preimage.push(qp_poseidon_core::Goldilocks::from_u64(word));
				}
			},
			Self::Rate4Compact | Self::Rate8Compact => {
				let mut digest = compact8_decode(secret);
				for felt in digest {
					preimage.push(felt);
				}
				wipe_felts(&mut digest);
			},
		}
		let first_hash = self.sponge().hash_felts(preimage.as_slice());
		let address = self.sponge().rehash(&first_hash);
		DerivedWormhole { first_hash, address }
	}

	fn sponge(self) -> Sponge {
		match self {
			Self::V09Injective => unreachable!("v09 uses its own field type; see derive()"),
			Self::Rate4Compact | Self::Rate4Injective => Sponge::Rate4Pad10,
			Self::Rate8Compact | Self::Rate8Injective => Sponge::Rate8Pad10,
		}
	}
}

struct DerivedWormhole {
	#[allow(dead_code)]
	first_hash: [u8; 32],
	address: [u8; 32],
}

#[derive(Clone, Copy)]
enum Sponge {
	Rate4Pad10,
	Rate8Pad10,
}

impl Sponge {
	fn hash_felts(self, input: &[qp_poseidon_core::Goldilocks]) -> [u8; 32] {
		match self {
			Self::Rate4Pad10 => hash_felts_rate4_pad10(input),
			Self::Rate8Pad10 => qp_poseidon_core::hash_to_bytes(input),
		}
	}

	fn rehash(self, digest: &[u8; 32]) -> [u8; 32] {
		self.hash_felts(&compact8_decode(digest))
	}
}

fn derive_v09(secret: &[u8; 32]) -> DerivedWormhole {
	use p3_field::{integers::QuotientMap, PrimeCharacteristicRing};
	type F = p3_goldilocks::Goldilocks;
	let salt = v09::injective_bytes_to_felts(b"wormhole");
	// Pre-sized zeroize-on-drop buffer, hashed from a borrowed slice by the
	// local v09 sponge. qp-poseidon-core 0.9.5's own `hash_no_pad` takes its
	// preimage Vec by value and frees it unscrubbed, so it must never see
	// the secret.
	let mut preimage = SensitiveFelts::with_capacity(F::ZERO, salt.len() + 9);
	for felt in salt {
		preimage.push(felt);
	}
	for word in injective4_secret_words(secret) {
		preimage.push(F::from_int(word));
	}
	let first_hash = v09_hash_no_pad(preimage.as_slice());
	let address = v09_hash_no_pad(&v09::digest_bytes_to_felts(&first_hash));
	DerivedWormhole { first_hash, address }
}

/// The v0.9.5 Poseidon2 permutation, rebuilt from the same public crates the
/// historical qp-poseidon-core used: ChaCha8-derived constants with seed
/// 0x189189189189189 over `Poseidon2Goldilocks<12>`. Equality with
/// `Poseidon2Core::new()` is pinned by the wormhole-v09-injective golden
/// vector test.
fn v09_permutation() -> &'static p3_goldilocks::Poseidon2Goldilocks<12> {
	use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
	static PERMUTATION: std::sync::OnceLock<p3_goldilocks::Poseidon2Goldilocks<12>> =
		std::sync::OnceLock::new();
	PERMUTATION.get_or_init(|| {
		const V09_POSEIDON2_SEED: u64 = 0x189189189189189;
		let mut rng = ChaCha8Rng::seed_from_u64(V09_POSEIDON2_SEED);
		p3_goldilocks::Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng)
	})
}

/// qp-poseidon-core 0.9.5's `hash_no_pad` sponge (rate 4, terminator felt in
/// the last short block, `[1,0,0,0]` block after a full final chunk, then an
/// unconditional `[0,0,0,1]` domain block), reimplemented over a borrowed
/// slice with stack state so no secret-bearing heap allocation is created or
/// handed to code that frees it unscrubbed.
fn v09_hash_no_pad(input: &[p3_goldilocks::Goldilocks]) -> [u8; 32] {
	use p3_field::{PrimeCharacteristicRing, PrimeField64};
	use p3_symmetric::Permutation;
	type F = p3_goldilocks::Goldilocks;
	const WIDTH: usize = 12;
	const RATE: usize = 4;

	let wipe = |felts: &mut [F]| {
		felts.fill(F::ZERO);
		core::hint::black_box(felts);
	};

	let poseidon2 = v09_permutation();
	let mut state = [F::ZERO; WIDTH];
	let mut block = [F::ZERO; RATE];
	let num_chunks = input.chunks(RATE).len();
	let mut unpadded = false;
	for (j, chunk) in input.chunks(RATE).enumerate() {
		block.fill(F::ZERO);
		if j == num_chunks - 1 {
			if chunk.len() < RATE {
				block[chunk.len()] = F::ONE;
			} else {
				unpadded = true;
			}
		}
		block[..chunk.len()].copy_from_slice(chunk);
		for i in 0..RATE {
			state[i] += block[i];
		}
		poseidon2.permute_mut(&mut state);
	}
	if unpadded {
		state[0] += F::ONE;
		poseidon2.permute_mut(&mut state);
	}
	state[RATE - 1] += F::ONE;
	poseidon2.permute_mut(&mut state);

	let mut out = [0u8; 32];
	for (i, felt) in state[..RATE].iter().enumerate() {
		out[i * 8..(i + 1) * 8].copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
	}
	wipe(&mut state);
	wipe(&mut block);
	out
}

/// The injective 4-bytes-per-felt encoding of a 32-byte secret, as canonical
/// limb values: eight little-endian u32 words plus the `1` terminator
/// (32 % 4 == 0, so the terminator is always appended). Matches both
/// `injective4` and v0.9.5's `injective_bytes_to_felts` without materializing
/// an intermediate felt buffer.
fn injective4_secret_words(secret: &[u8; 32]) -> impl Iterator<Item = u64> + '_ {
	secret
		.chunks(4)
		.map(|chunk| u32::from_le_bytes(chunk.try_into().expect("4-byte chunk")) as u64)
		.chain([1u64])
}

/// Heap buffer for secret-bearing field elements. The full capacity must be
/// reserved before secret material is written (a growing `Vec` frees its old
/// block unscrubbed); limbs are wiped on drop. Generic so both the current
/// qp-poseidon-core felts and the v09 p3-goldilocks felts are covered.
struct SensitiveFelts<F: Copy> {
	felts: Vec<F>,
	zero: F,
}

impl<F: Copy> SensitiveFelts<F> {
	fn with_capacity(zero: F, capacity: usize) -> Self {
		Self { felts: Vec::with_capacity(capacity), zero }
	}

	fn push(&mut self, felt: F) {
		debug_assert!(self.felts.len() < self.felts.capacity(), "SensitiveFelts must be pre-sized");
		self.felts.push(felt);
	}

	fn as_slice(&self) -> &[F] {
		&self.felts
	}
}

impl<F: Copy> Drop for SensitiveFelts<F> {
	fn drop(&mut self) {
		// Same dead-store-resistant wipe as `wipe_felts`.
		self.felts.fill(self.zero);
		core::hint::black_box(self.felts.as_mut_slice());
	}
}

/// Zero field elements, resistant to dead-store elimination: `black_box`
/// makes the compiler assume the zeros are observed, so the fill cannot be
/// elided (same construction as qp-poseidon-core's internal state wipe).
fn wipe_felts(felts: &mut [qp_poseidon_core::Goldilocks]) {
	felts.fill(qp_poseidon_core::Goldilocks::ZERO);
	core::hint::black_box(felts);
}

fn compact8_decode(
	bytes: &[u8; 32],
) -> [qp_poseidon_core::Goldilocks; qp_poseidon_core::POSEIDON2_OUTPUT] {
	qp_poseidon_core::serialization::bytes_to_digest_lossy(bytes)
}

fn injective4(bytes: &[u8]) -> Vec<qp_poseidon_core::Goldilocks> {
	use qp_poseidon_core::Goldilocks;
	if bytes.is_empty() {
		return Vec::new();
	}
	const N: usize = 4;
	let mut out = Vec::new();
	let num_chunks = bytes.len().div_ceil(N);
	let mut unpadded = false;
	for (i, chunk) in bytes.chunks(N).enumerate() {
		let mut word = [0u8; N];
		if i == num_chunks - 1 {
			if chunk.len() < N {
				word[chunk.len()] = 1;
			} else {
				unpadded = true;
			}
		}
		word[..chunk.len()].copy_from_slice(chunk);
		out.push(Goldilocks::from_u64(u32::from_le_bytes(word) as u64));
	}
	if unpadded {
		out.push(Goldilocks::from_u64(1));
	}
	out
}

fn hash_felts_rate4_pad10(x: &[qp_poseidon_core::Goldilocks]) -> [u8; 32] {
	use qp_poseidon_core::{Goldilocks, Poseidon2, POSEIDON2_OUTPUT, SPONGE_WIDTH};
	const RATE_4: usize = 4;
	let poseidon = Poseidon2::new();
	let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];
	let mut buf = [Goldilocks::ZERO; RATE_4];
	let mut buf_len = 0usize;

	let absorb = |felt: Goldilocks,
	              state: &mut [Goldilocks; SPONGE_WIDTH],
	              buf: &mut [Goldilocks; RATE_4],
	              buf_len: &mut usize| {
		buf[*buf_len] = felt;
		*buf_len += 1;
		if *buf_len == RATE_4 {
			for i in 0..RATE_4 {
				state[i] += buf[i];
			}
			poseidon.permute_mut(state);
			*buf = [Goldilocks::ZERO; RATE_4];
			*buf_len = 0;
		}
	};

	for &felt in x {
		absorb(felt, &mut state, &mut buf, &mut buf_len);
	}
	absorb(Goldilocks::ONE, &mut state, &mut buf, &mut buf_len);
	while buf_len != 0 {
		absorb(Goldilocks::ZERO, &mut state, &mut buf, &mut buf_len);
	}

	let digest: [Goldilocks; POSEIDON2_OUTPUT] =
		state[..POSEIDON2_OUTPUT].try_into().expect("width > output");
	// The absorb buffer holds raw preimage felts and the state is the
	// permuted secret; wipe both before returning.
	wipe_felts(&mut state);
	wipe_felts(&mut buf);
	qp_poseidon_core::serialization::digest_to_bytes(&digest)
}

// The v0.9.x permutation used different round constants than the current one,
// so v09 derivations go through the real historical crate.
fn hash_padded_v09(bytes: &[u8]) -> [u8; 32] {
	v09::Poseidon2Core::new().hash_padded(bytes)
}

// Pre-0.9.5 Resonance AccountId hash: legacy plonky2 Poseidon (unchanged in
// the current qp-plonky2) over little-endian limbs, zero-padded to a fixed
// preimage length. poseidon-resonance 0.8.0 used 8-byte limbs and 73 felts;
// qp-poseidon 0.9.1 used 4-byte limbs and 188 felts.
fn hash_padded_legacy(bytes: &[u8], bytes_per_felt: usize, pad_to: usize) -> [u8; 32] {
	use plonky2::{
		field::{goldilocks_field::GoldilocksField, types::Field},
		plonk::config::{GenericHashOut, Hasher},
	};

	let mut felts: Vec<GoldilocksField> = bytes
		.chunks(bytes_per_felt)
		.map(|chunk| {
			let mut word = [0u8; 8];
			word[..chunk.len()].copy_from_slice(chunk);
			GoldilocksField::from_noncanonical_u64(u64::from_le_bytes(word))
		})
		.collect();
	if felts.len() < pad_to {
		felts.resize(pad_to, GoldilocksField::ZERO);
	}
	plonky2::hash::poseidon::PoseidonHash::hash_no_pad(&felts)
		.to_bytes()
		.try_into()
		.expect("poseidon output is 32 bytes")
}

fn hash_padded_v10(bytes: &[u8]) -> [u8; 32] {
	use qp_poseidon_core::Goldilocks;
	const PAD: usize = 189;
	let mut felts = injective4(bytes);
	if felts.len() < PAD {
		felts.resize(PAD, Goldilocks::ZERO);
	}
	hash_felts_rate4_pad10(&felts)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn hex32(s: &str) -> [u8; 32] {
		hex::decode(s).unwrap().try_into().unwrap()
	}

	const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
	                             abandon abandon abandon about";

	fn test_seed() -> SensitiveBytes64 {
		let mut seed = SensitiveBytes64::zeroed();
		mnemonic_to_seed(TEST_MNEMONIC.into(), None, &mut seed).unwrap();
		seed
	}

	#[test]
	fn hd_scan_covers_change_branch_and_multiround_rounds() {
		let secrets = derive_hd_wormhole_secrets(&test_seed(), None, 8).unwrap();
		// Current tree + "Bitcoin seed" tree + the legacy master node.
		assert_eq!(secrets.len(), 2 * (9 * 17) + 1);

		// A `wormhole multiround` round-2 address must be in the scan and match
		// direct derivation.
		let path = format!("m/44'/{}/0'/2'/1'", QUANTUS_WORMHOLE_CHAIN_ID);
		let direct =
			qp_rusty_crystals_hdwallet::derive_wormhole_from_mnemonic(TEST_MNEMONIC, None, &path)
				.unwrap();
		let (secret, _) = secrets
			.iter()
			.find(|(_, label)| label == &format!("hd {path}"))
			.expect("round-2 path in scan");
		assert_eq!(secret.bytes(), direct.secret().as_bytes());

		// Explicit index still scans every branch/round in both trees.
		let pinned = derive_hd_wormhole_secrets(&test_seed(), Some(1), 8).unwrap();
		assert_eq!(pinned.len(), 2 * 9 + 1);
		assert!(pinned.iter().any(|(_, label)| label == &format!("hd {path}")));
	}

	/// `--scan-rounds` extends the wormhole window: a round-9 multiround
	/// secret is outside the default scan but found once the window covers it.
	#[test]
	fn scan_rounds_flag_reaches_round_nine() {
		let seed = test_seed();
		let path = format!("m/44'/{}/0'/9'/0'", QUANTUS_WORMHOLE_CHAIN_ID);
		let direct = generate_wormhole_from_seed(&seed, &path).unwrap();

		let default_window = derive_hd_wormhole_secrets(&seed, None, 8).unwrap();
		assert!(!default_window.iter().any(|(_, label)| label == &format!("hd {path}")));

		let widened = derive_hd_wormhole_secrets(&seed, None, 9).unwrap();
		let (secret, _) = widened
			.iter()
			.find(|(_, label)| label == &format!("hd {path}"))
			.expect("round-9 path in widened scan");
		assert_eq!(secret.bytes(), direct.secret().as_bytes());
	}

	/// The pre-March-2026 wormhole entropies ("Bitcoin seed" BIP32) pinned by
	/// the hdwallet 1.0.0 probe: the master-node secret
	/// (`generate_wormhole_pair`) and a path-derived one
	/// (`generate_wormhole_pair_from_path`).
	#[test]
	fn hd_scan_covers_bitcoin_seed_wormhole_entropies() {
		let secrets = derive_hd_wormhole_secrets(&test_seed(), None, 8).unwrap();
		let get = |label: &str| {
			secrets
				.iter()
				.find(|(_, l)| l == label)
				.unwrap_or_else(|| panic!("{label} missing"))
				.0
				.bytes()
				.to_owned()
		};
		assert_eq!(
			get("bitcoin-seed m"),
			hex32("1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67")
		);
		let path = format!("m/44'/{}/0'/0'/0'", QUANTUS_WORMHOLE_CHAIN_ID);
		assert_eq!(
			get(&format!("bitcoin-seed {path}")),
			hex32("87b3000325d7058a64b01b93f199b3d54ba5d9b2e036cee672199e7da326538c")
		);
	}

	/// sha256(pk) vectors computed with the exact shipped crates
	/// (`.probe-keygen`): qp-rusty-crystals-dilithium 1.0.3 (pre-FIPS
	/// expansion), 2.0.0 (FIPS expansion), qp-rusty-crystals-hdwallet 1.0.0
	/// ("Bitcoin seed" BIP32), and the current 4.1.1. These pin the local
	/// keygen reimplementation and the BIP32 tree to the historical bytes.
	#[test]
	fn historical_dilithium_keygens_match_shipped_crate_vectors() {
		use sha2::Digest;
		let seed = test_seed();
		let ids = dilithium_keygen_ids(8, None);
		let vectors = [
			("v1:seed", "77993f1dafc02c9162925807f825f611bab071d121d6a42250bc4957c9149562"),
			(
				"v1:bip32:m/44'/189189'/0'/0/0",
				"57eafbd7c902c02686aff7f39c692beb9f3c057383dc6c954defc381e2c59f7d",
			),
			("fips:seed", "1819feeaba63629813f1266de3d135de22ec505f1e014e669011cd9399bacb6f"),
			(
				"fips:bip32:m/44'/189189'/0'/0/0",
				"08fffe331b888d215c335e82712aa41ef680edd57e4634a89cca81b87e021e24",
			),
			(
				"fips:bip32:m/44'/189189'/0'/0'/0'",
				"7aeb9126559a7f750bf90941f632cf1f2835a57500cb1be74d9d3d15007d7e8d",
			),
			(
				"fips:bip32:m/44'/189189'/0'",
				"a49dac7c3537f61476626d491016abb2ca0e355be017c8cbbabc5a705d1cb5d7",
			),
			("fips:seed32", "2af97815f11fb93d64d0e93fecff2b0e7af88882ed9fda813b5cd6f421799ab2"),
			(
				"fips:hd:m/44'/189189'/0'/0'/0'",
				"aa46cca1014fa42d40388298b33a7537d6a313b401f5be259cc59797cf4307e7",
			),
		];
		for (id, expected_pk_sha) in vectors {
			assert!(ids.iter().any(|i| i == id), "{id} missing from scan list");
			let keypair = derive_historical_dilithium(&seed, id).unwrap();
			assert_eq!(hex::encode(sha2::Sha256::digest(&keypair.public)), expected_pk_sha, "{id}");
		}
		// Secret keys too, for the two locally reimplemented expansions: the
		// packed sk must be byte-identical to the historical crates' output.
		let v1 = derive_historical_dilithium(&seed, "v1:seed").unwrap();
		assert_eq!(
			hex::encode(sha2::Sha256::digest(&v1.secret.0)),
			"fbcb8f8db649111054baddc24f3eaab314c120950d76fdb8df5c1cd6a4102aa9"
		);
		let fips = derive_historical_dilithium(&seed, "fips:seed").unwrap();
		assert_eq!(
			hex::encode(sha2::Sha256::digest(&fips.secret.0)),
			"fbe63db6ccf71badbb5a4aea59bead046637065fca38270b1a6361644ecf20d3"
		);
	}

	/// An address minted by an era-1 wallet (pre-FIPS keygen, soft HD path,
	/// v0.8 address hash) is found from the seed alone, and the claim built
	/// for it signs with the era's key, verifying under the current crate —
	/// which is what the claim server runs.
	fn snapshot_for(address: [u8; 32]) -> SnapshotFile {
		let row = SnapshotRow {
			address: bytes_to_quantus_ss58(&address),
			account: hex::encode(address),
			amount_hundredths: 150,
			testnets: vec!["Resonance".into()],
			kind: "dilithium".into(),
		};
		SnapshotFile {
			version: 1,
			sha256: "0".repeat(64),
			rows: vec![row.clone()],
			by_account: HashMap::from([(address, row)]),
		}
	}

	fn seed_only_credentials(seed: SensitiveBytes64) -> Credentials {
		Credentials {
			dilithium: None,
			wallet_account: None,
			wormhole_secrets: Vec::new(),
			hd_seed: Some(seed),
			wallet_derivation_path: None,
			scan_accounts: 8,
		}
	}

	#[test]
	fn matches_and_claims_historical_dilithium_address() {
		let keygen = "v1:bip32:m/44'/189189'/1'/0/0";
		let seed = test_seed();
		let keypair = derive_historical_dilithium(&seed, keygen).unwrap();
		let address = DilithiumHash::V08Padded.derive(&keypair.public);
		let snapshot = snapshot_for(address);
		let credentials = seed_only_credentials(seed);

		let matches = find_matches(&snapshot, &credentials);
		assert_eq!(matches.len(), 1);
		assert_eq!(matches[0].scheme, "dilithium-v08-padded");
		let RewardSource::DilithiumHistorical { keygen: found_keygen } = &matches[0].source else {
			panic!("expected a historical Dilithium source");
		};
		assert_eq!(found_keygen, keygen);

		let claim_account = [9u8; 32];
		let body =
			build_dilithium_claim(&keypair.public, &keypair.secret.0, address, claim_account)
				.unwrap();
		assert_eq!(body.scheme, "dilithium-v08-padded");
		let msg = claim_message(&address, &claim_account, body.expiry_unix);
		let public =
			qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(&keypair.public).unwrap();
		let sig = hex::decode(&body.signature).unwrap();
		assert!(public.verify(&msg, &sig, Some(CLAIM_CONTEXT)));
	}

	/// `--scan-accounts` extends the Dilithium window: an account-9 key is
	/// outside the default scan but found once the window covers it.
	#[test]
	fn scan_accounts_flag_reaches_account_nine() {
		let keygen = "fips:bip32:m/44'/189189'/9'/0'/0'";
		let seed = test_seed();
		let keypair = derive_historical_dilithium(&seed, keygen).unwrap();
		let address = DilithiumHash::V10Padded.derive(&keypair.public);
		let snapshot = snapshot_for(address);

		let mut credentials = seed_only_credentials(seed);
		assert!(find_matches(&snapshot, &credentials).is_empty());

		credentials.scan_accounts = 9;
		let matches = find_matches(&snapshot, &credentials);
		assert_eq!(matches.len(), 1);
		let RewardSource::DilithiumHistorical { keygen: found_keygen } = &matches[0].source else {
			panic!("expected a historical Dilithium source");
		};
		assert_eq!(found_keygen, keygen);
	}

	/// The wallet's stored derivation path is scanned under every era even
	/// when it lies outside the account window — including soft paths the
	/// hardened-only current tree cannot express (those eras are skipped,
	/// not treated as scan failures).
	#[test]
	fn wallet_derivation_path_is_scanned_across_eras() {
		let keygen = "v1:bip32:m/44'/189189'/42'/0/0";
		let seed = test_seed();
		let keypair = derive_historical_dilithium(&seed, keygen).unwrap();
		let address = DilithiumHash::V08Padded.derive(&keypair.public);
		let snapshot = snapshot_for(address);

		let mut credentials = seed_only_credentials(seed);
		assert!(find_matches(&snapshot, &credentials).is_empty());

		credentials.wallet_derivation_path = Some("m/44'/189189'/42'/0/0".into());
		let matches = find_matches(&snapshot, &credentials);
		assert_eq!(matches.len(), 1);
		let RewardSource::DilithiumHistorical { keygen: found_keygen } = &matches[0].source else {
			panic!("expected a historical Dilithium source");
		};
		assert_eq!(found_keygen, keygen);
	}

	/// The non-HD marker path stored by legacy wallets must not add
	/// duplicate candidates (the seed ids already cover it).
	#[test]
	fn wallet_marker_path_adds_no_candidates() {
		assert_eq!(dilithium_keygen_ids(8, Some("m/")), dilithium_keygen_ids(8, None));
		assert_eq!(dilithium_keygen_ids(8, Some("m")), dilithium_keygen_ids(8, None));
		// A path already inside the window only adds era variants the window
		// lacks (here just v1:bip32 with a hardened tail).
		assert_eq!(
			dilithium_keygen_ids(8, Some("m/44'/189189'/0'/0'/0'")).len(),
			dilithium_keygen_ids(8, None).len() + 1
		);
	}

	/// #160103: wormhole secrets must not be accepted on argv. The paste
	/// prompt (`--wormhole-secret-prompt`) is a bare flag; any variant that
	/// takes the secret as a command-line value must fail to parse.
	#[test]
	fn airdrop_rejects_secret_cli_argument() {
		use clap::Parser;

		#[derive(Parser, Debug)]
		#[command(name = "quantus")]
		struct TestCli {
			#[command(subcommand)]
			command: crate::cli::Commands,
		}

		let secret = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
		for args in [
			vec!["quantus", "airdrop", "check", "--wormhole-secret", secret],
			vec!["quantus", "airdrop", "claim", "--wormhole-secret", secret],
			vec!["quantus", "airdrop", "check", "--wormhole-secret-prompt", secret],
			vec!["quantus", "airdrop", "claim", "--wormhole-secret-prompt", secret],
		] {
			let result = TestCli::try_parse_from(args.clone());
			assert!(result.is_err(), "airdrop must not accept a secret on argv; args={args:?}");
		}

		for args in [
			vec!["quantus", "airdrop", "check", "--wormhole-secret-prompt"],
			vec!["quantus", "airdrop", "claim", "--wormhole-secret-prompt"],
		] {
			assert!(
				TestCli::try_parse_from(args.clone()).is_ok(),
				"bare --wormhole-secret-prompt must parse; args={args:?}"
			);
		}
	}

	#[test]
	fn claim_message_is_address_dest_expiry() {
		let address = [1u8; 32];
		let dest = [2u8; 32];
		let expiry = 0x0102_0304_0506_0708i64;
		let msg = claim_message(&address, &dest, expiry);
		assert_eq!(&msg[..32], &address);
		assert_eq!(&msg[32..64], &dest);
		assert_eq!(&msg[64..], &expiry.to_be_bytes());
	}

	#[test]
	fn current_wormhole_matches_hdwallet_golden() {
		let secret = hex32("30051cfa3abd462d3bc26da2d660e90ba8af6080b7fe95d9fd3f3b37c7d9ce4b");
		let derived = WormholeHash::Rate8Compact.derive(&secret);
		assert_eq!(
			derived.first_hash,
			hex32("890ff21aa4fda75dc56c6c322c164d3c21a18ca7853d368c28cf158affc8b5b1")
		);
		assert_eq!(
			derived.address,
			hex32("6a2f0d3abe4390e0b05f6dea4ba10670676cda7c00d49526ddde59f16c85269f")
		);
	}

	/// Vectors computed with the exact crates the shipped Resonance chains
	/// pinned: poseidon-resonance 0.8.0 (rev fcb49a7, plonky2 fork rev 80a1000,
	/// per chain tag v0.0.12-resonance-alpha) and crates.io qp-poseidon 0.9.1
	/// (per chain rev e9fc9b9). The 2592-byte input is ML-DSA-87 pubkey sized.
	#[test]
	fn pre_v095_dilithium_matches_original_crate_vectors() {
		assert_eq!(
			DilithiumHash::V08Padded.derive(&[0u8]),
			hex32("fdf0715f178bfb2381d3804961bda8c679990d6318ff53f7a6475e1bef1982ca")
		);
		assert_eq!(
			DilithiumHash::V08Padded.derive(&[5u8; 2592]),
			hex32("9c69917b10f0228a0beed1d78ce34026b4778dc04a49a401dd5e692a51f44207")
		);
		assert_eq!(
			DilithiumHash::V091Padded.derive(&[0u8]),
			hex32("c4f1020767625056e669e3653f190b7763c6c398a45f1dc20db0d7ed32b14ff7")
		);
		assert_eq!(
			DilithiumHash::V091Padded.derive(&[5u8; 2592]),
			hex32("8ba4f919664c796aa811f552eaff5975570d56ed6812728944f60fe7d28d3c74")
		);
	}

	/// Vectors computed with qp-poseidon-core 0.9.5 (git tag v0.9.5); the `[0]`
	/// digest was also independently reproduced from the original tagged source.
	#[test]
	fn v09_schemes_match_original_crate_vectors() {
		assert_eq!(
			DilithiumHash::V09Padded.derive(&[0u8]),
			hex32("b17b423096da9ebd57af5038b490257d9c492e64059c0ccff23f44e6293213d4")
		);
		assert_eq!(
			WormholeHash::V09Injective.derive(&[42u8; 32]).address,
			hex32("f4e231ede747e9ca2da9528add147ee488651a0df72b00313b0a8e6b76388fea")
		);
	}

	#[test]
	fn historical_wormhole_schemes_diverge() {
		let secret = [9u8; 32];
		let addrs: Vec<_> = WormholeHash::ALL.iter().map(|s| s.derive(&secret).address).collect();
		assert!(addrs.iter().any(|a| *a != addrs[0]));
	}

	#[test]
	fn dilithium_hash_schemes_diverge() {
		let pk = [7u8; 64];
		let addrs: Vec<_> = DilithiumHash::ALL.iter().map(|s| s.derive(&pk)).collect();
		for i in 0..addrs.len() {
			for j in (i + 1)..addrs.len() {
				assert_ne!(
					addrs[i],
					addrs[j],
					"{} and {} collide",
					DilithiumHash::ALL[i].id(),
					DilithiumHash::ALL[j].id()
				);
			}
		}
		let a = DilithiumHash::V09Padded.derive(&pk);
		let b = DilithiumHash::V10Padded.derive(&pk);
		let c = DilithiumHash::Rate8HashBytes.derive(&pk);
		assert_ne!(a, b);
		assert_ne!(b, c);
	}

	#[test]
	fn dilithium_claim_json_is_internally_tagged() {
		let body = ClaimBody::Dilithium(DilithiumClaimBody {
			scheme: "dilithium-v10-padded".into(),
			address: "qzabc".into(),
			claim_account: "qzdef".into(),
			public_key: "aa".into(),
			signature: "bb".into(),
			expiry_unix: 42,
		});
		let value = serde_json::to_value(&body).unwrap();
		assert_eq!(value["kind"], "dilithium");
		assert_eq!(value["scheme"], "dilithium-v10-padded");
		assert_eq!(value["expiry_unix"], 42);
		assert!(value.get("Dilithium").is_none());
	}

	#[test]
	fn wormhole_claim_json_is_internally_tagged() {
		let body = ClaimBody::Wormhole(WormholeClaimBody {
			proof_kind: "wormhole_rate8".into(),
			proof: "cc".into(),
		});
		let value = serde_json::to_value(&body).unwrap();
		assert_eq!(value["kind"], "wormhole");
		assert_eq!(value["proof_kind"], "wormhole_rate8");
		assert_eq!(value["proof"], "cc");
	}

	#[test]
	fn spend_secret_debug_is_redacted() {
		let secret = SpendSecret([0xAB; 32]);
		let debug = format!("{secret:?}");
		assert!(!debug.contains("ab"), "debug output must not leak secret bytes: {debug}");
		assert!(!debug.contains("171"), "debug output must not leak secret bytes: {debug}");
		assert!(debug.contains("redacted"));
	}

	#[test]
	fn reward_source_debug_has_no_secret_material() {
		let source = RewardSource::Wormhole { secret_index: 0, label: "hd m/44'".into() };
		let debug = format!("{source:?}");
		assert!(debug.contains("secret_index"));
	}

	#[test]
	fn resolve_claim_account_prefers_to_over_wallet_account() {
		let credentials = Credentials {
			dilithium: None,
			wallet_account: Some([5u8; 32]),
			wormhole_secrets: Vec::new(),
			hd_seed: None,
			wallet_derivation_path: None,
			scan_accounts: 8,
		};
		let dest = [7u8; 32];
		let resolved =
			resolve_claim_account(Some(&bytes_to_quantus_ss58(&dest)), &credentials).unwrap();
		assert_eq!(resolved, dest);
	}

	#[test]
	fn resolve_claim_account_defaults_to_unlocked_wallet_without_reopening() {
		// The wallet account must come from Credentials (captured at unlock,
		// works for ML-DSA-65 + --password-file), not from re-resolving the
		// wallet name, which cannot see --password-file.
		let credentials = Credentials {
			dilithium: None,
			wallet_account: Some([5u8; 32]),
			wormhole_secrets: Vec::new(),
			hd_seed: None,
			wallet_derivation_path: None,
			scan_accounts: 8,
		};
		assert_eq!(resolve_claim_account(None, &credentials).unwrap(), [5u8; 32]);
	}

	#[test]
	fn resolve_claim_account_requires_to_without_wallet() {
		let credentials = Credentials {
			dilithium: None,
			wallet_account: None,
			wormhole_secrets: Vec::new(),
			hd_seed: None,
			wallet_derivation_path: None,
			scan_accounts: 8,
		};
		assert!(resolve_claim_account(None, &credentials).is_err());
	}

	fn unpaid_row(status: &str, claim_account: Option<&str>, amount: u64) -> UnpaidRow {
		UnpaidRow {
			address: "qAddr".into(),
			claim_account: claim_account.map(str::to_string),
			amount_hundredths: amount,
			kind: "dilithium".into(),
			scheme: Some("dilithium-v08-padded".into()),
			verified_at: Some(1_760_000_000),
			status: status.into(),
		}
	}

	#[test]
	fn recorded_payouts_keeps_only_recorded_rows_with_accounts() {
		let payouts = recorded_payouts(vec![
			unpaid_row("recorded", Some("qDest"), 150),
			unpaid_row("unclaimed", None, 999),
			unpaid_row("recorded", Some("qDest2"), 0),
		])
		.unwrap();
		assert_eq!(payouts.len(), 1);
		assert_eq!(payouts[0].claim_account, "qDest");
		assert_eq!(payouts[0].amount_hundredths, 150);

		// A recorded row without a claim account is a server bug, not a skip.
		assert!(recorded_payouts(vec![unpaid_row("recorded", None, 150)]).is_err());
	}

	/// Like passwords, the admin bearer token must not be accepted on argv.
	#[test]
	fn admin_token_rejected_on_argv() {
		let err = load_admin_token(&AdminTokenSource {
			argv: Some("token".into()),
			file: Some("/tmp/whatever".into()),
		})
		.unwrap_err()
		.to_string();
		assert!(err.contains("--admin-token-file"), "unexpected error: {err}");
	}

	#[test]
	fn verification_flags_paid_addresses_still_listed() {
		let rows =
			vec![unpaid_row("recorded", Some("qDest"), 150), unpaid_row("unclaimed", None, 10)];
		// unpaid_row uses address "qAddr" for every row.
		assert_eq!(
			addresses_still_listed(&rows, &["qAddr".to_string(), "qOther".to_string()]),
			vec!["qAddr".to_string(), "qAddr".to_string()],
		);
		assert!(addresses_still_listed(&rows, &["qGone".to_string()]).is_empty());
		assert!(addresses_still_listed(&[], &["qAddr".to_string()]).is_empty());
	}

	#[test]
	fn payout_selection_filters_and_limits() {
		let payout = |address: &str| Payout {
			address: address.into(),
			claim_account: "qDest".into(),
			amount_hundredths: 100,
			scheme: "dilithium-v10-padded".into(),
			verified_at: None,
		};
		let all = vec![payout("qA"), payout("qB"), payout("qC")];

		let none = PayoutSelection { only: vec![], limit: None };
		assert_eq!(select_payouts(all.clone(), &none).unwrap().len(), 3);

		let one = PayoutSelection { only: vec![], limit: Some(1) };
		let selected = select_payouts(all.clone(), &one).unwrap();
		assert_eq!(selected.len(), 1);
		assert_eq!(selected[0].address, "qA");

		let only_b = PayoutSelection { only: vec!["qB".into()], limit: None };
		let selected = select_payouts(all.clone(), &only_b).unwrap();
		assert_eq!(selected.len(), 1);
		assert_eq!(selected[0].address, "qB");

		let missing = PayoutSelection { only: vec!["qZ".into()], limit: None };
		assert!(select_payouts(all.clone(), &missing).is_err());

		let zero = PayoutSelection { only: vec![], limit: Some(0) };
		assert!(select_payouts(all, &zero).is_err());
	}

	#[test]
	fn hundredths_convert_to_raw_chain_units() {
		// 1.50 QTC at 12 decimals.
		assert_eq!(hundredths_to_raw(150, 12).unwrap(), 1_500_000_000_000);
		// 2 decimals: hundredths are already the raw unit.
		assert_eq!(hundredths_to_raw(150, 2).unwrap(), 150);
		// Fewer than 2 decimals cannot represent hundredths.
		assert!(hundredths_to_raw(150, 1).is_err());
		// Overflow is an error, not a wrap.
		assert!(hundredths_to_raw(u64::MAX, 38).is_err());
	}

	#[test]
	fn unpaid_response_parses_server_wire_format() {
		let unpaid: UnpaidResponse = serde_json::from_str(
			r#"{"rows":[{"address":"qA","claim_account":"qB","amount_hundredths":150,
			"kind":"dilithium","scheme":"dilithium-v10-padded","verified_at":1760000000,
			"status":"recorded"},{"address":"qC","claim_account":null,"amount_hundredths":10,
			"kind":"wormhole","scheme":null,"verified_at":null,"status":"unclaimed"}],
			"total_amount_hundredths":160}"#,
		)
		.unwrap();
		assert_eq!(unpaid.rows.len(), 2);
		let payouts = recorded_payouts(unpaid.rows).unwrap();
		assert_eq!(payouts.len(), 1);
		assert_eq!(payouts[0].address, "qA");
		assert_eq!(payouts[0].scheme, "dilithium-v10-padded");
	}

	#[test]
	fn finish_claims_fails_when_all_submissions_failed() {
		assert!(finish_claims(false, 0, 0, 0, 3).is_err());
	}

	#[test]
	fn finish_claims_fails_on_partial_failure() {
		assert!(finish_claims(false, 150, 1, 1, 1).is_err());
	}

	#[test]
	fn finish_claims_succeeds_with_skips_but_no_failures() {
		assert!(finish_claims(false, 150, 1, 2, 0).is_ok());
		assert!(finish_claims(true, 0, 1, 0, 0).is_ok());
	}
}

/// Regression test (security review): wormhole address matching must never
/// free heap memory that still contains the spend secret.
///
/// Mirroring `heap_zeroization.rs` in qp-zk-circuits, a global allocator
/// scans every freed block for the secret at `dealloc` time (the block is
/// still valid inside the hook). Two byte images are searched, because the
/// secret appears in two encodings: the raw 32 bytes (also the in-memory
/// image of the compact8 felt encoding — every 8-byte limb of the ASCII
/// pattern is canonical), and the injective4 felt image (4 secret bytes then
/// 4 zero bytes per limb). No exemptions: the v09 scheme hashes through the
/// local borrowed-slice sponge precisely so that no allocation holding the
/// secret is ever freed, by anyone.
///
/// The scanner only reacts to blocks containing the distinctive pattern, so
/// unrelated tests running in the same binary cannot trip it.
#[cfg(test)]
mod heap_zeroization_tests {
	use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use std::{
		alloc::{GlobalAlloc, Layout, System},
		sync::OnceLock,
	};

	use super::{injective4_secret_words, WormholeHash};
	use crate::cli::wormhole::parse_secret_hex;

	/// Distinctive all-ASCII 32-byte pattern; see module docs for why ASCII
	/// makes the compact8 felt image identical to the raw bytes.
	const SECRET_PATTERN: [u8; 32] = *b"quantus-cli-airdrop-zeroize-pat!";

	static SCANNING: AtomicBool = AtomicBool::new(false);
	static LEAKED_BLOCK_SIZE: AtomicUsize = AtomicUsize::new(0);
	/// Injective4 felt image of the pattern (precomputed: the dealloc hook
	/// should not allocate).
	static INJECTIVE4_IMAGE: OnceLock<Vec<u8>> = OnceLock::new();

	fn contains(haystack: &[u8], needle: &[u8]) -> bool {
		haystack.windows(needle.len()).any(|w| w == needle)
	}

	struct SecretScanningAllocator;

	unsafe impl GlobalAlloc for SecretScanningAllocator {
		unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
			unsafe { System.alloc(layout) }
		}

		unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
			if SCANNING.load(Ordering::SeqCst) && layout.size() >= SECRET_PATTERN.len() {
				let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
				let hit = contains(block, &SECRET_PATTERN) ||
					INJECTIVE4_IMAGE.get().is_some_and(|img| contains(block, img));
				if hit {
					LEAKED_BLOCK_SIZE.store(layout.size(), Ordering::SeqCst);
				}
			}
			unsafe { System.dealloc(ptr, layout) }
		}
	}

	#[global_allocator]
	static ALLOCATOR: SecretScanningAllocator = SecretScanningAllocator;

	fn injective4_image() -> Vec<u8> {
		injective4_secret_words(&SECRET_PATTERN)
			.take(8) // the terminator limb is not secret material
			.flat_map(u64::to_le_bytes)
			.collect()
	}

	#[test]
	fn matching_never_frees_heap_memory_containing_the_secret() {
		INJECTIVE4_IMAGE.set(injective4_image()).expect("set once");

		LEAKED_BLOCK_SIZE.store(0, Ordering::SeqCst);
		SCANNING.store(true, Ordering::SeqCst);
		for scheme in WormholeHash::ALL {
			let derived = scheme.derive(&SECRET_PATTERN);
			core::hint::black_box(derived.address);
		}
		// Explicit-secret ingestion: `parse_secret_hex` decodes into a stack
		// buffer (`hex::decode` would free a Vec holding the credential
		// unscrubbed), on error paths too.
		let secret_hex = hex::encode(SECRET_PATTERN);
		let parsed = parse_secret_hex(&secret_hex).expect("valid secret hex");
		core::hint::black_box(parsed);
		let mut bad_digit = hex::encode(&SECRET_PATTERN[..31]);
		bad_digit.push_str("zz");
		assert!(parse_secret_hex(&bad_digit).is_err());
		assert!(parse_secret_hex(&secret_hex[..62]).is_err());
		assert!(parse_secret_hex(&secret_hex[..63]).is_err());
		SCANNING.store(false, Ordering::SeqCst);

		let leaked = LEAKED_BLOCK_SIZE.load(Ordering::SeqCst);
		assert_eq!(
			leaked, 0,
			"a heap block of {leaked} bytes still containing the spend secret was freed \
			 unscrubbed; check SensitiveFelts pre-sizing and drop in cli/airdrop.rs"
		);
	}
}
