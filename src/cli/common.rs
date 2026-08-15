//! Common SubXT utilities and functions shared across CLI commands
use crate::{chain::client::ChainConfig, error::Result, log_error, log_verbose};
use colored::Colorize;
use hex;
use sp_core::crypto::{AccountId32, Ss58Codec};
use subxt::{
	tx::{TxProgress, TxStatus},
	OnlineClient,
};

pub type SubxtAccountId32 = subxt::ext::subxt_core::utils::AccountId32;

const MILLIS_PER_SECOND: u64 = 1_000;
/// Pre-inclusion inactivity window. The status stream is legitimately silent
/// between Broadcasted and InBestBlock for a full PoW block interval, and block
/// intervals are roughly exponential around the ~10s target: a 30s window
/// aborted ~1 in 20 valid transactions (e^-3), inviting duplicate-submission
/// retries. Twelve target intervals make a spurious abort negligible (~e^-12)
/// while still catching genuinely dead streams well inside the overall deadline.
const TX_STATUS_INACTIVITY_TIMEOUT_SECS: u64 = 120;
const TX_STATUS_INCLUDED_TIMEOUT_SECS: u64 = 5 * 60;
pub(crate) const TX_STATUS_FINALIZED_TIMEOUT_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutionMode {
	pub finalized: bool,
	pub wait_for_transaction: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStage {
	Submitted,
	Included,
	Finalized,
}

impl ExecutionMode {
	pub fn transaction_stage(self) -> TransactionStage {
		if self.finalized {
			TransactionStage::Finalized
		} else if self.wait_for_transaction {
			TransactionStage::Included
		} else {
			TransactionStage::Submitted
		}
	}

	pub fn should_watch_transaction(self) -> bool {
		self.transaction_stage() != TransactionStage::Submitted
	}
}

impl TransactionStage {
	pub fn status_label(self) -> &'static str {
		match self {
			Self::Submitted => "submitted",
			Self::Included => "included",
			Self::Finalized => "finalized",
		}
	}

	pub fn success_detail(self) -> &'static str {
		match self {
			Self::Submitted => "accepted by the node",
			Self::Included => "included in a best block",
			Self::Finalized => "finalized in a block",
		}
	}
}

pub(crate) fn delay_blocks_to_u32(blocks: u64) -> Result<u32> {
	u32::try_from(blocks).map_err(|_| {
		crate::error::QuantusError::Generic(format!(
			"Delay in blocks ({blocks}) exceeds the maximum supported block delay ({})",
			u32::MAX
		))
	})
}

pub(crate) fn delay_seconds_to_millis(seconds: u64) -> Result<u64> {
	seconds.checked_mul(MILLIS_PER_SECOND).ok_or_else(|| {
		crate::error::QuantusError::Generic(format!(
			"Delay in seconds ({seconds}) exceeds the maximum supported timestamp delay ({})",
			u64::MAX / MILLIS_PER_SECOND
		))
	})
}

fn tx_status_watch_timeout_secs(target_stage: TransactionStage) -> u64 {
	match target_stage {
		TransactionStage::Submitted => 0,
		TransactionStage::Included => TX_STATUS_INCLUDED_TIMEOUT_SECS,
		TransactionStage::Finalized => TX_STATUS_FINALIZED_TIMEOUT_SECS,
	}
}

/// How long to wait for the next status update.
///
/// A short inactivity timeout detects stalled streams before inclusion. After a
/// transaction is in a best block and we are waiting for PoW finalization, silent
/// gaps can exceed that inactivity window, so only the overall watch deadline applies.
fn next_status_wait_secs(remaining_watch_secs: u64, apply_inactivity_timeout: bool) -> u64 {
	if remaining_watch_secs == 0 {
		return 0;
	}
	if apply_inactivity_timeout {
		remaining_watch_secs.min(TX_STATUS_INACTIVITY_TIMEOUT_SECS)
	} else {
		remaining_watch_secs
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WatchedTxEvent {
	Validated,
	Broadcasted,
	NoLongerInBestBlock,
	InBestBlock,
	InFinalizedBlock,
	Error(String),
	Invalid(String),
	Dropped(String),
	StreamError(String),
	StreamEnded,
	/// No status updates within the short inactivity window.
	InactivityTimedOut {
		timeout_secs: u64,
	},
	/// Overall inclusion/finalization deadline elapsed.
	WatchDeadlineTimedOut {
		elapsed_secs: u64,
	},
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchDecision {
	Continue,
	WaitForFinalization,
	Success,
}

fn describe_watched_tx_event(
	event: WatchedTxEvent,
	target_stage: TransactionStage,
) -> Result<WatchDecision> {
	match event {
		WatchedTxEvent::Validated |
		WatchedTxEvent::Broadcasted |
		WatchedTxEvent::NoLongerInBestBlock => Ok(WatchDecision::Continue),
		WatchedTxEvent::InBestBlock =>
			if target_stage == TransactionStage::Finalized {
				Ok(WatchDecision::WaitForFinalization)
			} else {
				Ok(WatchDecision::Success)
			},
		WatchedTxEvent::InFinalizedBlock => Ok(WatchDecision::Success),
		WatchedTxEvent::Error(message) =>
			Err(crate::error::QuantusError::NetworkError(format!("Transaction error: {message}"))),
		WatchedTxEvent::Invalid(message) =>
			Err(crate::error::QuantusError::NetworkError(format!("Transaction invalid: {message}"))),
		WatchedTxEvent::Dropped(message) =>
			Err(crate::error::QuantusError::NetworkError(format!("Transaction dropped: {message}"))),
		WatchedTxEvent::StreamError(message) => Err(crate::error::QuantusError::NetworkError(
			format!("Transaction status stream error: {message}"),
		)),
		WatchedTxEvent::StreamEnded => Err(crate::error::QuantusError::NetworkError(format!(
			"Transaction status stream ended before the transaction was {}",
			target_stage.status_label()
		))),
		WatchedTxEvent::InactivityTimedOut { timeout_secs } =>
			Err(crate::error::QuantusError::NetworkError(format!(
				"Transaction status stream timed out after {timeout_secs} seconds without updates before the transaction was {}. The transaction may still be in the pool and execute later; verify its status on chain before resubmitting, or you may duplicate it",
				target_stage.status_label()
			))),
		WatchedTxEvent::WatchDeadlineTimedOut { elapsed_secs } =>
			Err(crate::error::QuantusError::NetworkError(format!(
				"Timed out after waiting {elapsed_secs} seconds for the transaction to be {}. The transaction may still be in the pool and execute later; verify its status on chain before resubmitting, or you may duplicate it",
				target_stage.status_label()
			))),
	}
}

fn should_check_execution_success(
	block_hash: &subxt::utils::H256,
	already_checked_for: Option<&subxt::utils::H256>,
) -> bool {
	already_checked_for != Some(block_hash)
}

/// Require the watched extrinsic to be present in the reported block.
/// Returns its index for event scanning, or an error if the hash is absent.
fn require_extrinsic_index(our_extrinsic_index: Option<usize>) -> Result<usize> {
	our_extrinsic_index.ok_or_else(|| {
		crate::error::QuantusError::NetworkError(
			"Extrinsic hash not found in reported block".to_string(),
		)
	})
}

/// `Break` carries the outcome of the watch: the hash of the block in which the
/// transaction reached the target stage, or the terminal error.
type TxWatchFlow = std::ops::ControlFlow<Result<subxt::utils::H256>, ()>;

fn update_waiting_spinner(
	spinner: Option<&indicatif::ProgressBar>,
	target_stage: TransactionStage,
	elapsed_secs: u64,
) {
	if let Some(pb) = spinner {
		if target_stage == TransactionStage::Finalized {
			pb.set_message(format!("Waiting for finalized block... ({}s)", elapsed_secs));
		} else {
			pb.set_message(format!("Waiting for block inclusion... ({}s)", elapsed_secs));
		}
	}
}

fn finish_failed_execution(
	spinner: Option<&indicatif::ProgressBar>,
	message: &str,
	elapsed_secs: u64,
) {
	if let Some(pb) = spinner {
		pb.finish_with_message(format!("{message} ({}s)", elapsed_secs));
	}
}

async fn ensure_execution_success_for_block(
	client: &OnlineClient<ChainConfig>,
	block_hash: &subxt::utils::H256,
	tx_hash: &subxt::utils::H256,
	execution_success_checked_for: &mut Option<subxt::utils::H256>,
) -> Result<()> {
	if should_check_execution_success(block_hash, execution_success_checked_for.as_ref()) {
		check_execution_success(client, block_hash, tx_hash).await?;
		*execution_success_checked_for = Some(*block_hash);
	}
	Ok(())
}

async fn handle_in_best_block(
	client: &OnlineClient<ChainConfig>,
	tx_hash: &subxt::utils::H256,
	block_hash: subxt::utils::H256,
	target_stage: TransactionStage,
	execution_success_checked_for: &mut Option<subxt::utils::H256>,
	spinner: Option<&indicatif::ProgressBar>,
	elapsed_secs: u64,
) -> TxWatchFlow {
	crate::log_verbose!("   Transaction included in block: {:?}", block_hash);
	if let Err(err) = ensure_execution_success_for_block(
		client,
		&block_hash,
		tx_hash,
		execution_success_checked_for,
	)
	.await
	{
		finish_failed_execution(spinner, "❌ Transaction failed in block", elapsed_secs);
		return std::ops::ControlFlow::Break(Err(err));
	}

	match describe_watched_tx_event(WatchedTxEvent::InBestBlock, target_stage) {
		Ok(WatchDecision::WaitForFinalization) => {
			if let Some(pb) = spinner {
				pb.set_message(format!(
					"In best block, waiting for finalization... ({}s)",
					elapsed_secs
				));
			}
			std::ops::ControlFlow::Continue(())
		},
		Ok(WatchDecision::Success) => {
			if let Some(pb) = spinner {
				pb.finish_with_message(format!(
					"✅ Transaction included in block! ({}s)",
					elapsed_secs
				));
			}
			std::ops::ControlFlow::Break(Ok(block_hash))
		},
		Ok(WatchDecision::Continue) => std::ops::ControlFlow::Continue(()),
		Err(err) => std::ops::ControlFlow::Break(Err(err)),
	}
}

async fn handle_in_finalized_block(
	client: &OnlineClient<ChainConfig>,
	tx_hash: &subxt::utils::H256,
	block_hash: subxt::utils::H256,
	target_stage: TransactionStage,
	execution_success_checked_for: &mut Option<subxt::utils::H256>,
	spinner: Option<&indicatif::ProgressBar>,
	elapsed_secs: u64,
) -> TxWatchFlow {
	crate::log_verbose!("   Transaction finalized in block: {:?}", block_hash);
	if let Err(err) = ensure_execution_success_for_block(
		client,
		&block_hash,
		tx_hash,
		execution_success_checked_for,
	)
	.await
	{
		finish_failed_execution(spinner, "❌ Transaction failed in finalized block", elapsed_secs);
		return std::ops::ControlFlow::Break(Err(err));
	}

	match describe_watched_tx_event(WatchedTxEvent::InFinalizedBlock, target_stage) {
		Ok(WatchDecision::Success) => {
			if let Some(pb) = spinner {
				pb.finish_with_message(format!("✅ Transaction finalized! ({}s)", elapsed_secs));
			}
			std::ops::ControlFlow::Break(Ok(block_hash))
		},
		Ok(WatchDecision::Continue) | Ok(WatchDecision::WaitForFinalization) =>
			std::ops::ControlFlow::Continue(()),
		Err(err) => std::ops::ControlFlow::Break(Err(err)),
	}
}

/// Resolve address - if it's a wallet name, return the wallet's address
/// If it's already an SS58 address, return it as is
pub fn resolve_address(address_or_wallet_name: &str) -> Result<String> {
	// First, try to parse as SS58 address
	if AccountId32::from_ss58check_with_version(address_or_wallet_name).is_ok() {
		// It's a valid SS58 address, return as is
		return Ok(address_or_wallet_name.to_string());
	}

	// If not a valid SS58 address, try to find it as a wallet name
	let wallet_manager = crate::wallet::WalletManager::new()?;
	match wallet_manager.find_wallet_address(address_or_wallet_name)? {
		crate::wallet::WalletAddressLookup::Address(wallet_address) => {
			log_verbose!(
				"🔍 Found wallet '{}' with address: {}",
				address_or_wallet_name.bright_cyan(),
				wallet_address.bright_green()
			);
			Ok(wallet_address)
		},
		crate::wallet::WalletAddressLookup::Protected =>
			resolve_protected_wallet_address(&wallet_manager, address_or_wallet_name),
		crate::wallet::WalletAddressLookup::NotFound => Err(crate::error::QuantusError::Generic(
			format!(
				"Invalid destination: '{address_or_wallet_name}' is neither a valid SS58 address nor a known wallet name"
			),
		)),
	}
}

/// Unlock path for resolving a password-protected wallet's address by name.
///
/// Uses the wallet's environment-variable password when set (works in
/// scripts), prompts when running on a terminal, and otherwise fails with an
/// error naming the wallet instead of pretending it does not exist.
fn resolve_protected_wallet_address(
	wallet_manager: &crate::wallet::WalletManager,
	wallet_name: &str,
) -> Result<String> {
	use std::io::IsTerminal;

	let password = if let Some(env_password) =
		crate::wallet::password::env_wallet_password(wallet_name)
	{
		env_password
	} else if std::io::stdin().is_terminal() {
		crate::log_print!(
			"🔒 Wallet '{}' is password-protected; enter its password to resolve its address",
			wallet_name.bright_cyan()
		);
		crate::wallet::password::get_password_from_user(&format!(
			"Enter password for wallet '{wallet_name}'"
		))?
	} else {
		return Err(crate::error::QuantusError::Generic(format!(
			"Wallet '{wallet_name}' exists but is password-protected and no password source is available non-interactively. Pass the SS58 address directly, or set QUANTUS_WALLET_PASSWORD_{} to unlock it",
			wallet_name.to_uppercase()
		)));
	};

	let wallet_data = wallet_manager.load_wallet(wallet_name, &password)?;
	let address = wallet_data.keypair.try_to_account_id_ss58check()?;
	log_verbose!(
		"🔍 Unlocked wallet '{}' with address: {}",
		wallet_name.bright_cyan(),
		address.bright_green()
	);
	Ok(address)
}

/// Resolve a wallet name or SS58 address and convert it into the AccountId32 type used by SubXT.
pub fn resolve_to_subxt_account_id(address_or_wallet_name: &str) -> Result<SubxtAccountId32> {
	let (_, account_id) = resolve_address_with_subxt_account_id(address_or_wallet_name)?;
	Ok(account_id)
}

/// Resolve a wallet name or SS58 address and return both the SS58 string and SubXT account id.
pub fn resolve_address_with_subxt_account_id(
	address_or_wallet_name: &str,
) -> Result<(String, SubxtAccountId32)> {
	let resolved_address = resolve_address(address_or_wallet_name)?;
	let (account_id_sp, _) =
		AccountId32::from_ss58check_with_version(&resolved_address).map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Invalid destination address {resolved_address}: {e:?}"
			))
		})?;
	let account_id_bytes: [u8; 32] = *account_id_sp.as_ref();
	Ok((resolved_address, SubxtAccountId32::from(account_id_bytes)))
}

/// Get fresh nonce for account from the latest block using existing QuantusClient
/// This function ensures we always get the most current nonce from the chain
/// to avoid "Transaction is outdated" errors
pub async fn get_fresh_nonce_with_client(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
) -> Result<u64> {
	let from_account_id = from_keypair.try_to_account_id_32().map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Invalid from keypair public key: {e}"))
	})?;

	// Get nonce from the latest block (best block)
	let latest_nonce = quantus_client
		.get_account_nonce_from_best_block(&from_account_id)
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to get account nonce from best block: {e:?}"
			))
		})?;

	log_verbose!("🔢 Using fresh nonce from latest block: {}", latest_nonce);

	// Compare with nonce from finalized block for debugging
	let finalized_nonce = quantus_client
		.client()
		.tx()
		.account_nonce(&from_account_id)
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to get account nonce from finalized block: {e:?}"
			))
		})?;

	if latest_nonce != finalized_nonce {
		log_verbose!(
			"⚠️  Nonce difference detected! Latest: {}, Finalized: {}",
			latest_nonce,
			finalized_nonce
		);
	}

	Ok(latest_nonce)
}

/// Submit transaction with optional finalization check
///
/// By default, returns immediately after the node accepts the transaction submission.
/// With `wait_for_transaction=true`, waits until the transaction is in a best block.
/// With `finalized=true`, waits until the transaction is in a finalized block.
///
/// Cold (watch-only) signers are routed to the QR signing flow instead of local
/// signing; there is no retry loop there, since a QR-signed extrinsic can never
/// be silently rebuilt.
pub async fn submit_transaction<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	signer: &crate::wallet::WalletSigner,
	call: Call,
	tip: Option<u128>,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	let (tx_hash, _included_in) =
		submit_transaction_with_inclusion_block(quantus_client, signer, call, tip, execution_mode)
			.await?;
	Ok(tx_hash)
}

/// Reject ML-DSA-65 signers on runtimes that only decode ML-DSA-87 signatures.
async fn ensure_keypair_scheme_supported(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
) -> crate::error::Result<()> {
	if from_keypair.scheme != crate::wallet::DilithiumScheme::MlDsa65 {
		return Ok(());
	}
	let (spec_version, transaction_version) = quantus_client.get_runtime_version().await?;
	crate::config::ensure_ml_dsa_65_supported(spec_version, transaction_version)
}

/// Like [`submit_transaction`], but also returns the hash of the block in which
/// the transaction reached the requested stage (`None` when the transaction was
/// only submitted without watching).
///
/// Callers that read events for the transaction must use this block hash rather
/// than the current best/finalized tip, which may have moved past the inclusion
/// block by the time the watch returns.
pub async fn submit_transaction_with_inclusion_block<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	signer: &crate::wallet::WalletSigner,
	call: Call,
	tip: Option<u128>,
	execution_mode: ExecutionMode,
) -> crate::error::Result<(subxt::utils::H256, Option<subxt::utils::H256>)>
where
	Call: subxt::tx::Payload,
{
	let from_keypair = match signer {
		crate::wallet::WalletSigner::Hot(keypair) => {
			crate::cli::cold_signing::warn_if_cold_flags_unused();
			keypair
		},
		crate::wallet::WalletSigner::Cold { name, address } =>
			return crate::cli::cold_signing::sign_and_submit_cold(
				quantus_client,
				name,
				address,
				&call,
				tip,
				None,
				execution_mode,
				crate::cli::cold_signing::ColdIo::global(),
			)
			.await,
	};
	ensure_keypair_scheme_supported(quantus_client, from_keypair).await?;
	let signer = from_keypair.to_subxt_signer().map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {e:?}"))
	})?;

	// Get a fresh nonce from the best block. Do not automatically resubmit the same
	// call with a different nonce after a submission error: without authoritative
	// confirmation that the prior extrinsic was rejected, doing so can duplicate
	// non-idempotent transactions.
	let nonce = get_fresh_nonce_with_client(quantus_client, from_keypair).await?;
	log_verbose!("🔢 Using fresh nonce from best block: {}", nonce);

	// Get current block for logging using latest block hash
	let latest_block_hash = quantus_client.get_latest_block().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get latest block: {e:?}"))
	})?;

	log_verbose!("🔗 Latest block hash: {:?}", latest_block_hash);

	// Create custom params with fresh nonce and optional tip
	use subxt::config::DefaultExtrinsicParamsBuilder;
	let mut params_builder = DefaultExtrinsicParamsBuilder::new()
		.mortal(256) // Value higher than our finalization - TODO: should come from config
		.nonce(nonce);

	if let Some(tip_amount) = tip {
		params_builder = params_builder.tip(tip_amount);
		log_verbose!("💰 Using tip: {} to increase priority", tip_amount);
	} else {
		log_verbose!("💰 No tip specified");
	}

	// Try to get chain parameters from the client
	// let genesis_hash = quantus_client.get_genesis_hash().await?;
	// let (spec_version, transaction_version) = quantus_client.get_runtime_version().await?;

	// log_verbose!("🔍 Chain parameters:");
	// log_verbose!("   Genesis hash: {:?}", genesis_hash);
	// log_verbose!("   Spec version: {}", spec_version);
	// log_verbose!("   Transaction version: {}", transaction_version);

	// For now, just use the default params
	let params = params_builder.build();

	// Log transaction parameters for debugging
	log_verbose!("🔍 Transaction parameters:");
	log_verbose!("   Nonce: {}", nonce);
	log_verbose!("   Tip: {:?}", tip);
	log_verbose!("   Latest block hash: {:?}", latest_block_hash);

	// Get and log era information
	log_verbose!("   Era: Using default era from SubXT");
	log_verbose!("   Genesis hash: Using default from SubXT");
	log_verbose!("   Spec version: Using default from SubXT");

	// Log additional debugging info
	log_verbose!("🔍 Additional debugging:");
	log_verbose!("   Call type: {:?}", std::any::type_name::<Call>());

	let metadata = quantus_client.client().metadata();
	let encoded_call =
		<_ as subxt::tx::Payload>::encode_call_data(&call, &metadata).map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Failed to encode call: {:?}", e))
		})?;
	crate::log_verbose!("📝 Encoded call: 0x{}", hex::encode(&encoded_call));
	crate::log_print!("📝 Encoded call size: {} bytes", encoded_call.len());

	if execution_mode.should_watch_transaction() {
		match quantus_client
			.client()
			.tx()
			.sign_and_submit_then_watch(&call, &signer, params)
			.await
		{
			Ok(mut tx_progress) => {
				crate::log_verbose!("📋 Transaction submitted: {:?}", tx_progress);

				let tx_hash = tx_progress.extrinsic_hash();

				let included_in = wait_tx_inclusion(
					&mut tx_progress,
					quantus_client.client(),
					&tx_hash,
					execution_mode.transaction_stage(),
				)
				.await?;

				Ok((tx_hash, Some(included_in)))
			},
			Err(e) => {
				log_error!("❌ Failed to submit transaction: {e:?}");
				Err(e.into())
			},
		}
	} else {
		match quantus_client.client().tx().sign_and_submit(&call, &signer, params).await {
			Ok(tx_hash) => {
				crate::log_print!("✅ Transaction submitted: {:?}", tx_hash);
				Ok((tx_hash, None))
			},
			Err(e) => {
				log_error!("❌ Failed to submit transaction: {e:?}");
				Err(e.into())
			},
		}
	}
}

/// Submit an already-signed transaction, honoring the execution mode.
///
/// Used by the cold-wallet flow: unlike `submit_transaction` there is NO retry
/// loop, because a QR-signed extrinsic can never be rebuilt or resigned behind
/// the user's back — a stale nonce or expired mortality means asking the user
/// to run the command (and sign) again.
pub async fn submit_prepared_transaction(
	quantus_client: &crate::chain::client::QuantusClient,
	tx: subxt::tx::SubmittableTransaction<ChainConfig, OnlineClient<ChainConfig>>,
	execution_mode: ExecutionMode,
) -> crate::error::Result<(subxt::utils::H256, Option<subxt::utils::H256>)> {
	let map_err = |e: subxt::Error| {
		let msg = format!("{e:?}");
		let stale = msg.contains("Transaction is outdated") ||
			msg.contains("Invalid Transaction") ||
			msg.contains("Transaction has a bad signature") ||
			msg.contains("Priority is too low");
		if stale {
			crate::error::QuantusError::NetworkError(format!(
				"Transaction rejected: {msg}. The signed transaction may have expired or the account nonce changed while signing — run the command again to generate a fresh QR"
			))
		} else {
			crate::error::QuantusError::NetworkError(format!("Failed to submit transaction: {msg}"))
		}
	};

	if execution_mode.should_watch_transaction() {
		let mut tx_progress = tx.submit_and_watch().await.map_err(map_err)?;
		let tx_hash = tx_progress.extrinsic_hash();
		let included_in = wait_tx_inclusion(
			&mut tx_progress,
			quantus_client.client(),
			&tx_hash,
			execution_mode.transaction_stage(),
		)
		.await?;
		Ok((tx_hash, Some(included_in)))
	} else {
		let tx_hash = tx.submit().await.map_err(map_err)?;
		crate::log_print!("✅ Transaction submitted: {:?}", tx_hash);
		Ok((tx_hash, None))
	}
}

/// Submit transaction with manual nonce (no retry logic - use exact nonce provided)
pub async fn submit_transaction_with_nonce<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	signer: &crate::wallet::WalletSigner,
	call: Call,
	tip: Option<u128>,
	nonce: u32,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
	let from_keypair = match signer {
		crate::wallet::WalletSigner::Hot(keypair) => {
			crate::cli::cold_signing::warn_if_cold_flags_unused();
			keypair
		},
		crate::wallet::WalletSigner::Cold { name, address } =>
			return crate::cli::cold_signing::sign_and_submit_cold(
				quantus_client,
				name,
				address,
				&call,
				tip,
				Some(nonce),
				execution_mode,
				crate::cli::cold_signing::ColdIo::global(),
			)
			.await
			.map(|(tx_hash, _included_in)| tx_hash),
	};
	ensure_keypair_scheme_supported(quantus_client, from_keypair).await?;
	let signer = from_keypair.to_subxt_signer().map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to convert keypair: {e:?}"))
	})?;

	// Get current block for logging using latest block hash
	let latest_block_hash = quantus_client.get_latest_block().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get latest block: {e:?}"))
	})?;

	log_verbose!("🔗 Latest block hash: {:?}", latest_block_hash);

	// Create custom params with manual nonce and optional tip
	use subxt::config::DefaultExtrinsicParamsBuilder;
	let mut params_builder = DefaultExtrinsicParamsBuilder::new()
		.mortal(256) // Value higher than our finalization - TODO: should come from config
		.nonce(nonce.into());

	if let Some(tip_amount) = tip {
		params_builder = params_builder.tip(tip_amount);
		log_verbose!("💰 Using tip: {}", tip_amount);
	}

	let params = params_builder.build();

	log_verbose!("🔢 Using manual nonce: {}", nonce);
	log_verbose!("📤 Submitting transaction with manual nonce...");

	// Submit the transaction with manual nonce
	if execution_mode.should_watch_transaction() {
		match quantus_client
			.client()
			.tx()
			.sign_and_submit_then_watch(&call, &signer, params)
			.await
		{
			Ok(mut tx_progress) => {
				let tx_hash = tx_progress.extrinsic_hash();
				crate::log_print!("✅ Transaction submitted: {:?}", tx_hash);
				let _included_in = wait_tx_inclusion(
					&mut tx_progress,
					quantus_client.client(),
					&tx_hash,
					execution_mode.transaction_stage(),
				)
				.await?;
				Ok(tx_hash)
			},
			Err(e) => {
				log_error!("❌ Failed to submit transaction with manual nonce {}: {e:?}", nonce);
				Err(e.into())
			},
		}
	} else {
		match quantus_client.client().tx().sign_and_submit(&call, &signer, params).await {
			Ok(tx_hash) => {
				crate::log_print!("✅ Transaction submitted: {:?}", tx_hash);
				Ok(tx_hash)
			},
			Err(e) => {
				log_error!("❌ Failed to submit transaction: {e:?}");
				Err(e.into())
			},
		}
	}
}

/// Watch transaction until it is included in the best block or finalized
///
/// Since Quantus network is PoW, we can't use default subxt's way of waiting for finalized block as
/// it may take a long time. We wait for the transaction to be included in the best block and leave
/// it up to the user to check the status of the transaction.
///
/// Returns the hash of the block in which the transaction reached the target
/// stage, so callers can read events from the actual inclusion block instead of
/// racing the moving finalized tip.
///
/// Also used by unsigned wormhole verify submitters so they share the same
/// inactivity / overall-deadline bounds as signed watches.
pub(crate) async fn wait_tx_inclusion(
	tx_progress: &mut TxProgress<ChainConfig, OnlineClient<ChainConfig>>,
	client: &OnlineClient<ChainConfig>,
	tx_hash: &subxt::utils::H256,
	target_stage: TransactionStage,
) -> Result<subxt::utils::H256> {
	use indicatif::{ProgressBar, ProgressStyle};

	let start_time = std::time::Instant::now();
	let mut execution_success_checked_for = None;

	let spinner = if !crate::log::is_verbose() && !crate::log::is_quiet() {
		let pb = ProgressBar::new_spinner();
		pb.set_style(
			ProgressStyle::default_spinner()
				.tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
				.template("{spinner:.cyan} {msg}")
				.unwrap(),
		);

		if target_stage == TransactionStage::Finalized {
			pb.set_message("Waiting for finalized block... (0s)");
		} else {
			pb.set_message("Waiting for block inclusion... (0s)");
		}

		pb.enable_steady_tick(std::time::Duration::from_millis(500));
		Some(pb)
	} else {
		None
	};

	let watch_timeout_secs = tx_status_watch_timeout_secs(target_stage);
	// After best-block inclusion while targeting finalization, PoW can be silent for
	// longer than the inactivity window; only the overall deadline should abort then.
	let mut waiting_for_finalization = false;

	loop {
		let elapsed_before_wait = start_time.elapsed().as_secs();
		let remaining_watch_secs = watch_timeout_secs.saturating_sub(elapsed_before_wait);
		let apply_inactivity_timeout = !waiting_for_finalization;
		let wait_secs = next_status_wait_secs(remaining_watch_secs, apply_inactivity_timeout);
		let (next_event, elapsed_secs) = if wait_secs == 0 {
			(
				WatchedTxEvent::WatchDeadlineTimedOut { elapsed_secs: elapsed_before_wait },
				elapsed_before_wait,
			)
		} else {
			let next_status =
				tokio::time::timeout(std::time::Duration::from_secs(wait_secs), tx_progress.next())
					.await;
			let elapsed_secs = start_time.elapsed().as_secs();
			let next_event = match next_status {
				Ok(Some(Ok(status))) => {
					crate::log_verbose!(
						"   Transaction status: {:?} (elapsed: {}s)",
						status,
						elapsed_secs
					);

					match status {
						TxStatus::Validated => {
							if let Some(ref pb) = spinner {
								pb.set_message(format!(
									"Transaction validated ✓ ({}s)",
									elapsed_secs
								));
							}
							WatchedTxEvent::Validated
						},
						TxStatus::Broadcasted => WatchedTxEvent::Broadcasted,
						TxStatus::NoLongerInBestBlock => {
							execution_success_checked_for = None;
							// Reorged out of best block; resume inactivity protection until
							// we see inclusion again.
							waiting_for_finalization = false;
							WatchedTxEvent::NoLongerInBestBlock
						},
						TxStatus::InBestBlock(tx_in_block) => {
							let block_hash = tx_in_block.block_hash();
							match handle_in_best_block(
								client,
								tx_hash,
								block_hash,
								target_stage,
								&mut execution_success_checked_for,
								spinner.as_ref(),
								elapsed_secs,
							)
							.await
							{
								std::ops::ControlFlow::Continue(()) => {
									if target_stage == TransactionStage::Finalized {
										waiting_for_finalization = true;
									}
									continue;
								},
								std::ops::ControlFlow::Break(result) => return result,
							}
						},
						TxStatus::InFinalizedBlock(tx_in_block) => {
							let block_hash = tx_in_block.block_hash();
							match handle_in_finalized_block(
								client,
								tx_hash,
								block_hash,
								target_stage,
								&mut execution_success_checked_for,
								spinner.as_ref(),
								elapsed_secs,
							)
							.await
							{
								std::ops::ControlFlow::Continue(()) => continue,
								std::ops::ControlFlow::Break(result) => return result,
							}
						},
						TxStatus::Error { message } => WatchedTxEvent::Error(message),
						TxStatus::Invalid { message } => WatchedTxEvent::Invalid(message),
						TxStatus::Dropped { message } => WatchedTxEvent::Dropped(message),
					}
				},
				Ok(Some(Err(err))) => WatchedTxEvent::StreamError(err.to_string()),
				Ok(None) => WatchedTxEvent::StreamEnded,
				Err(_) => {
					if apply_inactivity_timeout &&
						wait_secs == TX_STATUS_INACTIVITY_TIMEOUT_SECS &&
						remaining_watch_secs > TX_STATUS_INACTIVITY_TIMEOUT_SECS
					{
						WatchedTxEvent::InactivityTimedOut {
							timeout_secs: TX_STATUS_INACTIVITY_TIMEOUT_SECS,
						}
					} else {
						WatchedTxEvent::WatchDeadlineTimedOut { elapsed_secs }
					}
				},
			};
			(next_event, elapsed_secs)
		};

		match describe_watched_tx_event(next_event, target_stage) {
			Ok(WatchDecision::Continue) | Ok(WatchDecision::WaitForFinalization) => {
				update_waiting_spinner(spinner.as_ref(), target_stage, elapsed_secs);
			},
			// In-block events are handled (and returned) above; no other event
			// reports Success, so this arm is defensively unreachable.
			Ok(WatchDecision::Success) =>
				return Err(crate::error::QuantusError::Generic(
					"transaction watcher reported success without an inclusion block".to_string(),
				)),
			Err(err) => {
				crate::log_error!("   {} (elapsed: {}s)", err, elapsed_secs);
				if let Some(pb) = spinner {
					pb.finish_with_message(format!("❌ Transaction error! ({}s)", elapsed_secs));
				}
				return Err(err);
			},
		}
	}
}

pub(crate) fn format_dispatch_error(
	error: &crate::chain::quantus_subxt::api::runtime_types::sp_runtime::DispatchError,
	metadata: &subxt::Metadata,
) -> String {
	use crate::chain::quantus_subxt::api::runtime_types::sp_runtime::DispatchError;

	match error {
		DispatchError::Module(module_error) => {
			let pallet_index = module_error.index;
			let error_index = module_error.error[0];

			// Try to get human-readable error name from metadata
			if let Some(pallet) = metadata.pallet_by_index(pallet_index) {
				let pallet_name = pallet.name();
				// Look up the error variant name from metadata
				if let Some(variant) = pallet.error_variant_by_index(error_index) {
					let error_name = &variant.name;
					let docs = variant.docs.join(" ");
					if docs.is_empty() {
						format!("{}::{}", pallet_name, error_name)
					} else {
						format!("{}::{} - {}", pallet_name, error_name, docs)
					}
				} else {
					format!("{}::Error[{}]", pallet_name, error_index)
				}
			} else {
				format!("Pallet[{}]::Error[{}]", pallet_index, error_index)
			}
		},
		DispatchError::BadOrigin => "BadOrigin".to_string(),
		DispatchError::CannotLookup => "CannotLookup".to_string(),
		DispatchError::Other => "Other".to_string(),
		_ => format!("{:?}", error),
	}
}

async fn verify_preimage_on_chain(
	quantus_client: &crate::chain::client::QuantusClient,
	expected_preimage: &[u8],
	at_block: subxt::utils::H256,
) -> Result<()> {
	use sp_runtime::traits::{BlakeTwo256, Hash};

	let preimage_hash: sp_core::H256 = BlakeTwo256::hash(expected_preimage);
	let preimage_len = u32::try_from(expected_preimage.len()).map_err(|_| {
		crate::error::QuantusError::Generic(format!(
			"Preimage is too large to address: {} bytes",
			expected_preimage.len()
		))
	})?;
	let storage_at = quantus_client.client().storage().at(at_block);
	let preimage_addr = crate::chain::quantus_subxt::api::storage()
		.preimage()
		.preimage_for((preimage_hash, preimage_len));

	match storage_at.fetch(&preimage_addr).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!(
			"Failed to fetch preimage {:?} ({} bytes): {e:?}",
			preimage_hash, preimage_len
		))
	})? {
		Some(stored_preimage) if stored_preimage.0.as_slice() == expected_preimage => Ok(()),
		Some(stored_preimage) => Err(crate::error::QuantusError::Generic(format!(
			"On-chain preimage mismatch for {:?}: expected {} bytes, found {} bytes",
			preimage_hash,
			preimage_len,
			stored_preimage.0.len()
		))),
		None => Err(crate::error::QuantusError::Generic(format!(
			"Expected preimage {:?} ({} bytes) is not present on-chain",
			preimage_hash, preimage_len
		))),
	}
}

pub async fn submit_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	signer: &crate::wallet::WalletSigner,
	encoded_call: Vec<u8>,
	execution_mode: ExecutionMode,
) -> Result<()> {
	type PreimageBytes =
		crate::chain::quantus_subxt::api::preimage::calls::types::note_preimage::Bytes;
	let bounded_bytes: PreimageBytes = encoded_call.clone();

	crate::log_print!("📝 Submitting preimage...");
	let note_preimage_tx =
		crate::chain::quantus_subxt::api::tx().preimage().note_preimage(bounded_bytes);
	let wait_mode = ExecutionMode { wait_for_transaction: true, ..execution_mode };

	match submit_transaction_with_inclusion_block(
		quantus_client,
		signer,
		note_preimage_tx,
		None,
		wait_mode,
	)
	.await
	{
		Ok((_, included_in)) => {
			// Verify in the inclusion block: the moving tip may not have
			// advanced past (or even reached) the inclusion block when the
			// watch returns, so reading the latest block can miss the
			// just-noted preimage.
			let at_block = match included_in {
				Some(hash) => hash,
				None => quantus_client.get_latest_block().await?,
			};
			verify_preimage_on_chain(quantus_client, &encoded_call, at_block).await?;
			crate::log_success!("Preimage submitted");
		},
		Err(e) => {
			// Do not trust formatted error substrings (e.g. "AlreadyNoted"). Only
			// continue when the expected preimage bytes are present on-chain.
			// There is no inclusion block here (the submission failed), so an
			// already-noted preimage is looked up at the current tip.
			let latest_block_hash = quantus_client.get_latest_block().await?;
			verify_preimage_on_chain(quantus_client, &encoded_call, latest_block_hash)
				.await
				.map_err(|verify_err| {
					crate::error::QuantusError::Generic(format!(
					"Preimage submission failed ({e}); on-chain verification also failed ({verify_err})"
				))
				})?;
			crate::log_print!(
				"✅ {} Expected preimage already exists on-chain, continuing",
				"OK".bright_green().bold()
			);
		},
	}
	Ok(())
}

pub(crate) async fn check_execution_success(
	client: &OnlineClient<ChainConfig>,
	block_hash: &subxt::utils::H256,
	tx_hash: &subxt::utils::H256,
) -> Result<()> {
	use crate::chain::quantus_subxt::api::system::events::ExtrinsicFailed;

	let block = client.blocks().at(*block_hash).await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get block: {e:?}"))
	})?;

	let extrinsics = block.extrinsics().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to get extrinsics: {e:?}"))
	})?;

	let our_extrinsic_index = extrinsics
		.iter()
		.enumerate()
		.find(|(_, ext)| ext.hash() == *tx_hash)
		.map(|(idx, _)| idx);

	let events = block.events().await.map_err(|e| {
		crate::error::QuantusError::NetworkError(format!("Failed to fetch events: {e:?}"))
	})?;

	let ext_idx = require_extrinsic_index(our_extrinsic_index)?;

	let metadata = client.metadata();
	for event_result in events.iter() {
		let event = event_result.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!("Failed to decode event: {e:?}"))
		})?;

		if let subxt::events::Phase::ApplyExtrinsic(event_ext_idx) = event.phase() {
			if event_ext_idx == ext_idx as u32 {
				if let Ok(Some(ExtrinsicFailed { dispatch_error, .. })) =
					event.as_event::<ExtrinsicFailed>()
				{
					let error_msg = format_dispatch_error(&dispatch_error, &metadata);
					crate::log_error!("   Transaction failed: {}", error_msg);
					return Err(crate::error::QuantusError::NetworkError(format!(
						"Transaction execution failed: {}",
						error_msg
					)));
				}
			}
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn delay_blocks_to_u32_rejects_values_above_u32_max() {
		let too_large = u32::MAX as u64 + 7200;
		let err = delay_blocks_to_u32(too_large).unwrap_err();
		assert!(
			err.to_string().contains("exceeds the maximum supported block delay"),
			"unexpected error: {err}"
		);
		assert_eq!(delay_blocks_to_u32(u32::MAX as u64).unwrap(), u32::MAX);
	}

	#[test]
	fn delay_seconds_to_millis_rejects_overflow() {
		let too_large = (u64::MAX / MILLIS_PER_SECOND) + 1;
		let err = delay_seconds_to_millis(too_large).unwrap_err();
		assert!(
			err.to_string().contains("exceeds the maximum supported timestamp delay"),
			"unexpected error: {err}"
		);
		assert_eq!(delay_seconds_to_millis(1).unwrap(), 1_000);
	}

	#[test]
	fn finalized_mode_implies_waiting_for_finalization() {
		let mode = ExecutionMode { finalized: true, wait_for_transaction: false };

		assert_eq!(mode.transaction_stage(), TransactionStage::Finalized);
		assert!(mode.should_watch_transaction());
	}

	#[test]
	fn default_mode_is_submission_only() {
		let mode = ExecutionMode::default();

		assert_eq!(mode.transaction_stage(), TransactionStage::Submitted);
		assert!(!mode.should_watch_transaction());
	}

	#[test]
	fn watched_failures_are_terminal_errors() {
		assert!(describe_watched_tx_event(
			WatchedTxEvent::Error("boom".to_string()),
			TransactionStage::Included,
		)
		.is_err());
		assert!(describe_watched_tx_event(
			WatchedTxEvent::Invalid("bad nonce".to_string()),
			TransactionStage::Included,
		)
		.is_err());
		assert!(describe_watched_tx_event(
			WatchedTxEvent::Dropped("dropped".to_string()),
			TransactionStage::Included,
		)
		.is_err());
		assert!(describe_watched_tx_event(
			WatchedTxEvent::StreamError("rpc failed".to_string()),
			TransactionStage::Included,
		)
		.is_err());
		assert!(
			describe_watched_tx_event(WatchedTxEvent::StreamEnded, TransactionStage::Included,)
				.is_err()
		);
		let inactivity_err = describe_watched_tx_event(
			WatchedTxEvent::InactivityTimedOut { timeout_secs: TX_STATUS_INACTIVITY_TIMEOUT_SECS },
			TransactionStage::Included,
		)
		.expect_err("silent subscription must time out instead of waiting forever");
		assert!(
			inactivity_err.to_string().contains("without updates") &&
				inactivity_err
					.to_string()
					.contains(&TX_STATUS_INACTIVITY_TIMEOUT_SECS.to_string()),
			"unexpected inactivity error: {inactivity_err}"
		);

		let deadline_err = describe_watched_tx_event(
			WatchedTxEvent::WatchDeadlineTimedOut {
				elapsed_secs: TX_STATUS_FINALIZED_TIMEOUT_SECS,
			},
			TransactionStage::Finalized,
		)
		.expect_err("overall finalized deadline must be an error");
		let deadline_msg = deadline_err.to_string();
		assert!(
			deadline_msg.contains("Timed out after waiting") &&
				deadline_msg.contains(&TX_STATUS_FINALIZED_TIMEOUT_SECS.to_string()) &&
				!deadline_msg.contains("without updates"),
			"overall deadline must not be reported as the inactivity window: {deadline_msg}"
		);
	}

	#[test]
	fn transaction_status_watch_deadlines_are_finite() {
		assert_eq!(tx_status_watch_timeout_secs(TransactionStage::Submitted), 0);
		assert_eq!(
			tx_status_watch_timeout_secs(TransactionStage::Included),
			TX_STATUS_INCLUDED_TIMEOUT_SECS
		);
		assert_eq!(
			tx_status_watch_timeout_secs(TransactionStage::Finalized),
			TX_STATUS_FINALIZED_TIMEOUT_SECS
		);
		const {
			assert!(TX_STATUS_INACTIVITY_TIMEOUT_SECS > 0);
			// Must cover many ~10s PoW block intervals: the stream is silent
			// between Broadcasted and InBestBlock, and aborting a valid pending
			// transaction invites duplicate-submission retries (#160612).
			assert!(TX_STATUS_INACTIVITY_TIMEOUT_SECS >= 120);
			assert!(TX_STATUS_INACTIVITY_TIMEOUT_SECS < TX_STATUS_INCLUDED_TIMEOUT_SECS);
			assert!(TX_STATUS_INCLUDED_TIMEOUT_SECS < TX_STATUS_FINALIZED_TIMEOUT_SECS);
		}
	}

	#[test]
	fn finalization_wait_does_not_use_short_inactivity_timeout() {
		// Before inclusion, keep the short inactivity cap.
		assert_eq!(
			next_status_wait_secs(TX_STATUS_FINALIZED_TIMEOUT_SECS, true),
			TX_STATUS_INACTIVITY_TIMEOUT_SECS
		);
		// After best-block inclusion while waiting for PoW finalization, allow the
		// full remaining overall deadline so silent finality gaps do not abort early.
		assert_eq!(
			next_status_wait_secs(TX_STATUS_FINALIZED_TIMEOUT_SECS, false),
			TX_STATUS_FINALIZED_TIMEOUT_SECS
		);
		assert_eq!(next_status_wait_secs(12, false), 12);
		assert_eq!(next_status_wait_secs(0, false), 0);
	}

	#[test]
	fn inclusion_and_finalization_have_distinct_success_states() {
		assert_eq!(
			describe_watched_tx_event(WatchedTxEvent::InBestBlock, TransactionStage::Included)
				.unwrap(),
			WatchDecision::Success
		);
		assert_eq!(
			describe_watched_tx_event(WatchedTxEvent::InBestBlock, TransactionStage::Finalized)
				.unwrap(),
			WatchDecision::WaitForFinalization
		);
		assert_eq!(
			describe_watched_tx_event(
				WatchedTxEvent::InFinalizedBlock,
				TransactionStage::Finalized,
			)
			.unwrap(),
			WatchDecision::Success
		);
	}

	#[test]
	fn execution_success_check_is_skipped_for_same_block() {
		let best_block_hash = subxt::utils::H256::from([7u8; 32]);
		let finalized_block_hash = subxt::utils::H256::from([8u8; 32]);

		assert!(should_check_execution_success(&best_block_hash, None));
		assert!(!should_check_execution_success(&best_block_hash, Some(&best_block_hash),));
		assert!(should_check_execution_success(&finalized_block_hash, Some(&best_block_hash),));
	}

	#[test]
	fn missing_extrinsic_hash_in_reported_block_is_error() {
		let err = require_extrinsic_index(None).expect_err("absent extrinsic must not succeed");
		match err {
			crate::error::QuantusError::NetworkError(msg) => {
				assert!(
					msg.contains("not found in reported block"),
					"unexpected error message: {msg}"
				);
			},
			other => panic!("expected NetworkError, got {other:?}"),
		}

		assert_eq!(require_extrinsic_index(Some(3)).unwrap(), 3);
	}

	#[test]
	fn submit_preimage_does_not_classify_already_noted_by_substring() {
		// #160718: control flow must not branch on the literal "AlreadyNoted" in
		// formatted errors; success after a submit failure requires on-chain
		// preimage verification instead.
		let source = include_str!("common.rs");
		assert!(
			!source.contains("contains(\"AlreadyNoted\")"),
			"submit_preimage must not accept errors based on AlreadyNoted substrings"
		);
		assert!(
			source.contains("verify_preimage_on_chain"),
			"submit_preimage must verify expected preimage bytes on-chain"
		);
	}
}
