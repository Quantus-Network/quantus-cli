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

type TxWatchFlow = std::ops::ControlFlow<Result<()>, ()>;

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
			std::ops::ControlFlow::Break(Ok(()))
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
			std::ops::ControlFlow::Break(Ok(()))
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
	if let Some(wallet_address) = wallet_manager.find_wallet_address(address_or_wallet_name)? {
		log_verbose!(
			"🔍 Found wallet '{}' with address: {}",
			address_or_wallet_name.bright_cyan(),
			wallet_address.bright_green()
		);
		return Ok(wallet_address);
	}

	// Neither a valid SS58 address nor a wallet name
	Err(crate::error::QuantusError::Generic(format!(
		"Invalid destination: '{address_or_wallet_name}' is neither a valid SS58 address nor a known wallet name"
	)))
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
	let (from_account_id, _version) =
		AccountId32::from_ss58check_with_version(&from_keypair.to_account_id_ss58check()).map_err(
			|e| crate::error::QuantusError::NetworkError(format!("Invalid from address: {e:?}")),
		)?;

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

/// Get incremented nonce for retry scenarios from the latest block using existing QuantusClient
/// This is useful when a transaction fails but the chain doesn't update the nonce.
/// Not used by `submit_transaction` (auto nonce-bump retry removed); kept for intentional callers.
#[allow(dead_code)]
pub async fn get_incremented_nonce_with_client(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	base_nonce: u64,
) -> Result<u64> {
	let (from_account_id, _version) =
		AccountId32::from_ss58check_with_version(&from_keypair.to_account_id_ss58check()).map_err(
			|e| crate::error::QuantusError::NetworkError(format!("Invalid from address: {e:?}")),
		)?;

	// Get current nonce from the latest block
	let current_nonce = quantus_client
		.get_account_nonce_from_best_block(&from_account_id)
		.await
		.map_err(|e| {
			crate::error::QuantusError::NetworkError(format!(
				"Failed to get account nonce from best block: {e:?}"
			))
		})?;

	// Use the higher of current nonce or base_nonce + 1
	let incremented_nonce = std::cmp::max(current_nonce, base_nonce + 1);
	log_verbose!(
		"🔢 Using incremented nonce: {} (base: {}, current from latest block: {})",
		incremented_nonce,
		base_nonce,
		current_nonce
	);
	Ok(incremented_nonce)
}

/// Whether a formatted submission error may trigger automatic resubmit that bumps
/// the nonce and re-signs the same call.
///
/// Always `false`. Matching English substrings from untrusted RPC text is imprecise,
/// and bumping the nonce without proving the prior extrinsic was rejected can
/// duplicate non-idempotent transactions. Bad-signature / Invalid Transaction /
/// pool / ambiguous errors must not be auto-retried this way.
#[cfg_attr(not(test), allow(dead_code))]
fn is_retryable_submission_error(error_msg: &str) -> bool {
	// Categories that were previously (incorrectly) treated as transient.
	const UNSAFE_OR_AMBIGUOUS: &[&str] = &[
		"Transaction has a bad signature",
		"Invalid Transaction",
		"Priority is too low",
		"Transaction is outdated",
		"Transaction is temporarily banned",
	];
	if UNSAFE_OR_AMBIGUOUS.iter().any(|needle| error_msg.contains(needle)) {
		return false;
	}
	// Unknown / ambiguous formatted errors are also not safe for nonce-bump retry.
	false
}

/// Submit transaction with optional finalization check
///
/// By default, returns immediately after the node accepts the transaction submission.
/// With `wait_for_transaction=true`, waits until the transaction is in a best block.
/// With `finalized=true`, waits until the transaction is in a finalized block.
pub async fn submit_transaction<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	call: Call,
	tip: Option<u128>,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
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

				wait_tx_inclusion(
					&mut tx_progress,
					quantus_client.client(),
					&tx_hash,
					execution_mode.transaction_stage(),
				)
				.await?;

				Ok(tx_hash)
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
				Ok(tx_hash)
			},
			Err(e) => {
				log_error!("❌ Failed to submit transaction: {e:?}");
				Err(e.into())
			},
		}
	}
}

/// Submit transaction with manual nonce (no retry logic - use exact nonce provided)
pub async fn submit_transaction_with_nonce<Call>(
	quantus_client: &crate::chain::client::QuantusClient,
	from_keypair: &crate::wallet::QuantumKeyPair,
	call: Call,
	tip: Option<u128>,
	nonce: u32,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256>
where
	Call: subxt::tx::Payload,
{
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
				wait_tx_inclusion(
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
async fn wait_tx_inclusion(
	tx_progress: &mut TxProgress<ChainConfig, OnlineClient<ChainConfig>>,
	client: &OnlineClient<ChainConfig>,
	tx_hash: &subxt::utils::H256,
	target_stage: TransactionStage,
) -> Result<()> {
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

	loop {
		let elapsed_secs = start_time.elapsed().as_secs();
		let next_event = match tx_progress.next().await {
			Some(Ok(status)) => {
				crate::log_verbose!(
					"   Transaction status: {:?} (elapsed: {}s)",
					status,
					elapsed_secs
				);

				match status {
					TxStatus::Validated => {
						if let Some(ref pb) = spinner {
							pb.set_message(format!("Transaction validated ✓ ({}s)", elapsed_secs));
						}
						WatchedTxEvent::Validated
					},
					TxStatus::Broadcasted => WatchedTxEvent::Broadcasted,
					TxStatus::NoLongerInBestBlock => {
						execution_success_checked_for = None;
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
							std::ops::ControlFlow::Continue(()) => continue,
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
			Some(Err(err)) => WatchedTxEvent::StreamError(err.to_string()),
			None => WatchedTxEvent::StreamEnded,
		};

		match describe_watched_tx_event(next_event, target_stage) {
			Ok(WatchDecision::Continue) | Ok(WatchDecision::WaitForFinalization) => {
				update_waiting_spinner(spinner.as_ref(), target_stage, elapsed_secs);
			},
			Ok(WatchDecision::Success) => return Ok(()),
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

pub async fn submit_preimage(
	quantus_client: &crate::chain::client::QuantusClient,
	keypair: &crate::wallet::QuantumKeyPair,
	encoded_call: Vec<u8>,
	execution_mode: ExecutionMode,
) -> Result<()> {
	type PreimageBytes =
		crate::chain::quantus_subxt::api::preimage::calls::types::note_preimage::Bytes;
	let bounded_bytes: PreimageBytes = encoded_call;

	crate::log_print!("📝 Submitting preimage...");
	let note_preimage_tx =
		crate::chain::quantus_subxt::api::tx().preimage().note_preimage(bounded_bytes);
	let wait_mode = ExecutionMode { wait_for_transaction: true, ..execution_mode };

	match submit_transaction(quantus_client, keypair, note_preimage_tx, None, wait_mode).await {
		Ok(_) => {
			crate::log_success!("Preimage submitted");
		},
		Err(e) if e.to_string().contains("AlreadyNoted") => {
			crate::log_print!(
				"✅ {} Preimage already exists on-chain, continuing",
				"OK".bright_green().bold()
			);
		},
		Err(e) => return Err(e),
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
	fn unsafe_submission_errors_are_not_retryable() {
		assert!(!is_retryable_submission_error("Transaction has a bad signature"));
		assert!(!is_retryable_submission_error(
			"RpcError: Invalid Transaction: Transaction has a bad signature"
		));
		assert!(!is_retryable_submission_error("Invalid Transaction"));
		assert!(!is_retryable_submission_error(
			"Failed to submit transaction: Invalid Transaction"
		));
		assert!(!is_retryable_submission_error("Priority is too low"));
		assert!(!is_retryable_submission_error("Transaction is outdated"));
		assert!(!is_retryable_submission_error("Transaction is temporarily banned"));
	}

	#[test]
	fn ambiguous_submission_errors_are_not_retryable() {
		assert!(!is_retryable_submission_error("connection reset by peer"));
		assert!(!is_retryable_submission_error("timeout waiting for response"));
		assert!(!is_retryable_submission_error(""));
		assert!(!is_retryable_submission_error("some unknown node error"));
	}
}
