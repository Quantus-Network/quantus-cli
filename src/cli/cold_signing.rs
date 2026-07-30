//! Cold-wallet (air-gapped) transaction signing over QR codes.
//!
//! Wire protocol (shared with the Quantus mobile app, the Quantus cold wallet
//! app and the Keystone firmware):
//!
//! 1. The CLI displays the **raw, unhashed** Substrate V4 signing payload as a
//!    `ur:quantus-sign-request` QR (animated when multi-part): `call ‖ era ‖ nonce ‖ tip ‖ mode ‖
//!    specVersion ‖ txVersion ‖ genesis ‖ blockHash ‖ Option<metadataHash>`. Raw (not hashed) so
//!    the device can parse and show the user what they are signing.
//! 2. The cold wallet signs `payload.len() > 256 ? blake2b_256(payload) : payload` with ML-DSA-87
//!    and answers with an animated UR containing `signature[4627] ‖ public_key[2592]`.
//! 3. The CLI validates the response against the wallet's stored address, assembles the V4
//!    extrinsic with the *identical* parameters, and submits.
//!
//! Invariant: nonce and block context are captured **once** into [`TxContext`];
//! the QR payload and the final extrinsic are both built from it. Refetching
//! anything in between would silently invalidate the signature.

use crate::{
	chain::client::{ChainConfig, QuantusClient},
	error::{QuantusError, Result},
	log_print, log_verbose,
	qr::{display_ur_until_enter, render_ur_frames, scan_ur, UrSource},
};
use colored::Colorize;
use qp_dilithium_crypto::types::{DilithiumSignatureScheme, DilithiumSignatureWithPublic};
use sp_core::crypto::AccountId32;
use sp_runtime::traits::IdentifyAccount;
use std::{io::IsTerminal, path::PathBuf, time::Duration};
use subxt::{
	client::OfflineClientT,
	config::{DefaultExtrinsicParamsBuilder, ExtrinsicParams, ExtrinsicParamsEncoder},
};

/// Transactions stay valid this many blocks after the anchor block. Matches the
/// hot path's `.mortal(256)` in `common::submit_transaction`.
pub const MORTALITY_BLOCKS: u64 = 256;

/// Cold-wallet parsers reject payloads above this size.
pub const MAX_COLD_PAYLOAD: usize = 8 * 1024;

/// `ML-DSA-87 signature (4627) ‖ public key (2592)` — the only valid response size.
pub const SIGNATURE_RESPONSE_LEN: usize = DilithiumSignatureWithPublic::TOTAL_LEN;

/// How long to wait for the signed response before giving up.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(300);

/// Chain context captured once per signing session. Both the QR payload and
/// the submitted extrinsic derive from this exact snapshot.
pub struct TxContext {
	pub nonce: u64,
	pub block_number: u64,
	pub block_hash: subxt::utils::H256,
	pub tip: u128,
}

/// Where the sign-request goes out and the signature response comes in.
#[derive(Default)]
pub struct ColdIo {
	/// Also write the request UR parts to this file (one per line). Hidden
	/// flag, used for scripting/testing.
	pub request_out: Option<PathBuf>,
	/// Read the response from a file or stdin instead of the camera.
	pub response_in: Option<UrSource>,
	/// Camera device index when scanning with the camera.
	pub camera_index: u32,
}

static COLD_IO: std::sync::OnceLock<ColdIo> = std::sync::OnceLock::new();

impl ColdIo {
	/// Build from the global CLI flags. `"-"` for `response_in` means stdin.
	pub fn from_flags(
		request_out: Option<String>,
		response_in: Option<String>,
		camera_index: u32,
	) -> Self {
		Self {
			request_out: request_out.map(PathBuf::from),
			response_in: response_in.map(|s| {
				if s == "-" {
					UrSource::StdinLines
				} else {
					UrSource::File(PathBuf::from(s))
				}
			}),
			camera_index,
		}
	}

	/// Install the process-wide I/O config. Called once from `main` with the
	/// global CLI flags so the submit stage can reach it without threading it
	/// through every command.
	pub fn install(self) {
		let _ = COLD_IO.set(self);
	}

	/// The installed config, or the default (camera 0, no file overrides) for
	/// library and test users that never call `install`.
	pub fn global() -> &'static ColdIo {
		COLD_IO.get_or_init(ColdIo::default)
	}
}

/// Why a signature response was rejected.
enum ResponseError {
	/// Wrong size — almost always an incomplete or corrupted scan. Rescanning
	/// is safe because the payload hasn't changed.
	BadLength(usize),
	/// Structurally invalid signature/public key bytes; rescan-safe.
	Malformed(String),
	/// Signed by a different key than the cold wallet's address. Not retryable.
	WrongSigner { got: String },
	/// Correct key, invalid signature over this payload. Not retryable.
	BadSignature,
}

impl ResponseError {
	fn rescan_safe(&self) -> bool {
		matches!(self, ResponseError::BadLength(_) | ResponseError::Malformed(_))
	}

	fn message(&self, wallet_name: &str) -> String {
		match self {
			ResponseError::BadLength(got) => format!(
				"Response has {got} bytes, expected {SIGNATURE_RESPONSE_LEN} (signature ‖ public key). The scan was likely incomplete or picked up the wrong QR — rescan the response on the cold wallet."
			),
			ResponseError::Malformed(e) => format!(
				"Response bytes do not parse as an ML-DSA-87 signature + public key ({e}) — rescan the response."
			),
			ResponseError::WrongSigner { got } => format!(
				"Response was signed by a DIFFERENT key ({got}) than cold wallet '{wallet_name}'. Aborting — check that the right device/account signed."
			),
			ResponseError::BadSignature =>
				"Signature does not verify over this transaction. Aborting — the cold wallet may have signed a stale QR; run the command again to generate a fresh one."
					.to_string(),
		}
	}
}

/// Capture nonce + latest (best) block once. `nonce_override` honors `--nonce`.
pub async fn capture_tx_context(
	client: &QuantusClient,
	signer: &AccountId32,
	tip: u128,
	nonce_override: Option<u32>,
) -> Result<TxContext> {
	let nonce = match nonce_override {
		Some(n) => n as u64,
		None => client.get_account_nonce_from_best_block(signer).await?,
	};
	let block_hash = client.get_latest_block().await?;
	let block = client.client().blocks().at(block_hash).await?;
	let block_number = block.header().number as u64;
	Ok(TxContext { nonce, block_number, block_hash, tip })
}

/// Extrinsic params for this context. Deterministic — called once for the raw
/// payload and once for the submitted extrinsic, and both must encode
/// identically.
fn build_params(
	ctx: &TxContext,
) -> <<ChainConfig as subxt::Config>::ExtrinsicParams as ExtrinsicParams<ChainConfig>>::Params {
	DefaultExtrinsicParamsBuilder::<ChainConfig>::new()
		.nonce(ctx.nonce)
		.tip(ctx.tip)
		.mortal_from_unchecked(MORTALITY_BLOCKS, ctx.block_number, ctx.block_hash)
		.build()
}

/// Build the raw, unhashed V4 signer payload that goes into the QR.
///
/// Built by hand because subxt's `PartialTransaction::signer_payload()`
/// blake2-hashes payloads over 256 bytes (and its raw-bytes path is private),
/// while the cold wallet needs the raw bytes to parse and display the call.
pub fn build_raw_signer_payload<Call: subxt::tx::Payload>(
	state: &subxt::client::ClientState<ChainConfig>,
	call: &Call,
	ctx: &TxContext,
) -> Result<Vec<u8>> {
	let mut raw = call
		.encode_call_data(&state.metadata)
		.map_err(|e| QuantusError::Generic(format!("Failed to encode call data: {e:?}")))?;

	let encoder = <<ChainConfig as subxt::Config>::ExtrinsicParams as ExtrinsicParams<
		ChainConfig,
	>>::new(state, build_params(ctx))
	.map_err(|e| QuantusError::Generic(format!("Failed to build extrinsic params: {e:?}")))?;

	encoder.encode_signer_payload_value_to(&mut raw); // era ‖ nonce ‖ tip ‖ mode
	encoder.encode_implicit_to(&mut raw); // specV ‖ txV ‖ genesis ‖ blockHash ‖ metadataHash

	if raw.len() > MAX_COLD_PAYLOAD {
		return Err(QuantusError::Generic(format!(
			"Signing payload is {} bytes; cold wallets reject payloads over {} bytes",
			raw.len(),
			MAX_COLD_PAYLOAD
		)));
	}
	Ok(raw)
}

/// The bytes the cold wallet actually signs (and the chain verifies):
/// payloads over 256 bytes are Blake2b-256 hashed first.
pub fn signable_payload(raw: &[u8]) -> Vec<u8> {
	if raw.len() > 256 {
		<sp_runtime::traits::BlakeTwo256 as sp_runtime::traits::Hash>::hash(raw)
			.as_ref()
			.to_vec()
	} else {
		raw.to_vec()
	}
}

/// Split and verify a signature response. Checks length, structure, that the
/// embedded public key matches the cold wallet's address (poseidon binding),
/// and that the signature verifies over this exact payload.
fn validate_signature_response(
	raw_payload: &[u8],
	response: &[u8],
	expected_account: &AccountId32,
) -> std::result::Result<DilithiumSignatureWithPublic, ResponseError> {
	if response.len() != SIGNATURE_RESPONSE_LEN {
		return Err(ResponseError::BadLength(response.len()));
	}

	let sig_with_public = DilithiumSignatureWithPublic::from_bytes(response)
		.map_err(|e| ResponseError::Malformed(format!("{e:?}")))?;

	let derived_account = sig_with_public.public().into_account();
	if derived_account != *expected_account {
		use crate::cli::address_format::QuantusSS58;
		return Err(ResponseError::WrongSigner { got: derived_account.to_quantus_ss58() });
	}

	use sp_runtime::traits::Verify;
	let msg = signable_payload(raw_payload);
	let scheme = DilithiumSignatureScheme::Dilithium(sig_with_public.clone());
	if !scheme.verify(&msg[..], expected_account) {
		return Err(ResponseError::BadSignature);
	}

	Ok(sig_with_public)
}

fn confirm_or_abort(prompt: &str) -> Result<()> {
	use std::io::Write;
	print!("{prompt}");
	std::io::stdout().flush()?;
	let mut input = String::new();
	std::io::stdin().read_line(&mut input)?;
	if input.trim().eq_ignore_ascii_case("q") {
		return Err(QuantusError::Generic("Aborted by user".to_string()));
	}
	Ok(())
}

/// Run the full cold signing flow for `call` and submit the result.
///
/// Generic over the call payload; the shared submit stage in `cli::common`
/// routes every extrinsic here when the signer is a cold (watch-only) wallet.
#[allow(clippy::too_many_arguments)]
pub async fn sign_and_submit_cold<Call: subxt::tx::Payload>(
	client: &QuantusClient,
	wallet_name: &str,
	cold_address_ss58: &str,
	call: &Call,
	tip: Option<u128>,
	nonce_override: Option<u32>,
	execution_mode: crate::cli::common::ExecutionMode,
	io: &ColdIo,
) -> Result<subxt::utils::H256> {
	use sp_core::crypto::Ss58Codec;

	let account = AccountId32::from_ss58check_with_version(cold_address_ss58)
		.map_err(|e| {
			QuantusError::Generic(format!(
				"Cold wallet '{wallet_name}' has an invalid stored address: {e:?}"
			))
		})?
		.0;

	// 1. Capture chain context ONCE; everything below derives from it.
	let ctx = capture_tx_context(client, &account, tip.unwrap_or(0), nonce_override).await?;
	let state = client.client().client_state();
	let raw_payload = build_raw_signer_payload(&state, call, &ctx)?;

	log_print!("🧊 Cold wallet signing with '{}'", wallet_name.bright_blue().bold());
	log_print!("   Signer:  {}", cold_address_ss58.bright_cyan());
	log_print!("   Nonce:   {}", ctx.nonce);
	if ctx.tip > 0 {
		log_print!("   Tip:     {}", ctx.tip);
	}
	log_print!("   Valid for {} blocks from block #{}", MORTALITY_BLOCKS, ctx.block_number);
	log_print!("   Payload: {} bytes", raw_payload.len());
	log_verbose!("   Payload hex: 0x{}", hex::encode(&raw_payload));

	// Fee preview: the fee depends on tx length and weight, not signature
	// content, and Dilithium signatures have a fixed length — so a zeroed
	// signature estimates accurately. Best-effort only.
	if let Some(fee) = estimate_fee_with_dummy_signature(client, call, &ctx, &account).await {
		match crate::cli::send::format_balance_with_symbol(client, fee).await {
			Ok(formatted) => log_print!("   Estimated fee: {}", formatted.bright_cyan()),
			Err(_) => log_print!("   Estimated fee: {} (raw units)", fee),
		}
	}

	// 2. Encode as UR and hand it to the cold wallet.
	let parts = quantus_ur::encode_bytes(&raw_payload)
		.map_err(|e| QuantusError::Generic(format!("Failed to UR-encode payload: {e:?}")))?;

	if let Some(path) = &io.request_out {
		let content = parts.join("\n") + "\n";
		std::fs::write(path, content)?;
		log_print!("📤 Sign request written to {}", path.display());
	}

	// Skip the QR display and prompts when scripted (stdin is not a terminal);
	// the request file above is the handoff instead.
	let interactive = std::io::stdin().is_terminal();
	if interactive {
		let frames = render_ur_frames(&parts)?;
		log_print!("");
		display_ur_until_enter(
			&frames,
			"📱 Scan this QR with your cold wallet, then press Enter here…",
		)
		.await?;
		confirm_or_abort(
			"✍️  Sign the transaction on the cold wallet. Ready to scan its response? [Enter to scan / q to abort]: ",
		)?;
	} else {
		log_print!(
			"🤖 Non-interactive session: skipping QR display, waiting for the signature response…"
		);
	}

	// 3. Collect and validate the signature response. Fall back to the camera
	// only when no explicit source was given.
	let source = match &io.response_in {
		Some(source) => source.clone(),
		None => default_response_source(io)?,
	};
	let sig_with_public = loop {
		let response = scan_ur(&source, RESPONSE_TIMEOUT).await?;
		log_verbose!("📥 Received {} response bytes", response.len());

		match validate_signature_response(&raw_payload, &response, &account) {
			Ok(swp) => break swp,
			Err(err) => {
				let msg = err.message(wallet_name);
				if err.rescan_safe() && interactive {
					log_print!("⚠️  {}", msg);
					confirm_or_abort("Rescan? [Enter to rescan / q to abort]: ")?;
					continue;
				}
				return Err(QuantusError::Generic(msg));
			},
		}
	};
	log_print!("✅ Signature verified against cold wallet '{}'", wallet_name.bright_blue());

	// 4. Assemble the extrinsic from the SAME context and submit.
	let mut partial = client
		.client()
		.tx()
		.create_v4_partial_offline(call, build_params(&ctx))
		.map_err(|e| {
			QuantusError::Generic(format!("Failed to build partial transaction: {e:?}"))
		})?;

	// Cross-check: subxt's signer payload for the partial tx must equal the
	// (hashed-if-long) form of the QR payload, or the two constructions drifted.
	if partial.signer_payload() != signable_payload(&raw_payload) {
		return Err(QuantusError::Generic(
			"Internal error: submitted transaction params differ from the QR payload; nothing was submitted".to_string(),
		));
	}

	let signature = DilithiumSignatureScheme::Dilithium(sig_with_public);
	let submittable = partial.sign_with_account_and_signature(&account, &signature);

	crate::cli::common::submit_prepared_transaction(client, submittable, execution_mode).await
}

/// Estimate the fee by assembling a throwaway extrinsic with an all-zero
/// (correct-length) signature. Returns `None` on any failure — the preview is
/// informational and must never block signing.
async fn estimate_fee_with_dummy_signature<Call: subxt::tx::Payload>(
	client: &QuantusClient,
	call: &Call,
	ctx: &TxContext,
	account: &AccountId32,
) -> Option<u128> {
	let dummy = DilithiumSignatureWithPublic::from_bytes(&[0u8; SIGNATURE_RESPONSE_LEN]).ok()?;
	let mut partial =
		client.client().tx().create_v4_partial_offline(call, build_params(ctx)).ok()?;
	let tx = partial
		.sign_with_account_and_signature(account, &DilithiumSignatureScheme::Dilithium(dummy));
	tx.partial_fee_estimate().await.ok()
}

/// Fee estimate for a cold wallet when no [`TxContext`] exists yet (balance
/// preflight before signing). Same dummy-signature trick; the fee depends on
/// length and weight, not on nonce or signature content.
pub(crate) async fn estimate_cold_fee<Call: subxt::tx::Payload>(
	client: &QuantusClient,
	call: &Call,
	account: &AccountId32,
	tip: u128,
) -> Option<u128> {
	let ctx = capture_tx_context(client, account, tip, None).await.ok()?;
	estimate_fee_with_dummy_signature(client, call, &ctx, account).await
}

fn default_response_source(io: &ColdIo) -> Result<UrSource> {
	#[cfg(feature = "camera")]
	{
		Ok(UrSource::Camera { index: io.camera_index })
	}
	#[cfg(not(feature = "camera"))]
	{
		let _ = io;
		Err(QuantusError::Generic(
			"This build has no camera support (built without the `camera` feature). Pass --cold-response-in <file|-> to read the response from a file or stdin".to_string(),
		))
	}
}

/// `quantus developer cold-sign-sim` — act as the cold wallet side using a
/// local hot wallet. Reads a sign-request UR (file or stdin), signs it per the
/// protocol, and writes the response UR (file or stdout).
///
/// Unlike real devices, the simulator does not enforce a genesis-hash
/// allowlist, which is what makes end-to-end testing on a dev node possible.
pub async fn handle_cold_sign_sim(
	wallet: String,
	request_file: Option<String>,
	response_file: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	// 1. Read the request UR (polling the file allows scripted pipelines).
	let request_source = match &request_file {
		Some(path) => UrSource::File(PathBuf::from(path)),
		None => UrSource::StdinLines,
	};
	let payload = scan_ur(&request_source, Duration::from_secs(60)).await?;

	if payload.len() < 2 {
		return Err(QuantusError::Generic(format!(
			"Request payload is only {} bytes — not a signing payload",
			payload.len()
		)));
	}
	log_print!("🧾 Sign request: {} bytes", payload.len());
	log_print!("   Pallet index: {}, call index: {}", payload[0], payload[1]);
	log_verbose!("   Payload hex: 0x{}", hex::encode(&payload));

	// 2. Sign exactly like the cold wallet app / Keystone firmware.
	let keypair = crate::wallet::load_keypair_from_wallet(&wallet, password, password_file)?;
	let pair = keypair.to_resonance_pair()?;
	let msg = signable_payload(&payload);
	let sig_with_public = <qp_dilithium_crypto::DilithiumPair as sp_core::Pair>::sign(&pair, &msg);

	// 3. Emit the response UR.
	let parts = quantus_ur::encode_bytes(&sig_with_public.to_bytes())
		.map_err(|e| QuantusError::Generic(format!("Failed to UR-encode response: {e:?}")))?;

	match &response_file {
		Some(path) => {
			// Atomic write: pollers must never observe a half-written response.
			let tmp = format!("{path}.tmp");
			std::fs::write(&tmp, parts.join("\n") + "\n")?;
			std::fs::rename(&tmp, path)?;
			log_print!("📤 Signature response ({} UR parts) written to {}", parts.len(), path);
		},
		None =>
			for part in &parts {
				println!("{part}");
			},
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chain::quantus_subxt::api;
	use subxt::{client::ClientState, config::substrate::H256, utils::MultiAddress, OfflineClient};

	fn test_client_state() -> ClientState<ChainConfig> {
		let metadata_bytes: &[u8] = include_bytes!("../quantus_metadata.scale");
		let metadata = <subxt::Metadata as codec::Decode>::decode(&mut &metadata_bytes[..])
			.expect("valid metadata");
		ClientState {
			genesis_hash: H256::from([0x49u8; 32]),
			runtime_version: subxt::client::RuntimeVersion {
				spec_version: 136,
				transaction_version: 3,
			},
			metadata,
		}
	}

	fn test_ctx() -> TxContext {
		TxContext {
			nonce: 7,
			block_number: 1000,
			block_hash: subxt::utils::H256::from([0x11u8; 32]),
			tip: 0,
		}
	}

	fn alice_account() -> AccountId32 {
		let pair = qp_dilithium_crypto::crystal_alice();
		crate::wallet::QuantumKeyPair::from_resonance_pair(&pair).to_account_id_32()
	}

	fn transfer_call() -> impl subxt::tx::Payload {
		let dest: subxt::utils::AccountId32 =
			subxt::utils::AccountId32(*b"01234567890123456789012345678901");
		api::tx()
			.balances()
			.transfer_allow_death(MultiAddress::Id(dest), 1_000_000_000_000u128)
	}

	/// The raw payload must follow the exact field layout the cold-wallet
	/// parsers expect (see quantus_payload_parser.dart / Keystone parser.rs).
	#[test]
	fn test_raw_payload_golden_layout() {
		let state = test_client_state();
		let ctx = test_ctx();
		let raw = build_raw_signer_payload(&state, &transfer_call(), &ctx).unwrap();

		// Call: pallet 2 (Balances), call 0 (transfer_allow_death),
		// MultiAddress::Id tag 0, 32-byte dest, compact amount
		assert_eq!(raw[0], 2, "Balances pallet index");
		assert_eq!(raw[1], 0, "transfer_allow_death call index");
		assert_eq!(raw[2], 0, "MultiAddress::Id tag");
		assert_eq!(&raw[3..35], b"01234567890123456789012345678901");
		// Compact(1_000_000_000_000) = 0x07 0x0010a5d4e8
		let mut expected_tail = vec![0x07u8, 0x00, 0x10, 0xa5, 0xd4, 0xe8];
		// Era: mortal, period 256 → two bytes (low nibble 0b0101 = 5 for 2^(5+4)=... )
		// Era::mortal(256, 1000): period=256 → encoded via Substrate era encoding.
		let era = sp_runtime::generic::Era::mortal(256, 1000);
		expected_tail.extend(codec::Encode::encode(&era));
		// Compact nonce 7, compact tip 0, metadata mode 0
		expected_tail.extend(codec::Encode::encode(&codec::Compact(7u64)));
		expected_tail.extend(codec::Encode::encode(&codec::Compact(0u128)));
		expected_tail.push(0u8); // CheckMetadataHash mode = disabled
						   // Implicit: specVersion, txVersion (LE u32), genesis, era anchor block hash,
						   // metadataHash Option = None
		expected_tail.extend(136u32.to_le_bytes());
		expected_tail.extend(3u32.to_le_bytes());
		expected_tail.extend([0x49u8; 32]);
		expected_tail.extend([0x11u8; 32]);
		expected_tail.push(0u8); // metadataHash: None

		assert_eq!(
			&raw[35..],
			&expected_tail[..],
			"payload tail (extensions) must match the cold-wallet parser layout"
		);
	}

	/// Pin our manual raw-payload builder to subxt's canonical signer payload:
	/// identical below 256 bytes, blake2b-256 of ours above.
	#[test]
	fn test_raw_payload_matches_subxt_signer_payload() {
		let state = test_client_state();
		let ctx = test_ctx();
		let client = OfflineClient::<ChainConfig>::new(
			state.genesis_hash,
			state.runtime_version,
			state.metadata.clone(),
		);

		// Small payload: subxt's signer payload IS the raw payload
		let call = transfer_call();
		let raw = build_raw_signer_payload(&state, &call, &ctx).unwrap();
		assert!(raw.len() <= 256);
		let partial = client.tx().create_v4_partial_offline(&call, build_params(&ctx)).unwrap();
		assert_eq!(partial.signer_payload(), raw);
		assert_eq!(signable_payload(&raw), raw);

		// Large payload (remark > 256 bytes): subxt hashes, and so does signable_payload
		let big_call = api::tx().system().remark(vec![0xAB; 400]);
		let big_raw = build_raw_signer_payload(&state, &big_call, &ctx).unwrap();
		assert!(big_raw.len() > 256);
		let big_partial =
			client.tx().create_v4_partial_offline(&big_call, build_params(&ctx)).unwrap();
		assert_eq!(big_partial.signer_payload(), signable_payload(&big_raw));
		assert_ne!(signable_payload(&big_raw), big_raw);
		assert_eq!(signable_payload(&big_raw).len(), 32);
	}

	#[test]
	fn test_validate_signature_response_roundtrip() {
		let state = test_client_state();
		let ctx = test_ctx();
		let call = transfer_call();
		let raw = build_raw_signer_payload(&state, &call, &ctx).unwrap();

		// Simulate the cold wallet: sign the signable form with alice's key
		let alice = qp_dilithium_crypto::crystal_alice();
		let msg = signable_payload(&raw);
		let swp = <qp_dilithium_crypto::DilithiumPair as sp_core::Pair>::sign(&alice, &msg);
		let response = swp.to_bytes();
		assert_eq!(response.len(), SIGNATURE_RESPONSE_LEN);

		// Valid response verifies
		let validated =
			validate_signature_response(&raw, &response, &alice_account()).ok().unwrap();
		assert_eq!(validated.to_bytes(), response);

		// Truncated response → BadLength (rescan-safe)
		let err = validate_signature_response(&raw, &response[..1000], &alice_account())
			.err()
			.unwrap();
		assert!(err.rescan_safe());
		assert!(matches!(err, ResponseError::BadLength(1000)));

		// Signed by a different key → WrongSigner (abort)
		let bob = qp_dilithium_crypto::dilithium_bob();
		let bob_swp = <qp_dilithium_crypto::DilithiumPair as sp_core::Pair>::sign(&bob, &msg);
		let err = validate_signature_response(&raw, &bob_swp.to_bytes(), &alice_account())
			.err()
			.unwrap();
		assert!(!err.rescan_safe());
		assert!(matches!(err, ResponseError::WrongSigner { .. }));

		// Right key, tampered payload → BadSignature (abort)
		let mut other_ctx = test_ctx();
		other_ctx.nonce = 8;
		let other_raw = build_raw_signer_payload(&state, &call, &other_ctx).unwrap();
		let err = validate_signature_response(&other_raw, &response, &alice_account())
			.err()
			.unwrap();
		assert!(!err.rescan_safe());
		assert!(matches!(err, ResponseError::BadSignature));
	}

	/// The full simulator loop: request UR → sign → response UR → validate →
	/// assemble a submittable extrinsic offline.
	#[test]
	fn test_end_to_end_offline_sign_and_assemble() {
		let state = test_client_state();
		let ctx = test_ctx();
		let call = transfer_call();
		let raw = build_raw_signer_payload(&state, &call, &ctx).unwrap();

		// CLI → UR → cold wallet
		let request_parts = quantus_ur::encode_bytes(&raw).unwrap();
		let received = quantus_ur::decode_bytes(&request_parts).unwrap();
		assert_eq!(received, raw);

		// Cold wallet signs and answers over UR
		let alice = qp_dilithium_crypto::crystal_alice();
		let swp = <qp_dilithium_crypto::DilithiumPair as sp_core::Pair>::sign(
			&alice,
			&signable_payload(&received),
		);
		let response_parts = quantus_ur::encode_bytes(&swp.to_bytes()).unwrap();
		assert!(response_parts.len() > 1, "7219-byte response must be multi-part");

		// CLI decodes, validates, assembles
		let response = quantus_ur::decode_bytes(&response_parts).unwrap();
		let validated =
			validate_signature_response(&raw, &response, &alice_account()).ok().unwrap();

		let client = OfflineClient::<ChainConfig>::new(
			state.genesis_hash,
			state.runtime_version,
			state.metadata.clone(),
		);
		let mut partial = client.tx().create_v4_partial_offline(&call, build_params(&ctx)).unwrap();
		assert_eq!(partial.signer_payload(), signable_payload(&raw));

		let signature = DilithiumSignatureScheme::Dilithium(validated);
		let submittable = partial.sign_with_account_and_signature(&alice_account(), &signature);

		// V4 signed extrinsic: version byte 0x84 after the compact length prefix
		let encoded = submittable.encoded().to_vec();
		assert!(!encoded.is_empty());
		use codec::Decode;
		let mut cursor = &encoded[..];
		let _len = codec::Compact::<u32>::decode(&mut cursor).unwrap();
		assert_eq!(cursor[0], 0b1000_0000 | 4, "signed V4 extrinsic marker");
	}
}
