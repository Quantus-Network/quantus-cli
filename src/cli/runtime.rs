//! `quantus runtime` subcommand - runtime management
use crate::{
	chain::quantus_subxt,
	cli::common::{
		submit_preimage, submit_transaction, submit_transaction_with_inclusion_block, ExecutionMode,
	},
	error::QuantusError,
	log_print, log_success, log_verbose,
	wallet::WalletSigner,
};
use clap::Subcommand;
use colored::Colorize;
use sp_runtime::traits::{BlakeTwo256, Hash};

use crate::chain::client::ChainConfig;
use std::{
	fs,
	path::{Path, PathBuf},
};
use subxt::{tx::Payload, OnlineClient};

#[derive(Subcommand, Debug)]
pub enum RuntimeCommands {
	/// Propose a version-checked runtime upgrade on the FastUpgrade track
	Update {
		/// Path to the runtime WASM file
		#[arg(short, long)]
		wasm_file: PathBuf,

		/// Wallet name to sign with (must be allowed to submit Tech Referenda)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Force the update without confirmation
		#[arg(long)]
		force: bool,
	},

	/// Apply the exact WASM after its FastUpgrade authorization has enacted
	Apply {
		/// Path to the runtime WASM file whose hash was authorized
		#[arg(short, long)]
		wasm_file: PathBuf,

		/// Wallet name to sign with (any funded wallet)
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Apply without confirmation
		#[arg(long)]
		force: bool,
	},

	/// Compare local WASM file with current runtime
	Compare {
		/// Path to the runtime WASM file to compare
		#[arg(short, long)]
		wasm_file: PathBuf,
	},
}

#[derive(Debug)]
pub(crate) struct RuntimeAuthorization {
	pub code_hash: sp_core::H256,
	pub preimage_hash: sp_core::H256,
	pub encoded_call: Vec<u8>,
}

pub(crate) fn read_wasm_file(wasm_file: &Path) -> crate::error::Result<Vec<u8>> {
	if wasm_file.extension().is_some_and(|extension| extension != "wasm") {
		log_print!("⚠️  Warning: File doesn't have .wasm extension");
	}
	let wasm_code = fs::read(wasm_file)
		.map_err(|e| QuantusError::Generic(format!("Failed to read WASM file: {e}")))?;
	if wasm_code.is_empty() {
		return Err(QuantusError::Generic(format!("WASM file is empty: {}", wasm_file.display())));
	}
	Ok(wasm_code)
}

pub(crate) fn runtime_code_hash(wasm_code: &[u8]) -> sp_core::H256 {
	BlakeTwo256::hash(wasm_code)
}

pub(crate) fn build_runtime_authorization(
	metadata: &subxt::Metadata,
	wasm_code: &[u8],
) -> crate::error::Result<RuntimeAuthorization> {
	let code_hash = runtime_code_hash(wasm_code);
	let payload = quantus_subxt::api::tx().system().authorize_upgrade(code_hash);
	let encoded_call = payload.encode_call_data(metadata).map_err(|e| {
		QuantusError::Generic(format!("Failed to encode System::authorize_upgrade: {e:?}"))
	})?;
	let preimage_hash = BlakeTwo256::hash(&encoded_call);
	Ok(RuntimeAuthorization { code_hash, preimage_hash, encoded_call })
}

pub(crate) fn validate_runtime_authorization_preimage(
	metadata: &subxt::Metadata,
	encoded_call: &[u8],
) -> crate::error::Result<sp_core::H256> {
	if encoded_call.len() != 34 {
		return Err(QuantusError::Generic(format!(
			"Preimage is not System::authorize_upgrade: expected 34 bytes, found {}",
			encoded_call.len()
		)));
	}
	let code_hash = sp_core::H256::from_slice(&encoded_call[2..]);
	let expected = quantus_subxt::api::tx()
		.system()
		.authorize_upgrade(code_hash)
		.encode_call_data(metadata)
		.map_err(|e| {
			QuantusError::Generic(format!("Failed to validate authorization preimage: {e:?}"))
		})?;
	if encoded_call != expected {
		return Err(QuantusError::Generic(
			"Preimage is not System::authorize_upgrade for the connected runtime".to_string(),
		));
	}
	Ok(code_hash)
}

pub(crate) fn build_fast_upgrade_referendum(
	preimage_hash: sp_core::H256,
	call_len: u32,
) -> subxt::tx::DynamicPayload {
	use subxt::dynamic::Value;

	let origin = Value::unnamed_variant(
		"Origins",
		[Value::unnamed_variant("FastUpgrade", Vec::<Value>::new())],
	);
	let proposal = Value::named_variant(
		"Lookup",
		[
			("hash", Value::from_bytes(preimage_hash.as_bytes())),
			("len", Value::u128(u128::from(call_len))),
		],
	);
	let enactment = Value::unnamed_variant("After", [Value::u128(0)]);
	subxt::dynamic::tx("TechReferenda", "submit", vec![origin, proposal, enactment])
}

pub(crate) async fn submit_runtime_authorization(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_code: &[u8],
	signer: &WalletSigner,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	let authorization =
		build_runtime_authorization(&quantus_client.client().metadata(), wasm_code)?;
	let call_len = u32::try_from(authorization.encoded_call.len()).map_err(|_| {
		QuantusError::Generic("Runtime authorization call is too large".to_string())
	})?;

	log_print!("🔐 Runtime code hash: {:?}", authorization.code_hash);
	log_print!("🔗 Authorization preimage hash: {:?}", authorization.preimage_hash);
	log_verbose!("📝 Authorization call size: {} bytes", call_len);
	submit_preimage(quantus_client, signer, authorization.encoded_call, execution_mode).await?;

	log_print!("📡 Submitting FastUpgrade authorization referendum...");
	let submit_call = build_fast_upgrade_referendum(authorization.preimage_hash, call_len);
	let tx_hash =
		submit_transaction(quantus_client, signer, submit_call, None, execution_mode).await?;
	log_success!("Runtime authorization referendum submitted! Hash: 0x{}", hex::encode(tx_hash));
	Ok(tx_hash)
}

fn confirm_runtime_action(action: &str, force: bool) -> crate::error::Result<()> {
	if force {
		return Ok(());
	}
	log_print!("");
	log_print!(
		"⚠️  {} Runtime {} is a critical operation!",
		"WARNING:".bright_red().bold(),
		action
	);
	print!("Do you want to proceed with the runtime {action}? (yes/no): ");
	use std::io::{self, Write};
	io::stdout()
		.flush()
		.map_err(|e| QuantusError::Generic(format!("Failed to flush confirmation prompt: {e}")))?;
	let mut input = String::new();
	io::stdin()
		.read_line(&mut input)
		.map_err(|e| QuantusError::Generic(format!("Failed to read confirmation: {e}")))?;
	if !input.trim().eq_ignore_ascii_case("yes") {
		return Err(QuantusError::Generic(format!("Runtime {action} cancelled")));
	}
	Ok(())
}

pub async fn update_runtime(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_code: Vec<u8>,
	signer: &WalletSigner,
	force: bool,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	log_print!("📋 Upgrade path:");
	log_print!("   • Propose System::authorize_upgrade(code_hash) as Origins::FastUpgrade");
	log_print!("   • Apply the exact WASM after the authorization referendum enacts");
	confirm_runtime_action("authorization", force)?;
	submit_runtime_authorization(quantus_client, &wasm_code, signer, execution_mode).await
}

pub async fn apply_runtime(
	quantus_client: &crate::chain::client::QuantusClient,
	wasm_code: Vec<u8>,
	signer: &WalletSigner,
	force: bool,
	execution_mode: ExecutionMode,
) -> crate::error::Result<subxt::utils::H256> {
	let code_hash = runtime_code_hash(&wasm_code);
	let latest_block_hash = quantus_client.get_latest_block().await?;
	let storage = quantus_client.client().storage().at(latest_block_hash);
	let authorization = storage
		.fetch(&quantus_subxt::api::storage().system().authorized_upgrade())
		.await
		.map_err(|e| {
			QuantusError::NetworkError(format!("Failed to read authorized upgrade: {e:?}"))
		})?
		.ok_or_else(|| {
			QuantusError::Generic("No runtime upgrade is authorized on-chain".to_string())
		})?;
	if authorization.code_hash != code_hash {
		return Err(QuantusError::Generic(format!(
			"WASM hash {:?} does not match authorized hash {:?}",
			code_hash, authorization.code_hash
		)));
	}
	if !authorization.check_version {
		return Err(QuantusError::Generic(
			"Authorized upgrade disables runtime version checks; refusing to apply it".to_string(),
		));
	}
	let current_code = storage
		.fetch_raw(b":code".to_vec())
		.await
		.map_err(|e| {
			QuantusError::NetworkError(format!("Failed to read current runtime code: {e:?}"))
		})?
		.ok_or_else(|| {
			QuantusError::Generic("Current runtime code is missing on-chain".to_string())
		})?;
	if runtime_code_hash(&current_code) == code_hash {
		return Err(QuantusError::Generic("The authorized WASM is already installed".to_string()));
	}

	log_print!("🔐 Authorized runtime code hash: {:?}", code_hash);
	confirm_runtime_action("apply", force)?;
	let apply_call = quantus_subxt::api::tx().system().apply_authorized_upgrade(wasm_code);
	let wait_mode = ExecutionMode { wait_for_transaction: true, ..execution_mode };
	let (tx_hash, included_in) = submit_transaction_with_inclusion_block(
		quantus_client,
		signer,
		apply_call,
		None,
		wait_mode,
	)
	.await?;
	let included_in = included_in.ok_or_else(|| {
		QuantusError::NetworkError(
			"Runtime apply was submitted but no inclusion block was returned".to_string(),
		)
	})?;
	let installed_code = quantus_client
		.client()
		.storage()
		.at(included_in)
		.fetch_raw(b":code".to_vec())
		.await
		.map_err(|e| {
			QuantusError::NetworkError(format!("Failed to verify installed runtime: {e:?}"))
		})?
		.ok_or_else(|| {
			QuantusError::Generic("Installed runtime code is missing on-chain".to_string())
		})?;
	if runtime_code_hash(&installed_code) != code_hash {
		return Err(QuantusError::Generic(
			"Authorized WASM was not installed; its spec name or version may have been rejected"
				.to_string(),
		));
	}
	log_success!("Runtime code installed in block {:?}", included_in);
	Ok(tx_hash)
}

/// Runtime version information structure (internal use)
#[derive(Debug, Clone)]
pub struct RuntimeVersionInfo {
	pub spec_version: u32,
	pub impl_version: u32,
	pub transaction_version: u32,
}

/// Get runtime version information (internal use)
pub async fn get_runtime_version(
	client: &OnlineClient<ChainConfig>,
) -> crate::error::Result<RuntimeVersionInfo> {
	log_verbose!("🔍 Getting runtime version...");

	let runtime_version = client.runtime_version();

	// SubXT RuntimeVersion only has spec_version and transaction_version
	// We'll use defaults for missing fields
	Ok(RuntimeVersionInfo {
		spec_version: runtime_version.spec_version,
		impl_version: 1, // Default impl version since not available in SubXT
		transaction_version: runtime_version.transaction_version,
	})
}

/// Calculate WASM file hash
pub async fn calculate_wasm_hash(wasm_code: &[u8]) -> crate::error::Result<String> {
	use sha2::{Digest, Sha256};
	let mut hasher = Sha256::new();
	hasher.update(wasm_code);
	let local_hash = hasher.finalize();

	Ok(format!("0x{}", hex::encode(local_hash)))
}

/// Handle runtime subxt command
pub async fn handle_runtime_command(
	command: RuntimeCommands,
	node_url: &str,
	execution_mode: crate::cli::common::ExecutionMode,
) -> crate::error::Result<()> {
	let quantus_client = crate::chain::client::QuantusClient::new(node_url).await?;

	match command {
		RuntimeCommands::Update { wasm_file, from, password, password_file, force } => {
			log_print!("🚀 Runtime Management");
			log_print!("🔐 Runtime Upgrade Authorization");
			log_print!("   📂 WASM file: {}", wasm_file.display().to_string().bright_cyan());
			log_print!("   🔑 Signed by: {}", from.bright_yellow());
			log_verbose!("📖 Reading WASM file...");
			let wasm_code = read_wasm_file(&wasm_file)?;
			log_print!("📊 WASM file size: {} bytes", wasm_code.len());
			let signer = crate::wallet::load_signer_from_wallet(&from, password, password_file)?;
			update_runtime(&quantus_client, wasm_code, &signer, force, execution_mode).await?;

			log_print!("💡 Place the decision deposit, collect 8 ayes, and wait for enactment.");
			log_print!("💡 Then apply this exact file:");
			log_print!(
				"   quantus runtime apply --wasm-file {} --from <funded-wallet> --node-url {}",
				wasm_file.display(),
				node_url
			);

			Ok(())
		},

		RuntimeCommands::Apply { wasm_file, from, password, password_file, force } => {
			log_print!("🚀 Runtime Management");
			log_print!("⬆️  Apply Authorized Runtime");
			log_print!("   📂 WASM file: {}", wasm_file.display().to_string().bright_cyan());
			log_print!("   🔑 Signed by: {}", from.bright_yellow());
			log_verbose!("📖 Reading WASM file...");
			let wasm_code = read_wasm_file(&wasm_file)?;
			log_print!("📊 WASM file size: {} bytes", wasm_code.len());
			let signer = crate::wallet::load_signer_from_wallet(&from, password, password_file)?;
			let tx_hash =
				apply_runtime(&quantus_client, wasm_code, &signer, force, execution_mode).await?;
			log_success!("Runtime upgrade applied! Hash: 0x{}", hex::encode(tx_hash));
			log_print!("💡 Use 'quantus system --runtime' to verify the new runtime version.");
			Ok(())
		},

		RuntimeCommands::Compare { wasm_file } => {
			log_print!("🚀 Runtime Management");
			log_print!("🔍 Comparing WASM file with current runtime...");
			log_print!("   📂 Local file: {}", wasm_file.display().to_string().bright_cyan());

			let local_wasm = read_wasm_file(&wasm_file)?;

			log_print!("📊 Local WASM size: {} bytes", local_wasm.len());

			// Get current runtime version
			let current_version = get_runtime_version(quantus_client.client()).await?;
			log_print!("📋 Current chain runtime:");
			log_print!("   • Spec version: {}", current_version.spec_version);
			log_print!("   • Impl version: {}", current_version.impl_version);
			log_print!("   • Transaction version: {}", current_version.transaction_version);

			// Calculate hash of local file
			let local_hash = calculate_wasm_hash(&local_wasm).await?;
			log_print!("🔐 Local WASM SHA256: {}", local_hash.bright_blue());

			// Try to get runtime hash from chain
			if let Ok(Some(chain_runtime_hash)) = quantus_client.get_runtime_hash().await {
				log_print!("🔐 Chain runtime hash: {}", chain_runtime_hash.bright_yellow());

				// Compare hashes
				if local_hash == chain_runtime_hash {
					log_success!("✅ Runtime hashes match! The WASM file is identical to the current runtime.");
				} else {
					log_print!("⚠️  Runtime hashes differ. The WASM file is different from the current runtime.");
				}
			} else {
				log_print!("💡 Chain runtime hash not available for comparison");
			}

			// Try to extract version from filename
			let filename = wasm_file
				.file_name()
				.ok_or_else(|| QuantusError::Generic("WASM path has no file name".to_string()))?
				.to_string_lossy();
			log_verbose!("🔍 Parsing filename: {}", filename);

			if let Some(version_str) = filename.split('-').nth(2) {
				log_verbose!("🔍 Version part: {}", version_str);
				if let Some(version_num) = version_str.split('.').next() {
					log_verbose!("🔍 Version number: {}", version_num);
					// Remove 'v' prefix if present
					let clean_version = version_num.trim_start_matches('v');
					log_verbose!("🔍 Clean version: {}", clean_version);
					if let Ok(wasm_version) = clean_version.parse::<u32>() {
						log_print!("📋 Version comparison:");
						log_print!(
							"   • Local WASM version: {}",
							wasm_version.to_string().bright_green()
						);
						log_print!(
							"   • Chain runtime version: {}",
							current_version.spec_version.to_string().bright_yellow()
						);

						match wasm_version.cmp(&current_version.spec_version) {
							std::cmp::Ordering::Equal => {
								log_success!("✅ Versions match! The WASM file is compatible with the current runtime.");
							},
							std::cmp::Ordering::Greater => {
								log_print!("🔄 The WASM file is newer than the current runtime.");
								log_print!("   • This would be an upgrade");
							},
							std::cmp::Ordering::Less => {
								log_print!("⚠️  The WASM file is older than the current runtime.");
								log_print!("   • This would be a downgrade");
							},
						}
					} else {
						log_print!("⚠️  Could not parse version number from filename");
					}
				} else {
					log_print!("⚠️  Could not extract version number from filename");
				}
			} else {
				log_print!("⚠️  Could not extract version from filename format");
			}

			log_print!("💡 Use 'quantus system --runtime' for detailed runtime information");

			Ok(())
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Decode;

	fn metadata() -> subxt::Metadata {
		let bytes: &[u8] = include_bytes!("../quantus_metadata.scale");
		subxt::Metadata::decode(&mut &bytes[..]).expect("valid checked-in metadata")
	}

	#[test]
	fn authorization_preimage_contains_only_the_runtime_hash() {
		let metadata = metadata();
		let wasm = b"\0asm-test-runtime";
		let authorization =
			build_runtime_authorization(&metadata, wasm).expect("authorization must encode");

		assert_eq!(authorization.code_hash, runtime_code_hash(wasm));
		assert_eq!(authorization.encoded_call.len(), 34);
		assert_eq!(
			validate_runtime_authorization_preimage(&metadata, &authorization.encoded_call)
				.expect("authorization preimage must validate"),
			authorization.code_hash
		);
		assert_eq!(authorization.preimage_hash, BlakeTwo256::hash(&authorization.encoded_call));
	}

	#[test]
	fn authorization_preimage_validation_rejects_another_call() {
		let metadata = metadata();
		let mut encoded = build_runtime_authorization(&metadata, b"\0asm-test-runtime")
			.expect("authorization must encode")
			.encoded_call;
		encoded[1] ^= 1;

		let error = validate_runtime_authorization_preimage(&metadata, &encoded)
			.expect_err("another call must be rejected");
		assert!(error.to_string().contains("is not System::authorize_upgrade"));
	}

	#[test]
	fn fast_upgrade_referendum_uses_dynamic_live_metadata_payload() {
		let payload = build_fast_upgrade_referendum(sp_core::H256::repeat_byte(7), 34);
		assert_eq!(payload.pallet_name(), "TechReferenda");
		assert_eq!(payload.call_name(), "submit");
	}
}
