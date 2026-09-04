//! Common client utilities to eliminate code duplication
//!
//! This module provides shared functionality for creating and managing clients
//! across all CLI modules.

use crate::{error::QuantusError, log_verbose};
use jsonrpsee::{
	core::client::ClientT,
	ws_client::{WsClient, WsClientBuilder},
};
use qp_dilithium_crypto::types::DilithiumSignatureScheme;
use sp_core::crypto::AccountId32;
use sp_runtime::{traits::IdentifyAccount, MultiAddress};
use std::{sync::Arc, time::Duration};
use subxt::{
	backend::{legacy::LegacyBackend, rpc::RpcClient, Backend, BackendExt},
	client::RuntimeVersion,
	config::{substrate::SubstrateHeader, DefaultExtrinsicParams},
	utils::H256,
	Config, OnlineClient,
};
use subxt_metadata::Metadata as SubxtMetadata;

#[derive(Debug, Clone, Copy)]
pub struct SubxtBlake2bHasher;

impl subxt::config::Hasher for SubxtBlake2bHasher {
	type Output = sp_core::H256;

	fn new(_metadata: &SubxtMetadata) -> Self {
		SubxtBlake2bHasher
	}

	fn hash(&self, bytes: &[u8]) -> Self::Output {
		<sp_runtime::traits::BlakeTwo256 as sp_runtime::traits::Hash>::hash(bytes)
	}
}

/// Configuration of the chain
pub enum ChainConfig {}
impl Config for ChainConfig {
	type AccountId = AccountId32;
	type Address = MultiAddress<Self::AccountId, ()>;
	type Signature = DilithiumSignatureScheme;
	type Hasher = SubxtBlake2bHasher;
	type Header = SubstrateHeader<u32, SubxtBlake2bHasher>;
	type AssetId = u32;
	type ExtrinsicParams = DefaultExtrinsicParams<Self>;
}

/// Wrapper around OnlineClient that also stores the node URL and RPC client
#[derive(Clone)]
pub struct QuantusClient {
	client: OnlineClient<ChainConfig>,
	rpc_client: Arc<WsClient>,
	node_url: String,
}

impl QuantusClient {
	/// Return a URL suitable for logs and user-facing diagnostics by removing credentials.
	fn sanitize_url_for_diagnostics(url: &str) -> String {
		let Some(scheme_end) = url.find("://") else {
			return url.to_string();
		};

		let authority_start = scheme_end + 3;
		let authority_end = url[authority_start..]
			.find(['/', '?', '#'])
			.map(|offset| authority_start + offset)
			.unwrap_or(url.len());
		let authority = &url[authority_start..authority_end];

		if let Some(userinfo_end) = authority.rfind('@') {
			format!(
				"{}{}{}",
				&url[..authority_start],
				&authority[userinfo_end + 1..],
				&url[authority_end..]
			)
		} else {
			url.to_string()
		}
	}

	/// Create a new QuantusClient by connecting to the specified node URL
	pub async fn new(node_url: &str) -> crate::error::Result<Self> {
		Self::connect(node_url, true).await
	}

	/// Connect without enforcing the runtime identity gate.
	///
	/// Only for read-only diagnostics (e.g. `compatibility-check`) that must be able to
	/// inspect nodes this CLI would otherwise reject. Never use this client to sign or
	/// submit transactions.
	pub async fn new_without_runtime_check(node_url: &str) -> crate::error::Result<Self> {
		Self::connect(node_url, false).await
	}

	async fn connect(node_url: &str, enforce_runtime_identity: bool) -> crate::error::Result<Self> {
		let display_node_url = Self::sanitize_url_for_diagnostics(node_url);
		log_verbose!("🔗 Connecting to Quantus node: {}", display_node_url);

		// Validate URL format and provide helpful error messages
		if !node_url.starts_with("ws://") && !node_url.starts_with("wss://") {
			return Err(QuantusError::NetworkError(format!(
                "Invalid WebSocket URL: '{display_node_url}'. URL must start with 'ws://' (unsecured) or 'wss://' (secured)"
            )));
		}

		// Create WS client with custom timeouts
		let ws_client = WsClientBuilder::default()
            // TODO: Make these configurable in a separate change
            // These timeouts should be configurable via CLI or config file
            .connection_timeout(Duration::from_secs(30))
            .request_timeout(Duration::from_secs(30))
            .build(node_url)
            .await
            .map_err(|e| {
                // Provide more helpful error messages for common issues
                let error_str = format!("{e:?}").replace(node_url, &display_node_url);
                let error_msg = if error_str.contains("TimedOut") || error_str.contains("timed out") {
                    if node_url.starts_with("ws://") {
                        format!(
                            "Connection timed out. Try using 'wss://{}' instead of '{}'",
                            display_node_url.strip_prefix("ws://").unwrap_or(&display_node_url),
                            display_node_url
                        )
                    } else {
                        format!("Connection timed out. Please check if the node is running and accessible at: {display_node_url}")
                    }
                } else if error_str.contains("HTTP") {
                    format!("HTTP error: {error_str}. This might indicate the node doesn't support WebSocket connections")
                } else {
                    format!("Failed to create RPC client: {error_str}")
                };
                QuantusError::NetworkError(error_msg)
            })?;

		let ws_client = Arc::new(ws_client);
		let backend = Self::backend(&ws_client);

		// subxt's own constructor pins metadata to the latest finalized block. QPoW finality
		// trails the head by ~100 blocks, so for ~20 minutes after an upgrade enacts that
		// metadata describes the old runtime while the head already runs the new one. Read
		// the runtime version and metadata from one best-block hash instead, so the pair
		// cannot straddle an upgrade either.
		let best = best_block_hash(&ws_client).await?;
		let (version_json, runtime_version) = fetch_runtime_version(&ws_client, Some(best)).await?;

		// Reject non-Quantus / older-unsupported runtimes before encode/sign. Newer-than-table
		// Quantus specs are allowed with a warning (see validate_runtime_identity).
		if enforce_runtime_identity {
			crate::config::validate_runtime_version_value(&version_json).map_err(|e| match e {
				QuantusError::NetworkError(msg) =>
					QuantusError::NetworkError(format!("{msg} (from {display_node_url})")),
				other => other,
			})?;
		}

		log_verbose!(
			"📡 Head {:?} runs spec {} / tx {}",
			best,
			runtime_version.spec_version,
			runtime_version.transaction_version
		);
		let genesis_hash = backend.genesis_hash().await?;
		let metadata = fetch_metadata_at(&backend, best).await?;
		let client =
			OnlineClient::from_backend_with(genesis_hash, runtime_version, metadata, backend)?;

		log_verbose!("✅ Connected to Quantus node successfully!");

		Ok(QuantusClient { client, rpc_client: ws_client, node_url: node_url.to_string() })
	}

	fn backend(ws_client: &Arc<WsClient>) -> Arc<LegacyBackend<ChainConfig>> {
		Arc::new(LegacyBackend::builder().build(RpcClient::new(ws_client.clone())))
	}

	/// A client whose metadata and runtime version are the ones `hash` was produced under.
	///
	/// Use it to decode that block's events, extrinsics and storage. Reads at the head keep
	/// using `self`, which is returned unchanged when `hash` runs the same runtime. Never
	/// sign with the result: the chain verifies signatures against the head runtime.
	pub async fn at_block(&self, hash: H256) -> crate::error::Result<Self> {
		let (_, runtime_version) = fetch_runtime_version(&self.rpc_client, Some(hash)).await?;
		if runtime_version == self.client.runtime_version() {
			return Ok(self.clone());
		}
		log_verbose!(
			"📡 Block {:?} runs spec {} / tx {}; decoding it with that runtime's metadata",
			hash,
			runtime_version.spec_version,
			runtime_version.transaction_version
		);
		let backend = Self::backend(&self.rpc_client);
		let metadata = fetch_metadata_at(&backend, hash).await?;
		let client = OnlineClient::from_backend_with(
			self.client.genesis_hash(),
			runtime_version,
			metadata,
			backend,
		)?;
		Ok(Self { client, rpc_client: self.rpc_client.clone(), node_url: self.node_url.clone() })
	}

	/// Get reference to the underlying SubXT client
	/// The FIPS 204 context the connected runtime verifies extrinsic signatures under. Read from
	/// the runtime version subxt already cached at connect, so this costs no RPC.
	pub fn signing_context(&self) -> Option<&'static [u8]> {
		let version = self.client.runtime_version();
		crate::chain::signing::context_for_runtime(
			version.spec_version,
			version.transaction_version,
		)
	}

	pub fn client(&self) -> &OnlineClient<ChainConfig> {
		&self.client
	}

	/// Get the node URL
	pub fn node_url(&self) -> &str {
		&self.node_url
	}

	/// Get reference to the RPC client
	pub fn rpc_client(&self) -> &WsClient {
		&self.rpc_client
	}

	/// Get the latest block (best block) using RPC call
	/// This bypasses SubXT's default behavior of using finalized blocks
	pub async fn get_latest_block(&self) -> crate::error::Result<subxt::utils::H256> {
		log_verbose!("🔍 Fetching latest block hash via RPC...");
		let latest_hash = best_block_hash(&self.rpc_client).await?;
		log_verbose!("📦 Latest block hash: {:?}", latest_hash);
		Ok(latest_hash)
	}

	/// Interpret a System::Account nonce lookup without collapsing absence into a silent zero.
	///
	/// Returns `(nonce, account_exists)`. Missing accounts use nonce `0` (correct for the first
	/// extrinsic) but callers can log the absence explicitly.
	pub(crate) fn interpret_account_nonce(fetched_nonce: Option<u32>) -> (u32, bool) {
		match fetched_nonce {
			Some(nonce) => (nonce, true),
			None => (0, false),
		}
	}

	/// Get account nonce from the best block (latest) using direct RPC call
	/// This bypasses SubXT's default behavior of using finalized blocks
	pub async fn get_account_nonce_from_best_block(
		&self,
		account_id: &AccountId32,
	) -> crate::error::Result<u64> {
		log_verbose!("🔍 Fetching account nonce from best block via RPC...");

		// Get latest block hash first
		let latest_block_hash = self.get_latest_block().await?;
		log_verbose!("📦 Latest block hash for nonce query: {:?}", latest_block_hash);

		// Convert sp_core::AccountId32 to subxt::utils::AccountId32
		let account_bytes: [u8; 32] = *account_id.as_ref();
		let subxt_account_id = subxt::utils::AccountId32::from(account_bytes);

		// Use SubXT's storage API to query nonce at the best block
		use crate::chain::quantus_subxt::api;
		let storage_addr = api::storage().system().account(subxt_account_id);

		let storage_at = self.client.storage().at(latest_block_hash);

		let account_info = storage_at.fetch(&storage_addr).await?;
		let (nonce, exists) = Self::interpret_account_nonce(account_info.map(|info| info.nonce));
		if exists {
			log_verbose!("✅ Nonce from best block: {}", nonce);
		} else {
			log_verbose!(
				"⚠️  Account has no on-chain entry at best block; using nonce 0 for first extrinsic"
			);
		}
		Ok(nonce as u64)
	}

	/// Get genesis hash using RPC call
	pub async fn get_genesis_hash(&self) -> crate::error::Result<subxt::utils::H256> {
		log_verbose!("🔍 Fetching genesis hash via RPC...");

		let genesis_hash: subxt::utils::H256 = self
			.rpc_client
			.request::<subxt::utils::H256, [u32; 1]>("chain_getBlockHash", [0u32])
			.await
			.map_err(|e| {
				crate::error::QuantusError::NetworkError(format!(
					"Failed to fetch genesis hash: {e:?}"
				))
			})?;

		log_verbose!("🧬 Genesis hash: {:?}", genesis_hash);
		Ok(genesis_hash)
	}

	/// Get runtime version using RPC call
	pub async fn get_runtime_version(&self) -> crate::error::Result<(u32, u32)> {
		log_verbose!("🔍 Fetching runtime version via RPC...");
		let (_, version) = fetch_runtime_version(&self.rpc_client, None).await?;
		log_verbose!(
			"🔧 Runtime version: spec={}, tx={}",
			version.spec_version,
			version.transaction_version
		);
		Ok((version.spec_version, version.transaction_version))
	}

	/// Get runtime hash using RPC call (if available)
	pub async fn get_runtime_hash(&self) -> crate::error::Result<Option<String>> {
		log_verbose!("🔍 Fetching runtime hash via RPC...");

		// Try different possible RPC calls for runtime hash
		let possible_calls = ["state_getRuntimeHash", "state_getRuntime", "chain_getRuntimeHash"];

		for call_name in &possible_calls {
			match self.rpc_client.request::<serde_json::Value, [(); 0]>(call_name, []).await {
				Ok(result) => {
					log_verbose!("✅ Found runtime hash via {}", call_name);
					if let Some(hash) = result.as_str() {
						return Ok(Some(hash.to_string()));
					} else if let Some(hash_obj) = result.get("hash") {
						if let Some(hash) = hash_obj.as_str() {
							return Ok(Some(hash.to_string()));
						}
					}
				},
				Err(_e) => {
					log_verbose!("❌ {} failed: {:?}", call_name, _e);
				},
			}
		}

		log_verbose!("⚠️  No runtime hash RPC call available");
		Ok(None)
	}
}

async fn best_block_hash(ws_client: &WsClient) -> crate::error::Result<H256> {
	ws_client.request::<H256, [(); 0]>("chain_getBlockHash", []).await.map_err(|e| {
		QuantusError::NetworkError(format!("Failed to fetch latest block hash: {e:?}"))
	})
}

/// `state_getRuntimeVersion` at `at`, or at the head for `None`: the raw JSON and the parsed pair.
async fn fetch_runtime_version(
	ws_client: &WsClient,
	at: Option<H256>,
) -> crate::error::Result<(serde_json::Value, RuntimeVersion)> {
	let value: serde_json::Value =
		ws_client.request("state_getRuntimeVersion", [at]).await.map_err(|e| {
			QuantusError::NetworkError(format!("Failed to fetch runtime version: {e:?}"))
		})?;
	let version = parse_runtime_version(&value)?;
	Ok((value, version))
}

fn parse_runtime_version(value: &serde_json::Value) -> crate::error::Result<RuntimeVersion> {
	let field = |name: &str| {
		value
			.get(name)
			.and_then(serde_json::Value::as_u64)
			.and_then(|v| u32::try_from(v).ok())
			.ok_or_else(|| {
				QuantusError::NetworkError(format!("Runtime version has no usable `{name}`"))
			})
	};
	Ok(RuntimeVersion {
		spec_version: field("specVersion")?,
		transaction_version: field("transactionVersion")?,
	})
}

/// The newest metadata version the runtime at `at` serves, negotiated the way subxt does.
async fn fetch_metadata_at(
	backend: &LegacyBackend<ChainConfig>,
	at: H256,
) -> crate::error::Result<subxt::Metadata> {
	for version in subxt_metadata::SUPPORTED_METADATA_VERSIONS {
		match backend.metadata_at_version(version, at).await {
			Ok(metadata) => return Ok(metadata),
			Err(e) => log_verbose!("Metadata v{} unavailable at {:?}: {}", version, at, e),
		}
	}
	Ok(backend.legacy_metadata(at).await?)
}

/// Scheme-aware subxt signer (ML-DSA-65 or ML-DSA-87).
///
/// Pairs are boxed: Dilithium secret material is multi‑KB, and an unboxed enum
/// trips `clippy::large_enum_variant`.
pub enum SignerPair {
	MlDsa65(Box<qp_dilithium_crypto::types::Dilithium65Pair>),
	MlDsa87(Box<qp_dilithium_crypto::types::Dilithium87Pair>),
}

/// A key plus the FIPS 204 context the connected runtime verifies under. The context is part of
/// the signer because it is not a property of the key: the same wallet signs with no context for
/// a pre-148 runtime and under `QUANTUS_EXTRINSIC` from spec 148 on.
pub struct QuantusSigner {
	pub pair: SignerPair,
	context: Option<&'static [u8]>,
}

impl QuantusSigner {
	pub fn new(pair: SignerPair, context: Option<&'static [u8]>) -> Self {
		Self { pair, context }
	}
}

impl subxt::tx::Signer<ChainConfig> for QuantusSigner {
	fn account_id(&self) -> <ChainConfig as Config>::AccountId {
		use sp_core::Pair;
		match &self.pair {
			SignerPair::MlDsa65(pair) =>
				<qp_dilithium_crypto::types::Dilithium65Public as IdentifyAccount>::into_account(
					pair.public(),
				),
			SignerPair::MlDsa87(pair) =>
				<qp_dilithium_crypto::types::Dilithium87Public as IdentifyAccount>::into_account(
					pair.public(),
				),
		}
	}

	fn sign(&self, signer_payload: &[u8]) -> <ChainConfig as Config>::Signature {
		match &self.pair {
			SignerPair::MlDsa65(pair) => DilithiumSignatureScheme::Dilithium65(
				crate::chain::signing::sign_ml_dsa_65(pair, signer_payload, self.context),
			),
			SignerPair::MlDsa87(pair) => DilithiumSignatureScheme::Dilithium87(
				crate::chain::signing::sign_ml_dsa_87(pair, signer_payload, self.context),
			),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use jsonrpsee::{
		server::{RpcModule, Server, ServerHandle},
		types::ErrorObjectOwned,
	};
	use serde_json::json;
	use std::sync::Mutex;

	const OLD_RUNTIME: RuntimeVersion =
		RuntimeVersion { spec_version: 144, transaction_version: 3 };
	const NEW_RUNTIME: RuntimeVersion =
		RuntimeVersion { spec_version: 148, transaction_version: 6 };
	const GENESIS: H256 = H256([0x01; 32]);
	const FINALIZED: H256 = H256([0x44; 32]);
	const HEAD: H256 = H256([0x48; 32]);

	fn runtime_at(hash: H256) -> RuntimeVersion {
		if hash == HEAD {
			NEW_RUNTIME
		} else {
			OLD_RUNTIME
		}
	}

	/// A node caught mid-upgrade the way Heisenberg is for ~20 minutes after every enactment:
	/// the head runs the new runtime, the finalized block still runs the old one. Records the
	/// block named by every metadata request.
	async fn mock_node() -> (String, Arc<Mutex<Vec<H256>>>, ServerHandle) {
		let metadata_requests = Arc::new(Mutex::new(Vec::new()));
		let server = Server::builder().build("127.0.0.1:0").await.expect("bind mock node");
		let url = format!("ws://{}", server.local_addr().expect("mock node address"));
		let mut module = RpcModule::new(metadata_requests.clone());
		module
			.register_method("chain_getBlockHash", |params, _, _| {
				let number: Option<u32> = params.sequence().optional_next()?;
				Ok::<_, ErrorObjectOwned>(if number == Some(0) { GENESIS } else { HEAD })
			})
			.expect("register");
		module
			.register_method("chain_getFinalizedHead", |_, _, _| {
				Ok::<_, ErrorObjectOwned>(FINALIZED)
			})
			.expect("register");
		module
			.register_method("state_getRuntimeVersion", |params, _, _| {
				let at: Option<H256> = params.sequence().optional_next()?;
				let version = runtime_at(at.unwrap_or(HEAD));
				Ok::<_, ErrorObjectOwned>(json!({
					"specName": crate::config::EXPECTED_RUNTIME_SPEC_NAME,
					"specVersion": version.spec_version,
					"transactionVersion": version.transaction_version,
				}))
			})
			.expect("register");
		module
			.register_method("state_call", |params, requests: &Arc<Mutex<Vec<H256>>>, _| {
				let mut params = params.sequence();
				let function: String = params.next()?;
				let _encoded_args: String = params.next()?;
				let at: Option<H256> = params.optional_next()?;
				assert_eq!(function, "Metadata_metadata_at_version");
				requests
					.lock()
					.expect("lock")
					.push(at.expect("metadata request must name a block"));
				let metadata: &[u8] = include_bytes!("../quantus_metadata.scale");
				Ok::<_, ErrorObjectOwned>(format!(
					"0x{}",
					hex::encode(Some(metadata.to_vec()).encode())
				))
			})
			.expect("register");
		(url, metadata_requests, server.start(module))
	}

	#[tokio::test]
	async fn connect_reads_runtime_version_and_metadata_from_one_head_block() {
		let (url, metadata_requests, _node) = mock_node().await;
		let client = QuantusClient::new(&url).await.expect("connect");
		assert_eq!(client.client().runtime_version(), NEW_RUNTIME);
		assert_eq!(client.client().genesis_hash(), GENESIS);
		assert_eq!(*metadata_requests.lock().expect("lock"), vec![HEAD]);
	}

	#[tokio::test]
	async fn at_block_decodes_a_pre_upgrade_block_with_the_runtime_that_produced_it() {
		let (url, metadata_requests, _node) = mock_node().await;
		let head = QuantusClient::new(&url).await.expect("connect");

		let old = head.at_block(FINALIZED).await.expect("client at the finalized block");
		assert_eq!(old.client().runtime_version(), OLD_RUNTIME);
		assert_eq!(head.client().runtime_version(), NEW_RUNTIME, "head client must be untouched");
		assert_eq!(*metadata_requests.lock().expect("lock"), vec![HEAD, FINALIZED]);

		let same = head.at_block(HEAD).await.expect("client at the head block");
		assert_eq!(same.client().runtime_version(), NEW_RUNTIME);
		assert_eq!(
			*metadata_requests.lock().expect("lock"),
			vec![HEAD, FINALIZED],
			"same runtime: metadata is not fetched again"
		);
	}

	#[test]
	fn parse_runtime_version_rejects_missing_fields() {
		assert!(parse_runtime_version(&json!({ "specVersion": 148 })).is_err());
		assert_eq!(
			parse_runtime_version(&json!({ "specVersion": 148, "transactionVersion": 6 }))
				.expect("parse"),
			NEW_RUNTIME
		);
	}

	#[tokio::test]
	async fn quantus_client_new_redacts_userinfo_in_invalid_url_error() {
		let secret = format!(
			"rpc-token-{}-{}",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.expect("clock must be after unix epoch")
				.as_nanos()
		);
		let attacker_controlled_url = format!("https://api-user:{secret}@rpc.example.invalid/ws");

		let error = match QuantusClient::new(&attacker_controlled_url).await {
			Ok(_) => panic!("non-WebSocket scheme must fail"),
			Err(error) => error,
		};
		let diagnostic = error.to_string();

		assert!(
			!diagnostic.contains(&secret),
			"NetworkError must not expose URL userinfo; diagnostic was: {diagnostic}"
		);
		assert!(
			!diagnostic.contains(&format!("api-user:{secret}")),
			"NetworkError must not expose raw credentialed URL; diagnostic was: {diagnostic}"
		);
		assert!(
			diagnostic.contains("rpc.example.invalid"),
			"sanitized host should remain visible; diagnostic was: {diagnostic}"
		);
	}

	#[test]
	fn sanitize_url_for_diagnostics_strips_userinfo() {
		assert_eq!(
			QuantusClient::sanitize_url_for_diagnostics("wss://user:pass@rpc.example.com/path?q=1"),
			"wss://rpc.example.com/path?q=1"
		);
		assert_eq!(
			QuantusClient::sanitize_url_for_diagnostics("ws://token@localhost:9944"),
			"ws://localhost:9944"
		);
		assert_eq!(
			QuantusClient::sanitize_url_for_diagnostics("wss://rpc.example.com"),
			"wss://rpc.example.com"
		);
	}

	#[test]
	fn interpret_account_nonce_distinguishes_absent_account() {
		// #159454/#159455: absence must not be indistinguishable from a real nonce-0 account.
		assert_eq!(QuantusClient::interpret_account_nonce(None), (0, false));
		assert_eq!(QuantusClient::interpret_account_nonce(Some(0)), (0, true));
		assert_eq!(QuantusClient::interpret_account_nonce(Some(7)), (7, true));
	}
}
