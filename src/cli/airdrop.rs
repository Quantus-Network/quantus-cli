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
use qp_ownership_circuit::{CircuitInputs, Secret};
use qp_rusty_crystals_dilithium::ml_dsa_87::SecretKey;
use qp_rusty_crystals_hdwallet::{derive_wormhole_from_mnemonic, QUANTUS_WORMHOLE_CHAIN_ID};
use qp_zk_circuits_common::utils::BytesDigest;
use serde::{Deserialize, Serialize};
use sp_core::crypto::{AccountId32, Ss58Codec};
use std::{collections::HashMap, path::PathBuf, time::Duration};

const CLAIM_CONTEXT: &[u8] = b"qp-airdrop-claim-v1";
const CLAIM_TTL_SECS: i64 = 10 * 60;
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";
const HD_WORMHOLE_INDEXES: std::ops::RangeInclusive<usize> = 0..=16;
const CLAIMABLE_WORMHOLE_SCHEME: &str = "wormhole-rate8-compact";

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

		/// HD wormhole index at round 0 (default: scan 0..=16)
		#[arg(long)]
		wormhole_index: Option<usize>,
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

		/// HD wormhole index at round 0 (default: scan 0..=16)
		#[arg(long)]
		wormhole_index: Option<usize>,

		/// Print matches and signed/proved payloads without POSTing
		#[arg(long)]
		dry_run: bool,
	},
}

pub async fn handle_airdrop_command(command: AirdropCommands) -> Result<()> {
	match command {
		AirdropCommands::Check {
			server,
			wallet,
			password,
			password_file,
			wormhole_secret_file,
			wormhole_index,
		} =>
			handle_check(
				server,
				wallet,
				password,
				password_file,
				wormhole_secret_file,
				wormhole_index,
			)
			.await,
		AirdropCommands::Claim {
			server,
			wallet,
			to,
			password,
			password_file,
			wormhole_secret_file,
			wormhole_index,
			dry_run,
		} =>
			handle_claim(
				server,
				wallet,
				to,
				password,
				password_file,
				wormhole_secret_file,
				wormhole_index,
				dry_run,
			)
			.await,
	}
}

async fn handle_check(
	server: String,
	wallet: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
	wormhole_secret_file: Option<PathBuf>,
	wormhole_index: Option<usize>,
) -> Result<()> {
	let snapshot = fetch_snapshot(&server).await?;
	let credentials = collect_credentials(
		wallet.as_deref(),
		password,
		password_file,
		wormhole_secret_file.as_deref(),
		wormhole_index,
	)?;
	if credentials.dilithium.is_none() && credentials.wormhole_secrets.is_empty() {
		return Err(QuantusError::Generic("provide --wallet and/or --wormhole-secret-file".into()));
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
	wormhole_index: Option<usize>,
	dry_run: bool,
) -> Result<()> {
	let credentials = collect_credentials(
		wallet.as_deref(),
		password,
		password_file,
		wormhole_secret_file.as_deref(),
		wormhole_index,
	)?;
	if credentials.dilithium.is_none() && credentials.wormhole_secrets.is_empty() {
		return Err(QuantusError::Generic("provide --wallet and/or --wormhole-secret-file".into()));
	}

	let claim_account = resolve_claim_account(to.as_deref(), wallet.as_deref(), &credentials)?;
	let snapshot = fetch_snapshot(&server).await?;
	let matches = find_matches(&snapshot, &credentials);

	print_snapshot_header(&snapshot);
	print_matches(&matches);
	log_print!("Payout destination: {}", bytes_to_quantus_ss58(&claim_account).bright_cyan());

	if matches.is_empty() {
		log_print!("No snapshot addresses to claim.");
		return Ok(());
	}

	let client = http_client()?;
	let mut claimed = 0u64;
	let mut skipped = 0u64;
	for found in &matches {
		match submit_claim(&client, &server, found, &claim_account, &credentials, dry_run).await {
			Ok(ClaimOutcome::Recorded { amount_hundredths }) => {
				claimed = claimed.saturating_add(amount_hundredths);
			},
			Ok(ClaimOutcome::Skipped) => skipped += 1,
			Err(e) => {
				log_error!("Failed {}: {e}", found.ss58);
				skipped += 1;
			},
		}
	}

	if dry_run {
		log_print!(
			"Dry run finished. Would submit {} claim(s); skipped {}.",
			matches.len().saturating_sub(skipped as usize),
			skipped
		);
	} else {
		log_success!(
			"Recorded {} QUAN across submitted claims ({} skipped).",
			format_hundredths(claimed),
			skipped
		);
	}
	Ok(())
}

struct Credentials {
	dilithium: Option<QuantumKeyPair>,
	wormhole_secrets: Vec<([u8; 32], String)>,
}

fn collect_credentials(
	wallet: Option<&str>,
	password: Option<String>,
	password_file: Option<String>,
	wormhole_secret_file: Option<&std::path::Path>,
	wormhole_index: Option<usize>,
) -> Result<Credentials> {
	let mut wormhole_secrets = Vec::new();
	let mut dilithium = None;

	if let Some(name) = wallet {
		let (keypair, mnemonic) = load_wallet_material(name, password, password_file)?;
		if keypair.scheme != DilithiumScheme::MlDsa87 {
			log_print!(
				"Wallet '{}' is {:?}; Dilithium airdrop claims require ML-DSA-87.",
				name,
				keypair.scheme
			);
		} else {
			dilithium = Some(keypair);
		}
		if let Some(mnemonic) = mnemonic.as_deref() {
			wormhole_secrets.extend(derive_hd_wormhole_secrets(mnemonic, wormhole_index)?);
		} else {
			log_verbose!("Wallet '{}' has no mnemonic; HD wormhole derivation skipped", name);
		}
	}

	if let Some(path) = wormhole_secret_file {
		let secret = read_wormhole_secret(path)?;
		wormhole_secrets.push((secret, path.display().to_string()));
	}

	Ok(Credentials { dilithium, wormhole_secrets })
}

fn load_wallet_material(
	wallet_name: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<(QuantumKeyPair, Option<String>)> {
	let wallet_manager = WalletManager::new()?;
	if wallet_manager.wallet_type(wallet_name)? == Some(WalletType::Cold) {
		return Err(WalletError::ColdWalletNoKeys(wallet_name.to_string()).into());
	}
	let wallet_password = password::get_wallet_password(wallet_name, password, password_file)?;
	let mut wallet_data = wallet_manager.load_wallet(wallet_name, &wallet_password)?;
	let mnemonic = wallet_data.take_mnemonic();
	Ok((wallet_data.take_keypair(), mnemonic))
}

fn derive_hd_wormhole_secrets(
	mnemonic: &str,
	wormhole_index: Option<usize>,
) -> Result<Vec<([u8; 32], String)>> {
	let indexes: Vec<usize> = match wormhole_index {
		Some(index) => vec![index],
		None => HD_WORMHOLE_INDEXES.collect(),
	};
	let mut out = Vec::new();
	for index in indexes {
		let path = format!("m/44'/{}/0'/0'/{}'", QUANTUS_WORMHOLE_CHAIN_ID, index);
		let pair = derive_wormhole_from_mnemonic(mnemonic, None, &path)
			.map_err(|e| QuantusError::Generic(format!("HD derivation failed: {e:?}")))?;
		out.push((*pair.secret().as_bytes(), format!("hd {path}")));
	}
	Ok(out)
}

fn read_wormhole_secret(path: &std::path::Path) -> Result<[u8; 32]> {
	let hex_str = password::read_secret_file(
		path.to_str()
			.ok_or_else(|| QuantusError::Generic("secret path is not UTF-8".into()))?,
		"secret",
	)?;
	parse_secret_hex(&hex_str).map_err(QuantusError::Generic)
}

fn resolve_claim_account(
	to: Option<&str>,
	wallet: Option<&str>,
	credentials: &Credentials,
) -> Result<[u8; 32]> {
	if let Some(to) = to {
		let (_, account) = resolve_address_with_subxt_account_id(to)?;
		return Ok(*account.as_ref());
	}
	if let Some(keypair) = &credentials.dilithium {
		let account = keypair.try_to_account_id_32()?;
		return Ok(*account.as_ref());
	}
	if let Some(name) = wallet {
		let (_, account) = resolve_address_with_subxt_account_id(name)?;
		return Ok(*account.as_ref());
	}
	Err(QuantusError::Generic("--to is required when claiming without a Dilithium wallet".into()))
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

#[derive(Clone, Debug)]
enum RewardSource {
	Dilithium,
	Wormhole { secret: [u8; 32], label: String },
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
	for (secret, label) in &credentials.wormhole_secrets {
		for scheme in WormholeHash::ALL {
			let derived = scheme.derive(secret);
			if let Some(row) = snapshot.by_account.get(&derived.address) {
				found.push(FoundReward {
					account: derived.address,
					ss58: row.address.clone(),
					amount_hundredths: row.amount_hundredths,
					testnets: row.testnets.clone(),
					kind: row.kind.clone(),
					scheme: scheme.id(),
					source: RewardSource::Wormhole { secret: *secret, label: label.clone() },
				});
			}
		}
	}
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
			RewardSource::Dilithium => true,
			RewardSource::Wormhole { .. } => found.scheme == CLAIMABLE_WORMHOLE_SCHEME,
		};
		let note = if claimable { "claimable" } else { "not claimable yet" };
		log_print!(
			"  {}  {} QUAN  {}  {} ({})  [{}]",
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
			ClaimBody::Dilithium(build_dilithium_claim(keypair, found.account, *claim_account)?)
		},
		RewardSource::Wormhole { secret, label } => {
			if found.scheme != CLAIMABLE_WORMHOLE_SCHEME {
				log_print!(
					"Skipping {} ({}) from {label}: server only accepts {CLAIMABLE_WORMHOLE_SCHEME}",
					found.ss58,
					found.scheme
				);
				return Ok(ClaimOutcome::Skipped);
			}
			log_print!("Proving wormhole ownership for {}…", found.ss58.bright_cyan());
			ClaimBody::Wormhole(build_wormhole_claim(*secret, *claim_account).await?)
		},
	};

	if dry_run {
		log_print!("Dry run: would POST {} ({})", found.ss58, found.scheme);
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
		"Recorded {} → {} ({} QUAN)",
		recorded.address.bright_cyan(),
		recorded.claim_account.bright_green(),
		format_hundredths(recorded.amount_hundredths)
	);
	Ok(ClaimOutcome::Recorded { amount_hundredths: recorded.amount_hundredths })
}

fn build_dilithium_claim(
	keypair: &QuantumKeyPair,
	address: [u8; 32],
	claim_account: [u8; 32],
) -> Result<DilithiumClaimBody> {
	let expiry_unix = now_unix()?.saturating_add(CLAIM_TTL_SECS);
	let msg = claim_message(&address, &claim_account, expiry_unix);
	let secret = SecretKey::from_bytes(&keypair.private_key)
		.map_err(|_| QuantusError::Generic("invalid ML-DSA-87 secret key".into()))?;
	let signature = secret
		.sign(&msg, Some(CLAIM_CONTEXT), None)
		.map_err(|e| QuantusError::Generic(format!("ML-DSA sign failed: {e}")))?;
	let scheme = DilithiumHash::ALL
		.iter()
		.find(|s| s.derive(&keypair.public_key) == address)
		.ok_or_else(|| QuantusError::Generic("could not identify Dilithium hash scheme".into()))?;
	Ok(DilithiumClaimBody {
		scheme: scheme.id().to_string(),
		address: bytes_to_quantus_ss58(&address),
		claim_account: bytes_to_quantus_ss58(&claim_account),
		public_key: hex::encode(&keypair.public_key),
		signature: hex::encode(signature),
		expiry_unix,
	})
}

async fn build_wormhole_claim(
	secret: [u8; 32],
	claim_account: [u8; 32],
) -> Result<WormholeClaimBody> {
	let secret = Secret::try_from(secret)
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
	V09Padded,
	V10Padded,
	Rate8HashBytes,
}

impl DilithiumHash {
	const ALL: &'static [Self] = &[Self::V09Padded, Self::V10Padded, Self::Rate8HashBytes];

	fn id(self) -> &'static str {
		match self {
			Self::V09Padded => "dilithium-v09-padded",
			Self::V10Padded => "dilithium-v10-padded",
			Self::Rate8HashBytes => "dilithium-rate8-hash-bytes",
		}
	}

	fn derive(self, public_key: &[u8]) -> [u8; 32] {
		match self {
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
		let mut preimage = injective4(b"wormhole");
		preimage.extend(self.encode_secret(secret));
		let first_hash = self.sponge().hash_felts(&preimage);
		let address = self.sponge().rehash(&first_hash);
		DerivedWormhole { first_hash, address }
	}

	fn encode_secret(self, secret: &[u8; 32]) -> Vec<qp_poseidon_core::Goldilocks> {
		match self {
			Self::V09Injective | Self::Rate4Injective | Self::Rate8Injective => injective4(secret),
			Self::Rate4Compact | Self::Rate8Compact => compact8_decode(secret).to_vec(),
		}
	}

	fn sponge(self) -> Sponge {
		match self {
			Self::V09Injective => Sponge::Rate4Pad10PlusDomain,
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
	Rate4Pad10PlusDomain,
	Rate4Pad10,
	Rate8Pad10,
}

impl Sponge {
	fn hash_felts(self, input: &[qp_poseidon_core::Goldilocks]) -> [u8; 32] {
		match self {
			Self::Rate4Pad10PlusDomain => hash_no_pad_v09(input),
			Self::Rate4Pad10 => hash_felts_rate4_pad10(input),
			Self::Rate8Pad10 => qp_poseidon_core::hash_to_bytes(input),
		}
	}

	fn rehash(self, digest: &[u8; 32]) -> [u8; 32] {
		self.hash_felts(&compact8_decode(digest))
	}
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

fn hash_no_pad_v09(x: &[qp_poseidon_core::Goldilocks]) -> [u8; 32] {
	use qp_poseidon_core::{Goldilocks, Poseidon2, POSEIDON2_OUTPUT, SPONGE_WIDTH};
	const RATE_4: usize = 4;
	let poseidon = Poseidon2::new();
	let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];

	if !x.is_empty() {
		let num_chunks = x.chunks(RATE_4).len();
		let mut unpadded = false;
		for (j, chunk) in x.chunks(RATE_4).enumerate() {
			let mut block = [Goldilocks::ZERO; RATE_4];
			if j == num_chunks - 1 {
				if chunk.len() < RATE_4 {
					block[chunk.len()] = Goldilocks::ONE;
				} else {
					unpadded = true;
				}
			}
			block[..chunk.len()].copy_from_slice(chunk);
			for i in 0..RATE_4 {
				state[i] += block[i];
			}
			poseidon.permute_mut(&mut state);
		}
		if unpadded {
			state[0] += Goldilocks::ONE;
			poseidon.permute_mut(&mut state);
		}
	}

	state[3] += Goldilocks::ONE;
	poseidon.permute_mut(&mut state);

	let digest: [Goldilocks; POSEIDON2_OUTPUT] =
		state[..POSEIDON2_OUTPUT].try_into().expect("width > output");
	qp_poseidon_core::serialization::digest_to_bytes(&digest)
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
	qp_poseidon_core::serialization::digest_to_bytes(&digest)
}

fn hash_padded_v09(bytes: &[u8]) -> [u8; 32] {
	use qp_poseidon_core::Goldilocks;
	const MIN_FELTS: usize = 190;
	let mut felts = injective4(bytes);
	let len = felts.len();
	felts.insert(0, Goldilocks::from_u64(len as u64));
	if len < MIN_FELTS {
		felts.resize(MIN_FELTS, Goldilocks::ZERO);
	}
	hash_no_pad_v09(&felts)
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

	#[test]
	fn historical_wormhole_schemes_diverge() {
		let secret = [9u8; 32];
		let addrs: Vec<_> = WormholeHash::ALL.iter().map(|s| s.derive(&secret).address).collect();
		assert!(addrs.iter().any(|a| *a != addrs[0]));
	}

	#[test]
	fn dilithium_hash_schemes_diverge() {
		let pk = [7u8; 64];
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
}
