//! `quantus near` — control NEAR accounts with a Quantus ML-DSA-65 wallet.
//!
//! NEAR accepts ML-DSA-65 access keys and transaction signatures from
//! protocol version 85. These commands create and drive a NEAR account whose
//! only access key is a Quantus wallet's ML-DSA-65 key:
//!
//! 1. `near show-key` — the wallet's key in NEAR text form.
//! 2. `near create-account` — a parent account creates a sub-account born with the ML-DSA-65 key as
//!    its only key. The parent holds no key on it.
//! 3. `near keys` — verify the account's key list from the chain.
//! 4. `near send` — spend from the account, signed by the wallet.
//! 5. `near dao ...` — act as a co-signer in a Sputnik DAO multisig (the contract behind Trezu):
//!    propose transfers and vote, signed by the wallet. Sputnik authorizes by account id, so an
//!    ML-DSA-65-controlled account is a full member with no DAO-side changes.
//! 6. `near sign-cold` — sign a transaction prepared by near-cli-rs with a cold (air-gapped) wallet
//!    over QR codes, for any contract call the hot commands do not cover.
//! 7. `near import-cold-key` — read the NEAR public key a cold wallet exports as a QR, so the
//!    commands above work with a cold wallet too: a cold wallet file holds only an SS58 address,
//!    which cannot be turned back into the key NEAR needs.
//!
//! Every command that takes `--wallet` accepts a hot or a cold wallet; with a
//! cold wallet, signing runs the QR roundtrip of `sign-cold`.
//!
//! ML-DSA-87 wallets are rejected: NEAR defined ML-DSA-65 only.

use crate::{
	cli::cold_signing::{read_signature_response, response_source, ColdIo},
	error::{QuantusError, Result},
	log_print, log_success, log_verbose,
	near::{
		cold::{load_unsigned_transaction, sign_transaction_cold},
		protocol::{
			validate_account_id, AccessKey, Action, AddKeyAction, FunctionCallAction, PublicKey,
			SignedTransaction, Transaction, TransferAction, NEAR_DECIMALS,
		},
		rpc::{decode_success_value, NearRpcClient},
		sign::{load_credentials, sign_transaction_ed25519, sign_transaction_ml_dsa_65},
	},
	qr::NearPublicKeyExport,
	wallet::{QuantumKeyPair, WalletManager, WalletSigner},
};
use clap::Subcommand;
use colored::Colorize;
use std::path::PathBuf;

/// NEAR subcommands
#[derive(Subcommand, Debug)]
pub enum NearCommands {
	/// Show the wallet's ML-DSA-65 key in NEAR text forms
	ShowKey {
		/// Quantus wallet (must be ML-DSA-65); a cold wallet needs `near import-cold-key` first
		#[arg(long, short)]
		wallet: String,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Create a NEAR sub-account whose only access key is the wallet's
	/// ML-DSA-65 key. The parent signs the creation and holds no key on the
	/// new account.
	CreateAccount {
		/// New account id; must be a sub-account of the parent
		/// (e.g. vault.alice.testnet under alice.testnet)
		#[arg(long)]
		new_account: String,

		/// Quantus wallet whose ML-DSA-65 key controls the new account
		#[arg(long, short)]
		wallet: String,

		/// near-cli credentials JSON for the parent account
		/// (~/.near-credentials/<network>/<parent>.json)
		#[arg(long)]
		parent_credentials: PathBuf,

		/// Initial balance for the new account, in NEAR
		#[arg(long, default_value = "0.1")]
		deposit: String,

		/// NEAR network: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Custom NEAR RPC URL (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// List an account's access keys as stored on-chain
	Keys {
		/// NEAR account id to inspect
		#[arg(long)]
		account: String,

		/// Mark keys belonging to this Quantus wallet
		#[arg(long, short)]
		wallet: Option<String>,

		/// NEAR network: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Custom NEAR RPC URL (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Transfer NEAR from an account controlled by the wallet's ML-DSA-65 key
	Send {
		/// Quantus wallet holding the account's ML-DSA-65 key
		#[arg(long, short)]
		wallet: String,

		/// NEAR account to send from
		#[arg(long)]
		account: String,

		/// Recipient NEAR account id
		#[arg(long)]
		to: String,

		/// Amount in NEAR (e.g. "1.5")
		#[arg(long)]
		amount: String,

		/// NEAR network: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Custom NEAR RPC URL (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Sign a prepared NEAR transaction with a cold (air-gapped) Quantus
	/// wallet over QR codes. Build the transaction with near-cli-rs
	/// (`... sign-later --signer-public-key ml-dsa-65:<key> ... save-to-file`)
	/// and pass its output here; the result is a base64 signed transaction
	/// for `near transaction send-signed-transaction`, or send it directly
	/// with --send.
	SignCold {
		/// Unsigned transaction: base64 borsh, or @path to a file holding
		/// base64 or the JSON `sign-later ... save-to-file` writes
		#[arg(long)]
		unsigned_tx: String,

		/// Cold wallet (created with `quantus wallet import-cold`) whose
		/// ML-DSA-65 key the transaction declares
		#[arg(long, short)]
		wallet: String,

		/// NEAR network the transaction is for, shown on the device: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Write the signed transaction (base64) to this file
		#[arg(long)]
		out: Option<PathBuf>,

		/// Submit the signed transaction to the network and wait for finality
		#[arg(long)]
		send: bool,

		/// Custom NEAR RPC URL for --send (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,
	},

	/// Import a cold wallet's NEAR public key from the QR its device shows
	/// (cold wallet app: account → Show public key → NEAR). The key must
	/// belong to the wallet's address; afterwards the other commands accept
	/// the cold wallet.
	ImportColdKey {
		/// Cold wallet (created with `quantus wallet import-cold`)
		#[arg(long, short)]
		wallet: String,

		/// The key as text (`ml-dsa-65:<base58>`) instead of scanning a QR
		#[arg(long)]
		key: Option<String>,
	},

	/// Act in a Sputnik DAO multisig (the contract behind Trezu) as a member
	/// account controlled by the wallet
	Dao {
		#[command(subcommand)]
		command: DaoCommands,
	},
}

/// Sputnik DAO subcommands
#[derive(Subcommand, Debug)]
pub enum DaoCommands {
	/// Propose a NEAR transfer from the DAO treasury (calls `add_proposal`)
	ProposeTransfer {
		/// Sputnik DAO contract account id
		#[arg(long)]
		dao: String,

		/// Member account the wallet controls
		#[arg(long)]
		account: String,

		/// Quantus wallet holding the member account's ML-DSA-65 key
		#[arg(long, short)]
		wallet: String,

		/// Transfer recipient
		#[arg(long)]
		receiver: String,

		/// Amount in NEAR
		#[arg(long)]
		amount: String,

		/// Proposal description shown to voters
		#[arg(long, default_value = "Proposed via quantus-cli")]
		description: String,

		/// Proposal bond in NEAR (default: the exact bond from the DAO policy)
		#[arg(long)]
		bond: Option<String>,

		/// NEAR network: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Custom NEAR RPC URL (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Vote on a proposal (calls `act_proposal`; an approving vote that meets
	/// the threshold also executes the proposal)
	Vote {
		/// Sputnik DAO contract account id
		#[arg(long)]
		dao: String,

		/// Member account the wallet controls
		#[arg(long)]
		account: String,

		/// Quantus wallet holding the member account's ML-DSA-65 key
		#[arg(long, short)]
		wallet: String,

		/// Proposal id
		#[arg(long)]
		id: u64,

		/// approve, reject, or remove
		#[arg(long)]
		vote: String,

		/// NEAR network: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Custom NEAR RPC URL (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,

		/// Password for the wallet (unsupported on argv; use --password-file or prompt)
		#[arg(short, long, hide = true)]
		password: Option<String>,

		/// Read password from file (for scripting)
		#[arg(long)]
		password_file: Option<String>,
	},

	/// Show a proposal's state (view call, no wallet needed)
	Proposal {
		/// Sputnik DAO contract account id
		#[arg(long)]
		dao: String,

		/// Proposal id
		#[arg(long)]
		id: u64,

		/// NEAR network: testnet or mainnet
		#[arg(long, default_value = "testnet")]
		network: String,

		/// Custom NEAR RPC URL (overrides --network)
		#[arg(long)]
		rpc_url: Option<String>,
	},
}

pub async fn handle_near_command(command: NearCommands) -> Result<()> {
	match command {
		NearCommands::ShowKey { wallet, password, password_file } =>
			handle_show_key(&wallet, password, password_file),
		NearCommands::CreateAccount {
			new_account,
			wallet,
			parent_credentials,
			deposit,
			network,
			rpc_url,
			password,
			password_file,
		} =>
			handle_create_account(
				&new_account,
				&wallet,
				&parent_credentials,
				&deposit,
				&network,
				rpc_url,
				password,
				password_file,
			)
			.await,
		NearCommands::Keys { account, wallet, network, rpc_url, password, password_file } =>
			handle_keys(&account, wallet, &network, rpc_url, password, password_file).await,
		NearCommands::Send {
			wallet,
			account,
			to,
			amount,
			network,
			rpc_url,
			password,
			password_file,
		} =>
			handle_send(&wallet, &account, &to, &amount, &network, rpc_url, password, password_file)
				.await,
		NearCommands::SignCold { unsigned_tx, wallet, network, out, send, rpc_url } =>
			handle_sign_cold(&unsigned_tx, &wallet, &network, out, send, rpc_url).await,
		NearCommands::ImportColdKey { wallet, key } => handle_import_cold_key(&wallet, key).await,
		NearCommands::Dao { command } => handle_dao_command(command).await,
	}
}

async fn handle_import_cold_key(wallet: &str, key: Option<String>) -> Result<()> {
	let manager = WalletManager::new()?;
	let existing = manager.cold_near_public_key(wallet)?;
	let WalletSigner::Cold { address, .. } =
		crate::wallet::load_signer_from_wallet(wallet, None, None)?
	else {
		return Err(QuantusError::Generic(format!("wallet '{wallet}' is not a cold wallet")));
	};

	let export = match key {
		Some(key) => NearPublicKeyExport::new(address.clone(), key.trim())?,
		None => {
			let source = response_source(ColdIo::global())?;
			log_print!(
				"📷 On the cold wallet open the account, choose Show public key, then show the \
				 NEAR key QR."
			);
			let export = NearPublicKeyExport::decode(&read_signature_response(&source).await?)?;
			if export.address != address {
				return Err(QuantusError::Generic(format!(
					"the QR exports the key of {}, but wallet '{wallet}' is {address}",
					export.address
				)));
			}
			export
		},
	};
	let public = export.public_key()?;

	if existing.as_deref() == Some(export.near_public_key.as_str()) {
		log_print!("ℹ️  Wallet '{wallet}' already holds this NEAR key");
		print_key(&public);
		return Ok(());
	}
	manager.set_cold_near_public_key(wallet, &address, &export.near_public_key)?;
	log_success!("✅ NEAR key of cold wallet '{wallet}' ({address}) saved");
	print_key(&public);
	log_print!(
		"💡 Register it on an account with `quantus near create-account --wallet {wallet} ...` or \
		 `near account add-key`"
	);
	Ok(())
}

async fn handle_sign_cold(
	unsigned_tx: &str,
	wallet: &str,
	network: &str,
	out: Option<PathBuf>,
	send: bool,
	rpc_url: Option<String>,
) -> Result<()> {
	let cold_address = match crate::wallet::load_signer_from_wallet(wallet, None, None)? {
		crate::wallet::WalletSigner::Cold { address, .. } => address,
		crate::wallet::WalletSigner::Hot(_) =>
			return Err(QuantusError::Generic(format!(
				"wallet '{wallet}' is a hot wallet; sign-cold is for cold wallets. Use `quantus \
				 near send` or the other hot commands with it instead."
			))),
	};
	let tx = load_unsigned_transaction(unsigned_tx)?;

	let signed =
		sign_transaction_cold(tx, network, wallet, &cold_address, ColdIo::global()).await?;
	let signed_b64 = signed.to_base64()?;

	if let Some(path) = &out {
		std::fs::write(path, format!("{signed_b64}\n"))?;
		log_print!("📝 Signed transaction written to {}", path.display());
	} else if !send {
		log_print!("Signed transaction (base64):");
		println!("{signed_b64}");
	}

	if send {
		let client = NearRpcClient::for_network(network, rpc_url)?;
		client.ensure_ml_dsa_support().await?;
		let outcome = client.send_tx(&signed).await?;
		report_outcome(network, &outcome);
		log_success!("✅ Transaction finalized");
	} else {
		log_print!(
			"💡 Submit with: near transaction send-signed-transaction base64-signed-transaction \
			 '<base64>' network-config {network} send"
		);
	}
	Ok(())
}

async fn handle_dao_command(command: DaoCommands) -> Result<()> {
	match command {
		DaoCommands::ProposeTransfer {
			dao,
			account,
			wallet,
			receiver,
			amount,
			description,
			bond,
			network,
			rpc_url,
			password,
			password_file,
		} =>
			handle_dao_propose_transfer(
				&dao,
				&account,
				&wallet,
				&receiver,
				&amount,
				&description,
				bond,
				&network,
				rpc_url,
				password,
				password_file,
			)
			.await,
		DaoCommands::Vote {
			dao,
			account,
			wallet,
			id,
			vote,
			network,
			rpc_url,
			password,
			password_file,
		} =>
			handle_dao_vote(
				&dao,
				&account,
				&wallet,
				id,
				&vote,
				&network,
				rpc_url,
				password,
				password_file,
			)
			.await,
		DaoCommands::Proposal { dao, id, network, rpc_url } =>
			handle_dao_proposal(&dao, id, &network, rpc_url).await,
	}
}

/// How a NEAR transaction gets signed: locally from a hot wallet's key, or
/// over QR codes by a cold wallet.
enum NearSigner {
	Hot(QuantumKeyPair),
	Cold { name: String, address: String },
}

impl NearSigner {
	async fn sign(&self, tx: Transaction, network: &str) -> Result<SignedTransaction> {
		match self {
			NearSigner::Hot(keypair) =>
				sign_transaction_ml_dsa_65(tx, &keypair.to_dilithium65_pair()?),
			NearSigner::Cold { name, address } =>
				sign_transaction_cold(tx, network, name, address, ColdIo::global()).await,
		}
	}
}

/// Load a wallet and its key as a NEAR public key, refusing non-65 schemes.
/// A cold wallet resolves without a password, from the key it imported with
/// `near import-cold-key`.
fn load_near_signer(
	wallet: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<(NearSigner, PublicKey)> {
	match crate::wallet::load_signer_from_wallet(wallet, password, password_file)? {
		WalletSigner::Hot(keypair) => {
			if keypair.scheme != crate::wallet::DilithiumScheme::MlDsa65 {
				return Err(QuantusError::Generic(format!(
					"wallet '{wallet}' is {:?}; NEAR supports ML-DSA-65 only — create one with \
					 `quantus wallet create --scheme ml-dsa-65`",
					keypair.scheme
				)));
			}
			let public = PublicKey::from_ml_dsa_65_bytes(&keypair.public_key)?;
			Ok((NearSigner::Hot(keypair), public))
		},
		WalletSigner::Cold { name, address } => {
			let key = WalletManager::new()?.cold_near_public_key(&name)?.ok_or_else(|| {
				QuantusError::Generic(format!(
					"cold wallet '{wallet}' has no NEAR public key yet — import it from the \
					 device with `quantus near import-cold-key --wallet {wallet}`"
				))
			})?;
			// The wallet file is unencrypted; re-check the key against the
			// address rather than trusting what is on disk.
			let public = NearPublicKeyExport::new(address.clone(), key)?.public_key()?;
			Ok((NearSigner::Cold { name, address }, public))
		},
	}
}

fn print_key(public: &PublicKey) {
	log_print!("NEAR public key (use for AddKey / lookups):");
	log_print!("  {}", public.to_near_string().bright_cyan());
	log_print!("On-chain handle (what key lists show):");
	log_print!("  {}", public.handle_string().expect("ML-DSA-65 key has a handle").bright_cyan());
}

fn handle_show_key(
	wallet: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	let (_, public) = load_near_signer(wallet, password, password_file)?;
	print_key(&public);
	Ok(())
}

fn explorer_tx_url(network: &str, tx_hash: &str) -> Option<String> {
	match network {
		"testnet" => Some(format!("https://testnet.nearblocks.io/txns/{tx_hash}")),
		"mainnet" => Some(format!("https://nearblocks.io/txns/{tx_hash}")),
		_ => None,
	}
}

fn report_outcome(network: &str, outcome: &serde_json::Value) {
	if let Some(hash) = outcome.pointer("/transaction/hash").and_then(|h| h.as_str()) {
		log_print!("   Transaction: {}", hash.bright_cyan());
		if let Some(url) = explorer_tx_url(network, hash) {
			log_print!("   Explorer:    {url}");
		}
	}
}

#[allow(clippy::too_many_arguments)]
async fn handle_create_account(
	new_account: &str,
	wallet: &str,
	parent_credentials: &std::path::Path,
	deposit: &str,
	network: &str,
	rpc_url: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	validate_account_id(new_account)?;
	let (_, public) = load_near_signer(wallet, password, password_file)?;
	let parent = load_credentials(parent_credentials)?;

	if !new_account.ends_with(&format!(".{}", parent.account_id)) {
		return Err(QuantusError::Generic(format!(
			"'{new_account}' is not a sub-account of '{}' — NEAR only lets an account create \
			 accounts directly under its own name",
			parent.account_id
		)));
	}

	let deposit_yocto = crate::cli::send::parse_amount_with_decimals(deposit, NEAR_DECIMALS)?;
	let client = NearRpcClient::for_network(network, rpc_url)?;
	client.ensure_ml_dsa_support().await?;

	if client.account_exists(new_account).await? {
		return Err(QuantusError::Generic(format!("account '{new_account}' already exists")));
	}

	let parent_key = parent.public_key.to_near_string();
	let access_key = client.view_access_key(&parent.account_id, &parent_key).await?;

	let tx = Transaction {
		signer_id: parent.account_id.clone(),
		public_key: parent.public_key.clone(),
		nonce: access_key.nonce + 1,
		receiver_id: new_account.to_string(),
		block_hash: access_key.block_hash,
		actions: vec![
			Action::CreateAccount,
			Action::Transfer(TransferAction { deposit: deposit_yocto }),
			Action::AddKey(AddKeyAction {
				public_key: public.clone(),
				access_key: AccessKey::full_access(),
			}),
		],
	};

	log_print!("🌍 Creating {} on NEAR {network}", new_account.bright_cyan());
	log_print!(
		"   Parent:  {} (signs creation, keeps no key on the new account)",
		parent.account_id
	);
	log_print!(
		"   Deposit: {} NEAR",
		crate::cli::send::format_balance(deposit_yocto, NEAR_DECIMALS)
	);
	log_print!("   Sole key: {}", public.handle_string().expect("65 key").bright_cyan());

	let signed = sign_transaction_ed25519(tx, &parent.signing_key)?;
	let outcome = client.send_tx(&signed).await?;
	report_outcome(network, &outcome);

	// The parent chose the initial key list; prove from chain state that it
	// contains exactly our key.
	let keys = client.view_access_key_list(new_account).await?;
	let our_handle = public.handle_string().expect("65 key");
	let sole_key = keys.len() == 1 && keys[0].public_key == our_handle && keys[0].full_access;
	if !sole_key {
		let listed: Vec<&str> = keys.iter().map(|k| k.public_key.as_str()).collect();
		return Err(QuantusError::Generic(format!(
			"post-creation check failed: expected exactly one full-access key {our_handle}, chain \
			 lists {listed:?}"
		)));
	}

	log_success!(
		"✅ {new_account} exists and is solely controlled by wallet '{wallet}' — its only access \
		 key is {}",
		our_handle.bright_cyan()
	);
	log_print!("💡 Send from it with: quantus near send --wallet {wallet} --account {new_account} --to <recipient> --amount <NEAR>");
	Ok(())
}

async fn handle_keys(
	account: &str,
	wallet: Option<String>,
	network: &str,
	rpc_url: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	validate_account_id(account)?;
	let our_handle = match wallet {
		Some(wallet) => {
			let (_, public) = load_near_signer(&wallet, password, password_file)?;
			Some((wallet, public.handle_string().expect("65 key")))
		},
		None => None,
	};

	let client = NearRpcClient::for_network(network, rpc_url)?;
	let keys = client.view_access_key_list(account).await?;

	log_print!("🔑 {} access key(s) on {}:", keys.len(), account.bright_cyan());
	for key in &keys {
		let access = if key.full_access { "full-access" } else { "function-call" };
		let ours = match &our_handle {
			Some((wallet, handle)) if *handle == key.public_key =>
				format!("  ← wallet '{wallet}'").bright_green().to_string(),
			_ => String::new(),
		};
		log_print!("  {}  {access}{ours}", key.public_key);
	}
	Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_send(
	wallet: &str,
	account: &str,
	to: &str,
	amount: &str,
	network: &str,
	rpc_url: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	validate_account_id(account)?;
	validate_account_id(to)?;
	let (signer, public) = load_near_signer(wallet, password, password_file)?;
	let amount_yocto = crate::cli::send::parse_amount_with_decimals(amount, NEAR_DECIMALS)?;

	let client = NearRpcClient::for_network(network, rpc_url)?;
	client.ensure_ml_dsa_support().await?;

	// Nonce lookup by the full key also proves the key is on the account.
	let full_key = public.to_near_string();
	let access_key = client.view_access_key(account, &full_key).await?;
	log_verbose!("access key nonce: {}", access_key.nonce);

	let tx = Transaction {
		signer_id: account.to_string(),
		public_key: public,
		nonce: access_key.nonce + 1,
		receiver_id: to.to_string(),
		block_hash: access_key.block_hash,
		actions: vec![Action::Transfer(TransferAction { deposit: amount_yocto })],
	};

	log_print!(
		"💸 {} NEAR: {} → {} (signed with ML-DSA-65 wallet '{}')",
		crate::cli::send::format_balance(amount_yocto, NEAR_DECIMALS).bright_yellow(),
		account.bright_cyan(),
		to.bright_cyan(),
		wallet
	);

	let signed = signer.sign(tx, network).await?;
	let outcome = client.send_tx(&signed).await?;
	report_outcome(network, &outcome);
	log_success!("✅ Transfer finalized");
	Ok(())
}

const TGAS: u64 = 1_000_000_000_000;
const ADD_PROPOSAL_GAS: u64 = 100 * TGAS;
/// A threshold-meeting approval executes the proposal in the same call.
const ACT_PROPOSAL_GAS: u64 = 300 * TGAS;

fn vote_action(vote: &str) -> Result<&'static str> {
	match vote {
		"approve" => Ok("VoteApprove"),
		"reject" => Ok("VoteReject"),
		"remove" => Ok("VoteRemove"),
		other => Err(QuantusError::Generic(format!(
			"unknown vote '{other}' — use approve, reject, or remove"
		))),
	}
}

/// `add_proposal` args for a base-NEAR transfer (`token_id: ""`).
fn transfer_proposal_args(
	description: &str,
	receiver: &str,
	amount_yocto: u128,
) -> serde_json::Value {
	serde_json::json!({
		"proposal": {
			"description": description,
			"kind": {
				"Transfer": {
					"token_id": "",
					"receiver_id": receiver,
					"amount": amount_yocto.to_string(),
				}
			}
		}
	})
}

/// The stored kind of a proposal, required by `act_proposal`: the current
/// Sputnik contract re-checks it against the stored proposal
/// (`ERR_WRONG_KIND`) so a vote can't be replayed onto a swapped proposal.
fn proposal_kind(proposal: &serde_json::Value) -> Result<serde_json::Value> {
	match proposal.get("kind") {
		Some(kind) if !kind.is_null() => Ok(kind.clone()),
		_ => Err(QuantusError::Generic(
			"proposal has no kind field — cannot build a vote the DAO will accept".into(),
		)),
	}
}

/// The bond `add_proposal` must attach; the DAO rejects any other amount.
fn policy_proposal_bond(policy: &serde_json::Value) -> Result<u128> {
	policy
		.get("proposal_bond")
		.and_then(|v| v.as_str())
		.and_then(|s| s.parse().ok())
		.ok_or_else(|| {
			QuantusError::Generic(
				"DAO policy has no parseable proposal_bond — pass --bond explicitly".into(),
			)
		})
}

/// Sign a single function call on the DAO with the member account's
/// ML-DSA-65 key and submit it.
#[allow(clippy::too_many_arguments)]
async fn submit_dao_call(
	client: &NearRpcClient,
	signer: &NearSigner,
	public: PublicKey,
	account: &str,
	dao: &str,
	method_name: &str,
	args: serde_json::Value,
	gas: u64,
	deposit: u128,
	network: &str,
) -> Result<serde_json::Value> {
	let full_key = public.to_near_string();
	let access_key = client.view_access_key(account, &full_key).await?;
	log_verbose!("access key nonce: {}", access_key.nonce);

	let tx = Transaction {
		signer_id: account.to_string(),
		public_key: public,
		nonce: access_key.nonce + 1,
		receiver_id: dao.to_string(),
		block_hash: access_key.block_hash,
		actions: vec![Action::FunctionCall(FunctionCallAction {
			method_name: method_name.to_string(),
			args: args.to_string().into_bytes(),
			gas,
			deposit,
		})],
	};

	let signed = signer.sign(tx, network).await?;
	let outcome = client.send_tx(&signed).await?;
	report_outcome(network, &outcome);
	Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
async fn handle_dao_propose_transfer(
	dao: &str,
	account: &str,
	wallet: &str,
	receiver: &str,
	amount: &str,
	description: &str,
	bond: Option<String>,
	network: &str,
	rpc_url: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	validate_account_id(dao)?;
	validate_account_id(account)?;
	validate_account_id(receiver)?;
	let (signer, public) = load_near_signer(wallet, password, password_file)?;
	let amount_yocto = crate::cli::send::parse_amount_with_decimals(amount, NEAR_DECIMALS)?;

	let client = NearRpcClient::for_network(network, rpc_url)?;
	client.ensure_ml_dsa_support().await?;

	let bond_yocto = match bond {
		Some(bond) => crate::cli::send::parse_amount_with_decimals(&bond, NEAR_DECIMALS)?,
		None => {
			let policy =
				client.call_view_function(dao, "get_policy", &serde_json::json!({})).await?;
			policy_proposal_bond(&policy)?
		},
	};

	log_print!(
		"🏛️  Proposing on {}: transfer {} NEAR → {} (bond {} NEAR, member {}, ML-DSA-65 wallet \
		 '{wallet}')",
		dao.bright_cyan(),
		crate::cli::send::format_balance(amount_yocto, NEAR_DECIMALS).bright_yellow(),
		receiver.bright_cyan(),
		crate::cli::send::format_balance(bond_yocto, NEAR_DECIMALS),
		account.bright_cyan(),
	);

	let args = transfer_proposal_args(description, receiver, amount_yocto);
	let outcome = submit_dao_call(
		&client,
		&signer,
		public,
		account,
		dao,
		"add_proposal",
		args,
		ADD_PROPOSAL_GAS,
		bond_yocto,
		network,
	)
	.await?;

	match decode_success_value(&outcome).and_then(|v| v.as_u64()) {
		Some(id) => {
			log_success!("✅ Proposal {id} created on {dao}");
			log_print!(
				"💡 Members vote with: quantus near dao vote --dao {dao} --id {id} --vote approve \
				 --account <member> --wallet <wallet>"
			);
		},
		None => log_success!(
			"✅ Proposal created on {dao} (id not returned; check with quantus near dao proposal)"
		),
	}
	Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_dao_vote(
	dao: &str,
	account: &str,
	wallet: &str,
	id: u64,
	vote: &str,
	network: &str,
	rpc_url: Option<String>,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<()> {
	validate_account_id(dao)?;
	validate_account_id(account)?;
	let action = vote_action(vote)?;
	let (signer, public) = load_near_signer(wallet, password, password_file)?;

	let client = NearRpcClient::for_network(network, rpc_url)?;
	client.ensure_ml_dsa_support().await?;

	// act_proposal requires the stored kind and rejects mismatches, so read
	// the proposal first — this also shows the voter what they are signing.
	let proposal = client
		.call_view_function(dao, "get_proposal", &serde_json::json!({ "id": id }))
		.await?;
	print_proposal(id, &proposal);
	let kind = proposal_kind(&proposal)?;

	log_print!(
		"🗳️  Voting {} on proposal {id} of {} (member {}, ML-DSA-65 wallet '{wallet}')",
		action.bright_yellow(),
		dao.bright_cyan(),
		account.bright_cyan(),
	);

	let args = serde_json::json!({ "id": id, "action": action, "proposal": kind });
	submit_dao_call(
		&client,
		&signer,
		public,
		account,
		dao,
		"act_proposal",
		args,
		ACT_PROPOSAL_GAS,
		0,
		network,
	)
	.await?;
	log_success!("✅ Vote recorded");

	// Removed proposals disappear, so a failed follow-up view is not an error.
	match client
		.call_view_function(dao, "get_proposal", &serde_json::json!({ "id": id }))
		.await
	{
		Ok(proposal) => print_proposal(id, &proposal),
		Err(e) => log_verbose!("proposal state after vote: {e}"),
	}
	Ok(())
}

async fn handle_dao_proposal(
	dao: &str,
	id: u64,
	network: &str,
	rpc_url: Option<String>,
) -> Result<()> {
	validate_account_id(dao)?;
	let client = NearRpcClient::for_network(network, rpc_url)?;
	let proposal = client
		.call_view_function(dao, "get_proposal", &serde_json::json!({ "id": id }))
		.await?;
	print_proposal(id, &proposal);
	Ok(())
}

fn print_proposal(id: u64, proposal: &serde_json::Value) {
	let field = |key: &str| proposal.get(key).and_then(|v| v.as_str()).unwrap_or("?").to_string();
	log_print!("📋 Proposal {id}");
	log_print!("   Status:      {}", field("status").bright_yellow());
	log_print!("   Proposer:    {}", field("proposer"));
	log_print!("   Description: {}", field("description"));
	if let Some(kind) = proposal.get("kind") {
		log_print!("   Kind:        {kind}");
	}
	if let Some(votes) = proposal.get("votes").and_then(|v| v.as_object()) {
		log_print!("   Votes:");
		for (member, vote) in votes {
			log_print!("     {member}: {vote}");
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn vote_actions_map_to_sputnik_names() {
		assert_eq!(vote_action("approve").unwrap(), "VoteApprove");
		assert_eq!(vote_action("reject").unwrap(), "VoteReject");
		assert_eq!(vote_action("remove").unwrap(), "VoteRemove");
		assert!(vote_action("yes").is_err());
	}

	#[test]
	fn transfer_proposal_args_match_sputnik_schema() {
		let args = transfer_proposal_args("payroll", "bob.near", 1_500_000_000_000_000_000_000_000);
		assert_eq!(
			args,
			serde_json::json!({
				"proposal": {
					"description": "payroll",
					"kind": {
						"Transfer": {
							"token_id": "",
							"receiver_id": "bob.near",
							"amount": "1500000000000000000000000",
						}
					}
				}
			})
		);
	}

	#[test]
	fn vote_args_carry_the_stored_proposal_kind() {
		let stored = serde_json::json!({
			"status": "InProgress",
			"kind": { "Transfer": { "token_id": "", "receiver_id": "bob.near", "amount": "1" } },
		});
		let kind = proposal_kind(&stored).unwrap();
		let args = serde_json::json!({ "id": 7, "action": "VoteApprove", "proposal": kind });
		assert_eq!(args["proposal"]["Transfer"]["receiver_id"], "bob.near");

		assert!(proposal_kind(&serde_json::json!({ "status": "InProgress" })).is_err());
		assert!(proposal_kind(&serde_json::json!({ "kind": null })).is_err());
	}

	#[test]
	fn proposal_bond_comes_from_policy_as_yocto_string() {
		let policy = serde_json::json!({ "proposal_bond": "100000000000000000000000" });
		assert_eq!(policy_proposal_bond(&policy).unwrap(), 100_000_000_000_000_000_000_000);

		assert!(policy_proposal_bond(&serde_json::json!({})).is_err());
		assert!(policy_proposal_bond(&serde_json::json!({ "proposal_bond": 5 })).is_err());
	}
}
