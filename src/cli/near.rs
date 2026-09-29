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
//!
//! ML-DSA-87 wallets are rejected: NEAR defined ML-DSA-65 only.

use crate::{
	error::{QuantusError, Result},
	log_print, log_success, log_verbose,
	near::{
		protocol::{
			validate_account_id, AccessKey, Action, AddKeyAction, PublicKey, Transaction,
			TransferAction, NEAR_DECIMALS,
		},
		rpc::NearRpcClient,
		sign::{load_credentials, sign_transaction_ed25519, sign_transaction_ml_dsa_65},
	},
	wallet::QuantumKeyPair,
};
use clap::Subcommand;
use colored::Colorize;
use std::path::PathBuf;

/// NEAR subcommands
#[derive(Subcommand, Debug)]
pub enum NearCommands {
	/// Show the wallet's ML-DSA-65 key in NEAR text forms
	ShowKey {
		/// Quantus wallet (must be ML-DSA-65)
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
	}
}

/// Load a wallet and its key as a NEAR public key, refusing non-65 schemes.
fn load_ml_dsa_65_wallet(
	wallet: &str,
	password: Option<String>,
	password_file: Option<String>,
) -> Result<(QuantumKeyPair, PublicKey)> {
	let keypair = crate::wallet::load_keypair_from_wallet(wallet, password, password_file)?;
	if keypair.scheme != crate::wallet::DilithiumScheme::MlDsa65 {
		return Err(QuantusError::Generic(format!(
			"wallet '{wallet}' is {:?}; NEAR supports ML-DSA-65 only — create one with `quantus \
			 wallet create --scheme ml-dsa-65`",
			keypair.scheme
		)));
	}
	let public = PublicKey::from_ml_dsa_65_bytes(&keypair.public_key)?;
	Ok((keypair, public))
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
	let (_, public) = load_ml_dsa_65_wallet(wallet, password, password_file)?;
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
	let (_, public) = load_ml_dsa_65_wallet(wallet, password, password_file)?;
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
			let (_, public) = load_ml_dsa_65_wallet(&wallet, password, password_file)?;
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
	let (keypair, public) = load_ml_dsa_65_wallet(wallet, password, password_file)?;
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

	let pair = keypair.to_dilithium65_pair()?;
	let signed = sign_transaction_ml_dsa_65(tx, &pair)?;
	let outcome = client.send_tx(&signed).await?;
	report_outcome(network, &outcome);
	log_success!("✅ Transfer finalized");
	Ok(())
}
