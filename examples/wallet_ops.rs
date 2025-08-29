//! Advanced wallet operations example
//!
//! This example demonstrates:
//! 1. Creating a wallet manager
//! 2. Creating wallets with different methods
//! 3. Loading wallets for transactions
//! 4. Performing blockchain operations
//! 5. Error handling

use quantus_cli::{
	chain::client::QuantusClient,
	error::{QuantusError, Result},
	wallet::{QuantumKeyPair, WalletManager},
	AccountId32,
};
use sp_core::crypto::Ss58Codec;

/// Main application struct that manages wallets and blockchain operations
pub struct QuantusApp {
	wallet_manager: WalletManager,
	client: QuantusClient,
}

impl QuantusApp {
	/// Create a new Quantus application instance
	pub async fn new(node_url: &str) -> Result<Self> {
		let wallet_manager = WalletManager::new()?;
		let client = QuantusClient::new(node_url).await?;

		Ok(Self { wallet_manager, client })
	}

	/// Create a new wallet with a password
	pub async fn create_wallet(&self, name: &str, password: &str) -> Result<String> {
		let wallet_info = self.wallet_manager.create_wallet(name, Some(password)).await?;

		println!("✅ Created wallet: {}", wallet_info.name);
		println!("📍 Address: {}", wallet_info.address);

		Ok(wallet_info.address)
	}

	/// Import a wallet from mnemonic phrase
	pub async fn import_wallet(
		&self,
		name: &str,
		mnemonic: &str,
		password: &str,
	) -> Result<String> {
		let wallet_info = self.wallet_manager.import_wallet(name, mnemonic, Some(password)).await?;

		println!("✅ Imported wallet: {}", wallet_info.name);
		println!("📍 Address: {}", wallet_info.address);

		Ok(wallet_info.address)
	}

	/// Get wallet balance
	pub async fn get_balance(&self, wallet_name: &str, password: &str) -> Result<u128> {
		let wallet_data = self.wallet_manager.load_wallet(wallet_name, password)?;
		let account_id = wallet_data.keypair.to_account_id_32();

		self.get_account_balance(&account_id).await
	}

	/// Send tokens from one wallet to another
	pub async fn send_tokens(
		&self,
		from_wallet: &str,
		from_password: &str,
		to_address: &str,
		amount: u128,
	) -> Result<String> {
		// Load sender wallet
		let wallet_data = self.wallet_manager.load_wallet(from_wallet, from_password)?;
		let keypair = wallet_data.keypair;

		// Parse recipient address
		let to_account_id = AccountId32::from_ss58check(to_address)
			.map_err(|e| QuantusError::Generic(format!("Invalid recipient address: {e}")))?;

		// Perform the transfer
		let tx_hash = self.transfer_tokens(&keypair, &to_account_id, amount).await?;

		println!("✅ Transfer successful!");
		println!("🔗 Transaction hash: {tx_hash:?}");

		Ok(format!("{tx_hash:?}"))
	}

	/// List all available wallets
	pub fn list_wallets(&self) -> Result<Vec<String>> {
		let wallets = self.wallet_manager.list_wallets()?;
		let wallet_names: Vec<String> = wallets.iter().map(|w| w.name.clone()).collect();

		println!("📋 Available wallets:");
		for (i, wallet) in wallets.iter().enumerate() {
			println!("{}. {} - {}", i + 1, wallet.name, wallet.address);
		}

		Ok(wallet_names)
	}

	/// Get system information
	pub async fn get_system_info(&self) -> Result<()> {
		let runtime_version = self.client.get_runtime_version().await?;
		let latest_block = self.client.get_latest_block().await?;
		let genesis_hash = self.client.get_genesis_hash().await?;

		println!("🔧 System Information:");
		println!("   Runtime version: spec={}, tx={}", runtime_version.0, runtime_version.1);
		println!("   Latest block: {latest_block:?}");
		println!("   Genesis hash: {genesis_hash:?}");

		Ok(())
	}

	/// Private method to get account balance
	async fn get_account_balance(&self, account_id: &AccountId32) -> Result<u128> {
		use quantus_cli::chain::quantus_subxt::api;

		// Convert to subxt account ID
		let account_bytes: [u8; 32] = *account_id.as_ref();
		let subxt_account_id = subxt::utils::AccountId32::from(account_bytes);

		// Query balance from storage
		let storage_addr = api::storage().system().account(subxt_account_id);
		let latest_block_hash = self.client.get_latest_block().await?;
		let storage_at = self.client.client().storage().at(latest_block_hash);
		let account_info = storage_at.fetch_or_default(&storage_addr).await?;

		Ok(account_info.data.free)
	}

	/// Private method to transfer tokens
	async fn transfer_tokens(
		&self,
		from_keypair: &QuantumKeyPair,
		to_account_id: &AccountId32,
		amount: u128,
	) -> Result<subxt::utils::H256> {
		use quantus_cli::chain::quantus_subxt::api;

		// Convert recipient to subxt format
		let to_account_bytes: [u8; 32] = *to_account_id.as_ref();
		let to_subxt_account_id = subxt::utils::AccountId32::from(to_account_bytes);

		// Create transfer call
		let transfer_call =
			api::tx().balances().transfer_allow_death(to_subxt_account_id.into(), amount);

		// Convert QuantumKeyPair to DilithiumPair for signing
		let dilithium_pair = from_keypair.to_subxt_signer()?;

		// Submit transaction
		let tx_hash = self
			.client
			.client()
			.tx()
			.sign_and_submit_then_watch_default(&transfer_call, &dilithium_pair)
			.await?
			.wait_for_finalized_success()
			.await?
			.extrinsic_hash();

		Ok(tx_hash)
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	println!("🔮 Quantus CLI Library - Advanced Wallet Operations");

	// Create application instance
	let app = QuantusApp::new("ws://127.0.0.1:9944").await?;

	// Get system information
	app.get_system_info().await?;
	println!();

	// List existing wallets
	let existing_wallets = app.list_wallets()?;
	println!();

	// Create a new wallet if none exist
	if existing_wallets.is_empty() {
		println!("📝 Creating a new wallet...");
		let address = app.create_wallet("my_wallet", "secure_password").await?;
		println!("✅ Wallet created with address: {address}");
	} else {
		println!("📋 Using existing wallet: {}", existing_wallets[0]);

		// Get balance of first wallet
		let balance = app.get_balance(&existing_wallets[0], "").await?;
		println!("💰 Balance: {balance} DEV");

		// Example: Send tokens to another address (uncomment to test)
		// let tx_hash = app.send_tokens(
		//     &existing_wallets[0],
		//     "",
		//     "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2", // crystal_bob
		//     1000000000000, // 1 DEV
		// ).await?;
		// println!("✅ Transfer completed: {}", tx_hash);
	}

	Ok(())
}

/// Example of error handling
#[allow(dead_code)]
async fn demonstrate_error_handling() -> Result<()> {
	let app = QuantusApp::new("ws://127.0.0.1:9944").await?;

	// Try to get balance of non-existent wallet
	match app.get_balance("non_existent_wallet", "password").await {
		Ok(balance) => println!("Balance: {balance}"),
		Err(QuantusError::Wallet(quantus_cli::error::WalletError::NotFound)) => {
			println!("❌ Wallet not found");
		},
		Err(e) => {
			println!("❌ Other error: {e}");
		},
	}

	// Try to send tokens with invalid address
	match app.send_tokens("my_wallet", "password", "invalid_address", 1000).await {
		Ok(tx_hash) => println!("Transfer successful: {tx_hash}"),
		Err(QuantusError::Generic(msg)) => {
			println!("❌ Invalid address: {msg}");
		},
		Err(e) => {
			println!("❌ Other error: {e}");
		},
	}

	Ok(())
}

/// Example of batch operations
#[allow(dead_code)]
async fn demonstrate_batch_operations() -> Result<()> {
	let app = QuantusApp::new("ws://127.0.0.1:9944").await?;

	// Create multiple wallets
	let wallet_names = ["wallet_1", "wallet_2", "wallet_3"];
	let mut addresses = Vec::new();

	for name in &wallet_names {
		match app.create_wallet(name, "batch_password").await {
			Ok(address) => {
				addresses.push(address);
				println!("✅ Created {name}");
			},
			Err(QuantusError::Wallet(quantus_cli::error::WalletError::AlreadyExists)) => {
				println!("⚠️  Wallet {name} already exists");
			},
			Err(e) => {
				println!("❌ Failed to create {name}: {e}");
			},
		}
	}

	// Get balances for all wallets
	for name in wallet_names.iter() {
		match app.get_balance(name, "batch_password").await {
			Ok(balance) => println!("💰 {name} balance: {balance} DEV"),
			Err(e) => println!("❌ Failed to get balance for {name}: {e}"),
		}
	}

	Ok(())
}
