//! Service example showing how to use quantus-cli as a library in a web service
//!
//! This example demonstrates:
//! 1. Creating a service that manages multiple wallets
//! 2. Thread-safe wallet operations
//! 3. Async operations for web services
//! 4. Error handling and logging

use quantus_cli::{
	chain::client::QuantusClient,
	error::{QuantusError, Result},
	wallet::{QuantumKeyPair, WalletManager},
	AccountId32,
};
use serde::{Deserialize, Serialize};
use sp_core::crypto::Ss58Codec;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Wallet service that can be used in web applications
pub struct WalletService {
	wallet_manager: Arc<WalletManager>,
	client: Arc<RwLock<QuantusClient>>,
}

/// Response structure for API endpoints
#[derive(Serialize, Deserialize)]
pub struct WalletInfo {
	pub name: String,
	pub address: String,
	pub balance: u128,
	pub created_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransferRequest {
	pub from_wallet: String,
	pub to_address: String,
	pub amount: u128,
	pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TransferResponse {
	pub success: bool,
	pub transaction_hash: Option<String>,
	pub error: Option<String>,
}

impl WalletService {
	/// Create a new wallet service
	pub async fn new(node_url: &str) -> Result<Self> {
		let wallet_manager = Arc::new(WalletManager::new()?);
		let client = Arc::new(RwLock::new(QuantusClient::new(node_url).await?));

		Ok(Self { wallet_manager, client })
	}

	/// Create a new wallet (thread-safe)
	pub async fn create_wallet(&self, name: &str, password: &str) -> Result<WalletInfo> {
		let wallet_info = self.wallet_manager.create_wallet(name, Some(password)).await?;

		// Get balance
		let balance = self.get_wallet_balance(name, password).await?;

		Ok(WalletInfo {
			name: wallet_info.name,
			address: wallet_info.address,
			balance,
			created_at: wallet_info.created_at.to_rfc3339(),
		})
	}

	/// Get wallet information including balance
	pub async fn get_wallet_info(&self, name: &str, password: &str) -> Result<WalletInfo> {
		let wallet_data = self.wallet_manager.load_wallet(name, password)?;
		let balance = self.get_wallet_balance(name, password).await?;

		Ok(WalletInfo {
			name: wallet_data.name,
			address: wallet_data.keypair.to_account_id_ss58check(),
			balance,
			created_at: chrono::Utc::now().to_rfc3339(), // Could be stored in wallet data
		})
	}

	/// Get wallet balance
	pub async fn get_wallet_balance(&self, name: &str, password: &str) -> Result<u128> {
		let wallet_data = self.wallet_manager.load_wallet(name, password)?;
		let account_id = wallet_data.keypair.to_account_id_32();

		let client = self.client.read().await;
		self.get_account_balance(&client, &account_id).await
	}

	/// Transfer tokens between wallets
	pub async fn transfer_tokens(&self, request: TransferRequest) -> TransferResponse {
		match self.perform_transfer(&request).await {
			Ok(tx_hash) => TransferResponse {
				success: true,
				transaction_hash: Some(format!("{tx_hash:?}")),
				error: None,
			},
			Err(e) => TransferResponse {
				success: false,
				transaction_hash: None,
				error: Some(e.to_string()),
			},
		}
	}

	/// List all wallets (without passwords)
	pub fn list_wallets(&self) -> Result<Vec<String>> {
		let wallets = self.wallet_manager.list_wallets()?;
		Ok(wallets.iter().map(|w| w.name.clone()).collect())
	}

	/// Import wallet from mnemonic
	pub async fn import_wallet(
		&self,
		name: &str,
		mnemonic: &str,
		password: &str,
	) -> Result<WalletInfo> {
		let wallet_info = self.wallet_manager.import_wallet(name, mnemonic, Some(password)).await?;

		let balance = self.get_wallet_balance(name, password).await?;

		Ok(WalletInfo {
			name: wallet_info.name,
			address: wallet_info.address,
			balance,
			created_at: wallet_info.created_at.to_rfc3339(),
		})
	}

	/// Get system information
	pub async fn get_system_info(&self) -> Result<SystemInfo> {
		let client = self.client.read().await;
		let runtime_version = client.get_runtime_version().await?;
		let latest_block = client.get_latest_block().await?;
		let genesis_hash = client.get_genesis_hash().await?;

		Ok(SystemInfo {
			runtime_spec_version: runtime_version.0,
			runtime_transaction_version: runtime_version.1,
			latest_block: format!("{latest_block:?}"),
			genesis_hash: format!("{genesis_hash:?}"),
		})
	}

	/// Private method to perform transfer
	async fn perform_transfer(&self, request: &TransferRequest) -> Result<subxt::utils::H256> {
		// Load sender wallet
		let wallet_data =
			self.wallet_manager.load_wallet(&request.from_wallet, &request.password)?;
		let keypair = wallet_data.keypair;

		// Parse recipient address
		let to_account_id = AccountId32::from_ss58check(&request.to_address)
			.map_err(|e| QuantusError::Generic(format!("Invalid recipient address: {e}")))?;

		// Perform the transfer
		let client = self.client.read().await;
		self.transfer_tokens_internal(&client, &keypair, &to_account_id, request.amount)
			.await
	}

	/// Private method to get account balance
	async fn get_account_balance(
		&self,
		client: &QuantusClient,
		account_id: &AccountId32,
	) -> Result<u128> {
		use quantus_cli::chain::quantus_subxt::api;

		// Convert to subxt account ID
		let account_bytes: [u8; 32] = *account_id.as_ref();
		let subxt_account_id = subxt::utils::AccountId32::from(account_bytes);

		// Query balance from storage
		let storage_addr = api::storage().system().account(subxt_account_id);
		let latest_block_hash = client.get_latest_block().await?;
		let storage_at = client.client().storage().at(latest_block_hash);
		let account_info = storage_at.fetch_or_default(&storage_addr).await?;

		Ok(account_info.data.free)
	}

	/// Private method to transfer tokens
	async fn transfer_tokens_internal(
		&self,
		client: &QuantusClient,
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
		let tx_hash = client
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

#[derive(Serialize, Deserialize)]
pub struct SystemInfo {
	pub runtime_spec_version: u32,
	pub runtime_transaction_version: u32,
	pub latest_block: String,
	pub genesis_hash: String,
}

/// Example of using the service in a web application
#[tokio::main]
async fn main() -> Result<()> {
	println!("🔮 Quantus CLI Library - Service Example");

	// Create service instance
	let service = WalletService::new("ws://127.0.0.1:9944").await?;

	// Get system information
	let system_info = service.get_system_info().await?;
	println!("🔧 System Info:");
	println!("   Runtime spec version: {}", system_info.runtime_spec_version);
	println!("   Runtime transaction version: {}", system_info.runtime_transaction_version);
	println!("   Latest block: {}", system_info.latest_block);
	println!();

	// Create a wallet
	let wallet_info = service.create_wallet("service_wallet", "service_password").await?;
	println!("✅ Created wallet:");
	println!("   Name: {}", wallet_info.name);
	println!("   Address: {}", wallet_info.address);
	println!("   Balance: {} DEV", wallet_info.balance);
	println!();

	// List all wallets
	let wallets = service.list_wallets()?;
	println!("📋 Available wallets: {wallets:?}");
	println!();

	// Example transfer (commented out to avoid actual transfer)
	// let transfer_request = TransferRequest {
	//     from_wallet: "service_wallet".to_string(),
	//     to_address: "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2".to_string(),
	//     amount: 1000000000000, // 1 DEV
	//     password: "service_password".to_string(),
	// };
	//
	// let transfer_response = service.transfer_tokens(transfer_request).await;
	// println!("Transfer result: {:?}", transfer_response);

	Ok(())
}

/// Example of error handling in a service
#[allow(dead_code)]
async fn demonstrate_service_error_handling() -> Result<()> {
	let service = WalletService::new("ws://127.0.0.1:9944").await?;

	// Try to create wallet with invalid name
	match service.create_wallet("", "password").await {
		Ok(wallet) => println!("Created wallet: {}", wallet.name),
		Err(e) => println!("❌ Failed to create wallet: {e}"),
	}

	// Try to get balance of non-existent wallet
	match service.get_wallet_balance("non_existent", "password").await {
		Ok(balance) => println!("Balance: {balance}"),
		Err(e) => println!("❌ Failed to get balance: {e}"),
	}

	// Try invalid transfer
	let invalid_transfer = TransferRequest {
		from_wallet: "non_existent".to_string(),
		to_address: "invalid_address".to_string(),
		amount: 1000,
		password: "wrong_password".to_string(),
	};

	let result = service.transfer_tokens(invalid_transfer).await;
	println!("Transfer result: {result:?}");

	Ok(())
}

/// Example of concurrent operations
#[allow(dead_code)]
async fn demonstrate_concurrent_operations() -> Result<()> {
	let service: Arc<WalletService> = Arc::new(WalletService::new("ws://127.0.0.1:9944").await?);

	// Create multiple wallets concurrently
	let mut handles = Vec::new();

	for i in 0..5 {
		let service_clone = service.clone();
		let handle = tokio::spawn(async move {
			let wallet_name = format!("concurrent_wallet_{i}");
			match service_clone.create_wallet(&wallet_name, "concurrent_password").await {
				Ok(wallet) => {
					println!("✅ Created wallet: {}", wallet.name);
					Ok(wallet)
				},
				Err(e) => {
					println!("❌ Failed to create wallet {wallet_name}: {e}");
					Err(e)
				},
			}
		});
		handles.push(handle);
	}

	// Wait for all operations to complete
	for handle in handles {
		let _ = handle.await;
	}

	// List all wallets
	let wallets = service.list_wallets()?;
	println!("📋 Total wallets: {}", wallets.len());

	Ok(())
}
