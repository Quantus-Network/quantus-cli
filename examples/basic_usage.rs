//! Example of using quantus-cli as a library
//!
//! This example shows how to:
//! 1. Create and manage wallets programmatically
//! 2. Connect to a Quantus node
//! 3. Perform transactions using the library API
//! 4. Query blockchain data

use quantus_cli::{
	chain::client::QuantusClient,
	error::Result,
	wallet::{QuantumKeyPair, WalletManager},
	AccountId32,
};
use sp_core::crypto::Ss58Codec;

#[tokio::main]
async fn main() -> Result<()> {
	println!("🔮 Quantus CLI Library Usage Example");

	// 1. Create a wallet manager
	let wallet_manager = WalletManager::new()?;

	// 2. Create a new wallet programmatically
	let wallet_info = wallet_manager
		.create_wallet("lib_example_wallet", Some("example_password"))
		.await?;

	println!("✅ Created wallet: {}", wallet_info.name);
	println!("📍 Address: {}", wallet_info.address);
	println!("🔑 Key type: {}", wallet_info.key_type);

	// 3. Connect to a Quantus node
	let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
	println!("🔗 Connected to Quantus node");

	// 4. Load the wallet for transactions
	let wallet_data = wallet_manager.load_wallet("lib_example_wallet", "example_password")?;
	let keypair = wallet_data.keypair;

	// 5. Get account balance
	let account_id = keypair.to_account_id_32();
	let balance = get_account_balance(&client, &account_id).await?;
	println!("💰 Balance: {balance} DEV");

	// 6. Example: Send tokens (if you have another wallet)
	// This would require another wallet with funds
	// send_tokens(&client, &keypair, "recipient_address", 1000000000000).await?;

	// 7. Query system information
	let runtime_version = client.get_runtime_version().await?;
	println!("🔧 Runtime version: spec={}, tx={}", runtime_version.0, runtime_version.1);

	// 8. Get latest block
	let latest_block = client.get_latest_block().await?;
	println!("📦 Latest block: {latest_block:?}");

	Ok(())
}

/// Get account balance using the client
async fn get_account_balance(client: &QuantusClient, account_id: &AccountId32) -> Result<u128> {
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

/// Send tokens to another account
#[allow(dead_code)]
async fn send_tokens(
	client: &QuantusClient,
	from_keypair: &QuantumKeyPair,
	to_address: &str,
	amount: u128,
) -> Result<subxt::utils::H256> {
	use quantus_cli::chain::quantus_subxt::api;

	// Parse recipient address
	let to_account_id = AccountId32::from_ss58check(to_address)
		.map_err(|e| quantus_cli::error::QuantusError::Generic(format!("Invalid address: {e}")))?;
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

/// Example of creating a wallet from mnemonic
#[allow(dead_code)]
async fn create_wallet_from_mnemonic() -> Result<()> {
	let wallet_manager = WalletManager::new()?;

	// Example mnemonic (24 words)
	let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

	let wallet_info = wallet_manager
		.import_wallet("imported_wallet", mnemonic, Some("import_password"))
		.await?;

	println!("✅ Imported wallet: {}", wallet_info.name);
	println!("📍 Address: {}", wallet_info.address);

	Ok(())
}

/// Example of listing all wallets
#[allow(dead_code)]
async fn list_all_wallets() -> Result<()> {
	let wallet_manager = WalletManager::new()?;
	let wallets = wallet_manager.list_wallets()?;

	println!("📋 Found {} wallet(s):", wallets.len());
	for (i, wallet) in wallets.iter().enumerate() {
		println!("{}. {} - {}", i + 1, wallet.name, wallet.address);
	}

	Ok(())
}

/// Example of using developer/test wallets
#[allow(dead_code)]
async fn create_developer_wallet() -> Result<()> {
	let wallet_manager = WalletManager::new()?;

	// Create crystal_alice test wallet
	let wallet_info = wallet_manager.create_developer_wallet("crystal_alice").await?;

	println!("✅ Created developer wallet: {}", wallet_info.name);
	println!("📍 Address: {}", wallet_info.address);

	Ok(())
}
