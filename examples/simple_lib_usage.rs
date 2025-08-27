//! Simple example of using quantus-cli as a library
//!
//! This example shows basic usage without complex transactions

use quantus_cli::{chain::client::QuantusClient, error::Result, wallet::WalletManager};

#[tokio::main]
async fn main() -> Result<()> {
	println!("🔮 Quantus CLI Library - Simple Usage Example");

	// 1. Create a wallet manager
	let wallet_manager = WalletManager::new()?;

	// 2. List existing wallets
	let wallets = wallet_manager.list_wallets()?;
	println!("📋 Found {} wallet(s):", wallets.len());
	for wallet in &wallets {
		println!("  - {}: {}", wallet.name, wallet.address);
	}

	// 3. Connect to a Quantus node
	let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
	println!("🔗 Connected to Quantus node");

	// 4. Get system information
	let runtime_version = client.get_runtime_version().await?;
	println!("🔧 Runtime version: spec={}, tx={}", runtime_version.0, runtime_version.1);

	let latest_block = client.get_latest_block().await?;
	println!("📦 Latest block: {:?}", latest_block);

	let genesis_hash = client.get_genesis_hash().await?;
	println!("🧬 Genesis hash: {:?}", genesis_hash);

	// 5. Create a new wallet if none exist
	if wallets.is_empty() {
		println!("📝 Creating a new wallet...");
		let wallet_info =
			wallet_manager.create_wallet("example_wallet", Some("example_password")).await?;

		println!("✅ Created wallet:");
		println!("   Name: {}", wallet_info.name);
		println!("   Address: {}", wallet_info.address);
		println!("   Key type: {}", wallet_info.key_type);
	}

	println!("✅ Example completed successfully!");

	Ok(())
}
