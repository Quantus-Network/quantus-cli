//! Multisig wallet operations example
//!
//! This example demonstrates:
//! 1. Creating a multisig wallet
//! 2. Creating a proposal
//! 3. Approving proposals
//! 4. Querying multisig information
//! 5. Managing multisig lifecycle

use quantus_cli::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::common::ExecutionMode,
	error::Result,
	wallet::WalletManager,
};
use sp_core::crypto::Ss58Codec;

/// Example: Create and use a 2-of-3 multisig wallet
#[tokio::main]
async fn main() -> Result<()> {
	println!("🔐 Quantus Multisig Example");
	println!("================================\n");

	// 1. Setup: Connect to node and load wallets
	let node_url = "ws://127.0.0.1:9944";
	let quantus_client = QuantusClient::new(node_url).await?;
	let wallet_manager = WalletManager::new()?;

	println!("📡 Connected to node: {}", node_url);
	println!("");

	// 2. Create or load test wallets
	println!("👥 Setting up test wallets...");

	// For this example, we assume alice, bob, and charlie wallets exist
	// In real usage, create these first:
	// wallet_manager.create_wallet("alice", Some("password")).await?;
	// wallet_manager.create_wallet("bob", Some("password")).await?;
	// wallet_manager.create_wallet("charlie", Some("password")).await?;

	let alice_addr = wallet_manager.find_wallet_address("alice")?.expect("Alice wallet not found");
	let bob_addr = wallet_manager.find_wallet_address("bob")?.expect("Bob wallet not found");
	let charlie_addr = wallet_manager
		.find_wallet_address("charlie")?
		.expect("Charlie wallet not found");

	println!("   Alice: {}", alice_addr);
	println!("   Bob: {}", bob_addr);
	println!("   Charlie: {}", charlie_addr);
	println!("");

	// 3. Create multisig (2-of-3)
	println!("🔐 Creating 2-of-3 multisig...");

	let signers =
		vec![parse_address(&alice_addr)?, parse_address(&bob_addr)?, parse_address(&charlie_addr)?];
	let threshold = 2u32;

	let alice_keypair =
		quantus_cli::wallet::load_keypair_from_wallet("alice", Some("password".to_string()), None)?;

	let create_tx = quantus_subxt::api::tx().multisig().create_multisig(signers.clone(), threshold);

	let execution_mode = ExecutionMode { finalized: false, wait_for_transaction: true };

	let tx_hash = quantus_cli::cli::common::submit_transaction(
		&quantus_client,
		&alice_keypair,
		create_tx,
		None,
		execution_mode,
	)
	.await?;

	println!("✅ Multisig created! Tx hash: 0x{}", hex::encode(tx_hash));
	println!("");
	println!("💡 NOTE: Check the events to find the multisig address");
	println!("   The address is deterministically generated from signers + nonce");
	println!("");

	// 4. Example: Query multisig info
	println!("📋 To query multisig information:");
	println!("   quantus multisig info --multisig <multisig_address>");
	println!("");

	// 5. Example: Create a proposal
	println!("📝 To create a proposal:");
	println!("   # Simple transfer (recommended for transfers):");
	println!("   quantus multisig propose transfer \\");
	println!("     --address <multisig_address> \\");
	println!("     --to <recipient> \\");
	println!("     --amount 1000000000000 \\");
	println!("     --expiry 1000 \\");
	println!("     --from alice");
	println!("");
	println!("   # Custom transaction (full flexibility):");
	println!("   quantus multisig propose custom \\");
	println!("     --address <multisig_address> \\");
	println!("     --pallet Balances \\");
	println!("     --call transfer_allow_death \\");
	println!("     --args '[\"<recipient>\", \"1000000000000\"]' \\");
	println!("     --expiry 1000 \\");
	println!("     --from alice");
	println!("");

	// 6. Example: Approve a proposal
	println!("✅ To approve a proposal:");
	println!("   quantus multisig approve \\");
	println!("     --multisig <multisig_address> \\");
	println!("     --proposal-hash <hash> \\");
	println!("     --from bob");
	println!("");

	// 7. Example: List proposals
	println!("📋 To list all proposals:");
	println!("   quantus multisig list-proposals --multisig <multisig_address>");
	println!("");

	// 8. Example: Cleanup
	println!("🧹 To cleanup and recover deposits:");
	println!("   # Remove single proposal");
	println!("   quantus multisig remove-expired \\");
	println!("     --multisig <multisig_address> \\");
	println!("     --proposal-hash <hash> \\");
	println!("     --from alice");
	println!("");
	println!("   # Batch cleanup");
	println!("   quantus multisig claim-deposits \\");
	println!("     --multisig <multisig_address> \\");
	println!("     --from alice");
	println!("");

	// 9. Example: Dissolve multisig
	println!("🗑️  To dissolve multisig (requires no proposals, zero balance):");
	println!("   quantus multisig dissolve \\");
	println!("     --multisig <multisig_address> \\");
	println!("     --from alice");
	println!("");

	println!("✨ Multisig example complete!");
	println!("");
	println!("📚 For more information:");
	println!("   quantus multisig --help");
	println!("   quantus multisig <command> --help");

	Ok(())
}

/// Helper: Parse SS58 address to subxt AccountId32
fn parse_address(ss58: &str) -> Result<subxt::ext::subxt_core::utils::AccountId32> {
	use sp_core::crypto::AccountId32;

	let (account_id, _) = AccountId32::from_ss58check_with_version(ss58).map_err(|e| {
		quantus_cli::error::QuantusError::Generic(format!("Invalid address: {:?}", e))
	})?;

	let bytes: [u8; 32] = *account_id.as_ref();
	Ok(subxt::ext::subxt_core::utils::AccountId32::from(bytes))
}
