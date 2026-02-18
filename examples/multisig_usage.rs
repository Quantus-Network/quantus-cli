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
	println!();

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
	println!();

	// 3. Create multisig (2-of-3)
	println!("🔐 Creating 2-of-3 multisig...");

	let signers =
		vec![parse_address(&alice_addr)?, parse_address(&bob_addr)?, parse_address(&charlie_addr)?];
	let threshold = 2u32;
	let nonce = 0u64; // Default nonce. Use different values to create multiple multisigs

	let alice_keypair =
		quantus_cli::wallet::load_keypair_from_wallet("alice", Some("password".to_string()), None)?;

	let create_tx =
		quantus_subxt::api::tx()
			.multisig()
			.create_multisig(signers.clone(), threshold, nonce);

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
	println!();
	println!("💡 NOTE: Multisig addresses are deterministic (hash of signers + threshold + nonce)");
	println!("   Use 'quantus multisig predict-address' to calculate address before creating:");
	println!("   quantus multisig predict-address --signers <list> --threshold 2 --nonce 0");
	println!();

	// 4. Example: Query multisig info
	println!("📋 To query multisig information:");
	println!("   quantus multisig info --address <multisig_address>");
	println!();
	println!("   Or query specific proposal:");
	println!("   quantus multisig info --address <multisig_address> --proposal-id 0");
	println!();

	// 5. Example: Create a proposal
	println!("📝 To create a proposal:");
	println!("   # Simple transfer (recommended - human-readable amounts):");
	println!("   quantus multisig propose transfer \\");
	println!("     --address <multisig_address> \\");
	println!("     --to <recipient> \\");
	println!("     --amount 10 \\");
	println!("     --expiry 1000 \\");
	println!("     --from alice");
	println!();
	println!("   # Custom transaction (full flexibility):");
	println!("   quantus multisig propose custom \\");
	println!("     --address <multisig_address> \\");
	println!("     --pallet System \\");
	println!("     --call remark \\");
	println!("     --args '[\"Hello from multisig\"]' \\");
	println!("     --expiry 1000 \\");
	println!("     --from alice");
	println!();
	println!("   NOTE: Expiry is BLOCK NUMBER, not blocks from now!");
	println!("         Use a block number in the future (e.g., current + 1000)");
	println!();

	// 6. Example: Approve a proposal
	println!("✅ To approve a proposal (auto-executes at threshold):");
	println!("   quantus multisig approve \\");
	println!("     --address <multisig_address> \\");
	println!("     --proposal-id <id> \\");
	println!("     --from bob");
	println!();

	// 7. Example: List proposals
	println!("📋 To list all proposals:");
	println!("   quantus multisig list-proposals --address <multisig_address>");
	println!();

	// 8. Example: Cleanup (recover deposits from expired proposals)
	println!("🧹 To cleanup and recover deposits:");
	println!("   # Remove single expired proposal");
	println!("   quantus multisig remove-expired \\");
	println!("     --address <multisig_address> \\");
	println!("     --proposal-id <id> \\");
	println!("     --from alice");
	println!();
	println!("   # Batch cleanup all expired proposals");
	println!("   quantus multisig claim-deposits \\");
	println!("     --address <multisig_address> \\");
	println!("     --from alice");
	println!();

	// 9. Example: Dissolve multisig (requires threshold approvals)
	println!("🗑️  To dissolve multisig:");
	println!("   Requirements:");
	println!("   - No proposals (any status)");
	println!("   - Zero balance");
	println!("   - Threshold approvals");
	println!("   💡 INFO: Deposit is RETURNED to creator on successful dissolution");
	println!();
	println!("   # Each signer must approve:");
	println!("   quantus multisig dissolve --address <multisig_address> --from alice  # 1/2");
	println!(
		"   quantus multisig dissolve --address <multisig_address> --from bob    # 2/2 (dissolved)"
	);
	println!();
	println!("   # Check dissolution progress:");
	println!("   quantus multisig info --address <multisig_address>");
	println!();

	println!("✨ Multisig example complete!");
	println!();
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
