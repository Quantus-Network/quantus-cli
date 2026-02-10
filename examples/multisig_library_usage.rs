//! Multisig library usage example
//!
//! This example demonstrates using quantus-cli as a library for multisig operations

use quantus_cli::{
	approve_dissolve_multisig, approve_proposal, create_multisig, get_multisig_info,
	get_proposal_info, list_proposals, parse_multisig_amount, predict_multisig_address,
	propose_transfer,
	wallet::{load_keypair_from_wallet, WalletManager},
	QuantusClient, Result,
};
use sp_core::crypto::Ss58Codec;

#[tokio::main]
async fn main() -> Result<()> {
	println!("🔐 Quantus Multisig Library Usage Example");
	println!("==========================================\n");

	// 1. Setup: Connect to node
	let node_url = "ws://127.0.0.1:9944";
	let quantus_client = QuantusClient::new(node_url).await?;
	println!("📡 Connected to node: {}", node_url);
	println!();

	// 2. Load wallet manager and keypairs
	let wallet_manager = WalletManager::new()?;

	// Ensure test wallets exist
	println!("👥 Loading test wallets...");
	let alice_keypair = load_keypair_from_wallet("crystal_alice", None, None)?;
	let bob_keypair = load_keypair_from_wallet("crystal_bob", None, None)?;
	let _charlie_keypair = load_keypair_from_wallet("crystal_charlie", None, None)?;

	// Get addresses
	let alice_addr = wallet_manager
		.find_wallet_address("crystal_alice")?
		.expect("Alice wallet not found");
	let bob_addr = wallet_manager
		.find_wallet_address("crystal_bob")?
		.expect("Bob wallet not found");
	let charlie_addr = wallet_manager
		.find_wallet_address("crystal_charlie")?
		.expect("Charlie wallet not found");

	println!("   Alice: {}", alice_addr);
	println!("   Bob: {}", bob_addr);
	println!("   Charlie: {}", charlie_addr);
	println!();

	// 3. Convert addresses to AccountId32
	let alice_account = parse_address(&alice_addr)?;
	let bob_account = parse_address(&bob_addr)?;
	let charlie_account = parse_address(&charlie_addr)?;

	// 4. Create multisig (2-of-3)
	println!("🔐 Creating 2-of-3 multisig...");
	let signers = vec![alice_account.clone(), bob_account.clone(), charlie_account.clone()];
	let threshold = 2;
	let nonce = 0; // Use different nonce to create multiple multisigs with same signers

	// Predict address before creating
	let predicted_address = predict_multisig_address(signers.clone(), threshold, nonce);
	println!("📍 Predicted address: {}", predicted_address);

	let (tx_hash, multisig_address) =
		create_multisig(&quantus_client, &alice_keypair, signers, threshold, nonce, true).await?;

	println!("✅ Multisig created!");
	println!("   Tx hash: 0x{}", hex::encode(tx_hash));
	if let Some(addr) = &multisig_address {
		println!("   Address: {}", addr);
	}
	println!();

	// 5. Get multisig info
	if let Some(addr) = &multisig_address {
		let multisig_account = parse_address(addr)?;

		println!("📋 Querying multisig info...");
		if let Some(info) = get_multisig_info(&quantus_client, multisig_account.clone()).await? {
			println!("   Address: {}", info.address);
			println!("   Balance: {} (raw units)", info.balance);
			println!("   Threshold: {}", info.threshold);
			println!("   Signers: {}", info.signers.len());
			for (i, signer) in info.signers.iter().enumerate() {
				println!("     {}. {}", i + 1, signer);
			}
			println!("   Active Proposals: {}", info.active_proposals);
			println!();
		}

		// 6. Parse amount using library function
		println!("💰 Parsing amounts...");
		let amount_1 = parse_multisig_amount("10")?; // 10 QUAN
		let amount_2 = parse_multisig_amount("10.5")?; // 10.5 QUAN
		let amount_3 = parse_multisig_amount("0.001")?; // 0.001 QUAN

		println!("   10 QUAN = {} (raw)", amount_1);
		println!("   10.5 QUAN = {} (raw)", amount_2);
		println!("   0.001 QUAN = {} (raw)", amount_3);
		println!();

		// 7. Create a proposal (transfer 10 QUAN to Bob)
		println!("📝 Creating transfer proposal...");
		let expiry = 1000; // Block number
		let amount = parse_multisig_amount("10")?;

		let propose_tx_hash = propose_transfer(
			&quantus_client,
			&alice_keypair,
			multisig_account.clone(),
			bob_account.clone(),
			amount,
			expiry,
		)
		.await?;

		println!("✅ Proposal submitted!");
		println!("   Tx hash: 0x{}", hex::encode(propose_tx_hash));
		println!("   Check events for proposal ID");
		println!();

		// 8. List all proposals
		println!("📋 Listing all proposals...");
		let proposals = list_proposals(&quantus_client, multisig_account.clone()).await?;
		println!("   Found {} proposal(s)", proposals.len());

		for proposal in &proposals {
			println!();
			println!("   Proposal #{}:", proposal.id);
			println!("     Proposer: {}", proposal.proposer);
			println!("     Expiry: block {}", proposal.expiry);
			println!("     Status: {:?}", proposal.status);
			println!("     Approvals: {}", proposal.approvals.len());
			println!("     Deposit: {} (raw)", proposal.deposit);
		}
		println!();

		// 9. Get specific proposal info
		if !proposals.is_empty() {
			let proposal_id = proposals[0].id;
			println!("🔍 Querying proposal #{}...", proposal_id);

			if let Some(proposal) =
				get_proposal_info(&quantus_client, multisig_account.clone(), proposal_id).await?
			{
				println!("   Proposer: {}", proposal.proposer);
				println!("   Call data size: {} bytes", proposal.call_data.len());
				println!("   Expiry: block {}", proposal.expiry);
				println!("   Approvals: {}", proposal.approvals.len());
			}
			println!();

			// 10. Approve proposal (as Bob)
			println!("✅ Approving proposal #{}...", proposal_id);
			let approve_tx_hash = approve_proposal(
				&quantus_client,
				&bob_keypair,
				multisig_account.clone(),
				proposal_id,
			)
			.await?;

			println!("✅ Approval submitted!");
			println!("   Tx hash: 0x{}", hex::encode(approve_tx_hash));
			println!("   (Will auto-execute at threshold)");
			println!();
		}
	}

	println!("✨ Example complete!");
	println!();
	println!("📚 Available library functions:");
	println!("   - predict_multisig_address() - Calculate address before creating");
	println!("   - create_multisig() - Create with nonce for deterministic addresses");
	println!("   - propose_transfer()");
	println!("   - propose_custom()");
	println!("   - approve_proposal()");
	println!("   - cancel_proposal()");
	println!("   - get_multisig_info()");
	println!("   - get_proposal_info()");
	println!("   - list_proposals()");
	println!("   - approve_dissolve_multisig() - Requires threshold approvals");
	println!("   - parse_multisig_amount()");
	println!();
	println!("💡 Note: Multisig deposits are RETURNED to creator upon dissolution");

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
