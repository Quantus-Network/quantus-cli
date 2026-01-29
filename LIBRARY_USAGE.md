# Quantus CLI Library Usage

This document explains how to use `quantus-cli` as a library in your Rust applications.

## Adding to Cargo.toml

```toml
[dependencies]
quantus-cli = { path = "." }  # For local development
# or
quantus-cli = "0.1.0"  # When published to crates.io
```

## Basic Usage

### 1. Creating a Wallet Manager

```rust
use quantus_cli::wallet::WalletManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_manager = WalletManager::new()?;
    
    // Create a new wallet
    let wallet_info = wallet_manager
        .create_wallet("my_wallet", Some("secure_password"))
        .await?;
    
    println!("Created wallet: {}", wallet_info.name);
    println!("Address: {}", wallet_info.address);
    
    Ok(())
}
```

### 2. Connecting to a Quantus Node

```rust
use quantus_cli::chain::client::QuantusClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    
    // Get system information
    let runtime_version = client.get_runtime_version().await?;
    println!("Runtime version: {:?}", runtime_version);
    
    Ok(())
}
```

### 3. Loading a Wallet for Transactions

```rust
use quantus_cli::{
    wallet::{WalletManager, QuantumKeyPair},
    chain::client::QuantusClient,
};

async fn load_wallet_for_transactions() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_manager = WalletManager::new()?;
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    
    // Load wallet data (includes private key)
    let wallet_data = wallet_manager.load_wallet("my_wallet", "secure_password")?;
    let keypair = wallet_data.keypair;
    
    // Now you can use the keypair for transactions
    let account_id = keypair.to_account_id_32();
    println!("Account ID: {:?}", account_id);
    
    Ok(())
}
```

## Advanced Usage

### Wallet Operations

#### Creating Wallets

```rust
use quantus_cli::wallet::WalletManager;

async fn create_wallets() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_manager = WalletManager::new()?;
    
    // Create a regular wallet
    let wallet_info = wallet_manager
        .create_wallet("regular_wallet", Some("password"))
        .await?;
    
    // Create a developer/test wallet (crystal_alice, crystal_bob, crystal_charlie)
    let dev_wallet = wallet_manager
        .create_developer_wallet("crystal_alice")
        .await?;
    
    // Import wallet from mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let imported_wallet = wallet_manager
        .import_wallet("imported_wallet", mnemonic, Some("password"))
        .await?;
    
    Ok(())
}
```

#### Listing and Managing Wallets

```rust
async fn manage_wallets() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_manager = WalletManager::new()?;
    
    // List all wallets
    let wallets = wallet_manager.list_wallets()?;
    for wallet in wallets {
        println!("Wallet: {} - {}", wallet.name, wallet.address);
    }
    
    // Get specific wallet info
    if let Some(wallet_info) = wallet_manager.get_wallet("my_wallet", Some("password"))? {
        println!("Wallet details: {:?}", wallet_info);
    }
    
    // Delete a wallet
    let deleted = wallet_manager.delete_wallet("old_wallet")?;
    println!("Wallet deleted: {}", deleted);
    
    Ok(())
}
```

### Blockchain Operations

#### Querying Balances

```rust
use quantus_cli::{
    chain::client::QuantusClient,
    wallet::WalletManager,
};

async fn query_balance() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_manager = WalletManager::new()?;
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    
    // Load wallet
    let wallet_data = wallet_manager.load_wallet("my_wallet", "password")?;
    let account_id = wallet_data.keypair.to_account_id_32();
    
    // Query balance
    use quantus_cli::chain::quantus_subxt::api;
    let account_bytes: [u8; 32] = *account_id.as_ref();
    let subxt_account_id = subxt::utils::AccountId32::from(account_bytes);
    
    let storage_addr = api::storage().system().account(subxt_account_id);
    let account_info = client.client().storage().at(None).fetch_or_default(&storage_addr).await?;
    
    println!("Balance: {} DEV", account_info.data.free);
    
    Ok(())
}
```

#### Sending Transactions

```rust
use quantus_cli::{
    chain::client::QuantusClient,
    wallet::WalletManager,
    AccountId32,
};

async fn send_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let wallet_manager = WalletManager::new()?;
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    
    // Load sender wallet
    let wallet_data = wallet_manager.load_wallet("my_wallet", "password")?;
    let keypair = wallet_data.keypair;
    
    // Parse recipient address
    let to_address = "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2";
    let to_account_id = AccountId32::from_ss58check(to_address)?;
    
    // Create transfer call
    use quantus_cli::chain::quantus_subxt::api;
    use subxt::tx::TxClient;
    
    let to_account_bytes: [u8; 32] = *to_account_id.as_ref();
    let to_subxt_account_id = subxt::utils::AccountId32::from(to_account_bytes);
    
    let transfer_call = api::tx().balances().transfer(
        to_subxt_account_id.into(),
        1000000000000, // 1 DEV
    );
    
    // Submit transaction
    let tx_hash = client
        .client()
        .tx()
        .sign_and_submit_then_watch_default(&transfer_call, &keypair)
        .await?
        .wait_for_finalized_success()
        .await?
        .extrinsic_hash();
    
    println!("Transaction hash: {:?}", tx_hash);
    
    Ok(())
}
```

### Service Architecture

For web services or applications that need to manage multiple wallets:

```rust
use quantus_cli::{
    wallet::WalletManager,
    chain::client::QuantusClient,
};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct WalletService {
    wallet_manager: Arc<WalletManager>,
    client: Arc<RwLock<QuantusClient>>,
}

impl WalletService {
    pub async fn new(node_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let wallet_manager = Arc::new(WalletManager::new()?);
        let client = Arc::new(RwLock::new(QuantusClient::new(node_url).await?));
        
        Ok(Self {
            wallet_manager,
            client,
        })
    }
    
    pub async fn create_wallet(&self, name: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
        let wallet_info = self.wallet_manager
            .create_wallet(name, Some(password))
            .await?;
        
        Ok(wallet_info.address)
    }
    
    pub async fn get_balance(&self, name: &str, password: &str) -> Result<u128, Box<dyn std::error::Error>> {
        let wallet_data = self.wallet_manager.load_wallet(name, password)?;
        let account_id = wallet_data.keypair.to_account_id_32();
        
        // Query balance logic here...
        Ok(0) // Placeholder
    }
}
```

## Error Handling

The library uses custom error types for better error handling:

```rust
use quantus_cli::error::{QuantusError, Result};

async fn handle_errors() -> Result<()> {
    let wallet_manager = WalletManager::new()?;
    
    match wallet_manager.create_wallet("existing_wallet", Some("password")).await {
        Ok(wallet) => println!("Created wallet: {}", wallet.name),
        Err(QuantusError::Wallet(quantus_cli::wallet::WalletError::AlreadyExists)) => {
            println!("Wallet already exists");
        },
        Err(e) => {
            println!("Other error: {}", e);
        }
    }
    
    Ok(())
}
```

## Thread Safety

The library is designed to be thread-safe:

- `WalletManager` can be shared across threads using `Arc<WalletManager>`
- `QuantusClient` can be shared using `Arc<RwLock<QuantusClient>>`
- Wallet operations are safe to call concurrently

### Multisig Operations

The library provides full programmatic access to multisig functionality.

#### Creating a Multisig

```rust
use quantus_cli::{create_multisig, QuantusClient};

async fn create_multisig_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let keypair = quantus_cli::wallet::load_keypair_from_wallet("alice", None, None)?;
    
    // Parse signer addresses
    let alice_account = parse_address("qzkaf...")?;
    let bob_account = parse_address("qzmqr...")?;
    let charlie_account = parse_address("qzo4j...")?;
    
    let signers = vec![alice_account, bob_account, charlie_account];
    let threshold = 2; // 2-of-3
    
    // Create multisig (wait_for_inclusion=true to get address)
    let (tx_hash, multisig_address) = create_multisig(
        &client,
        &keypair,
        signers,
        threshold,
        true // wait for address from event
    ).await?;
    
    println!("Multisig created at: {:?}", multisig_address);
    Ok(())
}

fn parse_address(ss58: &str) -> Result<subxt::utils::AccountId32, Box<dyn std::error::Error>> {
    use sp_core::crypto::{AccountId32, Ss58Codec};
    let (account_id, _) = AccountId32::from_ss58check_with_version(ss58)?;
    let bytes: [u8; 32] = *account_id.as_ref();
    Ok(subxt::utils::AccountId32::from(bytes))
}
```

#### Querying Multisig Info

```rust
use quantus_cli::{get_multisig_info, MultisigInfo};

async fn query_multisig() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let multisig_account = parse_address("qz...")?;
    
    if let Some(info) = get_multisig_info(&client, multisig_account).await? {
        println!("Address: {}", info.address);
        println!("Balance: {} (raw units)", info.balance);
        println!("Threshold: {}", info.threshold);
        println!("Signers: {:?}", info.signers);
        println!("Active Proposals: {}", info.active_proposals);
        println!("Deposit: {} (locked)", info.deposit);
    }
    
    Ok(())
}
```

#### Creating a Transfer Proposal

```rust
use quantus_cli::{propose_transfer, parse_multisig_amount};

async fn create_proposal() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let keypair = quantus_cli::wallet::load_keypair_from_wallet("alice", None, None)?;
    
    let multisig_account = parse_address("qz...")?;
    let recipient = parse_address("qzmqr...")?;
    
    // Parse amount (supports "10", "10.5", "0.001" format)
    let amount = parse_multisig_amount("10")?; // 10 QUAN
    
    let expiry = 1000; // Block number
    
    let tx_hash = propose_transfer(
        &client,
        &keypair,
        multisig_account,
        recipient,
        amount,
        expiry
    ).await?;
    
    println!("Proposal created: 0x{}", hex::encode(tx_hash));
    Ok(())
}
```

#### Approving a Proposal

```rust
use quantus_cli::approve_proposal;

async fn approve_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let keypair = quantus_cli::wallet::load_keypair_from_wallet("bob", None, None)?;
    
    let multisig_account = parse_address("qz...")?;
    let proposal_id = 0u32;
    
    let tx_hash = approve_proposal(
        &client,
        &keypair,
        multisig_account,
        proposal_id
    ).await?;
    
    println!("Approval submitted: 0x{}", hex::encode(tx_hash));
    println!("(Will auto-execute at threshold)");
    Ok(())
}
```

#### Listing Proposals

```rust
use quantus_cli::{list_proposals, ProposalInfo, ProposalStatus};

async fn list_all_proposals() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let multisig_account = parse_address("qz...")?;
    
    let proposals = list_proposals(&client, multisig_account).await?;
    
    println!("Found {} proposal(s)", proposals.len());
    for proposal in proposals {
        println!("Proposal #{}:", proposal.id);
        println!("  Proposer: {}", proposal.proposer);
        println!("  Expiry: block {}", proposal.expiry);
        println!("  Status: {:?}", proposal.status);
        println!("  Approvals: {}", proposal.approvals.len());
    }
    
    Ok(())
}
```

#### Getting Specific Proposal Info

```rust
use quantus_cli::get_proposal_info;

async fn query_proposal() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let multisig_account = parse_address("qz...")?;
    let proposal_id = 0u32;
    
    if let Some(proposal) = get_proposal_info(&client, multisig_account, proposal_id).await? {
        println!("Proposer: {}", proposal.proposer);
        println!("Call data size: {} bytes", proposal.call_data.len());
        println!("Expiry: block {}", proposal.expiry);
        println!("Approvals: {:?}", proposal.approvals);
        println!("Status: {:?}", proposal.status);
    }
    
    Ok(())
}
```

#### Canceling a Proposal

```rust
use quantus_cli::cancel_proposal;

async fn cancel_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let keypair = quantus_cli::wallet::load_keypair_from_wallet("alice", None, None)?;
    
    let multisig_account = parse_address("qz...")?;
    let proposal_id = 0u32;
    
    let tx_hash = cancel_proposal(
        &client,
        &keypair,
        multisig_account,
        proposal_id
    ).await?;
    
    println!("Proposal canceled: 0x{}", hex::encode(tx_hash));
    Ok(())
}
```

#### Dissolving a Multisig

```rust
use quantus_cli::dissolve_multisig;

async fn dissolve_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    let keypair = quantus_cli::wallet::load_keypair_from_wallet("alice", None, None)?;
    
    let multisig_account = parse_address("qz...")?;
    
    // Requires: no proposals, zero balance
    let tx_hash = dissolve_multisig(
        &client,
        &keypair,
        multisig_account
    ).await?;
    
    println!("Multisig dissolved: 0x{}", hex::encode(tx_hash));
    println!("(Creation deposit returned to creator)");
    Ok(())
}
```

#### High-Security Operations for Multisig

Multisig accounts can be configured with high-security mode, which delays all transfers and allows a guardian to intercept suspicious transactions.

##### Checking High-Security Status

```bash
# CLI usage
quantus multisig high-security status --address qz...
```

Example output:
```
🔍 MULTISIG Checking High-Security status...

📋 Multisig: qz...

✅ High-Security: ENABLED

🛡️  Guardian/Interceptor: qzmqr...
⏱️  Delay: 100 blocks

💡 INFO All transfers from this multisig will be delayed and reversible
   The guardian can intercept suspicious transactions during the delay period
```

##### Enabling High-Security via Proposal

To enable high-security for a multisig, you need to create a proposal that will call `reversible_transfers.set_high_security`. This requires approval from threshold signers.

```bash
# CLI usage - Create proposal to enable high-security
quantus multisig propose high-security \
  --address qz... \
  --interceptor qzmqr... \
  --delay-blocks 100 \
  --expiry 2000 \
  --from alice \
  -p password

# Alternative: delay in seconds instead of blocks
quantus multisig propose high-security \
  --address qz... \
  --interceptor qzmqr... \
  --delay-seconds 600 \
  --expiry 2000 \
  --from alice \
  -p password
```

Example workflow:
```bash
# 1. Alice (signer) proposes high-security
quantus multisig propose high-security \
  --address qz123... \
  --interceptor qzguardian... \
  --delay-blocks 100 \
  --expiry 2000 \
  --from alice

# 2. Check proposals to find the ID
quantus multisig list-proposals --address qz123...

# 3. Bob (another signer) approves
quantus multisig approve \
  --address qz123... \
  --proposal-id 0 \
  --from bob

# 4. Once threshold is reached, high-security is automatically enabled
# 5. Verify it's enabled
quantus multisig high-security status --address qz123...
```

##### Key Concepts

- **Guardian/Interceptor**: An account that can intercept (reverse) transactions during the delay period
- **Delay**: Time window during which transactions are reversible (in blocks or seconds)
- **Delayed Transfers**: All transfers from a high-security multisig are scheduled for delayed execution
- **Interception**: Guardian can cancel suspicious transactions and recover funds

##### Disabling High-Security

**Note:** There is currently no `remove` command for disabling high-security mode. The runtime does not expose a `remove_high_security` extrinsic.

If you need to disable high-security for a multisig:
1. Create a new multisig without high-security
2. Transfer funds from the HS multisig to the new one
3. Dissolve the old HS multisig (after cleanup)

Alternatively, request a runtime upgrade to add `remove_high_security` functionality.

##### Security Considerations

- Choose a trusted guardian account (can be another multisig)
- Set an appropriate delay period (longer = more secure, but less convenient)
- Guardian has full control to intercept transactions during delay
- Once enabled, only whitelisted calls are allowed from high-security multisigs
- **High-security cannot be disabled** - consider this permanent for the multisig account

##### Programmatic Usage (Library)

Currently, high-security operations are best performed via CLI. For programmatic access, you can build the runtime call manually:

```rust
use quantus_cli::{chain::client::QuantusClient, chain::quantus_subxt};

async fn enable_hs_via_proposal() -> Result<(), Box<dyn std::error::Error>> {
    let client = QuantusClient::new("ws://127.0.0.1:9944").await?;
    
    // Build set_high_security call
    use quantus_subxt::api::reversible_transfers::calls::types::set_high_security::Delay;
    let delay = Delay::BlockNumber(100);
    let interceptor = parse_address("qzguardian...")?;
    
    let set_hs_call = quantus_subxt::api::tx()
        .reversible_transfers()
        .set_high_security(delay, interceptor);
    
    // Encode as call data
    use subxt::tx::Payload;
    let call_data = set_hs_call.encode_call_data(&client.client().metadata())?;
    
    // Create multisig proposal with this call
    let multisig_account = parse_address("qz...")?;
    let expiry = 2000;
    
    let propose_tx = quantus_subxt::api::tx()
        .multisig()
        .propose(multisig_account, call_data, expiry);
    
    // Submit via your signer keypair
    // ... (submit transaction)
    
    Ok(())
}
```

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic_usage.rs` - Basic library usage
- `examples/wallet_ops.rs` - Advanced wallet operations
- `examples/service.rs` - Service architecture example
- `examples/multisig_library_usage.rs` - Multisig operations
- `examples/multisig_usage.rs` - Multisig CLI usage reference

## Running Examples

```bash
# Run basic usage example
cargo run --example basic_usage

# Run wallet operations example
cargo run --example wallet_ops

# Run service example
cargo run --example service

# Run multisig library usage example
cargo run --example multisig_library_usage
```

## Key Features

- **Quantum-safe cryptography**: Uses Dilithium ML-DSA-87 for all cryptographic operations
- **Wallet management**: Create, import, export, and manage multiple wallets
- **Blockchain interaction**: Query balances, send transactions, get system info
- **Thread-safe**: Safe to use in multi-threaded applications
- **Async/await**: Full async support for non-blocking operations
- **Error handling**: Comprehensive error types for better error handling
- **Developer wallets**: Built-in support for test wallets (crystal_alice, crystal_bob, crystal_charlie)

## Security Considerations

- Always use strong passwords for wallet encryption
- Store passwords securely in production applications
- Use environment variables or secure key management for passwords
- The library uses quantum-safe encryption (AES-256-GCM + Argon2) for wallet storage
- Private keys are never stored in plain text
