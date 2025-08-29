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

## Examples

See the `examples/` directory for complete working examples:

- `examples/basic_usage.rs` - Basic library usage
- `examples/wallet_ops.rs` - Advanced wallet operations
- `examples/service.rs` - Service architecture example

## Running Examples

```bash
# Run basic usage example
cargo run --example basic_usage

# Run wallet operations example
cargo run --example wallet_ops

# Run service example
cargo run --example service
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
