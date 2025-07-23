# Quantus CLI

A modern command line interface for interacting with the Quantus Network, featuring built-in quantum-safe wallet management and real blockchain operations using SubXT.

## 🌟 Features

- **Quantum-Safe Wallets**: Built with Dilithium post-quantum cryptography
- **SubXT Integration**: Modern Substrate client with type-safe API
- **Generic Pallet Calls**: Call ANY blockchain function using metadata-driven parsing
- **Real Chain Operations**: Send tokens, query balances, explore metadata
- **Smart Type Detection**: Automatic parsing of addresses, balances, and data types
- **Developer Tools**: Pre-built test wallets and utilities
- **Modern CLI**: Built with Rust and Clap for excellent UX
- **Cross-Platform**: Runs on macOS, Linux, and Windows
- **Beautiful UI**: Colorized output with emoji indicators and progress spinners
- **Smart Balance Display**: Automatic formatting with proper decimals and token symbols
- **Password Convenience**: Multiple authentication options including environment variables
- **Fresh Nonce Management**: Automatic nonce handling to avoid transaction conflicts

## 🚀 Quick Start

### Installation

```bash
# Clone and build
git clone <repository-url>
cd quantus-cli
cargo build --release

# The binary will be available as `quantus`
```

### First Steps

```bash
# Get help
quantus --help

# Create your first wallet
quantus wallet create --name my-wallet

# Create test wallets for development
quantus developer create-test-wallets

# Check a wallet's balance
quantus balance --address qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ

# Send tokens
quantus send --from crystal_alice --to qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2 --amount 10.5

# Manage Tech Collective governance
quantus tech-collective list-members
quantus tech-collective vote --referendum-index 0 --aye true --from crystal_alice

# Call any blockchain function generically
quantus call --pallet Balances --call transfer_allow_death --args '["qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ", "1000000000"]' --from crystal_alice

# Explore the blockchain
quantus metadata --stats-only
```

## 📋 All Commands

### Global Options
Available for all commands:
- `--verbose` / `-v`: Enable debug logging with detailed output
- `--node-url <URL>`: Specify node endpoint (default: `ws://127.0.0.1:9944`)

### Wallet Management
```bash
# Create, list, and manage quantum-safe wallets
quantus wallet create --name <WALLET_NAME>
quantus wallet list
quantus wallet view --name <WALLET_NAME>
quantus wallet export --name <WALLET_NAME> --format mnemonic
quantus wallet import --name <WALLET_NAME> --mnemonic "<PHRASE>"
quantus wallet delete --name <WALLET_NAME>
quantus wallet nonce --wallet <WALLET_NAME>
```

### Blockchain Operations
```bash
# Query balances and send tokens
quantus balance --address <ADDRESS>
quantus send --from <WALLET> --to <ADDRESS> --amount <AMOUNT>

# Reversible transfers with delay
quantus reversible schedule-transfer --from <WALLET> --to <ADDRESS> --amount <AMOUNT>
quantus reversible schedule-transfer-with-delay --from <WALLET> --to <ADDRESS> --amount <AMOUNT> --delay <SECONDS>
quantus reversible cancel --tx-id <HASH> --from <WALLET>
quantus reversible list-pending --from <WALLET>

# Generic calls to any pallet function
quantus call --pallet <PALLET> --call <FUNCTION> --args <JSON_ARRAY> --from <WALLET>
```

### Storage Operations (Sudo Required)
```bash
# Read and write storage directly
quantus storage get --pallet <PALLET> --name <STORAGE_ITEM> [--decode-as <TYPE>]
quantus storage set --pallet <PALLET> --name <STORAGE_ITEM> --value <VALUE> [--type <TYPE>] --wallet <SUDO_WALLET>
```

### Tech Collective Management
Simple governance system for technical proposals:

```bash
# Member management (requires sudo)
quantus tech-collective add-member --who <ADDRESS> --from <SUDO_WALLET>
quantus tech-collective remove-member --who <ADDRESS> --from <SUDO_WALLET>

# Voting on referenda
quantus tech-collective vote --referendum-index <INDEX> --aye <BOOL> --from <MEMBER>

# Query collective state
quantus tech-collective list-members
quantus tech-collective is-member --address <ADDRESS>
quantus tech-collective check-sudo
quantus tech-collective list-referenda
quantus tech-collective get-referendum --index <INDEX>
```

### Runtime Management (Sudo Required)
```bash
# Runtime version and update operations
quantus runtime check-version
quantus runtime update --wasm-file <PATH> --from <SUDO_WALLET>
quantus runtime compare --wasm-file <PATH>
```

### System Information
```bash
# Query system and metadata information
quantus system --runtime
quantus system --metadata
quantus metadata [--no-docs] [--stats-only]
quantus version
```

### Scheduler Operations
```bash
# Query scheduler state
quantus scheduler get-last-processed-timestamp
```

### Developer Tools
```bash
# Create test wallets for development
quantus developer create-test-wallets
```

## 💼 Wallet Management

### Create Wallet
Creates a new quantum-safe wallet with Dilithium post-quantum cryptography:

```bash
# Create with prompted password
quantus wallet create --name my-wallet

# Create with password parameter (not recommended for production)
quantus wallet create --name my-wallet --password mypassword

# Verbose output shows detailed creation process
quantus wallet create --name my-wallet --verbose
```

**Output:**
```
🔐 Creating new quantum wallet...
Wallet name: my-wallet
Address: qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ
Key type: ML-DSA-87 (Dilithium)
Created: 2024-01-15 10:30:45 UTC
✅ Wallet created successfully!
```

### List Wallets
Shows all available wallets:

```bash
quantus wallet list
```

**Output:**
```
📁 Found 3 wallets:

1. crystal_alice
   Address: qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ
   Type: ML-DSA-87 (Dilithium)
   Created: 2024-01-15 09:15:30 UTC

2. crystal_bob
   Address: qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2
   Type: ML-DSA-87 (Dilithium)
   Created: 2024-01-15 09:15:31 UTC

3. my-wallet
   Address: qzkx3FCxAA1eCtA1n6ij7xS3W9oNmuncYaPReWoYNviddvaT3
   Type: ML-DSA-87 (Dilithium)
   Created: 2024-01-15 10:30:45 UTC
```

### View Wallet Details
Display detailed information about wallets:

```bash
# View specific wallet
quantus wallet view --name my-wallet

# View all wallets (same as list but different format)
quantus wallet view --all
```

### Export Wallet
Export wallet data in various formats:

```bash
# Export mnemonic phrase (default)
quantus wallet export --name my-wallet --format mnemonic

# Export private key
quantus wallet export --name my-wallet --format private-key
```

### Import Wallet
Import a wallet from mnemonic phrase:

```bash
# Import with prompted mnemonic
quantus wallet import --name imported-wallet

# Import with mnemonic parameter
quantus wallet import --name imported-wallet --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Import with password
quantus wallet import --name imported-wallet --password mypassword
```

### Delete Wallet
Remove a wallet (with safety confirmation):

```bash
# Delete with confirmation prompt
quantus wallet delete --name my-wallet

# Force delete without confirmation (be careful!)
quantus wallet delete --name my-wallet --force
```

**Interactive confirmation:**
```
⚠️  You are about to delete wallet 'my-wallet'
📍 Address: qzkx3FCxAA1eCtA1n6ij7xS3W9oNmuncYaPReWoYNviddvaT3
⚠️  This action cannot be undone!

To confirm deletion, type the wallet name: my-wallet
```

### Check Nonce
Get the current transaction nonce for an account:

```bash
# Check nonce for a wallet
quantus wallet nonce --wallet crystal_alice

# Check nonce for a specific address
quantus wallet nonce --address qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ
```

## 💰 Blockchain Operations

### Query Balance
Check account balances with automatic formatting:

```bash
quantus balance --address qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ
```

**Output:**
```
💰 Balance: 1152921500.346108076 DEV
```

### Send Tokens
Transfer tokens between accounts with multiple convenience options:

```bash
# Basic send
quantus send --from crystal_alice --to qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2 --amount 10

# Send with decimal amounts
quantus send --from my-wallet --to crystal_bob --amount 10.5 --verbose

# Send with password parameter
quantus send --from my-wallet --to crystal_bob --amount 0.0001 --password mypassword

# Send with password from file (for scripting)
quantus send --from my-wallet --to crystal_bob --amount 100 --password-file /path/to/password.txt
```

**Password Convenience Options:**
1. **Environment Variables**: Set `QUANTUS_WALLET_PASSWORD` or `QUANTUS_WALLET_PASSWORD_CRYSTAL_ALICE`
2. **CLI Flags**: Use `--password` or `--password-file`
3. **Empty Password**: Automatically tries empty password for development wallets
4. **Interactive Prompt**: Falls back to secure password prompt

**Verbose Output:**
```
🚀 Preparing to send tokens...
   From: crystal_alice (qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ)
   To: qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2
   Amount: 10.5 DEV (10500000000000 raw units)

✅ Empty password works for wallet 'crystal_alice'
🔗 Connecting to Quantus node: ws://127.0.0.1:9944
✅ Connected to Quantus node successfully!
💰 Balance before: 1152921500.346108076 DEV
🚀 Creating transfer transaction...
✍️  Creating balance transfer extrinsic...
🔢 Using fresh nonce from tx API: 1
🔗 Waiting for confirmation... / (5s)
📋 Transaction hash: 0x1234567890abcdef...
✅ Transaction completed successfully!
💰 Balance after: 1152921489.935861777 DEV
```

### Reversible Transfers
Schedule transfers that can be cancelled before execution:

```bash
# Schedule transfer with default delay
quantus reversible schedule-transfer --from crystal_alice --to crystal_bob --amount 10

# Schedule transfer with custom delay
quantus reversible schedule-transfer-with-delay --from crystal_alice --to crystal_bob --amount 10 --delay 3600

# Cancel a pending transfer
quantus reversible cancel --tx-id 0x1234567890abcdef --from crystal_alice

# List pending transfers
quantus reversible list-pending --from crystal_alice
```

### Generic Calls
Call any pallet function using metadata-driven parsing:

```bash
# Transfer using generic call
quantus call --pallet Balances --call transfer_allow_death --args '["qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2", "1000000000"]' --from crystal_alice

# System remark
quantus call --pallet System --call remark --args '["0x48656c6c6f20576f726c64"]' --from crystal_alice

# With tip for priority
quantus call --pallet Balances --call transfer_allow_death --args '["qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2", "1000000000"]' --from crystal_alice --tip 1000000000
```

### Direct Storage Interaction (Sudo Required)
Directly read and write raw storage values on the chain. This is a powerful and dangerous feature that requires a sudo-enabled wallet.

#### Get Storage Value
Read a raw value from storage.

```bash
# Get the raw hex value for a storage item
quantus storage get --pallet Scheduler --name LastProcessedTimestamp
```
**Output:**
```
🔎 Getting storage for Scheduler::LastProcessedTimestamp
✅ Raw Value: 0x406f343798010000
```

You can also decode the value into a common type.

```bash
# Get and decode the value as a "moment" (u64 timestamp)
quantus storage get \
  --pallet Scheduler \
  --name LastProcessedTimestamp \
  --decode-as moment
```
**Output:**
```
🔎 Getting storage for Scheduler::LastProcessedTimestamp
✅ Raw Value: 0x406f343798010000
Attempting to decode as moment...
✅ Decoded Value: 1753272858000
```

#### Set Storage Value
Write a value directly to storage.

```bash
# Set a storage item using a pre-encoded hex value
quantus storage set \
  --pallet Scheduler \
  --name LastProcessedTimestamp \
  --value 0x107f0c0199010000 \
  --wallet my-sudo-wallet
```

For convenience, you can provide a plain value and specify its type for automatic encoding.

```bash
# Set the same value by providing the number and type
quantus storage set \
  --pallet Scheduler \
  --name LastProcessedTimestamp \
  --value 1750834698000 \
  --type moment \
  --wallet my-sudo-wallet
```
**Output:**
```
✍️  Setting storage for Scheduler::LastProcessedTimestamp

🛑 This is a SUDO operation!
📡 Submitting sudo extrinsic to the chain...
🎉 Transaction submitted successfully!
📋 Transaction hash: 0x9876543210abcdef...
```

### System Information
Query blockchain system information:

```bash
# Get runtime information
quantus system --runtime

# Get metadata statistics
quantus system --metadata
```

### Metadata Exploration
Explore all available blockchain functionality:

```bash
# Full metadata with documentation
quantus metadata

# Compact view without docs
quantus metadata --no-docs

# Just statistics
quantus metadata --stats-only
```

**Output:**
```
📊 Metadata Statistics (SubXT):
   📦 Total pallets: 23
   🔗 API: Type-safe SubXT
   🎯 Total calls: 143
   💾 Total storage items: 98
```

## 🧪 Developer Tools

### Create Test Wallets
Generate standard test wallets for development:

```bash
quantus developer create-test-wallets --verbose
```

**Output:**
```
🧪 DEVELOPER Creating standard test wallets...

✅ Created crystal_alice
   Address: qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ
   Description: Alice's test wallet for development

✅ Created crystal_bob  
   Address: qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2
   Description: Bob's test wallet for development

✅ Created crystal_charlie
   Address: qzkx3FCxAA1eCtA1n6ij7xS3W9oNmuncYaPReWoYNviddvaT3
   Description: Charlie's test wallet for development

🎉 Test wallet creation complete!
✅ Created 3 test wallets with empty passwords for easy development
💡 Use these wallets for testing - they use empty passwords by default
```

**Test Wallets:**
- `crystal_alice`: Primary test account with empty password
- `crystal_bob`: Secondary test account with empty password  
- `crystal_charlie`: Third test account with empty password

## 📊 Version Information

```bash
quantus version
```

**Output:**
```
🔮 Quantus CLI
CLI Version: Quantus CLI v0.1.0
Runtime Version: spec_version: 103, impl_version: 1
```

## 🔧 Environment Variables

### Password Management
- `QUANTUS_WALLET_PASSWORD`: Global password for all wallets
- `QUANTUS_WALLET_PASSWORD_<WALLET_NAME>`: Wallet-specific password (e.g., `QUANTUS_WALLET_PASSWORD_CRYSTAL_ALICE`)

### Node Configuration  
- Set via `--node-url` flag or default to `ws://127.0.0.1:9944`

## 💡 Usage Examples

### Complete Workflow Example
```bash
# 1. Set up development environment
export QUANTUS_WALLET_PASSWORD_CRYSTAL_ALICE=""
quantus developer create-test-wallets

# 2. Check initial balance
quantus balance --address qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ

# 3. Create your own wallet
quantus wallet create --name my-production-wallet

# 4. Send some test tokens (traditional way)
quantus send --from crystal_alice --to my-production-wallet --amount 100 --verbose

# 4b. Or use the generic call interface
quantus call --pallet Balances --call transfer_allow_death --args '["my-production-wallet", "50000000000"]' --from crystal_alice

# 5. Verify the transfer
quantus balance --address $(quantus wallet view --name my-production-wallet | grep Address | cut -d' ' -f2)

# 6. Explore what else you can do
quantus metadata --stats-only

# 7. Try other generic calls
quantus call --pallet System --call remark --args '["0x48656c6c6f20576f726c64"]' --from crystal_alice
```

### Scripting Example
```bash
#!/bin/bash
# Script to distribute tokens to multiple accounts

export QUANTUS_WALLET_PASSWORD_CRYSTAL_ALICE=""

RECIPIENTS=(
    "qzkeicNBtW2AG2E7USjDcLzAL8d9WxTZnV2cbtXoDzWxzpHC2"
    "qzkx3FCxAA1eCtA1n6ij7xS3W9oNmuncYaPReWoYNviddvaT3"
)

for recipient in "${RECIPIENTS[@]}"; do
    echo "Sending 50 DEV to $recipient"
    quantus send --from crystal_alice --to "$recipient" --amount 50
    sleep 2  # Wait between transactions
done
```

## 🏗️ Architecture

### Quantum-Safe Cryptography
- **Dilithium (ML-DSA-87)**: Post-quantum digital signatures
- **Secure Storage**: AES-256-GCM + Argon2 encryption for wallet files
- **Future-Proof**: Ready for ML-KEM key encapsulation

### SubXT Integration
- **Type-Safe API**: Compile-time type checking for all blockchain operations
- **Metadata-Driven**: Discovers available functionality from chain metadata
- **Fresh Nonce Management**: Automatic nonce handling to avoid transaction conflicts
- **Progress Indicators**: Real-time transaction confirmation with spinners

### Smart Features
- **Dynamic Balance Formatting**: Automatically fetches chain decimals and token symbol
- **Progress Indicators**: Spinners during network operations
- **Error Recovery**: Comprehensive error handling with helpful messages
- **Development Mode**: Empty password detection for test wallets

### Real Blockchain Integration
- **Substrate Integration**: Direct connection to Quantus node via WebSocket
- **Metadata-Driven**: Discovers available functionality from chain metadata
- **Transaction Monitoring**: Real-time transaction confirmation and fee calculation
- **Extensible Architecture**: Macro-based extrinsic submission supports any pallet

## 🛠️ Current Status

**🔮 Architecture Ready For:**
- Additional pallet integrations (staking, governance, etc.)
- Hardware wallet support
- Multi-chain support
- Advanced key derivation

## 📦 Technical Dependencies

### Core Runtime
- `clap`: Modern CLI argument parsing
- `tokio`: Async runtime for blockchain operations
- `subxt`: Modern Substrate client with type-safe API
- `serde` + `serde_json`: Data serialization

### Cryptography
- `dilithium-crypto`: Post-quantum signatures
- `aes-gcm`: Symmetric encryption
- `argon2`: Password-based key derivation
- `bip39`: Mnemonic phrase generation

### User Experience
- `colored`: Terminal output colorization
- `chrono`: Date/time formatting
- `thiserror`: Structured error handling

## 🎯 Real-World Ready

The Quantus CLI is a **production-ready** tool that:

✅ **Handles Real Money**: All transactions are real and irreversible  
✅ **Quantum-Safe**: Uses post-quantum cryptography for future security  
✅ **Developer-Friendly**: Rich tooling and clear error messages  
✅ **Scriptable**: Environment variables and flags for automation  
✅ **Extensible**: Clean architecture for adding new blockchain features  
✅ **SubXT-Powered**: Modern, type-safe blockchain integration

**⚠️ Security Note**: This tool handles real cryptocurrency. Always:
- Back up your wallet files and mnemonic phrases
- Use strong passwords for production wallets
- Test with small amounts first
- Keep your private keys secure

## 🏛️ Tech Collective Management

The Quantus CLI includes comprehensive management for the Tech Collective - a simple governance system for technical proposals.

### Available Commands

```bash
# List all tech collective commands
quantus tech-collective --help

# Add a member (requires sudo permissions)
quantus tech-collective add-member --who <ADDRESS> --from <SUDO_WALLET>

# Remove a member (requires sudo permissions)
quantus tech-collective remove-member --who <ADDRESS> --from <SUDO_WALLET>

# Vote on tech referenda
quantus tech-collective vote --referendum-index <INDEX> --aye <true/false> --from <MEMBER_WALLET>

# Query collective state
quantus tech-collective list-members
quantus tech-collective is-member --address <ADDRESS>
quantus tech-collective check-sudo

# List and view referenda
quantus tech-collective list-referenda
quantus tech-collective get-referendum --index <INDEX>
```

### Example Usage

```bash
# Create test wallets first
quantus developer create-test-wallets

# Try to vote (this works if you're already a member)
quantus tech-collective vote --referendum-index 0 --aye true --from crystal_alice

# Check membership status
quantus tech-collective is-member --address qzpVkR5dV7o2ryrQaWFWA7ifma4tonnJS4sr3MzJLpti9cTvQ

# List current members
quantus tech-collective list-members
```

### Tech Collective Architecture

The Tech Collective in Quantus is based on `pallet_ranked_collective` configured for simplicity:

- **Simple Membership**: All members have equal standing (rank 0)
- **Equal Voting**: All members have the same voting weight
- **Technical Governance**: Focus on technical proposals and referenda  
- **Integration**: Works with Tech Referenda for proposal lifecycle

---

## 🔄 Recent Updates

### v0.1.0 (Current)
- ✅ **SubXT Integration**: Complete migration from substrate-api-client to SubXT
- ✅ **Fresh Nonce Management**: Automatic nonce handling to avoid transaction conflicts
- ✅ **Progress Spinner**: Real-time transaction confirmation with visual feedback
- ✅ **Code Cleanup**: Removed duplicate code and improved architecture
- ✅ **Common Utilities**: Shared functions for consistent behavior across commands
- ✅ **Verbose Logging**: Enhanced debug output with detailed transaction information

### Key Improvements
- **Type Safety**: All blockchain operations now use SubXT's type-safe API
- **Error Handling**: Better error messages and recovery mechanisms
- **Performance**: Optimized transaction submission and confirmation
- **Developer Experience**: Improved CLI feedback and progress indicators

## 🔧 Development Tools

### Metadata Regeneration

The project includes a script to regenerate SubXT types and metadata when the blockchain runtime changes:

```bash
# Regenerate metadata and types from the running node
./regenerate_metadata.sh
```

**What this script does:**
1. **Updates metadata**: Downloads the latest chain metadata to `src/quantus_metadata.scale`
2. **Generates types**: Creates type-safe Rust code in `src/chain/quantus_subxt.rs`
3. **Formats code**: Automatically formats the generated code with `cargo fmt`

**When to use:**
- After updating the Quantus runtime
- When new pallets are added to the chain
- When existing pallet APIs change
- To ensure CLI compatibility with the latest chain version

**Requirements:**
- Quantus node must be running on `ws://127.0.0.1:9944`
- `subxt-cli` must be installed: `cargo install subxt-cli`
- Node must be fully synced and ready

**Output:**
```
Updating metadata file at src/quantus_metadata.scale...
Generating SubXT types to src/chain/quantus_subxt.rs...
Formatting generated code...
Done!
```

This ensures the CLI always has the latest type definitions and can interact with new chain features.
