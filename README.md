# Quantus CLI

A modern command line interface for interacting with the Quantus Network, featuring built-in quantum-safe wallet management and real blockchain operations.

## 🌟 Features

- **Quantum-Safe Wallets**: Built with Dilithium post-quantum cryptography
- **Generic Pallet Calls**: Call ANY blockchain function using metadata-driven parsing
- **Real Chain Operations**: Send tokens, query balances, explore metadata
- **Smart Type Detection**: Automatic parsing of addresses, balances, and data types
- **Developer Tools**: Pre-built test wallets and utilities
- **Modern CLI**: Built with Rust and Clap for excellent UX
- **Cross-Platform**: Runs on macOS, Linux, and Windows
- **Beautiful UI**: Colorized output with emoji indicators and progress spinners
- **Smart Balance Display**: Automatic formatting with proper decimals and token symbols
- **Password Convenience**: Multiple authentication options including environment variables

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
quantus developer create-test-wallets --verbose

# Check a wallet's balance
quantus balance --address 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP

# Send tokens
quantus send --from crystal_alice --to 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP --amount 10.5

# Manage Tech Collective governance
quantus tech-collective list-members
quantus tech-collective vote --referendum-index 0 --aye true --from crystal_alice

# Call any blockchain function generically
quantus call --pallet Balances --call transfer_allow_death --args '["5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP", "5"]' --from crystal_alice

# Explore the blockchain
quantus metadata --no-docs
```

## 📋 All Commands

### Global Options
Available for all commands:
- `--verbose` / `-v`: Enable debug logging with detailed output
- `--node-url <URL>`: Specify node endpoint (default: `ws://127.0.0.1:9944`)

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
Address: 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP
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
   Address: 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP
   Type: ML-DSA-87 (Dilithium)
   Created: 2024-01-15 09:15:30 UTC

2. crystal_bob
   Address: 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
   Type: ML-DSA-87 (Dilithium)
   Created: 2024-01-15 09:15:31 UTC

3. my-wallet
   Address: 5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy
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
📍 Address: 5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy
⚠️  This action cannot be undone!

To confirm deletion, type the wallet name: my-wallet
```

## 💰 Blockchain Operations

### Query Balance
Check account balances with automatic formatting:

```bash
quantus balance --address 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP
```

**Output:**
```
✅ Balance: 1152921500.346108076 DEV
```

### Send Tokens
Transfer tokens between accounts with multiple convenience options:

```bash
# Basic send
quantus send --from crystal_alice --to 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty --amount 10

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
   From: crystal_alice (5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP)
   To: 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
   Amount: 10.5 DEV (10500000000000 raw units)

✅ Empty password works for wallet 'crystal_alice'
🔗 Connecting to Quantus node: ws://127.0.0.1:9944
✅ Connected to Quantus node successfully!
💰 Balance before: 1152921500.346108076 DEV
🚀 Creating transfer transaction...
✍️  Creating balance transfer extrinsic...
🔗 Waiting for confirmation... / (3s)
📋 Transaction hash: 0x1234567890abcdef...
🔗 Included in block: 0xabcdef1234567890...
💸 Transaction fee: 1.410246299 DEV
✅ Transaction completed successfully!
💰 Balance after: 1152921489.935861777 DEV
```

### System Information
Query blockchain system information:

```bash
quantus system
```

### Metadata Exploration
Explore all available blockchain functionality:

```bash
# Full metadata with documentation
quantus metadata

# Compact view without docs
quantus metadata --no-docs
```

**Output:**
```
🏗️  Chain Metadata Information:
📦 Found 22 pallets:

1. System (Index: 0)
   📞 Calls (6):
      1. remark
         📝 Make some on-chain remark
         📥 Parameters:
           • remark: Vec<u8>
      2. set_heap_pages
         📥 Parameters:
           • pages: u64
   💾 Storage (16):
      1. Account
      2. BlockHash
   📡 Events (6):
      1. ExtrinsicSuccess
      2. ExtrinsicFailed

2. Balances (Index: 10)
   📞 Calls (9):
      1. transfer_allow_death
         📝 Transfer some liquid free balance to another account
         📥 Parameters:
           • dest: AccountIdLookupOf<T>
           • value: u128
      2. force_transfer
         📥 Parameters:
           • source: AccountIdLookupOf<T>
           • dest: AccountIdLookupOf<T>
           • value: u128

...

💡 Use this information to implement new extrinsic calls!
💡 Each call can be submitted using the submit_extrinsic! macro
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
   Address: 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP
   Description: Alice's test wallet for development

✅ Created crystal_bob  
   Address: 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
   Description: Bob's test wallet for development

✅ Created crystal_charlie
   Address: 5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy
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
Quantus CLI v0.1.0
Build: Command line interface for the Quantus Network
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
quantus balance --address 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP

# 3. Create your own wallet
quantus wallet create --name my-production-wallet

# 4. Send some test tokens (traditional way)
quantus send --from crystal_alice --to my-production-wallet --amount 100 --verbose

# 4b. Or use the generic call interface
quantus call --pallet Balances --call transfer_allow_death --args '["my-production-wallet", "50"]' --from crystal_alice

# 5. Verify the transfer
quantus balance --address $(quantus wallet view --name my-production-wallet | grep Address | cut -d' ' -f2)

# 6. Explore what else you can do
quantus metadata --no-docs

# 7. Try other generic calls
quantus call --pallet System --call remark --args '["0x48656c6c6f20576f726c64"]' --from crystal_alice
```

### Scripting Example
```bash
#!/bin/bash
# Script to distribute tokens to multiple accounts

export QUANTUS_WALLET_PASSWORD_CRYSTAL_ALICE=""

RECIPIENTS=(
    "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
    "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy"
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
- `substrate-api-client`: Direct Substrate chain integration
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

### ⚠️ Important: Sudo Requirements

Many Tech Collective operations (like `add_member`) require **sudo permissions**. In development mode, `crystal_alice` has sudo access.

**If you get `BadOrigin` error when adding members:**

The `add_member` call requires sudo permissions. Currently, this must be done through a manual sudo wrapper call. Here's the workflow:

```bash
# ❌ This will fail with BadOrigin (insufficient permissions)
quantus tech-collective add-member --who 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY --from crystal_alice

# ✅ Instead, you need to implement a sudo wrapper call
# This is a complex operation that requires encoding the inner call
# Future CLI versions will include a dedicated sudo wrapper command
```

**Alternative approaches:**
1. **Check Genesis Config**: The chain may already have initial tech collective members
2. **Direct Storage Queries**: Use storage queries to check current members
3. **Manual Encoding**: Create the sudo call manually (advanced users)

### Example Usage

```bash
# Create test wallets first
quantus developer create-test-wallets

# Try to vote (this works if you're already a member)
quantus tech-collective vote --referendum-index 0 --aye true --from crystal_alice

# Check membership status
quantus tech-collective is-member --address 5H7DdvKue19FQZpRKc2hmBfSBGEczwvdnVYDNZC3W95UDyGP

# List current members (requires implementation enhancement)
quantus tech-collective list-members
```

### Tech Collective Architecture

The Tech Collective in Quantus is based on `pallet_ranked_collective` configured for simplicity:

- **Simple Membership**: All members have equal standing (rank 0)
- **Equal Voting**: All members have the same voting weight
- **Technical Governance**: Focus on technical proposals and referenda  
- **Integration**: Works with Tech Referenda for proposal lifecycle

---
