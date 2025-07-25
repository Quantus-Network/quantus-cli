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

## 📋 CLI Navigation

### Help System
Every command and subcommand has built-in help. Use `--help` at any level:

```bash
# Main help - shows all available commands
quantus --help

# Command help - shows options for a specific command
quantus wallet --help
quantus send --help
quantus call --help

# Subcommand help - shows options for subcommands
quantus wallet create --help
quantus runtime check-version --help
quantus tech-collective list-members --help

# Even deeper subcommands
quantus wallet export --help
quantus storage get --help
```

### Verbose Mode
Every command supports `--verbose` for detailed debugging information:

```bash
# Basic command
quantus send --from crystal_alice --to bob --amount 10

# Same command with verbose output
quantus send --from crystal_alice --to bob --amount 10 --verbose

# Verbose works on any command level
quantus wallet create --name my-wallet --verbose
quantus balance --address alice --verbose
quantus compatibility-check --verbose
```

### Global Options
These options work on every command:
- `--verbose` / `-v`: Enable debug logging with detailed output
- `--node-url <URL>`: Specify node endpoint (default: `ws://127.0.0.1:9944`)
- `--help` / `-h`: Show help for any command or subcommand

### Command Structure
The CLI uses a hierarchical structure:

```
quantus [GLOBAL_OPTIONS] <COMMAND> [COMMAND_OPTIONS] <SUBCOMMAND> [SUBCOMMAND_OPTIONS]
```

**Examples:**
```bash
# Top level command
quantus version

# Command with options
quantus send --from alice --to bob --amount 10

# Command with subcommand
quantus wallet create --name my-wallet

# Command with subcommand and options
quantus runtime check-version --verbose

# Deep nesting
quantus tech-collective vote --referendum-index 0 --aye true --from alice
```

### Discovering Commands
Start with the main help and drill down:

```bash
# See all available commands
quantus --help

# Explore a command group
quantus wallet --help

# See what a subcommand does
quantus wallet create --help

# Check if a command exists
quantus nonexistent-command --help  # Will show error with suggestions
```

### Error Recovery
When you make a mistake, the CLI provides helpful guidance:

```bash
# Wrong command - shows suggestions
quantus wallt create  # Typo in "wallet"
# Error: 'wallt' isn't a valid command. Did you mean 'wallet'?

# Missing required arguments
quantus send --from alice
# Error: the following required arguments were not provided: --to <TO> --amount <AMOUNT>

# Wrong subcommand
quantus wallet nonexistent --help
# Error: 'nonexistent' isn't a valid subcommand for 'wallet'
```

### Quick Reference
Common navigation patterns:

```bash
# Always start here
quantus --help

# Explore any command
quantus <command> --help

# Get verbose output for debugging
quantus <command> --verbose

# Check compatibility first
quantus compatibility-check

# Use different node
quantus <command> --node-url ws://other-node:9944
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
