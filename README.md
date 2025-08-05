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

Start by exploring the available commands:

```bash
# Get help to see all available commands
quantus --help

# Explore specific command groups
quantus wallet --help
quantus send --help
quantus tech-collective --help
```

The CLI provides comprehensive help at every level, allowing you to discover functionality step by step.

## 📋 CLI Navigation

### Help System
The CLI provides comprehensive help at every level. Every command and subcommand supports `--help`:

- **Main level**: `quantus --help` shows all available top-level commands
- **Command level**: `quantus <command> --help` shows options for specific commands
- **Subcommand level**: `quantus <command> <subcommand> --help` shows options for subcommands
- **Deep nesting**: Help is available at any depth of command nesting

This hierarchical help system allows you to discover available functionality step by step, starting from the main help and drilling down to specific command options.

### Verbose Mode
Every command supports `--verbose` for detailed debugging information:

- **Standard output**: Commands show essential information by default
- **Verbose output**: Adding `--verbose` provides detailed execution logs, network calls, and internal state information
- **Universal support**: Verbose mode works on any command level and any subcommand
- **Debugging aid**: Use verbose mode to troubleshoot issues or understand command execution flow

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

**Structure:**
The CLI follows a consistent pattern where global options can be combined with any command and subcommand at any level of nesting.

### Discovering Commands
Start with the main help and drill down to explore available functionality. The CLI provides helpful error messages and suggestions when you make mistakes, guiding you to the correct command syntax.

### Quick Reference
Common navigation patterns:
- Start with `quantus --help` to see all available commands
- Use `quantus <command> --help` to explore specific command options
- Add `--verbose` to any command for detailed debugging information
- Use `--node-url` to connect to different nodes (defaults to localhost)



## 🔧 Environment Variables

### Password Management
- `QUANTUS_WALLET_PASSWORD`: Global password for all wallets
- `QUANTUS_WALLET_PASSWORD_<WALLET_NAME>`: Wallet-specific password (e.g., `QUANTUS_WALLET_PASSWORD_CRYSTAL_ALICE`)

### Node Configuration  
- Set via `--node-url` flag or default to `ws://127.0.0.1:9944`

## 💡 Getting Started

The CLI provides a comprehensive set of commands for blockchain interaction. Start by exploring the help system to discover available functionality:

1. **Explore commands**: Use `quantus --help` to see all available commands
2. **Discover options**: Use `quantus <command> --help` to see command-specific options
3. **Get details**: Add `--verbose` to any command for detailed execution information
4. **Connect to nodes**: Use `--node-url` to connect to different blockchain nodes

The CLI supports both simple commands and complex workflows, with built-in help and error recovery at every level.

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
- **Event Decoding**: Automatic SS58 address formatting in event output
- **Fresh Nonce Management**: Automatic nonce handling to avoid transaction conflicts
- **Transaction Retry Logic**: Exponential backoff for failed transactions
- **Latest Block Reading**: Consistent reading from latest (not finalized) blocks

### Real Blockchain Integration
- **Substrate Integration**: Direct connection to Quantus node via WebSocket
- **Metadata-Driven**: Discovers available functionality from chain metadata
- **Transaction Monitoring**: Real-time transaction confirmation and fee calculation
- **Extensible Architecture**: Macro-based extrinsic submission supports any pallet
- **Event System**: Query events by block number, hash, or finalized status
- **Storage Operations**: Direct storage queries and sudo-based storage modifications
- **Reversible Transfers**: Schedule and cancel reversible transactions
- **Scheduler Integration**: Query and manage scheduled operations

## 🛠️ Current Status

**✅ Fully Implemented:**
- Quantum-safe wallet management with Dilithium cryptography
- Real blockchain operations (send, balance, storage, events)
- Tech Collective governance (add/remove members, voting)
- Generic pallet calls via metadata-driven parsing
- Reversible transfers with scheduling and cancellation
- Scheduler integration for automated operations
- System information and runtime management
- Event querying with SS58 address formatting
- Fresh nonce management and transaction retry logic

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
- `subxt-cli` must be installed: `cargo install subxt-cli`
- Node must be fully synced and ready

**Usage:**
```bash
# Use default node URL (ws://127.0.0.1:9944)
./regenerate_metadata.sh

# Use custom node URL
./regenerate_metadata.sh --node-url ws://other-node:9944

# Show help
./regenerate_metadata.sh --help
```

**Output:**
```
Using node URL: ws://127.0.0.1:9944
Updating metadata file at src/quantus_metadata.scale...
Generating SubXT types to src/chain/quantus_subxt.rs...
Formatting generated code...
Done!
```

This ensures the CLI always has the latest type definitions and can interact with new chain features.
