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

#### From crates.io

```bash
# Install the CLI tool
cargo install quantus-cli

# The binary will be available as `quantus`
quantus --help
```

#### From source

```bash
# Clone and build
git clone https://github.com/Quantus-Network/quantus-cli
cd quantus-cli
cargo build --release

# The binary will be available as `quantus`
```

#### As a library

Add to your `Cargo.toml`:

```toml
[dependencies]
# Full functionality (CLI + library)
quantus-cli = "0.1.0"

# Library only (smaller dependencies)
quantus-cli = { version = "0.1.0", default-features = false }
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



## Command Reference

### Wormhole (Privacy-Preserving Transfers)

The `wormhole` commands implement a ZK-proof-based privacy layer. Funds are sent to an unspendable account derived from a secret, a zero-knowledge proof is generated to prove ownership, and the proof is verified on-chain to mint equivalent tokens to an exit account -- breaking the on-chain link between sender and receiver.

#### `quantus wormhole address`

Derive the unspendable wormhole address from a secret. This is step one of a private transfer -- it shows the address you need to send funds to.

```bash
quantus wormhole address --secret 0x<64-hex-chars>
```

Output:
```
Wormhole Address
  SS58:  qDx...
  Hex:   0x...

To fund this address:
  quantus send --from <wallet> --to qDx... --amount <amount>
```

Then send funds using a standard transfer (the chain's `WormholeProofRecorderExtension` automatically records a transfer proof for any balance transfer):

```bash
quantus send --from crystal_alice --to qDx... --amount 100
```

#### `quantus wormhole prove`

Generate a ZK proof for an existing wormhole transfer. The proof demonstrates knowledge of the secret without revealing it.

```bash
quantus wormhole prove \
  --secret 0x<secret> \
  --amount 100000000000000 \
  --exit-account <SS58-or-hex> \
  --block 0x<block-hash> \
  --transfer-count <count> \
  --funding-account 0x<funding-account> \
  --output proof.hex
```

- `--exit-account`: The destination address that will receive funds after on-chain verification (SS58 or `0x`-prefixed hex).
- `--block`: Block hash where the transfer was included.
- `--transfer-count`: Transfer count from the `NativeTransferred` event.
- `--output`: Output file path for the hex-encoded proof (default: `proof.hex`).

#### `quantus wormhole aggregate`

Aggregate multiple leaf proofs into a single recursive proof. The aggregation circuit pads with dummy proofs and shuffles to hide which slots are real.

```bash
quantus wormhole aggregate \
  --proofs proof_1.hex proof_2.hex \
  --output aggregated_proof.hex
```

- `--proofs`: One or more hex-encoded proof files. The number must not exceed `num_leaf_proofs` from the circuit config.
- Before aggregation, the CLI verifies binary hashes from `generated-bins/config.json` to detect stale circuit binaries.
- Displays timing for dummy proof generation and aggregation separately.

#### `quantus wormhole verify-aggregated`

Submit an aggregated proof to the chain for on-chain verification. This is an unsigned extrinsic -- no wallet is needed.

```bash
quantus wormhole verify-aggregated --proof aggregated_proof.hex
```

- On success, the chain mints tokens to each exit account listed in the proof.
- The command checks for `ProofVerified` and `ExtrinsicFailed` events and reports the result.

#### `quantus wormhole parse-proof`

Inspect the public inputs of a proof file for debugging.

```bash
# Parse a leaf proof
quantus wormhole parse-proof --proof proof.hex

# Parse an aggregated proof
quantus wormhole parse-proof --proof aggregated_proof.hex --aggregated

# Parse and cryptographically verify locally
quantus wormhole parse-proof --proof aggregated_proof.hex --aggregated --verify
```

#### `quantus wormhole multiround`

Run an automated multi-round wormhole flow: fund -> prove -> aggregate -> verify on-chain, repeated over multiple rounds. This is the primary integration test for the wormhole system.

```bash
quantus wormhole multiround \
  --num-proofs 4 \
  --rounds 2 \
  --amount 100000000000000 \
  --wallet crystal_alice \
  --password "" \
  --keep-files \
  --output-dir /tmp/wormhole_test
```

- `--num-proofs`: Number of proofs per round (1 to `num_leaf_proofs` from circuit config, default: 2).
- `--rounds`: Number of rounds (default: 2). In intermediate rounds, exit accounts are the next round's wormhole addresses; in the final round, funds exit back to the wallet.
- `--amount`: Total amount in planck to randomly partition across proofs (default: 100 DEV).
- `--wallet`: Wallet name for funding (round 1) and final exit.
- `--keep-files`: Preserve proof files after completion (default: cleaned up).
- `--output-dir`: Directory for intermediate proof files (default: `/tmp/wormhole_multiround`).
- `--dry-run`: Show configuration and derived addresses without executing.

Each round performs:
1. **Transfer** (round 1 only): Randomly partition the total amount and send to wormhole addresses derived via HD path `m/44'/189189189'/0'/<round>'/<index>'`.
2. **Generate proofs**: Create a ZK proof for each transfer with randomized dual-output assignments.
3. **Aggregate**: Combine all leaf proofs into a single recursive proof.
4. **Verify on-chain**: Submit the aggregated proof; the chain mints tokens to exit accounts.

After all rounds, the command verifies the wallet balance matches expectations (initial - fees).

---

### Developer Tools

#### `quantus developer build-circuits`

Build ZK circuit binaries from the `qp-zk-circuits` repository, then copy them to the CLI and chain directories. This is required whenever the circuit logic changes.

```bash
quantus developer build-circuits \
  --branching-factor 2 \
  --depth 1 \
  --circuits-path ../qp-zk-circuits \
  --chain-path ../chain
```

- `--branching-factor`: Number of proofs aggregated at each tree level.
- `--depth`: Depth of the aggregation tree. Total leaf proofs = `branching_factor ^ depth`.
- `--circuits-path`: Path to the `qp-zk-circuits` repo (default: `../qp-zk-circuits`).
- `--chain-path`: Path to the chain repo (default: `../chain`).
- `--skip-chain`: Skip copying binaries to the chain directory.

**What it does (4 steps):**
1. Builds the `qp-wormhole-circuit-builder` binary.
2. Runs the circuit builder to generate binary files in `generated-bins/` (includes `prover.bin`, `verifier.bin`, `common.bin`, `aggregated_verifier.bin`, `aggregated_common.bin`, `config.json` with SHA256 hashes).
3. Copies binaries to the CLI's `generated-bins/` directory and touches the aggregator source to force recompilation.
4. Copies chain-relevant binaries (`aggregated_common.bin`, `aggregated_verifier.bin`, `config.json`) to `chain/pallets/wormhole/` and touches the pallet source.

After running, rebuild the chain (`cargo build --release` in the chain directory) so `include_bytes!()` picks up the new binaries.

#### `quantus developer create-test-wallets`

Create standard test wallets (`crystal_alice`, `crystal_bob`, `crystal_charlie`) with developer passwords for local testing.

```bash
quantus developer create-test-wallets
```

---

### Wallet Management

```bash
# Create a new quantum-safe wallet
quantus wallet create --name my_wallet

# Create with explicit derivation path
quantus wallet create --name my_wallet --derivation-path "m/44'/189189'/0'/0/0"

# Import from mnemonic
quantus wallet import --name recovered_wallet --mnemonic "word1 word2 ... word24"

# Create from raw 32-byte seed
quantus wallet from-seed --name raw_wallet --seed <64-hex-chars>

# List wallets
quantus wallet list

# View wallet details
quantus wallet view --name my_wallet

# Export mnemonic
quantus wallet export --name my_wallet --format mnemonic
```

---

### Sending Tokens

```bash
# Simple transfer
quantus send --from crystal_alice --to <address> --amount 10.5

# With tip for priority
quantus send --from crystal_alice --to <address> --amount 10 --tip 0.1

# With manual nonce
quantus send --from crystal_alice --to <address> --amount 10 --nonce 42
```

---

### Batch Transfers

```bash
# From a JSON file
quantus batch send --from crystal_alice --batch-file transfers.json

# Generate identical test transfers
quantus batch send --from crystal_alice --count 10 --to <address> --amount 1.0

# Check batch limits
quantus batch config --limits
```

---

### Reversible Transfers

Schedule transfers with a time delay, allowing cancellation before execution.

```bash
# Schedule with default delay
quantus reversible schedule-transfer --from alice --to bob --amount 10

# Schedule with custom delay
quantus reversible schedule-transfer-with-delay --from alice --to bob --amount 10 --delay 3600

# Cancel a pending transfer
quantus reversible cancel --tx-id 0x<hash> --from alice
```

---

### High-Security Mode

Configure reversibility settings for an account (interceptor + delay).

```bash
# Check status
quantus high-security status --account <address>

# Enable high-security with an interceptor
quantus high-security set --interceptor <address> --delay-seconds 3600 --from alice

# Show accounts you guard
quantus high-security entrusted --from alice
```

---

### Account Recovery

Social recovery using trusted friends.

```bash
# Initiate recovery
quantus recovery initiate --rescuer bob --lost alice

# Friend vouches
quantus recovery vouch --friend charlie --lost alice --rescuer bob

# Claim after threshold met
quantus recovery claim --rescuer bob --lost alice
```

---

### Treasury

Treasury is the account that receives a configurable portion of mining rewards. No special spend/proposal flow — just view its state.

```bash
# Show treasury account and balance
quantus treasury info
```

---

### Privacy-Preserving Transfer Queries

Query transfers via a Subsquid indexer using hash-prefix queries that hide your exact address.

```bash
quantus transfers query \
  --subsquid-url https://indexer.quantus.com/graphql \
  --prefix-len 4 \
  --wallet my_wallet
```

---

### Block Analysis

```bash
# Analyze a specific block
quantus block analyze --number 1234 --all

# Analyze latest block
quantus block analyze --latest --extrinsics --events

# List blocks in a range
quantus block list --start 100 --end 110
```

---

### Generic Pallet Calls

Call any pallet function using metadata-driven parsing:

```bash
quantus call \
  --pallet Balances \
  --call transfer_allow_death \
  --args '["5GrwvaEF...", "1000000000000"]' \
  --from crystal_alice
```

---

### Other Commands

| Command | Description |
|---------|-------------|
| `quantus balance --address <addr>` | Query account balance |
| `quantus events --block 123` | Query events from a block |
| `quantus events --finalized` | Events from the latest finalized block |
| `quantus system` | System information |
| `quantus system --runtime` | Runtime version details |
| `quantus metadata --pallet Balances` | Explore chain metadata |
| `quantus version` | CLI version |
| `quantus compatibility-check` | Check CLI/node compatibility |

---

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

## 🔐 Multisig Wallets

The Quantus CLI provides comprehensive support for multi-signature wallets, allowing you to create shared accounts that require multiple approvals before executing transactions.

### Key Features

- **Deterministic Address Generation**: Multisig addresses are derived from signers + nonce
- **Flexible Threshold**: Configure how many approvals are needed (e.g., 2-of-3, 5-of-7)
- **Full Call Transparency**: Complete transaction data stored on-chain (no blind signing)
- **Auto-Execution**: Proposals execute automatically when threshold is reached
- **Human-Readable Amounts**: Use simple formats like `10` instead of `10000000000000`
- **Smart Address Display**: Automatic SS58 formatting with proper network prefix (`qz...`)
- **Balance Tracking**: View multisig balance directly in `info` command
- **Expiry Validation**: Client-side checks prevent expired proposals
- **Deposit Management**: Refundable deposits incentivize cleanup
- **Query Support**: Inspect multisig configuration, proposals, and balances

### Quick Start Example

```bash
# 1. Create a 2-of-3 multisig (waits for confirmation by default)
quantus multisig create \
  --signers "alice,bob,charlie" \
  --threshold 2 \
  --from alice \
  --wait-for-transaction

# Output: 📍 Multisig address: qz... (with proper network prefix)

# 2. Fund the multisig (anyone can send funds)
quantus send \
  --from alice \
  --to qz... \
  --amount 1000

# 3. Create a transfer proposal (human-readable amount)
quantus multisig propose transfer \
  --address qz... \
  --to dave \
  --amount 10 \
  --expiry 1500 \
  --from alice

# Note: Expiry is BLOCK NUMBER (e.g., current block + 1000)

# 4. Check proposal details (shows current block + blocks remaining)
quantus multisig info --address qz... --proposal-id 0

# Output shows:
#   Current Block: 450
#   Expiry: block 1500 (1050 blocks remaining)

# 5. Second signer approves (auto-executes at threshold)
quantus multisig approve \
  --address qz... \
  --proposal-id 0 \
  --from bob
```

### Available Commands

#### Create Multisig
```bash
# Default: Wait for transaction and extract address from event
quantus multisig create \
  --signers "addr1,addr2,addr3" \
  --threshold 2 \
  --from creator_wallet

# Fast mode: Predict address immediately (may be wrong if concurrent creation)
quantus multisig create \
  --signers "addr1,addr2,addr3" \
  --threshold 2 \
  --from creator_wallet \
  --predict
```

#### Propose Transfer (Recommended for simple transfers)
```bash
quantus multisig propose transfer \
  --address <multisig_address> \
  --to <recipient> \
  --amount 10 \
  --expiry <future_block_number> \
  --from signer_wallet

# Amount formats supported:
#   10       → 10 QUAN
#   10.5     → 10.5 QUAN
#   0.001    → 0.001 QUAN
#   10000000000000 → raw format (auto-detected)
```

#### Propose Custom Transaction (Full flexibility)
```bash
quantus multisig propose custom \
  --address <multisig_address> \
  --pallet System \
  --call remark \
  --args '["Hello from multisig"]' \
  --expiry <future_block_number> \
  --from signer_wallet
```

#### Approve Proposal
```bash
quantus multisig approve \
  --address <multisig_address> \
  --proposal-id <id> \
  --from signer_wallet
```

#### Cancel Proposal (proposer only)
```bash
quantus multisig cancel \
  --address <multisig_address> \
  --proposal-id <id> \
  --from proposer_wallet
```

#### Query Multisig Info
```bash
# Show multisig details (signers, threshold, balance, etc.)
quantus multisig info --address <multisig_address>

# Show specific proposal details (includes current block + time remaining)
quantus multisig info --address <multisig_address> --proposal-id <id>
```

#### List All Proposals
```bash
quantus multisig list-proposals --address <multisig_address>
```

#### Cleanup (Recover Deposits)
```bash
# Remove single expired proposal
quantus multisig remove-expired \
  --address <multisig_address> \
  --proposal-id <id> \
  --from signer_wallet

# Batch cleanup all expired proposals
quantus multisig claim-deposits \
  --address <multisig_address> \
  --from any_signer_wallet
```

#### Dissolve Multisig
```bash
# Requires: no proposals exist, zero balance
quantus multisig dissolve \
  --address <multisig_address> \
  --from creator_or_signer_wallet
```

### Economics

The multisig pallet uses an economic model to prevent spam and incentivize cleanup:

- **MultisigFee**: Non-refundable fee paid to treasury on creation
- **MultisigDeposit**: Refundable deposit (locked, returned on dissolution)
- **ProposalFee**: Non-refundable fee per proposal (scales with signer count)
- **ProposalDeposit**: Refundable deposit per proposal (locked, returned after cleanup)

**Deposits are visible in `multisig info` output:**
```
Balance: 1000 QUAN          ← Spendable balance
Deposit: 0.5 QUAN (locked)  ← Refundable creation deposit
```

### Best Practices

1. **Use Descriptive Names**: Use wallet names instead of raw addresses for better readability
2. **Set Reasonable Expiry**: Use future block numbers (current + 1000 for ~3.3 hours at 12s/block)
3. **Verify Proposals**: Use `info --proposal-id` to decode and verify proposal contents before approving
4. **Cleanup Regularly**: Use `claim-deposits` to recover deposits from expired proposals
5. **Monitor Balances**: Check multisig balance with `info --address` command
6. **High Security**: For high-value multisigs, use higher thresholds (e.g., 5-of-7 or 4-of-6)

### Security Considerations

- **Immutable Configuration**: Signers and threshold cannot be changed after creation
- **Full Transparency**: All call data is stored and decoded on-chain (no blind signing)
- **Auto-Execution**: Proposals execute automatically when threshold is reached
- **Access Control**: Only signers can propose/approve, only proposer can cancel
- **Expiry Protection**: Client validates expiry before submission to prevent wasted fees
- **Deterministic Addresses**: Multisig addresses are deterministic and verifiable

### Advanced Features

**Decoding Proposals**: The CLI automatically decodes common call types:
```bash
$ quantus multisig info --address qz... --proposal-id 0

📝 PROPOSAL Information:
   Current Block: 450
   Call:  Balances::transfer_allow_death
   To:  qzmqr...
   Amount:  10 QUAN
   Expiry: block 1500 (1050 blocks remaining)
```

**SS58 Address Format**: All addresses use the Quantus network prefix (`qz...` for prefix 189) automatically.

**Password Convenience**: Omit `--password ""` for wallets with no password.

For more details, see `quantus multisig --help` and explore subcommands with `--help`.

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
