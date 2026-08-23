# Quantus CLI

A modern command line interface for interacting with the Quantus Network, featuring built-in quantum-safe wallet management and real blockchain operations using SubXT.

## 🌟 Features

- **Quantum-Safe Wallets**: Built with Dilithium post-quantum cryptography
- **Cold Wallet Signing**: Air-gapped signing over QR codes with Keystone or the Quantus cold wallet app
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

#### Updating

The CLI checks GitHub for newer releases and notifies you when one is available
(the result is cached for a few hours, and the check is non-blocking and
best-effort). You can update in place without visiting the releases page:

```bash
# Check whether a newer version is available (no install)
quantus update --check

# Download and install the latest release for your platform
quantus update

# Update without the confirmation prompt (useful in scripts)
quantus update --yes

# Install a specific version
quantus update --version 1.5.0
```

`quantus update` downloads the prebuilt binary for your platform from the
[GitHub releases](https://github.com/Quantus-Network/quantus-cli/releases) and
replaces the running executable. If the binary lives in a protected location
you may need to re-run with elevated privileges (e.g. `sudo quantus update`).

To disable the automatic "new version available" notice, set the
`QUANTUS_NO_UPDATE_CHECK` environment variable to any value.

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

#### `quantus wormhole collect-rewards`

Collect miner rewards from a wormhole address. Queries Subsquid for pending transfers, filters out already-spent nullifiers, generates ZK proofs, and submits withdrawal transactions.

```bash
# Collect all available rewards using a stored wallet
quantus wormhole collect-rewards --wallet my_wallet --password ""

# Collect a specific amount
quantus wormhole collect-rewards --wallet my_wallet --amount 50.0

# Use a mnemonic file (requires --destination; the phrase is never accepted on argv)
quantus wormhole collect-rewards \
  --mnemonic-file ./mnemonic.txt \
  --destination <SS58-address>

# Dry run to see available transfers without submitting
quantus wormhole collect-rewards --wallet my_wallet --dry-run
```

- `--wallet`: Wallet name for HD derivation of the wormhole secret and default exit address.
- `--mnemonic-file`: Alternative to `--wallet`; derive wormhole secrets from the mnemonic in the file. On Unix the file must be a regular file owned by you with no group/other access (`chmod 600`), like `--password-file`.
- `--destination`: Destination address for withdrawn funds (required with `--mnemonic-file`, defaults to wallet address).
- `--amount`: Amount in DEV to withdraw (default: withdraw all available).
- `--wormhole-index`: Wormhole address index for HD derivation (default: `0`).
- `--subsquid-url`: Subsquid indexer URL (default: `https://sub2.quantus.com/v1/graphql`).
- `--dry-run`: Show available transfers without submitting any transactions.
- `--at-block`: Use a specific block number for proofs instead of the latest block.

#### `quantus wormhole check-nullifier`

Check whether nullifiers have been spent (consumed by a withdrawal). Useful for verifying if specific transfers have already been claimed.

```bash
# Check a single transfer count using a wallet
quantus wormhole check-nullifier --wallet my_wallet --transfer-counts 0

# Check a range of transfer counts
quantus wormhole check-nullifier --wallet my_wallet --transfer-counts 0-10

# Check using a secret directly
quantus wormhole check-nullifier --secret 0x<64-hex-chars> --transfer-counts 0-5
```

- `--wallet`: Wallet name for HD derivation of the wormhole secret.
- `--secret`: 32-byte hex secret (alternative to `--wallet`).
- `--transfer-counts`: Single number or range (e.g., `0-10`) of transfer counts to check.
- `--wormhole-index`: Wormhole address index for HD derivation (default: `0`).
- `--subsquid-url`: Subsquid indexer URL (default: `https://sub2.quantus.com/v1/graphql`).

---

### Developer Tools

#### `quantus developer build-circuits`

Build ZK circuit binaries from the `qp-zk-circuits` repository, then copy them to the CLI and chain directories. This is required whenever the circuit logic changes.

```bash
quantus developer build-circuits \
  --num-leaf-proofs 2 \
  --num-layer0-proofs 2 \
  --chain-path ../chain
```

Add `--skip-prover` when you only need verifier artifacts:

```bash
quantus developer build-circuits \
  --num-leaf-proofs 2 \
  --num-layer0-proofs 2 \
  --chain-path ../chain \
  --skip-prover
```

- `--num-leaf-proofs`: Number of leaf proofs per layer-0 aggregation.
- `--num-layer0-proofs`: Number of inner proofs per layer-1 aggregation.
- `--chain-path`: Path to the chain repo (default: `../chain`).
- `--skip-chain`: Skip copying binaries to the chain directory.
- `--skip-prover`: Skip generating prover binaries.

**What it does (3 steps):**
1. Clears stale artifacts from the CLI's `generated-bins/` directory.
2. Calls the `qp-wormhole-circuit-builder` library directly to regenerate binary files in `generated-bins/` (`verifier.bin`, `common.bin`, `private_batch_verifier.bin`, `private_batch_common.bin`, `config.json`, plus prover binaries unless `--skip-prover` is set).
3. Copies chain-relevant binaries (`private_batch_common.bin`, `private_batch_verifier.bin`, `config.json`) to `chain/pallets/wormhole/` and touches the pallet source.

After running, rebuild the chain (`cargo build --release` in the chain directory) so `include_bytes!()` picks up the new binaries.

#### `quantus developer create-test-wallets`

Create standard test wallets (`crystal_alice`, `crystal_bob`, `crystal_charlie`) with developer passwords for local testing.

```bash
quantus developer create-test-wallets
```

---

### Wallet Management

```bash
# Create a new quantum-safe wallet (default scheme: ml-dsa-65, HD path …/1')
quantus wallet create --name my_wallet

# ML-DSA-87 (HD path defaults to …/0' when --derivation-path is omitted)
quantus wallet create --name my_wallet_87 --scheme ml-dsa-87

# Create with an explicit derivation path
quantus wallet create --name my_wallet --derivation-path "m/44'/189189'/0'/0'/1'"

# Import from mnemonic (phrase is read from a hidden prompt — never pass it on the CLI)
quantus wallet import --name recovered_wallet

# Import from a mnemonic file (owner-only on Unix, chmod 600; never pass the phrase on argv)
quantus wallet import --name recovered_wallet --mnemonic-file ./mnemonic.txt

# Import as ML-DSA-87 (same secure prompt)
quantus wallet import --name recovered_87 --scheme ml-dsa-87

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

### Cold Wallets (Keystone / Quantus Cold Wallet App)

Pair the CLI with an air-gapped signer — a Keystone 3 hardware wallet or the
Quantus cold wallet app. The CLI stores only the address (watch-only); every
transaction is signed on the device by exchanging QR codes.

```bash
# Import by scanning the device's address QR with the laptop camera
quantus wallet import-cold --name my_cold

# Or paste the address directly (no camera needed)
quantus wallet import-cold --name my_cold --address qz...

# Any extrinsic command works with a cold wallet: the CLI shows the
# transaction as a QR, then scans the device's animated signature QR
quantus send --from my_cold --to <address> --amount 10.5 --wait-for-transaction
quantus multisig approve --from my_cold --address qz... --proposal-id 0
```

The signing flow (identical for every command — commands don't know whether
the wallet is hot or cold; the shared submit stage branches on the wallet
type):

1. The CLI displays the transaction as a `ur:quantus-sign-request` QR
   (animated if the payload is large). Scan it with the cold wallet, review
   the details on the device, and press Enter in the CLI.
2. Sign on the device — it shows an animated QR containing the signature.
3. Confirm in the CLI, then point the laptop camera at the device's screen.
   The CLI verifies the signature against the stored address before
   submitting; a response signed by any other key is rejected.

Notes:

- The transaction stays valid for 256 blocks after the QR is generated; if it
  expires or the account's nonce changes before submission, re-run the
  command to sign a fresh QR.
- Commands that submit several extrinsics (e.g. `runtime update`,
  `tech-referenda submit-with-preimage`) do one QR roundtrip per extrinsic.
- Wormhole operations are not cold-compatible: they derive secrets from the
  wallet's mnemonic and submit unsigned extrinsics.
- **macOS camera permission**: the permission prompt is attributed to your
  terminal app (Terminal, iTerm, VS Code, …) — grant it under System
  Settings > Privacy & Security > Camera.
- **Headless / no camera**: `--cold-response-in <file>` (or `-` for stdin)
  reads the response UR parts (one per line) instead of scanning, and the
  hidden `--cold-request-out <file>` writes the request UR parts for
  scripted flows. Both are global flags that work with any command. Builds
  without the default `camera` feature (`cargo build --no-default-features`)
  support only this path.
- Real devices only sign for known networks (Planck / Heisenberg genesis
  hashes) and whitelisted calls — balance transfers, reversible transfers,
  and (cold wallet app only) multisig. Test against a dev node with the
  hidden `quantus developer cold-sign-sim` command, which plays the cold
  wallet side using a local hot wallet.

---

### Sending Tokens

```bash
# Simple transfer (default: submit and return once the node accepts the extrinsic)
quantus send --from crystal_alice --to <address> --amount 10.5

# Wait for inclusion in a best block
quantus send --from crystal_alice --to <address> --amount 10.5 --wait-for-transaction

# Wait for finalization (implies --wait-for-transaction)
quantus send --from crystal_alice --to <address> --amount 10.5 --finalized-tx

# Optional advanced: add a tip to prioritize the transaction
quantus send --from crystal_alice --to <address> --amount 10 --tip 0.1

# With manual nonce
quantus send --from crystal_alice --to <address> --amount 10 --nonce 42
```

Transaction status terms:
- `submitted`: accepted by the node, but not yet known to be in a block
- `included`: observed in a best block
- `finalized`: observed in a finalized block

`--amount` and `--tip` use exact decimal parsing based on the chain's configured decimals. Malformed values, negative values, over-precision, or values that would round to zero are rejected. `--tip` is optional and omitted by default.

---

### Batch Transfers

```bash
# From a JSON file (amounts are raw smallest-unit integers)
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

### Vesting

Treasury-funded vesting schedules. Funds vest linearly between `start` and `end` (nothing before `cliff`). `claim` is permissionless — anyone can trigger a payout, which always goes to the schedule's stored beneficiary (this is the claim path for keyless wormhole or high-security beneficiaries). The admin calls (`create-schedule`, `end-schedule`, `retarget`) require the treasury origin; since the treasury is a multisig on real deployments, print the call data with `--call-data-only` and route it through `quantus multisig propose`.

```bash
# Inspect
quantus vesting info
quantus vesting list [--beneficiary qz...]
quantus vesting show --schedule-id 0

# Claim the vested payout of a schedule (any funded wallet can sign)
quantus vesting claim --schedule-id 0 --from my_wallet

# Admin: create a schedule (moments are unix ms, "now", or "+<seconds>")
quantus vesting create-schedule \
  --beneficiary qz... \
  --start now --cliff +7776000 --end +31536000 \
  --total 10000 \
  --call-data-only   # print hex call data for a treasury multisig proposal

# Admin: end early (vested part to beneficiary, rest back to treasury)
quantus vesting end-schedule --schedule-id 3 --call-data-only

# Admin: change beneficiary
quantus vesting retarget --schedule-id 3 --new-beneficiary qz... --call-data-only
```

---

### Runtime Upgrades

Runtime upgrades use the restricted `FastUpgrade` governance track. The proposal contains only
`System::authorize_upgrade(blake2_256(wasm))`, so it stays below the referendum's 4 KiB proposal
limit. The full WASM is supplied only after the authorization enacts.

```bash
# Note the small authorization preimage and submit the FastUpgrade referendum
quantus runtime update \
  --wasm-file /path/to/quantus-runtime.compact.compressed.wasm \
  --from <tech-collective-wallet> \
  --node-url <endpoint>

# Place the decision deposit, collect 8-of-10 ayes, then wait for enactment
quantus tech-referenda list --node-url <endpoint>
quantus tech-referenda place-decision-deposit \
  --index <referendum-index> --from <funded-wallet> --node-url <endpoint>
quantus tech-collective vote \
  --referendum-index <referendum-index> --vote aye \
  --from <member-wallet> --node-url <endpoint>

# Anyone can submit the exact authorized WASM after enactment
quantus runtime apply \
  --wasm-file /path/to/quantus-runtime.compact.compressed.wasm \
  --from <funded-wallet> \
  --node-url <endpoint>
```

`runtime apply` verifies the on-chain authorization hash before submitting and verifies `:code`
at the inclusion block afterward. It always waits for inclusion even without
`--wait-for-transaction`. Because the apply extrinsic carries the full WASM, use a hot wallet in
normal operation rather than QR signing.

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

### Chain Exercise Suite

`quantus exercise` runs a live-node smoke/fuzz suite against a node — reads, balances,
utility, reversible transfers, multisig, recovery, preimage, governance, vesting, negative
cases, a seeded fuzz loop, and wormhole round-trips. It derives a handful of ephemeral
accounts, funds them from a **root account**, drives each pallet, and verifies on-chain state
as it goes. Intended for CI and post-upgrade validation.

```bash
# Against a local dev node — crystal_alice is genesis-funded, so every phase runs
quantus exercise

# Against a public testnet: fund from your own wallet, spending no more than 100 tokens.
# Specifying --total-amount drops the governance phase automatically (it needs the dev
# genesis tech-collective accounts, and its referendum deposits alone are far larger than
# the rest of the suite)
quantus exercise \
  --root-account my-wallet --root-password <pw> \
  --total-amount 100 \
  --node-url wss://a1-planck.quantus.cat

# Run only specific phases, or skip the CPU-heavy wormhole phase
quantus exercise --phases reads,balances,multisig
quantus exercise --skip wormhole

# Reproduce a fuzz failure from its seed; emit the report as JSON
quantus exercise --seed 12345 --json

# Runtime upgrade smoke (fast-governance node only). Mutually exclusive:
#   --self-upgrade  re-installs the current on-chain :code (no WASM file; no post-upgrade re-run)
#   --upgrade-wasm  installs a candidate WASM, then re-runs the other phases against it
quantus exercise --phases upgrade --self-upgrade
quantus exercise --phases upgrade --upgrade-wasm path/to/runtime.wasm
```

Key flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--root-account <NAME>` | `crystal_alice` | Wallet that funds the run. Supply your own to run against a public testnet. |
| `--root-password <PW>` / `--root-password-file <PATH>` | — | Password for the root wallet (or set `QUANTUS_WALLET_PASSWORD_<NAME>`). |
| `--total-amount <TOKENS>` | `500` | Hard cap on what the whole run may draw from the root account. A ceiling, not an allocation — see below. Specifying it drops the `governance` phase unless `--phases` lists it explicitly. |
| `--ephemeral-accounts <N>` | `4` | Number of ephemeral accounts to derive and fund. |
| `--phases <LIST>` / `--skip <LIST>` | all | Comma-separated phases to run / skip. |
| `--seed <N>` | random | Reproducible fuzz seed. |
| `--fuzz-iterations <N>` | `25` | Number of fuzz iterations. |
| `--upgrade-wasm <PATH>` | — | Enable the runtime-upgrade phase with the given WASM (fast-governance node only). Re-runs other phases after a successful upgrade. |
| `--self-upgrade` | off | No-WASM upgrade smoke test: authorize/apply the current on-chain runtime blob via tech-referenda (fast-governance node only). Conflicts with `--upgrade-wasm`. Does not re-run other phases (runtime unchanged). Not the same as `quantus update` (CLI binary self-update). |
| `--upgrade-timeout-secs <N>` | `900` | How long to wait for the upgrade referendum / code write. |
| `--fail-fast` | off | Stop at the first failed step. |
| `--json` | off | Emit the final report as JSON. |

#### What the run spends

`--total-amount` is a hard cap on the root account's balance drop, enforced for the whole run,
not just the initial funding: every root-paid transfer, deposit and estimated transaction fee
is reserved against it before submission and the run fails with the numbers rather than
exceeding it. The final report ends with a `budget / root_account_spend` line stating what was
actually spent — and fails if the cap was exceeded.

It is a ceiling, not an allocation. Ephemeral accounts are funded with what the chain's own
deposits and fees require, not with a share of the cap, and the phases that fund dedicated
accounts — `recovery` and `wormhole` — sweep them back into the root account when they are
done, so their funding is borrowed rather than spent. Discretionary test transfers are scaled
down by a fixed factor on top of that; chain-imposed amounts (existential deposit, multisig,
recovery, vesting and governance deposits) are read from the chain and never scaled.

> **Notes:**
> - `governance` submits two referenda whose chain-fixed deposits stay locked for the whole
>   run — on the order of a thousand tokens, dwarfing every other phase — and it relies on the
>   dev genesis tech-collective accounts. It is therefore dropped whenever `--total-amount` is
>   given, and when it (or `upgrade`) does run, its dev-account spend is exempt from the cap.
> - `vesting`'s admin steps dispatch through the dev Alice/Bob/Charlie treasury multisig; on
>   chains whose treasury is a different account they are skipped, and the permissionless
>   vesting checks still run.
> - The `wormhole` phase is CPU-heavy (ZK proving) — use `--skip wormhole` for a faster run. Its
>   amount is fixed by an on-chain minimum and cannot be scaled down, so it needs ~52 tokens of
>   headroom at once (returned afterwards).
> - Setup fails fast, with the numbers, if the root account can't cover `--total-amount`, if the
>   cap is too low to fund the ephemeral accounts, or if a selected phase needs more headroom
>   than the cap leaves.

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
| `quantus compatibility-check` | Check CLI/node spec-version and transaction-version compatibility |

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

- **Deterministic Address Generation**: Multisig addresses are derived from signers + threshold + nonce
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
- **Deterministic Addresses**: Multisig addresses are derived from signers + threshold + nonce and are verifiable

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
- **Dilithium (ML-DSA)**: Post-quantum digital signatures — default **ML-DSA-65** (`--scheme ml-dsa-65`), with **ML-DSA-87** available (`--scheme ml-dsa-87`). Each scheme has its own default HD path (`…/1'` vs `…/0'`) so the same mnemonic does not collide across schemes.
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
4. **Prompts compatibility update**: Reminds you to add the new runtime/transaction pair to the allowlist in `src/config/mod.rs` (newer unlisted specs warn rather than hard-fail)

**When to use:**
- After updating the Quantus runtime
- When new pallets are added to the chain
- When existing pallet APIs change
- To ensure CLI compatibility with the latest chain version
- Before updating the `quantus compatibility-check` allowlist

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
Reminder: update src/config/mod.rs with the new compatible spec/transaction version pair.
Done!
```

After regeneration, re-run:

```bash
quantus compatibility-check --node-url <node>
```

The compatibility gate accepts exact `spec_version` / `transaction_version` pairs listed in `src/config/mod.rs`. A Quantus node whose `spec_version` is **newer** than the highest listed pair connects with a warning (extrinsics may still fail if the runtime has moved on). Wrong `specName` values and older/unknown pairs outside the table are still rejected.
