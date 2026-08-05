## Summary

Addresses the V12 security audit findings in `v12-issues.md`.

**Scope:** only findings with `Validity: Unreviewed`. V12 marks **314 Low** findings as `Validity: Invalid` (likely incorrect); those are **excluded** from this analysis and are not treated as open work.

| Severity | Unreviewed (in scope) | Invalid (excluded) |
|----------|----------------------:|-------------------:|
| High | 20 | 0 |
| Medium | 30 | 0 |
| Low | 11 | 314 |
| Info | 2 | 0 |

This PR remediates **all 20 High and 30 Medium** Unreviewed findings (with red→green tests where applicable). The **11 Unreviewed Lows** are listed below; most remain open for follow-up. A few Invalid Lows were hardened opportunistically and are noted separately (out of audit scope).

**34 commits** on `illuzen/v12-2`. Library suite: **211+ tests passing**.

## High (20/20 addressed)

| ID | Title | Outcome |
|----|-------|---------|
| #159453 | Wallet mnemonic/seed as CLI args | Fixed — always hidden prompt |
| #159924 | Malformed wallet aborts listing | Fixed — skip bad files; validate SS58 |
| #160053 | MultisigCreated mis-attribution | Fixed — correlate creator/signers/threshold/nonce |
| #160582 | Raw `--password` CLI credentials | Fixed — reject at helper boundary |
| #160592 | Keystore permissive permissions | Fixed — dir `0700`, files `0600` |
| #160593 | Unauthenticated address redirect | Fixed — integrity check on decrypt |
| #160594 | Unauthenticated metadata substitution | Fixed — passwordless paths stop trusting envelope |
| #160598 | Filesystem races in wallet storage | Fixed — locks, random temps, name checks |
| #160605 | Failed legacy migration bypass | Fixed — fail closed on migration save |
| #160611 | Watched txs succeed when absent | Fixed — missing extrinsic → error |
| #160612 | Unsafe retries duplicate txs | Fixed — single submit, no nonce-bump retry |
| #160624 | Unverified RPC signing context | Fixed — Quantus runtime identity gate |
| #160655 | Batch not atomic | Fixed — `utility.batch_all` |
| #160708 | Password-file permission checks | Fixed — Unix owner-only required |
| #160716 | Legacy AES key alongside ciphertext | Already fixed (`e0be480`); residual: refuse re-persisting digests |
| #160737 | Wallet creation not atomic | Fixed — exclusive create / hard_link |
| #160748 | Ephemeral mnemonic strands funds | Fixed — require persisted mnemonic |
| #160754 | Transfer events unbound | Fixed — match from/amount/count |
| #160773 | Self-update without integrity check | Fixed — same-origin SHA-256 integrity (not signing; see update note) |
| #160791 | Unvalidated RPC token properties | Fixed — fail-closed decimals/symbol/ss58 |

## Medium (30/30 addressed)

| ID | Title | Outcome |
|----|-------|---------|
| #159340 | Version/nonce panics on decrypt | Fixed |
| #159469 | Exported mnemonic on stdout | Fixed — require `--output` (0o600) |
| #159662 | Storage pagination loop/overflow | Fixed |
| #159890 | Spent transfers reported available | Fixed |
| #159916 | Single-block over-limit abort | Fixed — offset pagination |
| #160052 | Duplicate signers | Fixed — sort+dedup |
| #160103 | Wormhole `--secret` argv | Fixed — `--secret-file` |
| #160105 | Secrets not zeroized after proof | Partially fixed — see zeroization scope note |
| #160110 | Unbounded Merkle depth | Fixed |
| #160591 | Wallet secrets retained | Partially fixed — see zeroization scope note |
| #160595 | Wallet name path escape | Fixed (with #160598 name validation) |
| #160625 | Unbounded tx-status waits | Fixed — deadlines |
| #160640 | Malformed pubkey panic | Fixed — `InvalidPublicKey` |
| #160652 | Token metadata / decimal format | Fixed — `checked_pow` + validation |
| #160656 | Transfer data / chain decimals | Fixed |
| #160660 | Removal missing member rank | Fixed — required `--min-rank` |
| #160667 | Recursive wormhole unfinalized | Fixed — finalized snapshots |
| #160674 | Delay conversion overflow | Fixed — checked helpers |
| #160697 | Circuit artifacts unauthenticated | Fixed — `manifest.json` SHA-256 |
| #160699 | Artifact symlink redirection | Fixed — refuse symlinks |
| #160700 | Build artifact publish races | Fixed — atomic publish |
| #160715 | Exhausting Argon2 params | Fixed — lock to generated profile |
| #160718 | Preimage AlreadyNoted substring | Fixed — verify on-chain |
| #160724 | WS URL credentials in diagnostics | Fixed — redact userinfo |
| #160732 | Transfer total wrap | Fixed — `checked_add` |
| #160734 | Batch vs call-count limit | Fixed — runtime `batched_calls_limit` |
| #160749 | Failed extrinsic reported verified | Fixed — failure-dominant |
| #160776 | Missing aggregate bypasses split | Fixed |
| #160777 | Offset not global across ranges | Fixed |
| #160783 | Public helpers panic on bad input | Fixed — fallible APIs |

## Low (11 Unreviewed — in scope)

| ID | Title | Status in this PR |
|----|-------|-------------------|
| #159905 | Byte-indexed address truncation on remote IDs | Open |
| #159911 | CLI transfer limit accepts values above documented 1000 | Open |
| #159917 | Fragile substring matching for limit-exceeded errors | Open |
| #160136 | Distribution invariant broken by u128 overflow | Open (related hardening via checked adds elsewhere) |
| #160585 | Password-file permits symlink targets / unbounded reads | Partial — mode/owner checks added (#160708); symlink/size bounds still open |
| #160678 | Malformed RPC header fields can panic CLI | Open |
| #160711 | Malformed wallet nonce panics during unlock | Open |
| #160744 | Unchecked RPC string slicing can crash system inspection | Open |
| #160760 | Unavailable home directories can panic | Open |
| #160789 | WalletManager lacks sync for concurrent FS ops | Partial — keystore process lock / create locks from High #160598/#160737 |
| #160800 | Proposal IDs decoded from key suffix without layout validation | Open |

### Excluded: 314 Low with `Validity: Invalid`
Out of scope per V12. No further triage required for merge of this PR.

### Opportunistic hardening (Invalid Lows — not audit blockers)
Some Invalid Lows were still tightened while adjacent to High/Medium work (e.g. block-list bounds, storage iterate cap, JSON numeric parsing, multisend dupes, metadata `checked_add`). These are optional defense-in-depth, not required to close the Unreviewed set.

## Info (2 Unreviewed)
- #160685 Bind deposits/votes to confirmed referendum index — informational
- #160730 Non-native leaves represented as native assets — informational

## Self-update integrity scope note (#160773)

The self-update SHA-256 check is same-origin integrity, not authenticity: the
expected hash is a sibling asset of the same GitHub release fetched over the
same TLS channel. It stops corruption and single-object substitution; it does
not stop an attacker who can write release assets or MITM TLS, since they
control both files. Upgrading to real authenticity means signing release
archives (e.g. `self_update`'s zipsign/ed25519 `signatures` feature with the
public key embedded in the binary), which requires release-pipeline changes
and is left as follow-up. The claim in the table above should not be read as
release signing.

## Zeroization scope note (#160105 / #160591)

Zeroization is enforced at the library boundary (`wormhole_lib::generate_proof`
wipes `input.secret` on all paths via drop guards; wallet decrypt buffers,
`WalletData`, and derived AES keys are wiped) and at the caller sites that were
tractable: hex-encoded secret strings in the multiround/dissolve flows,
`DissolveOutput` secrets (zeroize-on-drop, redacted `Debug`), prompted
mnemonics/seeds in `wallet import`/`from-seed`, seed copies inside
`WalletManager`, and password-file reads.

These items are still not *fully* closed, and cannot be with the current type
shapes: secrets are `Copy` arrays (`[u8; 32]`) and plain `String`s, so every
pass-by-value and reallocation can leave untracked copies on the stack or in
freed heap blocks (e.g. the expected-event tuples in the dissolve flow, and
`String` reallocations inside prompt libraries). Fully closing them would mean
migrating to non-`Copy` zeroize-on-drop wrapper types end to end, which is out
of scope for this PR. Treat the residual risk as: secrets may persist in
process memory until overwritten; they are never persisted or printed.

## CodeQL workflow narrowed (was: removed)

The CodeQL workflow was initially deleted in this PR because nearly all of its
alerts were noise in `#[cfg(test)]` modules and `examples/` (hard-coded test
keys, intentional diagnostic prints). Deleting it outright also removed the
repo's only first-party SAST (source-level taint analysis) and the
Actions-hygiene checks — `cargo audit` covers dependency CVEs only and clippy
is not a security analyzer — so the workflow is reinstated in narrowed form
instead:

- Default high-precision security query suite instead of the prior
  `security-and-quality` sweep (drops the quality-noise class).
- `paths-ignore: examples` so intentional example code stops generating
  alerts. Inline `mod tests` blocks cannot be path-excluded; the narrowed
  suite already skips most of what fired there.
- The `actions` language matrix (workflow hygiene rules) is kept as before.

## Breaking / UX changes callers should know

- `wallet import` / `from-seed`: no `--mnemonic` / `--seed` flags (stdin prompts)
- `--password` / `-p` rejected everywhere; use `--password-file`, env, or prompt
- `wallet create` / `import` / `from-seed` no longer silently use an empty password; prompt (with confirm), `--password-file`, or env; empty only via `--allow-empty-password`
- Wormhole: `--secret` → `--secret-file`; `collect-rewards --mnemonic` → `--mnemonic-file`
- `wallet export`: requires `--output` file (no stdout mnemonic dump)
- Tech collective remove: requires `--min-rank`
- Circuit artifacts: need a rebuild so `generated-bins/` is a real directory with `manifest.json` (symlink-style bins rejected)
- Circuit artifacts: `./generated-bins` in the current working directory is no longer trusted implicitly (the unsigned manifest lives in the directory it authenticates, so an untrusted checkout could ship a self-consistent artifact set). Local dev must opt in with `QUANTUS_BINS_DIR=./generated-bins`; installed binaries keep using `~/.quantus/generated-bins`
- `QuantusClient::new` rejects non-Quantus / incompatible runtimes (expects `specName=quantus-runtime`, the name the real runtime declares); `compatibility-check` connects ungated so it can diagnose rejected nodes
- Batch transfers use `batch_all` (atomic fail-all)

## Test plan

- [x] `cargo test --lib` (211 passed)
- [ ] Manual: `quantus wallet import --name x --mnemonic '...'` fails clap parse
- [ ] Manual: `quantus wallet create --name x --password secret` errors with guidance
- [ ] Manual: wallet dir/files are `0700`/`0600` after create
- [x] Manual: connect to wrong `specName` RPC fails (verified vs `wss://rpc.polkadot.io`); real node accepted (verified vs `wss://a2-heisenberg.quantus.cat`, spec 136/tx 3); `compatibility-check` reports INCOMPATIBLE for Polkadot
- [ ] Manual: `quantus update` refuses checksum mismatch (if exercising updater)
- [ ] Full circuit rebuild without `SKIP_CIRCUIT_BUILD` once for new `generated-bins` layout
- [ ] Smoke send / multisig create / wormhole prove against local node

## Commits

```
3d781aa fix(wallet): require an explicit password when creating wallets
ccc244a fix(cli): bound ranges and reject silent zero coercions
7f569f9 fix(bins): authenticate circuit artifacts and publish atomically
fdaee0c fix(cli): validate amounts delays ranks and fallible address helpers
06997c2 fix(wallet): zeroize secret material after encrypt and decrypt
8cd2d4c fix(wormhole): validate Merkle depth and prefer finalized snapshots
fbd38ed fix(wormhole): zeroize proof-generation secrets after use
fb5b36f fix(subsquid): harden exhaustive transfer queries and spent filtering
bcdab11 fix(batch): enforce runtime batched_calls_limit for batch size
12d3ff6 fix(rewards): use checked addition for indexer transfer totals
5015a2e fix(tx): bound transaction-status subscription waits
b7039e6 fix(storage): bound pagination against overflow and stuck cursors
1e9e910 fix(multisig): deduplicate signers before predict and threshold
0bec0ea fix(wallet): write exported mnemonics to a protected file
a710bf6 fix(wormhole): remove --secret argv and verify extrinsic failures
986c2cd fix(client): redact WebSocket URL credentials in diagnostics
95c1fc9 fix(wallet): return errors for malformed public keys
eeaefa7 fix(wallet): refuse to persist wallets with embedded AES key material
c5d3f2d fix(update): verify release archive SHA-256 before install
5fc7920 fix(wormhole): bind transfer events to from amount and count
304d6d5 fix(system): fail closed on invalid RPC token properties
a8051b1 fix(client): verify Quantus runtime identity at connect time
bfd228e fix(wallet): harden storage races and exclusive wallet creation
02c741a fix(wallet): authenticate address metadata and fail closed on migration
dfd96c0 fix(tx): stop unsafe nonce-bump retries on ambiguous errors
f111d9b fix(wormhole): require persisted mnemonic for HD secrets
0460883 fix(batch): use utility.batch_all for atomic transfers
27d8a9f fix(wallet): require restrictive password-file permissions
3bc368c fix(wallet): enforce owner-only keystore permissions
58b8780 fix(tx): fail when watched extrinsic is missing from block
e6dd668 fix(wallet): reject raw --password CLI credentials
d2ac243 fix(multisig): correlate MultisigCreated to creator and params
253c791 fix(wallet): skip malformed files when listing wallets
03dad4d fix(wallet): stop accepting mnemonic and seed via CLI flags
```
