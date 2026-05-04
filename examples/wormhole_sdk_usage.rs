//! End-to-end wormhole SDK example.
//!
//! Shows how a downstream crate (e.g. `stress-test`) consumes the wormhole
//! helpers re-exported from `quantus_cli`. The example is split into two
//! parts:
//!
//! 1. **Offline** — deterministic, no node required. Computes a wormhole address from a secret,
//!    decodes a SCALE-encoded `ZkLeaf`, exercises the proof-file round trip and demonstrates
//!    `IncludedAt`/`TransferInfo` formatting. Always runs.
//! 2. **Online (read-only)** — connects to a node and exercises *real* on-chain primitives without
//!    submitting anything: `at_best_block`, scans recent blocks for a real `NativeTransferred`
//!    event, runs `parse_transfer_events`, fetches the ZK Merkle proof via `get_zk_merkle_proof`,
//!    computes positions with `compute_merkle_positions` and decodes the leaf bytes with
//!    `decode_full_leaf_data`. The submission path (`submit_unsigned_verify_aggregated_proof`,
//!    `verify_aggregated_and_get_events`) is shown only as pseudocode — it requires a funded
//!    deposit + ZK proof generation, which [`wormhole_sdk_e2e.rs`](./wormhole_sdk_e2e.rs)
//!    demonstrates end-to-end. If the node is unreachable the example exits cleanly with hints; CI
//!    without a node still builds and runs it green.
//!
//! Typical full flow (for context, not executed here):
//!
//! ```text
//!  DEPOSIT (signed `balances.transfer_allow_death` to wormhole address)
//!         │
//!         ▼
//!  collect events ──► parse_transfer_events ──► Vec<TransferInfo>
//!         │
//!         ▼
//!  for each TransferInfo:
//!      get_zk_merkle_proof(client, block_hash, leaf_index) → siblings + positions
//!      wormhole_lib::generate_proof(...)                   → leaf proof bytes
//!         │
//!         ▼
//!  aggregate_proofs(leaf_files, "agg.hex")                 → aggregated proof file
//!         │
//!         ▼
//!  verify_aggregated_and_get_events("agg.hex", &client)
//!         │   (locally verifies + submits unsigned `verify_aggregated_proof`
//!         │    + waits for inclusion + collects NativeTransferred events)
//!         ▼
//!  Vec<NativeTransferred> with the minted amounts at the exit accounts
//! ```
//!
//! Run:
//! ```bash
//! cargo run --example wormhole_sdk_usage
//! cargo run --example wormhole_sdk_usage -- ws://127.0.0.1:9944
//! ```

use std::env;

use codec::Encode;
use quantus_cli::{
	// All wormhole helpers re-exported by `quantus_cli` for SDK use:
	at_best_block,
	chain::{client::QuantusClient, quantus_subxt::api::wormhole},
	compute_merkle_positions,
	compute_wormhole_address,
	decode_full_leaf_data,
	error::Result,
	get_zk_merkle_proof,
	parse_transfer_events,
	read_proof_file,
	wormhole_lib::{self, NATIVE_ASSET_ID},
	write_proof_file,
	IncludedAt,
	NativeTransferred,
	TransferInfo,
};
use subxt::utils::AccountId32 as SubxtAccountId;

/// How many recent blocks to scan when looking for an existing
/// `NativeTransferred` event. Keep this small to stay snappy on a fresh node.
const RECENT_BLOCKS_TO_SCAN: u32 = 200;

/// Tiny `--node <URL>` parser so we don't pull in clap for a single argument.
/// Also accepts a bare URL as the first positional argument for backwards
/// compatibility with `cargo run --example wormhole_sdk_usage -- ws://...`.
fn parse_node_arg() -> Option<String> {
	let mut args = env::args().skip(1);
	while let Some(a) = args.next() {
		match a.as_str() {
			"--node" => return args.next(),
			s if s.starts_with("--node=") => return Some(s["--node=".len()..].to_string()),
			s if s.starts_with("ws://") || s.starts_with("wss://") => return Some(s.to_string()),
			_ => continue,
		}
	}
	None
}

#[tokio::main]
async fn main() -> Result<()> {
	println!("Quantus wormhole SDK example");
	println!("============================");

	offline_demo()?;
	online_demo().await?;

	println!();
	println!("Done. See `examples/wormhole_sdk_usage.rs` for the full SDK API surface.");
	Ok(())
}

/// Deterministic, no-network demonstration of the wormhole helpers.
fn offline_demo() -> Result<()> {
	println!();
	println!("--- Offline ---");

	// 1) Address derivation.
	//
	// `compute_wormhole_address` is `Poseidon2(Poseidon2(secret))`. The first
	// hash is the "inner_hash" used by `quantus-node --rewards-inner-hash`;
	// the second hash is the unspendable account id where rewards land.
	let secret: [u8; 32] = [42u8; 32];
	let address = compute_wormhole_address(&secret).expect("compute_wormhole_address");
	println!("  secret  : 0x{}", hex::encode(secret));
	println!("  address : 0x{}", hex::encode(address));

	// 2) ZkLeaf decoding.
	//
	// The on-chain ZK trie stores SCALE-encoded `(AccountId32, u64, u32, u128)`
	// tuples. A real leaf comes from the `zkTree_getMerkleProof` RPC; here we
	// synthesise one to show the decode round trip.
	let leaf = (
		SubxtAccountId::from(address),
		7u64,                  // transfer_count
		NATIVE_ASSET_ID,       // asset_id
		1_234_567_890_000u128, // raw planck (12 decimals)
	);
	let leaf_bytes = leaf.encode();
	let (to, transfer_count, asset_id, raw_amount) = decode_full_leaf_data(&leaf_bytes)?;
	println!(
		"  leaf    : to=0x{} transfer_count={} asset_id={} raw_amount={} planck",
		hex::encode(to),
		transfer_count,
		asset_id,
		raw_amount,
	);
	let quantized = wormhole_lib::quantize_amount(raw_amount)
		.map_err(|e| quantus_cli::error::QuantusError::Generic(e.message))?;
	println!("            quantized (2 decimals): {quantized}");

	// 3) Proof file round trip. SDKs that already have proof bytes in memory can persist them with
	//    `write_proof_file` and pick them up later with `read_proof_file` (hex-encoded format
	//    compatible with the CLI).
	let tmp = std::env::temp_dir().join("wormhole-sdk-demo.hex");
	let dummy_proof: Vec<u8> = (0u8..32).collect();
	write_proof_file(tmp.to_str().unwrap(), &dummy_proof)
		.map_err(quantus_cli::error::QuantusError::Generic)?;
	let read_back = read_proof_file(tmp.to_str().unwrap())
		.map_err(quantus_cli::error::QuantusError::Generic)?;
	assert_eq!(read_back, dummy_proof);
	let _ = std::fs::remove_file(&tmp);
	println!("  proof   : write+read round trip OK ({} bytes)", read_back.len());

	// 4) IncludedAt Display impl.
	for v in [IncludedAt::Best, IncludedAt::Finalized] {
		println!("  IncludedAt::{:?} -> {}", v, v);
	}

	// 5) Building a TransferInfo by hand. In production this is produced by
	//    `parse_transfer_events(&[NativeTransferred], &[expected_addrs], block_hash)`.
	let info = TransferInfo {
		block_hash: subxt::utils::H256::zero(),
		transfer_count,
		amount: raw_amount,
		wormhole_address: SubxtAccountId::from(address),
		funding_account: SubxtAccountId::from([0u8; 32]),
		leaf_index: 0,
	};
	println!(
		"  TransferInfo: block={:?} transfer_count={} leaf_index={} amount={} planck",
		info.block_hash, info.transfer_count, info.leaf_index, info.amount,
	);

	// 6) Show that `NativeTransferred` is reachable from the SDK without drilling into
	//    `chain::quantus_subxt::api::wormhole::events::*`.
	let _zero_event_type: Option<NativeTransferred> = None;

	Ok(())
}

/// Online demonstration. Best-effort: if there's no node, log and return Ok(()).
async fn online_demo() -> Result<()> {
	println!();
	println!("--- Online ---");

	let node_url = parse_node_arg().unwrap_or_else(|| "ws://127.0.0.1:9944".to_string());
	println!("  Trying node: {node_url}");

	let client = match QuantusClient::new(&node_url).await {
		Ok(c) => c,
		Err(e) => {
			println!("  No node reachable ({e}); skipping online section.");
			print_online_recipe();
			return Ok(());
		},
	};

	let block = at_best_block(&client).await?;
	let header = block.header();
	let best_number = header.number;
	let best_hash = block.hash();
	println!("  Best block: #{} {:?}", best_number, best_hash);
	println!("  Parent     : {:?}", header.parent_hash);

	// Read-only on-chain demo: scan recent blocks for a real NativeTransferred,
	// then exercise parse_transfer_events + get_zk_merkle_proof + decode.
	match find_recent_native_transferred(&client, best_number).await? {
		Some((event_block_hash, event)) => {
			scan_real_event(&client, event_block_hash, event).await?;
		},
		None => {
			println!();
			println!(
				"  No NativeTransferred event found in the last {RECENT_BLOCKS_TO_SCAN} blocks."
			);
			println!(
				"  This is normal on a fresh dev chain. Run examples/wormhole_sdk_e2e.rs first"
			);
			println!("  (it submits a deposit + verify_aggregated_proof) to populate the chain.");
		},
	}

	print_online_recipe();
	Ok(())
}

/// Walk back from `best_number` and return the first `NativeTransferred` event
/// we find together with its block hash. `None` if none in the window.
async fn find_recent_native_transferred(
	client: &QuantusClient,
	best_number: u32,
) -> Result<Option<(subxt::utils::H256, NativeTransferred)>> {
	use jsonrpsee::core::client::ClientT;

	let lower = best_number.saturating_sub(RECENT_BLOCKS_TO_SCAN);
	println!();
	println!("  Scanning blocks #{lower}..=#{best_number} for NativeTransferred...");

	for n in (lower..=best_number).rev() {
		// chain_getBlockHash(n) -> H256
		let hash: Option<subxt::utils::H256> =
			client.rpc_client().request("chain_getBlockHash", [n]).await.map_err(|e| {
				quantus_cli::error::QuantusError::NetworkError(format!(
					"chain_getBlockHash({n}): {e:?}"
				))
			})?;
		let Some(block_hash) = hash else { continue };

		let events = match client.client().events().at(block_hash).await {
			Ok(e) => e,
			Err(_) => continue,
		};
		let first = events.find::<wormhole::events::NativeTransferred>().flatten().next();
		if let Some(ev) = first {
			println!("  Found NativeTransferred in block #{n} ({:?})", block_hash);
			return Ok(Some((block_hash, ev)));
		}
	}
	Ok(None)
}

/// Run the real-data section of the demo against a known on-chain event.
async fn scan_real_event(
	client: &QuantusClient,
	event_block_hash: subxt::utils::H256,
	event: NativeTransferred,
) -> Result<()> {
	let to_addr = event.to.0;
	let leaf_index = event.leaf_index;

	// 1) parse_transfer_events on the real event ---------------------------
	let infos: Vec<TransferInfo> =
		parse_transfer_events(&[event], &[SubxtAccountId::from(to_addr)], event_block_hash)?;
	let info = infos.first().expect("parse_transfer_events returned the input event");
	println!();
	println!("  parse_transfer_events ->");
	println!("    block_hash      : {:?}", info.block_hash);
	println!("    transfer_count  : {}", info.transfer_count);
	println!("    leaf_index      : {}", info.leaf_index);
	println!("    amount (planck) : {}", info.amount);
	println!("    funding_account : {:?}", info.funding_account);
	println!("    wormhole_addr   : 0x{}", hex::encode(to_addr));

	// 2) ZK Merkle proof -- the proof is taken at the *current* best block because the trie's root
	//    advances as new leaves are added; using the deposit's own block would give us a stale
	//    proof.
	let proof_block = client.get_latest_block().await?;
	let proof = match get_zk_merkle_proof(client, leaf_index, proof_block).await {
		Ok(p) => p,
		Err(e) => {
			println!("  get_zk_merkle_proof failed (zkTree RPC may be disabled): {e}");
			return Ok(());
		},
	};
	println!();
	println!("  get_zk_merkle_proof ->");
	println!("    leaf_index : {}", proof.leaf_index);
	println!("    leaf_hash  : 0x{}", hex::encode(proof.leaf_hash));
	println!("    root       : 0x{}", hex::encode(proof.root));
	println!("    depth      : {}", proof.depth);
	println!("    siblings   : {} levels", proof.siblings.len());

	// 3) Sort siblings + compute position hints (what the circuit expects).
	let (sorted, positions) = compute_merkle_positions(&proof.siblings, proof.leaf_hash);
	println!("  compute_merkle_positions ->");
	println!("    sorted siblings: {} levels", sorted.len());
	println!("    positions      : {:?}", positions.iter().take(8).copied().collect::<Vec<_>>());

	// 4) Decode the leaf bytes with the public helper.
	let (to, transfer_count, asset_id, raw_amount) = decode_full_leaf_data(&proof.leaf_data)?;
	let quantized = wormhole_lib::quantize_amount(raw_amount)
		.map_err(|e| quantus_cli::error::QuantusError::Generic(e.message))?;
	println!();
	println!("  decode_full_leaf_data ->");
	println!("    to             : 0x{}", hex::encode(to));
	println!("    transfer_count : {transfer_count}");
	println!("    asset_id       : {asset_id} (NATIVE_ASSET_ID = {NATIVE_ASSET_ID})");
	println!("    raw amount     : {raw_amount} planck");
	println!("    quantized      : {quantized} (2 decimals)");
	assert_eq!(to, to_addr, "leaf 'to' must match the event recipient");
	Ok(())
}

/// Show the canonical SDK recipe for the on-chain side without actually
/// broadcasting anything. Helpful both with and without a node.
fn print_online_recipe() {
	println!();
	println!("Typical SDK recipe (pseudo-code):");
	println!("  let bytes = std::fs::read(\"agg.hex\")?;");
	println!("  let bytes = hex::decode(bytes.trim_ascii())?;");
	println!("  let (included_at, block_hash, tx_hash) =");
	println!("      submit_unsigned_verify_aggregated_proof(&client, bytes).await?;");
	println!("  println!(\"included @ {{}} block={{:?}} tx={{:?}}\",");
	println!("           included_at, block_hash, tx_hash);");
	println!();
	println!("  // Or, with local verify + event collection:");
	println!("  let (block_hash, tx_hash, transfers) =");
	println!("      verify_aggregated_and_get_events(\"agg.hex\", &client).await?;");
	println!("  for ev in transfers {{");
	println!("      println!(\"  -> {{}} planck to {{}}\", ev.amount, ev.to.to_ss58check());");
	println!("  }}");
}
