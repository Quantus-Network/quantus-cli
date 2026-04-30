//! End-to-end wormhole SDK example.
//!
//! This is the *functional* counterpart to [`wormhole_sdk_usage.rs`]: it
//! actually moves coins on a live chain. Given a funded Dilithium wallet and a
//! reachable node, it runs the full wormhole loop:
//!
//! ```text
//!  1. derive a fresh wormhole address from a random secret
//!  2. signed deposit  -> balances.transfer_allow_death(wh_addr, amount)
//!  3. wait for inclusion + locate NativeTransferred event in the block
//!  4. parse_transfer_events                       -> TransferInfo
//!  5. fetch block header + ZK Merkle proof at a recent block
//!  6. compute_merkle_positions                    -> (siblings, positions)
//!  7. wormhole_lib::generate_proof                -> leaf proof bytes
//!  8. aggregate_proofs([leaf])                    -> agg.hex
//!  9. verify_aggregated_and_get_events            -> minted NativeTransferred
//! ```
//!
//! All helpers are the same ones consumed by `stress-test`. The example is
//! intentionally written against the public re-exports from `lib.rs` so that
//! it doubles as documentation of the SDK surface.
//!
//! Requirements:
//!  - A reachable Quantus node (default `ws://127.0.0.1:9944`). On a fresh dev node, run
//!    `quantus-node --dev --tmp` and create a developer wallet (e.g. `quantus-cli wallet
//!    create-developer crystal_alice`).
//!  - A funded wallet whose name + password you'll pass to this example.
//!  - The bundled circuit binaries — generated lazily on first use into
//!    `~/.quantus/generated-bins/` (or `$QUANTUS_BINS_DIR`).
//!
//! Run:
//!
//! ```bash
//! # default: alice on a local dev chain, deposit 5 DEV
//! cargo run --example wormhole_sdk_e2e -- \
//!     --node ws://127.0.0.1:9944 \
//!     --funder crystal_alice \
//!     --password '' \
//!     --amount 5
//!
//! # also keep generated proof files for inspection
//! cargo run --example wormhole_sdk_e2e -- \
//!     --funder crystal_alice --password '' --amount 5 --keep-files
//! ```
//!
//! The example prints each step's inputs / outputs so you can correlate them
//! with the chain state (subscan, `quantus block analyze ...`, etc.).

use std::{env, time::Duration};

use quantus_cli::{
	aggregate_proofs, bins,
	chain::{client::QuantusClient, quantus_subxt::api::wormhole},
	cli::{address_format::bytes_to_quantus_ss58, common::ExecutionMode, send::parse_amount},
	compute_merkle_positions, compute_wormhole_address, decode_full_leaf_data,
	error::{QuantusError, Result},
	get_zk_merkle_proof, parse_transfer_events, transfer, verify_aggregated_and_get_events,
	wallet::WalletManager,
	wormhole_lib::{
		self, ProofGenerationInput, NATIVE_ASSET_ID, SCALE_DOWN_FACTOR, VOLUME_FEE_BPS,
	},
	write_proof_file, NativeTransferred,
};
use rand::RngCore;
use subxt::{ext::codec::Encode, utils::H256};
use tempfile::TempDir;
use tokio::time::sleep;

/// How many recent blocks to scan for the inclusion event before giving up.
const INCLUSION_SCAN_BLOCKS: u32 = 60;
/// How long to wait between rescans while looking for the inclusion event.
const INCLUSION_POLL_INTERVAL_MS: u64 = 1_000;
/// Depth (best - depth) used as the "stable" proof block for the ZK Merkle
/// proof. Small enough that we don't wait for finality, large enough to
/// avoid most reorgs on a quiet dev chain.
const PROOF_BLOCK_DEPTH: u32 = 2;

#[derive(Debug)]
struct Args {
	node_url: String,
	funder: String,
	password: String,
	amount_str: String,
	keep_files: bool,
}

fn parse_args() -> Args {
	let mut node_url = "ws://127.0.0.1:9944".to_string();
	let mut funder = "crystal_alice".to_string();
	let mut password: Option<String> = None;
	let mut amount_str = "5".to_string();
	let mut keep_files = false;

	let mut it = env::args().skip(1);
	while let Some(a) = it.next() {
		match a.as_str() {
			"--node" => node_url = it.next().expect("--node requires a value"),
			s if s.starts_with("--node=") => node_url = s["--node=".len()..].to_string(),
			"--funder" => funder = it.next().expect("--funder requires a value"),
			s if s.starts_with("--funder=") => funder = s["--funder=".len()..].to_string(),
			"--password" => password = Some(it.next().expect("--password requires a value")),
			s if s.starts_with("--password=") =>
				password = Some(s["--password=".len()..].to_string()),
			"--amount" => amount_str = it.next().expect("--amount requires a value"),
			s if s.starts_with("--amount=") => amount_str = s["--amount=".len()..].to_string(),
			"--keep-files" => keep_files = true,
			"--help" | "-h" => {
				print_usage();
				std::process::exit(0);
			},
			other => {
				eprintln!("Unknown argument: {other}");
				print_usage();
				std::process::exit(2);
			},
		}
	}

	let password = password
		.or_else(|| env::var("QUANTUS_WALLET_PASSWORD").ok())
		.unwrap_or_default();

	Args { node_url, funder, password, amount_str, keep_files }
}

fn print_usage() {
	eprintln!(
		"Usage: cargo run --example wormhole_sdk_e2e -- [--node URL] \
		 [--funder NAME] [--password PASS] [--amount DEV] [--keep-files]\n\
		 \n\
		 Defaults: --node ws://127.0.0.1:9944  --funder crystal_alice  \
		 --password (empty)  --amount 5\n\
		 The password also falls back to $QUANTUS_WALLET_PASSWORD."
	);
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = parse_args();
	println!("Quantus wormhole SDK e2e example");
	println!("================================");
	println!("  node    : {}", args.node_url);
	println!("  funder  : {}", args.funder);
	println!("  amount  : {} DEV", args.amount_str);

	let client = QuantusClient::new(&args.node_url).await?;
	let amount_planck = parse_amount(&client, &args.amount_str).await?;
	println!("  planck  : {amount_planck}");

	// 1. wallet ----------------------------------------------------------------
	let wm = WalletManager::new()?;
	let wallet = wm.load_wallet(&args.funder, &args.password)?;
	let funder_kp = wallet.keypair;
	let funder_ss58 = funder_kp.to_account_id_ss58check();
	println!("  wallet  : {funder_ss58}");

	// 2. derive wormhole address from a random secret + random exit account ---
	let mut rng = rand::rng();
	let mut secret = [0u8; 32];
	rng.fill_bytes(&mut secret);
	let mut exit_account = [0u8; 32];
	rng.fill_bytes(&mut exit_account);

	let wh_addr =
		compute_wormhole_address(&secret).map_err(|e| QuantusError::Generic(e.message))?;
	let wh_ss58 = bytes_to_quantus_ss58(&wh_addr);
	println!();
	println!("[1/9] secret + addresses");
	println!("  secret      : 0x{}", hex::encode(secret));
	println!("  wh_addr     : 0x{} ({wh_ss58})", hex::encode(wh_addr));
	println!("  exit_account: 0x{}", hex::encode(exit_account));

	// 3. signed deposit --------------------------------------------------------
	println!();
	println!("[2/9] depositing {} planck -> wormhole address...", amount_planck);
	let tx_hash = transfer(
		&client,
		&funder_kp,
		&wh_ss58,
		amount_planck,
		None,
		ExecutionMode { finalized: false, wait_for_transaction: true },
	)
	.await?;
	println!("  deposit tx_hash: {:?}", tx_hash);

	// 4. find inclusion block + NativeTransferred event ------------------------
	println!();
	println!("[3/9] scanning recent blocks for NativeTransferred to {wh_ss58}...");
	let (block_hash, block_number, event) = wait_for_native_transferred(&client, &wh_addr).await?;
	println!("  found in block #{block_number} ({:?})", block_hash);
	println!("    transfer_count : {}", event.transfer_count);
	println!("    leaf_index     : {}", event.leaf_index);
	println!("    amount         : {} planck", event.amount);

	// 5. parse_transfer_events -------------------------------------------------
	println!();
	println!("[4/9] parse_transfer_events");
	let infos = parse_transfer_events(
		std::slice::from_ref(&event),
		std::slice::from_ref(&event.to),
		block_hash,
	)?;
	let info = infos.first().expect("one event in -> one info out");
	println!(
		"  TransferInfo: block={:?} count={} leaf={} amount={}",
		info.block_hash, info.transfer_count, info.leaf_index, info.amount
	);

	// 6. proof block + header + zk merkle proof --------------------------------
	// We want a stable block whose ZK trie already contains our leaf; it must
	// therefore be on or after the deposit's block. We also wait a few blocks
	// past the deposit so a tiny reorg won't invalidate the proof on us.
	println!();
	let target_best = block_number + PROOF_BLOCK_DEPTH;
	let best_number = wait_for_best_at_least(&client, target_best).await?;
	let proof_number = best_number.saturating_sub(PROOF_BLOCK_DEPTH).max(block_number);
	let proof_hash = fetch_block_hash(&client, proof_number).await?;
	let header = fetch_header(&client, proof_hash).await?;
	println!(
		"[5/9] proof block: #{proof_number} (best #{best_number}, depth {PROOF_BLOCK_DEPTH}) {:?}",
		proof_hash
	);

	let proof = get_zk_merkle_proof(&client, info.leaf_index, proof_hash).await?;
	let (siblings, positions) = compute_merkle_positions(&proof.siblings, proof.leaf_hash);
	println!("  zk root       : 0x{}", hex::encode(proof.root));
	println!("  leaf_hash     : 0x{}", hex::encode(proof.leaf_hash));
	println!("  siblings/levels: {}", siblings.len());

	// Decode the leaf to extract the quantized input amount the circuit
	// expects (raw_amount / SCALE_DOWN_FACTOR, capped to u32).
	let (_to_dec, _tc_dec, asset_id, raw_amount) = decode_full_leaf_data(&proof.leaf_data)?;
	assert_eq!(asset_id, NATIVE_ASSET_ID, "this example only handles native asset");
	let leaf_input_amount_quantized = (raw_amount / SCALE_DOWN_FACTOR) as u32;
	let output_amount =
		((leaf_input_amount_quantized as u64) * (10_000 - VOLUME_FEE_BPS as u64) / 10_000) as u32;
	println!(
		"  input(qz)={} output(qz)={} fee_bps={}",
		leaf_input_amount_quantized, output_amount, VOLUME_FEE_BPS
	);

	// 7. generate the leaf ZK proof -------------------------------------------
	println!();
	println!("[6/9] generating leaf ZK proof (CPU-heavy, can take 10-60s)...");
	let bins_dir = bins::ensure_bins_dir()?;
	let prover_bin = bins_dir.join("prover.bin");
	let common_bin = bins_dir.join("common.bin");

	let pgi = ProofGenerationInput {
		secret,
		transfer_count: event.transfer_count,
		wormhole_address: wh_addr,
		input_amount: leaf_input_amount_quantized,
		block_hash: header.block_hash,
		block_number: header.block_number,
		parent_hash: header.parent_hash,
		state_root: header.state_root,
		extrinsics_root: header.extrinsics_root,
		digest: header.digest.clone(),
		zk_tree_root: proof.root,
		zk_merkle_siblings: siblings,
		zk_merkle_positions: positions,
		exit_account_1: exit_account,
		exit_account_2: [0u8; 32],
		output_amount_1: output_amount,
		output_amount_2: 0,
		volume_fee_bps: VOLUME_FEE_BPS,
		asset_id: NATIVE_ASSET_ID,
	};

	let leaf_start = std::time::Instant::now();
	let leaf_result = wormhole_lib::generate_proof(&pgi, &prover_bin, &common_bin)
		.map_err(|e| QuantusError::Generic(format!("generate_proof: {}", e.message)))?;
	println!(
		"  leaf proof generated in {:.2}s ({} bytes)",
		leaf_start.elapsed().as_secs_f64(),
		leaf_result.proof_bytes.len()
	);

	// 8. write + aggregate -----------------------------------------------------
	println!();
	println!("[7/9] writing leaf proof + aggregating");
	let tmp = TempDir::new()
		.map_err(|e| QuantusError::Generic(format!("Failed to create temp dir: {e}")))?;
	let work_dir = if args.keep_files {
		let p = std::env::temp_dir().join(format!("quantus-sdk-e2e-{}", std::process::id()));
		std::fs::create_dir_all(&p)
			.map_err(|e| QuantusError::Generic(format!("Failed to create work dir {p:?}: {e}")))?;
		println!("  --keep-files: writing to {p:?}");
		p
	} else {
		tmp.path().to_path_buf()
	};

	let leaf_path = work_dir.join("leaf_0.hex");
	write_proof_file(leaf_path.to_str().unwrap(), &leaf_result.proof_bytes)
		.map_err(QuantusError::Generic)?;
	let agg_path = work_dir.join("agg.hex");
	let agg_start = std::time::Instant::now();
	aggregate_proofs(
		vec![leaf_path.to_string_lossy().into_owned()],
		agg_path.to_string_lossy().into_owned(),
	)
	.await?;
	println!("  aggregated in {:.2}s -> {:?}", agg_start.elapsed().as_secs_f64(), agg_path);

	// 9. verify + submit -------------------------------------------------------
	println!();
	println!("[8/9] verify_aggregated_and_get_events (off-chain verify + on-chain submit)");
	let verify_start = std::time::Instant::now();
	let (mint_block, mint_tx, transfers) =
		verify_aggregated_and_get_events(agg_path.to_str().unwrap(), &client).await?;
	println!("  verified+included in {:.2}s", verify_start.elapsed().as_secs_f64());
	println!("  mint block : {:?}", mint_block);
	println!("  mint tx    : {:?}", mint_tx);

	println!();
	println!("[9/9] minted NativeTransferred events:");
	if transfers.is_empty() {
		println!("  (none — verify_aggregated_proof did not emit any events?)");
	}
	for (i, ev) in transfers.iter().enumerate() {
		let to_ss58 = bytes_to_quantus_ss58(&ev.to.0);
		let to_match = if ev.to.0 == exit_account { " (== exit_account)" } else { "" };
		println!(
			"  [{i}] -> {} ({}){} amount={} planck transfer_count={} leaf_index={}",
			to_ss58,
			hex::encode(ev.to.0),
			to_match,
			ev.amount,
			ev.transfer_count,
			ev.leaf_index
		);
	}

	println!();
	println!("Done.");
	Ok(())
}

/// Small helper for the deposit's block header data needed by the prover.
struct HeaderBits {
	parent_hash: [u8; 32],
	state_root: [u8; 32],
	extrinsics_root: [u8; 32],
	block_number: u32,
	block_hash: [u8; 32],
	digest: Vec<u8>,
}

async fn current_best_number(client: &QuantusClient) -> Result<u32> {
	let best = client.get_latest_block().await?;
	let block = client
		.client()
		.blocks()
		.at(best)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("blocks().at(best): {e:?}")))?;
	Ok(block.header().number)
}

/// Block until the chain's best block reaches `target` (with a small timeout).
async fn wait_for_best_at_least(client: &QuantusClient, target: u32) -> Result<u32> {
	let start = std::time::Instant::now();
	loop {
		let best = current_best_number(client).await?;
		if best >= target {
			return Ok(best);
		}
		if start.elapsed() > Duration::from_secs(60) {
			return Err(QuantusError::Generic(format!(
				"Timed out waiting for best block #{target}, still at #{best} after 60s"
			)));
		}
		sleep(Duration::from_millis(500)).await;
	}
}

async fn fetch_block_hash(client: &QuantusClient, n: u32) -> Result<H256> {
	use jsonrpsee::core::client::ClientT;
	let h: Option<H256> = client
		.rpc_client()
		.request("chain_getBlockHash", [n])
		.await
		.map_err(|e| QuantusError::NetworkError(format!("chain_getBlockHash({n}): {e:?}")))?;
	h.ok_or_else(|| QuantusError::Generic(format!("Block #{n} has no hash")))
}

async fn fetch_header(client: &QuantusClient, hash: H256) -> Result<HeaderBits> {
	let block = client
		.client()
		.blocks()
		.at(hash)
		.await
		.map_err(|e| QuantusError::NetworkError(format!("blocks().at({hash:?}): {e:?}")))?;
	let header = block.header();
	Ok(HeaderBits {
		parent_hash: header.parent_hash.0,
		state_root: header.state_root.0,
		extrinsics_root: header.extrinsics_root.0,
		block_number: header.number,
		block_hash: hash.0,
		digest: header.digest.encode(),
	})
}

/// Polls recent blocks until it finds a `NativeTransferred` whose recipient
/// matches `wh_addr`, or runs out of blocks/time.
async fn wait_for_native_transferred(
	client: &QuantusClient,
	wh_addr: &[u8; 32],
) -> Result<(H256, u32, NativeTransferred)> {
	use jsonrpsee::core::client::ClientT;

	let start = std::time::Instant::now();
	let timeout = Duration::from_millis(
		(INCLUSION_POLL_INTERVAL_MS * INCLUSION_SCAN_BLOCKS as u64).max(60_000),
	);
	let mut last_seen_best: u32 = 0;

	loop {
		let best = client.get_latest_block().await?;
		let best_number = client
			.client()
			.blocks()
			.at(best)
			.await
			.map_err(|e| QuantusError::NetworkError(format!("blocks().at(best): {e:?}")))?
			.header()
			.number;
		let lower = best_number.saturating_sub(INCLUSION_SCAN_BLOCKS);
		let scan_from = last_seen_best.max(lower);

		for n in scan_from..=best_number {
			let hash: Option<H256> =
				client.rpc_client().request("chain_getBlockHash", [n]).await.map_err(|e| {
					QuantusError::NetworkError(format!("chain_getBlockHash({n}): {e:?}"))
				})?;
			let Some(block_hash) = hash else { continue };
			let events = match client.client().events().at(block_hash).await {
				Ok(e) => e,
				Err(_) => continue,
			};
			for ev in events.find::<wormhole::events::NativeTransferred>().flatten() {
				if &ev.to.0 == wh_addr {
					return Ok((block_hash, n, ev));
				}
			}
		}
		last_seen_best = best_number;

		if start.elapsed() > timeout {
			return Err(QuantusError::Generic(format!(
				"Timed out waiting for NativeTransferred to 0x{} after {:.1}s",
				hex::encode(wh_addr),
				start.elapsed().as_secs_f64()
			)));
		}
		sleep(Duration::from_millis(INCLUSION_POLL_INTERVAL_MS)).await;
	}
}
