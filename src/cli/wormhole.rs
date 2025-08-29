use crate::{
	chain::{client::QuantusClient, quantus_subxt},
	cli::{
		progress_spinner::wait_for_tx_confirmation,
		send::{
			format_balance_with_symbol, get_balance, get_chain_properties,
			parse_amount_with_decimals, validate_and_format_amount,
		},
		storage::{get_storage_at_block_raw, get_storage_raw},
	},
	error::Result,
	log_info, log_print, log_success, log_verbose,
};
use clap::Subcommand;
use codec::{Decode, Encode};
use colored::Colorize;
use dilithium_crypto::traits::WormholeAddress;
use hex;
use poseidon_resonance::PoseidonHasher;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use serde::Serialize;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	twox_128, Bytes, Hasher,
};

use sp_runtime::traits::IdentifyAccount;
use sp_state_machine::read_proof_check;
use sp_storage::StorageKey;
use sp_trie::StorageProof;
use trie_db::{
	node::{Node, NodeHandle},
	NodeCodec, TrieLayout,
};

#[derive(Debug, Serialize)]
struct TransferProofBundle {
	transfer_count: u64,
	state_root: String,         // hex (no 0x)
	storage_proof: Vec<String>, // hex-encoded nodes (no 0x)
	indices: Vec<usize>,        // byte offsets in hex-string space, for node hashes
}

/// Wormhole commands
#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
	/// Generate a new wormhole address and secret
	GenerateAddress,

	/// Spend funds from a wormhole address
	Spend {
		/// The hex-encoded secret key for the wormhole address
		#[arg(long)]
		secret: String,

		/// Recipient's on-chain address
		#[arg(short, long)]
		to: String,

		/// Amount to send (e.g., "10", "10.5", "0.0001")
		#[arg(short, long)]
		amount: String,

		/// Wallet name to sign the bridge transaction
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,
	},
	/// Generate transfer proof data (for testing purposes)
	GenerateProof {
		/// The hex-encoded secret key for the wormhole address
		#[arg(long)]
		secret: String,

		/// Amount to send (e.g., "10", "10.5", "0.0001")
		#[arg(short, long)]
		amount: String,

		/// Wallet name to sign the bridge transaction
		#[arg(short, long)]
		from_wallet: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Optional tip amount to prioritize the transaction (e.g., "1", "0.5")
		#[arg(long)]
		tip: Option<String>,
	},
}

/// Handle wormhole commands
pub async fn handle_wormhole_command(command: WormholeCommands, node_url: &str) -> Result<()> {
	match command {
		WormholeCommands::GenerateAddress => {
			log_print!("Generating new wormhole address...");

			let wormhole_pair = WormholePair::generate_new().map_err(|e| {
				crate::error::QuantusError::Generic(format!("Wormhole generation error: {:?}", e))
			})?;

			// The on-chain address for funding MUST be the unspendable account derived
			// from the secret key. The ZK proof verifies transfers to this address.
			let wormhole_address = WormholeAddress(wormhole_pair.address);
			let unspendable_account: AccountId32 = wormhole_address.into_account();

			log_print!("{}", "XXXXXXXXXXXXXXX Quantus Wormhole Details XXXXXXXXXXXXXXXXX".yellow());
			log_print!(
				"{}: {}",
				"Wormhole Address account ID".green(),
				unspendable_account.to_ss58check().bright_cyan()
			);
			log_print!(
				"{}: 0x{}",
				"Wormhole Address".green(),
				hex::encode(wormhole_pair.address).bright_cyan()
			);
			log_print!(
				"{}: 0x{}",
				"Secret Key      ".green(),
				hex::encode(wormhole_pair.secret).bright_cyan()
			);
			log_print!(
				"{}",
				"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".yellow()
			);

			log_success!("Wormhole address generated successfully!");
		},
		WormholeCommands::Spend {
			secret: _,
			to: _,
			amount: _,
			from: _,
			password: _,
			password_file: _,
		} => {
			log_print!("🚀 Initiating wormhole spend...");
		},
		WormholeCommands::GenerateProof {
			secret,
			amount,
			from_wallet,
			password,
			password_file,
			tip,
		} => {
			// Create quantus chain client
			let quantus_client = QuantusClient::new(node_url).await?;
			// Parse and validate the amount
			let (amount, _) = validate_and_format_amount(&quantus_client, &amount).await?;
			// Get password securely for decryption
			log_verbose!("📦 Using wallet: {}", from_wallet.bright_blue().bold());
			let keypair =
				crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;
			let from = keypair.to_account_id_32();
			// log the funding account as a bytes array
			log_print!(
				"Funding account address (bytes): {:?}",
				<sp_runtime::AccountId32 as AsRef<[u8]>>::as_ref(&from)
			);

			// Get account information
			let from_account_id = keypair.to_account_id_ss58check();
			let balance = get_balance(&quantus_client, &from_account_id).await?;

			// Get formatted balance with proper decimals
			let formatted_balance = format_balance_with_symbol(&quantus_client, balance).await?;
			log_verbose!("💰 Current balance: {}", formatted_balance.bright_yellow());

			if balance < amount {
				return Err(crate::error::QuantusError::InsufficientBalance {
					available: balance,
					required: amount,
				});
			}
			log_print!("Generating new transfer proof...");
			let secret_bytes: [u8; 32] = hex::decode(secret.trim_start_matches("0x"))
				.map_err(|e| {
					crate::error::QuantusError::Generic(format!("Hex decode error: {:?}", e))
				})?
				.try_into()
				.map_err(|_| {
					crate::error::QuantusError::Generic("Secret must be 32 bytes".to_string())
				})?;
			let wormhole_pair = WormholePair::generate_pair_from_secret(&secret_bytes);
			let wormhole_address = WormholeAddress(wormhole_pair.address);
			let unspendable_account = wormhole_address.into_account();
			log_print!(
				"Derived unspendable account address (bytes): {:?}",
				<sp_runtime::AccountId32 as AsRef<[u8]>>::as_ref(&unspendable_account)
			);
			let unspendable_account_id_bytes: [u8; 32] = *unspendable_account.as_ref();
			let unspendable_account_subxt =
				subxt::ext::subxt_core::utils::AccountId32::from(unspendable_account_id_bytes);
			// Submit transaction
			// Create the transfer call using static API from quantus_subxt
			let transfer_call = quantus_subxt::api::tx().balances().transfer_allow_death(
				subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_subxt.clone()),
				amount,
			);

			// Parse tip amount if provided
			let tip_amount = if let Some(tip_str) = &tip {
				// Get chain properties for proper decimal parsing
				let (_, decimals) = get_chain_properties(&quantus_client).await?;
				parse_amount_with_decimals(tip_str, decimals).ok()
			} else {
				None
			};

			let tip_to_use = tip_amount.unwrap_or(10_000_000_000); // Use default 10 DEV

			// Construct the storage key to fetch the transfer count
			let pallet = "Balances".to_string();
			let name = "TransferCount".to_string();
			let mut storage_key = twox_128(pallet.as_bytes()).to_vec();
			storage_key.extend(&twox_128(name.as_bytes()));

			// Construct the storage key to fetch the transfer count
			let latest_block_hash = quantus_client.get_latest_block().await?;
			let transfer_count_previous =
				get_transfer_count(&quantus_client, &storage_key, &latest_block_hash).await?;

			// Submit the transaction and wait for finalization
			let hash = crate::cli::common::submit_transaction(
				&quantus_client,
				&keypair,
				transfer_call,
				Some(tip_to_use),
			)
			.await?;
			log_verbose!("Transaction submitted with hash: 0x{}", hex::encode(hash));
			wait_for_tx_confirmation(quantus_client.client(), hash).await?;
			let tx_block_hash = quantus_client.get_latest_block().await?;
			log_info!("✅ Transaction confirmed and finalized on chain at block {}", tx_block_hash);
			let transfer_count =
				get_transfer_count(&quantus_client, &storage_key, &tx_block_hash).await?;
			log_verbose!("Transfer count range: {} - {}", transfer_count_previous, transfer_count);

			let mut correct_storage_key = Vec::<u8>::new();
			let mut correct_leaf_hash = [0u8; 32];
			let mut matched_count: Option<u64> = None;

			let pallet_prefix = twox_128("Balances".as_bytes());
			let storage_prefix = twox_128("TransferProof".as_bytes());
			let storage_key_prefix = [&pallet_prefix[..], &storage_prefix[..]].concat();

			for count in transfer_count_previous..transfer_count {
				let computed_leaf_hash =
					compute_transfer_proof_leaf(count, &from, &unspendable_account, amount);
				let storage_key = [&storage_key_prefix[..], computed_leaf_hash.as_ref()].concat();
				let result = get_storage_raw(&quantus_client, storage_key.to_vec()).await?;
				if result.is_some() {
					correct_storage_key = storage_key;
					correct_leaf_hash = computed_leaf_hash;
					matched_count = Some(count);
					log_success!(
						"🍀 Found matching storage key: {:?} for transfer proof with leaf hash: {:?} for transfer count {:?}",
						hex::encode(&correct_storage_key),
						hex::encode(correct_leaf_hash),
						count
					);
					break;
				};
			}
			if correct_storage_key.is_empty() || correct_leaf_hash == [0u8; 32] {
				return Err(crate::error::QuantusError::Generic(
					"🍀 No matching storage key / leaf hash found for transfer proof".to_string(),
				));
			}
			let proof = quantus_client
				.get_storage_proof_by_keys(
					vec![StorageKey(correct_storage_key.clone())],
					Some(tx_block_hash),
				)
				.await?;
			let proof_as_u8: Vec<Vec<u8>> =
				proof.proof.iter().map(|bytes: &Bytes| bytes.0.clone()).collect();
			let (leaf_checked, last_idx) =
				check_leaf(&correct_leaf_hash, proof_as_u8[proof_as_u8.len() - 1].clone());
			let check_string = if leaf_checked { "✅" } else { "⚔️" };
			log_verbose!("🍀 Leaf check: {check_string}");
			tree_structure_check(&proof_as_u8)?;
			let header = quantus_client.get_block_header(tx_block_hash).await?;
			let state_root = header["stateRoot"].as_str().unwrap();
			// remove the 0x prefix
			let state_root = &state_root[2..];
			let state_root_bytes = hex::decode(state_root).unwrap();
			let state_root_array: [u8; 32] =
				state_root_bytes.try_into().expect("State root must be 32 bytes");
			let state_root: subxt::utils::H256 = state_root_array.into();

			// Build the vectors used in-circuit and capture indices
			let (storage_proof, indices) =
				prepare_proof_for_circuit(proof_as_u8.clone(), hex::encode(state_root), last_idx);

			// Verify the proof against the runtime (safety)
			let expected_value = ().encode();
			let items = vec![correct_storage_key.clone()];
			let storage_proof_typed = StorageProof::new(proof_as_u8.clone());
			let result = read_proof_check::<PoseidonHasher, &Vec<Vec<u8>>>(
				state_root,
				storage_proof_typed,
				&items,
			);

			match result {
				Ok(map) => match map.get(&correct_storage_key) {
					Some(Some(value)) if value == &expected_value => {
						log_print!(
							"Proof verified for key {:?}",
							hex::encode(&correct_storage_key)
						);
						let data = TransferProofBundle {
							transfer_count: matched_count.unwrap(),
							state_root: hex::encode(state_root),
							storage_proof,
							indices,
						};
						// pretty print the TransferProofBundle
						log_print!("🍀 TransferProofBundle: {:?}", data);
					},
					other =>
						return Err(crate::error::QuantusError::Generic(format!(
							"Unexpected proof map result: {:?}",
							other
						))),
				},
				Err(e) =>
					return Err(crate::error::QuantusError::Generic(format!(
						"Failed to check proof: {:?}",
						e
					))),
			}
		},
	}
	Ok(())
}

async fn get_transfer_count(
	quantus_client: &QuantusClient,
	storage_key: &[u8],
	block_hash: &subxt::utils::H256,
) -> Result<u64> {
	let result =
		get_storage_at_block_raw(quantus_client, storage_key.to_vec(), *block_hash).await?;
	let value_bytes = result.ok_or_else(|| {
		crate::error::QuantusError::Generic("TransferCount not found in storage.".to_string())
	})?;
	let transfer_count = u64::decode(&mut &value_bytes[..]).unwrap();
	Ok(transfer_count)
}

pub fn compute_transfer_proof_leaf(
	tx_count: u64,
	from: &AccountId32,
	to: &AccountId32,
	amount: u128,
) -> [u8; 32] {
	// Step 1: Encode the key components into a single byte vector
	let mut key_bytes = Vec::new();
	key_bytes.extend_from_slice(&tx_count.encode());
	key_bytes.extend_from_slice(&from.encode());
	key_bytes.extend_from_slice(&to.encode());
	key_bytes.extend_from_slice(&amount.encode());
	// Step 2: Hash the concatenated bytes using PoseidonHasher
	PoseidonHasher::hash_storage::<AccountId32>(&key_bytes)
}

// Function to check that the 24 byte suffix of the leaf hash is the last [-32, -8] bytes of the
// leaf node
pub fn check_leaf(leaf_hash: &[u8; 32], leaf_node: Vec<u8>) -> (bool, usize) {
	let hash_suffix = &leaf_hash[8..32];
	let mut last_idx = 0usize;
	let mut found = false;

	for i in 0..=leaf_node.len().saturating_sub(hash_suffix.len()) {
		if &leaf_node[i..i + hash_suffix.len()] == hash_suffix {
			last_idx = i;
			found = true;
			break;
		}
	}

	log_verbose!(
		"Checking leaf hash suffix: {:?} in leaf_node at index: {:?}",
		hex::encode(hash_suffix),
		last_idx
	);
	log_verbose!("leaf_node: {:?}", hex::encode(leaf_node.clone()));

	(found, (last_idx * 2).saturating_sub(16))
}

pub fn tree_structure_check(proof: &[Vec<u8>]) -> Result<()> {
	for (i, node_data) in proof.iter().enumerate() {
		let node_hash = <PoseidonHasher as Hasher>::hash(node_data);
		match <sp_trie::LayoutV1<PoseidonHasher> as TrieLayout>::Codec::decode(node_data) {
			Ok(node) => match &node {
				Node::Empty => log_verbose!("Proof node {}: Empty", i),
				Node::Leaf(partial, value) => {
					let nibbles: Vec<u8> = partial.right_iter().collect();
					log_verbose!(
						"Proof node {}: Leaf, partial: {:?}, value: {:?} hash: {:?} bytes: {:?}",
						i,
						hex::encode(&nibbles),
						value,
						node_hash,
						hex::encode(node_data)
					);
				},
				Node::Extension(partial, _) => {
					let nibbles: Vec<u8> = partial.right_iter().collect();
					log_verbose!(
						"Proof node {}: Extension, partial: {:?} hash: {:?} bytes: {:?}",
						i,
						hex::encode(&nibbles),
						node_hash,
						hex::encode(node_data)
					);
				},
				Node::Branch(children, value) => {
					log_verbose!(
						"Proof node {}: Branch, value: {:?} hash: {:?} bytes: {:?}",
						i,
						value,
						node_hash,
						hex::encode(node_data)
					);
					for (j, child) in children.iter().enumerate() {
						if let Some(child) = child {
							log_verbose!("  Child {}: {:?}", j, child);
						}
					}
				},
				Node::NibbledBranch(partial, children, value) => {
					let nibbles: Vec<u8> = partial.right_iter().collect();
					let children = children
						.iter()
						.filter_map(|x| {
							x.as_ref().map(|val| match val {
								NodeHandle::Hash(h) => hex::encode(h),
								NodeHandle::Inline(i) => hex::encode(i),
							})
						})
						.collect::<Vec<String>>();
					log_verbose!(
                        "Proof node {}: NibbledBranch, partial: {:?}, value: {:?}, children: {:?} hash: {:?} bytes: {:?}",
                        i,
                        hex::encode(&nibbles),
                        value,
                        children,
                        node_hash,
                        hex::encode(node_data)
                    );
				},
			},
			Err(e) => log_verbose!("Failed to decode proof node {}: {:?}", i, e),
		}
	}
	Ok(())
}

fn prepare_proof_for_circuit(
	proof: Vec<Vec<u8>>,
	state_root: String,
	last_idx: usize,
) -> (Vec<String>, Vec<usize>) {
	let mut hashes = Vec::<String>::new();
	let mut bytes = Vec::<String>::new();
	let mut parts = Vec::<(String, String)>::new();
	let mut storage_proof = Vec::<String>::new();
	for node_data in proof.iter() {
		let hash = hex::encode(<PoseidonHasher as Hasher>::hash(node_data));
		let node_bytes = hex::encode(node_data);
		if hash == state_root {
			storage_proof.push(node_bytes);
		} else {
			// don't put the hash in if it is the root
			hashes.push(hash);
			bytes.push(node_bytes.clone());
		}
	}

	log_verbose!("Finished constructing bytes and hashes vectors {:?} {:?}", bytes, hashes);

	let mut ordered_hashes = Vec::<String>::new();
	let mut indices = Vec::<usize>::new();

	while !hashes.is_empty() {
		for i in (0..hashes.len()).rev() {
			let hash = hashes[i].clone();
			if let Some(last) = storage_proof.last() {
				if let Some(index) = last.find(&hash) {
					let (left, right) = last.split_at(index);
					indices.push(index);
					parts.push((left.to_string(), right.to_string()));
					storage_proof.push(bytes[i].clone());
					ordered_hashes.push(hash.clone());
					hashes.remove(i);
					bytes.remove(i);
				}
			}
		}
	}
	indices.push(last_idx);

	// iterate through the storage proof, printing the size of each.
	for (i, node) in storage_proof.iter().enumerate() {
		println!("Storage proof node {}: {} bytes", i, (node.len() / 16));
	}

	log_verbose!(
		"Storage proof generated: {:?} {:?} {:?} {:?}",
		&storage_proof,
		parts,
		ordered_hashes,
		indices
	);

	for (i, _) in storage_proof.iter().enumerate() {
		if i == parts.len() {
			break;
		}
		let part = parts[i].clone();
		let hash = ordered_hashes[i].clone();
		if part.1[..64] != hash {
			panic!("storage proof index incorrect {:?} != {:?}", part.1, hash);
		} else {
			log_verbose!("storage proof index correct: {:?}", part.0.len());
		}
	}

	(storage_proof, indices)
}
