use crate::{
	chain::{
		client::{ChainConfig, QuantusClient},
		quantus_subxt as quantus_node,
		quantus_subxt::api::balances,
	},
	cli::common::submit_transaction,
	log_print, log_success, log_verbose,
	wallet::QuantumKeyPair,
};
use anyhow::anyhow;
use clap::Subcommand;
use plonky2::plonk::{circuit_data::CircuitConfig, proof::ProofWithPublicInputs};
use qp_poseidon::PoseidonHasher;
use qp_wormhole_circuit::{
	inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs},
	nullifier::Nullifier,
};
use qp_wormhole_prover::WormholeProver;
use qp_zk_circuits_common::utils::{BytesDigest, Digest};
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	Hasher,
};
use subxt::{
	backend::legacy::rpc_methods::{Bytes, ReadProof},
	blocks::Block,
	ext::{
		codec::Encode,
		jsonrpsee::{core::client::ClientT, rpc_params},
	},
	utils::{to_hex, AccountId32 as SubxtAccountId},
	OnlineClient,
};

#[derive(Subcommand, Debug)]
pub enum WormholeCommands {
	/// Generate a wormhole proof
	Generate {
		/// Secret (32-byte hex string)
		#[arg(long)]
		secret: String,

		/// Funding amount to transfer
		#[arg(long)]
		amount: u128,

		/// Exit account (where funds will be withdrawn)
		#[arg(long)]
		exit_account: String,

		/// Wallet name to fund from
		#[arg(short, long)]
		from: String,

		/// Password for the wallet
		#[arg(short, long)]
		password: Option<String>,

		/// Read password from file
		#[arg(long)]
		password_file: Option<String>,

		/// Output file for the proof (default: proof.hex)
		#[arg(short, long, default_value = "proof.hex")]
		output: String,
	},
}

pub async fn handle_wormhole_command(
	command: WormholeCommands,
	node_url: &str,
) -> crate::error::Result<()> {
	match command {
		WormholeCommands::Generate {
			secret,
			amount,
			exit_account,
			from,
			password,
			password_file,
			output,
		} =>
			generate_proof(
				secret,
				amount,
				exit_account,
				from,
				password,
				password_file,
				output,
				node_url,
			)
			.await,
	}
}

async fn generate_proof(
	secret_hex: String,
	funding_amount: u128,
	exit_account_str: String,
	from_wallet: String,
	password: Option<String>,
	password_file: Option<String>,
	output_file: String,
	node_url: &str,
) -> crate::error::Result<()> {
	log_print!("Generating wormhole proof...");

	// Parse secret
	let secret_bytes = hex::decode(secret_hex.trim_start_matches("0x"))
		.map_err(|e| crate::error::QuantusError::Generic(format!("Invalid secret hex: {}", e)))?;
	if secret_bytes.len() != 32 {
		return Err(crate::error::QuantusError::Generic(
			"Secret must be exactly 32 bytes".to_string(),
		));
	}
	let secret_array: [u8; 32] = secret_bytes
		.try_into()
		.map_err(|_| crate::error::QuantusError::Generic("Failed to convert secret".to_string()))?;
	let secret: BytesDigest = secret_array.try_into().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to convert secret: {:?}", e))
	})?;

	// Parse exit account
	let exit_account_id = if exit_account_str.starts_with("0x") {
		let exit_account_bytes = hex::decode(&exit_account_str[2..]).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid exit account hex: {}", e))
		})?;
		if exit_account_bytes.len() != 32 {
			return Err(crate::error::QuantusError::Generic(
				"Exit account must be 32 bytes".to_string(),
			));
		}
		SubxtAccountId(exit_account_bytes.try_into().map_err(|_| {
			crate::error::QuantusError::Generic("Failed to convert exit account".to_string())
		})?)
	} else {
		// Assume it's a wallet name, resolve it
		let resolved = crate::cli::common::resolve_address(&exit_account_str)?;
		let account_id = AccountId32::from_ss58check(&resolved).map_err(|e| {
			crate::error::QuantusError::Generic(format!("Invalid SS58 address: {}", e))
		})?;
		let bytes: [u8; 32] = account_id.into();
		SubxtAccountId(bytes)
	};

	// Load keypair
	let keypair = crate::wallet::load_keypair_from_wallet(&from_wallet, password, password_file)?;

	// Connect to node
	let quantus_client = QuantusClient::new(node_url)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(format!("Failed to connect: {}", e)))?;
	let client = quantus_client.client();

	log_verbose!("Connected to node");

	let funding_account = AccountId32::new(PoseidonHasher::hash(keypair.public_key.as_ref()).0);

	// Generate unspendable account
	let unspendable_account =
		qp_wormhole_circuit::unspendable_account::UnspendableAccount::from_secret(secret)
			.account_id;
	let unspendable_account_bytes_digest =
		qp_zk_circuits_common::utils::digest_felts_to_bytes(unspendable_account);
	let unspendable_account_bytes: [u8; 32] = unspendable_account_bytes_digest
		.as_ref()
		.try_into()
		.expect("BytesDigest is always 32 bytes");
	let unspendable_account_id = SubxtAccountId(unspendable_account_bytes);

	log_verbose!("Unspendable account: {:?}", &unspendable_account_id);
	log_verbose!("Exit account: {:?}", &exit_account_id);

	// Transfer to unspendable account
	let transfer_tx = quantus_node::api::tx().balances().transfer_keep_alive(
		subxt::ext::subxt_core::utils::MultiAddress::Id(unspendable_account_id.clone()),
		funding_amount,
	);

	log_verbose!("Submitting transfer to unspendable account...");

	let blocks = at_best_block(&quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let block_hash_pre = blocks.hash();

	let storage_api = client.storage().at(block_hash_pre);
	let transfer_count_previous = storage_api
		.fetch(&quantus_node::api::storage().balances().transfer_count())
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?
		.unwrap_or_default();

	let quantum_keypair = QuantumKeyPair {
		public_key: keypair.public_key.clone(),
		private_key: keypair.private_key.clone(),
	};

	submit_transaction(&quantus_client, &quantum_keypair, transfer_tx, None)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let blocks = at_best_block(&quantus_client)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let block_hash = blocks.hash();

	log_success!("Transfer included in block: {:?}", block_hash);

	let events_api = client
		.events()
		.at(block_hash)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let event = events_api
		.find::<balances::events::TransferProofStored>()
		.next()
		.ok_or_else(|| {
			crate::error::QuantusError::Generic("No TransferProofStored event found".to_string())
		})?
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let storage_api = client.storage().at(block_hash);
	let transfer_count = storage_api
		.fetch(&quantus_node::api::storage().balances().transfer_count())
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?
		.unwrap_or_default();

	if transfer_count <= transfer_count_previous {
		return Err(crate::error::QuantusError::Generic(
			"Transfer count was not incremented".to_string(),
		));
	}

	// Get storage proof
	let leaf_hash = qp_poseidon::PoseidonHasher::hash_storage::<AccountId32>(
		&(event.transfer_count, event.source.clone(), event.dest.clone(), event.funding_amount)
			.encode(),
	);
	let proof_address = quantus_node::api::storage().balances().transfer_proof((
		event.transfer_count,
		event.source.clone(),
		event.dest.clone(),
		event.funding_amount,
	));
	let mut final_key = proof_address.to_root_bytes();
	final_key.extend_from_slice(&leaf_hash);
	let val = storage_api
		.fetch_raw(final_key.clone())
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	if val.is_none() {
		return Err(crate::error::QuantusError::Generic("Storage key not found".to_string()));
	}

	let proof_params = rpc_params![vec![to_hex(&final_key)], block_hash];
	let read_proof: ReadProof<sp_core::H256> = quantus_client
		.rpc_client()
		.request("state_getReadProof", proof_params)
		.await
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let header = blocks.header();

	let state_root = BytesDigest::try_from(header.state_root.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let parent_hash = BytesDigest::try_from(header.parent_hash.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let extrinsics_root = BytesDigest::try_from(header.extrinsics_root.as_bytes())
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let digest =
		header.digest.encode().try_into().map_err(|_| {
			crate::error::QuantusError::Generic("Failed to encode digest".to_string())
		})?;

	let block_number = header.number;

	// Prepare storage proof
	let processed_storage_proof =
		prepare_proof_for_circuit(read_proof.proof, hex::encode(header.state_root.0), leaf_hash)
			.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let inputs = CircuitInputs {
		private: PrivateCircuitInputs {
			secret,
			transfer_count: event.transfer_count,
			funding_account: BytesDigest::try_from(funding_account.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			storage_proof: processed_storage_proof,
			unspendable_account: Digest::from(unspendable_account).into(),
			state_root,
			extrinsics_root,
			digest,
		},
		public: PublicCircuitInputs {
			funding_amount,
			nullifier: Nullifier::from_preimage(secret, event.transfer_count).hash.into(),
			exit_account: BytesDigest::try_from(exit_account_id.as_ref() as &[u8])
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			block_hash: BytesDigest::try_from(block_hash.as_ref())
				.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?,
			parent_hash,
			block_number,
		},
	};

	log_verbose!("Generating ZK proof...");
	let config = CircuitConfig::standard_recursion_config();
	let prover = WormholeProver::new(config);
	let prover_next = prover
		.commit(&inputs)
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;
	let proof: ProofWithPublicInputs<_, _, 2> = prover_next.prove().map_err(|e| {
		crate::error::QuantusError::Generic(format!("Proof generation failed: {}", e))
	})?;

	let public_inputs = PublicCircuitInputs::try_from(&proof)
		.map_err(|e| crate::error::QuantusError::Generic(e.to_string()))?;

	let proof_hex = hex::encode(proof.to_bytes());
	std::fs::write(&output_file, proof_hex).map_err(|e| {
		crate::error::QuantusError::Generic(format!("Failed to write proof: {}", e))
	})?;

	log_success!("Proof generated successfully!");
	log_success!("Output: {}", output_file);
	log_verbose!("Public inputs: {:?}", public_inputs);

	Ok(())
}

async fn at_best_block(
	quantus_client: &QuantusClient,
) -> anyhow::Result<Block<ChainConfig, OnlineClient<ChainConfig>>> {
	let best_block = quantus_client.get_latest_block().await?;
	let block = quantus_client.client().blocks().at(best_block).await?;
	Ok(block)
}

// Utility functions from proof-utils.rs
fn hash_node_with_poseidon_padded(node_bytes: &[u8]) -> [u8; 32] {
	use qp_poseidon_core::{hash_padded_bytes, FIELD_ELEMENT_PREIMAGE_PADDING_LEN};
	hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(node_bytes)
}

fn prepare_proof_for_circuit(
	proof: Vec<Bytes>,
	state_root: String,
	leaf_hash: [u8; 32],
) -> anyhow::Result<qp_wormhole_circuit::storage_proof::ProcessedStorageProof> {
	let mut node_map: std::collections::HashMap<String, (usize, Vec<u8>, String)> =
		std::collections::HashMap::new();
	for (idx, node) in proof.iter().enumerate() {
		let hash = hash_node_with_poseidon_padded(&node.0);
		let hash_hex = hex::encode(hash);
		let node_hex = hex::encode(&node.0);
		node_map.insert(hash_hex.clone(), (idx, node.0.clone(), node_hex));
	}

	let state_root_hex = state_root.trim_start_matches("0x").to_string();

	let root_hash = if node_map.contains_key(&state_root_hex) {
		state_root_hex.clone()
	} else {
		anyhow::bail!("No node hashes to state root!");
	};

	let root_entry = node_map
		.get(&root_hash)
		.ok_or_else(|| anyhow!("Failed to get root entry from map"))?;

	let mut ordered_nodes = vec![root_entry.1.clone()];
	let mut current_node_hex = root_entry.2.clone();

	const HASH_LENGTH_PREFIX: &str = "2000000000000000";

	loop {
		let mut found_child = None;
		for (child_hash, (_, child_bytes, _)) in &node_map {
			let hash_with_prefix = format!("{}{}", HASH_LENGTH_PREFIX, child_hash);
			if current_node_hex.contains(&hash_with_prefix) {
				if !ordered_nodes.iter().any(|n| n == child_bytes) {
					found_child = Some((child_hash.clone(), child_bytes.clone()));
					break;
				}
			}
		}

		if let Some((_, child_bytes)) = found_child {
			ordered_nodes.push(child_bytes.clone());
			current_node_hex = hex::encode(ordered_nodes.last().unwrap());
		} else {
			break;
		}
	}

	let mut indices = Vec::<usize>::new();

	for i in 0..ordered_nodes.len() - 1 {
		let current_hex = hex::encode(&ordered_nodes[i]);
		let next_node = &ordered_nodes[i + 1];
		let next_hash = hex::encode(hash_node_with_poseidon_padded(next_node));

		if let Some(hex_idx) = current_hex.find(&next_hash) {
			indices.push(hex_idx);
		} else {
			anyhow::bail!("Could not find child hash in ordered node {}", i);
		}
	}

	let (found, last_idx) = check_leaf(&leaf_hash, ordered_nodes.last().unwrap().clone());
	if !found {
		anyhow::bail!("Leaf hash suffix not found in leaf node!");
	}

	indices.push(last_idx);

	if indices.len() != ordered_nodes.len() {
		log_verbose!(
			"Warning: indices.len() = {}, ordered_nodes.len() = {}",
			indices.len(),
			ordered_nodes.len()
		);
	}

	qp_wormhole_circuit::storage_proof::ProcessedStorageProof::new(ordered_nodes, indices)
}

fn check_leaf(leaf_hash: &[u8; 32], leaf_node: Vec<u8>) -> (bool, usize) {
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

	(found, (last_idx * 2).saturating_sub(16))
}
