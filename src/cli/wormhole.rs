use crate::{chain::client::ChainClient, error::Result, log_print, log_success};
use clap::Subcommand;
use colored::Colorize;
use hex;
use poseidon_resonance::PoseidonHasher;
use rusty_crystals_hdwallet::wormhole::WormholePair;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::Hasher;
use sp_core::H256;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use substrate_api_client::ac_compose_macros::compose_extrinsic;

use wormhole_circuit::cli_data::WormholeData;
use wormhole_circuit::unspendable_account::UnspendableAccount;
use zk_circuits_common::utils::felts_to_bytes;

/// Recursively performs a pre-order DFS traversal of the proof's Merkle-Patricia
/// trie. This is the standard and correct way to process a storage proof.
fn dfs_traversal(
    parent_bytes_hex: &str,
    node_map: &mut HashMap<String, String>,
    ordered_proof_hex: &mut Vec<String>,
    indices: &mut Vec<usize>,
) {
    // 1. Find all direct children of the current node from the remaining pool.
    let mut children = Vec::new();
    for (hash, bytes) in node_map.iter() {
        if let Some(index) = parent_bytes_hex.find(hash) {
            // Store the byte index, the hash, and the node's bytes.
            children.push((index / 2, hash.clone(), bytes.clone()));
        }
    }

    // 2. It is CRITICAL to sort the children by their index of appearance in the
    // parent node. This ensures the pre-order traversal is correct.
    children.sort_by_key(|(index, _, _)| *index);

    // 3. For each child, in the correct order:
    //    a. Add it to our ordered lists.
    //    b. Recurse into that child to find its children *before* moving to the next sibling.
    for (index, child_hash, child_bytes) in children {
        if node_map.remove(&child_hash).is_some() {
            indices.push(index);
            ordered_proof_hex.push(child_bytes.clone());
            dfs_traversal(&child_bytes, node_map, ordered_proof_hex, indices);
        }
    }
}

/// Takes the raw storage proof from the chain and processes it into the format
/// expected by the ZK circuit. This kicks off the recursive DFS traversal.
fn prepare_proof_for_circuit(proof: Vec<Vec<u8>>, state_root: H256) -> (Vec<String>, Vec<usize>) {
    let state_root_hex = hex::encode(state_root.as_ref());
    let mut node_map: HashMap<String, String> = proof
        .into_iter()
        .map(|node_data| {
            let hash = hex::encode(<PoseidonHasher as Hasher>::hash(&node_data));
            let bytes = hex::encode(node_data);
            (hash, bytes)
        })
        .collect();

    let mut ordered_proof_hex = Vec::<String>::new();
    let mut indices = Vec::<usize>::new();

    // Find the root node. If it exists, add it as the first element and start the traversal.
    if let Some(root_node_bytes) = node_map.remove(&state_root_hex) {
        ordered_proof_hex.push(root_node_bytes.clone());
        dfs_traversal(
            &root_node_bytes,
            &mut node_map,
            &mut ordered_proof_hex,
            &mut indices,
        );
    } else {
        log::error!("State root not found in the provided proof nodes.");
        return (Vec::new(), Vec::new());
    }

    // The leaf node doesn't point to any other node, but the circuit expects an
    // index for every node. We add a placeholder '0' for the final node.
    if !ordered_proof_hex.is_empty() {
        indices.push(0);
    }

    (ordered_proof_hex, indices)
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
            let unspendable_account = UnspendableAccount::from_secret(&wormhole_pair.secret);
            let account_id_bytes: [u8; 32] = felts_to_bytes(&unspendable_account.account_id)
                .try_into()
                .expect("Failed to convert Vec<u8> to [u8; 32]");
            let account_id: AccountId32 = account_id_bytes.into();

            log_print!(
                "{}",
                "XXXXXXXXXXXXXXX Quantus Wormhole Details XXXXXXXXXXXXXXXXX".yellow()
            );
            log_print!(
                "{}: {}",
                "On-chain Address".green(),
                account_id.to_ss58check().bright_cyan()
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
        }
        WormholeCommands::Spend {
            secret,
            to,
            amount: amount_str,
            from,
            password,
            password_file,
        } => {
            log_print!("🚀 Initiating wormhole spend...");

            let chain_client = ChainClient::new(node_url).await?;

            // Step 1: Parse and validate inputs
            let clean_secret = secret.strip_prefix("0x").unwrap_or(&secret);
            let secret_bytes = hex::decode(clean_secret)
                .map_err(|_| crate::error::QuantusError::InvalidHexSecret)?;

            let secret_array: [u8; 32] = secret_bytes
                .clone()
                .try_into()
                .map_err(|v: Vec<u8>| crate::error::QuantusError::InvalidSecretLength(v.len()))?;

            // The on-chain destination for the funding transfer MUST be the unspendable account
            // derived from the secret. This is what the ZK circuit is built to prove.
            let unspendable_account = UnspendableAccount::from_secret(&secret_array);
            let unspendable_account_bytes: [u8; 32] =
                felts_to_bytes(&unspendable_account.account_id)
                    .try_into()
                    .expect("Failed to convert Vec<u8> to [u8; 32]");
            let wormhole_account: AccountId32 = unspendable_account_bytes.into();

            let (amount_u128, formatted_amount) =
                chain_client.validate_and_format_amount(&amount_str).await?;

            // Load the signing wallet
            let keypair = crate::wallet::load_keypair_from_wallet(&from, password, password_file)?;

            log_print!("🔗 Wormhole Spend Details:",);
            log_print!(
                "   Wormhole Address: {}",
                wormhole_account.to_ss58check().bright_yellow()
            );
            log_print!("   To Destination: {}", to.bright_green());
            log_print!("   Amount: {}", formatted_amount.bright_cyan());
            log_print!(
                "   Signed by: {}",
                keypair.to_account_id_ss58check().bright_blue()
            );

            // Step 2: Transfer funds to the wormhole's on-chain address
            log_print!("📤 Step 1: Transferring funds to wormhole address...");

            let tx_report = chain_client
                .transfer(&keypair, &wormhole_account.to_ss58check(), amount_u128)
                .await?;

            log_success!("Transfer submitted!",);
            log_print!(
                "📍 Transaction hash: {}",
                tx_report.extrinsic_hash.to_string().bright_blue()
            );

            // Per team confirmation, we can use the InBlock status for the proof.
            // No finalization wait is needed.
            let inclusion_block_hash = tx_report.block_hash.ok_or_else(|| {
                crate::error::QuantusError::Generic(
                    "Transaction report did not include a block hash. This should not happen."
                        .to_string(),
                )
            })?;

            log_print!(
                "📦 Transaction included in block: {}",
                inclusion_block_hash.to_string().bright_blue()
            );

            // Step 2: Get storage proof from the inclusion block
            log_print!("🔍 Step 2: Fetching storage proof from the chain...");

            // Use the original TransferProof approach - the circuit is designed to handle
            // the MPT partial key issue by only checking the last three felts
            let (state_root, storage_proof, transfer_count) = chain_client
                .get_transfer_storage_proof_at_block(
                    &keypair.to_resonance_pair()?.public().into(),
                    &wormhole_account,
                    amount_u128,
                    inclusion_block_hash,
                )
                .await?;

            log_success!("Storage proof fetched successfully!");
            log_print!(
                "   State Root: 0x{}",
                hex::encode(state_root.as_ref()).bright_yellow()
            );
            log_print!(
                "   Storage Proof Length: {}",
                storage_proof.len().to_string().bright_magenta()
            );
            for (i, proof_node) in storage_proof.iter().enumerate() {
                log_print!(
                    "   Proof Node {}: 0x{}",
                    i,
                    hex::encode(proof_node).bright_cyan()
                );
            }

            // Step 3: Process the storage proof for the circuit
            log_print!("🔐 Step 3: Processing storage proof for ZK circuit...");
            let (ordered_proof_hex, indices) = prepare_proof_for_circuit(storage_proof, state_root);

            log_success!("Storage proof processed successfully!");
            log_print!("   Processed Proof Length: {}", ordered_proof_hex.len());
            log_print!("   Calculated Indices: {:?}", indices);

            // Step 4: Generate ZK proof using wormhole prover
            log_print!("🔐 Step 4: Generating zero-knowledge proof...");

            // Create the simple data struct to pass to the prover CLI
            let wormhole_data = WormholeData {
                secret_hex: secret.clone(),
                from_address_ss58: keypair.to_account_id_ss58check(),
                exit_address_ss58: to.clone(),
                funding_amount: amount_u128,
                state_root_hex: hex::encode(state_root.as_ref()),
                storage_proof_hex: ordered_proof_hex,
                storage_proof_indices: indices,
                transfer_count,
            };

            log_print!("🔍 Debug: Wormhole data being sent to prover:");
            log_print!(
                "   Storage Proof Hex Length: {}",
                wormhole_data.storage_proof_hex.len()
            );
            for (i, proof_hex) in wormhole_data.storage_proof_hex.iter().enumerate() {
                log_print!("   Proof Hex {}: {}", i, proof_hex);
            }

            // Serialize the data to JSON
            let data_json = serde_json::to_string(&wormhole_data).map_err(|e| {
                crate::error::QuantusError::Generic(format!(
                    "Failed to serialize wormhole data: {:?}",
                    e
                ))
            })?;

            log_print!("🔍 Debug: JSON being sent to prover:");
            log_print!("   {}", data_json);

            // Execute the wormhole-prover-cli as a subprocess.
            // We must set the working directory for the prover so it can find its
            // artifact files (`prover.bin`, `common.bin`) using its default relative paths.
            let prover_project_path = "../wormhole-circuit/wormhole/prover-cli";
            let prover_cli_path = if cfg!(debug_assertions) {
                "../../target/debug/wormhole-prover-cli"
            } else {
                "../../target/release/wormhole-prover-cli"
            };

            let output = Command::new(prover_cli_path)
                .current_dir(prover_project_path)
                .arg("--data-json")
                .arg(data_json)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| {
                    crate::error::QuantusError::Generic(format!(
                        "Failed to execute prover CLI from path '{}' with working directory '{}': {}. Ensure the wormhole-prover-cli is built.",
                        prover_cli_path, prover_project_path, e
                    ))
                })?;

            if !output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("--- ❌ Prover CLI Failed ---");
                println!("--- STDOUT ---");
                println!("{}", stdout);
                println!("--- STDERR ---");
                println!("{}", stderr);
                println!("--------------------------");
                return Err(crate::error::QuantusError::WormholeProofGeneration(
                    format!("Prover CLI failed. See output above."),
                ));
            }

            // The last line of stdout should be the hex-encoded proof
            let stdout = String::from_utf8_lossy(&output.stdout);
            let proof_hex = stdout.lines().last().unwrap_or("").trim();

            if proof_hex.is_empty() {
                return Err(crate::error::QuantusError::WormholeProofGeneration(
                    "Prover CLI did not produce a proof".to_string(),
                ));
            }

            let proof_bytes = hex::decode(proof_hex).map_err(|e| {
                crate::error::QuantusError::WormholeProofGeneration(format!(
                    "Failed to decode proof from hex: {:?}",
                    e
                ))
            })?;

            log_success!("✅ Zero-knowledge proof generated successfully!");

            // Step 5: Submit proof via unsigned extrinsic
            log_print!("📡 Step 5: Submitting proof for verification...");

            // Create the wormhole_verify_proof extrinsic
            let api = chain_client.get_api();
            let extrinsic = compose_extrinsic!(api, "Wormhole", "verify_proof", proof_bytes)
                .ok_or_else(|| {
                    crate::error::QuantusError::WormholeUnsignedExtrinsic(
                        "Failed to create wormhole_verify_proof extrinsic".to_string(),
                    )
                })?;

            // Submit the unsigned extrinsic using the macro
            let proof_tx_report = crate::submit_unsigned_extrinsic!(chain_client, extrinsic)?;

            log_success!(
                "✅ Proof verification submitted in block {}!",
                proof_tx_report
                    .block_hash
                    .unwrap_or_default()
                    .to_string()
                    .bright_blue()
            );

            log_success!("🎉 Wormhole spend completed successfully!");
            log_print!("💰 Funds have been spent from wormhole address");
        }
    }
    Ok(())
}
