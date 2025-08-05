use crate::chain::client::QuantusClient;
use crate::{log_print, log_verbose};
use codec::Decode;
use colored::Colorize;
use jsonrpsee::core::client::ClientT;
use sp_core::crypto::Ss58Codec;

/// Handle events command to query events from specific blocks
pub async fn handle_events_command(
    block: Option<u32>,
    block_hash: Option<String>,
    _latest: bool, // Renamed to _latest to suppress unused warning
    finalized: bool,
    pallet_filter: Option<String>,
    raw: bool,
    decode: bool,
    node_url: &str,
) -> crate::error::Result<()> {
    let quantus_client = QuantusClient::new(node_url).await?;

    // Get the appropriate block based on parameters
    let block = if let Some(block_num) = block {
        log_print!("📋 Querying events from block #{}", block_num);

        // Try to get block hash for the given number using raw RPC
        let block_hash_result: Result<Option<String>, _> = quantus_client
            .rpc_client()
            .request("chain_getBlockHash", [block_num])
            .await;

        match block_hash_result {
            Ok(Some(hash_str)) => {
                log_print!("🔍 Found block hash for #{}: {}", block_num, hash_str);

                // Parse the returned hash
                let hash_bytes = hex::decode(hash_str.trim_start_matches("0x")).map_err(|e| {
                    crate::error::QuantusError::Generic(format!(
                        "Invalid block hash from RPC: {:?}",
                        e
                    ))
                })?;

                if hash_bytes.len() != 32 {
                    return Err(crate::error::QuantusError::Generic(
                        "Invalid block hash length from RPC".to_string(),
                    ));
                }

                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hash_bytes);
                let block_hash = subxt::utils::H256::from(hash_array);

                // Get block using the hash
                quantus_client
                    .client()
                    .blocks()
                    .at(block_hash)
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!(
                            "Failed to get block #{}: {:?}",
                            block_num, e
                        ))
                    })?
            }
            Ok(None) => {
                return Err(crate::error::QuantusError::Generic(format!(
                    "Block #{} not found",
                    block_num
                )));
            }
            Err(e) => {
                log_print!("⚠️  RPC call failed, falling back to latest block: {:?}", e);

                // Get the latest block hash to read from the latest state (not finalized)
                let latest_block_hash = quantus_client.get_latest_block().await?;

                let latest_block = quantus_client
                    .client()
                    .blocks()
                    .at(latest_block_hash)
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!(
                            "Failed to get latest block: {:?}",
                            e
                        ))
                    })?;

                let latest_num = latest_block.number();

                if block_num > latest_num {
                    return Err(crate::error::QuantusError::Generic(format!(
                        "Block #{} is beyond latest block #{}",
                        block_num, latest_num
                    )));
                }

                log_print!(
                    "🔍 Using latest block #{} instead of requested #{}",
                    latest_num,
                    block_num
                );
                latest_block
            }
        }
    } else if let Some(hash_str) = &block_hash {
        log_print!("📋 Querying events from block hash: {}", hash_str);

        // Parse the hash string
        let hash_bytes = hex::decode(hash_str.trim_start_matches("0x")).map_err(|e| {
            crate::error::QuantusError::Generic(format!("Invalid block hash: {:?}", e))
        })?;

        if hash_bytes.len() != 32 {
            return Err(crate::error::QuantusError::Generic(
                "Invalid block hash length".to_string(),
            ));
        }

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash_bytes);
        let block_hash = subxt::utils::H256::from(hash_array);

        quantus_client
            .client()
            .blocks()
            .at(block_hash)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!("Failed to get block: {:?}", e))
            })?
    } else if finalized {
        log_print!("📋 Querying events from finalized block");

        // Get finalized block hash using raw RPC
        let finalized_hash_result: Result<String, _> = quantus_client
            .rpc_client()
            .request("chain_getFinalizedHead", [] as [u8; 0])
            .await;

        match finalized_hash_result {
            Ok(hash_str) => {
                log_print!("🔍 Found finalized block hash: {}", hash_str);

                // Parse the returned hash
                let hash_bytes = hex::decode(hash_str.trim_start_matches("0x")).map_err(|e| {
                    crate::error::QuantusError::Generic(format!(
                        "Invalid finalized hash from RPC: {:?}",
                        e
                    ))
                })?;

                if hash_bytes.len() != 32 {
                    return Err(crate::error::QuantusError::Generic(
                        "Invalid finalized hash length from RPC".to_string(),
                    ));
                }

                let mut hash_array = [0u8; 32];
                hash_array.copy_from_slice(&hash_bytes);
                let finalized_hash = subxt::utils::H256::from(hash_array);

                quantus_client
                    .client()
                    .blocks()
                    .at(finalized_hash)
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!(
                            "Failed to get finalized block: {:?}",
                            e
                        ))
                    })?
            }
            Err(e) => {
                log_print!(
                    "⚠️  Finalized head RPC call failed, using latest block: {:?}",
                    e
                );

                // Get the latest block hash to read from the latest state (not finalized)
                let latest_block_hash = quantus_client.get_latest_block().await?;

                quantus_client
                    .client()
                    .blocks()
                    .at(latest_block_hash)
                    .await
                    .map_err(|e| {
                        crate::error::QuantusError::NetworkError(format!(
                            "Failed to get latest block: {:?}",
                            e
                        ))
                    })?
            }
        }
    } else {
        log_print!("📋 Querying events from latest block");

        // Get the latest block hash to read from the latest state (not finalized)
        let latest_block_hash = quantus_client.get_latest_block().await?;

        quantus_client
            .client()
            .blocks()
            .at(latest_block_hash)
            .await
            .map_err(|e| {
                crate::error::QuantusError::NetworkError(format!(
                    "Failed to get latest block: {:?}",
                    e
                ))
            })?
    };

    log_print!("🎯 Found Block #{}", block.number());

    // Get all events from the block
    let events = block.events().await.map_err(|e| {
        crate::error::QuantusError::NetworkError(format!("Failed to get events: {:?}", e))
    })?;

    let mut event_count = 0;
    let mut filtered_count = 0;

    log_print!("📋 Block Events:");

    // Iterate through all events
    for event in events.iter() {
        event_count += 1;

        let event = event.map_err(|e| {
            crate::error::QuantusError::NetworkError(format!("Failed to decode event: {:?}", e))
        })?;

        // Apply pallet filter if specified
        if let Some(ref filter) = pallet_filter {
            if event.pallet_name() != filter {
                continue;
            }
        }

        filtered_count += 1;

        // Display event information
        log_print!(
            "  📌 {}.{}",
            event.pallet_name().bright_cyan(),
            event.variant_name().bright_yellow()
        );

        // Enhanced event decoding with details
        if !raw && decode {
            decode_event_details(&event)?;
        }

        // Show raw data if requested or in verbose mode
        if raw || crate::log::is_verbose() {
            log_verbose!("     📝 Raw event data: {:?}", event.field_bytes());
        }
    }

    // Summary
    log_print!("");
    if let Some(ref filter) = pallet_filter {
        log_print!(
            "📊 Summary: {} events total, {} events from {} pallet",
            event_count,
            filtered_count,
            filter.bright_cyan()
        );
    } else {
        log_print!("📊 Summary: {} events total", event_count);
    }

    if filtered_count == 0 && pallet_filter.is_some() {
        log_print!("💡 Tip: No events found for the specified pallet. Try without --pallet filter to see all events.");
    }

    log_print!("💡 Tip: Use --verbose for raw event data");
    log_print!("💡 Tip: Use --pallet <PALLET_NAME> to filter events by pallet");

    Ok(())
}

// =============================================================================
// UNIFIED EVENT DECODER SYSTEM
// =============================================================================

/// Macro to make adding new pallets super easy!
/// Usage: add_pallet_decoder!(registry, "PalletName", DecoderStruct);
macro_rules! add_pallet_decoder {
    ($registry:expr, $pallet_name:expr, $decoder_variant:expr) => {
        $registry.register($pallet_name, $decoder_variant);
    };
}

// =============================================================================

/// Enum holding all possible pallet decoders - easier to extend than trait objects
#[derive(Clone)]
enum PalletDecoder {
    Balances,
    System,
    MiningRewards,
    QPoW,
    Wormhole,
    ReversibleTransfers,
}

impl PalletDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        match self {
            PalletDecoder::Balances => BalancesDecoder.decode_event(event_name, event),
            PalletDecoder::System => SystemDecoder.decode_event(event_name, event),
            PalletDecoder::MiningRewards => MiningRewardsDecoder.decode_event(event_name, event),
            PalletDecoder::QPoW => QPoWDecoder.decode_event(event_name, event),
            PalletDecoder::Wormhole => WormholeDecoder.decode_event(event_name, event),
            PalletDecoder::ReversibleTransfers => {
                ReversibleTransfersDecoder.decode_event(event_name, event)
            }
        }
    }
}

/// Simple trait for individual pallet decoders (now without generics issues)
trait PalletEventDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String>;
}

/// Registry of all pallet decoders using enum pattern
struct EventDecoderRegistry {
    decoders: std::collections::HashMap<String, PalletDecoder>,
}

impl EventDecoderRegistry {
    fn new() -> Self {
        let mut registry = EventDecoderRegistry {
            decoders: std::collections::HashMap::new(),
        };

        // Register all pallet decoders - super easy to add new ones using the macro!
        add_pallet_decoder!(registry, "Balances", PalletDecoder::Balances);
        add_pallet_decoder!(registry, "System", PalletDecoder::System);
        add_pallet_decoder!(registry, "MiningRewards", PalletDecoder::MiningRewards);
        add_pallet_decoder!(registry, "QPoW", PalletDecoder::QPoW);
        add_pallet_decoder!(registry, "Wormhole", PalletDecoder::Wormhole);
        add_pallet_decoder!(
            registry,
            "ReversibleTransfers",
            PalletDecoder::ReversibleTransfers
        );

        // 💡 Easy to add new pallets! Example:
        // add_pallet_decoder!(registry, "MerkleAirdrop", PalletDecoder::MerkleAirdrop);

        registry
    }

    fn register(&mut self, pallet_name: &str, decoder: PalletDecoder) {
        self.decoders.insert(pallet_name.to_string(), decoder);
    }

    fn decode_event<T: subxt::Config>(
        &self,
        pallet_name: &str,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        self.decoders
            .get(pallet_name)?
            .decode_event(event_name, event)
    }
}

/// Decode and display detailed event information using the unified system
fn decode_event_details<T: subxt::Config>(
    event: &subxt::events::EventDetails<T>,
) -> crate::error::Result<()> {
    static REGISTRY: std::sync::OnceLock<EventDecoderRegistry> = std::sync::OnceLock::new();
    let registry = REGISTRY.get_or_init(EventDecoderRegistry::new);

    if let Some(decoded_message) =
        registry.decode_event(event.pallet_name(), event.variant_name(), event)
    {
        log_print!("{}", decoded_message);
    } else {
        // For other events, show basic info in verbose mode
        log_verbose!("     📝 Event in {} pallet", event.pallet_name());
    }

    Ok(())
}

// =============================================================================
// PALLET-SPECIFIC DECODERS
// =============================================================================
//
// 🚀 HOW TO ADD A NEW PALLET DECODER:
//
// 1. Add your pallet to the PalletDecoder enum:
//    enum PalletDecoder {
//        ...
//        YourNewPallet,  // <- Add this
//    }
//
// 2. Add the match arm in PalletDecoder::decode_event:
//    PalletDecoder::YourNewPallet => YourNewPalletDecoder.decode_event(event_name, event),
//
// 3. Register it in EventDecoderRegistry::new():
//    add_pallet_decoder!(registry, "YourPallet", PalletDecoder::YourNewPallet);
//
// 4. Create your decoder struct implementing PalletEventDecoder:
//    struct YourNewPalletDecoder;
//    impl PalletEventDecoder for YourNewPalletDecoder { ... }
//
// That's it! 🎉
// =============================================================================

// Helper functions for common decoding patterns
fn decode_account_id(input: &mut &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let account = subxt::ext::subxt_core::utils::AccountId32::decode(input)?;
    Ok(sp_core::crypto::AccountId32::from(account.0).to_ss58check())
}

fn decode_u128(input: &mut &[u8]) -> Result<u128, Box<dyn std::error::Error>> {
    Ok(u128::decode(input)?)
}

fn decode_h256(input: &mut &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let hash = subxt::ext::subxt_core::utils::H256::decode(input)?;
    Ok(hash.0)
}

// Balances pallet decoder
struct BalancesDecoder;

impl PalletEventDecoder for BalancesDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        let field_bytes = event.field_bytes();
        let mut input = &field_bytes[..];

        match event_name {
            "Transfer" => {
                if let (Ok(from), Ok(to), Ok(amount)) = (
                    decode_account_id(&mut input),
                    decode_account_id(&mut input),
                    decode_u128(&mut input),
                ) {
                    Some(format!(
                        "     💸 {} → {} (Amount: {})",
                        from.bright_green(),
                        to.bright_green(),
                        amount.to_string().bright_yellow()
                    ))
                } else {
                    Some("     💸 Balance Transfer event (decoding failed)".to_string())
                }
            }
            "Deposit" => {
                if let (Ok(account), Ok(amount)) =
                    (decode_account_id(&mut input), decode_u128(&mut input))
                {
                    Some(format!(
                        "     💰 Deposit to {} (Amount: {})",
                        account.bright_green(),
                        amount.to_string().bright_yellow()
                    ))
                } else {
                    Some("     💰 Balance Deposit event (decoding failed)".to_string())
                }
            }
            "Withdraw" => {
                if let (Ok(account), Ok(amount)) =
                    (decode_account_id(&mut input), decode_u128(&mut input))
                {
                    Some(format!(
                        "     💳 Withdraw from {} (Amount: {})",
                        account.bright_green(),
                        amount.to_string().bright_yellow()
                    ))
                } else {
                    Some("     💳 Balance Withdraw event (decoding failed)".to_string())
                }
            }
            "Minted" => {
                if let (Ok(account), Ok(amount)) =
                    (decode_account_id(&mut input), decode_u128(&mut input))
                {
                    Some(format!(
                        "     🪙 Minted {} to {}",
                        amount.to_string().bright_yellow(),
                        account.bright_green()
                    ))
                } else {
                    Some("     🪙 Balance Minted event (decoding failed)".to_string())
                }
            }
            _ => None,
        }
    }
}

// System pallet decoder
struct SystemDecoder;

impl PalletEventDecoder for SystemDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        match event_name {
            "ExtrinsicSuccess" => Some(format!(
                "     ✅ {}",
                "Extrinsic executed successfully".bright_green()
            )),
            "ExtrinsicFailed" => Some(format!(
                "     ❌ {}",
                "Extrinsic execution failed".bright_red()
            )),
            "NewAccount" => {
                let field_bytes = event.field_bytes();
                let mut input = &field_bytes[..];

                if let Ok(account) = decode_account_id(&mut input) {
                    Some(format!(
                        "     👤 New account created: {}",
                        account.bright_green()
                    ))
                } else {
                    Some("     👤 New account created (decoding failed)".to_string())
                }
            }
            _ => None,
        }
    }
}

// MiningRewards pallet decoder
struct MiningRewardsDecoder;

impl PalletEventDecoder for MiningRewardsDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        let field_bytes = event.field_bytes();
        let mut input = &field_bytes[..];

        match event_name {
            "MinerRewarded" => {
                if let (Ok(miner), Ok(reward)) =
                    (decode_account_id(&mut input), decode_u128(&mut input))
                {
                    Some(format!(
                        "     ⛏️  Miner {} rewarded with {} tokens",
                        miner.bright_green(),
                        reward.to_string().bright_yellow()
                    ))
                } else {
                    Some("     ⛏️  Miner rewarded (decoding failed)".to_string())
                }
            }
            "FeesCollected" => {
                if let (Ok(amount), Ok(total)) = (decode_u128(&mut input), decode_u128(&mut input))
                {
                    Some(format!(
                        "     📊 Fees collected: {} (Total: {})",
                        amount.to_string().bright_yellow(),
                        total.to_string().bright_cyan()
                    ))
                } else {
                    Some("     📊 Fees collected (decoding failed)".to_string())
                }
            }
            "TreasuryRewarded" => {
                if let Ok(reward) = decode_u128(&mut input) {
                    Some(format!(
                        "     🏛️  Treasury rewarded with {} tokens",
                        reward.to_string().bright_yellow()
                    ))
                } else {
                    Some("     🏛️  Treasury rewarded (decoding failed)".to_string())
                }
            }
            "FeesRedirectedToTreasury" => {
                if let Ok(amount) = decode_u128(&mut input) {
                    Some(format!(
                        "     🔄 Fees redirected to Treasury: {} tokens",
                        amount.to_string().bright_yellow()
                    ))
                } else {
                    Some("     🔄 Fees redirected to Treasury (decoding failed)".to_string())
                }
            }
            _ => None,
        }
    }
}

// QPoW pallet decoder
struct QPoWDecoder;

impl PalletEventDecoder for QPoWDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        match event_name {
            "ProofSubmitted" => {
                let field_bytes = event.field_bytes();
                let mut input = &field_bytes[..];

                if let Ok(nonce) = <[u8; 64]>::decode(&mut input) {
                    Some(format!(
                        "     🔗 PoW proof submitted (nonce: {}...)",
                        hex::encode(&nonce[0..8]).bright_cyan()
                    ))
                } else {
                    Some("     🔗 PoW proof submitted (decoding failed)".to_string())
                }
            }
            "DistanceThresholdAdjusted" => {
                Some("     ⚖️  Distance threshold adjusted for mining difficulty".to_string())
            }
            _ => None,
        }
    }
}

// Wormhole pallet decoder
struct WormholeDecoder;

impl PalletEventDecoder for WormholeDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        match event_name {
            "ProofVerified" => {
                let field_bytes = event.field_bytes();
                let mut input = &field_bytes[..];

                if let Ok(exit_amount) = decode_u128(&mut input) {
                    Some(format!(
                        "     🌀 Wormhole proof verified (Exit: {} tokens)",
                        exit_amount.to_string().bright_yellow()
                    ))
                } else {
                    Some("     🌀 Wormhole proof verified (decoding failed)".to_string())
                }
            }
            _ => None,
        }
    }
}

// ReversibleTransfers pallet decoder
struct ReversibleTransfersDecoder;

impl PalletEventDecoder for ReversibleTransfersDecoder {
    fn decode_event<T: subxt::Config>(
        &self,
        event_name: &str,
        event: &subxt::events::EventDetails<T>,
    ) -> Option<String> {
        let field_bytes = event.field_bytes();
        let mut input = &field_bytes[..];

        match event_name {
            "HighSecuritySet" => {
                if let (Ok(who), Ok(interceptor)) =
                    (decode_account_id(&mut input), decode_account_id(&mut input))
                {
                    // Skip recoverer field for now as it's not used in display
                    let _ = decode_account_id(&mut input);

                    Some(format!(
                        "     🔒 High security enabled for {} (Interceptor: {})",
                        who.bright_green(),
                        interceptor.bright_cyan()
                    ))
                } else {
                    Some("     🔒 High security enabled (decoding failed)".to_string())
                }
            }
            "TransactionScheduled" => {
                if let (Ok(from), Ok(to), Ok(_interceptor), Ok(amount), Ok(tx_id)) = (
                    decode_account_id(&mut input),
                    decode_account_id(&mut input),
                    decode_account_id(&mut input),
                    decode_u128(&mut input),
                    decode_h256(&mut input),
                ) {
                    Some(format!(
                        "     ⏰ Transaction scheduled: {} → {} (Amount: {}, ID: {}...)",
                        from.bright_green(),
                        to.bright_green(),
                        amount.to_string().bright_yellow(),
                        hex::encode(&tx_id[0..4]).bright_cyan()
                    ))
                } else {
                    Some("     ⏰ Transaction scheduled (decoding failed)".to_string())
                }
            }
            "TransactionCancelled" => {
                if let (Ok(who), Ok(tx_id)) =
                    (decode_account_id(&mut input), decode_h256(&mut input))
                {
                    Some(format!(
                        "     ❌ Transaction cancelled by {} (ID: {}...)",
                        who.bright_green(),
                        hex::encode(&tx_id[0..4]).bright_cyan()
                    ))
                } else {
                    Some("     ❌ Transaction cancelled (decoding failed)".to_string())
                }
            }
            "TransactionExecuted" => {
                if let Ok(tx_id) = decode_h256(&mut input) {
                    // For result, we'll try to decode but just extract success/failure status
                    let result_success = match input.len() {
                        0 => true, // No error data usually means success
                        _ => {
                            // Try to decode the result enum variant (0 = Ok, 1 = Err)
                            match input.get(0) {
                                Some(0) => true,  // Ok variant
                                Some(1) => false, // Err variant
                                _ => true,        // Default to success
                            }
                        }
                    };

                    let status = if result_success {
                        "✅ Success"
                    } else {
                        "❌ Failed"
                    };
                    Some(format!(
                        "     🚀 Transaction executed (ID: {}...) - {}",
                        hex::encode(&tx_id[0..4]).bright_cyan(),
                        status
                    ))
                } else {
                    Some("     🚀 Transaction executed (decoding failed)".to_string())
                }
            }
            _ => None,
        }
    }
}

// =============================================================================
// TEMPLATE FOR NEW PALLET DECODER
// =============================================================================
//
// Copy this template when adding support for a new pallet:
//
// // NewPallet pallet decoder
// struct NewPalletDecoder;
//
// impl PalletEventDecoder for NewPalletDecoder {
//     fn decode_event<T: subxt::Config>(
//         &self,
//         event_name: &str,
//         event: &subxt::events::EventDetails<T>,
//     ) -> Option<String> {
//         let field_bytes = event.field_bytes();
//         let mut input = &field_bytes[..];
//
//         match event_name {
//             "YourEventName" => {
//                 if let Ok(param) = decode_u128(&mut input) {
//                     Some(format!(
//                         "     🔥 Your event description: {}",
//                         param.to_string().bright_yellow()
//                     ))
//                 } else {
//                     Some("     🔥 Your event (decoding failed)".to_string())
//                 }
//             }
//             _ => None,
//         }
//     }
// }
//
// Don't forget to:
// 1. Add to PalletDecoder enum
// 2. Add to PalletDecoder::decode_event match
// 3. Register in EventDecoderRegistry::new()
// =============================================================================
