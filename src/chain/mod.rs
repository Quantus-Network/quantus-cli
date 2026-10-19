/// Chain interaction module
///
/// This module provides functionality for:
/// - Connecting to Quantus nodes
/// - Submitting transactions and extrinsics
/// - Querying chain state
/// - Managing RPC connections
pub mod client;
pub mod quantus_subxt;
pub mod signing;

#[cfg(test)]
pub(crate) fn test_metadata() -> subxt::Metadata {
	let bytes: &[u8] = include_bytes!("../quantus_metadata.scale");
	<subxt::Metadata as codec::Decode>::decode(&mut &bytes[..]).expect("valid checked-in metadata")
}
