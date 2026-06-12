//! Types for Subsquid API responses.

use serde::{Deserialize, Serialize};

/// A transfer as returned by the Subsquid indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transfer {
	/// Unique identifier
	pub id: String,

	/// Block ID
	pub block_id: String,

	/// Block height
	pub block_height: i64,

	/// Timestamp of the transfer
	pub timestamp: String,

	/// Extrinsic hash (if available)
	pub extrinsic_hash: Option<String>,

	/// Sender address (SS58 format)
	pub from_id: String,

	/// Recipient address (SS58 format)
	pub to_id: String,

	/// Transfer amount (as string to handle large numbers)
	pub amount: String,

	/// Transaction fee
	pub fee: String,

	/// Blake3 hash of the sender's raw address
	pub from_hash: String,

	/// Blake3 hash of the recipient's raw address
	pub to_hash: String,

	/// Index in the ZK trie for Merkle proof generation
	pub leaf_index: String,

	/// Transfer count from Wormhole pallet - required for nullifier computation
	#[serde(default)]
	pub transfer_count: String,
}

/// Deserialize a Hasura `numeric` scalar into a `String`.
///
/// Hasura serializes Postgres `numeric` columns as JSON numbers by default
/// (or strings when `HASURA_GRAPHQL_STRINGIFY_NUMERIC_TYPES` is set), so
/// accept both representations.
fn numeric_string<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
	D: serde::Deserializer<'de>,
{
	struct NumericVisitor;

	impl serde::de::Visitor<'_> for NumericVisitor {
		type Value = String;

		fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
			formatter.write_str("a number or a numeric string")
		}

		fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<String, E> {
			Ok(v.to_string())
		}

		fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<String, E> {
			Ok(v.to_string())
		}

		fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<String, E> {
			Ok(v.to_string())
		}

		fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<String, E> {
			if v.fract() == 0.0 && v.is_finite() {
				Ok(format!("{:.0}", v))
			} else {
				Ok(v.to_string())
			}
		}
	}

	deserializer.deserialize_any(NumericVisitor)
}

/// Nested `block { height }` relationship in Hasura responses.
#[derive(Debug, Clone, Deserialize)]
pub struct HasuraBlockRef {
	pub height: i64,
}

/// A transfer row as returned by the Hasura GraphQL server.
///
/// Uses snake_case column names and nested relationships; converted into the
/// flat [`Transfer`] struct that the rest of the codebase consumes.
#[derive(Debug, Clone, Deserialize)]
pub struct HasuraTransferRow {
	pub id: String,
	pub block_id: Option<String>,
	pub block: Option<HasuraBlockRef>,
	pub timestamp: String,
	pub extrinsic_id: Option<String>,
	pub from_id: Option<String>,
	pub to_id: Option<String>,
	#[serde(deserialize_with = "numeric_string")]
	pub amount: String,
	#[serde(deserialize_with = "numeric_string")]
	pub fee: String,
	pub from_hash: String,
	pub to_hash: String,
	#[serde(deserialize_with = "numeric_string")]
	pub leaf_index: String,
	#[serde(deserialize_with = "numeric_string")]
	pub transfer_count: String,
}

impl From<HasuraTransferRow> for Transfer {
	fn from(row: HasuraTransferRow) -> Self {
		Transfer {
			id: row.id,
			block_id: row.block_id.unwrap_or_default(),
			block_height: row.block.map(|b| b.height).unwrap_or_default(),
			timestamp: row.timestamp,
			extrinsic_hash: row.extrinsic_id,
			from_id: row.from_id.unwrap_or_default(),
			to_id: row.to_id.unwrap_or_default(),
			amount: row.amount,
			fee: row.fee,
			from_hash: row.from_hash,
			to_hash: row.to_hash,
			leaf_index: row.leaf_index,
			transfer_count: row.transfer_count,
		}
	}
}

/// A wormhole nullifier row as returned by the Hasura GraphQL server.
#[derive(Debug, Clone, Deserialize)]
pub struct HasuraNullifierRow {
	pub nullifier: String,
	pub nullifier_hash: String,
	pub block: Option<HasuraBlockRef>,
	pub timestamp: String,
	#[serde(rename = "wormholeExtrinsic")]
	pub wormhole_extrinsic: Option<HasuraWormholeExtrinsicRef>,
}

/// Nested `wormholeExtrinsic { extrinsic_id }` relationship.
#[derive(Debug, Clone, Deserialize)]
pub struct HasuraWormholeExtrinsicRef {
	pub extrinsic_id: Option<String>,
}

impl From<HasuraNullifierRow> for NullifierResult {
	fn from(row: HasuraNullifierRow) -> Self {
		NullifierResult {
			nullifier: row.nullifier,
			nullifier_hash: row.nullifier_hash,
			extrinsic_hash: row.wormhole_extrinsic.and_then(|e| e.extrinsic_id).unwrap_or_default(),
			block_height: row.block.map(|b| b.height).unwrap_or_default(),
			timestamp: row.timestamp,
		}
	}
}

/// GraphQL response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse<T> {
	pub data: Option<T>,
	pub errors: Option<Vec<GraphQLError>>,
}

/// GraphQL error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
	pub message: String,
	pub locations: Option<Vec<GraphQLErrorLocation>>,
	pub path: Option<Vec<serde_json::Value>>,
}

/// GraphQL error location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLErrorLocation {
	pub line: i64,
	pub column: i64,
}

/// A nullifier as returned by the Subsquid indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NullifierResult {
	/// The nullifier bytes as hex
	pub nullifier: String,

	/// Blake3 hash of the nullifier for prefix queries
	pub nullifier_hash: String,

	/// Extrinsic hash that consumed this nullifier
	pub extrinsic_hash: String,

	/// Block height where the nullifier was consumed
	pub block_height: i64,

	/// Timestamp when the nullifier was consumed
	pub timestamp: String,
}

/// Query parameters for nullifier prefix queries.
#[derive(Debug, Clone, Default)]
pub struct NullifierQueryParams {
	/// Minimum block number (inclusive)
	pub after_block: Option<u32>,
}

impl NullifierQueryParams {
	pub fn new() -> Self {
		Self::default()
	}

	#[allow(dead_code)]
	pub fn with_after_block(mut self, block: u32) -> Self {
		self.after_block = Some(block);
		self
	}
}

/// Query parameters for transfer prefix queries.
#[derive(Debug, Clone, Default)]
pub struct TransferQueryParams {
	/// Minimum block number (inclusive)
	pub after_block: Option<u32>,

	/// Maximum block number (inclusive)
	pub before_block: Option<u32>,

	/// Minimum transfer amount
	pub min_amount: Option<u128>,

	/// Maximum transfer amount
	pub max_amount: Option<u128>,

	/// Maximum number of results
	pub limit: u32,

	/// Offset for pagination
	pub offset: u32,
}

impl TransferQueryParams {
	pub fn new() -> Self {
		Self { limit: 100, offset: 0, ..Default::default() }
	}

	pub fn with_limit(mut self, limit: u32) -> Self {
		self.limit = limit;
		self
	}

	#[allow(dead_code)]
	pub fn with_offset(mut self, offset: u32) -> Self {
		self.offset = offset;
		self
	}

	pub fn with_after_block(mut self, block: u32) -> Self {
		self.after_block = Some(block);
		self
	}

	pub fn with_before_block(mut self, block: u32) -> Self {
		self.before_block = Some(block);
		self
	}

	pub fn with_min_amount(mut self, amount: u128) -> Self {
		self.min_amount = Some(amount);
		self
	}

	#[allow(dead_code)]
	pub fn with_max_amount(mut self, amount: u128) -> Self {
		self.max_amount = Some(amount);
		self
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_transfer_query_params_default() {
		let params = TransferQueryParams::default();
		assert_eq!(params.limit, 0);
		assert_eq!(params.offset, 0);
		assert!(params.after_block.is_none());
		assert!(params.before_block.is_none());
		assert!(params.min_amount.is_none());
		assert!(params.max_amount.is_none());
	}

	#[test]
	fn test_transfer_query_params_new() {
		let params = TransferQueryParams::new();
		assert_eq!(params.limit, 100);
		assert_eq!(params.offset, 0);
	}

	#[test]
	fn test_transfer_query_params_builder() {
		let params = TransferQueryParams::new()
			.with_limit(50)
			.with_offset(10)
			.with_after_block(1000)
			.with_before_block(2000)
			.with_min_amount(1_000_000)
			.with_max_amount(10_000_000);

		assert_eq!(params.limit, 50);
		assert_eq!(params.offset, 10);
		assert_eq!(params.after_block, Some(1000));
		assert_eq!(params.before_block, Some(2000));
		assert_eq!(params.min_amount, Some(1_000_000));
		assert_eq!(params.max_amount, Some(10_000_000));
	}

	#[test]
	fn test_transfer_deserialization() {
		let json = r#"{
            "id": "transfer-123",
            "blockId": "block-456",
            "blockHeight": 12345,
            "timestamp": "2024-01-15T12:30:00Z",
            "extrinsicHash": "0xabcd1234",
            "fromId": "qzAlice123",
            "toId": "qzBob456",
            "amount": "1000000000000",
            "fee": "1000000",
            "fromHash": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
            "toHash": "5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh",
            "leafIndex": "42",
            "transferCount": "100"
        }"#;

		let transfer: Transfer = serde_json::from_str(json).expect("should deserialize");

		assert_eq!(transfer.id, "transfer-123");
		assert_eq!(transfer.block_id, "block-456");
		assert_eq!(transfer.block_height, 12345);
		assert_eq!(transfer.timestamp, "2024-01-15T12:30:00Z");
		assert_eq!(transfer.extrinsic_hash, Some("0xabcd1234".to_string()));
		assert_eq!(transfer.from_id, "qzAlice123");
		assert_eq!(transfer.to_id, "qzBob456");
		assert_eq!(transfer.amount, "1000000000000");
		assert_eq!(transfer.fee, "1000000");
		assert_eq!(transfer.leaf_index, "42");
		assert_eq!(transfer.transfer_count, "100");
	}

	#[test]
	fn test_transfer_deserialization_null_extrinsic_hash() {
		let json = r#"{
            "id": "transfer-123",
            "blockId": "block-456",
            "blockHeight": 12345,
            "timestamp": "2024-01-15T12:30:00Z",
            "extrinsicHash": null,
            "fromId": "qzAlice123",
            "toId": "qzBob456",
            "amount": "1000000000000",
            "fee": "1000000",
            "fromHash": "abcd1234",
            "toHash": "5678efgh",
            "leafIndex": "0",
            "transferCount": "1"
        }"#;

		let transfer: Transfer = serde_json::from_str(json).expect("should deserialize");
		assert!(transfer.extrinsic_hash.is_none());
	}

	#[test]
	fn test_hasura_transfer_row_deserialization() {
		// Hasura returns numeric columns as JSON numbers by default.
		let json = r#"{
            "id": "transfer-123",
            "block_id": "block-456",
            "block": { "height": 12345 },
            "timestamp": "2024-01-15T12:30:00+00:00",
            "extrinsic_id": "0xabcd1234",
            "from_id": "qzAlice123",
            "to_id": "qzBob456",
            "amount": 1000000000000,
            "fee": 1000000,
            "from_hash": "abcd1234",
            "to_hash": "5678efgh",
            "leaf_index": 42,
            "transfer_count": 100
        }"#;

		let row: HasuraTransferRow = serde_json::from_str(json).expect("should deserialize");
		let transfer: Transfer = row.into();

		assert_eq!(transfer.id, "transfer-123");
		assert_eq!(transfer.block_id, "block-456");
		assert_eq!(transfer.block_height, 12345);
		assert_eq!(transfer.extrinsic_hash, Some("0xabcd1234".to_string()));
		assert_eq!(transfer.from_id, "qzAlice123");
		assert_eq!(transfer.to_id, "qzBob456");
		assert_eq!(transfer.amount, "1000000000000");
		assert_eq!(transfer.fee, "1000000");
		assert_eq!(transfer.leaf_index, "42");
		assert_eq!(transfer.transfer_count, "100");
	}

	#[test]
	fn test_hasura_transfer_row_stringified_numerics_and_nulls() {
		// With HASURA_GRAPHQL_STRINGIFY_NUMERIC_TYPES enabled, numerics come as strings.
		let json = r#"{
            "id": "transfer-123",
            "block_id": null,
            "block": null,
            "timestamp": "2024-01-15T12:30:00+00:00",
            "extrinsic_id": null,
            "from_id": null,
            "to_id": null,
            "amount": "1000000000000",
            "fee": "0",
            "from_hash": "abcd1234",
            "to_hash": "5678efgh",
            "leaf_index": "0",
            "transfer_count": "1"
        }"#;

		let row: HasuraTransferRow = serde_json::from_str(json).expect("should deserialize");
		let transfer: Transfer = row.into();

		assert_eq!(transfer.block_id, "");
		assert_eq!(transfer.block_height, 0);
		assert!(transfer.extrinsic_hash.is_none());
		assert_eq!(transfer.amount, "1000000000000");
		assert_eq!(transfer.fee, "0");
	}

	#[test]
	fn test_hasura_nullifier_row_deserialization() {
		let json = r#"{
            "nullifier": "0xdeadbeef",
            "nullifier_hash": "aabbccdd",
            "block": { "height": 777 },
            "timestamp": "2024-02-01T00:00:00+00:00",
            "wormholeExtrinsic": { "extrinsic_id": "0xfeed" }
        }"#;

		let row: HasuraNullifierRow = serde_json::from_str(json).expect("should deserialize");
		let result: NullifierResult = row.into();

		assert_eq!(result.nullifier, "0xdeadbeef");
		assert_eq!(result.nullifier_hash, "aabbccdd");
		assert_eq!(result.extrinsic_hash, "0xfeed");
		assert_eq!(result.block_height, 777);
		assert_eq!(result.timestamp, "2024-02-01T00:00:00+00:00");
	}

	#[test]
	fn test_graphql_response_with_error() {
		let json = r#"{
            "data": null,
            "errors": [
                {
                    "message": "Query returned too many results",
                    "locations": [{"line": 1, "column": 1}],
                    "path": ["transfer"]
                }
            ]
        }"#;

		let response: GraphQLResponse<serde_json::Value> =
			serde_json::from_str(json).expect("should deserialize");

		assert!(response.data.is_none());
		assert!(response.errors.is_some());

		let errors = response.errors.unwrap();
		assert_eq!(errors.len(), 1);
		assert_eq!(errors[0].message, "Query returned too many results");
	}
}
