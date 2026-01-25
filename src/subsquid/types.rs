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
}

/// Result from a prefix query.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransfersByPrefixResult {
	/// Matching transfers
	pub transfers: Vec<Transfer>,

	/// Total count of matches
	pub total_count: i64,
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
            "toHash": "5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh5678efgh"
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
            "toHash": "5678efgh"
        }"#;

		let transfer: Transfer = serde_json::from_str(json).expect("should deserialize");
		assert!(transfer.extrinsic_hash.is_none());
	}

	#[test]
	fn test_graphql_response_with_data() {
		let json = r#"{
            "data": {
                "transfers": [],
                "totalCount": 0
            }
        }"#;

		let response: GraphQLResponse<TransfersByPrefixResult> =
			serde_json::from_str(json).expect("should deserialize");

		assert!(response.data.is_some());
		assert!(response.errors.is_none());
		assert_eq!(response.data.unwrap().total_count, 0);
	}

	#[test]
	fn test_graphql_response_with_error() {
		let json = r#"{
            "data": null,
            "errors": [
                {
                    "message": "Query returned too many results",
                    "locations": [{"line": 1, "column": 1}],
                    "path": ["transfersByHashPrefix"]
                }
            ]
        }"#;

		let response: GraphQLResponse<TransfersByPrefixResult> =
			serde_json::from_str(json).expect("should deserialize");

		assert!(response.data.is_none());
		assert!(response.errors.is_some());

		let errors = response.errors.unwrap();
		assert_eq!(errors.len(), 1);
		assert_eq!(errors[0].message, "Query returned too many results");
	}
}
