//! Subsquid GraphQL client for privacy-preserving transfer queries.

use crate::error::{QuantusError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::types::{GraphQLResponse, Transfer, TransferQueryParams, TransfersByPrefixResult};

/// Client for querying the Subsquid indexer.
pub struct SubsquidClient {
	url: String,
	http_client: Client,
}

#[derive(Serialize)]
struct GraphQLRequest {
	query: String,
	variables: serde_json::Value,
}

#[derive(Deserialize)]
struct TransfersByHashPrefixData {
	#[serde(rename = "transfersByHashPrefix")]
	transfers_by_hash_prefix: TransfersByPrefixResult,
}

impl SubsquidClient {
	/// Create a new Subsquid client.
	///
	/// # Arguments
	///
	/// * `url` - The GraphQL endpoint URL (e.g., "https://indexer.quantus.com/graphql")
	pub fn new(url: String) -> Result<Self> {
		let http_client = Client::builder()
			.build()
			.map_err(|e| QuantusError::Generic(format!("Failed to create HTTP client: {}", e)))?;

		Ok(Self { url, http_client })
	}

	/// Query transfers by hash prefixes.
	///
	/// This method allows privacy-preserving queries by matching against
	/// blake3 hash prefixes of addresses rather than the addresses themselves.
	///
	/// # Arguments
	///
	/// * `to_prefixes` - Hash prefixes for destination addresses (OR logic)
	/// * `from_prefixes` - Hash prefixes for source addresses (OR logic)
	/// * `params` - Additional query parameters (block range, amount filters, pagination)
	///
	/// # Returns
	///
	/// A list of matching transfers. Returns an error if too many results match.
	pub async fn query_transfers_by_prefix(
		&self,
		to_prefixes: Option<Vec<String>>,
		from_prefixes: Option<Vec<String>>,
		params: TransferQueryParams,
	) -> Result<Vec<Transfer>> {
		// Build the GraphQL query
		let query = r#"
            query TransfersByHashPrefix($input: TransfersByPrefixInput!) {
                transfersByHashPrefix(input: $input) {
                    transfers {
                        id
                        blockId
                        blockHeight
                        timestamp
                        extrinsicHash
                        fromId
                        toId
                        amount
                        fee
                        fromHash
                        toHash
                    }
                    totalCount
                }
            }
        "#;

		// Build input variables
		let mut input = serde_json::json!({
			"limit": params.limit,
			"offset": params.offset,
		});

		if let Some(prefixes) = to_prefixes {
			input["toHashPrefixes"] = serde_json::json!(prefixes);
		}

		if let Some(prefixes) = from_prefixes {
			input["fromHashPrefixes"] = serde_json::json!(prefixes);
		}

		if let Some(block) = params.after_block {
			input["afterBlock"] = serde_json::json!(block);
		}

		if let Some(block) = params.before_block {
			input["beforeBlock"] = serde_json::json!(block);
		}

		if let Some(amount) = params.min_amount {
			input["minAmount"] = serde_json::json!(amount.to_string());
		}

		if let Some(amount) = params.max_amount {
			input["maxAmount"] = serde_json::json!(amount.to_string());
		}

		let request = GraphQLRequest {
			query: query.to_string(),
			variables: serde_json::json!({ "input": input }),
		};

		// Send request
		let response = self
			.http_client
			.post(&self.url)
			.json(&request)
			.send()
			.await
			.map_err(|e| QuantusError::Generic(format!("Failed to send request: {}", e)))?;

		if !response.status().is_success() {
			let status = response.status();
			let body = response.text().await.unwrap_or_default();
			return Err(QuantusError::Generic(format!(
				"Subsquid request failed with status {}: {}",
				status, body
			)));
		}

		let graphql_response: GraphQLResponse<TransfersByHashPrefixData> = response
			.json()
			.await
			.map_err(|e| QuantusError::Generic(format!("Failed to parse response: {}", e)))?;

		// Check for GraphQL errors
		if let Some(errors) = graphql_response.errors {
			let error_messages: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
			return Err(QuantusError::Generic(format!(
				"GraphQL errors: {}",
				error_messages.join("; ")
			)));
		}

		// Extract transfers
		let data = graphql_response
			.data
			.ok_or_else(|| QuantusError::Generic("No data in response".to_string()))?;

		Ok(data.transfers_by_hash_prefix.transfers)
	}

	/// Query transfers for a set of addresses using privacy-preserving hash prefixes.
	///
	/// This is a convenience method that:
	/// 1. Computes hash prefixes for all provided addresses
	/// 2. Queries the indexer with those prefixes
	/// 3. Filters results locally to only include transfers involving the exact addresses
	///
	/// # Arguments
	///
	/// * `addresses` - Raw 32-byte account IDs to query for
	/// * `prefix_len` - Length of hash prefix to use (shorter = more privacy, more noise)
	/// * `params` - Additional query parameters
	///
	/// # Returns
	///
	/// Transfers involving any of the provided addresses (filtered locally for exact matches)
	pub async fn query_transfers_for_addresses(
		&self,
		addresses: &[[u8; 32]],
		prefix_len: usize,
		params: TransferQueryParams,
	) -> Result<Vec<Transfer>> {
		use super::hash::{compute_address_hash, get_hash_prefix};
		use std::collections::HashSet;

		if addresses.is_empty() {
			return Ok(vec![]);
		}

		// Compute full hashes and prefixes for all addresses
		let address_hashes: HashSet<String> = addresses.iter().map(compute_address_hash).collect();

		let prefixes: Vec<String> = address_hashes
			.iter()
			.map(|h| get_hash_prefix(h, prefix_len))
			.collect::<HashSet<_>>()
			.into_iter()
			.collect();

		// Query with prefixes (for both to and from)
		let transfers = self
			.query_transfers_by_prefix(Some(prefixes.clone()), Some(prefixes), params)
			.await?;

		// Filter locally to only include exact matches
		let filtered: Vec<Transfer> = transfers
			.into_iter()
			.filter(|t| {
				address_hashes.contains(&t.to_hash) || address_hashes.contains(&t.from_hash)
			})
			.collect();

		Ok(filtered)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_transfer_query_params_builder() {
		let params = TransferQueryParams::new()
			.with_limit(50)
			.with_offset(10)
			.with_after_block(1000)
			.with_before_block(2000);

		assert_eq!(params.limit, 50);
		assert_eq!(params.offset, 10);
		assert_eq!(params.after_block, Some(1000));
		assert_eq!(params.before_block, Some(2000));
	}
}
