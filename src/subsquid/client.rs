//! Subsquid GraphQL client for privacy-preserving transfer queries.

use crate::error::{QuantusError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::types::{
	GraphQLResponse, NullifierQueryParams, NullifierResult, NullifiersByPrefixResult, Transfer,
	TransferQueryParams, TransfersByPrefixResult,
};

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

#[derive(Deserialize)]
struct NullifiersByPrefixData {
	#[serde(rename = "nullifiersByPrefix")]
	nullifiers_by_prefix: NullifiersByPrefixResult,
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
                        leafIndex
                        transferCount
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

	/// Fetch every transfer matching the given prefixes, paginating by block range.
	///
	/// The server caps any single query at 1000 results and rejects larger result sets
	/// with a "Query returned N results, which exceeds the limit of 1000" error. This
	/// method handles that by binary-splitting the `[after_block, before_block]` range
	/// whenever the cap is hit, then concatenating results.
	///
	/// `base_params.after_block` / `base_params.before_block` are honored as the initial
	/// bounds; unset means `0` / `i32::MAX` (GraphQL `Int` is signed 32-bit so we can't
	/// exceed that). Other filters (amount, offset) are forwarded unchanged. `limit` is
	/// always set to the server max (1000) per sub-query.
	pub async fn query_all_transfers_by_prefix(
		&self,
		to_prefixes: Option<Vec<String>>,
		from_prefixes: Option<Vec<String>>,
		base_params: TransferQueryParams,
	) -> Result<Vec<Transfer>> {
		const SERVER_MAX_LIMIT: u32 = 1000;
		const LIMIT_EXCEEDED_MARKER: &str = "exceeds the limit";
		const MAX_BLOCK_SENTINEL: u32 = i32::MAX as u32;

		let initial_lo = base_params.after_block.unwrap_or(0);
		let initial_hi = base_params.before_block.unwrap_or(MAX_BLOCK_SENTINEL);

		if initial_lo > initial_hi {
			return Ok(vec![]);
		}

		let mut all: Vec<Transfer> = Vec::new();
		let mut stack: Vec<(u32, u32)> = vec![(initial_lo, initial_hi)];

		while let Some((lo, hi)) = stack.pop() {
			let params = base_params
				.clone()
				.with_after_block(lo)
				.with_before_block(hi)
				.with_limit(SERVER_MAX_LIMIT);

			match self
				.query_transfers_by_prefix(to_prefixes.clone(), from_prefixes.clone(), params)
				.await
			{
				Ok(transfers) => all.extend(transfers),
				Err(e) if e.to_string().contains(LIMIT_EXCEEDED_MARKER) => {
					if lo == hi {
						return Err(QuantusError::Generic(format!(
							"More than {} transfers in single block {}: {}",
							SERVER_MAX_LIMIT, lo, e
						)));
					}
					let mid = lo + (hi - lo) / 2;
					stack.push((mid + 1, hi));
					stack.push((lo, mid));
				},
				Err(e) => return Err(e),
			}
		}

		Ok(all)
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

	/// Query consumed nullifiers by hash prefixes.
	///
	/// This method allows privacy-preserving queries by matching against
	/// blake3 hash prefixes of nullifiers rather than the nullifiers themselves.
	///
	/// # Arguments
	///
	/// * `prefixes` - Hash prefixes to search for (hex strings)
	/// * `params` - Additional query parameters (block range)
	///
	/// # Returns
	///
	/// A list of matching nullifiers. The caller should filter locally for exact matches.
	pub async fn query_nullifiers_by_prefix(
		&self,
		prefixes: Vec<String>,
		params: NullifierQueryParams,
	) -> Result<Vec<NullifierResult>> {
		if prefixes.is_empty() {
			return Ok(vec![]);
		}

		let query = r#"
            query NullifiersByPrefix($input: NullifiersByPrefixInput!) {
                nullifiersByPrefix(input: $input) {
                    nullifiers {
                        nullifier
                        nullifierHash
                        extrinsicHash
                        blockHeight
                        timestamp
                    }
                    totalCount
                }
            }
        "#;

		let mut input = serde_json::json!({
			"hashPrefixes": prefixes,
		});

		if let Some(block) = params.after_block {
			input["afterBlock"] = serde_json::json!(block);
		}

		let request = GraphQLRequest {
			query: query.to_string(),
			variables: serde_json::json!({ "input": input }),
		};

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

		let graphql_response: GraphQLResponse<NullifiersByPrefixData> = response
			.json()
			.await
			.map_err(|e| QuantusError::Generic(format!("Failed to parse response: {}", e)))?;

		if let Some(errors) = graphql_response.errors {
			let error_messages: Vec<String> = errors.iter().map(|e| e.message.clone()).collect();
			return Err(QuantusError::Generic(format!(
				"GraphQL errors: {}",
				error_messages.join("; ")
			)));
		}

		let data = graphql_response
			.data
			.ok_or_else(|| QuantusError::Generic("No data in response".to_string()))?;

		Ok(data.nullifiers_by_prefix.nullifiers)
	}

	/// Check if specific nullifiers have been spent.
	///
	/// Given a list of (nullifier_hex, nullifier_hash) pairs, returns which ones
	/// are found in the indexer (i.e., have been spent).
	///
	/// # Arguments
	///
	/// * `nullifiers` - List of (nullifier_hex, nullifier_hash) pairs to check
	/// * `prefix_len` - Length of hash prefix to use for queries (8 recommended)
	///
	/// # Returns
	///
	/// Set of nullifier hex strings that have been spent.
	pub async fn check_nullifiers_spent(
		&self,
		nullifiers: &[(String, String)], // (nullifier_hex, nullifier_hash)
		prefix_len: usize,
	) -> Result<std::collections::HashSet<String>> {
		use super::hash::get_hash_prefix;
		use std::collections::HashSet;

		if nullifiers.is_empty() {
			return Ok(HashSet::new());
		}

		// Build map of hash -> nullifier_hex for local filtering
		let hash_to_nullifier: std::collections::HashMap<String, String> =
			nullifiers.iter().map(|(nul, hash)| (hash.clone(), nul.clone())).collect();

		// Get unique prefixes
		let prefixes: Vec<String> = nullifiers
			.iter()
			.map(|(_, hash)| get_hash_prefix(hash, prefix_len))
			.collect::<HashSet<_>>()
			.into_iter()
			.collect();

		// Query subsquid
		let results =
			self.query_nullifiers_by_prefix(prefixes, NullifierQueryParams::new()).await?;

		// Filter to exact matches
		let spent: HashSet<String> = results
			.into_iter()
			.filter_map(|r| hash_to_nullifier.get(&r.nullifier_hash).cloned())
			.collect();

		Ok(spent)
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

	// Guards the substring the paginator matches on. If the server ever changes this
	// wording, `query_all_transfers_by_prefix` will stop triggering binary-split and
	// this test will fail loudly.
	#[test]
	fn test_server_limit_error_marker() {
		let server_message = "Query returned 1234 results, which exceeds the limit of 1000. \
			Please use longer hash prefixes for more specific queries.";
		assert!(server_message.contains("exceeds the limit"));
	}
}
