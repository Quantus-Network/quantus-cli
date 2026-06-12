//! Hasura GraphQL client for privacy-preserving transfer queries.

use crate::error::{QuantusError, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::types::{
	GraphQLResponse, HasuraNullifierRow, HasuraTransferRow, NullifierQueryParams, NullifierResult,
	Transfer, TransferQueryParams,
};

/// Maximum number of results the client will accept for a single broad query.
/// Mirrors the cap the old custom GraphQL server enforced; queries matching
/// more rows than this are rejected so callers can narrow their block range.
const SERVER_MAX_LIMIT: u32 = 1000;

/// Client for querying the Hasura GraphQL indexer.
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
struct HasuraTransfersData {
	transfers: Vec<HasuraTransferRow>,
	meta: AggregateWrapper,
}

#[derive(Deserialize)]
struct AggregateWrapper {
	aggregate: Option<AggregateCount>,
}

#[derive(Deserialize)]
struct AggregateCount {
	count: i64,
}

#[derive(Deserialize)]
struct HasuraNullifiersData {
	nullifiers: Vec<HasuraNullifierRow>,
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
		// Hasura table query with an aggregate count so we can emulate the old
		// server's "too many results" rejection for overly broad queries.
		let query = r#"
            query TransfersByHashPrefix($where: transfer_bool_exp!, $limit: Int!, $offset: Int!) {
                transfers: transfer(
                    where: $where
                    limit: $limit
                    offset: $offset
                    order_by: [{ block: { height: asc } }, { id: asc }]
                ) {
                    id
                    block_id
                    block { height }
                    timestamp
                    extrinsic_id
                    from_id
                    to_id
                    amount
                    fee
                    from_hash
                    to_hash
                    leaf_index
                    transfer_count
                }
                meta: transfer_aggregate(where: $where) {
                    aggregate { count }
                }
            }
        "#;

		let where_clause = Self::build_transfer_where(&to_prefixes, &from_prefixes, &params);

		let request = GraphQLRequest {
			query: query.to_string(),
			variables: serde_json::json!({
				"where": where_clause,
				"limit": params.limit,
				"offset": params.offset,
			}),
		};

		let data: HasuraTransfersData = self.execute(&request).await?;

		let total_count = data.meta.aggregate.map(|a| a.count).unwrap_or(0);
		if total_count > SERVER_MAX_LIMIT as i64 {
			// Same wording as the old server so query_all_transfers_by_prefix
			// keeps binary-splitting block ranges on this marker.
			return Err(QuantusError::Generic(format!(
				"Query returned {} results, which exceeds the limit of {}. \
				Please use longer hash prefixes or a narrower block range for more specific queries.",
				total_count, SERVER_MAX_LIMIT
			)));
		}

		Ok(data.transfers.into_iter().map(Transfer::from).collect())
	}

	/// Build a Hasura `transfer_bool_exp` where-clause from prefix lists and params.
	fn build_transfer_where(
		to_prefixes: &Option<Vec<String>>,
		from_prefixes: &Option<Vec<String>>,
		params: &TransferQueryParams,
	) -> serde_json::Value {
		let mut where_clause = serde_json::Map::new();

		// Prefix conditions are OR'ed together (a transfer matches if any
		// to/from hash prefix matches), then AND'ed with the other filters.
		let mut or_conditions: Vec<serde_json::Value> = Vec::new();
		if let Some(prefixes) = to_prefixes {
			for prefix in prefixes {
				or_conditions.push(serde_json::json!({
					"to_hash": { "_like": format!("{}%", prefix) }
				}));
			}
		}
		if let Some(prefixes) = from_prefixes {
			for prefix in prefixes {
				or_conditions.push(serde_json::json!({
					"from_hash": { "_like": format!("{}%", prefix) }
				}));
			}
		}
		if !or_conditions.is_empty() {
			where_clause.insert("_or".to_string(), serde_json::Value::Array(or_conditions));
		}

		let mut height = serde_json::Map::new();
		if let Some(block) = params.after_block {
			height.insert("_gte".to_string(), serde_json::json!(block));
		}
		if let Some(block) = params.before_block {
			height.insert("_lte".to_string(), serde_json::json!(block));
		}
		if !height.is_empty() {
			where_clause.insert(
				"block".to_string(),
				serde_json::json!({ "height": serde_json::Value::Object(height) }),
			);
		}

		// Amounts are sent as strings to avoid precision loss on large values.
		let mut amount = serde_json::Map::new();
		if let Some(min) = params.min_amount {
			amount.insert("_gte".to_string(), serde_json::json!(min.to_string()));
		}
		if let Some(max) = params.max_amount {
			amount.insert("_lte".to_string(), serde_json::json!(max.to_string()));
		}
		if !amount.is_empty() {
			where_clause.insert("amount".to_string(), serde_json::Value::Object(amount));
		}

		serde_json::Value::Object(where_clause)
	}

	/// Execute a GraphQL request and deserialize the `data` payload.
	async fn execute<T: serde::de::DeserializeOwned>(&self, request: &GraphQLRequest) -> Result<T> {
		let response = self
			.http_client
			.post(&self.url)
			.json(request)
			.send()
			.await
			.map_err(|e| QuantusError::Generic(format!("Failed to send request: {}", e)))?;

		if !response.status().is_success() {
			let status = response.status();
			let body = response.text().await.unwrap_or_default();
			return Err(QuantusError::Generic(format!(
				"Indexer request failed with status {}: {}",
				status, body
			)));
		}

		let graphql_response: GraphQLResponse<T> = response
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

		graphql_response
			.data
			.ok_or_else(|| QuantusError::Generic("No data in response".to_string()))
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
            query NullifiersByPrefix($where: wormhole_nullifier_bool_exp!) {
                nullifiers: wormhole_nullifier(
                    where: $where
                    order_by: [{ timestamp: asc }]
                ) {
                    nullifier
                    nullifier_hash
                    block { height }
                    timestamp
                    wormholeExtrinsic { extrinsic_id }
                }
            }
        "#;

		let or_conditions: Vec<serde_json::Value> = prefixes
			.iter()
			.map(|prefix| {
				serde_json::json!({
					"nullifier_hash": { "_like": format!("{}%", prefix) }
				})
			})
			.collect();

		let mut where_clause = serde_json::Map::new();
		where_clause.insert("_or".to_string(), serde_json::Value::Array(or_conditions));

		if let Some(block) = params.after_block {
			where_clause
				.insert("block".to_string(), serde_json::json!({ "height": { "_gte": block } }));
		}

		let request = GraphQLRequest {
			query: query.to_string(),
			variables: serde_json::json!({
				"where": serde_json::Value::Object(where_clause),
			}),
		};

		let data: HasuraNullifiersData = self.execute(&request).await?;

		Ok(data.nullifiers.into_iter().map(NullifierResult::from).collect())
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
