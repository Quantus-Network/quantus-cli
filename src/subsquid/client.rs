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
		let (transfers, total_count) =
			self.query_transfers_by_prefix_page(to_prefixes, from_prefixes, params).await?;

		if total_count > SERVER_MAX_LIMIT as i64 {
			// Same wording as the old server so query_all_transfers_by_prefix
			// keeps binary-splitting block ranges on this marker.
			return Err(QuantusError::Generic(format!(
				"Query returned {} results, which exceeds the limit of {}. \
				Please use longer hash prefixes or a narrower block range for more specific queries.",
				total_count, SERVER_MAX_LIMIT
			)));
		}

		Ok(transfers)
	}

	async fn query_transfers_by_prefix_page(
		&self,
		to_prefixes: Option<Vec<String>>,
		from_prefixes: Option<Vec<String>>,
		params: TransferQueryParams,
	) -> Result<(Vec<Transfer>, i64)> {
		// Hasura table query with an aggregate count so callers can detect when a
		// block range needs further narrowing or offset-based pagination.
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

		let total_count = data.meta.aggregate.map(|a| a.count).ok_or_else(|| {
			QuantusError::Generic(
				"Missing transfer aggregate count in indexer response".to_string(),
			)
		})?;
		let transfers = data.transfers.into_iter().map(Transfer::from).collect();

		Ok((transfers, total_count))
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

	/// Fetch every transfer matching the given prefixes.
	///
	/// The server caps any single query at 1000 results. This method handles that
	/// by binary-splitting the `[after_block, before_block]` range whenever the cap
	/// is hit, then falling back to offset pagination if a single block still exceeds
	/// the cap.
	///
	/// `base_params.after_block` / `base_params.before_block` are honored as the initial
	/// bounds; unset means `0` / `i32::MAX` (GraphQL `Int` is signed 32-bit so we can't
	/// exceed that). Other filters (amount) are forwarded unchanged. `limit` is
	/// always set to the server max (1000) per sub-query. `offset` is applied once to
	/// the complete ordered result set, not to each block-range sub-query.
	pub async fn query_all_transfers_by_prefix(
		&self,
		to_prefixes: Option<Vec<String>>,
		from_prefixes: Option<Vec<String>>,
		base_params: TransferQueryParams,
	) -> Result<Vec<Transfer>> {
		const MAX_BLOCK_SENTINEL: u32 = i32::MAX as u32;

		let initial_lo = base_params.after_block.unwrap_or(0);
		let initial_hi = base_params.before_block.unwrap_or(MAX_BLOCK_SENTINEL);

		if initial_lo > initial_hi {
			return Ok(vec![]);
		}

		let global_offset = base_params.offset as usize;
		let mut all: Vec<Transfer> = Vec::new();
		let mut stack: Vec<(u32, u32)> = vec![(initial_lo, initial_hi)];

		while let Some((lo, hi)) = stack.pop() {
			let params = base_params
				.clone()
				.with_after_block(lo)
				.with_before_block(hi)
				.with_limit(SERVER_MAX_LIMIT)
				.with_offset(0);

			let (transfers, total_count) = self
				.query_transfers_by_prefix_page(
					to_prefixes.clone(),
					from_prefixes.clone(),
					params.clone(),
				)
				.await?;

			if total_count <= SERVER_MAX_LIMIT as i64 {
				// A Hasura deployment with an API row cap below our requested
				// limit would return fewer rows than total_count and silently
				// drop the rest; fail instead of returning a truncated set.
				if transfers.len() as i64 != total_count {
					return Err(QuantusError::Generic(format!(
						"Indexer returned {} of {} transfers for blocks {}..={}; the server row cap appears lower than the requested limit of {}",
						transfers.len(),
						total_count,
						lo,
						hi,
						SERVER_MAX_LIMIT
					)));
				}
				all.extend(transfers);
				continue;
			}

			if lo != hi {
				let mid = lo + (hi - lo) / 2;
				stack.push((mid + 1, hi));
				stack.push((lo, mid));
				continue;
			}

			// Single-block offset pagination: total_count > SERVER_MAX_LIMIT,
			// so this first page must be exactly the server limit.
			if transfers.len() != SERVER_MAX_LIMIT as usize {
				return Err(QuantusError::Generic(format!(
					"Indexer returned {} of {} transfers on the first page for block {}; the server row cap appears lower than the requested limit of {}",
					transfers.len(),
					total_count,
					lo,
					SERVER_MAX_LIMIT
				)));
			}
			all.extend(transfers);
			let total_count = u32::try_from(total_count).map_err(|_| {
				QuantusError::Generic(format!(
					"Transfer count {} for block {} exceeds supported pagination range",
					total_count, lo
				))
			})?;
			let mut offset = params.offset.checked_add(SERVER_MAX_LIMIT).ok_or_else(|| {
				QuantusError::Generic(format!(
					"Transfer pagination offset overflow for block {}",
					lo
				))
			})?;

			while offset < total_count {
				let page_params = params.clone().with_offset(offset);
				let (page, _) = self
					.query_transfers_by_prefix_page(
						to_prefixes.clone(),
						from_prefixes.clone(),
						page_params,
					)
					.await?;

				// Every page must be exactly full except the last, which must
				// hold the remainder; anything else means rows were dropped.
				let expected = std::cmp::min(SERVER_MAX_LIMIT, total_count - offset) as usize;
				if page.len() != expected {
					return Err(QuantusError::Generic(format!(
						"Indexer returned {} transfers at offset {} of {} for block {}, expected {}",
						page.len(),
						offset,
						total_count,
						lo,
						expected
					)));
				}

				all.extend(page);
				offset = offset.checked_add(SERVER_MAX_LIMIT).ok_or_else(|| {
					QuantusError::Generic(format!(
						"Transfer pagination offset overflow for block {}",
						lo
					))
				})?;
			}
		}

		Ok(all.into_iter().skip(global_offset).collect())
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
	use serde_json::{json, Value};
	use std::{
		collections::HashSet,
		io::{Read, Write},
		net::{TcpListener, TcpStream},
		sync::{
			atomic::{AtomicUsize, Ordering},
			Arc, Mutex,
		},
		thread,
		time::Duration,
	};

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

	fn transfer_row(i: usize, block_height: i64) -> Value {
		json!({
			"id": format!("transfer-{i}"),
			"block_id": format!("block-{i}"),
			"block": { "height": block_height },
			"timestamp": "2026-01-01T00:00:00Z",
			"extrinsic_id": null,
			"from_id": "qzFrom",
			"to_id": "qzTo",
			"amount": "1",
			"fee": "0",
			"from_hash": "from-hash",
			"to_hash": "target-prefix-full-hash",
			"leaf_index": i.to_string(),
			"transfer_count": (i + 1).to_string()
		})
	}

	fn read_http_request(stream: &mut TcpStream) -> String {
		stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
		let mut buf = Vec::new();
		let mut tmp = [0u8; 4096];
		let mut header_end = None;
		let mut content_len = 0usize;

		loop {
			let n = stream.read(&mut tmp).unwrap();
			assert_ne!(n, 0, "mock indexer closed before request completed");
			buf.extend_from_slice(&tmp[..n]);

			if header_end.is_none() {
				if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
					header_end = Some(pos + 4);
					let headers = String::from_utf8_lossy(&buf[..pos]);
					for line in headers.lines() {
						if let Some((name, value)) = line.split_once(':') {
							if name.eq_ignore_ascii_case("content-length") {
								content_len = value.trim().parse().unwrap();
							}
						}
					}
				}
			}

			if let Some(end) = header_end {
				if buf.len() >= end + content_len {
					break;
				}
			}
		}

		String::from_utf8(buf).unwrap()
	}

	fn write_json_response(stream: &mut TcpStream, body: Value) {
		let body = body.to_string();
		write!(
			stream,
			"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
			body.len(),
			body
		)
		.unwrap();
	}

	fn parse_request_vars(request: &str) -> (usize, usize, u64, u64) {
		let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
		let request_json: Value = serde_json::from_str(body).expect("GraphQL JSON body");
		let variables = &request_json["variables"];
		let height = &variables["where"]["block"]["height"];
		let after = height["_gte"].as_u64().unwrap_or(0);
		let before = height["_lte"].as_u64().unwrap_or(u64::from(u32::MAX));
		let limit = variables["limit"].as_u64().expect("limit") as usize;
		let offset = variables["offset"].as_u64().expect("offset") as usize;
		(limit, offset, after, before)
	}

	/// #160776: missing/null aggregate must not be treated as a complete page.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn missing_aggregate_count_rejects_incomplete_prefix_page() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = format!("http://{}", listener.local_addr().unwrap());
		let rows: Arc<Vec<Value>> =
			Arc::new((0..=1000).map(|i| transfer_row(i, i as i64)).collect());
		let request_count = Arc::new(AtomicUsize::new(0));
		let server_rows = Arc::clone(&rows);
		let server_count = Arc::clone(&request_count);

		thread::spawn(move || {
			let (mut stream, _) = listener.accept().unwrap();
			server_count.fetch_add(1, Ordering::SeqCst);
			let request = read_http_request(&mut stream);
			let (limit, _offset, _lo, _hi) = parse_request_vars(&request);
			let transfers: Vec<Value> = server_rows.iter().take(limit).cloned().collect();
			write_json_response(
				&mut stream,
				json!({
					"data": {
						"transfers": transfers,
						"meta": { "aggregate": null }
					}
				}),
			);
		});

		let client = SubsquidClient::new(endpoint).unwrap();
		let err = client
			.query_all_transfers_by_prefix(
				Some(vec!["target".to_string()]),
				None,
				TransferQueryParams::new().with_after_block(0).with_before_block(1000),
			)
			.await
			.expect_err("missing aggregate must fail closed");

		assert!(
			err.to_string().contains("Missing transfer aggregate count"),
			"unexpected error: {err}"
		);
		assert_eq!(request_count.load(Ordering::SeqCst), 1);
	}

	/// #159916: a single over-limit block must be offset-paginated, not aborted.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn single_block_over_limit_is_offset_paginated() {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = format!("http://{}", listener.local_addr().unwrap());
		let total = 1001usize;
		let rows: Arc<Vec<Value>> = Arc::new((0..total).map(|i| transfer_row(i, 42)).collect());
		let observed_offsets = Arc::new(Mutex::new(Vec::new()));
		let server_rows = Arc::clone(&rows);
		let server_offsets = Arc::clone(&observed_offsets);

		thread::spawn(move || {
			for _ in 0..4 {
				let Ok((mut stream, _)) = listener.accept() else { break };
				let request = read_http_request(&mut stream);
				let (limit, offset, lo, hi) = parse_request_vars(&request);
				assert_eq!(lo, 42);
				assert_eq!(hi, 42);
				server_offsets.lock().unwrap().push(offset);
				let page: Vec<Value> =
					server_rows.iter().skip(offset).take(limit).cloned().collect();
				write_json_response(
					&mut stream,
					json!({
						"data": {
							"transfers": page,
							"meta": { "aggregate": { "count": total as i64 } }
						}
					}),
				);
			}
		});

		let client = SubsquidClient::new(endpoint).unwrap();
		let transfers = client
			.query_all_transfers_by_prefix(
				Some(vec!["target".to_string()]),
				None,
				TransferQueryParams::new().with_after_block(42).with_before_block(42),
			)
			.await
			.expect("single-block over-limit fetch must complete via offset pages");

		assert_eq!(transfers.len(), total);
		assert_eq!(transfers.first().map(|t| t.id.as_str()), Some("transfer-0"));
		assert_eq!(transfers.last().map(|t| t.id.as_str()), Some("transfer-1000"));
		let offsets = observed_offsets.lock().unwrap().clone();
		assert!(offsets.contains(&0), "expected first page at offset 0: {offsets:?}");
		assert!(offsets.contains(&1000), "expected second page at offset 1000: {offsets:?}");
	}

	/// #160777: caller offset must apply once globally across split ranges.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn query_all_transfers_applies_offset_globally_across_split_ranges() {
		const TOTAL_TRANSFERS: u32 = 1001;
		const GLOBAL_OFFSET: u32 = 1;

		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let endpoint = format!("http://{}", listener.local_addr().unwrap());

		thread::spawn(move || {
			for stream in listener.incoming().take(32) {
				let Ok(mut stream) = stream else { continue };
				let request = read_http_request(&mut stream);
				let (limit, offset, lo, hi) = parse_request_vars(&request);
				let matching: Vec<u32> =
					(0..TOTAL_TRANSFERS).filter(|h| *h >= lo as u32 && *h <= hi as u32).collect();
				let aggregate_count = matching.len();
				let page: Vec<Value> = matching
					.into_iter()
					.skip(offset)
					.take(limit)
					.map(|height| transfer_row(height as usize, height as i64))
					.collect();
				write_json_response(
					&mut stream,
					json!({
						"data": {
							"transfers": page,
							"meta": { "aggregate": { "count": aggregate_count as i64 } }
						}
					}),
				);
			}
		});

		let client = SubsquidClient::new(endpoint).unwrap();

		let complete = client
			.query_all_transfers_by_prefix(
				Some(vec!["eligible".to_string()]),
				None,
				TransferQueryParams::new()
					.with_after_block(0)
					.with_before_block(TOTAL_TRANSFERS)
					.with_offset(0),
			)
			.await
			.expect("baseline exhaustive query");

		let expected: HashSet<String> =
			complete.iter().skip(GLOBAL_OFFSET as usize).map(|t| t.id.clone()).collect();

		let shifted = client
			.query_all_transfers_by_prefix(
				Some(vec!["eligible".to_string()]),
				None,
				TransferQueryParams::new()
					.with_after_block(0)
					.with_before_block(TOTAL_TRANSFERS)
					.with_offset(GLOBAL_OFFSET),
			)
			.await
			.expect("global offset query");

		let shifted_ids: HashSet<String> = shifted.iter().map(|t| t.id.clone()).collect();
		assert_eq!(
			shifted_ids, expected,
			"offset must skip once across the complete ordered result set"
		);
	}
}
