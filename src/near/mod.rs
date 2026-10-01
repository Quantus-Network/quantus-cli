//! NEAR protocol integration.
//!
//! NEAR accepts FIPS 204 ML-DSA-65 as a transaction-signature scheme and
//! access-key type from protocol version 85, which lets a Quantus ML-DSA-65
//! wallet control a NEAR account. This module provides the minimal client
//! side: borsh transaction encoding ([`protocol`]), transaction hashing and
//! signing ([`sign`]), air-gapped signing with a cold wallet over QR
//! ([`cold`]), and a JSON-RPC client ([`rpc`]).
//!
//! ML-DSA-87 has no NEAR equivalent; only ML-DSA-65 wallets can sign here.

pub mod cold;
pub mod protocol;
pub mod rpc;
pub mod sign;
