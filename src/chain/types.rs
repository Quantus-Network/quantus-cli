// This is a generated file used by a macro - do not change.

#![allow(dead_code)]
#![allow(unused_imports)]

use dilithium_crypto::ResonanceSignatureScheme;
use poseidon_resonance::PoseidonHasher;
use sp_core::H256;
use substrate_api_client::ac_primitives::{AccountId32, MultiAddress};

use subxt::config::substrate::SubstrateHeader;
use subxt::config::DefaultExtrinsicParams;
use subxt::{
    client::ClientState,
    config::{Config, ExtrinsicParams, ExtrinsicParamsEncoder},
};
use subxt_metadata::Metadata as SubxtMetadata;

// use super::quantus_extrinsic_params;

/// Wrapper around the `PoseidonHasher` that implements the `subxt::config::Hasher` trait
/// required by the SubXT runtime `Config`.
#[derive(Debug, Clone, Copy)]
pub struct SubxtPoseidonHasher;

impl subxt::config::Hasher for SubxtPoseidonHasher {
    type Output = sp_core::H256;

    fn new(_metadata: &SubxtMetadata) -> Self {
        SubxtPoseidonHasher
    }

    fn hash(&self, bytes: &[u8]) -> Self::Output {
        <PoseidonHasher as sp_runtime::traits::Hash>::hash(bytes)
    }
}

// #[subxt::subxt(runtime_metadata_path = "./src/quantus_metadata.scale")]

// mod src_chain {}
// pub use src_chain::*;

/// Configuration of the chain
pub enum ChainConfig {}
impl Config for ChainConfig {
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, u32>;
    type Signature = ResonanceSignatureScheme;
    type Hasher = SubxtPoseidonHasher;
    type Header = SubstrateHeader<u32, SubxtPoseidonHasher>;
    type AssetId = u32;
    type ExtrinsicParams = DefaultExtrinsicParams<Self>;
}
