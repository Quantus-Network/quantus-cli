// This is a generated file used by a macro - do not change.

#![allow(dead_code)]
#![allow(unused_imports)]

use super::*;
use dilithium_crypto::DilithiumSignatureScheme;
use poseidon_resonance::PoseidonHasher;
use substrate_api_client::ac_primitives::{
    AccountData, AccountId32, Block, ExtrinsicSigner, GenericExtrinsicParams, Header, MultiAddress,
    OpaqueExtrinsic, PlainTip, H256,
};
use subxt::config::transaction_extensions;
use subxt::OnlineClient;
use subxt::{
    config::substrate::{BlakeTwo256, SubstrateHeader},
    Config, PolkadotConfig,
};

#[subxt::subxt(runtime_metadata_path = "./src/quantus_metadata.scale")]

mod src_chain {}
pub use src_chain::*;

/// Configuration of the chain
pub enum ChainConfig {}
impl Config for ChainConfig {
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, u32>;
    type Signature = DilithiumSignatureScheme;
    type Hasher = BlakeTwo256; // TODO: replace with PoseidonHasher
    type Header = SubstrateHeader<u32, BlakeTwo256>;
    type AssetId = u32;
    type ExtrinsicParams = transaction_extensions::AnyOf<
        Self,
        (
            transaction_extensions::VerifySignature<Self>,
            transaction_extensions::CheckSpecVersion,
            transaction_extensions::CheckTxVersion,
            transaction_extensions::CheckNonce,
            transaction_extensions::CheckMortality<Self>,
            transaction_extensions::ChargeAssetTxPayment<Self>,
            transaction_extensions::ChargeTransactionPayment,
            transaction_extensions::CheckMetadataHash,
        ),
    >;
}
