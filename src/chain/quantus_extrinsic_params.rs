use codec::{Compact, Encode};
use scale_info::TypeInfo;
use sp_runtime::{generic::Era, traits::BlakeTwo256};
use subxt::config::extrinsic_params::{ExtrinsicParams, ExtrinsicParamsEncoder, Params};
use subxt::config::{ClientState, Config};
use subxt::ext::sp_core::H256;

/// Simple tip (identical layout to PlainTip in resonance-api-client)
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Encode, TypeInfo)]
pub struct PlainTip {
    #[codec(compact)]
    tip: u128,
}

impl From<u128> for PlainTip {
    fn from(v: u128) -> Self {
        Self { tip: v }
    }
}

/// Transaction extension layout expected by Quantus runtime
#[derive(Clone, Debug, Encode, TypeInfo, PartialEq, Eq)]
pub struct QuantusTxExtension<Index> {
    pub era: Era,
    #[codec(compact)]
    pub nonce: Index,
    pub tip: PlainTip,
    pub check_hash: u8, // always 0 (metadata hash disabled)
}

impl<Index> QuantusTxExtension<Index> {
    fn new(era: Era, nonce: Index, tip: PlainTip) -> Self {
        Self {
            era,
            nonce,
            tip,
            check_hash: 0,
        }
    }
}

/// Implicit tuple (must match runtime order)
pub type QuantusImplicit<Hash> = ((), u32, u32, Hash, Hash, (), (), (), Option<H256>, ());

/// Additional params builder
#[derive(Clone, Debug)]
pub struct QuantusAdditionalParams {
    /// era (default Immortal)
    pub era: Era,
    /// optional nonce override
    pub nonce: Option<u32>,
    /// tip
    pub tip: PlainTip,
}

impl Default for QuantusAdditionalParams {
    fn default() -> Self {
        Self {
            era: Era::Immortal,
            nonce: None,
            tip: PlainTip::default(),
        }
    }
}

impl<T: Config> Params<T> for QuantusAdditionalParams {
    fn inject_nonce(&mut self, n: <T as Config>::Index) {
        if self.nonce.is_none() {
            // T::Index may not be u32; convert via Into<u64> then as u32
            self.nonce = Some(n.into() as u32);
        }
    }
}

/// Full ExtrinsicParams impl
#[derive(Clone, Debug)]
pub struct QuantusExtrinsicParams<T: Config> {
    tip: PlainTip,
    era: Era,
    nonce: T::Index,
    spec_version: u32,
    tx_version: u32,
    genesis_hash: <T::Hasher as subxt::config::Hasher>::Output,
}

impl<T: Config> ExtrinsicParams<T> for QuantusExtrinsicParams<T> {
    type Params = QuantusAdditionalParams;

    fn new(client: &ClientState<T>, mut params: Self::Params) -> Result<Self, subxt::error::Error> {
        // ensure nonce present (SubXT will have injected if None)
        let nonce = params.nonce.unwrap_or_default().into();
        Ok(Self {
            tip: params.tip,
            era: params.era,
            nonce,
            spec_version: client.runtime_version.spec_version,
            tx_version: client.runtime_version.transaction_version,
            genesis_hash: client.genesis_hash,
        })
    }
}

impl<T: Config> ExtrinsicParamsEncoder for QuantusExtrinsicParams<T> {
    fn encode_value_to(&self, out: &mut Vec<u8>) {
        let ext = QuantusTxExtension::new(self.era, self.nonce, self.tip);
        ext.encode_to(out);
    }

    fn encode_implicit_to(&self, out: &mut Vec<u8>) {
        let checkpoint_hash = self.genesis_hash; // immortal, so use genesis for era checkpoint
        let implicit: QuantusImplicit<_> = (
            (),                // CheckNonZeroSender
            self.spec_version, // CheckSpecVersion
            self.tx_version,   // CheckTxVersion
            self.genesis_hash, // CheckGenesis
            checkpoint_hash,   // CheckEra
            (),
            (),
            (),           // CheckNonce / Weight / TxPayment (implicit)
            None::<H256>, // CheckMetadataHash disabled
            (),           // WeightReclaim (default)
        );
        implicit.encode_to(out);
    }
}
