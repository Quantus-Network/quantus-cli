#[allow(dead_code, unused_imports, non_camel_case_types, unreachable_patterns)]
#[allow(clippy::all)]
#[allow(rustdoc::broken_intra_doc_links)]
pub mod api {
	#[allow(unused_imports)]
	mod root_mod {
		pub use super::*;
	}
	pub static PALLETS: [&str; 21usize] = [
		"System",
		"Timestamp",
		"Balances",
		"TransactionPayment",
		"Sudo",
		"QPoW",
		"Wormhole",
		"MiningRewards",
		"Vesting",
		"Preimage",
		"Scheduler",
		"Utility",
		"Referenda",
		"ReversibleTransfers",
		"ConvictionVoting",
		"TechCollective",
		"TechReferenda",
		"MerkleAirdrop",
		"TreasuryPallet",
		"Origins",
		"Recovery",
	];
	pub static RUNTIME_APIS: [&str; 11usize] = [
		"Core",
		"Metadata",
		"BlockBuilder",
		"TaggedTransactionQueue",
		"OffchainWorkerApi",
		"SessionKeys",
		"QPoWApi",
		"AccountNonceApi",
		"TransactionPaymentApi",
		"TransactionPaymentCallApi",
		"GenesisBuilder",
	];
	#[doc = r" The error type that is returned when there is a runtime issue."]
	pub type DispatchError = runtime_types::sp_runtime::DispatchError;
	#[doc = r" The outer event enum."]
	pub type Event = runtime_types::quantus_runtime::RuntimeEvent;
	#[doc = r" The outer extrinsic enum."]
	pub type Call = runtime_types::quantus_runtime::RuntimeCall;
	#[doc = r" The outer error enum represents the DispatchError's Module variant."]
	pub type Error = runtime_types::quantus_runtime::RuntimeError;
	pub fn constants() -> ConstantsApi {
		ConstantsApi
	}
	pub fn storage() -> StorageApi {
		StorageApi
	}
	pub fn tx() -> TransactionApi {
		TransactionApi
	}
	pub fn apis() -> runtime_apis::RuntimeApi {
		runtime_apis::RuntimeApi
	}
	pub mod runtime_apis {
		use super::{root_mod, runtime_types};
		use ::subxt::ext::subxt_core::ext::codec::Encode;
		pub struct RuntimeApi;
		impl RuntimeApi {
			pub fn core(&self) -> core::Core {
				core::Core
			}
			pub fn metadata(&self) -> metadata::Metadata {
				metadata::Metadata
			}
			pub fn block_builder(&self) -> block_builder::BlockBuilder {
				block_builder::BlockBuilder
			}
			pub fn tagged_transaction_queue(
				&self,
			) -> tagged_transaction_queue::TaggedTransactionQueue {
				tagged_transaction_queue::TaggedTransactionQueue
			}
			pub fn offchain_worker_api(&self) -> offchain_worker_api::OffchainWorkerApi {
				offchain_worker_api::OffchainWorkerApi
			}
			pub fn session_keys(&self) -> session_keys::SessionKeys {
				session_keys::SessionKeys
			}
			pub fn q_po_w_api(&self) -> q_po_w_api::QPoWApi {
				q_po_w_api::QPoWApi
			}
			pub fn account_nonce_api(&self) -> account_nonce_api::AccountNonceApi {
				account_nonce_api::AccountNonceApi
			}
			pub fn transaction_payment_api(
				&self,
			) -> transaction_payment_api::TransactionPaymentApi {
				transaction_payment_api::TransactionPaymentApi
			}
			pub fn transaction_payment_call_api(
				&self,
			) -> transaction_payment_call_api::TransactionPaymentCallApi {
				transaction_payment_call_api::TransactionPaymentCallApi
			}
			pub fn genesis_builder(&self) -> genesis_builder::GenesisBuilder {
				genesis_builder::GenesisBuilder
			}
		}
		pub mod core {
			use super::{root_mod, runtime_types};
			#[doc = " The `Core` runtime api that every Substrate runtime needs to implement."]
			pub struct Core;
			impl Core {
				#[doc = " Returns the version of the runtime."]
				pub fn version(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::Version,
					types::version::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"Core",
						"version",
						types::Version {},
						[
							79u8, 22u8, 137u8, 4u8, 40u8, 64u8, 30u8, 180u8, 49u8, 222u8, 114u8,
							125u8, 44u8, 25u8, 33u8, 152u8, 98u8, 42u8, 72u8, 178u8, 240u8, 103u8,
							34u8, 187u8, 81u8, 161u8, 183u8, 6u8, 120u8, 2u8, 146u8, 0u8,
						],
					)
				}
				#[doc = " Execute the given block."]
				pub fn execute_block(
					&self,
					block: types::execute_block::Block,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::ExecuteBlock,
					types::execute_block::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"Core",
						"execute_block",
						types::ExecuteBlock { block },
						[
							133u8, 135u8, 228u8, 65u8, 106u8, 27u8, 85u8, 158u8, 112u8, 254u8,
							93u8, 26u8, 102u8, 201u8, 118u8, 216u8, 249u8, 247u8, 91u8, 74u8, 56u8,
							208u8, 231u8, 115u8, 131u8, 29u8, 209u8, 6u8, 65u8, 57u8, 214u8, 125u8,
						],
					)
				}
				#[doc = " Initialize a block with the given header and return the runtime executive mode."]
				pub fn initialize_block(
					&self,
					header: types::initialize_block::Header,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::InitializeBlock,
					types::initialize_block::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"Core",
						"initialize_block",
						types::InitializeBlock { header },
						[
							132u8, 169u8, 113u8, 112u8, 80u8, 139u8, 113u8, 35u8, 41u8, 81u8, 36u8,
							35u8, 37u8, 202u8, 29u8, 207u8, 205u8, 229u8, 145u8, 7u8, 133u8, 94u8,
							25u8, 108u8, 233u8, 86u8, 234u8, 29u8, 236u8, 57u8, 56u8, 186u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod version {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::sp_version::RuntimeVersion;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Version {}
				pub mod execute_block {
					use super::runtime_types;
					pub type Block = runtime_types :: sp_runtime :: generic :: block :: Block < runtime_types :: sp_runtime :: generic :: header :: Header < :: core :: primitive :: u32 > , :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > > ;
					pub mod output {
						use super::runtime_types;
						pub type Output = ();
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ExecuteBlock {
					pub block: execute_block::Block,
				}
				pub mod initialize_block {
					use super::runtime_types;
					pub type Header =
						runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::sp_runtime::ExtrinsicInclusionMode;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct InitializeBlock {
					pub header: initialize_block::Header,
				}
			}
		}
		pub mod metadata {
			use super::{root_mod, runtime_types};
			#[doc = " The `Metadata` api trait that returns metadata for the runtime."]
			pub struct Metadata;
			impl Metadata {
				#[doc = " Returns the metadata of a runtime."]
				pub fn metadata(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::Metadata,
					types::metadata::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"Metadata",
						"metadata",
						types::Metadata {},
						[
							231u8, 24u8, 67u8, 152u8, 23u8, 26u8, 188u8, 82u8, 229u8, 6u8, 185u8,
							27u8, 175u8, 68u8, 83u8, 122u8, 69u8, 89u8, 185u8, 74u8, 248u8, 87u8,
							217u8, 124u8, 193u8, 252u8, 199u8, 186u8, 196u8, 179u8, 179u8, 96u8,
						],
					)
				}
				#[doc = " Returns the metadata at a given version."]
				#[doc = ""]
				#[doc = " If the given `version` isn't supported, this will return `None`."]
				#[doc = " Use [`Self::metadata_versions`] to find out about supported metadata version of the runtime."]
				pub fn metadata_at_version(
					&self,
					version: types::metadata_at_version::Version,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::MetadataAtVersion,
					types::metadata_at_version::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"Metadata",
						"metadata_at_version",
						types::MetadataAtVersion { version },
						[
							131u8, 53u8, 212u8, 234u8, 16u8, 25u8, 120u8, 252u8, 153u8, 153u8,
							216u8, 28u8, 54u8, 113u8, 52u8, 236u8, 146u8, 68u8, 142u8, 8u8, 10u8,
							169u8, 131u8, 142u8, 204u8, 38u8, 48u8, 108u8, 134u8, 86u8, 226u8,
							61u8,
						],
					)
				}
				#[doc = " Returns the supported metadata versions."]
				#[doc = ""]
				#[doc = " This can be used to call `metadata_at_version`."]
				pub fn metadata_versions(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::MetadataVersions,
					types::metadata_versions::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"Metadata",
						"metadata_versions",
						types::MetadataVersions {},
						[
							23u8, 144u8, 137u8, 91u8, 188u8, 39u8, 231u8, 208u8, 252u8, 218u8,
							224u8, 176u8, 77u8, 32u8, 130u8, 212u8, 223u8, 76u8, 100u8, 190u8,
							82u8, 94u8, 190u8, 8u8, 82u8, 244u8, 225u8, 179u8, 85u8, 176u8, 56u8,
							16u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod metadata {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::sp_core::OpaqueMetadata;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Metadata {}
				pub mod metadata_at_version {
					use super::runtime_types;
					pub type Version = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							::core::option::Option<runtime_types::sp_core::OpaqueMetadata>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct MetadataAtVersion {
					pub version: metadata_at_version::Version,
				}
				pub mod metadata_versions {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u32>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct MetadataVersions {}
			}
		}
		pub mod block_builder {
			use super::{root_mod, runtime_types};
			#[doc = " The `BlockBuilder` api trait that provides the required functionality for building a block."]
			pub struct BlockBuilder;
			impl BlockBuilder {
				#[doc = " Apply the given extrinsic."]
				#[doc = ""]
				#[doc = " Returns an inclusion outcome which specifies if this extrinsic is included in"]
				#[doc = " this block or not."]
				pub fn apply_extrinsic(
					&self,
					extrinsic: types::apply_extrinsic::Extrinsic,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::ApplyExtrinsic,
					types::apply_extrinsic::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"BlockBuilder",
						"apply_extrinsic",
						types::ApplyExtrinsic { extrinsic },
						[
							192u8, 184u8, 199u8, 4u8, 85u8, 136u8, 214u8, 205u8, 29u8, 29u8, 98u8,
							145u8, 172u8, 92u8, 168u8, 161u8, 150u8, 133u8, 100u8, 243u8, 100u8,
							100u8, 118u8, 28u8, 104u8, 82u8, 93u8, 63u8, 79u8, 36u8, 149u8, 144u8,
						],
					)
				}
				#[doc = " Finish the current block."]
				pub fn finalize_block(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::FinalizeBlock,
					types::finalize_block::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"BlockBuilder",
						"finalize_block",
						types::FinalizeBlock {},
						[
							244u8, 207u8, 24u8, 33u8, 13u8, 69u8, 9u8, 249u8, 145u8, 143u8, 122u8,
							96u8, 197u8, 55u8, 64u8, 111u8, 238u8, 224u8, 34u8, 201u8, 27u8, 146u8,
							232u8, 99u8, 191u8, 30u8, 114u8, 16u8, 32u8, 220u8, 58u8, 62u8,
						],
					)
				}
				#[doc = " Generate inherent extrinsics. The inherent data will vary from chain to chain."]
				pub fn inherent_extrinsics(
					&self,
					inherent: types::inherent_extrinsics::Inherent,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::InherentExtrinsics,
					types::inherent_extrinsics::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"BlockBuilder",
						"inherent_extrinsics",
						types::InherentExtrinsics { inherent },
						[
							254u8, 110u8, 245u8, 201u8, 250u8, 192u8, 27u8, 228u8, 151u8, 213u8,
							166u8, 89u8, 94u8, 81u8, 189u8, 234u8, 64u8, 18u8, 245u8, 80u8, 29u8,
							18u8, 140u8, 129u8, 113u8, 236u8, 135u8, 55u8, 79u8, 159u8, 175u8,
							183u8,
						],
					)
				}
				#[doc = " Check that the inherents are valid. The inherent data will vary from chain to chain."]
				pub fn check_inherents(
					&self,
					block: types::check_inherents::Block,
					data: types::check_inherents::Data,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::CheckInherents,
					types::check_inherents::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"BlockBuilder",
						"check_inherents",
						types::CheckInherents { block, data },
						[
							153u8, 134u8, 1u8, 215u8, 139u8, 11u8, 53u8, 51u8, 210u8, 175u8, 197u8,
							28u8, 38u8, 209u8, 175u8, 247u8, 142u8, 157u8, 50u8, 151u8, 164u8,
							191u8, 181u8, 118u8, 80u8, 97u8, 160u8, 248u8, 110u8, 217u8, 181u8,
							234u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod apply_extrinsic {
					use super::runtime_types;
					pub type Extrinsic = :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > ;
					pub mod output {
						use super::runtime_types;
						pub type Output = :: core :: result :: Result < :: core :: result :: Result < () , runtime_types :: sp_runtime :: DispatchError > , runtime_types :: sp_runtime :: transaction_validity :: TransactionValidityError > ;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ApplyExtrinsic {
					pub extrinsic: apply_extrinsic::Extrinsic,
				}
				pub mod finalize_block {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::sp_runtime::generic::header::Header<
							::core::primitive::u32,
						>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct FinalizeBlock {}
				pub mod inherent_extrinsics {
					use super::runtime_types;
					pub type Inherent = runtime_types::sp_inherents::InherentData;
					pub mod output {
						use super::runtime_types;
						pub type Output = :: subxt :: ext :: subxt_core :: alloc :: vec :: Vec < :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > > ;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct InherentExtrinsics {
					pub inherent: inherent_extrinsics::Inherent,
				}
				pub mod check_inherents {
					use super::runtime_types;
					pub type Block = runtime_types :: sp_runtime :: generic :: block :: Block < runtime_types :: sp_runtime :: generic :: header :: Header < :: core :: primitive :: u32 > , :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > > ;
					pub type Data = runtime_types::sp_inherents::InherentData;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::sp_inherents::CheckInherentsResult;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct CheckInherents {
					pub block: check_inherents::Block,
					pub data: check_inherents::Data,
				}
			}
		}
		pub mod tagged_transaction_queue {
			use super::{root_mod, runtime_types};
			#[doc = " The `TaggedTransactionQueue` api trait for interfering with the transaction queue."]
			pub struct TaggedTransactionQueue;
			impl TaggedTransactionQueue {
				#[doc = " Validate the transaction."]
				#[doc = ""]
				#[doc = " This method is invoked by the transaction pool to learn details about given transaction."]
				#[doc = " The implementation should make sure to verify the correctness of the transaction"]
				#[doc = " against current state. The given `block_hash` corresponds to the hash of the block"]
				#[doc = " that is used as current state."]
				#[doc = ""]
				#[doc = " Note that this call may be performed by the pool multiple times and transactions"]
				#[doc = " might be verified in any possible order."]
				pub fn validate_transaction(
					&self,
					source: types::validate_transaction::Source,
					tx: types::validate_transaction::Tx,
					block_hash: types::validate_transaction::BlockHash,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::ValidateTransaction,
					types::validate_transaction::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TaggedTransactionQueue",
						"validate_transaction",
						types::ValidateTransaction { source, tx, block_hash },
						[
							19u8, 53u8, 170u8, 115u8, 75u8, 121u8, 231u8, 50u8, 199u8, 181u8,
							243u8, 170u8, 163u8, 224u8, 213u8, 134u8, 206u8, 207u8, 88u8, 242u8,
							80u8, 139u8, 233u8, 87u8, 175u8, 249u8, 178u8, 169u8, 255u8, 171u8,
							4u8, 125u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod validate_transaction {
					use super::runtime_types;
					pub type Source =
						runtime_types::sp_runtime::transaction_validity::TransactionSource;
					pub type Tx = :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > ;
					pub type BlockHash = ::subxt::ext::subxt_core::utils::H256;
					pub mod output {
						use super::runtime_types;
						pub type Output = :: core :: result :: Result < runtime_types :: sp_runtime :: transaction_validity :: ValidTransaction , runtime_types :: sp_runtime :: transaction_validity :: TransactionValidityError > ;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ValidateTransaction {
					pub source: validate_transaction::Source,
					pub tx: validate_transaction::Tx,
					pub block_hash: validate_transaction::BlockHash,
				}
			}
		}
		pub mod offchain_worker_api {
			use super::{root_mod, runtime_types};
			#[doc = " The offchain worker api."]
			pub struct OffchainWorkerApi;
			impl OffchainWorkerApi {
				#[doc = " Starts the off-chain task for given block header."]
				pub fn offchain_worker(
					&self,
					header: types::offchain_worker::Header,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::OffchainWorker,
					types::offchain_worker::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"OffchainWorkerApi",
						"offchain_worker",
						types::OffchainWorker { header },
						[
							10u8, 135u8, 19u8, 153u8, 33u8, 216u8, 18u8, 242u8, 33u8, 140u8, 4u8,
							223u8, 200u8, 130u8, 103u8, 118u8, 137u8, 24u8, 19u8, 127u8, 161u8,
							29u8, 184u8, 111u8, 222u8, 111u8, 253u8, 73u8, 45u8, 31u8, 79u8, 60u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod offchain_worker {
					use super::runtime_types;
					pub type Header =
						runtime_types::sp_runtime::generic::header::Header<::core::primitive::u32>;
					pub mod output {
						use super::runtime_types;
						pub type Output = ();
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct OffchainWorker {
					pub header: offchain_worker::Header,
				}
			}
		}
		pub mod session_keys {
			use super::{root_mod, runtime_types};
			#[doc = " Session keys runtime api."]
			pub struct SessionKeys;
			impl SessionKeys {
				#[doc = " Generate a set of session keys with optionally using the given seed."]
				#[doc = " The keys should be stored within the keystore exposed via runtime"]
				#[doc = " externalities."]
				#[doc = ""]
				#[doc = " The seed needs to be a valid `utf8` string."]
				#[doc = ""]
				#[doc = " Returns the concatenated SCALE encoded public keys."]
				pub fn generate_session_keys(
					&self,
					seed: types::generate_session_keys::Seed,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GenerateSessionKeys,
					types::generate_session_keys::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"SessionKeys",
						"generate_session_keys",
						types::GenerateSessionKeys { seed },
						[
							96u8, 171u8, 164u8, 166u8, 175u8, 102u8, 101u8, 47u8, 133u8, 95u8,
							102u8, 202u8, 83u8, 26u8, 238u8, 47u8, 126u8, 132u8, 22u8, 11u8, 33u8,
							190u8, 175u8, 94u8, 58u8, 245u8, 46u8, 80u8, 195u8, 184u8, 107u8, 65u8,
						],
					)
				}
				#[doc = " Decode the given public session keys."]
				#[doc = ""]
				#[doc = " Returns the list of public raw public keys + key type."]
				pub fn decode_session_keys(
					&self,
					encoded: types::decode_session_keys::Encoded,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::DecodeSessionKeys,
					types::decode_session_keys::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"SessionKeys",
						"decode_session_keys",
						types::DecodeSessionKeys { encoded },
						[
							57u8, 242u8, 18u8, 51u8, 132u8, 110u8, 238u8, 255u8, 39u8, 194u8, 8u8,
							54u8, 198u8, 178u8, 75u8, 151u8, 148u8, 176u8, 144u8, 197u8, 87u8,
							29u8, 179u8, 235u8, 176u8, 78u8, 252u8, 103u8, 72u8, 203u8, 151u8,
							248u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod generate_session_keys {
					use super::runtime_types;
					pub type Seed = ::core::option::Option<
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					>;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GenerateSessionKeys {
					pub seed: generate_session_keys::Seed,
				}
				pub mod decode_session_keys {
					use super::runtime_types;
					pub type Encoded =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::option::Option<
							::subxt::ext::subxt_core::alloc::vec::Vec<(
								::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
								runtime_types::sp_core::crypto::KeyTypeId,
							)>,
						>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct DecodeSessionKeys {
					pub encoded: decode_session_keys::Encoded,
				}
			}
		}
		pub mod q_po_w_api {
			use super::{root_mod, runtime_types};
			pub struct QPoWApi;
			impl QPoWApi {
				#[doc = " Verify a nonce for a historical block that's already in the chain"]
				pub fn verify_historical_block(
					&self,
					header: types::verify_historical_block::Header,
					nonce: types::verify_historical_block::Nonce,
					block_number: types::verify_historical_block::BlockNumber,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::VerifyHistoricalBlock,
					types::verify_historical_block::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"verify_historical_block",
						types::VerifyHistoricalBlock { header, nonce, block_number },
						[
							110u8, 10u8, 34u8, 119u8, 84u8, 17u8, 127u8, 204u8, 198u8, 160u8,
							190u8, 122u8, 224u8, 127u8, 150u8, 62u8, 227u8, 220u8, 49u8, 212u8,
							211u8, 96u8, 227u8, 95u8, 212u8, 124u8, 124u8, 159u8, 93u8, 74u8, 62u8,
							203u8,
						],
					)
				}
				#[doc = " calculate distance header with nonce to with nonce"]
				pub fn get_nonce_distance(
					&self,
					block_hash: types::get_nonce_distance::BlockHash,
					nonce: types::get_nonce_distance::Nonce,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetNonceDistance,
					types::get_nonce_distance::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_nonce_distance",
						types::GetNonceDistance { block_hash, nonce },
						[
							129u8, 114u8, 220u8, 23u8, 229u8, 124u8, 105u8, 65u8, 77u8, 91u8, 9u8,
							2u8, 2u8, 177u8, 124u8, 108u8, 143u8, 100u8, 174u8, 61u8, 29u8, 55u8,
							166u8, 162u8, 16u8, 61u8, 75u8, 213u8, 182u8, 125u8, 7u8, 120u8,
						],
					)
				}
				#[doc = " Get the max possible reorg depth"]
				pub fn get_max_reorg_depth(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetMaxReorgDepth,
					types::get_max_reorg_depth::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_max_reorg_depth",
						types::GetMaxReorgDepth {},
						[
							95u8, 253u8, 190u8, 31u8, 75u8, 182u8, 224u8, 166u8, 3u8, 9u8, 29u8,
							200u8, 89u8, 143u8, 104u8, 126u8, 178u8, 83u8, 156u8, 109u8, 140u8,
							177u8, 70u8, 113u8, 23u8, 182u8, 236u8, 236u8, 111u8, 145u8, 237u8,
							148u8,
						],
					)
				}
				#[doc = " Get the max possible distance_threshold for work calculation"]
				pub fn get_max_distance(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetMaxDistance,
					types::get_max_distance::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_max_distance",
						types::GetMaxDistance {},
						[
							228u8, 221u8, 157u8, 71u8, 206u8, 66u8, 16u8, 79u8, 17u8, 1u8, 0u8,
							134u8, 36u8, 195u8, 232u8, 254u8, 165u8, 162u8, 169u8, 184u8, 85u8,
							136u8, 11u8, 10u8, 40u8, 197u8, 225u8, 249u8, 240u8, 43u8, 120u8, 45u8,
						],
					)
				}
				#[doc = " Get the current difficulty (max_distance / distance_threshold)"]
				pub fn get_difficulty(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetDifficulty,
					types::get_difficulty::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_difficulty",
						types::GetDifficulty {},
						[
							180u8, 101u8, 92u8, 73u8, 15u8, 146u8, 167u8, 45u8, 127u8, 230u8,
							148u8, 6u8, 174u8, 121u8, 38u8, 103u8, 46u8, 5u8, 235u8, 20u8, 133u8,
							207u8, 67u8, 211u8, 25u8, 112u8, 83u8, 196u8, 118u8, 66u8, 118u8,
							179u8,
						],
					)
				}
				#[doc = " Get the current distance_threshold target for proof generation"]
				pub fn get_distance_threshold(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetDistanceThreshold,
					types::get_distance_threshold::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_distance_threshold",
						types::GetDistanceThreshold {},
						[
							84u8, 236u8, 60u8, 104u8, 10u8, 61u8, 150u8, 165u8, 61u8, 214u8, 204u8,
							210u8, 47u8, 211u8, 67u8, 136u8, 243u8, 72u8, 252u8, 132u8, 128u8,
							28u8, 166u8, 87u8, 131u8, 48u8, 61u8, 109u8, 115u8, 66u8, 190u8, 201u8,
						],
					)
				}
				#[doc = " Get distance_threshold at block"]
				pub fn get_distance_threshold_at_block(
					&self,
					block_number: types::get_distance_threshold_at_block::BlockNumber,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetDistanceThresholdAtBlock,
					types::get_distance_threshold_at_block::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_distance_threshold_at_block",
						types::GetDistanceThresholdAtBlock { block_number },
						[
							22u8, 139u8, 170u8, 164u8, 154u8, 98u8, 153u8, 248u8, 43u8, 220u8,
							56u8, 38u8, 101u8, 236u8, 112u8, 68u8, 45u8, 57u8, 158u8, 156u8, 252u8,
							177u8, 112u8, 188u8, 176u8, 200u8, 221u8, 206u8, 144u8, 8u8, 98u8,
							106u8,
						],
					)
				}
				#[doc = " Get total work"]
				pub fn get_total_work(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetTotalWork,
					types::get_total_work::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_total_work",
						types::GetTotalWork {},
						[
							1u8, 91u8, 59u8, 140u8, 203u8, 250u8, 8u8, 65u8, 208u8, 35u8, 187u8,
							190u8, 255u8, 125u8, 190u8, 111u8, 216u8, 168u8, 83u8, 32u8, 37u8,
							203u8, 102u8, 226u8, 88u8, 207u8, 253u8, 59u8, 86u8, 72u8, 30u8, 171u8,
						],
					)
				}
				#[doc = " Get sum of block times in rolling history"]
				pub fn get_block_time_sum(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetBlockTimeSum,
					types::get_block_time_sum::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_block_time_sum",
						types::GetBlockTimeSum {},
						[
							135u8, 226u8, 38u8, 138u8, 155u8, 194u8, 162u8, 121u8, 106u8, 22u8,
							48u8, 208u8, 71u8, 14u8, 50u8, 123u8, 66u8, 153u8, 169u8, 95u8, 75u8,
							70u8, 237u8, 160u8, 129u8, 81u8, 117u8, 200u8, 238u8, 102u8, 138u8,
							98u8,
						],
					)
				}
				#[doc = " Get median block time for preconfigured list of elements"]
				pub fn get_median_block_time(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetMedianBlockTime,
					types::get_median_block_time::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_median_block_time",
						types::GetMedianBlockTime {},
						[
							202u8, 211u8, 53u8, 71u8, 198u8, 56u8, 32u8, 243u8, 236u8, 124u8,
							116u8, 100u8, 215u8, 111u8, 101u8, 20u8, 4u8, 55u8, 98u8, 187u8, 90u8,
							224u8, 167u8, 20u8, 175u8, 252u8, 50u8, 220u8, 146u8, 87u8, 245u8,
							52u8,
						],
					)
				}
				#[doc = " Get last block timestamp"]
				pub fn get_last_block_time(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetLastBlockTime,
					types::get_last_block_time::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_last_block_time",
						types::GetLastBlockTime {},
						[
							207u8, 192u8, 227u8, 7u8, 154u8, 92u8, 133u8, 111u8, 21u8, 9u8, 21u8,
							171u8, 235u8, 117u8, 143u8, 199u8, 19u8, 67u8, 76u8, 35u8, 220u8, 32u8,
							221u8, 166u8, 0u8, 234u8, 107u8, 217u8, 122u8, 89u8, 91u8, 144u8,
						],
					)
				}
				pub fn get_last_block_duration(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetLastBlockDuration,
					types::get_last_block_duration::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_last_block_duration",
						types::GetLastBlockDuration {},
						[
							103u8, 98u8, 123u8, 21u8, 125u8, 171u8, 88u8, 46u8, 187u8, 94u8, 96u8,
							238u8, 16u8, 122u8, 81u8, 108u8, 157u8, 204u8, 79u8, 43u8, 170u8,
							235u8, 176u8, 238u8, 174u8, 235u8, 47u8, 152u8, 167u8, 245u8, 243u8,
							157u8,
						],
					)
				}
				pub fn get_chain_height(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetChainHeight,
					types::get_chain_height::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_chain_height",
						types::GetChainHeight {},
						[
							249u8, 203u8, 37u8, 234u8, 170u8, 203u8, 200u8, 147u8, 30u8, 193u8,
							91u8, 97u8, 96u8, 104u8, 39u8, 96u8, 171u8, 69u8, 119u8, 30u8, 112u8,
							81u8, 132u8, 33u8, 69u8, 168u8, 70u8, 33u8, 196u8, 16u8, 215u8, 113u8,
						],
					)
				}
				pub fn get_random_rsa(
					&self,
					block_hash: types::get_random_rsa::BlockHash,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetRandomRsa,
					types::get_random_rsa::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"get_random_rsa",
						types::GetRandomRsa { block_hash },
						[
							179u8, 195u8, 121u8, 252u8, 235u8, 176u8, 160u8, 58u8, 188u8, 236u8,
							106u8, 222u8, 47u8, 7u8, 73u8, 89u8, 186u8, 175u8, 25u8, 77u8, 196u8,
							68u8, 111u8, 186u8, 181u8, 178u8, 2u8, 205u8, 215u8, 142u8, 157u8,
							160u8,
						],
					)
				}
				pub fn hash_to_group_bigint(
					&self,
					h: types::hash_to_group_bigint::H,
					m: types::hash_to_group_bigint::M,
					n: types::hash_to_group_bigint::N,
					solution: types::hash_to_group_bigint::Solution,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::HashToGroupBigint,
					types::hash_to_group_bigint::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"hash_to_group_bigint",
						types::HashToGroupBigint { h, m, n, solution },
						[
							117u8, 71u8, 148u8, 115u8, 194u8, 210u8, 59u8, 139u8, 102u8, 255u8,
							55u8, 207u8, 118u8, 114u8, 98u8, 151u8, 147u8, 99u8, 142u8, 158u8,
							185u8, 151u8, 118u8, 31u8, 192u8, 26u8, 63u8, 150u8, 50u8, 123u8, 40u8,
							163u8,
						],
					)
				}
				pub fn verify_nonce_on_import_block(
					&self,
					block_hash: types::verify_nonce_on_import_block::BlockHash,
					nonce: types::verify_nonce_on_import_block::Nonce,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::VerifyNonceOnImportBlock,
					types::verify_nonce_on_import_block::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"verify_nonce_on_import_block",
						types::VerifyNonceOnImportBlock { block_hash, nonce },
						[
							178u8, 216u8, 20u8, 254u8, 253u8, 202u8, 63u8, 238u8, 164u8, 135u8,
							163u8, 28u8, 170u8, 44u8, 183u8, 157u8, 211u8, 62u8, 4u8, 77u8, 30u8,
							32u8, 68u8, 166u8, 42u8, 161u8, 111u8, 79u8, 54u8, 54u8, 40u8, 15u8,
						],
					)
				}
				pub fn verify_nonce_local_mining(
					&self,
					block_hash: types::verify_nonce_local_mining::BlockHash,
					nonce: types::verify_nonce_local_mining::Nonce,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::VerifyNonceLocalMining,
					types::verify_nonce_local_mining::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"QPoWApi",
						"verify_nonce_local_mining",
						types::VerifyNonceLocalMining { block_hash, nonce },
						[
							10u8, 191u8, 243u8, 4u8, 31u8, 132u8, 202u8, 157u8, 183u8, 189u8, 49u8,
							76u8, 201u8, 182u8, 52u8, 197u8, 34u8, 248u8, 253u8, 226u8, 64u8,
							100u8, 108u8, 2u8, 119u8, 85u8, 184u8, 96u8, 25u8, 156u8, 108u8, 240u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod verify_historical_block {
					use super::runtime_types;
					pub type Header = [::core::primitive::u8; 32usize];
					pub type Nonce = [::core::primitive::u8; 64usize];
					pub type BlockNumber = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::bool;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct VerifyHistoricalBlock {
					pub header: verify_historical_block::Header,
					pub nonce: verify_historical_block::Nonce,
					pub block_number: verify_historical_block::BlockNumber,
				}
				pub mod get_nonce_distance {
					use super::runtime_types;
					pub type BlockHash = [::core::primitive::u8; 32usize];
					pub type Nonce = [::core::primitive::u8; 64usize];
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetNonceDistance {
					pub block_hash: get_nonce_distance::BlockHash,
					pub nonce: get_nonce_distance::Nonce,
				}
				pub mod get_max_reorg_depth {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u32;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetMaxReorgDepth {}
				pub mod get_max_distance {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetMaxDistance {}
				pub mod get_difficulty {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetDifficulty {}
				pub mod get_distance_threshold {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetDistanceThreshold {}
				pub mod get_distance_threshold_at_block {
					use super::runtime_types;
					pub type BlockNumber = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetDistanceThresholdAtBlock {
					pub block_number: get_distance_threshold_at_block::BlockNumber,
				}
				pub mod get_total_work {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetTotalWork {}
				pub mod get_block_time_sum {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u64;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetBlockTimeSum {}
				pub mod get_median_block_time {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u64;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetMedianBlockTime {}
				pub mod get_last_block_time {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u64;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetLastBlockTime {}
				pub mod get_last_block_duration {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u64;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetLastBlockDuration {}
				pub mod get_chain_height {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u32;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetChainHeight {}
				pub mod get_random_rsa {
					use super::runtime_types;
					pub type BlockHash = [::core::primitive::u8; 32usize];
					pub mod output {
						use super::runtime_types;
						pub type Output = (
							runtime_types::primitive_types::U512,
							runtime_types::primitive_types::U512,
						);
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetRandomRsa {
					pub block_hash: get_random_rsa::BlockHash,
				}
				pub mod hash_to_group_bigint {
					use super::runtime_types;
					pub type H = runtime_types::primitive_types::U512;
					pub type M = runtime_types::primitive_types::U512;
					pub type N = runtime_types::primitive_types::U512;
					pub type Solution = runtime_types::primitive_types::U512;
					pub mod output {
						use super::runtime_types;
						pub type Output = runtime_types::primitive_types::U512;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct HashToGroupBigint {
					pub h: hash_to_group_bigint::H,
					pub m: hash_to_group_bigint::M,
					pub n: hash_to_group_bigint::N,
					pub solution: hash_to_group_bigint::Solution,
				}
				pub mod verify_nonce_on_import_block {
					use super::runtime_types;
					pub type BlockHash = [::core::primitive::u8; 32usize];
					pub type Nonce = [::core::primitive::u8; 64usize];
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::bool;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct VerifyNonceOnImportBlock {
					pub block_hash: verify_nonce_on_import_block::BlockHash,
					pub nonce: verify_nonce_on_import_block::Nonce,
				}
				pub mod verify_nonce_local_mining {
					use super::runtime_types;
					pub type BlockHash = [::core::primitive::u8; 32usize];
					pub type Nonce = [::core::primitive::u8; 64usize];
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::bool;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct VerifyNonceLocalMining {
					pub block_hash: verify_nonce_local_mining::BlockHash,
					pub nonce: verify_nonce_local_mining::Nonce,
				}
			}
		}
		pub mod account_nonce_api {
			use super::{root_mod, runtime_types};
			#[doc = " The API to query account nonce."]
			pub struct AccountNonceApi;
			impl AccountNonceApi {
				#[doc = " Get current account nonce of given `AccountId`."]
				pub fn account_nonce(
					&self,
					account: types::account_nonce::Account,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::AccountNonce,
					types::account_nonce::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"AccountNonceApi",
						"account_nonce",
						types::AccountNonce { account },
						[
							231u8, 82u8, 7u8, 227u8, 131u8, 2u8, 215u8, 252u8, 173u8, 82u8, 11u8,
							103u8, 200u8, 25u8, 114u8, 116u8, 79u8, 229u8, 152u8, 150u8, 236u8,
							37u8, 101u8, 26u8, 220u8, 146u8, 182u8, 101u8, 73u8, 55u8, 191u8,
							171u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod account_nonce {
					use super::runtime_types;
					pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u32;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct AccountNonce {
					pub account: account_nonce::Account,
				}
			}
		}
		pub mod transaction_payment_api {
			use super::{root_mod, runtime_types};
			pub struct TransactionPaymentApi;
			impl TransactionPaymentApi {
				pub fn query_info(
					&self,
					uxt: types::query_info::Uxt,
					len: types::query_info::Len,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryInfo,
					types::query_info::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentApi",
						"query_info",
						types::QueryInfo { uxt, len },
						[
							56u8, 30u8, 174u8, 34u8, 202u8, 24u8, 177u8, 189u8, 145u8, 36u8, 1u8,
							156u8, 98u8, 209u8, 178u8, 49u8, 198u8, 23u8, 150u8, 173u8, 35u8,
							205u8, 147u8, 129u8, 42u8, 22u8, 69u8, 3u8, 129u8, 8u8, 196u8, 139u8,
						],
					)
				}
				pub fn query_fee_details(
					&self,
					uxt: types::query_fee_details::Uxt,
					len: types::query_fee_details::Len,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryFeeDetails,
					types::query_fee_details::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentApi",
						"query_fee_details",
						types::QueryFeeDetails { uxt, len },
						[
							117u8, 60u8, 137u8, 159u8, 237u8, 252u8, 216u8, 238u8, 232u8, 1u8,
							100u8, 152u8, 26u8, 185u8, 145u8, 125u8, 68u8, 189u8, 4u8, 30u8, 125u8,
							7u8, 196u8, 153u8, 235u8, 51u8, 219u8, 108u8, 185u8, 254u8, 100u8,
							201u8,
						],
					)
				}
				pub fn query_weight_to_fee(
					&self,
					weight: types::query_weight_to_fee::Weight,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryWeightToFee,
					types::query_weight_to_fee::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentApi",
						"query_weight_to_fee",
						types::QueryWeightToFee { weight },
						[
							206u8, 243u8, 189u8, 83u8, 231u8, 244u8, 247u8, 52u8, 126u8, 208u8,
							224u8, 5u8, 163u8, 108u8, 254u8, 114u8, 214u8, 156u8, 227u8, 217u8,
							211u8, 198u8, 121u8, 164u8, 110u8, 54u8, 181u8, 146u8, 50u8, 146u8,
							146u8, 23u8,
						],
					)
				}
				pub fn query_length_to_fee(
					&self,
					length: types::query_length_to_fee::Length,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryLengthToFee,
					types::query_length_to_fee::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentApi",
						"query_length_to_fee",
						types::QueryLengthToFee { length },
						[
							92u8, 132u8, 29u8, 119u8, 66u8, 11u8, 196u8, 224u8, 129u8, 23u8, 249u8,
							12u8, 32u8, 28u8, 92u8, 50u8, 188u8, 101u8, 203u8, 229u8, 248u8, 216u8,
							130u8, 150u8, 212u8, 161u8, 81u8, 254u8, 116u8, 89u8, 162u8, 48u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod query_info {
					use super::runtime_types;
					pub type Uxt = :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > ;
					pub type Len = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							runtime_types::pallet_transaction_payment::types::RuntimeDispatchInfo<
								::core::primitive::u128,
								runtime_types::sp_weights::weight_v2::Weight,
							>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryInfo {
					pub uxt: query_info::Uxt,
					pub len: query_info::Len,
				}
				pub mod query_fee_details {
					use super::runtime_types;
					pub type Uxt = :: subxt :: ext :: subxt_core :: utils :: UncheckedExtrinsic < :: subxt :: ext :: subxt_core :: utils :: MultiAddress < :: subxt :: ext :: subxt_core :: utils :: AccountId32 , () > , runtime_types :: quantus_runtime :: RuntimeCall , runtime_types :: dilithium_crypto :: types :: DilithiumSignatureScheme , (runtime_types :: frame_system :: extensions :: check_non_zero_sender :: CheckNonZeroSender , runtime_types :: frame_system :: extensions :: check_spec_version :: CheckSpecVersion , runtime_types :: frame_system :: extensions :: check_tx_version :: CheckTxVersion , runtime_types :: frame_system :: extensions :: check_genesis :: CheckGenesis , runtime_types :: frame_system :: extensions :: check_mortality :: CheckMortality , runtime_types :: frame_system :: extensions :: check_nonce :: CheckNonce , runtime_types :: frame_system :: extensions :: check_weight :: CheckWeight , runtime_types :: pallet_transaction_payment :: ChargeTransactionPayment , runtime_types :: frame_metadata_hash_extension :: CheckMetadataHash , runtime_types :: quantus_runtime :: transaction_extensions :: ReversibleTransactionExtension ,) > ;
					pub type Len = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							runtime_types::pallet_transaction_payment::types::FeeDetails<
								::core::primitive::u128,
							>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryFeeDetails {
					pub uxt: query_fee_details::Uxt,
					pub len: query_fee_details::Len,
				}
				pub mod query_weight_to_fee {
					use super::runtime_types;
					pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u128;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryWeightToFee {
					pub weight: query_weight_to_fee::Weight,
				}
				pub mod query_length_to_fee {
					use super::runtime_types;
					pub type Length = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u128;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryLengthToFee {
					pub length: query_length_to_fee::Length,
				}
			}
		}
		pub mod transaction_payment_call_api {
			use super::{root_mod, runtime_types};
			pub struct TransactionPaymentCallApi;
			impl TransactionPaymentCallApi {
				#[doc = " Query information of a dispatch class, weight, and fee of a given encoded `Call`."]
				pub fn query_call_info(
					&self,
					call: types::query_call_info::Call,
					len: types::query_call_info::Len,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryCallInfo,
					types::query_call_info::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentCallApi",
						"query_call_info",
						types::QueryCallInfo { call, len },
						[
							148u8, 128u8, 119u8, 67u8, 237u8, 151u8, 224u8, 163u8, 125u8, 21u8,
							226u8, 226u8, 187u8, 223u8, 84u8, 42u8, 77u8, 71u8, 127u8, 73u8, 180u8,
							253u8, 21u8, 52u8, 65u8, 82u8, 161u8, 192u8, 199u8, 133u8, 160u8,
							117u8,
						],
					)
				}
				#[doc = " Query fee details of a given encoded `Call`."]
				pub fn query_call_fee_details(
					&self,
					call: types::query_call_fee_details::Call,
					len: types::query_call_fee_details::Len,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryCallFeeDetails,
					types::query_call_fee_details::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentCallApi",
						"query_call_fee_details",
						types::QueryCallFeeDetails { call, len },
						[
							43u8, 173u8, 253u8, 181u8, 107u8, 160u8, 168u8, 209u8, 78u8, 22u8,
							229u8, 97u8, 8u8, 136u8, 41u8, 219u8, 71u8, 13u8, 21u8, 214u8, 1u8,
							249u8, 159u8, 250u8, 154u8, 75u8, 15u8, 250u8, 236u8, 14u8, 211u8,
							123u8,
						],
					)
				}
				#[doc = " Query the output of the current `WeightToFee` given some input."]
				pub fn query_weight_to_fee(
					&self,
					weight: types::query_weight_to_fee::Weight,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryWeightToFee,
					types::query_weight_to_fee::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentCallApi",
						"query_weight_to_fee",
						types::QueryWeightToFee { weight },
						[
							117u8, 91u8, 94u8, 22u8, 248u8, 212u8, 15u8, 23u8, 97u8, 116u8, 64u8,
							228u8, 83u8, 123u8, 87u8, 77u8, 97u8, 7u8, 98u8, 181u8, 6u8, 165u8,
							114u8, 141u8, 164u8, 113u8, 126u8, 88u8, 174u8, 171u8, 224u8, 35u8,
						],
					)
				}
				#[doc = " Query the output of the current `LengthToFee` given some input."]
				pub fn query_length_to_fee(
					&self,
					length: types::query_length_to_fee::Length,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::QueryLengthToFee,
					types::query_length_to_fee::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"TransactionPaymentCallApi",
						"query_length_to_fee",
						types::QueryLengthToFee { length },
						[
							246u8, 40u8, 4u8, 160u8, 152u8, 94u8, 170u8, 53u8, 205u8, 122u8, 5u8,
							69u8, 70u8, 25u8, 128u8, 156u8, 119u8, 134u8, 116u8, 147u8, 14u8,
							164u8, 65u8, 140u8, 86u8, 13u8, 250u8, 218u8, 89u8, 95u8, 234u8, 228u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod query_call_info {
					use super::runtime_types;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
					pub type Len = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							runtime_types::pallet_transaction_payment::types::RuntimeDispatchInfo<
								::core::primitive::u128,
								runtime_types::sp_weights::weight_v2::Weight,
							>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryCallInfo {
					pub call: query_call_info::Call,
					pub len: query_call_info::Len,
				}
				pub mod query_call_fee_details {
					use super::runtime_types;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
					pub type Len = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output =
							runtime_types::pallet_transaction_payment::types::FeeDetails<
								::core::primitive::u128,
							>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryCallFeeDetails {
					pub call: query_call_fee_details::Call,
					pub len: query_call_fee_details::Len,
				}
				pub mod query_weight_to_fee {
					use super::runtime_types;
					pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u128;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryWeightToFee {
					pub weight: query_weight_to_fee::Weight,
				}
				pub mod query_length_to_fee {
					use super::runtime_types;
					pub type Length = ::core::primitive::u32;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::primitive::u128;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct QueryLengthToFee {
					pub length: query_length_to_fee::Length,
				}
			}
		}
		pub mod genesis_builder {
			use super::{root_mod, runtime_types};
			#[doc = " API to interact with `RuntimeGenesisConfig` for the runtime"]
			pub struct GenesisBuilder;
			impl GenesisBuilder {
				#[doc = " Build `RuntimeGenesisConfig` from a JSON blob not using any defaults and store it in the"]
				#[doc = " storage."]
				#[doc = ""]
				#[doc = " In the case of a FRAME-based runtime, this function deserializes the full"]
				#[doc = " `RuntimeGenesisConfig` from the given JSON blob and puts it into the storage. If the"]
				#[doc = " provided JSON blob is incorrect or incomplete or the deserialization fails, an error"]
				#[doc = " is returned."]
				#[doc = ""]
				#[doc = " Please note that provided JSON blob must contain all `RuntimeGenesisConfig` fields, no"]
				#[doc = " defaults will be used."]
				pub fn build_state(
					&self,
					json: types::build_state::Json,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::BuildState,
					types::build_state::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"GenesisBuilder",
						"build_state",
						types::BuildState { json },
						[
							203u8, 233u8, 104u8, 116u8, 111u8, 131u8, 201u8, 235u8, 117u8, 116u8,
							140u8, 185u8, 93u8, 25u8, 155u8, 210u8, 56u8, 49u8, 23u8, 32u8, 253u8,
							92u8, 149u8, 241u8, 85u8, 245u8, 137u8, 45u8, 209u8, 189u8, 81u8, 2u8,
						],
					)
				}
				#[doc = " Returns a JSON blob representation of the built-in `RuntimeGenesisConfig` identified by"]
				#[doc = " `id`."]
				#[doc = ""]
				#[doc = " If `id` is `None` the function should return JSON blob representation of the default"]
				#[doc = " `RuntimeGenesisConfig` struct of the runtime. Implementation must provide default"]
				#[doc = " `RuntimeGenesisConfig`."]
				#[doc = ""]
				#[doc = " Otherwise function returns a JSON representation of the built-in, named"]
				#[doc = " `RuntimeGenesisConfig` preset identified by `id`, or `None` if such preset does not"]
				#[doc = " exist. Returned `Vec<u8>` contains bytes of JSON blob (patch) which comprises a list of"]
				#[doc = " (potentially nested) key-value pairs that are intended for customizing the default"]
				#[doc = " runtime genesis config. The patch shall be merged (rfc7386) with the JSON representation"]
				#[doc = " of the default `RuntimeGenesisConfig` to create a comprehensive genesis config that can"]
				#[doc = " be used in `build_state` method."]
				pub fn get_preset(
					&self,
					id: types::get_preset::Id,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::GetPreset,
					types::get_preset::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"GenesisBuilder",
						"get_preset",
						types::GetPreset { id },
						[
							43u8, 153u8, 23u8, 52u8, 113u8, 161u8, 227u8, 122u8, 169u8, 135u8,
							119u8, 8u8, 128u8, 33u8, 143u8, 235u8, 13u8, 173u8, 58u8, 121u8, 178u8,
							223u8, 66u8, 217u8, 22u8, 244u8, 168u8, 113u8, 202u8, 186u8, 241u8,
							124u8,
						],
					)
				}
				#[doc = " Returns a list of identifiers for available builtin `RuntimeGenesisConfig` presets."]
				#[doc = ""]
				#[doc = " The presets from the list can be queried with [`GenesisBuilder::get_preset`] method. If"]
				#[doc = " no named presets are provided by the runtime the list is empty."]
				pub fn preset_names(
					&self,
				) -> ::subxt::ext::subxt_core::runtime_api::payload::StaticPayload<
					types::PresetNames,
					types::preset_names::output::Output,
				> {
					::subxt::ext::subxt_core::runtime_api::payload::StaticPayload::new_static(
						"GenesisBuilder",
						"preset_names",
						types::PresetNames {},
						[
							150u8, 117u8, 54u8, 129u8, 221u8, 130u8, 186u8, 71u8, 13u8, 140u8,
							77u8, 180u8, 141u8, 37u8, 22u8, 219u8, 149u8, 218u8, 186u8, 206u8,
							80u8, 42u8, 165u8, 41u8, 99u8, 184u8, 73u8, 37u8, 125u8, 188u8, 167u8,
							122u8,
						],
					)
				}
			}
			pub mod types {
				use super::runtime_types;
				pub mod build_state {
					use super::runtime_types;
					pub type Json =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::result::Result<
							(),
							::subxt::ext::subxt_core::alloc::string::String,
						>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct BuildState {
					pub json: build_state::Json,
				}
				pub mod get_preset {
					use super::runtime_types;
					pub type Id =
						::core::option::Option<::subxt::ext::subxt_core::alloc::string::String>;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::core::option::Option<
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct GetPreset {
					pub id: get_preset::Id,
				}
				pub mod preset_names {
					use super::runtime_types;
					pub mod output {
						use super::runtime_types;
						pub type Output = ::subxt::ext::subxt_core::alloc::vec::Vec<
							::subxt::ext::subxt_core::alloc::string::String,
						>;
					}
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct PresetNames {}
			}
		}
	}
	pub fn view_functions() -> ViewFunctionsApi {
		ViewFunctionsApi
	}
	pub fn custom() -> CustomValuesApi {
		CustomValuesApi
	}
	pub struct CustomValuesApi;
	impl CustomValuesApi {}
	pub struct ConstantsApi;
	impl ConstantsApi {
		pub fn system(&self) -> system::constants::ConstantsApi {
			system::constants::ConstantsApi
		}
		pub fn timestamp(&self) -> timestamp::constants::ConstantsApi {
			timestamp::constants::ConstantsApi
		}
		pub fn balances(&self) -> balances::constants::ConstantsApi {
			balances::constants::ConstantsApi
		}
		pub fn transaction_payment(&self) -> transaction_payment::constants::ConstantsApi {
			transaction_payment::constants::ConstantsApi
		}
		pub fn q_po_w(&self) -> q_po_w::constants::ConstantsApi {
			q_po_w::constants::ConstantsApi
		}
		pub fn wormhole(&self) -> wormhole::constants::ConstantsApi {
			wormhole::constants::ConstantsApi
		}
		pub fn mining_rewards(&self) -> mining_rewards::constants::ConstantsApi {
			mining_rewards::constants::ConstantsApi
		}
		pub fn vesting(&self) -> vesting::constants::ConstantsApi {
			vesting::constants::ConstantsApi
		}
		pub fn scheduler(&self) -> scheduler::constants::ConstantsApi {
			scheduler::constants::ConstantsApi
		}
		pub fn utility(&self) -> utility::constants::ConstantsApi {
			utility::constants::ConstantsApi
		}
		pub fn referenda(&self) -> referenda::constants::ConstantsApi {
			referenda::constants::ConstantsApi
		}
		pub fn reversible_transfers(&self) -> reversible_transfers::constants::ConstantsApi {
			reversible_transfers::constants::ConstantsApi
		}
		pub fn conviction_voting(&self) -> conviction_voting::constants::ConstantsApi {
			conviction_voting::constants::ConstantsApi
		}
		pub fn tech_referenda(&self) -> tech_referenda::constants::ConstantsApi {
			tech_referenda::constants::ConstantsApi
		}
		pub fn merkle_airdrop(&self) -> merkle_airdrop::constants::ConstantsApi {
			merkle_airdrop::constants::ConstantsApi
		}
		pub fn treasury_pallet(&self) -> treasury_pallet::constants::ConstantsApi {
			treasury_pallet::constants::ConstantsApi
		}
		pub fn recovery(&self) -> recovery::constants::ConstantsApi {
			recovery::constants::ConstantsApi
		}
	}
	pub struct StorageApi;
	impl StorageApi {
		pub fn system(&self) -> system::storage::StorageApi {
			system::storage::StorageApi
		}
		pub fn timestamp(&self) -> timestamp::storage::StorageApi {
			timestamp::storage::StorageApi
		}
		pub fn balances(&self) -> balances::storage::StorageApi {
			balances::storage::StorageApi
		}
		pub fn transaction_payment(&self) -> transaction_payment::storage::StorageApi {
			transaction_payment::storage::StorageApi
		}
		pub fn sudo(&self) -> sudo::storage::StorageApi {
			sudo::storage::StorageApi
		}
		pub fn q_po_w(&self) -> q_po_w::storage::StorageApi {
			q_po_w::storage::StorageApi
		}
		pub fn wormhole(&self) -> wormhole::storage::StorageApi {
			wormhole::storage::StorageApi
		}
		pub fn mining_rewards(&self) -> mining_rewards::storage::StorageApi {
			mining_rewards::storage::StorageApi
		}
		pub fn vesting(&self) -> vesting::storage::StorageApi {
			vesting::storage::StorageApi
		}
		pub fn preimage(&self) -> preimage::storage::StorageApi {
			preimage::storage::StorageApi
		}
		pub fn scheduler(&self) -> scheduler::storage::StorageApi {
			scheduler::storage::StorageApi
		}
		pub fn referenda(&self) -> referenda::storage::StorageApi {
			referenda::storage::StorageApi
		}
		pub fn reversible_transfers(&self) -> reversible_transfers::storage::StorageApi {
			reversible_transfers::storage::StorageApi
		}
		pub fn conviction_voting(&self) -> conviction_voting::storage::StorageApi {
			conviction_voting::storage::StorageApi
		}
		pub fn tech_collective(&self) -> tech_collective::storage::StorageApi {
			tech_collective::storage::StorageApi
		}
		pub fn tech_referenda(&self) -> tech_referenda::storage::StorageApi {
			tech_referenda::storage::StorageApi
		}
		pub fn merkle_airdrop(&self) -> merkle_airdrop::storage::StorageApi {
			merkle_airdrop::storage::StorageApi
		}
		pub fn treasury_pallet(&self) -> treasury_pallet::storage::StorageApi {
			treasury_pallet::storage::StorageApi
		}
		pub fn recovery(&self) -> recovery::storage::StorageApi {
			recovery::storage::StorageApi
		}
	}
	pub struct TransactionApi;
	impl TransactionApi {
		pub fn system(&self) -> system::calls::TransactionApi {
			system::calls::TransactionApi
		}
		pub fn timestamp(&self) -> timestamp::calls::TransactionApi {
			timestamp::calls::TransactionApi
		}
		pub fn balances(&self) -> balances::calls::TransactionApi {
			balances::calls::TransactionApi
		}
		pub fn sudo(&self) -> sudo::calls::TransactionApi {
			sudo::calls::TransactionApi
		}
		pub fn wormhole(&self) -> wormhole::calls::TransactionApi {
			wormhole::calls::TransactionApi
		}
		pub fn vesting(&self) -> vesting::calls::TransactionApi {
			vesting::calls::TransactionApi
		}
		pub fn preimage(&self) -> preimage::calls::TransactionApi {
			preimage::calls::TransactionApi
		}
		pub fn scheduler(&self) -> scheduler::calls::TransactionApi {
			scheduler::calls::TransactionApi
		}
		pub fn utility(&self) -> utility::calls::TransactionApi {
			utility::calls::TransactionApi
		}
		pub fn referenda(&self) -> referenda::calls::TransactionApi {
			referenda::calls::TransactionApi
		}
		pub fn reversible_transfers(&self) -> reversible_transfers::calls::TransactionApi {
			reversible_transfers::calls::TransactionApi
		}
		pub fn conviction_voting(&self) -> conviction_voting::calls::TransactionApi {
			conviction_voting::calls::TransactionApi
		}
		pub fn tech_collective(&self) -> tech_collective::calls::TransactionApi {
			tech_collective::calls::TransactionApi
		}
		pub fn tech_referenda(&self) -> tech_referenda::calls::TransactionApi {
			tech_referenda::calls::TransactionApi
		}
		pub fn merkle_airdrop(&self) -> merkle_airdrop::calls::TransactionApi {
			merkle_airdrop::calls::TransactionApi
		}
		pub fn treasury_pallet(&self) -> treasury_pallet::calls::TransactionApi {
			treasury_pallet::calls::TransactionApi
		}
		pub fn recovery(&self) -> recovery::calls::TransactionApi {
			recovery::calls::TransactionApi
		}
	}
	pub struct ViewFunctionsApi;
	impl ViewFunctionsApi {}
	#[doc = r" check whether the metadata provided is aligned with this statically generated code."]
	pub fn is_codegen_valid_for(metadata: &::subxt::ext::subxt_core::Metadata) -> bool {
		let runtime_metadata_hash = metadata
			.hasher()
			.only_these_pallets(&PALLETS)
			.only_these_runtime_apis(&RUNTIME_APIS)
			.hash();
		runtime_metadata_hash ==
			[
				157u8, 155u8, 114u8, 204u8, 148u8, 96u8, 131u8, 139u8, 202u8, 79u8, 247u8, 156u8,
				184u8, 178u8, 178u8, 170u8, 46u8, 42u8, 245u8, 21u8, 255u8, 201u8, 150u8, 11u8,
				132u8, 69u8, 181u8, 62u8, 127u8, 83u8, 48u8, 230u8,
			]
	}
	pub mod system {
		use super::{root_mod, runtime_types};
		#[doc = "Error for the System pallet"]
		pub type Error = runtime_types::frame_system::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::frame_system::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Make some on-chain remark."]
				#[doc = ""]
				#[doc = "Can be executed by every `origin`."]
				pub struct Remark {
					pub remark: remark::Remark,
				}
				pub mod remark {
					use super::runtime_types;
					pub type Remark =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Remark {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "remark";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set the number of pages in the WebAssembly environment's heap."]
				pub struct SetHeapPages {
					pub pages: set_heap_pages::Pages,
				}
				pub mod set_heap_pages {
					use super::runtime_types;
					pub type Pages = ::core::primitive::u64;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetHeapPages {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "set_heap_pages";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set the new runtime code."]
				pub struct SetCode {
					pub code: set_code::Code,
				}
				pub mod set_code {
					use super::runtime_types;
					pub type Code =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetCode {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "set_code";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set the new runtime code without doing any checks of the given `code`."]
				#[doc = ""]
				#[doc = "Note that runtime upgrades will not run if this is called with a not-increasing spec"]
				#[doc = "version!"]
				pub struct SetCodeWithoutChecks {
					pub code: set_code_without_checks::Code,
				}
				pub mod set_code_without_checks {
					use super::runtime_types;
					pub type Code =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetCodeWithoutChecks {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "set_code_without_checks";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set some items of storage."]
				pub struct SetStorage {
					pub items: set_storage::Items,
				}
				pub mod set_storage {
					use super::runtime_types;
					pub type Items = ::subxt::ext::subxt_core::alloc::vec::Vec<(
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					)>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetStorage {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "set_storage";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Kill some items from storage."]
				pub struct KillStorage {
					pub keys: kill_storage::Keys,
				}
				pub mod kill_storage {
					use super::runtime_types;
					pub type Keys = ::subxt::ext::subxt_core::alloc::vec::Vec<
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for KillStorage {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "kill_storage";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Kill all storage items with a key that starts with the given prefix."]
				#[doc = ""]
				#[doc = "**NOTE:** We rely on the Root origin to provide us the number of subkeys under"]
				#[doc = "the prefix we are removing to accurately calculate the weight of this function."]
				pub struct KillPrefix {
					pub prefix: kill_prefix::Prefix,
					pub subkeys: kill_prefix::Subkeys,
				}
				pub mod kill_prefix {
					use super::runtime_types;
					pub type Prefix =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
					pub type Subkeys = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for KillPrefix {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "kill_prefix";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Make some on-chain remark and emit event."]
				pub struct RemarkWithEvent {
					pub remark: remark_with_event::Remark,
				}
				pub mod remark_with_event {
					use super::runtime_types;
					pub type Remark =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemarkWithEvent {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "remark_with_event";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied"]
				#[doc = "later."]
				#[doc = ""]
				#[doc = "This call requires Root origin."]
				pub struct AuthorizeUpgrade {
					pub code_hash: authorize_upgrade::CodeHash,
				}
				pub mod authorize_upgrade {
					use super::runtime_types;
					pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AuthorizeUpgrade {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "authorize_upgrade";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied"]
				#[doc = "later."]
				#[doc = ""]
				#[doc = "WARNING: This authorizes an upgrade that will take place without any safety checks, for"]
				#[doc = "example that the spec name remains the same and that the version number increases. Not"]
				#[doc = "recommended for normal use. Use `authorize_upgrade` instead."]
				#[doc = ""]
				#[doc = "This call requires Root origin."]
				pub struct AuthorizeUpgradeWithoutChecks {
					pub code_hash: authorize_upgrade_without_checks::CodeHash,
				}
				pub mod authorize_upgrade_without_checks {
					use super::runtime_types;
					pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AuthorizeUpgradeWithoutChecks {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "authorize_upgrade_without_checks";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Provide the preimage (runtime binary) `code` for an upgrade that has been authorized."]
				#[doc = ""]
				#[doc = "If the authorization required a version check, this call will ensure the spec name"]
				#[doc = "remains unchanged and that the spec version has increased."]
				#[doc = ""]
				#[doc = "Depending on the runtime's `OnSetCode` configuration, this function may directly apply"]
				#[doc = "the new `code` in the same block or attempt to schedule the upgrade."]
				#[doc = ""]
				#[doc = "All origins are allowed."]
				pub struct ApplyAuthorizedUpgrade {
					pub code: apply_authorized_upgrade::Code,
				}
				pub mod apply_authorized_upgrade {
					use super::runtime_types;
					pub type Code =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ApplyAuthorizedUpgrade {
					const PALLET: &'static str = "System";
					const CALL: &'static str = "apply_authorized_upgrade";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Make some on-chain remark."]
				#[doc = ""]
				#[doc = "Can be executed by every `origin`."]
				pub fn remark(
					&self,
					remark: types::remark::Remark,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Remark> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"remark",
						types::Remark { remark },
						[
							43u8, 126u8, 180u8, 174u8, 141u8, 48u8, 52u8, 125u8, 166u8, 212u8,
							216u8, 98u8, 100u8, 24u8, 132u8, 71u8, 101u8, 64u8, 246u8, 169u8, 33u8,
							250u8, 147u8, 208u8, 2u8, 40u8, 129u8, 209u8, 232u8, 207u8, 207u8,
							13u8,
						],
					)
				}
				#[doc = "Set the number of pages in the WebAssembly environment's heap."]
				pub fn set_heap_pages(
					&self,
					pages: types::set_heap_pages::Pages,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetHeapPages> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"set_heap_pages",
						types::SetHeapPages { pages },
						[
							188u8, 191u8, 99u8, 216u8, 219u8, 109u8, 141u8, 50u8, 78u8, 235u8,
							215u8, 242u8, 195u8, 24u8, 111u8, 76u8, 229u8, 64u8, 99u8, 225u8,
							134u8, 121u8, 81u8, 209u8, 127u8, 223u8, 98u8, 215u8, 150u8, 70u8,
							57u8, 147u8,
						],
					)
				}
				#[doc = "Set the new runtime code."]
				pub fn set_code(
					&self,
					code: types::set_code::Code,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetCode> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"set_code",
						types::SetCode { code },
						[
							233u8, 248u8, 88u8, 245u8, 28u8, 65u8, 25u8, 169u8, 35u8, 237u8, 19u8,
							203u8, 136u8, 160u8, 18u8, 3u8, 20u8, 197u8, 81u8, 169u8, 244u8, 188u8,
							27u8, 147u8, 147u8, 236u8, 65u8, 25u8, 3u8, 143u8, 182u8, 22u8,
						],
					)
				}
				#[doc = "Set the new runtime code without doing any checks of the given `code`."]
				#[doc = ""]
				#[doc = "Note that runtime upgrades will not run if this is called with a not-increasing spec"]
				#[doc = "version!"]
				pub fn set_code_without_checks(
					&self,
					code: types::set_code_without_checks::Code,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetCodeWithoutChecks>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"set_code_without_checks",
						types::SetCodeWithoutChecks { code },
						[
							82u8, 212u8, 157u8, 44u8, 70u8, 0u8, 143u8, 15u8, 109u8, 109u8, 107u8,
							157u8, 141u8, 42u8, 169u8, 11u8, 15u8, 186u8, 252u8, 138u8, 10u8,
							147u8, 15u8, 178u8, 247u8, 229u8, 213u8, 98u8, 207u8, 231u8, 119u8,
							115u8,
						],
					)
				}
				#[doc = "Set some items of storage."]
				pub fn set_storage(
					&self,
					items: types::set_storage::Items,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetStorage> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"set_storage",
						types::SetStorage { items },
						[
							141u8, 216u8, 52u8, 222u8, 223u8, 136u8, 123u8, 181u8, 19u8, 75u8,
							163u8, 102u8, 229u8, 189u8, 158u8, 142u8, 95u8, 235u8, 240u8, 49u8,
							150u8, 76u8, 78u8, 137u8, 126u8, 88u8, 183u8, 88u8, 231u8, 146u8,
							234u8, 43u8,
						],
					)
				}
				#[doc = "Kill some items from storage."]
				pub fn kill_storage(
					&self,
					keys: types::kill_storage::Keys,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::KillStorage> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"kill_storage",
						types::KillStorage { keys },
						[
							73u8, 63u8, 196u8, 36u8, 144u8, 114u8, 34u8, 213u8, 108u8, 93u8, 209u8,
							234u8, 153u8, 185u8, 33u8, 91u8, 187u8, 195u8, 223u8, 130u8, 58u8,
							156u8, 63u8, 47u8, 228u8, 249u8, 216u8, 139u8, 143u8, 177u8, 41u8,
							35u8,
						],
					)
				}
				#[doc = "Kill all storage items with a key that starts with the given prefix."]
				#[doc = ""]
				#[doc = "**NOTE:** We rely on the Root origin to provide us the number of subkeys under"]
				#[doc = "the prefix we are removing to accurately calculate the weight of this function."]
				pub fn kill_prefix(
					&self,
					prefix: types::kill_prefix::Prefix,
					subkeys: types::kill_prefix::Subkeys,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::KillPrefix> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"kill_prefix",
						types::KillPrefix { prefix, subkeys },
						[
							184u8, 57u8, 139u8, 24u8, 208u8, 87u8, 108u8, 215u8, 198u8, 189u8,
							175u8, 242u8, 167u8, 215u8, 97u8, 63u8, 110u8, 166u8, 238u8, 98u8,
							67u8, 236u8, 111u8, 110u8, 234u8, 81u8, 102u8, 5u8, 182u8, 5u8, 214u8,
							85u8,
						],
					)
				}
				#[doc = "Make some on-chain remark and emit event."]
				pub fn remark_with_event(
					&self,
					remark: types::remark_with_event::Remark,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemarkWithEvent>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"remark_with_event",
						types::RemarkWithEvent { remark },
						[
							120u8, 120u8, 153u8, 92u8, 184u8, 85u8, 34u8, 2u8, 174u8, 206u8, 105u8,
							228u8, 233u8, 130u8, 80u8, 246u8, 228u8, 59u8, 234u8, 240u8, 4u8, 49u8,
							147u8, 170u8, 115u8, 91u8, 149u8, 200u8, 228u8, 181u8, 8u8, 154u8,
						],
					)
				}
				#[doc = "Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied"]
				#[doc = "later."]
				#[doc = ""]
				#[doc = "This call requires Root origin."]
				pub fn authorize_upgrade(
					&self,
					code_hash: types::authorize_upgrade::CodeHash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AuthorizeUpgrade>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"authorize_upgrade",
						types::AuthorizeUpgrade { code_hash },
						[
							4u8, 14u8, 76u8, 107u8, 209u8, 129u8, 9u8, 39u8, 193u8, 17u8, 84u8,
							254u8, 170u8, 214u8, 24u8, 155u8, 29u8, 184u8, 249u8, 241u8, 109u8,
							58u8, 145u8, 131u8, 109u8, 63u8, 38u8, 165u8, 107u8, 215u8, 217u8,
							172u8,
						],
					)
				}
				#[doc = "Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied"]
				#[doc = "later."]
				#[doc = ""]
				#[doc = "WARNING: This authorizes an upgrade that will take place without any safety checks, for"]
				#[doc = "example that the spec name remains the same and that the version number increases. Not"]
				#[doc = "recommended for normal use. Use `authorize_upgrade` instead."]
				#[doc = ""]
				#[doc = "This call requires Root origin."]
				pub fn authorize_upgrade_without_checks(
					&self,
					code_hash: types::authorize_upgrade_without_checks::CodeHash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::AuthorizeUpgradeWithoutChecks,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"authorize_upgrade_without_checks",
						types::AuthorizeUpgradeWithoutChecks { code_hash },
						[
							126u8, 126u8, 55u8, 26u8, 47u8, 55u8, 66u8, 8u8, 167u8, 18u8, 29u8,
							136u8, 146u8, 14u8, 189u8, 117u8, 16u8, 227u8, 162u8, 61u8, 149u8,
							197u8, 104u8, 184u8, 185u8, 161u8, 99u8, 154u8, 80u8, 125u8, 181u8,
							233u8,
						],
					)
				}
				#[doc = "Provide the preimage (runtime binary) `code` for an upgrade that has been authorized."]
				#[doc = ""]
				#[doc = "If the authorization required a version check, this call will ensure the spec name"]
				#[doc = "remains unchanged and that the spec version has increased."]
				#[doc = ""]
				#[doc = "Depending on the runtime's `OnSetCode` configuration, this function may directly apply"]
				#[doc = "the new `code` in the same block or attempt to schedule the upgrade."]
				#[doc = ""]
				#[doc = "All origins are allowed."]
				pub fn apply_authorized_upgrade(
					&self,
					code: types::apply_authorized_upgrade::Code,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::ApplyAuthorizedUpgrade,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"System",
						"apply_authorized_upgrade",
						types::ApplyAuthorizedUpgrade { code },
						[
							232u8, 107u8, 127u8, 38u8, 230u8, 29u8, 97u8, 4u8, 160u8, 191u8, 222u8,
							156u8, 245u8, 102u8, 196u8, 141u8, 44u8, 163u8, 98u8, 68u8, 125u8,
							32u8, 124u8, 101u8, 108u8, 93u8, 211u8, 52u8, 0u8, 231u8, 33u8, 227u8,
						],
					)
				}
			}
		}
		#[doc = "Event for the System pallet."]
		pub type Event = runtime_types::frame_system::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An extrinsic completed successfully."]
			pub struct ExtrinsicSuccess {
				pub dispatch_info: extrinsic_success::DispatchInfo,
			}
			pub mod extrinsic_success {
				use super::runtime_types;
				pub type DispatchInfo = runtime_types::frame_system::DispatchEventInfo;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ExtrinsicSuccess {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "ExtrinsicSuccess";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An extrinsic failed."]
			pub struct ExtrinsicFailed {
				pub dispatch_error: extrinsic_failed::DispatchError,
				pub dispatch_info: extrinsic_failed::DispatchInfo,
			}
			pub mod extrinsic_failed {
				use super::runtime_types;
				pub type DispatchError = runtime_types::sp_runtime::DispatchError;
				pub type DispatchInfo = runtime_types::frame_system::DispatchEventInfo;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ExtrinsicFailed {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "ExtrinsicFailed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "`:code` was updated."]
			pub struct CodeUpdated;
			impl ::subxt::ext::subxt_core::events::StaticEvent for CodeUpdated {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "CodeUpdated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A new account was created."]
			pub struct NewAccount {
				pub account: new_account::Account,
			}
			pub mod new_account {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for NewAccount {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "NewAccount";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An account was reaped."]
			pub struct KilledAccount {
				pub account: killed_account::Account,
			}
			pub mod killed_account {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for KilledAccount {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "KilledAccount";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "On on-chain remark happened."]
			pub struct Remarked {
				pub sender: remarked::Sender,
				pub hash: remarked::Hash,
			}
			pub mod remarked {
				use super::runtime_types;
				pub type Sender = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Remarked {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "Remarked";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An upgrade was authorized."]
			pub struct UpgradeAuthorized {
				pub code_hash: upgrade_authorized::CodeHash,
				pub check_version: upgrade_authorized::CheckVersion,
			}
			pub mod upgrade_authorized {
				use super::runtime_types;
				pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
				pub type CheckVersion = ::core::primitive::bool;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for UpgradeAuthorized {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "UpgradeAuthorized";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An invalid authorized upgrade was rejected while trying to apply it."]
			pub struct RejectedInvalidAuthorizedUpgrade {
				pub code_hash: rejected_invalid_authorized_upgrade::CodeHash,
				pub error: rejected_invalid_authorized_upgrade::Error,
			}
			pub mod rejected_invalid_authorized_upgrade {
				use super::runtime_types;
				pub type CodeHash = ::subxt::ext::subxt_core::utils::H256;
				pub type Error = runtime_types::sp_runtime::DispatchError;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RejectedInvalidAuthorizedUpgrade {
				const PALLET: &'static str = "System";
				const EVENT: &'static str = "RejectedInvalidAuthorizedUpgrade";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod account {
					use super::runtime_types;
					pub type Account = runtime_types::frame_system::AccountInfo<
						::core::primitive::u32,
						runtime_types::pallet_balances::types::AccountData<::core::primitive::u128>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod extrinsic_count {
					use super::runtime_types;
					pub type ExtrinsicCount = ::core::primitive::u32;
				}
				pub mod inherents_applied {
					use super::runtime_types;
					pub type InherentsApplied = ::core::primitive::bool;
				}
				pub mod block_weight {
					use super::runtime_types;
					pub type BlockWeight = runtime_types::frame_support::dispatch::PerDispatchClass<
						runtime_types::sp_weights::weight_v2::Weight,
					>;
				}
				pub mod all_extrinsics_len {
					use super::runtime_types;
					pub type AllExtrinsicsLen = ::core::primitive::u32;
				}
				pub mod block_hash {
					use super::runtime_types;
					pub type BlockHash = ::subxt::ext::subxt_core::utils::H256;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod extrinsic_data {
					use super::runtime_types;
					pub type ExtrinsicData =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod number {
					use super::runtime_types;
					pub type Number = ::core::primitive::u32;
				}
				pub mod parent_hash {
					use super::runtime_types;
					pub type ParentHash = ::subxt::ext::subxt_core::utils::H256;
				}
				pub mod digest {
					use super::runtime_types;
					pub type Digest = runtime_types::sp_runtime::generic::digest::Digest;
				}
				pub mod events {
					use super::runtime_types;
					pub type Events = ::subxt::ext::subxt_core::alloc::vec::Vec<
						runtime_types::frame_system::EventRecord<
							runtime_types::quantus_runtime::RuntimeEvent,
							::subxt::ext::subxt_core::utils::H256,
						>,
					>;
				}
				pub mod event_count {
					use super::runtime_types;
					pub type EventCount = ::core::primitive::u32;
				}
				pub mod event_topics {
					use super::runtime_types;
					pub type EventTopics = ::subxt::ext::subxt_core::alloc::vec::Vec<(
						::core::primitive::u32,
						::core::primitive::u32,
					)>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::H256;
				}
				pub mod last_runtime_upgrade {
					use super::runtime_types;
					pub type LastRuntimeUpgrade =
						runtime_types::frame_system::LastRuntimeUpgradeInfo;
				}
				pub mod upgraded_to_u32_ref_count {
					use super::runtime_types;
					pub type UpgradedToU32RefCount = ::core::primitive::bool;
				}
				pub mod upgraded_to_triple_ref_count {
					use super::runtime_types;
					pub type UpgradedToTripleRefCount = ::core::primitive::bool;
				}
				pub mod execution_phase {
					use super::runtime_types;
					pub type ExecutionPhase = runtime_types::frame_system::Phase;
				}
				pub mod authorized_upgrade {
					use super::runtime_types;
					pub type AuthorizedUpgrade =
						runtime_types::frame_system::CodeUpgradeAuthorization;
				}
				pub mod extrinsic_weight_reclaimed {
					use super::runtime_types;
					pub type ExtrinsicWeightReclaimed =
						runtime_types::sp_weights::weight_v2::Weight;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The full account information for a particular account ID."]
				pub fn account_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::account::Account,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"Account",
						(),
						[
							14u8, 233u8, 115u8, 214u8, 0u8, 109u8, 222u8, 121u8, 162u8, 65u8, 60u8,
							175u8, 209u8, 79u8, 222u8, 124u8, 22u8, 235u8, 138u8, 176u8, 133u8,
							124u8, 90u8, 158u8, 85u8, 45u8, 37u8, 174u8, 47u8, 79u8, 47u8, 166u8,
						],
					)
				}
				#[doc = " The full account information for a particular account ID."]
				pub fn account(
					&self,
					_0: types::account::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::account::Param0,
					>,
					types::account::Account,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"Account",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							14u8, 233u8, 115u8, 214u8, 0u8, 109u8, 222u8, 121u8, 162u8, 65u8, 60u8,
							175u8, 209u8, 79u8, 222u8, 124u8, 22u8, 235u8, 138u8, 176u8, 133u8,
							124u8, 90u8, 158u8, 85u8, 45u8, 37u8, 174u8, 47u8, 79u8, 47u8, 166u8,
						],
					)
				}
				#[doc = " Total extrinsics count for the current block."]
				pub fn extrinsic_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::extrinsic_count::ExtrinsicCount,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"ExtrinsicCount",
						(),
						[
							102u8, 76u8, 236u8, 42u8, 40u8, 231u8, 33u8, 222u8, 123u8, 147u8,
							153u8, 148u8, 234u8, 203u8, 181u8, 119u8, 6u8, 187u8, 177u8, 199u8,
							120u8, 47u8, 137u8, 254u8, 96u8, 100u8, 165u8, 182u8, 249u8, 230u8,
							159u8, 79u8,
						],
					)
				}
				#[doc = " Whether all inherents have been applied."]
				pub fn inherents_applied(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::inherents_applied::InherentsApplied,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"InherentsApplied",
						(),
						[
							132u8, 249u8, 142u8, 252u8, 8u8, 103u8, 80u8, 120u8, 50u8, 6u8, 188u8,
							223u8, 101u8, 55u8, 165u8, 189u8, 172u8, 249u8, 165u8, 230u8, 183u8,
							109u8, 34u8, 65u8, 185u8, 150u8, 29u8, 8u8, 186u8, 129u8, 135u8, 239u8,
						],
					)
				}
				#[doc = " The current weight for the block."]
				pub fn block_weight(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::block_weight::BlockWeight,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"BlockWeight",
						(),
						[
							158u8, 46u8, 228u8, 89u8, 210u8, 214u8, 84u8, 154u8, 50u8, 68u8, 63u8,
							62u8, 43u8, 42u8, 99u8, 27u8, 54u8, 42u8, 146u8, 44u8, 241u8, 216u8,
							229u8, 30u8, 216u8, 255u8, 165u8, 238u8, 181u8, 130u8, 36u8, 102u8,
						],
					)
				}
				#[doc = " Total length (in bytes) for all extrinsics put together, for the current block."]
				pub fn all_extrinsics_len(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::all_extrinsics_len::AllExtrinsicsLen,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"AllExtrinsicsLen",
						(),
						[
							117u8, 86u8, 61u8, 243u8, 41u8, 51u8, 102u8, 214u8, 137u8, 100u8,
							243u8, 185u8, 122u8, 174u8, 187u8, 117u8, 86u8, 189u8, 63u8, 135u8,
							101u8, 218u8, 203u8, 201u8, 237u8, 254u8, 128u8, 183u8, 169u8, 221u8,
							242u8, 65u8,
						],
					)
				}
				#[doc = " Map of block numbers to block hashes."]
				pub fn block_hash_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::block_hash::BlockHash,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"BlockHash",
						(),
						[
							217u8, 32u8, 215u8, 253u8, 24u8, 182u8, 207u8, 178u8, 157u8, 24u8,
							103u8, 100u8, 195u8, 165u8, 69u8, 152u8, 112u8, 181u8, 56u8, 192u8,
							164u8, 16u8, 20u8, 222u8, 28u8, 214u8, 144u8, 142u8, 146u8, 69u8,
							202u8, 118u8,
						],
					)
				}
				#[doc = " Map of block numbers to block hashes."]
				pub fn block_hash(
					&self,
					_0: types::block_hash::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::block_hash::Param0,
					>,
					types::block_hash::BlockHash,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"BlockHash",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							217u8, 32u8, 215u8, 253u8, 24u8, 182u8, 207u8, 178u8, 157u8, 24u8,
							103u8, 100u8, 195u8, 165u8, 69u8, 152u8, 112u8, 181u8, 56u8, 192u8,
							164u8, 16u8, 20u8, 222u8, 28u8, 214u8, 144u8, 142u8, 146u8, 69u8,
							202u8, 118u8,
						],
					)
				}
				#[doc = " Extrinsics data for the current block (maps an extrinsic's index to its data)."]
				pub fn extrinsic_data_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::extrinsic_data::ExtrinsicData,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"ExtrinsicData",
						(),
						[
							160u8, 180u8, 122u8, 18u8, 196u8, 26u8, 2u8, 37u8, 115u8, 232u8, 133u8,
							220u8, 106u8, 245u8, 4u8, 129u8, 42u8, 84u8, 241u8, 45u8, 199u8, 179u8,
							128u8, 61u8, 170u8, 137u8, 231u8, 156u8, 247u8, 57u8, 47u8, 38u8,
						],
					)
				}
				#[doc = " Extrinsics data for the current block (maps an extrinsic's index to its data)."]
				pub fn extrinsic_data(
					&self,
					_0: types::extrinsic_data::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::extrinsic_data::Param0,
					>,
					types::extrinsic_data::ExtrinsicData,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"ExtrinsicData",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							160u8, 180u8, 122u8, 18u8, 196u8, 26u8, 2u8, 37u8, 115u8, 232u8, 133u8,
							220u8, 106u8, 245u8, 4u8, 129u8, 42u8, 84u8, 241u8, 45u8, 199u8, 179u8,
							128u8, 61u8, 170u8, 137u8, 231u8, 156u8, 247u8, 57u8, 47u8, 38u8,
						],
					)
				}
				#[doc = " The current block number being processed. Set by `execute_block`."]
				pub fn number(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::number::Number,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"Number",
						(),
						[
							30u8, 194u8, 177u8, 90u8, 194u8, 232u8, 46u8, 180u8, 85u8, 129u8, 14u8,
							9u8, 8u8, 8u8, 23u8, 95u8, 230u8, 5u8, 13u8, 105u8, 125u8, 2u8, 22u8,
							200u8, 78u8, 93u8, 115u8, 28u8, 150u8, 113u8, 48u8, 53u8,
						],
					)
				}
				#[doc = " Hash of the previous block."]
				pub fn parent_hash(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::parent_hash::ParentHash,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"ParentHash",
						(),
						[
							26u8, 130u8, 11u8, 216u8, 155u8, 71u8, 128u8, 170u8, 30u8, 153u8, 21u8,
							192u8, 62u8, 93u8, 137u8, 80u8, 120u8, 81u8, 202u8, 94u8, 248u8, 125u8,
							71u8, 82u8, 141u8, 229u8, 32u8, 56u8, 73u8, 50u8, 101u8, 78u8,
						],
					)
				}
				#[doc = " Digest of the current block, also part of the block header."]
				pub fn digest(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::digest::Digest,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"Digest",
						(),
						[
							61u8, 64u8, 237u8, 91u8, 145u8, 232u8, 17u8, 254u8, 181u8, 16u8, 234u8,
							91u8, 51u8, 140u8, 254u8, 131u8, 98u8, 135u8, 21u8, 37u8, 251u8, 20u8,
							58u8, 92u8, 123u8, 141u8, 14u8, 227u8, 146u8, 46u8, 222u8, 117u8,
						],
					)
				}
				#[doc = " Events deposited for the current block."]
				#[doc = ""]
				#[doc = " NOTE: The item is unbound and should therefore never be read on chain."]
				#[doc = " It could otherwise inflate the PoV size of a block."]
				#[doc = ""]
				#[doc = " Events have a large in-memory size. Box the events to not go out-of-memory"]
				#[doc = " just in case someone still reads them from within the runtime."]
				pub fn events(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::events::Events,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"Events",
						(),
						[
							247u8, 113u8, 206u8, 36u8, 120u8, 159u8, 199u8, 114u8, 139u8, 213u8,
							233u8, 3u8, 45u8, 108u8, 1u8, 57u8, 21u8, 248u8, 251u8, 33u8, 53u8,
							239u8, 202u8, 118u8, 254u8, 168u8, 223u8, 3u8, 58u8, 212u8, 160u8,
							106u8,
						],
					)
				}
				#[doc = " The number of events in the `Events<T>` list."]
				pub fn event_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::event_count::EventCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"EventCount",
						(),
						[
							175u8, 24u8, 252u8, 184u8, 210u8, 167u8, 146u8, 143u8, 164u8, 80u8,
							151u8, 205u8, 189u8, 189u8, 55u8, 220u8, 47u8, 101u8, 181u8, 33u8,
							254u8, 131u8, 13u8, 143u8, 3u8, 244u8, 245u8, 45u8, 2u8, 210u8, 79u8,
							133u8,
						],
					)
				}
				#[doc = " Mapping between a topic (represented by T::Hash) and a vector of indexes"]
				#[doc = " of events in the `<Events<T>>` list."]
				#[doc = ""]
				#[doc = " All topic vectors have deterministic storage locations depending on the topic. This"]
				#[doc = " allows light-clients to leverage the changes trie storage tracking mechanism and"]
				#[doc = " in case of changes fetch the list of events of interest."]
				#[doc = ""]
				#[doc = " The value has the type `(BlockNumberFor<T>, EventIndex)` because if we used only just"]
				#[doc = " the `EventIndex` then in case if the topic has the same contents on the next block"]
				#[doc = " no notification will be triggered thus the event might be lost."]
				pub fn event_topics_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::event_topics::EventTopics,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"EventTopics",
						(),
						[
							40u8, 225u8, 14u8, 75u8, 44u8, 176u8, 76u8, 34u8, 143u8, 107u8, 69u8,
							133u8, 114u8, 13u8, 172u8, 250u8, 141u8, 73u8, 12u8, 65u8, 217u8, 63u8,
							120u8, 241u8, 48u8, 106u8, 143u8, 161u8, 128u8, 100u8, 166u8, 59u8,
						],
					)
				}
				#[doc = " Mapping between a topic (represented by T::Hash) and a vector of indexes"]
				#[doc = " of events in the `<Events<T>>` list."]
				#[doc = ""]
				#[doc = " All topic vectors have deterministic storage locations depending on the topic. This"]
				#[doc = " allows light-clients to leverage the changes trie storage tracking mechanism and"]
				#[doc = " in case of changes fetch the list of events of interest."]
				#[doc = ""]
				#[doc = " The value has the type `(BlockNumberFor<T>, EventIndex)` because if we used only just"]
				#[doc = " the `EventIndex` then in case if the topic has the same contents on the next block"]
				#[doc = " no notification will be triggered thus the event might be lost."]
				pub fn event_topics(
					&self,
					_0: types::event_topics::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::event_topics::Param0,
					>,
					types::event_topics::EventTopics,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"EventTopics",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							40u8, 225u8, 14u8, 75u8, 44u8, 176u8, 76u8, 34u8, 143u8, 107u8, 69u8,
							133u8, 114u8, 13u8, 172u8, 250u8, 141u8, 73u8, 12u8, 65u8, 217u8, 63u8,
							120u8, 241u8, 48u8, 106u8, 143u8, 161u8, 128u8, 100u8, 166u8, 59u8,
						],
					)
				}
				#[doc = " Stores the `spec_version` and `spec_name` of when the last runtime upgrade happened."]
				pub fn last_runtime_upgrade(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::last_runtime_upgrade::LastRuntimeUpgrade,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"LastRuntimeUpgrade",
						(),
						[
							197u8, 212u8, 249u8, 209u8, 79u8, 34u8, 55u8, 203u8, 31u8, 42u8, 199u8,
							242u8, 188u8, 74u8, 234u8, 250u8, 245u8, 44u8, 139u8, 162u8, 45u8,
							150u8, 230u8, 249u8, 135u8, 100u8, 158u8, 167u8, 118u8, 219u8, 28u8,
							98u8,
						],
					)
				}
				#[doc = " True if we have upgraded so that `type RefCount` is `u32`. False (default) if not."]
				pub fn upgraded_to_u32_ref_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::upgraded_to_u32_ref_count::UpgradedToU32RefCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"UpgradedToU32RefCount",
						(),
						[
							229u8, 73u8, 9u8, 132u8, 186u8, 116u8, 151u8, 171u8, 145u8, 29u8, 34u8,
							130u8, 52u8, 146u8, 124u8, 175u8, 79u8, 189u8, 147u8, 230u8, 234u8,
							107u8, 124u8, 31u8, 2u8, 22u8, 86u8, 190u8, 4u8, 147u8, 50u8, 245u8,
						],
					)
				}
				#[doc = " True if we have upgraded so that AccountInfo contains three types of `RefCount`. False"]
				#[doc = " (default) if not."]
				pub fn upgraded_to_triple_ref_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::upgraded_to_triple_ref_count::UpgradedToTripleRefCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"UpgradedToTripleRefCount",
						(),
						[
							97u8, 66u8, 124u8, 243u8, 27u8, 167u8, 147u8, 81u8, 254u8, 201u8,
							101u8, 24u8, 40u8, 231u8, 14u8, 179u8, 154u8, 163u8, 71u8, 81u8, 185u8,
							167u8, 82u8, 254u8, 189u8, 3u8, 101u8, 207u8, 206u8, 194u8, 155u8,
							151u8,
						],
					)
				}
				#[doc = " The execution phase of the block."]
				pub fn execution_phase(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::execution_phase::ExecutionPhase,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"ExecutionPhase",
						(),
						[
							191u8, 129u8, 100u8, 134u8, 126u8, 116u8, 154u8, 203u8, 220u8, 200u8,
							0u8, 26u8, 161u8, 250u8, 133u8, 205u8, 146u8, 24u8, 5u8, 156u8, 158u8,
							35u8, 36u8, 253u8, 52u8, 235u8, 86u8, 167u8, 35u8, 100u8, 119u8, 27u8,
						],
					)
				}
				#[doc = " `Some` if a code upgrade has been authorized."]
				pub fn authorized_upgrade(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::authorized_upgrade::AuthorizedUpgrade,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"AuthorizedUpgrade",
						(),
						[
							165u8, 97u8, 27u8, 138u8, 2u8, 28u8, 55u8, 92u8, 96u8, 96u8, 168u8,
							169u8, 55u8, 178u8, 44u8, 127u8, 58u8, 140u8, 206u8, 178u8, 1u8, 37u8,
							214u8, 213u8, 251u8, 123u8, 5u8, 111u8, 90u8, 148u8, 217u8, 135u8,
						],
					)
				}
				#[doc = " The weight reclaimed for the extrinsic."]
				#[doc = ""]
				#[doc = " This information is available until the end of the extrinsic execution."]
				#[doc = " More precisely this information is removed in `note_applied_extrinsic`."]
				#[doc = ""]
				#[doc = " Logic doing some post dispatch weight reduction must update this storage to avoid duplicate"]
				#[doc = " reduction."]
				pub fn extrinsic_weight_reclaimed(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::extrinsic_weight_reclaimed::ExtrinsicWeightReclaimed,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"System",
						"ExtrinsicWeightReclaimed",
						(),
						[
							195u8, 143u8, 164u8, 84u8, 225u8, 194u8, 227u8, 128u8, 196u8, 241u8,
							188u8, 159u8, 59u8, 197u8, 11u8, 12u8, 119u8, 164u8, 46u8, 229u8, 92u8,
							212u8, 236u8, 255u8, 238u8, 54u8, 105u8, 200u8, 229u8, 191u8, 221u8,
							202u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " Block & extrinsics weights: base values and limits."]
				pub fn block_weights(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::frame_system::limits::BlockWeights,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"System",
						"BlockWeights",
						[
							176u8, 124u8, 225u8, 136u8, 25u8, 73u8, 247u8, 33u8, 82u8, 206u8, 85u8,
							190u8, 127u8, 102u8, 71u8, 11u8, 185u8, 8u8, 58u8, 0u8, 94u8, 55u8,
							163u8, 177u8, 104u8, 59u8, 60u8, 136u8, 246u8, 116u8, 0u8, 239u8,
						],
					)
				}
				#[doc = " The maximum length of a block (in bytes)."]
				pub fn block_length(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::frame_system::limits::BlockLength,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"System",
						"BlockLength",
						[
							23u8, 242u8, 225u8, 39u8, 225u8, 67u8, 152u8, 41u8, 155u8, 104u8, 68u8,
							229u8, 185u8, 133u8, 10u8, 143u8, 184u8, 152u8, 234u8, 44u8, 140u8,
							96u8, 166u8, 235u8, 162u8, 160u8, 72u8, 7u8, 35u8, 194u8, 3u8, 37u8,
						],
					)
				}
				#[doc = " Maximum number of block number to block hash mappings to keep (oldest pruned first)."]
				pub fn block_hash_count(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"System",
						"BlockHashCount",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The weight of runtime database operations the runtime can invoke."]
				pub fn db_weight(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::sp_weights::RuntimeDbWeight,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"System",
						"DbWeight",
						[
							42u8, 43u8, 178u8, 142u8, 243u8, 203u8, 60u8, 173u8, 118u8, 111u8,
							200u8, 170u8, 102u8, 70u8, 237u8, 187u8, 198u8, 120u8, 153u8, 232u8,
							183u8, 76u8, 74u8, 10u8, 70u8, 243u8, 14u8, 218u8, 213u8, 126u8, 29u8,
							177u8,
						],
					)
				}
				#[doc = " Get the chain's in-code version."]
				pub fn version(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::sp_version::RuntimeVersion,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"System",
						"Version",
						[
							214u8, 43u8, 96u8, 193u8, 96u8, 213u8, 63u8, 124u8, 22u8, 111u8, 41u8,
							78u8, 146u8, 77u8, 34u8, 163u8, 117u8, 100u8, 6u8, 216u8, 238u8, 54u8,
							80u8, 185u8, 219u8, 11u8, 192u8, 200u8, 129u8, 88u8, 161u8, 250u8,
						],
					)
				}
				#[doc = " The designated SS58 prefix of this chain."]
				#[doc = ""]
				#[doc = " This replaces the \"ss58Format\" property declared in the chain spec. Reason is"]
				#[doc = " that the runtime should know about the prefix in order to make use of it as"]
				#[doc = " an identifier of the chain."]
				pub fn ss58_prefix(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u16,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"System",
						"SS58Prefix",
						[
							116u8, 33u8, 2u8, 170u8, 181u8, 147u8, 171u8, 169u8, 167u8, 227u8,
							41u8, 144u8, 11u8, 236u8, 82u8, 100u8, 74u8, 60u8, 184u8, 72u8, 169u8,
							90u8, 208u8, 135u8, 15u8, 117u8, 10u8, 123u8, 128u8, 193u8, 29u8, 70u8,
						],
					)
				}
			}
		}
	}
	pub mod timestamp {
		use super::{root_mod, runtime_types};
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_timestamp::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set the current time."]
				#[doc = ""]
				#[doc = "This call should be invoked exactly once per block. It will panic at the finalization"]
				#[doc = "phase, if this call hasn't been invoked by that time."]
				#[doc = ""]
				#[doc = "The timestamp should be greater than the previous one by the amount specified by"]
				#[doc = "[`Config::MinimumPeriod`]."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _None_."]
				#[doc = ""]
				#[doc = "This dispatch class is _Mandatory_ to ensure it gets executed in the block. Be aware"]
				#[doc = "that changing the complexity of this call could result exhausting the resources in a"]
				#[doc = "block to execute any other calls."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)` (Note that implementations of `OnTimestampSet` must also be `O(1)`)"]
				#[doc = "- 1 storage read and 1 storage mutation (codec `O(1)` because of `DidUpdate::take` in"]
				#[doc = "  `on_finalize`)"]
				#[doc = "- 1 event handler `on_timestamp_set`. Must be `O(1)`."]
				pub struct Set {
					#[codec(compact)]
					pub now: set::Now,
				}
				pub mod set {
					use super::runtime_types;
					pub type Now = ::core::primitive::u64;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Set {
					const PALLET: &'static str = "Timestamp";
					const CALL: &'static str = "set";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Set the current time."]
				#[doc = ""]
				#[doc = "This call should be invoked exactly once per block. It will panic at the finalization"]
				#[doc = "phase, if this call hasn't been invoked by that time."]
				#[doc = ""]
				#[doc = "The timestamp should be greater than the previous one by the amount specified by"]
				#[doc = "[`Config::MinimumPeriod`]."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _None_."]
				#[doc = ""]
				#[doc = "This dispatch class is _Mandatory_ to ensure it gets executed in the block. Be aware"]
				#[doc = "that changing the complexity of this call could result exhausting the resources in a"]
				#[doc = "block to execute any other calls."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)` (Note that implementations of `OnTimestampSet` must also be `O(1)`)"]
				#[doc = "- 1 storage read and 1 storage mutation (codec `O(1)` because of `DidUpdate::take` in"]
				#[doc = "  `on_finalize`)"]
				#[doc = "- 1 event handler `on_timestamp_set`. Must be `O(1)`."]
				pub fn set(
					&self,
					now: types::set::Now,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Set> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Timestamp",
						"set",
						types::Set { now },
						[
							37u8, 95u8, 49u8, 218u8, 24u8, 22u8, 0u8, 95u8, 72u8, 35u8, 155u8,
							199u8, 213u8, 54u8, 207u8, 22u8, 185u8, 193u8, 221u8, 70u8, 18u8,
							200u8, 4u8, 231u8, 195u8, 173u8, 6u8, 122u8, 11u8, 203u8, 231u8, 227u8,
						],
					)
				}
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod now {
					use super::runtime_types;
					pub type Now = ::core::primitive::u64;
				}
				pub mod did_update {
					use super::runtime_types;
					pub type DidUpdate = ::core::primitive::bool;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The current time for the current block."]
				pub fn now(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::now::Now,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Timestamp",
						"Now",
						(),
						[
							44u8, 50u8, 80u8, 30u8, 195u8, 146u8, 123u8, 238u8, 8u8, 163u8, 187u8,
							92u8, 61u8, 39u8, 51u8, 29u8, 173u8, 169u8, 217u8, 158u8, 85u8, 187u8,
							141u8, 26u8, 12u8, 115u8, 51u8, 11u8, 200u8, 244u8, 138u8, 152u8,
						],
					)
				}
				#[doc = " Whether the timestamp has been updated in this block."]
				#[doc = ""]
				#[doc = " This value is updated to `true` upon successful submission of a timestamp by a node."]
				#[doc = " It is then checked at the end of each block execution in the `on_finalize` hook."]
				pub fn did_update(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::did_update::DidUpdate,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Timestamp",
						"DidUpdate",
						(),
						[
							229u8, 175u8, 246u8, 102u8, 237u8, 158u8, 212u8, 229u8, 238u8, 214u8,
							205u8, 160u8, 164u8, 252u8, 195u8, 75u8, 139u8, 110u8, 22u8, 34u8,
							248u8, 204u8, 107u8, 46u8, 20u8, 200u8, 238u8, 167u8, 71u8, 41u8,
							214u8, 140u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The minimum period between blocks."]
				#[doc = ""]
				#[doc = " Be aware that this is different to the *expected* period that the block production"]
				#[doc = " apparatus provides. Your chosen consensus system will generally work with this to"]
				#[doc = " determine a sensible block time. For example, in the Aura pallet it will be double this"]
				#[doc = " period on default settings."]
				pub fn minimum_period(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u64,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Timestamp",
						"MinimumPeriod",
						[
							128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8,
							59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8,
							103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8,
							246u8,
						],
					)
				}
			}
		}
	}
	pub mod balances {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_balances::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_balances::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Transfer some liquid free balance to another account."]
				#[doc = ""]
				#[doc = "`transfer_allow_death` will set the `FreeBalance` of the sender and receiver."]
				#[doc = "If the sender's account is below the existential deposit as a result"]
				#[doc = "of the transfer, the account will be reaped."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be `Signed` by the transactor."]
				pub struct TransferAllowDeath {
					pub dest: transfer_allow_death::Dest,
					#[codec(compact)]
					pub value: transfer_allow_death::Value,
				}
				pub mod transfer_allow_death {
					use super::runtime_types;
					pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Value = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferAllowDeath {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "transfer_allow_death";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Exactly as `transfer_allow_death`, except the origin must be root and the source account"]
				#[doc = "may be specified."]
				pub struct ForceTransfer {
					pub source: force_transfer::Source,
					pub dest: force_transfer::Dest,
					#[codec(compact)]
					pub value: force_transfer::Value,
				}
				pub mod force_transfer {
					use super::runtime_types;
					pub type Source = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Value = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceTransfer {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "force_transfer";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Same as the [`transfer_allow_death`] call, but with a check that the transfer will not"]
				#[doc = "kill the origin account."]
				#[doc = ""]
				#[doc = "99% of the time you want [`transfer_allow_death`] instead."]
				#[doc = ""]
				#[doc = "[`transfer_allow_death`]: struct.Pallet.html#method.transfer"]
				pub struct TransferKeepAlive {
					pub dest: transfer_keep_alive::Dest,
					#[codec(compact)]
					pub value: transfer_keep_alive::Value,
				}
				pub mod transfer_keep_alive {
					use super::runtime_types;
					pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Value = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferKeepAlive {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "transfer_keep_alive";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Transfer the entire transferable balance from the caller account."]
				#[doc = ""]
				#[doc = "NOTE: This function only attempts to transfer _transferable_ balances. This means that"]
				#[doc = "any locked, reserved, or existential deposits (when `keep_alive` is `true`), will not be"]
				#[doc = "transferred by this function. To ensure that this function results in a killed account,"]
				#[doc = "you might need to prepare the account by removing any reference counters, storage"]
				#[doc = "deposits, etc..."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be Signed."]
				#[doc = ""]
				#[doc = "- `dest`: The recipient of the transfer."]
				#[doc = "- `keep_alive`: A boolean to determine if the `transfer_all` operation should send all"]
				#[doc = "  of the funds the account has, causing the sender account to be killed (false), or"]
				#[doc = "  transfer everything except at least the existential deposit, which will guarantee to"]
				#[doc = "  keep the sender account alive (true)."]
				pub struct TransferAll {
					pub dest: transfer_all::Dest,
					pub keep_alive: transfer_all::KeepAlive,
				}
				pub mod transfer_all {
					use super::runtime_types;
					pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type KeepAlive = ::core::primitive::bool;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for TransferAll {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "transfer_all";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Unreserve some balance from a user by force."]
				#[doc = ""]
				#[doc = "Can only be called by ROOT."]
				pub struct ForceUnreserve {
					pub who: force_unreserve::Who,
					pub amount: force_unreserve::Amount,
				}
				pub mod force_unreserve {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Amount = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceUnreserve {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "force_unreserve";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Upgrade a specified account."]
				#[doc = ""]
				#[doc = "- `origin`: Must be `Signed`."]
				#[doc = "- `who`: The account to be upgraded."]
				#[doc = ""]
				#[doc = "This will waive the transaction fee if at least all but 10% of the accounts needed to"]
				#[doc = "be upgraded. (We let some not have to be upgraded just in order to allow for the"]
				#[doc = "possibility of churn)."]
				pub struct UpgradeAccounts {
					pub who: upgrade_accounts::Who,
				}
				pub mod upgrade_accounts {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::alloc::vec::Vec<
						::subxt::ext::subxt_core::utils::AccountId32,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UpgradeAccounts {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "upgrade_accounts";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set the regular balance of a given account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call is `root`."]
				pub struct ForceSetBalance {
					pub who: force_set_balance::Who,
					#[codec(compact)]
					pub new_free: force_set_balance::NewFree,
				}
				pub mod force_set_balance {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type NewFree = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceSetBalance {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "force_set_balance";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Adjust the total issuance in a saturating way."]
				#[doc = ""]
				#[doc = "Can only be called by root and always needs a positive `delta`."]
				#[doc = ""]
				#[doc = "# Example"]
				pub struct ForceAdjustTotalIssuance {
					pub direction: force_adjust_total_issuance::Direction,
					#[codec(compact)]
					pub delta: force_adjust_total_issuance::Delta,
				}
				pub mod force_adjust_total_issuance {
					use super::runtime_types;
					pub type Direction = runtime_types::pallet_balances::types::AdjustmentDirection;
					pub type Delta = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceAdjustTotalIssuance {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "force_adjust_total_issuance";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Burn the specified liquid free balance from the origin account."]
				#[doc = ""]
				#[doc = "If the origin's account ends up below the existential deposit as a result"]
				#[doc = "of the burn and `keep_alive` is false, the account will be reaped."]
				#[doc = ""]
				#[doc = "Unlike sending funds to a _burn_ address, which merely makes the funds inaccessible,"]
				#[doc = "this `burn` operation will reduce total issuance by the amount _burned_."]
				pub struct Burn {
					#[codec(compact)]
					pub value: burn::Value,
					pub keep_alive: burn::KeepAlive,
				}
				pub mod burn {
					use super::runtime_types;
					pub type Value = ::core::primitive::u128;
					pub type KeepAlive = ::core::primitive::bool;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Burn {
					const PALLET: &'static str = "Balances";
					const CALL: &'static str = "burn";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Transfer some liquid free balance to another account."]
				#[doc = ""]
				#[doc = "`transfer_allow_death` will set the `FreeBalance` of the sender and receiver."]
				#[doc = "If the sender's account is below the existential deposit as a result"]
				#[doc = "of the transfer, the account will be reaped."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be `Signed` by the transactor."]
				pub fn transfer_allow_death(
					&self,
					dest: types::transfer_allow_death::Dest,
					value: types::transfer_allow_death::Value,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferAllowDeath>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"transfer_allow_death",
						types::TransferAllowDeath { dest, value },
						[
							51u8, 166u8, 195u8, 10u8, 139u8, 218u8, 55u8, 130u8, 6u8, 194u8, 35u8,
							140u8, 27u8, 205u8, 214u8, 222u8, 102u8, 43u8, 143u8, 145u8, 86u8,
							219u8, 210u8, 147u8, 13u8, 39u8, 51u8, 21u8, 237u8, 179u8, 132u8,
							130u8,
						],
					)
				}
				#[doc = "Exactly as `transfer_allow_death`, except the origin must be root and the source account"]
				#[doc = "may be specified."]
				pub fn force_transfer(
					&self,
					source: types::force_transfer::Source,
					dest: types::force_transfer::Dest,
					value: types::force_transfer::Value,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceTransfer>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"force_transfer",
						types::ForceTransfer { source, dest, value },
						[
							154u8, 93u8, 222u8, 27u8, 12u8, 248u8, 63u8, 213u8, 224u8, 86u8, 250u8,
							153u8, 249u8, 102u8, 83u8, 160u8, 79u8, 125u8, 105u8, 222u8, 77u8,
							180u8, 90u8, 105u8, 81u8, 217u8, 60u8, 25u8, 213u8, 51u8, 185u8, 96u8,
						],
					)
				}
				#[doc = "Same as the [`transfer_allow_death`] call, but with a check that the transfer will not"]
				#[doc = "kill the origin account."]
				#[doc = ""]
				#[doc = "99% of the time you want [`transfer_allow_death`] instead."]
				#[doc = ""]
				#[doc = "[`transfer_allow_death`]: struct.Pallet.html#method.transfer"]
				pub fn transfer_keep_alive(
					&self,
					dest: types::transfer_keep_alive::Dest,
					value: types::transfer_keep_alive::Value,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferKeepAlive>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"transfer_keep_alive",
						types::TransferKeepAlive { dest, value },
						[
							245u8, 14u8, 190u8, 193u8, 32u8, 210u8, 74u8, 92u8, 25u8, 182u8, 76u8,
							55u8, 247u8, 83u8, 114u8, 75u8, 143u8, 236u8, 117u8, 25u8, 54u8, 157u8,
							208u8, 207u8, 233u8, 89u8, 70u8, 161u8, 235u8, 242u8, 222u8, 59u8,
						],
					)
				}
				#[doc = "Transfer the entire transferable balance from the caller account."]
				#[doc = ""]
				#[doc = "NOTE: This function only attempts to transfer _transferable_ balances. This means that"]
				#[doc = "any locked, reserved, or existential deposits (when `keep_alive` is `true`), will not be"]
				#[doc = "transferred by this function. To ensure that this function results in a killed account,"]
				#[doc = "you might need to prepare the account by removing any reference counters, storage"]
				#[doc = "deposits, etc..."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be Signed."]
				#[doc = ""]
				#[doc = "- `dest`: The recipient of the transfer."]
				#[doc = "- `keep_alive`: A boolean to determine if the `transfer_all` operation should send all"]
				#[doc = "  of the funds the account has, causing the sender account to be killed (false), or"]
				#[doc = "  transfer everything except at least the existential deposit, which will guarantee to"]
				#[doc = "  keep the sender account alive (true)."]
				pub fn transfer_all(
					&self,
					dest: types::transfer_all::Dest,
					keep_alive: types::transfer_all::KeepAlive,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::TransferAll> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"transfer_all",
						types::TransferAll { dest, keep_alive },
						[
							105u8, 132u8, 49u8, 144u8, 195u8, 250u8, 34u8, 46u8, 213u8, 248u8,
							112u8, 188u8, 81u8, 228u8, 136u8, 18u8, 67u8, 172u8, 37u8, 38u8, 238u8,
							9u8, 34u8, 15u8, 67u8, 34u8, 148u8, 195u8, 223u8, 29u8, 154u8, 6u8,
						],
					)
				}
				#[doc = "Unreserve some balance from a user by force."]
				#[doc = ""]
				#[doc = "Can only be called by ROOT."]
				pub fn force_unreserve(
					&self,
					who: types::force_unreserve::Who,
					amount: types::force_unreserve::Amount,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceUnreserve>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"force_unreserve",
						types::ForceUnreserve { who, amount },
						[
							142u8, 151u8, 64u8, 205u8, 46u8, 64u8, 62u8, 122u8, 108u8, 49u8, 223u8,
							140u8, 120u8, 153u8, 35u8, 165u8, 187u8, 38u8, 157u8, 200u8, 123u8,
							199u8, 198u8, 168u8, 208u8, 159u8, 39u8, 134u8, 92u8, 103u8, 84u8,
							171u8,
						],
					)
				}
				#[doc = "Upgrade a specified account."]
				#[doc = ""]
				#[doc = "- `origin`: Must be `Signed`."]
				#[doc = "- `who`: The account to be upgraded."]
				#[doc = ""]
				#[doc = "This will waive the transaction fee if at least all but 10% of the accounts needed to"]
				#[doc = "be upgraded. (We let some not have to be upgraded just in order to allow for the"]
				#[doc = "possibility of churn)."]
				pub fn upgrade_accounts(
					&self,
					who: types::upgrade_accounts::Who,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UpgradeAccounts>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"upgrade_accounts",
						types::UpgradeAccounts { who },
						[
							66u8, 200u8, 179u8, 104u8, 65u8, 2u8, 101u8, 56u8, 130u8, 161u8, 224u8,
							233u8, 255u8, 124u8, 70u8, 122u8, 8u8, 49u8, 103u8, 178u8, 68u8, 47u8,
							214u8, 166u8, 217u8, 116u8, 178u8, 50u8, 212u8, 164u8, 98u8, 226u8,
						],
					)
				}
				#[doc = "Set the regular balance of a given account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call is `root`."]
				pub fn force_set_balance(
					&self,
					who: types::force_set_balance::Who,
					new_free: types::force_set_balance::NewFree,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceSetBalance>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"force_set_balance",
						types::ForceSetBalance { who, new_free },
						[
							114u8, 229u8, 59u8, 204u8, 180u8, 83u8, 17u8, 4u8, 59u8, 4u8, 55u8,
							39u8, 151u8, 196u8, 124u8, 60u8, 209u8, 65u8, 193u8, 11u8, 44u8, 164u8,
							116u8, 93u8, 169u8, 30u8, 199u8, 165u8, 55u8, 231u8, 223u8, 43u8,
						],
					)
				}
				#[doc = "Adjust the total issuance in a saturating way."]
				#[doc = ""]
				#[doc = "Can only be called by root and always needs a positive `delta`."]
				#[doc = ""]
				#[doc = "# Example"]
				pub fn force_adjust_total_issuance(
					&self,
					direction: types::force_adjust_total_issuance::Direction,
					delta: types::force_adjust_total_issuance::Delta,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::ForceAdjustTotalIssuance,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"force_adjust_total_issuance",
						types::ForceAdjustTotalIssuance { direction, delta },
						[
							208u8, 134u8, 56u8, 133u8, 232u8, 164u8, 10u8, 213u8, 53u8, 193u8,
							190u8, 63u8, 236u8, 186u8, 96u8, 122u8, 104u8, 87u8, 173u8, 38u8, 58u8,
							176u8, 21u8, 78u8, 42u8, 106u8, 46u8, 248u8, 251u8, 190u8, 150u8,
							202u8,
						],
					)
				}
				#[doc = "Burn the specified liquid free balance from the origin account."]
				#[doc = ""]
				#[doc = "If the origin's account ends up below the existential deposit as a result"]
				#[doc = "of the burn and `keep_alive` is false, the account will be reaped."]
				#[doc = ""]
				#[doc = "Unlike sending funds to a _burn_ address, which merely makes the funds inaccessible,"]
				#[doc = "this `burn` operation will reduce total issuance by the amount _burned_."]
				pub fn burn(
					&self,
					value: types::burn::Value,
					keep_alive: types::burn::KeepAlive,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Burn> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Balances",
						"burn",
						types::Burn { value, keep_alive },
						[
							176u8, 64u8, 7u8, 109u8, 16u8, 44u8, 145u8, 125u8, 147u8, 152u8, 130u8,
							114u8, 221u8, 201u8, 150u8, 162u8, 118u8, 71u8, 52u8, 92u8, 240u8,
							116u8, 203u8, 98u8, 5u8, 22u8, 43u8, 102u8, 94u8, 208u8, 101u8, 57u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_balances::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An account was created with some free balance."]
			pub struct Endowed {
				pub account: endowed::Account,
				pub free_balance: endowed::FreeBalance,
			}
			pub mod endowed {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type FreeBalance = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Endowed {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Endowed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An account was removed whose balance was non-zero but below ExistentialDeposit,"]
			#[doc = "resulting in an outright loss."]
			pub struct DustLost {
				pub account: dust_lost::Account,
				pub amount: dust_lost::Amount,
			}
			pub mod dust_lost {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DustLost {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "DustLost";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Transfer succeeded."]
			pub struct Transfer {
				pub from: transfer::From,
				pub to: transfer::To,
				pub amount: transfer::Amount,
			}
			pub mod transfer {
				use super::runtime_types;
				pub type From = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type To = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Transfer {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Transfer";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A balance was set by root."]
			pub struct BalanceSet {
				pub who: balance_set::Who,
				pub free: balance_set::Free,
			}
			pub mod balance_set {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Free = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for BalanceSet {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "BalanceSet";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was reserved (moved from free to reserved)."]
			pub struct Reserved {
				pub who: reserved::Who,
				pub amount: reserved::Amount,
			}
			pub mod reserved {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Reserved {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Reserved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was unreserved (moved from reserved to free)."]
			pub struct Unreserved {
				pub who: unreserved::Who,
				pub amount: unreserved::Amount,
			}
			pub mod unreserved {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Unreserved {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Unreserved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was moved from the reserve of the first account to the second account."]
			#[doc = "Final argument indicates the destination balance type."]
			pub struct ReserveRepatriated {
				pub from: reserve_repatriated::From,
				pub to: reserve_repatriated::To,
				pub amount: reserve_repatriated::Amount,
				pub destination_status: reserve_repatriated::DestinationStatus,
			}
			pub mod reserve_repatriated {
				use super::runtime_types;
				pub type From = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type To = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
				pub type DestinationStatus =
					runtime_types::frame_support::traits::tokens::misc::BalanceStatus;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ReserveRepatriated {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "ReserveRepatriated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was deposited (e.g. for transaction fees)."]
			pub struct Deposit {
				pub who: deposit::Who,
				pub amount: deposit::Amount,
			}
			pub mod deposit {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Deposit {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Deposit";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was withdrawn from the account (e.g. for transaction fees)."]
			pub struct Withdraw {
				pub who: withdraw::Who,
				pub amount: withdraw::Amount,
			}
			pub mod withdraw {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Withdraw {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Withdraw";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was removed from the account (e.g. for misbehavior)."]
			pub struct Slashed {
				pub who: slashed::Who,
				pub amount: slashed::Amount,
			}
			pub mod slashed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Slashed {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Slashed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was minted into an account."]
			pub struct Minted {
				pub who: minted::Who,
				pub amount: minted::Amount,
			}
			pub mod minted {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Minted {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Minted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was burned from an account."]
			pub struct Burned {
				pub who: burned::Who,
				pub amount: burned::Amount,
			}
			pub mod burned {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Burned {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Burned";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was suspended from an account (it can be restored later)."]
			pub struct Suspended {
				pub who: suspended::Who,
				pub amount: suspended::Amount,
			}
			pub mod suspended {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Suspended {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Suspended";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some amount was restored into an account."]
			pub struct Restored {
				pub who: restored::Who,
				pub amount: restored::Amount,
			}
			pub mod restored {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Restored {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Restored";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An account was upgraded."]
			pub struct Upgraded {
				pub who: upgraded::Who,
			}
			pub mod upgraded {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Upgraded {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Upgraded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Total issuance was increased by `amount`, creating a credit to be balanced."]
			pub struct Issued {
				pub amount: issued::Amount,
			}
			pub mod issued {
				use super::runtime_types;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Issued {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Issued";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Total issuance was decreased by `amount`, creating a debt to be balanced."]
			pub struct Rescinded {
				pub amount: rescinded::Amount,
			}
			pub mod rescinded {
				use super::runtime_types;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Rescinded {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Rescinded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was locked."]
			pub struct Locked {
				pub who: locked::Who,
				pub amount: locked::Amount,
			}
			pub mod locked {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Locked {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Locked";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was unlocked."]
			pub struct Unlocked {
				pub who: unlocked::Who,
				pub amount: unlocked::Amount,
			}
			pub mod unlocked {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Unlocked {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Unlocked";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was frozen."]
			pub struct Frozen {
				pub who: frozen::Who,
				pub amount: frozen::Amount,
			}
			pub mod frozen {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Frozen {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Frozen";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some balance was thawed."]
			pub struct Thawed {
				pub who: thawed::Who,
				pub amount: thawed::Amount,
			}
			pub mod thawed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Thawed {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "Thawed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The `TotalIssuance` was forcefully changed."]
			pub struct TotalIssuanceForced {
				pub old: total_issuance_forced::Old,
				pub new: total_issuance_forced::New,
			}
			pub mod total_issuance_forced {
				use super::runtime_types;
				pub type Old = ::core::primitive::u128;
				pub type New = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TotalIssuanceForced {
				const PALLET: &'static str = "Balances";
				const EVENT: &'static str = "TotalIssuanceForced";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod total_issuance {
					use super::runtime_types;
					pub type TotalIssuance = ::core::primitive::u128;
				}
				pub mod inactive_issuance {
					use super::runtime_types;
					pub type InactiveIssuance = ::core::primitive::u128;
				}
				pub mod account {
					use super::runtime_types;
					pub type Account =
						runtime_types::pallet_balances::types::AccountData<::core::primitive::u128>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod locks {
					use super::runtime_types;
					pub type Locks =
						runtime_types::bounded_collections::weak_bounded_vec::WeakBoundedVec<
							runtime_types::pallet_balances::types::BalanceLock<
								::core::primitive::u128,
							>,
						>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod reserves {
					use super::runtime_types;
					pub type Reserves = runtime_types::bounded_collections::bounded_vec::BoundedVec<
						runtime_types::pallet_balances::types::ReserveData<
							[::core::primitive::u8; 8usize],
							::core::primitive::u128,
						>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod holds {
					use super::runtime_types;
					pub type Holds = runtime_types::bounded_collections::bounded_vec::BoundedVec<
						runtime_types::frame_support::traits::tokens::misc::IdAmount<
							runtime_types::quantus_runtime::RuntimeHoldReason,
							::core::primitive::u128,
						>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod freezes {
					use super::runtime_types;
					pub type Freezes = runtime_types::bounded_collections::bounded_vec::BoundedVec<
						runtime_types::frame_support::traits::tokens::misc::IdAmount<
							runtime_types::quantus_runtime::RuntimeFreezeReason,
							::core::primitive::u128,
						>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod transfer_proof {
					use super::runtime_types;
					pub type TransferProof = ();
					pub type Param0 = (
						::core::primitive::u64,
						::subxt::ext::subxt_core::utils::AccountId32,
						::subxt::ext::subxt_core::utils::AccountId32,
						::core::primitive::u128,
					);
				}
				pub mod transfer_count {
					use super::runtime_types;
					pub type TransferCount = ::core::primitive::u64;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The total units issued in the system."]
				pub fn total_issuance(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::total_issuance::TotalIssuance,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"TotalIssuance",
						(),
						[
							116u8, 70u8, 119u8, 194u8, 69u8, 37u8, 116u8, 206u8, 171u8, 70u8,
							171u8, 210u8, 226u8, 111u8, 184u8, 204u8, 206u8, 11u8, 68u8, 72u8,
							255u8, 19u8, 194u8, 11u8, 27u8, 194u8, 81u8, 204u8, 59u8, 224u8, 202u8,
							185u8,
						],
					)
				}
				#[doc = " The total units of outstanding deactivated balance in the system."]
				pub fn inactive_issuance(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::inactive_issuance::InactiveIssuance,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"InactiveIssuance",
						(),
						[
							212u8, 185u8, 19u8, 50u8, 250u8, 72u8, 173u8, 50u8, 4u8, 104u8, 161u8,
							249u8, 77u8, 247u8, 204u8, 248u8, 11u8, 18u8, 57u8, 4u8, 82u8, 110u8,
							30u8, 216u8, 16u8, 37u8, 87u8, 67u8, 189u8, 235u8, 214u8, 155u8,
						],
					)
				}
				#[doc = " The Balances pallet example of storing the balance of an account."]
				#[doc = ""]
				#[doc = " # Example"]
				#[doc = ""]
				#[doc = " ```nocompile"]
				#[doc = "  impl pallet_balances::Config for Runtime {"]
				#[doc = "    type AccountStore = StorageMapShim<Self::Account<Runtime>, frame_system::Provider<Runtime>, AccountId, Self::AccountData<Balance>>"]
				#[doc = "  }"]
				#[doc = " ```"]
				#[doc = ""]
				#[doc = " You can also store the balance of an account in the `System` pallet."]
				#[doc = ""]
				#[doc = " # Example"]
				#[doc = ""]
				#[doc = " ```nocompile"]
				#[doc = "  impl pallet_balances::Config for Runtime {"]
				#[doc = "   type AccountStore = System"]
				#[doc = "  }"]
				#[doc = " ```"]
				#[doc = ""]
				#[doc = " But this comes with tradeoffs, storing account balances in the system pallet stores"]
				#[doc = " `frame_system` data alongside the account data contrary to storing account balances in the"]
				#[doc = " `Balances` pallet, which uses a `StorageMap` to store balances data only."]
				#[doc = " NOTE: This is only used in the case that this pallet is used to store balances."]
				pub fn account_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::account::Account,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Account",
						(),
						[
							213u8, 38u8, 200u8, 69u8, 218u8, 0u8, 112u8, 181u8, 160u8, 23u8, 96u8,
							90u8, 3u8, 88u8, 126u8, 22u8, 103u8, 74u8, 64u8, 69u8, 29u8, 247u8,
							18u8, 17u8, 234u8, 143u8, 189u8, 22u8, 247u8, 194u8, 154u8, 249u8,
						],
					)
				}
				#[doc = " The Balances pallet example of storing the balance of an account."]
				#[doc = ""]
				#[doc = " # Example"]
				#[doc = ""]
				#[doc = " ```nocompile"]
				#[doc = "  impl pallet_balances::Config for Runtime {"]
				#[doc = "    type AccountStore = StorageMapShim<Self::Account<Runtime>, frame_system::Provider<Runtime>, AccountId, Self::AccountData<Balance>>"]
				#[doc = "  }"]
				#[doc = " ```"]
				#[doc = ""]
				#[doc = " You can also store the balance of an account in the `System` pallet."]
				#[doc = ""]
				#[doc = " # Example"]
				#[doc = ""]
				#[doc = " ```nocompile"]
				#[doc = "  impl pallet_balances::Config for Runtime {"]
				#[doc = "   type AccountStore = System"]
				#[doc = "  }"]
				#[doc = " ```"]
				#[doc = ""]
				#[doc = " But this comes with tradeoffs, storing account balances in the system pallet stores"]
				#[doc = " `frame_system` data alongside the account data contrary to storing account balances in the"]
				#[doc = " `Balances` pallet, which uses a `StorageMap` to store balances data only."]
				#[doc = " NOTE: This is only used in the case that this pallet is used to store balances."]
				pub fn account(
					&self,
					_0: types::account::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::account::Param0,
					>,
					types::account::Account,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Account",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							213u8, 38u8, 200u8, 69u8, 218u8, 0u8, 112u8, 181u8, 160u8, 23u8, 96u8,
							90u8, 3u8, 88u8, 126u8, 22u8, 103u8, 74u8, 64u8, 69u8, 29u8, 247u8,
							18u8, 17u8, 234u8, 143u8, 189u8, 22u8, 247u8, 194u8, 154u8, 249u8,
						],
					)
				}
				#[doc = " Any liquidity locks on some account balances."]
				#[doc = " NOTE: Should only be accessed when setting, changing and freeing a lock."]
				#[doc = ""]
				#[doc = " Use of locks is deprecated in favour of freezes. See `https://github.com/paritytech/substrate/pull/12951/`"]
				pub fn locks_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::locks::Locks,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Locks",
						(),
						[
							10u8, 223u8, 55u8, 0u8, 249u8, 69u8, 168u8, 41u8, 75u8, 35u8, 120u8,
							167u8, 18u8, 132u8, 9u8, 20u8, 91u8, 51u8, 27u8, 69u8, 136u8, 187u8,
							13u8, 220u8, 163u8, 122u8, 26u8, 141u8, 174u8, 249u8, 85u8, 37u8,
						],
					)
				}
				#[doc = " Any liquidity locks on some account balances."]
				#[doc = " NOTE: Should only be accessed when setting, changing and freeing a lock."]
				#[doc = ""]
				#[doc = " Use of locks is deprecated in favour of freezes. See `https://github.com/paritytech/substrate/pull/12951/`"]
				pub fn locks(
					&self,
					_0: types::locks::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::locks::Param0,
					>,
					types::locks::Locks,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Locks",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							10u8, 223u8, 55u8, 0u8, 249u8, 69u8, 168u8, 41u8, 75u8, 35u8, 120u8,
							167u8, 18u8, 132u8, 9u8, 20u8, 91u8, 51u8, 27u8, 69u8, 136u8, 187u8,
							13u8, 220u8, 163u8, 122u8, 26u8, 141u8, 174u8, 249u8, 85u8, 37u8,
						],
					)
				}
				#[doc = " Named reserves on some account balances."]
				#[doc = ""]
				#[doc = " Use of reserves is deprecated in favour of holds. See `https://github.com/paritytech/substrate/pull/12951/`"]
				pub fn reserves_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::reserves::Reserves,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Reserves",
						(),
						[
							112u8, 10u8, 241u8, 77u8, 64u8, 187u8, 106u8, 159u8, 13u8, 153u8,
							140u8, 178u8, 182u8, 50u8, 1u8, 55u8, 149u8, 92u8, 196u8, 229u8, 170u8,
							106u8, 193u8, 88u8, 255u8, 244u8, 2u8, 193u8, 62u8, 235u8, 204u8, 91u8,
						],
					)
				}
				#[doc = " Named reserves on some account balances."]
				#[doc = ""]
				#[doc = " Use of reserves is deprecated in favour of holds. See `https://github.com/paritytech/substrate/pull/12951/`"]
				pub fn reserves(
					&self,
					_0: types::reserves::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::reserves::Param0,
					>,
					types::reserves::Reserves,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Reserves",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							112u8, 10u8, 241u8, 77u8, 64u8, 187u8, 106u8, 159u8, 13u8, 153u8,
							140u8, 178u8, 182u8, 50u8, 1u8, 55u8, 149u8, 92u8, 196u8, 229u8, 170u8,
							106u8, 193u8, 88u8, 255u8, 244u8, 2u8, 193u8, 62u8, 235u8, 204u8, 91u8,
						],
					)
				}
				#[doc = " Holds on account balances."]
				pub fn holds_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::holds::Holds,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Holds",
						(),
						[
							108u8, 118u8, 163u8, 86u8, 4u8, 174u8, 42u8, 210u8, 139u8, 171u8, 15u8,
							242u8, 10u8, 4u8, 255u8, 205u8, 247u8, 61u8, 236u8, 127u8, 54u8, 175u8,
							182u8, 131u8, 84u8, 129u8, 78u8, 242u8, 92u8, 143u8, 219u8, 35u8,
						],
					)
				}
				#[doc = " Holds on account balances."]
				pub fn holds(
					&self,
					_0: types::holds::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::holds::Param0,
					>,
					types::holds::Holds,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Holds",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							108u8, 118u8, 163u8, 86u8, 4u8, 174u8, 42u8, 210u8, 139u8, 171u8, 15u8,
							242u8, 10u8, 4u8, 255u8, 205u8, 247u8, 61u8, 236u8, 127u8, 54u8, 175u8,
							182u8, 131u8, 84u8, 129u8, 78u8, 242u8, 92u8, 143u8, 219u8, 35u8,
						],
					)
				}
				#[doc = " Freeze locks on account balances."]
				pub fn freezes_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::freezes::Freezes,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Freezes",
						(),
						[
							170u8, 69u8, 116u8, 92u8, 165u8, 14u8, 129u8, 179u8, 165u8, 6u8, 123u8,
							156u8, 4u8, 30u8, 25u8, 181u8, 191u8, 29u8, 3u8, 92u8, 96u8, 167u8,
							102u8, 38u8, 128u8, 140u8, 85u8, 248u8, 114u8, 127u8, 128u8, 40u8,
						],
					)
				}
				#[doc = " Freeze locks on account balances."]
				pub fn freezes(
					&self,
					_0: types::freezes::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::freezes::Param0,
					>,
					types::freezes::Freezes,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"Freezes",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							170u8, 69u8, 116u8, 92u8, 165u8, 14u8, 129u8, 179u8, 165u8, 6u8, 123u8,
							156u8, 4u8, 30u8, 25u8, 181u8, 191u8, 29u8, 3u8, 92u8, 96u8, 167u8,
							102u8, 38u8, 128u8, 140u8, 85u8, 248u8, 114u8, 127u8, 128u8, 40u8,
						],
					)
				}
				#[doc = " Transfer proofs for a wormhole transfers"]
				pub fn transfer_proof_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::transfer_proof::TransferProof,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"TransferProof",
						(),
						[
							210u8, 54u8, 36u8, 79u8, 12u8, 123u8, 227u8, 172u8, 23u8, 232u8, 200u8,
							138u8, 130u8, 99u8, 12u8, 186u8, 77u8, 74u8, 208u8, 111u8, 137u8,
							159u8, 169u8, 112u8, 227u8, 111u8, 65u8, 127u8, 232u8, 57u8, 166u8,
							14u8,
						],
					)
				}
				#[doc = " Transfer proofs for a wormhole transfers"]
				pub fn transfer_proof(
					&self,
					_0: types::transfer_proof::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::transfer_proof::Param0,
					>,
					types::transfer_proof::TransferProof,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"TransferProof",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							210u8, 54u8, 36u8, 79u8, 12u8, 123u8, 227u8, 172u8, 23u8, 232u8, 200u8,
							138u8, 130u8, 99u8, 12u8, 186u8, 77u8, 74u8, 208u8, 111u8, 137u8,
							159u8, 169u8, 112u8, 227u8, 111u8, 65u8, 127u8, 232u8, 57u8, 166u8,
							14u8,
						],
					)
				}
				pub fn transfer_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::transfer_count::TransferCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Balances",
						"TransferCount",
						(),
						[
							105u8, 10u8, 160u8, 118u8, 193u8, 131u8, 207u8, 188u8, 78u8, 238u8,
							252u8, 99u8, 31u8, 72u8, 159u8, 128u8, 159u8, 215u8, 110u8, 101u8,
							27u8, 132u8, 12u8, 59u8, 182u8, 107u8, 98u8, 77u8, 189u8, 100u8, 51u8,
							209u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The minimum amount required to keep an account open. MUST BE GREATER THAN ZERO!"]
				#[doc = ""]
				#[doc = " If you *really* need it to be zero, you can enable the feature `insecure_zero_ed` for"]
				#[doc = " this pallet. However, you do so at your own risk: this will open up a major DoS vector."]
				#[doc = " In case you have multiple sources of provider references, you may also get unexpected"]
				#[doc = " behaviour if you set this to zero."]
				#[doc = ""]
				#[doc = " Bottom line: Do yourself a favour and make it at least one!"]
				pub fn existential_deposit(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Balances",
						"ExistentialDeposit",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " The maximum number of locks that should exist on an account."]
				#[doc = " Not strictly enforced, but used for weight estimation."]
				#[doc = ""]
				#[doc = " Use of locks is deprecated in favour of freezes. See `https://github.com/paritytech/substrate/pull/12951/`"]
				pub fn max_locks(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Balances",
						"MaxLocks",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The maximum number of named reserves that can exist on an account."]
				#[doc = ""]
				#[doc = " Use of reserves is deprecated in favour of holds. See `https://github.com/paritytech/substrate/pull/12951/`"]
				pub fn max_reserves(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Balances",
						"MaxReserves",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The maximum number of individual freeze locks that can exist on an account at any time."]
				pub fn max_freezes(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Balances",
						"MaxFreezes",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
			}
		}
	}
	pub mod transaction_payment {
		use super::{root_mod, runtime_types};
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_transaction_payment::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A transaction fee `actual_fee`, of which `tip` was added to the minimum inclusion fee,"]
			#[doc = "has been paid by `who`."]
			pub struct TransactionFeePaid {
				pub who: transaction_fee_paid::Who,
				pub actual_fee: transaction_fee_paid::ActualFee,
				pub tip: transaction_fee_paid::Tip,
			}
			pub mod transaction_fee_paid {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type ActualFee = ::core::primitive::u128;
				pub type Tip = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TransactionFeePaid {
				const PALLET: &'static str = "TransactionPayment";
				const EVENT: &'static str = "TransactionFeePaid";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod next_fee_multiplier {
					use super::runtime_types;
					pub type NextFeeMultiplier =
						runtime_types::sp_arithmetic::fixed_point::FixedU128;
				}
				pub mod storage_version {
					use super::runtime_types;
					pub type StorageVersion = runtime_types::pallet_transaction_payment::Releases;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				pub fn next_fee_multiplier(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::next_fee_multiplier::NextFeeMultiplier,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TransactionPayment",
						"NextFeeMultiplier",
						(),
						[
							247u8, 39u8, 81u8, 170u8, 225u8, 226u8, 82u8, 147u8, 34u8, 113u8,
							147u8, 213u8, 59u8, 80u8, 139u8, 35u8, 36u8, 196u8, 152u8, 19u8, 9u8,
							159u8, 176u8, 79u8, 249u8, 201u8, 170u8, 1u8, 129u8, 79u8, 146u8,
							197u8,
						],
					)
				}
				pub fn storage_version(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::storage_version::StorageVersion,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TransactionPayment",
						"StorageVersion",
						(),
						[
							105u8, 243u8, 158u8, 241u8, 159u8, 231u8, 253u8, 6u8, 4u8, 32u8, 85u8,
							178u8, 126u8, 31u8, 203u8, 134u8, 154u8, 38u8, 122u8, 155u8, 150u8,
							251u8, 174u8, 15u8, 74u8, 134u8, 216u8, 244u8, 168u8, 175u8, 158u8,
							144u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " A fee multiplier for `Operational` extrinsics to compute \"virtual tip\" to boost their"]
				#[doc = " `priority`"]
				#[doc = ""]
				#[doc = " This value is multiplied by the `final_fee` to obtain a \"virtual tip\" that is later"]
				#[doc = " added to a tip component in regular `priority` calculations."]
				#[doc = " It means that a `Normal` transaction can front-run a similarly-sized `Operational`"]
				#[doc = " extrinsic (with no tip), by including a tip value greater than the virtual tip."]
				#[doc = ""]
				#[doc = " ```rust,ignore"]
				#[doc = " // For `Normal`"]
				#[doc = " let priority = priority_calc(tip);"]
				#[doc = ""]
				#[doc = " // For `Operational`"]
				#[doc = " let virtual_tip = (inclusion_fee + tip) * OperationalFeeMultiplier;"]
				#[doc = " let priority = priority_calc(tip + virtual_tip);"]
				#[doc = " ```"]
				#[doc = ""]
				#[doc = " Note that since we use `final_fee` the multiplier applies also to the regular `tip`"]
				#[doc = " sent with the transaction. So, not only does the transaction get a priority bump based"]
				#[doc = " on the `inclusion_fee`, but we also amplify the impact of tips applied to `Operational`"]
				#[doc = " transactions."]
				pub fn operational_fee_multiplier(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u8,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TransactionPayment",
						"OperationalFeeMultiplier",
						[
							141u8, 130u8, 11u8, 35u8, 226u8, 114u8, 92u8, 179u8, 168u8, 110u8,
							28u8, 91u8, 221u8, 64u8, 4u8, 148u8, 201u8, 193u8, 185u8, 66u8, 226u8,
							114u8, 97u8, 79u8, 62u8, 212u8, 202u8, 114u8, 237u8, 228u8, 183u8,
							165u8,
						],
					)
				}
			}
		}
	}
	pub mod sudo {
		use super::{root_mod, runtime_types};
		#[doc = "Error for the Sudo pallet."]
		pub type Error = runtime_types::pallet_sudo::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_sudo::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Authenticates the sudo key and dispatches a function call with `Root` origin."]
				pub struct Sudo {
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<sudo::Call>,
				}
				pub mod sudo {
					use super::runtime_types;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Sudo {
					const PALLET: &'static str = "Sudo";
					const CALL: &'static str = "sudo";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Authenticates the sudo key and dispatches a function call with `Root` origin."]
				#[doc = "This function does not check the weight of the call, and instead allows the"]
				#[doc = "Sudo user to specify the weight of the call."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				pub struct SudoUncheckedWeight {
					pub call:
						::subxt::ext::subxt_core::alloc::boxed::Box<sudo_unchecked_weight::Call>,
					pub weight: sudo_unchecked_weight::Weight,
				}
				pub mod sudo_unchecked_weight {
					use super::runtime_types;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
					pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SudoUncheckedWeight {
					const PALLET: &'static str = "Sudo";
					const CALL: &'static str = "sudo_unchecked_weight";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Authenticates the current sudo key and sets the given AccountId (`new`) as the new sudo"]
				#[doc = "key."]
				pub struct SetKey {
					pub new: set_key::New,
				}
				pub mod set_key {
					use super::runtime_types;
					pub type New = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetKey {
					const PALLET: &'static str = "Sudo";
					const CALL: &'static str = "set_key";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Authenticates the sudo key and dispatches a function call with `Signed` origin from"]
				#[doc = "a given account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				pub struct SudoAs {
					pub who: sudo_as::Who,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<sudo_as::Call>,
				}
				pub mod sudo_as {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SudoAs {
					const PALLET: &'static str = "Sudo";
					const CALL: &'static str = "sudo_as";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Permanently removes the sudo key."]
				#[doc = ""]
				#[doc = "**This cannot be un-done.**"]
				pub struct RemoveKey;
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveKey {
					const PALLET: &'static str = "Sudo";
					const CALL: &'static str = "remove_key";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Authenticates the sudo key and dispatches a function call with `Root` origin."]
				pub fn sudo(
					&self,
					call: types::sudo::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Sudo> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Sudo",
						"sudo",
						types::Sudo {
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							226u8, 13u8, 120u8, 131u8, 148u8, 75u8, 28u8, 201u8, 23u8, 105u8,
							162u8, 50u8, 130u8, 0u8, 90u8, 154u8, 92u8, 255u8, 56u8, 74u8, 131u8,
							20u8, 147u8, 15u8, 68u8, 25u8, 87u8, 96u8, 82u8, 253u8, 126u8, 137u8,
						],
					)
				}
				#[doc = "Authenticates the sudo key and dispatches a function call with `Root` origin."]
				#[doc = "This function does not check the weight of the call, and instead allows the"]
				#[doc = "Sudo user to specify the weight of the call."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				pub fn sudo_unchecked_weight(
					&self,
					call: types::sudo_unchecked_weight::Call,
					weight: types::sudo_unchecked_weight::Weight,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SudoUncheckedWeight>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Sudo",
						"sudo_unchecked_weight",
						types::SudoUncheckedWeight {
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
							weight,
						},
						[
							3u8, 29u8, 145u8, 217u8, 139u8, 99u8, 189u8, 227u8, 29u8, 208u8, 41u8,
							95u8, 160u8, 161u8, 245u8, 92u8, 8u8, 101u8, 132u8, 102u8, 92u8, 181u8,
							251u8, 214u8, 240u8, 227u8, 0u8, 146u8, 127u8, 251u8, 129u8, 111u8,
						],
					)
				}
				#[doc = "Authenticates the current sudo key and sets the given AccountId (`new`) as the new sudo"]
				#[doc = "key."]
				pub fn set_key(
					&self,
					new: types::set_key::New,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetKey> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Sudo",
						"set_key",
						types::SetKey { new },
						[
							9u8, 73u8, 39u8, 205u8, 188u8, 127u8, 143u8, 54u8, 128u8, 94u8, 8u8,
							227u8, 197u8, 44u8, 70u8, 93u8, 228u8, 196u8, 64u8, 165u8, 226u8,
							158u8, 101u8, 192u8, 22u8, 193u8, 102u8, 84u8, 21u8, 35u8, 92u8, 198u8,
						],
					)
				}
				#[doc = "Authenticates the sudo key and dispatches a function call with `Signed` origin from"]
				#[doc = "a given account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				pub fn sudo_as(
					&self,
					who: types::sudo_as::Who,
					call: types::sudo_as::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SudoAs> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Sudo",
						"sudo_as",
						types::SudoAs {
							who,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							53u8, 107u8, 54u8, 177u8, 231u8, 29u8, 253u8, 33u8, 192u8, 62u8, 101u8,
							94u8, 31u8, 165u8, 94u8, 24u8, 171u8, 201u8, 98u8, 116u8, 183u8, 43u8,
							141u8, 174u8, 30u8, 238u8, 102u8, 185u8, 47u8, 93u8, 21u8, 69u8,
						],
					)
				}
				#[doc = "Permanently removes the sudo key."]
				#[doc = ""]
				#[doc = "**This cannot be un-done.**"]
				pub fn remove_key(
					&self,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveKey> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Sudo",
						"remove_key",
						types::RemoveKey {},
						[
							133u8, 253u8, 54u8, 175u8, 202u8, 239u8, 5u8, 198u8, 180u8, 138u8,
							25u8, 28u8, 109u8, 40u8, 30u8, 56u8, 126u8, 100u8, 52u8, 205u8, 250u8,
							191u8, 61u8, 195u8, 172u8, 142u8, 184u8, 239u8, 247u8, 10u8, 211u8,
							79u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_sudo::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A sudo call just took place."]
			pub struct Sudid {
				pub sudo_result: sudid::SudoResult,
			}
			pub mod sudid {
				use super::runtime_types;
				pub type SudoResult =
					::core::result::Result<(), runtime_types::sp_runtime::DispatchError>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Sudid {
				const PALLET: &'static str = "Sudo";
				const EVENT: &'static str = "Sudid";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The sudo key has been updated."]
			pub struct KeyChanged {
				pub old: key_changed::Old,
				pub new: key_changed::New,
			}
			pub mod key_changed {
				use super::runtime_types;
				pub type Old = ::core::option::Option<::subxt::ext::subxt_core::utils::AccountId32>;
				pub type New = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for KeyChanged {
				const PALLET: &'static str = "Sudo";
				const EVENT: &'static str = "KeyChanged";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The key was permanently removed."]
			pub struct KeyRemoved;
			impl ::subxt::ext::subxt_core::events::StaticEvent for KeyRemoved {
				const PALLET: &'static str = "Sudo";
				const EVENT: &'static str = "KeyRemoved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A [sudo_as](Pallet::sudo_as) call just took place."]
			pub struct SudoAsDone {
				pub sudo_result: sudo_as_done::SudoResult,
			}
			pub mod sudo_as_done {
				use super::runtime_types;
				pub type SudoResult =
					::core::result::Result<(), runtime_types::sp_runtime::DispatchError>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for SudoAsDone {
				const PALLET: &'static str = "Sudo";
				const EVENT: &'static str = "SudoAsDone";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod key {
					use super::runtime_types;
					pub type Key = ::subxt::ext::subxt_core::utils::AccountId32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The `AccountId` of the sudo key."]
				pub fn key(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::key::Key,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Sudo",
						"Key",
						(),
						[
							72u8, 14u8, 225u8, 162u8, 205u8, 247u8, 227u8, 105u8, 116u8, 57u8, 4u8,
							31u8, 84u8, 137u8, 227u8, 228u8, 133u8, 245u8, 206u8, 227u8, 117u8,
							36u8, 252u8, 151u8, 107u8, 15u8, 180u8, 4u8, 4u8, 152u8, 195u8, 144u8,
						],
					)
				}
			}
		}
	}
	pub mod q_po_w {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_qpow::pallet::Error;
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_qpow::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ProofSubmitted {
				pub nonce: proof_submitted::Nonce,
				pub difficulty: proof_submitted::Difficulty,
				pub distance_achieved: proof_submitted::DistanceAchieved,
			}
			pub mod proof_submitted {
				use super::runtime_types;
				pub type Nonce = [::core::primitive::u8; 64usize];
				pub type Difficulty = runtime_types::primitive_types::U512;
				pub type DistanceAchieved = runtime_types::primitive_types::U512;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ProofSubmitted {
				const PALLET: &'static str = "QPoW";
				const EVENT: &'static str = "ProofSubmitted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct DistanceThresholdAdjusted {
				pub old_distance_threshold: distance_threshold_adjusted::OldDistanceThreshold,
				pub new_distance_threshold: distance_threshold_adjusted::NewDistanceThreshold,
				pub observed_block_time: distance_threshold_adjusted::ObservedBlockTime,
			}
			pub mod distance_threshold_adjusted {
				use super::runtime_types;
				pub type OldDistanceThreshold = runtime_types::primitive_types::U512;
				pub type NewDistanceThreshold = runtime_types::primitive_types::U512;
				pub type ObservedBlockTime = ::core::primitive::u64;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DistanceThresholdAdjusted {
				const PALLET: &'static str = "QPoW";
				const EVENT: &'static str = "DistanceThresholdAdjusted";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod block_distance_thresholds {
					use super::runtime_types;
					pub type BlockDistanceThresholds = runtime_types::primitive_types::U512;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod last_block_time {
					use super::runtime_types;
					pub type LastBlockTime = ::core::primitive::u64;
				}
				pub mod last_block_duration {
					use super::runtime_types;
					pub type LastBlockDuration = ::core::primitive::u64;
				}
				pub mod current_distance_threshold {
					use super::runtime_types;
					pub type CurrentDistanceThreshold = runtime_types::primitive_types::U512;
				}
				pub mod total_work {
					use super::runtime_types;
					pub type TotalWork = runtime_types::primitive_types::U512;
				}
				pub mod blocks_in_period {
					use super::runtime_types;
					pub type BlocksInPeriod = ::core::primitive::u32;
				}
				pub mod block_time_history {
					use super::runtime_types;
					pub type BlockTimeHistory = ::core::primitive::u64;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod history_index {
					use super::runtime_types;
					pub type HistoryIndex = ::core::primitive::u32;
				}
				pub mod history_size {
					use super::runtime_types;
					pub type HistorySize = ::core::primitive::u32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				pub fn block_distance_thresholds_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::block_distance_thresholds::BlockDistanceThresholds,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"BlockDistanceThresholds",
						(),
						[
							245u8, 88u8, 219u8, 50u8, 137u8, 246u8, 187u8, 252u8, 181u8, 133u8,
							227u8, 54u8, 166u8, 201u8, 139u8, 81u8, 223u8, 125u8, 243u8, 78u8, 5u8,
							216u8, 42u8, 222u8, 152u8, 140u8, 234u8, 243u8, 47u8, 240u8, 251u8,
							220u8,
						],
					)
				}
				pub fn block_distance_thresholds(
					&self,
					_0: types::block_distance_thresholds::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::block_distance_thresholds::Param0,
					>,
					types::block_distance_thresholds::BlockDistanceThresholds,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"BlockDistanceThresholds",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							245u8, 88u8, 219u8, 50u8, 137u8, 246u8, 187u8, 252u8, 181u8, 133u8,
							227u8, 54u8, 166u8, 201u8, 139u8, 81u8, 223u8, 125u8, 243u8, 78u8, 5u8,
							216u8, 42u8, 222u8, 152u8, 140u8, 234u8, 243u8, 47u8, 240u8, 251u8,
							220u8,
						],
					)
				}
				pub fn last_block_time(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::last_block_time::LastBlockTime,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"LastBlockTime",
						(),
						[
							239u8, 229u8, 252u8, 169u8, 178u8, 1u8, 146u8, 236u8, 50u8, 59u8,
							221u8, 169u8, 107u8, 168u8, 203u8, 103u8, 252u8, 189u8, 52u8, 64u8,
							235u8, 110u8, 164u8, 100u8, 85u8, 66u8, 202u8, 71u8, 189u8, 18u8, 4u8,
							217u8,
						],
					)
				}
				pub fn last_block_duration(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::last_block_duration::LastBlockDuration,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"LastBlockDuration",
						(),
						[
							44u8, 139u8, 180u8, 95u8, 43u8, 58u8, 255u8, 71u8, 201u8, 240u8, 61u8,
							131u8, 214u8, 202u8, 118u8, 157u8, 21u8, 52u8, 154u8, 123u8, 253u8,
							160u8, 68u8, 100u8, 91u8, 196u8, 168u8, 14u8, 84u8, 60u8, 160u8, 229u8,
						],
					)
				}
				pub fn current_distance_threshold(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::current_distance_threshold::CurrentDistanceThreshold,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"CurrentDistanceThreshold",
						(),
						[
							241u8, 84u8, 91u8, 177u8, 115u8, 209u8, 7u8, 88u8, 15u8, 186u8, 180u8,
							244u8, 29u8, 198u8, 42u8, 162u8, 144u8, 70u8, 255u8, 39u8, 235u8,
							121u8, 239u8, 136u8, 137u8, 171u8, 183u8, 245u8, 158u8, 225u8, 244u8,
							147u8,
						],
					)
				}
				pub fn total_work(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::total_work::TotalWork,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"TotalWork",
						(),
						[
							184u8, 29u8, 54u8, 146u8, 220u8, 155u8, 103u8, 67u8, 21u8, 188u8, 53u8,
							160u8, 171u8, 107u8, 52u8, 211u8, 251u8, 52u8, 192u8, 227u8, 150u8,
							156u8, 172u8, 1u8, 233u8, 37u8, 49u8, 13u8, 213u8, 104u8, 10u8, 134u8,
						],
					)
				}
				pub fn blocks_in_period(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::blocks_in_period::BlocksInPeriod,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"BlocksInPeriod",
						(),
						[
							151u8, 58u8, 246u8, 176u8, 204u8, 107u8, 224u8, 209u8, 240u8, 52u8,
							246u8, 45u8, 69u8, 123u8, 23u8, 193u8, 126u8, 200u8, 131u8, 199u8,
							65u8, 39u8, 43u8, 20u8, 18u8, 4u8, 13u8, 120u8, 115u8, 31u8, 204u8,
							134u8,
						],
					)
				}
				pub fn block_time_history_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::block_time_history::BlockTimeHistory,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"BlockTimeHistory",
						(),
						[
							149u8, 198u8, 140u8, 12u8, 144u8, 112u8, 153u8, 141u8, 207u8, 242u8,
							220u8, 87u8, 63u8, 234u8, 158u8, 87u8, 143u8, 186u8, 111u8, 14u8, 94u8,
							134u8, 215u8, 201u8, 141u8, 196u8, 39u8, 107u8, 113u8, 219u8, 41u8,
							58u8,
						],
					)
				}
				pub fn block_time_history(
					&self,
					_0: types::block_time_history::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::block_time_history::Param0,
					>,
					types::block_time_history::BlockTimeHistory,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"BlockTimeHistory",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							149u8, 198u8, 140u8, 12u8, 144u8, 112u8, 153u8, 141u8, 207u8, 242u8,
							220u8, 87u8, 63u8, 234u8, 158u8, 87u8, 143u8, 186u8, 111u8, 14u8, 94u8,
							134u8, 215u8, 201u8, 141u8, 196u8, 39u8, 107u8, 113u8, 219u8, 41u8,
							58u8,
						],
					)
				}
				pub fn history_index(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::history_index::HistoryIndex,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"HistoryIndex",
						(),
						[
							86u8, 246u8, 20u8, 135u8, 119u8, 68u8, 164u8, 167u8, 110u8, 235u8,
							121u8, 151u8, 221u8, 179u8, 25u8, 155u8, 187u8, 30u8, 43u8, 45u8,
							220u8, 156u8, 218u8, 20u8, 78u8, 59u8, 41u8, 144u8, 124u8, 166u8, 84u8,
							149u8,
						],
					)
				}
				pub fn history_size(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::history_size::HistorySize,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"QPoW",
						"HistorySize",
						(),
						[
							77u8, 208u8, 178u8, 115u8, 101u8, 133u8, 140u8, 3u8, 76u8, 240u8,
							162u8, 223u8, 90u8, 131u8, 243u8, 231u8, 54u8, 101u8, 3u8, 25u8, 126u8,
							93u8, 42u8, 4u8, 82u8, 198u8, 226u8, 198u8, 59u8, 74u8, 205u8, 218u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " Pallet's weight info"]
				pub fn initial_distance_threshold_exponent(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"InitialDistanceThresholdExponent",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				pub fn difficulty_adjust_percent_clamp(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u8,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"DifficultyAdjustPercentClamp",
						[
							141u8, 130u8, 11u8, 35u8, 226u8, 114u8, 92u8, 179u8, 168u8, 110u8,
							28u8, 91u8, 221u8, 64u8, 4u8, 148u8, 201u8, 193u8, 185u8, 66u8, 226u8,
							114u8, 97u8, 79u8, 62u8, 212u8, 202u8, 114u8, 237u8, 228u8, 183u8,
							165u8,
						],
					)
				}
				pub fn target_block_time(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u64,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"TargetBlockTime",
						[
							128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8,
							59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8,
							103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8,
							246u8,
						],
					)
				}
				pub fn adjustment_period(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"AdjustmentPeriod",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				pub fn block_time_history_size(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"BlockTimeHistorySize",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				pub fn max_reorg_depth(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"MaxReorgDepth",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Fixed point scale for calculations (default: 10^18)"]
				pub fn fixed_u128_scale(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"FixedU128Scale",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " Maximum distance threshold multiplier (default: 4)"]
				pub fn max_distance_multiplier(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"QPoW",
						"MaxDistanceMultiplier",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
			}
		}
	}
	pub mod wormhole {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_wormhole::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_wormhole::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct VerifyWormholeProof {
					pub proof_bytes: verify_wormhole_proof::ProofBytes,
					pub block_number: verify_wormhole_proof::BlockNumber,
				}
				pub mod verify_wormhole_proof {
					use super::runtime_types;
					pub type ProofBytes =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
					pub type BlockNumber = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for VerifyWormholeProof {
					const PALLET: &'static str = "Wormhole";
					const CALL: &'static str = "verify_wormhole_proof";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				pub fn verify_wormhole_proof(
					&self,
					proof_bytes: types::verify_wormhole_proof::ProofBytes,
					block_number: types::verify_wormhole_proof::BlockNumber,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::VerifyWormholeProof>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Wormhole",
						"verify_wormhole_proof",
						types::VerifyWormholeProof { proof_bytes, block_number },
						[
							243u8, 243u8, 212u8, 153u8, 44u8, 36u8, 106u8, 182u8, 177u8, 104u8,
							202u8, 172u8, 53u8, 111u8, 255u8, 121u8, 131u8, 84u8, 224u8, 250u8,
							104u8, 52u8, 241u8, 228u8, 51u8, 63u8, 233u8, 191u8, 215u8, 100u8,
							166u8, 76u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_wormhole::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ProofVerified {
				pub exit_amount: proof_verified::ExitAmount,
			}
			pub mod proof_verified {
				use super::runtime_types;
				pub type ExitAmount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ProofVerified {
				const PALLET: &'static str = "Wormhole";
				const EVENT: &'static str = "ProofVerified";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod used_nullifiers {
					use super::runtime_types;
					pub type UsedNullifiers = ::core::primitive::bool;
					pub type Param0 = [::core::primitive::u8; 32usize];
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				pub fn used_nullifiers_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::used_nullifiers::UsedNullifiers,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Wormhole",
						"UsedNullifiers",
						(),
						[
							111u8, 222u8, 249u8, 87u8, 31u8, 249u8, 120u8, 32u8, 221u8, 33u8, 86u8,
							103u8, 116u8, 235u8, 16u8, 191u8, 73u8, 183u8, 183u8, 77u8, 229u8,
							255u8, 221u8, 186u8, 29u8, 179u8, 110u8, 138u8, 146u8, 113u8, 241u8,
							222u8,
						],
					)
				}
				pub fn used_nullifiers(
					&self,
					_0: types::used_nullifiers::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::used_nullifiers::Param0,
					>,
					types::used_nullifiers::UsedNullifiers,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Wormhole",
						"UsedNullifiers",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							111u8, 222u8, 249u8, 87u8, 31u8, 249u8, 120u8, 32u8, 221u8, 33u8, 86u8,
							103u8, 116u8, 235u8, 16u8, 191u8, 73u8, 183u8, 183u8, 77u8, 229u8,
							255u8, 221u8, 186u8, 29u8, 179u8, 110u8, 138u8, 146u8, 113u8, 241u8,
							222u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " Account ID used as the \"from\" account when creating transfer proofs for minted tokens"]
				pub fn minting_account(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::subxt::ext::subxt_core::utils::AccountId32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Wormhole",
						"MintingAccount",
						[
							115u8, 233u8, 13u8, 223u8, 88u8, 20u8, 202u8, 139u8, 153u8, 28u8,
							155u8, 157u8, 224u8, 66u8, 3u8, 250u8, 23u8, 53u8, 88u8, 168u8, 211u8,
							204u8, 122u8, 166u8, 248u8, 23u8, 174u8, 225u8, 99u8, 108u8, 89u8,
							135u8,
						],
					)
				}
			}
		}
	}
	pub mod mining_rewards {
		use super::{root_mod, runtime_types};
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_mining_rewards::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A miner has been identified for a block"]
			pub struct MinerRewarded {
				pub miner: miner_rewarded::Miner,
				pub reward: miner_rewarded::Reward,
			}
			pub mod miner_rewarded {
				use super::runtime_types;
				pub type Miner = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Reward = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MinerRewarded {
				const PALLET: &'static str = "MiningRewards";
				const EVENT: &'static str = "MinerRewarded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Transaction fees were collected for later distribution"]
			pub struct FeesCollected {
				pub amount: fees_collected::Amount,
				pub total: fees_collected::Total,
			}
			pub mod fees_collected {
				use super::runtime_types;
				pub type Amount = ::core::primitive::u128;
				pub type Total = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for FeesCollected {
				const PALLET: &'static str = "MiningRewards";
				const EVENT: &'static str = "FeesCollected";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Rewards were sent to Treasury when no miner was specified"]
			pub struct TreasuryRewarded {
				pub reward: treasury_rewarded::Reward,
			}
			pub mod treasury_rewarded {
				use super::runtime_types;
				pub type Reward = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TreasuryRewarded {
				const PALLET: &'static str = "MiningRewards";
				const EVENT: &'static str = "TreasuryRewarded";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod collected_fees {
					use super::runtime_types;
					pub type CollectedFees = ::core::primitive::u128;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				pub fn collected_fees(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::collected_fees::CollectedFees,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MiningRewards",
						"CollectedFees",
						(),
						[
							136u8, 52u8, 218u8, 204u8, 2u8, 250u8, 34u8, 8u8, 16u8, 23u8, 171u8,
							3u8, 253u8, 35u8, 59u8, 7u8, 167u8, 227u8, 86u8, 15u8, 155u8, 14u8,
							139u8, 44u8, 208u8, 108u8, 85u8, 131u8, 170u8, 37u8, 211u8, 211u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The base block reward given to miners"]
				pub fn miner_block_reward(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MiningRewards",
						"MinerBlockReward",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " The base block reward given to treasury"]
				pub fn treasury_block_reward(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MiningRewards",
						"TreasuryBlockReward",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " The treasury pallet ID"]
				pub fn treasury_pallet_id(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::frame_support::PalletId,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MiningRewards",
						"TreasuryPalletId",
						[
							56u8, 243u8, 53u8, 83u8, 154u8, 179u8, 170u8, 80u8, 133u8, 173u8, 61u8,
							161u8, 47u8, 225u8, 146u8, 21u8, 50u8, 229u8, 248u8, 27u8, 104u8, 58u8,
							129u8, 197u8, 102u8, 160u8, 168u8, 205u8, 154u8, 42u8, 217u8, 53u8,
						],
					)
				}
				#[doc = " Account ID used as the \"from\" account when creating transfer proofs for minted tokens"]
				pub fn minting_account(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::subxt::ext::subxt_core::utils::AccountId32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MiningRewards",
						"MintingAccount",
						[
							115u8, 233u8, 13u8, 223u8, 88u8, 20u8, 202u8, 139u8, 153u8, 28u8,
							155u8, 157u8, 224u8, 66u8, 3u8, 250u8, 23u8, 53u8, 88u8, 168u8, 211u8,
							204u8, 122u8, 166u8, 248u8, 23u8, 174u8, 225u8, 99u8, 108u8, 89u8,
							135u8,
						],
					)
				}
			}
		}
	}
	pub mod vesting {
		use super::{root_mod, runtime_types};
		#[doc = "Error for the vesting pallet."]
		pub type Error = runtime_types::pallet_vesting::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_vesting::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Unlock any vested funds of the sender account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and the sender must have funds still"]
				#[doc = "locked under this pallet."]
				#[doc = ""]
				#[doc = "Emits either `VestingCompleted` or `VestingUpdated`."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub struct Vest;
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Vest {
					const PALLET: &'static str = "Vesting";
					const CALL: &'static str = "vest";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Unlock any vested funds of a `target` account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `target`: The account whose vested funds should be unlocked. Must have funds still"]
				#[doc = "locked under this pallet."]
				#[doc = ""]
				#[doc = "Emits either `VestingCompleted` or `VestingUpdated`."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub struct VestOther {
					pub target: vest_other::Target,
				}
				pub mod vest_other {
					use super::runtime_types;
					pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for VestOther {
					const PALLET: &'static str = "Vesting";
					const CALL: &'static str = "vest_other";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Create a vested transfer."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `target`: The account receiving the vested funds."]
				#[doc = "- `schedule`: The vesting schedule attached to the transfer."]
				#[doc = ""]
				#[doc = "Emits `VestingCreated`."]
				#[doc = ""]
				#[doc = "NOTE: This will unlock all schedules through the current block."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub struct VestedTransfer {
					pub target: vested_transfer::Target,
					pub schedule: vested_transfer::Schedule,
				}
				pub mod vested_transfer {
					use super::runtime_types;
					pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Schedule = runtime_types::pallet_vesting::vesting_info::VestingInfo<
						::core::primitive::u128,
						::core::primitive::u32,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for VestedTransfer {
					const PALLET: &'static str = "Vesting";
					const CALL: &'static str = "vested_transfer";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Force a vested transfer."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				#[doc = ""]
				#[doc = "- `source`: The account whose funds should be transferred."]
				#[doc = "- `target`: The account that should be transferred the vested funds."]
				#[doc = "- `schedule`: The vesting schedule attached to the transfer."]
				#[doc = ""]
				#[doc = "Emits `VestingCreated`."]
				#[doc = ""]
				#[doc = "NOTE: This will unlock all schedules through the current block."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub struct ForceVestedTransfer {
					pub source: force_vested_transfer::Source,
					pub target: force_vested_transfer::Target,
					pub schedule: force_vested_transfer::Schedule,
				}
				pub mod force_vested_transfer {
					use super::runtime_types;
					pub type Source = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Schedule = runtime_types::pallet_vesting::vesting_info::VestingInfo<
						::core::primitive::u128,
						::core::primitive::u32,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceVestedTransfer {
					const PALLET: &'static str = "Vesting";
					const CALL: &'static str = "force_vested_transfer";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Merge two vesting schedules together, creating a new vesting schedule that unlocks over"]
				#[doc = "the highest possible start and end blocks. If both schedules have already started the"]
				#[doc = "current block will be used as the schedule start; with the caveat that if one schedule"]
				#[doc = "is finished by the current block, the other will be treated as the new merged schedule,"]
				#[doc = "unmodified."]
				#[doc = ""]
				#[doc = "NOTE: If `schedule1_index == schedule2_index` this is a no-op."]
				#[doc = "NOTE: This will unlock all schedules through the current block prior to merging."]
				#[doc = "NOTE: If both schedules have ended by the current block, no new schedule will be created"]
				#[doc = "and both will be removed."]
				#[doc = ""]
				#[doc = "Merged schedule attributes:"]
				#[doc = "- `starting_block`: `MAX(schedule1.starting_block, scheduled2.starting_block,"]
				#[doc = "  current_block)`."]
				#[doc = "- `ending_block`: `MAX(schedule1.ending_block, schedule2.ending_block)`."]
				#[doc = "- `locked`: `schedule1.locked_at(current_block) + schedule2.locked_at(current_block)`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `schedule1_index`: index of the first schedule to merge."]
				#[doc = "- `schedule2_index`: index of the second schedule to merge."]
				pub struct MergeSchedules {
					pub schedule1_index: merge_schedules::Schedule1Index,
					pub schedule2_index: merge_schedules::Schedule2Index,
				}
				pub mod merge_schedules {
					use super::runtime_types;
					pub type Schedule1Index = ::core::primitive::u32;
					pub type Schedule2Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for MergeSchedules {
					const PALLET: &'static str = "Vesting";
					const CALL: &'static str = "merge_schedules";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Force remove a vesting schedule"]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				#[doc = ""]
				#[doc = "- `target`: An account that has a vesting schedule"]
				#[doc = "- `schedule_index`: The vesting schedule index that should be removed"]
				pub struct ForceRemoveVestingSchedule {
					pub target: force_remove_vesting_schedule::Target,
					pub schedule_index: force_remove_vesting_schedule::ScheduleIndex,
				}
				pub mod force_remove_vesting_schedule {
					use super::runtime_types;
					pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type ScheduleIndex = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceRemoveVestingSchedule {
					const PALLET: &'static str = "Vesting";
					const CALL: &'static str = "force_remove_vesting_schedule";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Unlock any vested funds of the sender account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and the sender must have funds still"]
				#[doc = "locked under this pallet."]
				#[doc = ""]
				#[doc = "Emits either `VestingCompleted` or `VestingUpdated`."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub fn vest(
					&self,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Vest> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Vesting",
						"vest",
						types::Vest {},
						[
							149u8, 89u8, 178u8, 148u8, 127u8, 127u8, 155u8, 60u8, 114u8, 126u8,
							204u8, 123u8, 166u8, 70u8, 104u8, 208u8, 186u8, 69u8, 139u8, 181u8,
							151u8, 154u8, 235u8, 161u8, 191u8, 35u8, 111u8, 60u8, 21u8, 165u8,
							44u8, 122u8,
						],
					)
				}
				#[doc = "Unlock any vested funds of a `target` account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `target`: The account whose vested funds should be unlocked. Must have funds still"]
				#[doc = "locked under this pallet."]
				#[doc = ""]
				#[doc = "Emits either `VestingCompleted` or `VestingUpdated`."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub fn vest_other(
					&self,
					target: types::vest_other::Target,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::VestOther> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Vesting",
						"vest_other",
						types::VestOther { target },
						[
							238u8, 92u8, 25u8, 149u8, 27u8, 211u8, 196u8, 31u8, 211u8, 28u8, 241u8,
							30u8, 128u8, 35u8, 0u8, 227u8, 202u8, 215u8, 186u8, 69u8, 216u8, 110u8,
							199u8, 120u8, 134u8, 141u8, 176u8, 224u8, 234u8, 42u8, 152u8, 128u8,
						],
					)
				}
				#[doc = "Create a vested transfer."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `target`: The account receiving the vested funds."]
				#[doc = "- `schedule`: The vesting schedule attached to the transfer."]
				#[doc = ""]
				#[doc = "Emits `VestingCreated`."]
				#[doc = ""]
				#[doc = "NOTE: This will unlock all schedules through the current block."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub fn vested_transfer(
					&self,
					target: types::vested_transfer::Target,
					schedule: types::vested_transfer::Schedule,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::VestedTransfer>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Vesting",
						"vested_transfer",
						types::VestedTransfer { target, schedule },
						[
							198u8, 133u8, 254u8, 5u8, 22u8, 170u8, 205u8, 79u8, 218u8, 30u8, 81u8,
							207u8, 227u8, 121u8, 132u8, 14u8, 217u8, 43u8, 66u8, 206u8, 15u8, 80u8,
							173u8, 208u8, 128u8, 72u8, 223u8, 175u8, 93u8, 69u8, 128u8, 88u8,
						],
					)
				}
				#[doc = "Force a vested transfer."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				#[doc = ""]
				#[doc = "- `source`: The account whose funds should be transferred."]
				#[doc = "- `target`: The account that should be transferred the vested funds."]
				#[doc = "- `schedule`: The vesting schedule attached to the transfer."]
				#[doc = ""]
				#[doc = "Emits `VestingCreated`."]
				#[doc = ""]
				#[doc = "NOTE: This will unlock all schedules through the current block."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- `O(1)`."]
				pub fn force_vested_transfer(
					&self,
					source: types::force_vested_transfer::Source,
					target: types::force_vested_transfer::Target,
					schedule: types::force_vested_transfer::Schedule,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceVestedTransfer>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Vesting",
						"force_vested_transfer",
						types::ForceVestedTransfer { source, target, schedule },
						[
							112u8, 17u8, 176u8, 133u8, 169u8, 192u8, 155u8, 217u8, 153u8, 36u8,
							230u8, 45u8, 9u8, 192u8, 2u8, 201u8, 165u8, 60u8, 206u8, 226u8, 95u8,
							86u8, 239u8, 196u8, 109u8, 62u8, 224u8, 237u8, 88u8, 74u8, 209u8,
							251u8,
						],
					)
				}
				#[doc = "Merge two vesting schedules together, creating a new vesting schedule that unlocks over"]
				#[doc = "the highest possible start and end blocks. If both schedules have already started the"]
				#[doc = "current block will be used as the schedule start; with the caveat that if one schedule"]
				#[doc = "is finished by the current block, the other will be treated as the new merged schedule,"]
				#[doc = "unmodified."]
				#[doc = ""]
				#[doc = "NOTE: If `schedule1_index == schedule2_index` this is a no-op."]
				#[doc = "NOTE: This will unlock all schedules through the current block prior to merging."]
				#[doc = "NOTE: If both schedules have ended by the current block, no new schedule will be created"]
				#[doc = "and both will be removed."]
				#[doc = ""]
				#[doc = "Merged schedule attributes:"]
				#[doc = "- `starting_block`: `MAX(schedule1.starting_block, scheduled2.starting_block,"]
				#[doc = "  current_block)`."]
				#[doc = "- `ending_block`: `MAX(schedule1.ending_block, schedule2.ending_block)`."]
				#[doc = "- `locked`: `schedule1.locked_at(current_block) + schedule2.locked_at(current_block)`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `schedule1_index`: index of the first schedule to merge."]
				#[doc = "- `schedule2_index`: index of the second schedule to merge."]
				pub fn merge_schedules(
					&self,
					schedule1_index: types::merge_schedules::Schedule1Index,
					schedule2_index: types::merge_schedules::Schedule2Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::MergeSchedules>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Vesting",
						"merge_schedules",
						types::MergeSchedules { schedule1_index, schedule2_index },
						[
							45u8, 24u8, 13u8, 108u8, 26u8, 99u8, 61u8, 117u8, 195u8, 218u8, 182u8,
							23u8, 188u8, 157u8, 181u8, 81u8, 38u8, 136u8, 31u8, 226u8, 8u8, 190u8,
							33u8, 81u8, 86u8, 185u8, 156u8, 77u8, 157u8, 197u8, 41u8, 58u8,
						],
					)
				}
				#[doc = "Force remove a vesting schedule"]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				#[doc = ""]
				#[doc = "- `target`: An account that has a vesting schedule"]
				#[doc = "- `schedule_index`: The vesting schedule index that should be removed"]
				pub fn force_remove_vesting_schedule(
					&self,
					target: types::force_remove_vesting_schedule::Target,
					schedule_index: types::force_remove_vesting_schedule::ScheduleIndex,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::ForceRemoveVestingSchedule,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Vesting",
						"force_remove_vesting_schedule",
						types::ForceRemoveVestingSchedule { target, schedule_index },
						[
							211u8, 253u8, 60u8, 15u8, 20u8, 53u8, 23u8, 13u8, 45u8, 223u8, 136u8,
							183u8, 162u8, 143u8, 196u8, 188u8, 35u8, 64u8, 174u8, 16u8, 47u8, 13u8,
							147u8, 173u8, 120u8, 143u8, 75u8, 89u8, 128u8, 187u8, 9u8, 18u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_vesting::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A vesting schedule has been created."]
			pub struct VestingCreated {
				pub account: vesting_created::Account,
				pub schedule_index: vesting_created::ScheduleIndex,
			}
			pub mod vesting_created {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type ScheduleIndex = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for VestingCreated {
				const PALLET: &'static str = "Vesting";
				const EVENT: &'static str = "VestingCreated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The amount vested has been updated. This could indicate a change in funds available."]
			#[doc = "The balance given is the amount which is left unvested (and thus locked)."]
			pub struct VestingUpdated {
				pub account: vesting_updated::Account,
				pub unvested: vesting_updated::Unvested,
			}
			pub mod vesting_updated {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Unvested = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for VestingUpdated {
				const PALLET: &'static str = "Vesting";
				const EVENT: &'static str = "VestingUpdated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An \\[account\\] has become fully vested."]
			pub struct VestingCompleted {
				pub account: vesting_completed::Account,
			}
			pub mod vesting_completed {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for VestingCompleted {
				const PALLET: &'static str = "Vesting";
				const EVENT: &'static str = "VestingCompleted";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod vesting {
					use super::runtime_types;
					pub type Vesting = runtime_types::bounded_collections::bounded_vec::BoundedVec<
						runtime_types::pallet_vesting::vesting_info::VestingInfo<
							::core::primitive::u128,
							::core::primitive::u32,
						>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod storage_version {
					use super::runtime_types;
					pub type StorageVersion = runtime_types::pallet_vesting::Releases;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " Information regarding the vesting of a given account."]
				pub fn vesting_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::vesting::Vesting,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Vesting",
						"Vesting",
						(),
						[
							95u8, 168u8, 217u8, 248u8, 149u8, 86u8, 195u8, 93u8, 73u8, 206u8,
							105u8, 165u8, 33u8, 173u8, 232u8, 81u8, 147u8, 254u8, 50u8, 228u8,
							156u8, 92u8, 242u8, 149u8, 42u8, 91u8, 58u8, 209u8, 142u8, 221u8,
							230u8, 112u8,
						],
					)
				}
				#[doc = " Information regarding the vesting of a given account."]
				pub fn vesting(
					&self,
					_0: types::vesting::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::vesting::Param0,
					>,
					types::vesting::Vesting,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Vesting",
						"Vesting",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							95u8, 168u8, 217u8, 248u8, 149u8, 86u8, 195u8, 93u8, 73u8, 206u8,
							105u8, 165u8, 33u8, 173u8, 232u8, 81u8, 147u8, 254u8, 50u8, 228u8,
							156u8, 92u8, 242u8, 149u8, 42u8, 91u8, 58u8, 209u8, 142u8, 221u8,
							230u8, 112u8,
						],
					)
				}
				#[doc = " Storage version of the pallet."]
				#[doc = ""]
				#[doc = " New networks start with latest version, as determined by the genesis build."]
				pub fn storage_version(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::storage_version::StorageVersion,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Vesting",
						"StorageVersion",
						(),
						[
							230u8, 137u8, 180u8, 133u8, 142u8, 124u8, 231u8, 234u8, 223u8, 10u8,
							154u8, 98u8, 158u8, 253u8, 228u8, 80u8, 5u8, 9u8, 91u8, 210u8, 252u8,
							9u8, 13u8, 195u8, 193u8, 164u8, 129u8, 113u8, 128u8, 218u8, 8u8, 40u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The minimum amount transferred to call `vested_transfer`."]
				pub fn min_vested_transfer(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Vesting",
						"MinVestedTransfer",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				pub fn max_vesting_schedules(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Vesting",
						"MaxVestingSchedules",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
			}
		}
	}
	pub mod preimage {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_preimage::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_preimage::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Register a preimage on-chain."]
				#[doc = ""]
				#[doc = "If the preimage was previously requested, no fees or deposits are taken for providing"]
				#[doc = "the preimage. Otherwise, a deposit is taken proportional to the size of the preimage."]
				pub struct NotePreimage {
					pub bytes: note_preimage::Bytes,
				}
				pub mod note_preimage {
					use super::runtime_types;
					pub type Bytes =
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for NotePreimage {
					const PALLET: &'static str = "Preimage";
					const CALL: &'static str = "note_preimage";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Clear an unrequested preimage from the runtime storage."]
				#[doc = ""]
				#[doc = "If `len` is provided, then it will be a much cheaper operation."]
				#[doc = ""]
				#[doc = "- `hash`: The hash of the preimage to be removed from the store."]
				#[doc = "- `len`: The length of the preimage of `hash`."]
				pub struct UnnotePreimage {
					pub hash: unnote_preimage::Hash,
				}
				pub mod unnote_preimage {
					use super::runtime_types;
					pub type Hash = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UnnotePreimage {
					const PALLET: &'static str = "Preimage";
					const CALL: &'static str = "unnote_preimage";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Request a preimage be uploaded to the chain without paying any fees or deposits."]
				#[doc = ""]
				#[doc = "If the preimage requests has already been provided on-chain, we unreserve any deposit"]
				#[doc = "a user may have paid, and take the control of the preimage out of their hands."]
				pub struct RequestPreimage {
					pub hash: request_preimage::Hash,
				}
				pub mod request_preimage {
					use super::runtime_types;
					pub type Hash = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RequestPreimage {
					const PALLET: &'static str = "Preimage";
					const CALL: &'static str = "request_preimage";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Clear a previously made request for a preimage."]
				#[doc = ""]
				#[doc = "NOTE: THIS MUST NOT BE CALLED ON `hash` MORE TIMES THAN `request_preimage`."]
				pub struct UnrequestPreimage {
					pub hash: unrequest_preimage::Hash,
				}
				pub mod unrequest_preimage {
					use super::runtime_types;
					pub type Hash = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for UnrequestPreimage {
					const PALLET: &'static str = "Preimage";
					const CALL: &'static str = "unrequest_preimage";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Ensure that the bulk of pre-images is upgraded."]
				#[doc = ""]
				#[doc = "The caller pays no fee if at least 90% of pre-images were successfully updated."]
				pub struct EnsureUpdated {
					pub hashes: ensure_updated::Hashes,
				}
				pub mod ensure_updated {
					use super::runtime_types;
					pub type Hashes = ::subxt::ext::subxt_core::alloc::vec::Vec<
						::subxt::ext::subxt_core::utils::H256,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for EnsureUpdated {
					const PALLET: &'static str = "Preimage";
					const CALL: &'static str = "ensure_updated";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Register a preimage on-chain."]
				#[doc = ""]
				#[doc = "If the preimage was previously requested, no fees or deposits are taken for providing"]
				#[doc = "the preimage. Otherwise, a deposit is taken proportional to the size of the preimage."]
				pub fn note_preimage(
					&self,
					bytes: types::note_preimage::Bytes,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::NotePreimage> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Preimage",
						"note_preimage",
						types::NotePreimage { bytes },
						[
							121u8, 88u8, 18u8, 92u8, 176u8, 15u8, 192u8, 198u8, 146u8, 198u8, 38u8,
							242u8, 213u8, 83u8, 7u8, 230u8, 14u8, 110u8, 235u8, 32u8, 215u8, 26u8,
							192u8, 217u8, 113u8, 224u8, 206u8, 96u8, 177u8, 198u8, 246u8, 33u8,
						],
					)
				}
				#[doc = "Clear an unrequested preimage from the runtime storage."]
				#[doc = ""]
				#[doc = "If `len` is provided, then it will be a much cheaper operation."]
				#[doc = ""]
				#[doc = "- `hash`: The hash of the preimage to be removed from the store."]
				#[doc = "- `len`: The length of the preimage of `hash`."]
				pub fn unnote_preimage(
					&self,
					hash: types::unnote_preimage::Hash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UnnotePreimage>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Preimage",
						"unnote_preimage",
						types::UnnotePreimage { hash },
						[
							188u8, 116u8, 222u8, 22u8, 127u8, 215u8, 2u8, 133u8, 96u8, 202u8,
							190u8, 123u8, 203u8, 43u8, 200u8, 161u8, 226u8, 24u8, 49u8, 36u8,
							221u8, 160u8, 130u8, 119u8, 30u8, 138u8, 144u8, 85u8, 5u8, 164u8,
							252u8, 222u8,
						],
					)
				}
				#[doc = "Request a preimage be uploaded to the chain without paying any fees or deposits."]
				#[doc = ""]
				#[doc = "If the preimage requests has already been provided on-chain, we unreserve any deposit"]
				#[doc = "a user may have paid, and take the control of the preimage out of their hands."]
				pub fn request_preimage(
					&self,
					hash: types::request_preimage::Hash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RequestPreimage>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Preimage",
						"request_preimage",
						types::RequestPreimage { hash },
						[
							87u8, 0u8, 204u8, 111u8, 43u8, 115u8, 64u8, 209u8, 133u8, 13u8, 83u8,
							45u8, 164u8, 166u8, 233u8, 105u8, 242u8, 238u8, 235u8, 208u8, 113u8,
							134u8, 93u8, 242u8, 86u8, 32u8, 7u8, 152u8, 107u8, 208u8, 79u8, 59u8,
						],
					)
				}
				#[doc = "Clear a previously made request for a preimage."]
				#[doc = ""]
				#[doc = "NOTE: THIS MUST NOT BE CALLED ON `hash` MORE TIMES THAN `request_preimage`."]
				pub fn unrequest_preimage(
					&self,
					hash: types::unrequest_preimage::Hash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::UnrequestPreimage>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Preimage",
						"unrequest_preimage",
						types::UnrequestPreimage { hash },
						[
							55u8, 37u8, 224u8, 149u8, 142u8, 120u8, 8u8, 68u8, 183u8, 225u8, 255u8,
							240u8, 254u8, 111u8, 58u8, 200u8, 113u8, 217u8, 177u8, 203u8, 107u8,
							104u8, 233u8, 87u8, 252u8, 53u8, 33u8, 112u8, 116u8, 254u8, 117u8,
							134u8,
						],
					)
				}
				#[doc = "Ensure that the bulk of pre-images is upgraded."]
				#[doc = ""]
				#[doc = "The caller pays no fee if at least 90% of pre-images were successfully updated."]
				pub fn ensure_updated(
					&self,
					hashes: types::ensure_updated::Hashes,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::EnsureUpdated>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Preimage",
						"ensure_updated",
						types::EnsureUpdated { hashes },
						[
							254u8, 228u8, 88u8, 44u8, 126u8, 235u8, 188u8, 153u8, 61u8, 27u8,
							103u8, 253u8, 163u8, 161u8, 113u8, 243u8, 87u8, 136u8, 2u8, 231u8,
							209u8, 188u8, 215u8, 106u8, 192u8, 225u8, 75u8, 125u8, 224u8, 96u8,
							221u8, 90u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_preimage::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A preimage has been noted."]
			pub struct Noted {
				pub hash: noted::Hash,
			}
			pub mod noted {
				use super::runtime_types;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Noted {
				const PALLET: &'static str = "Preimage";
				const EVENT: &'static str = "Noted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A preimage has been requested."]
			pub struct Requested {
				pub hash: requested::Hash,
			}
			pub mod requested {
				use super::runtime_types;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Requested {
				const PALLET: &'static str = "Preimage";
				const EVENT: &'static str = "Requested";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A preimage has ben cleared."]
			pub struct Cleared {
				pub hash: cleared::Hash,
			}
			pub mod cleared {
				use super::runtime_types;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Cleared {
				const PALLET: &'static str = "Preimage";
				const EVENT: &'static str = "Cleared";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod status_for {
					use super::runtime_types;
					pub type StatusFor = runtime_types::pallet_preimage::OldRequestStatus<
						::subxt::ext::subxt_core::utils::AccountId32,
						::core::primitive::u128,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::H256;
				}
				pub mod request_status_for {
					use super::runtime_types;
					pub type RequestStatusFor = runtime_types::pallet_preimage::RequestStatus<
						::subxt::ext::subxt_core::utils::AccountId32,
						runtime_types::quantus_runtime::governance::definitions::PreimageDeposit,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::H256;
				}
				pub mod preimage_for {
					use super::runtime_types;
					pub type PreimageFor =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::core::primitive::u8,
						>;
					pub type Param0 =
						(::subxt::ext::subxt_core::utils::H256, ::core::primitive::u32);
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The request status of a given hash."]
				pub fn status_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::status_for::StatusFor,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Preimage",
						"StatusFor",
						(),
						[
							187u8, 100u8, 54u8, 112u8, 96u8, 129u8, 36u8, 149u8, 127u8, 226u8,
							126u8, 171u8, 72u8, 189u8, 59u8, 126u8, 204u8, 125u8, 67u8, 204u8,
							231u8, 6u8, 212u8, 135u8, 166u8, 252u8, 5u8, 46u8, 111u8, 120u8, 54u8,
							209u8,
						],
					)
				}
				#[doc = " The request status of a given hash."]
				pub fn status_for(
					&self,
					_0: types::status_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::status_for::Param0,
					>,
					types::status_for::StatusFor,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Preimage",
						"StatusFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							187u8, 100u8, 54u8, 112u8, 96u8, 129u8, 36u8, 149u8, 127u8, 226u8,
							126u8, 171u8, 72u8, 189u8, 59u8, 126u8, 204u8, 125u8, 67u8, 204u8,
							231u8, 6u8, 212u8, 135u8, 166u8, 252u8, 5u8, 46u8, 111u8, 120u8, 54u8,
							209u8,
						],
					)
				}
				#[doc = " The request status of a given hash."]
				pub fn request_status_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::request_status_for::RequestStatusFor,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Preimage",
						"RequestStatusFor",
						(),
						[
							113u8, 195u8, 77u8, 23u8, 125u8, 170u8, 77u8, 145u8, 201u8, 168u8,
							39u8, 13u8, 143u8, 50u8, 100u8, 92u8, 25u8, 110u8, 125u8, 20u8, 96u8,
							156u8, 225u8, 200u8, 57u8, 199u8, 226u8, 242u8, 230u8, 126u8, 138u8,
							123u8,
						],
					)
				}
				#[doc = " The request status of a given hash."]
				pub fn request_status_for(
					&self,
					_0: types::request_status_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::request_status_for::Param0,
					>,
					types::request_status_for::RequestStatusFor,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Preimage",
						"RequestStatusFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							113u8, 195u8, 77u8, 23u8, 125u8, 170u8, 77u8, 145u8, 201u8, 168u8,
							39u8, 13u8, 143u8, 50u8, 100u8, 92u8, 25u8, 110u8, 125u8, 20u8, 96u8,
							156u8, 225u8, 200u8, 57u8, 199u8, 226u8, 242u8, 230u8, 126u8, 138u8,
							123u8,
						],
					)
				}
				pub fn preimage_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::preimage_for::PreimageFor,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Preimage",
						"PreimageFor",
						(),
						[
							106u8, 5u8, 17u8, 46u8, 6u8, 184u8, 177u8, 113u8, 169u8, 34u8, 119u8,
							141u8, 117u8, 40u8, 30u8, 94u8, 187u8, 35u8, 206u8, 216u8, 143u8,
							208u8, 49u8, 156u8, 200u8, 255u8, 109u8, 200u8, 210u8, 134u8, 24u8,
							139u8,
						],
					)
				}
				pub fn preimage_for(
					&self,
					_0: types::preimage_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::preimage_for::Param0,
					>,
					types::preimage_for::PreimageFor,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Preimage",
						"PreimageFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							106u8, 5u8, 17u8, 46u8, 6u8, 184u8, 177u8, 113u8, 169u8, 34u8, 119u8,
							141u8, 117u8, 40u8, 30u8, 94u8, 187u8, 35u8, 206u8, 216u8, 143u8,
							208u8, 49u8, 156u8, 200u8, 255u8, 109u8, 200u8, 210u8, 134u8, 24u8,
							139u8,
						],
					)
				}
			}
		}
	}
	pub mod scheduler {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_scheduler::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_scheduler::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Anonymously schedule a task."]
				pub struct Schedule {
					pub when: schedule::When,
					pub maybe_periodic: schedule::MaybePeriodic,
					pub priority: schedule::Priority,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<schedule::Call>,
				}
				pub mod schedule {
					use super::runtime_types;
					pub type When = ::core::primitive::u32;
					pub type MaybePeriodic = ::core::option::Option<(
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					)>;
					pub type Priority = ::core::primitive::u8;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Schedule {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "schedule";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel an anonymously scheduled task."]
				pub struct Cancel {
					pub when: cancel::When,
					pub index: cancel::Index,
				}
				pub mod cancel {
					use super::runtime_types;
					pub type When = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Cancel {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "cancel";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Schedule a named task."]
				pub struct ScheduleNamed {
					pub id: schedule_named::Id,
					pub when: schedule_named::When,
					pub maybe_periodic: schedule_named::MaybePeriodic,
					pub priority: schedule_named::Priority,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<schedule_named::Call>,
				}
				pub mod schedule_named {
					use super::runtime_types;
					pub type Id = [::core::primitive::u8; 32usize];
					pub type When = ::core::primitive::u32;
					pub type MaybePeriodic = ::core::option::Option<(
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					)>;
					pub type Priority = ::core::primitive::u8;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ScheduleNamed {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "schedule_named";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel a named scheduled task."]
				pub struct CancelNamed {
					pub id: cancel_named::Id,
				}
				pub mod cancel_named {
					use super::runtime_types;
					pub type Id = [::core::primitive::u8; 32usize];
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CancelNamed {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "cancel_named";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Anonymously schedule a task after a delay."]
				pub struct ScheduleAfter {
					pub after: schedule_after::After,
					pub maybe_periodic: schedule_after::MaybePeriodic,
					pub priority: schedule_after::Priority,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<schedule_after::Call>,
				}
				pub mod schedule_after {
					use super::runtime_types;
					pub type After = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
					pub type MaybePeriodic = ::core::option::Option<(
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					)>;
					pub type Priority = ::core::primitive::u8;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ScheduleAfter {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "schedule_after";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Schedule a named task after a delay."]
				pub struct ScheduleNamedAfter {
					pub id: schedule_named_after::Id,
					pub after: schedule_named_after::After,
					pub maybe_periodic: schedule_named_after::MaybePeriodic,
					pub priority: schedule_named_after::Priority,
					pub call:
						::subxt::ext::subxt_core::alloc::boxed::Box<schedule_named_after::Call>,
				}
				pub mod schedule_named_after {
					use super::runtime_types;
					pub type Id = [::core::primitive::u8; 32usize];
					pub type After = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
					pub type MaybePeriodic = ::core::option::Option<(
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					)>;
					pub type Priority = ::core::primitive::u8;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ScheduleNamedAfter {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "schedule_named_after";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set a retry configuration for a task so that, in case its scheduled run fails, it will"]
				#[doc = "be retried after `period` blocks, for a total amount of `retries` retries or until it"]
				#[doc = "succeeds."]
				#[doc = ""]
				#[doc = "Tasks which need to be scheduled for a retry are still subject to weight metering and"]
				#[doc = "agenda space, same as a regular task. If a periodic task fails, it will be scheduled"]
				#[doc = "normally while the task is retrying."]
				#[doc = ""]
				#[doc = "Tasks scheduled as a result of a retry for a periodic task are unnamed, non-periodic"]
				#[doc = "clones of the original task. Their retry configuration will be derived from the"]
				#[doc = "original task's configuration, but will have a lower value for `remaining` than the"]
				#[doc = "original `total_retries`."]
				pub struct SetRetry {
					pub task: set_retry::Task,
					pub retries: set_retry::Retries,
					pub period: set_retry::Period,
				}
				pub mod set_retry {
					use super::runtime_types;
					pub type Task = (
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					);
					pub type Retries = ::core::primitive::u8;
					pub type Period = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetRetry {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "set_retry";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set a retry configuration for a named task so that, in case its scheduled run fails, it"]
				#[doc = "will be retried after `period` blocks, for a total amount of `retries` retries or until"]
				#[doc = "it succeeds."]
				#[doc = ""]
				#[doc = "Tasks which need to be scheduled for a retry are still subject to weight metering and"]
				#[doc = "agenda space, same as a regular task. If a periodic task fails, it will be scheduled"]
				#[doc = "normally while the task is retrying."]
				#[doc = ""]
				#[doc = "Tasks scheduled as a result of a retry for a periodic task are unnamed, non-periodic"]
				#[doc = "clones of the original task. Their retry configuration will be derived from the"]
				#[doc = "original task's configuration, but will have a lower value for `remaining` than the"]
				#[doc = "original `total_retries`."]
				pub struct SetRetryNamed {
					pub id: set_retry_named::Id,
					pub retries: set_retry_named::Retries,
					pub period: set_retry_named::Period,
				}
				pub mod set_retry_named {
					use super::runtime_types;
					pub type Id = [::core::primitive::u8; 32usize];
					pub type Retries = ::core::primitive::u8;
					pub type Period = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetRetryNamed {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "set_retry_named";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Removes the retry configuration of a task."]
				pub struct CancelRetry {
					pub task: cancel_retry::Task,
				}
				pub mod cancel_retry {
					use super::runtime_types;
					pub type Task = (
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					);
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CancelRetry {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "cancel_retry";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel the retry configuration of a named task."]
				pub struct CancelRetryNamed {
					pub id: cancel_retry_named::Id,
				}
				pub mod cancel_retry_named {
					use super::runtime_types;
					pub type Id = [::core::primitive::u8; 32usize];
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CancelRetryNamed {
					const PALLET: &'static str = "Scheduler";
					const CALL: &'static str = "cancel_retry_named";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Anonymously schedule a task."]
				pub fn schedule(
					&self,
					when: types::schedule::When,
					maybe_periodic: types::schedule::MaybePeriodic,
					priority: types::schedule::Priority,
					call: types::schedule::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Schedule> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"schedule",
						types::Schedule {
							when,
							maybe_periodic,
							priority,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							194u8, 5u8, 9u8, 214u8, 152u8, 152u8, 73u8, 196u8, 61u8, 76u8, 101u8,
							85u8, 216u8, 10u8, 40u8, 112u8, 113u8, 29u8, 48u8, 3u8, 202u8, 8u8,
							201u8, 182u8, 110u8, 160u8, 146u8, 148u8, 162u8, 144u8, 11u8, 113u8,
						],
					)
				}
				#[doc = "Cancel an anonymously scheduled task."]
				pub fn cancel(
					&self,
					when: types::cancel::When,
					index: types::cancel::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Cancel> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"cancel",
						types::Cancel { when, index },
						[
							134u8, 77u8, 15u8, 56u8, 137u8, 12u8, 58u8, 147u8, 164u8, 204u8, 221u8,
							150u8, 103u8, 42u8, 36u8, 79u8, 146u8, 115u8, 13u8, 194u8, 39u8, 73u8,
							109u8, 10u8, 168u8, 164u8, 190u8, 173u8, 30u8, 17u8, 35u8, 17u8,
						],
					)
				}
				#[doc = "Schedule a named task."]
				pub fn schedule_named(
					&self,
					id: types::schedule_named::Id,
					when: types::schedule_named::When,
					maybe_periodic: types::schedule_named::MaybePeriodic,
					priority: types::schedule_named::Priority,
					call: types::schedule_named::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ScheduleNamed>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"schedule_named",
						types::ScheduleNamed {
							id,
							when,
							maybe_periodic,
							priority,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							206u8, 123u8, 136u8, 68u8, 23u8, 17u8, 237u8, 5u8, 64u8, 1u8, 217u8,
							33u8, 184u8, 27u8, 210u8, 126u8, 141u8, 227u8, 187u8, 47u8, 203u8,
							113u8, 212u8, 127u8, 46u8, 176u8, 117u8, 103u8, 213u8, 237u8, 121u8,
							187u8,
						],
					)
				}
				#[doc = "Cancel a named scheduled task."]
				pub fn cancel_named(
					&self,
					id: types::cancel_named::Id,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CancelNamed> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"cancel_named",
						types::CancelNamed { id },
						[
							205u8, 35u8, 28u8, 57u8, 224u8, 7u8, 49u8, 233u8, 236u8, 163u8, 93u8,
							236u8, 103u8, 69u8, 65u8, 51u8, 121u8, 84u8, 9u8, 196u8, 147u8, 122u8,
							227u8, 200u8, 181u8, 233u8, 62u8, 240u8, 174u8, 83u8, 129u8, 193u8,
						],
					)
				}
				#[doc = "Anonymously schedule a task after a delay."]
				pub fn schedule_after(
					&self,
					after: types::schedule_after::After,
					maybe_periodic: types::schedule_after::MaybePeriodic,
					priority: types::schedule_after::Priority,
					call: types::schedule_after::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ScheduleAfter>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"schedule_after",
						types::ScheduleAfter {
							after,
							maybe_periodic,
							priority,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							50u8, 250u8, 128u8, 55u8, 8u8, 69u8, 136u8, 110u8, 240u8, 28u8, 34u8,
							118u8, 216u8, 6u8, 17u8, 200u8, 242u8, 75u8, 59u8, 174u8, 223u8, 131u8,
							81u8, 31u8, 173u8, 106u8, 110u8, 100u8, 102u8, 177u8, 4u8, 171u8,
						],
					)
				}
				#[doc = "Schedule a named task after a delay."]
				pub fn schedule_named_after(
					&self,
					id: types::schedule_named_after::Id,
					after: types::schedule_named_after::After,
					maybe_periodic: types::schedule_named_after::MaybePeriodic,
					priority: types::schedule_named_after::Priority,
					call: types::schedule_named_after::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ScheduleNamedAfter>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"schedule_named_after",
						types::ScheduleNamedAfter {
							id,
							after,
							maybe_periodic,
							priority,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							87u8, 169u8, 152u8, 52u8, 117u8, 15u8, 166u8, 36u8, 128u8, 119u8,
							111u8, 113u8, 199u8, 89u8, 186u8, 195u8, 212u8, 14u8, 78u8, 238u8,
							48u8, 143u8, 82u8, 183u8, 215u8, 71u8, 63u8, 225u8, 103u8, 235u8,
							247u8, 151u8,
						],
					)
				}
				#[doc = "Set a retry configuration for a task so that, in case its scheduled run fails, it will"]
				#[doc = "be retried after `period` blocks, for a total amount of `retries` retries or until it"]
				#[doc = "succeeds."]
				#[doc = ""]
				#[doc = "Tasks which need to be scheduled for a retry are still subject to weight metering and"]
				#[doc = "agenda space, same as a regular task. If a periodic task fails, it will be scheduled"]
				#[doc = "normally while the task is retrying."]
				#[doc = ""]
				#[doc = "Tasks scheduled as a result of a retry for a periodic task are unnamed, non-periodic"]
				#[doc = "clones of the original task. Their retry configuration will be derived from the"]
				#[doc = "original task's configuration, but will have a lower value for `remaining` than the"]
				#[doc = "original `total_retries`."]
				pub fn set_retry(
					&self,
					task: types::set_retry::Task,
					retries: types::set_retry::Retries,
					period: types::set_retry::Period,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetRetry> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"set_retry",
						types::SetRetry { task, retries, period },
						[
							31u8, 128u8, 255u8, 13u8, 13u8, 252u8, 74u8, 151u8, 60u8, 242u8, 152u8,
							58u8, 190u8, 155u8, 132u8, 65u8, 139u8, 208u8, 222u8, 175u8, 89u8,
							222u8, 186u8, 98u8, 53u8, 125u8, 71u8, 55u8, 95u8, 2u8, 76u8, 248u8,
						],
					)
				}
				#[doc = "Set a retry configuration for a named task so that, in case its scheduled run fails, it"]
				#[doc = "will be retried after `period` blocks, for a total amount of `retries` retries or until"]
				#[doc = "it succeeds."]
				#[doc = ""]
				#[doc = "Tasks which need to be scheduled for a retry are still subject to weight metering and"]
				#[doc = "agenda space, same as a regular task. If a periodic task fails, it will be scheduled"]
				#[doc = "normally while the task is retrying."]
				#[doc = ""]
				#[doc = "Tasks scheduled as a result of a retry for a periodic task are unnamed, non-periodic"]
				#[doc = "clones of the original task. Their retry configuration will be derived from the"]
				#[doc = "original task's configuration, but will have a lower value for `remaining` than the"]
				#[doc = "original `total_retries`."]
				pub fn set_retry_named(
					&self,
					id: types::set_retry_named::Id,
					retries: types::set_retry_named::Retries,
					period: types::set_retry_named::Period,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetRetryNamed>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"set_retry_named",
						types::SetRetryNamed { id, retries, period },
						[
							102u8, 70u8, 114u8, 48u8, 180u8, 194u8, 107u8, 81u8, 104u8, 117u8,
							33u8, 169u8, 43u8, 172u8, 61u8, 129u8, 143u8, 221u8, 44u8, 101u8,
							235u8, 228u8, 224u8, 71u8, 65u8, 223u8, 180u8, 130u8, 83u8, 89u8,
							157u8, 75u8,
						],
					)
				}
				#[doc = "Removes the retry configuration of a task."]
				pub fn cancel_retry(
					&self,
					task: types::cancel_retry::Task,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CancelRetry> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"cancel_retry",
						types::CancelRetry { task },
						[
							153u8, 252u8, 168u8, 142u8, 100u8, 114u8, 25u8, 46u8, 225u8, 95u8,
							243u8, 78u8, 160u8, 175u8, 17u8, 33u8, 27u8, 241u8, 149u8, 187u8,
							228u8, 182u8, 233u8, 74u8, 10u8, 228u8, 117u8, 218u8, 210u8, 127u8,
							245u8, 105u8,
						],
					)
				}
				#[doc = "Cancel the retry configuration of a named task."]
				pub fn cancel_retry_named(
					&self,
					id: types::cancel_retry_named::Id,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CancelRetryNamed>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Scheduler",
						"cancel_retry_named",
						types::CancelRetryNamed { id },
						[
							76u8, 157u8, 253u8, 113u8, 162u8, 54u8, 98u8, 21u8, 62u8, 44u8, 155u8,
							202u8, 2u8, 28u8, 153u8, 219u8, 67u8, 166u8, 206u8, 79u8, 139u8, 3u8,
							119u8, 182u8, 254u8, 134u8, 143u8, 121u8, 155u8, 220u8, 192u8, 209u8,
						],
					)
				}
			}
		}
		#[doc = "Events type."]
		pub type Event = runtime_types::pallet_scheduler::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Scheduled some task."]
			pub struct Scheduled {
				pub when: scheduled::When,
				pub index: scheduled::Index,
			}
			pub mod scheduled {
				use super::runtime_types;
				pub type When = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
					::core::primitive::u32,
					::core::primitive::u64,
				>;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Scheduled {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "Scheduled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Canceled some task."]
			pub struct Canceled {
				pub when: canceled::When,
				pub index: canceled::Index,
			}
			pub mod canceled {
				use super::runtime_types;
				pub type When = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
					::core::primitive::u32,
					::core::primitive::u64,
				>;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Canceled {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "Canceled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Dispatched some task."]
			pub struct Dispatched {
				pub task: dispatched::Task,
				pub id: dispatched::Id,
				pub result: dispatched::Result,
			}
			pub mod dispatched {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
				pub type Result =
					::core::result::Result<(), runtime_types::sp_runtime::DispatchError>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Dispatched {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "Dispatched";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Set a retry configuration for some task."]
			pub struct RetrySet {
				pub task: retry_set::Task,
				pub id: retry_set::Id,
				pub period: retry_set::Period,
				pub retries: retry_set::Retries,
			}
			pub mod retry_set {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
				pub type Period = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
					::core::primitive::u32,
					::core::primitive::u64,
				>;
				pub type Retries = ::core::primitive::u8;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RetrySet {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "RetrySet";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Cancel a retry configuration for some task."]
			pub struct RetryCancelled {
				pub task: retry_cancelled::Task,
				pub id: retry_cancelled::Id,
			}
			pub mod retry_cancelled {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RetryCancelled {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "RetryCancelled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The call for the provided hash was not found so the task has been aborted."]
			pub struct CallUnavailable {
				pub task: call_unavailable::Task,
				pub id: call_unavailable::Id,
			}
			pub mod call_unavailable {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for CallUnavailable {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "CallUnavailable";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The given task was unable to be renewed since the agenda is full at that block."]
			pub struct PeriodicFailed {
				pub task: periodic_failed::Task,
				pub id: periodic_failed::Id,
			}
			pub mod periodic_failed {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for PeriodicFailed {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "PeriodicFailed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The given task was unable to be retried since the agenda is full at that block or there"]
			#[doc = "was not enough weight to reschedule it."]
			pub struct RetryFailed {
				pub task: retry_failed::Task,
				pub id: retry_failed::Id,
			}
			pub mod retry_failed {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RetryFailed {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "RetryFailed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The given task can never be executed since it is overweight."]
			pub struct PermanentlyOverweight {
				pub task: permanently_overweight::Task,
				pub id: permanently_overweight::Id,
			}
			pub mod permanently_overweight {
				use super::runtime_types;
				pub type Task = (
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
					::core::primitive::u32,
				);
				pub type Id = ::core::option::Option<[::core::primitive::u8; 32usize]>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for PermanentlyOverweight {
				const PALLET: &'static str = "Scheduler";
				const EVENT: &'static str = "PermanentlyOverweight";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod incomplete_block_since {
					use super::runtime_types;
					pub type IncompleteBlockSince = ::core::primitive::u32;
				}
				pub mod incomplete_timestamp_since {
					use super::runtime_types;
					pub type IncompleteTimestampSince = ::core::primitive::u64;
				}
				pub mod last_processed_timestamp {
					use super::runtime_types;
					pub type LastProcessedTimestamp = ::core::primitive::u64;
				}
				pub mod agenda {
					use super::runtime_types;
					pub type Agenda = runtime_types::bounded_collections::bounded_vec::BoundedVec<
						::core::option::Option<
							runtime_types::pallet_scheduler::Scheduled<
								[::core::primitive::u8; 32usize],
								runtime_types::frame_support::traits::preimages::Bounded<
									runtime_types::quantus_runtime::RuntimeCall,
									runtime_types::poseidon_resonance::PoseidonHasher,
								>,
								::core::primitive::u32,
								runtime_types::quantus_runtime::OriginCaller,
								::subxt::ext::subxt_core::utils::AccountId32,
								::core::primitive::u64,
							>,
						>,
					>;
					pub type Param0 = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
				}
				pub mod retries {
					use super::runtime_types;
					pub type Retries = runtime_types::pallet_scheduler::RetryConfig<
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
					>;
					pub type Param0 = (
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					);
				}
				pub mod lookup {
					use super::runtime_types;
					pub type Lookup = (
						runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						::core::primitive::u32,
					);
					pub type Param0 = [::core::primitive::u8; 32usize];
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " Tracks incomplete block-based agendas that need to be processed in a later block."]
				pub fn incomplete_block_since(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::incomplete_block_since::IncompleteBlockSince,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"IncompleteBlockSince",
						(),
						[
							134u8, 34u8, 161u8, 236u8, 176u8, 35u8, 218u8, 109u8, 229u8, 93u8,
							29u8, 95u8, 81u8, 106u8, 98u8, 65u8, 132u8, 91u8, 237u8, 225u8, 75u8,
							125u8, 81u8, 218u8, 72u8, 215u8, 20u8, 66u8, 160u8, 196u8, 68u8, 34u8,
						],
					)
				}
				#[doc = " Tracks incomplete timestamp-based agendas that need to be processed in a later block."]
				pub fn incomplete_timestamp_since(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::incomplete_timestamp_since::IncompleteTimestampSince,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"IncompleteTimestampSince",
						(),
						[
							223u8, 125u8, 99u8, 28u8, 81u8, 135u8, 125u8, 26u8, 3u8, 20u8, 32u8,
							125u8, 141u8, 114u8, 100u8, 38u8, 219u8, 191u8, 30u8, 88u8, 82u8, 33u8,
							140u8, 223u8, 168u8, 84u8, 144u8, 85u8, 57u8, 241u8, 97u8, 141u8,
						],
					)
				}
				#[doc = " Tracks the last timestamp bucket that was fully processed."]
				#[doc = " Used to avoid reprocessing all buckets from 0 on every run."]
				pub fn last_processed_timestamp(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::last_processed_timestamp::LastProcessedTimestamp,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"LastProcessedTimestamp",
						(),
						[
							172u8, 193u8, 6u8, 47u8, 185u8, 134u8, 179u8, 132u8, 178u8, 0u8, 228u8,
							198u8, 232u8, 24u8, 85u8, 199u8, 102u8, 222u8, 246u8, 178u8, 8u8,
							221u8, 51u8, 188u8, 239u8, 218u8, 112u8, 245u8, 46u8, 146u8, 65u8,
							119u8,
						],
					)
				}
				#[doc = " Items to be executed, indexed by the block number that they should be executed on."]
				pub fn agenda_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::agenda::Agenda,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"Agenda",
						(),
						[
							188u8, 177u8, 84u8, 167u8, 206u8, 4u8, 136u8, 133u8, 67u8, 121u8,
							247u8, 186u8, 6u8, 46u8, 115u8, 104u8, 239u8, 41u8, 75u8, 143u8, 24u8,
							155u8, 212u8, 196u8, 166u8, 82u8, 63u8, 39u8, 104u8, 21u8, 19u8, 93u8,
						],
					)
				}
				#[doc = " Items to be executed, indexed by the block number that they should be executed on."]
				pub fn agenda(
					&self,
					_0: types::agenda::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::agenda::Param0,
					>,
					types::agenda::Agenda,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"Agenda",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							188u8, 177u8, 84u8, 167u8, 206u8, 4u8, 136u8, 133u8, 67u8, 121u8,
							247u8, 186u8, 6u8, 46u8, 115u8, 104u8, 239u8, 41u8, 75u8, 143u8, 24u8,
							155u8, 212u8, 196u8, 166u8, 82u8, 63u8, 39u8, 104u8, 21u8, 19u8, 93u8,
						],
					)
				}
				#[doc = " Retry configurations for items to be executed, indexed by task address."]
				pub fn retries_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::retries::Retries,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"Retries",
						(),
						[
							94u8, 54u8, 136u8, 189u8, 244u8, 118u8, 102u8, 67u8, 203u8, 238u8,
							109u8, 130u8, 229u8, 246u8, 244u8, 68u8, 59u8, 132u8, 12u8, 9u8, 219u8,
							176u8, 251u8, 1u8, 216u8, 200u8, 205u8, 176u8, 145u8, 201u8, 206u8,
							108u8,
						],
					)
				}
				#[doc = " Retry configurations for items to be executed, indexed by task address."]
				pub fn retries(
					&self,
					_0: types::retries::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::retries::Param0,
					>,
					types::retries::Retries,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"Retries",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							94u8, 54u8, 136u8, 189u8, 244u8, 118u8, 102u8, 67u8, 203u8, 238u8,
							109u8, 130u8, 229u8, 246u8, 244u8, 68u8, 59u8, 132u8, 12u8, 9u8, 219u8,
							176u8, 251u8, 1u8, 216u8, 200u8, 205u8, 176u8, 145u8, 201u8, 206u8,
							108u8,
						],
					)
				}
				#[doc = " Lookup from a name to the block number and index of the task."]
				#[doc = ""]
				#[doc = " For v3 -> v4 the previously unbounded identities are Blake2-256 hashed to form the v4"]
				#[doc = " identities."]
				pub fn lookup_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::lookup::Lookup,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"Lookup",
						(),
						[
							133u8, 194u8, 6u8, 16u8, 27u8, 10u8, 159u8, 62u8, 113u8, 59u8, 58u8,
							225u8, 244u8, 206u8, 35u8, 113u8, 41u8, 40u8, 89u8, 71u8, 133u8, 117u8,
							33u8, 192u8, 106u8, 85u8, 83u8, 186u8, 36u8, 160u8, 144u8, 221u8,
						],
					)
				}
				#[doc = " Lookup from a name to the block number and index of the task."]
				#[doc = ""]
				#[doc = " For v3 -> v4 the previously unbounded identities are Blake2-256 hashed to form the v4"]
				#[doc = " identities."]
				pub fn lookup(
					&self,
					_0: types::lookup::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::lookup::Param0,
					>,
					types::lookup::Lookup,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Scheduler",
						"Lookup",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							133u8, 194u8, 6u8, 16u8, 27u8, 10u8, 159u8, 62u8, 113u8, 59u8, 58u8,
							225u8, 244u8, 206u8, 35u8, 113u8, 41u8, 40u8, 89u8, 71u8, 133u8, 117u8,
							33u8, 192u8, 106u8, 85u8, 83u8, 186u8, 36u8, 160u8, 144u8, 221u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The maximum weight that may be scheduled per block for any dispatchables."]
				pub fn maximum_weight(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::sp_weights::weight_v2::Weight,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Scheduler",
						"MaximumWeight",
						[
							149u8, 252u8, 129u8, 80u8, 169u8, 36u8, 79u8, 127u8, 240u8, 156u8,
							56u8, 202u8, 219u8, 86u8, 5u8, 65u8, 245u8, 148u8, 138u8, 243u8, 210u8,
							128u8, 234u8, 216u8, 240u8, 219u8, 123u8, 235u8, 21u8, 158u8, 237u8,
							112u8,
						],
					)
				}
				#[doc = " The maximum number of scheduled calls in the queue for a single block."]
				#[doc = ""]
				#[doc = " NOTE:"]
				#[doc = " + Dependent pallets' benchmarks might require a higher limit for the setting. Set a"]
				#[doc = " higher limit under `runtime-benchmarks` feature."]
				pub fn max_scheduled_per_block(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Scheduler",
						"MaxScheduledPerBlock",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Precision of the timestamp buckets."]
				#[doc = ""]
				#[doc = " Timestamp based dispatches are rounded to the nearest bucket of this precision."]
				pub fn timestamp_bucket_size(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u64,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Scheduler",
						"TimestampBucketSize",
						[
							128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8,
							59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8,
							103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8,
							246u8,
						],
					)
				}
			}
		}
	}
	pub mod utility {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_utility::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_utility::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Send a batch of dispatch calls."]
				#[doc = ""]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
				#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
				#[doc = ""]
				#[doc = "If origin is root then the calls are dispatched without checking origin filter. (This"]
				#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(C) where C is the number of calls to be batched."]
				#[doc = ""]
				#[doc = "This will return `Ok` in all circumstances. To determine the success of the batch, an"]
				#[doc = "event is deposited. If a call failed and the batch was interrupted, then the"]
				#[doc = "`BatchInterrupted` event is deposited, along with the number of successful calls made"]
				#[doc = "and the error of the failed call. If all were successful, then the `BatchCompleted`"]
				#[doc = "event is deposited."]
				pub struct Batch {
					pub calls: batch::Calls,
				}
				pub mod batch {
					use super::runtime_types;
					pub type Calls = ::subxt::ext::subxt_core::alloc::vec::Vec<
						runtime_types::quantus_runtime::RuntimeCall,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Batch {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "batch";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Send a call through an indexed pseudonym of the sender."]
				#[doc = ""]
				#[doc = "Filter from origin are passed along. The call will be dispatched with an origin which"]
				#[doc = "use the same filter as the origin of this call."]
				#[doc = ""]
				#[doc = "NOTE: If you need to ensure that any account-based filtering is not honored (i.e."]
				#[doc = "because you expect `proxy` to have been used prior in the call stack and you do not want"]
				#[doc = "the call restrictions to apply to any sub-accounts), then use `as_multi_threshold_1`"]
				#[doc = "in the Multisig pallet instead."]
				#[doc = ""]
				#[doc = "NOTE: Prior to version *12, this was called `as_limited_sub`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				pub struct AsDerivative {
					pub index: as_derivative::Index,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<as_derivative::Call>,
				}
				pub mod as_derivative {
					use super::runtime_types;
					pub type Index = ::core::primitive::u16;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AsDerivative {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "as_derivative";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Send a batch of dispatch calls and atomically execute them."]
				#[doc = "The whole transaction will rollback and fail if any of the calls failed."]
				#[doc = ""]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
				#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
				#[doc = ""]
				#[doc = "If origin is root then the calls are dispatched without checking origin filter. (This"]
				#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(C) where C is the number of calls to be batched."]
				pub struct BatchAll {
					pub calls: batch_all::Calls,
				}
				pub mod batch_all {
					use super::runtime_types;
					pub type Calls = ::subxt::ext::subxt_core::alloc::vec::Vec<
						runtime_types::quantus_runtime::RuntimeCall,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for BatchAll {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "batch_all";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Dispatches a function call with a provided origin."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(1)."]
				pub struct DispatchAs {
					pub as_origin:
						::subxt::ext::subxt_core::alloc::boxed::Box<dispatch_as::AsOrigin>,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<dispatch_as::Call>,
				}
				pub mod dispatch_as {
					use super::runtime_types;
					pub type AsOrigin = runtime_types::quantus_runtime::OriginCaller;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for DispatchAs {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "dispatch_as";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Send a batch of dispatch calls."]
				#[doc = "Unlike `batch`, it allows errors and won't interrupt."]
				#[doc = ""]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
				#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
				#[doc = ""]
				#[doc = "If origin is root then the calls are dispatch without checking origin filter. (This"]
				#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(C) where C is the number of calls to be batched."]
				pub struct ForceBatch {
					pub calls: force_batch::Calls,
				}
				pub mod force_batch {
					use super::runtime_types;
					pub type Calls = ::subxt::ext::subxt_core::alloc::vec::Vec<
						runtime_types::quantus_runtime::RuntimeCall,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ForceBatch {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "force_batch";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Dispatch a function call with a specified weight."]
				#[doc = ""]
				#[doc = "This function does not check the weight of the call, and instead allows the"]
				#[doc = "Root origin to specify the weight of the call."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				pub struct WithWeight {
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<with_weight::Call>,
					pub weight: with_weight::Weight,
				}
				pub mod with_weight {
					use super::runtime_types;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
					pub type Weight = runtime_types::sp_weights::weight_v2::Weight;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for WithWeight {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "with_weight";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Dispatch a fallback call in the event the main call fails to execute."]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "This function first attempts to dispatch the `main` call."]
				#[doc = "If the `main` call fails, the `fallback` is attemted."]
				#[doc = "if the fallback is successfully dispatched, the weights of both calls"]
				#[doc = "are accumulated and an event containing the main call error is deposited."]
				#[doc = ""]
				#[doc = "In the event of a fallback failure the whole call fails"]
				#[doc = "with the weights returned."]
				#[doc = ""]
				#[doc = "- `main`: The main call to be dispatched. This is the primary action to execute."]
				#[doc = "- `fallback`: The fallback call to be dispatched in case the `main` call fails."]
				#[doc = ""]
				#[doc = "## Dispatch Logic"]
				#[doc = "- If the origin is `root`, both the main and fallback calls are executed without"]
				#[doc = "  applying any origin filters."]
				#[doc = "- If the origin is not `root`, the origin filter is applied to both the `main` and"]
				#[doc = "  `fallback` calls."]
				#[doc = ""]
				#[doc = "## Use Case"]
				#[doc = "- Some use cases might involve submitting a `batch` type call in either main, fallback"]
				#[doc = "  or both."]
				pub struct IfElse {
					pub main: ::subxt::ext::subxt_core::alloc::boxed::Box<if_else::Main>,
					pub fallback: ::subxt::ext::subxt_core::alloc::boxed::Box<if_else::Fallback>,
				}
				pub mod if_else {
					use super::runtime_types;
					pub type Main = runtime_types::quantus_runtime::RuntimeCall;
					pub type Fallback = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for IfElse {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "if_else";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Dispatches a function call with a provided origin."]
				#[doc = ""]
				#[doc = "Almost the same as [`Pallet::dispatch_as`] but forwards any error of the inner call."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				pub struct DispatchAsFallible {
					pub as_origin:
						::subxt::ext::subxt_core::alloc::boxed::Box<dispatch_as_fallible::AsOrigin>,
					pub call:
						::subxt::ext::subxt_core::alloc::boxed::Box<dispatch_as_fallible::Call>,
				}
				pub mod dispatch_as_fallible {
					use super::runtime_types;
					pub type AsOrigin = runtime_types::quantus_runtime::OriginCaller;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for DispatchAsFallible {
					const PALLET: &'static str = "Utility";
					const CALL: &'static str = "dispatch_as_fallible";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Send a batch of dispatch calls."]
				#[doc = ""]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
				#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
				#[doc = ""]
				#[doc = "If origin is root then the calls are dispatched without checking origin filter. (This"]
				#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(C) where C is the number of calls to be batched."]
				#[doc = ""]
				#[doc = "This will return `Ok` in all circumstances. To determine the success of the batch, an"]
				#[doc = "event is deposited. If a call failed and the batch was interrupted, then the"]
				#[doc = "`BatchInterrupted` event is deposited, along with the number of successful calls made"]
				#[doc = "and the error of the failed call. If all were successful, then the `BatchCompleted`"]
				#[doc = "event is deposited."]
				pub fn batch(
					&self,
					calls: types::batch::Calls,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Batch> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"batch",
						types::Batch { calls },
						[
							199u8, 107u8, 4u8, 184u8, 37u8, 208u8, 138u8, 138u8, 72u8, 80u8, 69u8,
							33u8, 68u8, 104u8, 89u8, 106u8, 26u8, 212u8, 101u8, 77u8, 43u8, 64u8,
							105u8, 187u8, 65u8, 195u8, 179u8, 63u8, 150u8, 242u8, 147u8, 102u8,
						],
					)
				}
				#[doc = "Send a call through an indexed pseudonym of the sender."]
				#[doc = ""]
				#[doc = "Filter from origin are passed along. The call will be dispatched with an origin which"]
				#[doc = "use the same filter as the origin of this call."]
				#[doc = ""]
				#[doc = "NOTE: If you need to ensure that any account-based filtering is not honored (i.e."]
				#[doc = "because you expect `proxy` to have been used prior in the call stack and you do not want"]
				#[doc = "the call restrictions to apply to any sub-accounts), then use `as_multi_threshold_1`"]
				#[doc = "in the Multisig pallet instead."]
				#[doc = ""]
				#[doc = "NOTE: Prior to version *12, this was called `as_limited_sub`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				pub fn as_derivative(
					&self,
					index: types::as_derivative::Index,
					call: types::as_derivative::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AsDerivative> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"as_derivative",
						types::AsDerivative {
							index,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							255u8, 148u8, 192u8, 241u8, 50u8, 58u8, 115u8, 72u8, 226u8, 159u8,
							65u8, 246u8, 183u8, 252u8, 180u8, 175u8, 170u8, 83u8, 88u8, 44u8, 20u8,
							216u8, 212u8, 54u8, 231u8, 42u8, 140u8, 122u8, 120u8, 240u8, 177u8,
							89u8,
						],
					)
				}
				#[doc = "Send a batch of dispatch calls and atomically execute them."]
				#[doc = "The whole transaction will rollback and fail if any of the calls failed."]
				#[doc = ""]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
				#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
				#[doc = ""]
				#[doc = "If origin is root then the calls are dispatched without checking origin filter. (This"]
				#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(C) where C is the number of calls to be batched."]
				pub fn batch_all(
					&self,
					calls: types::batch_all::Calls,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::BatchAll> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"batch_all",
						types::BatchAll { calls },
						[
							80u8, 2u8, 212u8, 226u8, 168u8, 219u8, 189u8, 151u8, 171u8, 238u8,
							36u8, 22u8, 214u8, 80u8, 60u8, 134u8, 110u8, 74u8, 127u8, 101u8, 195u8,
							100u8, 149u8, 41u8, 116u8, 208u8, 137u8, 173u8, 134u8, 127u8, 202u8,
							212u8,
						],
					)
				}
				#[doc = "Dispatches a function call with a provided origin."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(1)."]
				pub fn dispatch_as(
					&self,
					as_origin: types::dispatch_as::AsOrigin,
					call: types::dispatch_as::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::DispatchAs> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"dispatch_as",
						types::DispatchAs {
							as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box::new(as_origin),
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							64u8, 139u8, 112u8, 32u8, 214u8, 116u8, 71u8, 50u8, 4u8, 61u8, 185u8,
							230u8, 92u8, 127u8, 63u8, 124u8, 62u8, 42u8, 210u8, 137u8, 155u8,
							160u8, 7u8, 117u8, 83u8, 229u8, 49u8, 140u8, 243u8, 158u8, 143u8,
							125u8,
						],
					)
				}
				#[doc = "Send a batch of dispatch calls."]
				#[doc = "Unlike `batch`, it allows errors and won't interrupt."]
				#[doc = ""]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
				#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
				#[doc = ""]
				#[doc = "If origin is root then the calls are dispatch without checking origin filter. (This"]
				#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
				#[doc = ""]
				#[doc = "## Complexity"]
				#[doc = "- O(C) where C is the number of calls to be batched."]
				pub fn force_batch(
					&self,
					calls: types::force_batch::Calls,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ForceBatch> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"force_batch",
						types::ForceBatch { calls },
						[
							178u8, 11u8, 46u8, 170u8, 80u8, 28u8, 31u8, 82u8, 113u8, 185u8, 152u8,
							72u8, 51u8, 133u8, 251u8, 231u8, 255u8, 24u8, 80u8, 31u8, 52u8, 151u8,
							157u8, 123u8, 132u8, 210u8, 143u8, 150u8, 244u8, 163u8, 169u8, 119u8,
						],
					)
				}
				#[doc = "Dispatch a function call with a specified weight."]
				#[doc = ""]
				#[doc = "This function does not check the weight of the call, and instead allows the"]
				#[doc = "Root origin to specify the weight of the call."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				pub fn with_weight(
					&self,
					call: types::with_weight::Call,
					weight: types::with_weight::Weight,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::WithWeight> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"with_weight",
						types::WithWeight {
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
							weight,
						},
						[
							148u8, 144u8, 13u8, 219u8, 41u8, 23u8, 240u8, 185u8, 172u8, 80u8,
							120u8, 153u8, 253u8, 249u8, 208u8, 88u8, 150u8, 132u8, 94u8, 53u8,
							199u8, 177u8, 20u8, 117u8, 115u8, 225u8, 36u8, 149u8, 130u8, 161u8,
							213u8, 14u8,
						],
					)
				}
				#[doc = "Dispatch a fallback call in the event the main call fails to execute."]
				#[doc = "May be called from any origin except `None`."]
				#[doc = ""]
				#[doc = "This function first attempts to dispatch the `main` call."]
				#[doc = "If the `main` call fails, the `fallback` is attemted."]
				#[doc = "if the fallback is successfully dispatched, the weights of both calls"]
				#[doc = "are accumulated and an event containing the main call error is deposited."]
				#[doc = ""]
				#[doc = "In the event of a fallback failure the whole call fails"]
				#[doc = "with the weights returned."]
				#[doc = ""]
				#[doc = "- `main`: The main call to be dispatched. This is the primary action to execute."]
				#[doc = "- `fallback`: The fallback call to be dispatched in case the `main` call fails."]
				#[doc = ""]
				#[doc = "## Dispatch Logic"]
				#[doc = "- If the origin is `root`, both the main and fallback calls are executed without"]
				#[doc = "  applying any origin filters."]
				#[doc = "- If the origin is not `root`, the origin filter is applied to both the `main` and"]
				#[doc = "  `fallback` calls."]
				#[doc = ""]
				#[doc = "## Use Case"]
				#[doc = "- Some use cases might involve submitting a `batch` type call in either main, fallback"]
				#[doc = "  or both."]
				pub fn if_else(
					&self,
					main: types::if_else::Main,
					fallback: types::if_else::Fallback,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::IfElse> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"if_else",
						types::IfElse {
							main: ::subxt::ext::subxt_core::alloc::boxed::Box::new(main),
							fallback: ::subxt::ext::subxt_core::alloc::boxed::Box::new(fallback),
						},
						[
							0u8, 27u8, 171u8, 182u8, 168u8, 222u8, 131u8, 139u8, 212u8, 81u8,
							244u8, 248u8, 235u8, 235u8, 183u8, 40u8, 200u8, 142u8, 120u8, 206u8,
							220u8, 48u8, 168u8, 132u8, 197u8, 162u8, 5u8, 216u8, 217u8, 8u8, 7u8,
							212u8,
						],
					)
				}
				#[doc = "Dispatches a function call with a provided origin."]
				#[doc = ""]
				#[doc = "Almost the same as [`Pallet::dispatch_as`] but forwards any error of the inner call."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Root_."]
				pub fn dispatch_as_fallible(
					&self,
					as_origin: types::dispatch_as_fallible::AsOrigin,
					call: types::dispatch_as_fallible::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::DispatchAsFallible>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Utility",
						"dispatch_as_fallible",
						types::DispatchAsFallible {
							as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box::new(as_origin),
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							161u8, 156u8, 154u8, 193u8, 234u8, 76u8, 172u8, 105u8, 176u8, 172u8,
							253u8, 121u8, 19u8, 99u8, 16u8, 232u8, 253u8, 12u8, 33u8, 11u8, 97u8,
							64u8, 49u8, 6u8, 4u8, 120u8, 4u8, 175u8, 39u8, 232u8, 129u8, 51u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_utility::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Batch of dispatches did not complete fully. Index of first failing dispatch given, as"]
			#[doc = "well as the error."]
			pub struct BatchInterrupted {
				pub index: batch_interrupted::Index,
				pub error: batch_interrupted::Error,
			}
			pub mod batch_interrupted {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Error = runtime_types::sp_runtime::DispatchError;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for BatchInterrupted {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "BatchInterrupted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Batch of dispatches completed fully with no error."]
			pub struct BatchCompleted;
			impl ::subxt::ext::subxt_core::events::StaticEvent for BatchCompleted {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "BatchCompleted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Batch of dispatches completed but has errors."]
			pub struct BatchCompletedWithErrors;
			impl ::subxt::ext::subxt_core::events::StaticEvent for BatchCompletedWithErrors {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "BatchCompletedWithErrors";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A single item within a Batch of dispatches has completed with no error."]
			pub struct ItemCompleted;
			impl ::subxt::ext::subxt_core::events::StaticEvent for ItemCompleted {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "ItemCompleted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A single item within a Batch of dispatches has completed with error."]
			pub struct ItemFailed {
				pub error: item_failed::Error,
			}
			pub mod item_failed {
				use super::runtime_types;
				pub type Error = runtime_types::sp_runtime::DispatchError;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ItemFailed {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "ItemFailed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A call was dispatched."]
			pub struct DispatchedAs {
				pub result: dispatched_as::Result,
			}
			pub mod dispatched_as {
				use super::runtime_types;
				pub type Result =
					::core::result::Result<(), runtime_types::sp_runtime::DispatchError>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DispatchedAs {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "DispatchedAs";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Main call was dispatched."]
			pub struct IfElseMainSuccess;
			impl ::subxt::ext::subxt_core::events::StaticEvent for IfElseMainSuccess {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "IfElseMainSuccess";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The fallback call was dispatched."]
			pub struct IfElseFallbackCalled {
				pub main_error: if_else_fallback_called::MainError,
			}
			pub mod if_else_fallback_called {
				use super::runtime_types;
				pub type MainError = runtime_types::sp_runtime::DispatchError;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for IfElseFallbackCalled {
				const PALLET: &'static str = "Utility";
				const EVENT: &'static str = "IfElseFallbackCalled";
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The limit on the number of batched calls."]
				pub fn batched_calls_limit(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Utility",
						"batched_calls_limit",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
			}
		}
	}
	pub mod referenda {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_referenda::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_referenda::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Propose a referendum on a privileged action."]
				#[doc = ""]
				#[doc = "- `origin`: must be `SubmitOrigin` and the account must have `SubmissionDeposit` funds"]
				#[doc = "  available."]
				#[doc = "- `proposal_origin`: The origin from which the proposal should be executed."]
				#[doc = "- `proposal`: The proposal."]
				#[doc = "- `enactment_moment`: The moment that the proposal should be enacted."]
				#[doc = ""]
				#[doc = "Emits `Submitted`."]
				pub struct Submit {
					pub proposal_origin:
						::subxt::ext::subxt_core::alloc::boxed::Box<submit::ProposalOrigin>,
					pub proposal: submit::Proposal,
					pub enactment_moment: submit::EnactmentMoment,
				}
				pub mod submit {
					use super::runtime_types;
					pub type ProposalOrigin = runtime_types::quantus_runtime::OriginCaller;
					pub type Proposal = runtime_types::frame_support::traits::preimages::Bounded<
						runtime_types::quantus_runtime::RuntimeCall,
						runtime_types::poseidon_resonance::PoseidonHasher,
					>;
					pub type EnactmentMoment =
						runtime_types::frame_support::traits::schedule::DispatchTime<
							::core::primitive::u32,
						>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Submit {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "submit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Post the Decision Deposit for a referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` and the account must have funds available for the"]
				#[doc = "  referendum's track's Decision Deposit."]
				#[doc = "- `index`: The index of the submitted referendum whose Decision Deposit is yet to be"]
				#[doc = "  posted."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositPlaced`."]
				pub struct PlaceDecisionDeposit {
					pub index: place_decision_deposit::Index,
				}
				pub mod place_decision_deposit {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for PlaceDecisionDeposit {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "place_decision_deposit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Refund the Decision Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Decision Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositRefunded`."]
				pub struct RefundDecisionDeposit {
					pub index: refund_decision_deposit::Index,
				}
				pub mod refund_decision_deposit {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RefundDecisionDeposit {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "refund_decision_deposit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel an ongoing referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `CancelOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Cancelled`."]
				pub struct Cancel {
					pub index: cancel::Index,
				}
				pub mod cancel {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Cancel {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "cancel";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel an ongoing referendum and slash the deposits."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `KillOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Killed` and `DepositSlashed`."]
				pub struct Kill {
					pub index: kill::Index,
				}
				pub mod kill {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Kill {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "kill";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Advance a referendum onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `index`: the referendum to be advanced."]
				pub struct NudgeReferendum {
					pub index: nudge_referendum::Index,
				}
				pub mod nudge_referendum {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for NudgeReferendum {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "nudge_referendum";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Advance a track onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `track`: the track to be advanced."]
				#[doc = ""]
				#[doc = "Action item for when there is now one fewer referendum in the deciding phase and the"]
				#[doc = "`DecidingCount` is not yet updated. This means that we should either:"]
				#[doc = "- begin deciding another referendum (and leave `DecidingCount` alone); or"]
				#[doc = "- decrement `DecidingCount`."]
				pub struct OneFewerDeciding {
					pub track: one_fewer_deciding::Track,
				}
				pub mod one_fewer_deciding {
					use super::runtime_types;
					pub type Track = ::core::primitive::u16;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for OneFewerDeciding {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "one_fewer_deciding";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Refund the Submission Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Submission Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `SubmissionDepositRefunded`."]
				pub struct RefundSubmissionDeposit {
					pub index: refund_submission_deposit::Index,
				}
				pub mod refund_submission_deposit {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RefundSubmissionDeposit {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "refund_submission_deposit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set or clear metadata of a referendum."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `origin`: Must be `Signed` by a creator of a referendum or by anyone to clear a"]
				#[doc = "  metadata of a finished referendum."]
				#[doc = "- `index`:  The index of a referendum to set or clear metadata for."]
				#[doc = "- `maybe_hash`: The hash of an on-chain stored preimage. `None` to clear a metadata."]
				pub struct SetMetadata {
					pub index: set_metadata::Index,
					pub maybe_hash: set_metadata::MaybeHash,
				}
				pub mod set_metadata {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
					pub type MaybeHash =
						::core::option::Option<::subxt::ext::subxt_core::utils::H256>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetMetadata {
					const PALLET: &'static str = "Referenda";
					const CALL: &'static str = "set_metadata";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Propose a referendum on a privileged action."]
				#[doc = ""]
				#[doc = "- `origin`: must be `SubmitOrigin` and the account must have `SubmissionDeposit` funds"]
				#[doc = "  available."]
				#[doc = "- `proposal_origin`: The origin from which the proposal should be executed."]
				#[doc = "- `proposal`: The proposal."]
				#[doc = "- `enactment_moment`: The moment that the proposal should be enacted."]
				#[doc = ""]
				#[doc = "Emits `Submitted`."]
				pub fn submit(
					&self,
					proposal_origin: types::submit::ProposalOrigin,
					proposal: types::submit::Proposal,
					enactment_moment: types::submit::EnactmentMoment,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Submit> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"submit",
						types::Submit {
							proposal_origin: ::subxt::ext::subxt_core::alloc::boxed::Box::new(
								proposal_origin,
							),
							proposal,
							enactment_moment,
						},
						[
							30u8, 232u8, 132u8, 0u8, 199u8, 166u8, 49u8, 94u8, 238u8, 61u8, 236u8,
							207u8, 2u8, 136u8, 37u8, 81u8, 67u8, 133u8, 2u8, 147u8, 177u8, 176u8,
							178u8, 113u8, 155u8, 180u8, 104u8, 176u8, 215u8, 255u8, 240u8, 100u8,
						],
					)
				}
				#[doc = "Post the Decision Deposit for a referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` and the account must have funds available for the"]
				#[doc = "  referendum's track's Decision Deposit."]
				#[doc = "- `index`: The index of the submitted referendum whose Decision Deposit is yet to be"]
				#[doc = "  posted."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositPlaced`."]
				pub fn place_decision_deposit(
					&self,
					index: types::place_decision_deposit::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::PlaceDecisionDeposit>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"place_decision_deposit",
						types::PlaceDecisionDeposit { index },
						[
							247u8, 158u8, 55u8, 191u8, 188u8, 200u8, 3u8, 47u8, 20u8, 175u8, 86u8,
							203u8, 52u8, 253u8, 91u8, 131u8, 21u8, 213u8, 56u8, 68u8, 40u8, 84u8,
							184u8, 30u8, 9u8, 193u8, 63u8, 182u8, 178u8, 241u8, 247u8, 220u8,
						],
					)
				}
				#[doc = "Refund the Decision Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Decision Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositRefunded`."]
				pub fn refund_decision_deposit(
					&self,
					index: types::refund_decision_deposit::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::RefundDecisionDeposit,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"refund_decision_deposit",
						types::RefundDecisionDeposit { index },
						[
							159u8, 19u8, 35u8, 216u8, 114u8, 105u8, 18u8, 42u8, 148u8, 151u8,
							136u8, 92u8, 117u8, 30u8, 29u8, 41u8, 238u8, 58u8, 195u8, 91u8, 115u8,
							135u8, 96u8, 99u8, 154u8, 233u8, 8u8, 249u8, 145u8, 165u8, 77u8, 164u8,
						],
					)
				}
				#[doc = "Cancel an ongoing referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `CancelOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Cancelled`."]
				pub fn cancel(
					&self,
					index: types::cancel::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Cancel> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"cancel",
						types::Cancel { index },
						[
							55u8, 206u8, 119u8, 156u8, 238u8, 165u8, 193u8, 73u8, 242u8, 13u8,
							212u8, 75u8, 136u8, 156u8, 151u8, 14u8, 35u8, 41u8, 156u8, 107u8, 60u8,
							190u8, 39u8, 216u8, 8u8, 74u8, 213u8, 130u8, 160u8, 131u8, 237u8,
							122u8,
						],
					)
				}
				#[doc = "Cancel an ongoing referendum and slash the deposits."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `KillOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Killed` and `DepositSlashed`."]
				pub fn kill(
					&self,
					index: types::kill::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Kill> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"kill",
						types::Kill { index },
						[
							50u8, 89u8, 57u8, 0u8, 87u8, 129u8, 113u8, 140u8, 179u8, 178u8, 126u8,
							198u8, 92u8, 92u8, 189u8, 64u8, 123u8, 232u8, 57u8, 227u8, 223u8,
							219u8, 73u8, 217u8, 179u8, 44u8, 210u8, 125u8, 180u8, 10u8, 143u8,
							48u8,
						],
					)
				}
				#[doc = "Advance a referendum onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `index`: the referendum to be advanced."]
				pub fn nudge_referendum(
					&self,
					index: types::nudge_referendum::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::NudgeReferendum>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"nudge_referendum",
						types::NudgeReferendum { index },
						[
							75u8, 99u8, 172u8, 30u8, 170u8, 150u8, 211u8, 229u8, 249u8, 128u8,
							194u8, 246u8, 100u8, 142u8, 193u8, 184u8, 232u8, 81u8, 29u8, 17u8,
							99u8, 91u8, 236u8, 85u8, 230u8, 226u8, 57u8, 115u8, 45u8, 170u8, 54u8,
							213u8,
						],
					)
				}
				#[doc = "Advance a track onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `track`: the track to be advanced."]
				#[doc = ""]
				#[doc = "Action item for when there is now one fewer referendum in the deciding phase and the"]
				#[doc = "`DecidingCount` is not yet updated. This means that we should either:"]
				#[doc = "- begin deciding another referendum (and leave `DecidingCount` alone); or"]
				#[doc = "- decrement `DecidingCount`."]
				pub fn one_fewer_deciding(
					&self,
					track: types::one_fewer_deciding::Track,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::OneFewerDeciding>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"one_fewer_deciding",
						types::OneFewerDeciding { track },
						[
							15u8, 84u8, 79u8, 231u8, 21u8, 239u8, 244u8, 143u8, 183u8, 215u8,
							181u8, 25u8, 225u8, 195u8, 95u8, 171u8, 17u8, 156u8, 182u8, 128u8,
							111u8, 40u8, 151u8, 102u8, 196u8, 55u8, 36u8, 212u8, 89u8, 190u8,
							131u8, 167u8,
						],
					)
				}
				#[doc = "Refund the Submission Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Submission Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `SubmissionDepositRefunded`."]
				pub fn refund_submission_deposit(
					&self,
					index: types::refund_submission_deposit::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::RefundSubmissionDeposit,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"refund_submission_deposit",
						types::RefundSubmissionDeposit { index },
						[
							20u8, 217u8, 115u8, 6u8, 1u8, 60u8, 54u8, 136u8, 35u8, 41u8, 38u8,
							23u8, 85u8, 100u8, 141u8, 126u8, 30u8, 160u8, 61u8, 46u8, 134u8, 98u8,
							82u8, 38u8, 211u8, 124u8, 208u8, 222u8, 210u8, 10u8, 155u8, 122u8,
						],
					)
				}
				#[doc = "Set or clear metadata of a referendum."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `origin`: Must be `Signed` by a creator of a referendum or by anyone to clear a"]
				#[doc = "  metadata of a finished referendum."]
				#[doc = "- `index`:  The index of a referendum to set or clear metadata for."]
				#[doc = "- `maybe_hash`: The hash of an on-chain stored preimage. `None` to clear a metadata."]
				pub fn set_metadata(
					&self,
					index: types::set_metadata::Index,
					maybe_hash: types::set_metadata::MaybeHash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetMetadata> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Referenda",
						"set_metadata",
						types::SetMetadata { index, maybe_hash },
						[
							207u8, 29u8, 146u8, 233u8, 219u8, 205u8, 88u8, 118u8, 106u8, 61u8,
							124u8, 101u8, 2u8, 41u8, 169u8, 70u8, 114u8, 189u8, 162u8, 118u8, 1u8,
							108u8, 234u8, 98u8, 245u8, 245u8, 183u8, 126u8, 89u8, 13u8, 112u8,
							88u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_referenda::pallet::Event1;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been submitted."]
			pub struct Submitted {
				pub index: submitted::Index,
				pub track: submitted::Track,
				pub proposal: submitted::Proposal,
			}
			pub mod submitted {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Track = ::core::primitive::u16;
				pub type Proposal = runtime_types::frame_support::traits::preimages::Bounded<
					runtime_types::quantus_runtime::RuntimeCall,
					runtime_types::poseidon_resonance::PoseidonHasher,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Submitted {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "Submitted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The decision deposit has been placed."]
			pub struct DecisionDepositPlaced {
				pub index: decision_deposit_placed::Index,
				pub who: decision_deposit_placed::Who,
				pub amount: decision_deposit_placed::Amount,
			}
			pub mod decision_deposit_placed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DecisionDepositPlaced {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "DecisionDepositPlaced";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The decision deposit has been refunded."]
			pub struct DecisionDepositRefunded {
				pub index: decision_deposit_refunded::Index,
				pub who: decision_deposit_refunded::Who,
				pub amount: decision_deposit_refunded::Amount,
			}
			pub mod decision_deposit_refunded {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DecisionDepositRefunded {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "DecisionDepositRefunded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A deposit has been slashed."]
			pub struct DepositSlashed {
				pub who: deposit_slashed::Who,
				pub amount: deposit_slashed::Amount,
			}
			pub mod deposit_slashed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DepositSlashed {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "DepositSlashed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has moved into the deciding phase."]
			pub struct DecisionStarted {
				pub index: decision_started::Index,
				pub track: decision_started::Track,
				pub proposal: decision_started::Proposal,
				pub tally: decision_started::Tally,
			}
			pub mod decision_started {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Track = ::core::primitive::u16;
				pub type Proposal = runtime_types::frame_support::traits::preimages::Bounded<
					runtime_types::quantus_runtime::RuntimeCall,
					runtime_types::poseidon_resonance::PoseidonHasher,
				>;
				pub type Tally =
					runtime_types::pallet_conviction_voting::types::Tally<::core::primitive::u128>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DecisionStarted {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "DecisionStarted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ConfirmStarted {
				pub index: confirm_started::Index,
			}
			pub mod confirm_started {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ConfirmStarted {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "ConfirmStarted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ConfirmAborted {
				pub index: confirm_aborted::Index,
			}
			pub mod confirm_aborted {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ConfirmAborted {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "ConfirmAborted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has ended its confirmation phase and is ready for approval."]
			pub struct Confirmed {
				pub index: confirmed::Index,
				pub tally: confirmed::Tally,
			}
			pub mod confirmed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally =
					runtime_types::pallet_conviction_voting::types::Tally<::core::primitive::u128>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Confirmed {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "Confirmed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been approved and its proposal has been scheduled."]
			pub struct Approved {
				pub index: approved::Index,
			}
			pub mod approved {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Approved {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "Approved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A proposal has been rejected by referendum."]
			pub struct Rejected {
				pub index: rejected::Index,
				pub tally: rejected::Tally,
			}
			pub mod rejected {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally =
					runtime_types::pallet_conviction_voting::types::Tally<::core::primitive::u128>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Rejected {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "Rejected";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been timed out without being decided."]
			pub struct TimedOut {
				pub index: timed_out::Index,
				pub tally: timed_out::Tally,
			}
			pub mod timed_out {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally =
					runtime_types::pallet_conviction_voting::types::Tally<::core::primitive::u128>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TimedOut {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "TimedOut";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been cancelled."]
			pub struct Cancelled {
				pub index: cancelled::Index,
				pub tally: cancelled::Tally,
			}
			pub mod cancelled {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally =
					runtime_types::pallet_conviction_voting::types::Tally<::core::primitive::u128>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Cancelled {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "Cancelled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been killed."]
			pub struct Killed {
				pub index: killed::Index,
				pub tally: killed::Tally,
			}
			pub mod killed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally =
					runtime_types::pallet_conviction_voting::types::Tally<::core::primitive::u128>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Killed {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "Killed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The submission deposit has been refunded."]
			pub struct SubmissionDepositRefunded {
				pub index: submission_deposit_refunded::Index,
				pub who: submission_deposit_refunded::Who,
				pub amount: submission_deposit_refunded::Amount,
			}
			pub mod submission_deposit_refunded {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for SubmissionDepositRefunded {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "SubmissionDepositRefunded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Metadata for a referendum has been set."]
			pub struct MetadataSet {
				pub index: metadata_set::Index,
				pub hash: metadata_set::Hash,
			}
			pub mod metadata_set {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MetadataSet {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "MetadataSet";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Metadata for a referendum has been cleared."]
			pub struct MetadataCleared {
				pub index: metadata_cleared::Index,
				pub hash: metadata_cleared::Hash,
			}
			pub mod metadata_cleared {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MetadataCleared {
				const PALLET: &'static str = "Referenda";
				const EVENT: &'static str = "MetadataCleared";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod referendum_count {
					use super::runtime_types;
					pub type ReferendumCount = ::core::primitive::u32;
				}
				pub mod referendum_info_for {
					use super::runtime_types;
					pub type ReferendumInfoFor =
						runtime_types::pallet_referenda::types::ReferendumInfo<
							::core::primitive::u16,
							runtime_types::quantus_runtime::OriginCaller,
							::core::primitive::u32,
							runtime_types::frame_support::traits::preimages::Bounded<
								runtime_types::quantus_runtime::RuntimeCall,
								runtime_types::poseidon_resonance::PoseidonHasher,
							>,
							::core::primitive::u128,
							runtime_types::pallet_conviction_voting::types::Tally<
								::core::primitive::u128,
							>,
							::subxt::ext::subxt_core::utils::AccountId32,
							(
								runtime_types::qp_scheduler::BlockNumberOrTimestamp<
									::core::primitive::u32,
									::core::primitive::u64,
								>,
								::core::primitive::u32,
							),
						>;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod track_queue {
					use super::runtime_types;
					pub type TrackQueue =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<(
							::core::primitive::u32,
							::core::primitive::u128,
						)>;
					pub type Param0 = ::core::primitive::u16;
				}
				pub mod deciding_count {
					use super::runtime_types;
					pub type DecidingCount = ::core::primitive::u32;
					pub type Param0 = ::core::primitive::u16;
				}
				pub mod metadata_of {
					use super::runtime_types;
					pub type MetadataOf = ::subxt::ext::subxt_core::utils::H256;
					pub type Param0 = ::core::primitive::u32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The next free referendum index, aka the number of referenda started so far."]
				pub fn referendum_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::referendum_count::ReferendumCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"ReferendumCount",
						(),
						[
							64u8, 145u8, 232u8, 153u8, 121u8, 87u8, 128u8, 253u8, 170u8, 192u8,
							139u8, 18u8, 0u8, 33u8, 243u8, 11u8, 238u8, 222u8, 244u8, 5u8, 247u8,
							198u8, 149u8, 31u8, 122u8, 208u8, 86u8, 179u8, 166u8, 167u8, 93u8,
							67u8,
						],
					)
				}
				#[doc = " Information concerning any given referendum."]
				pub fn referendum_info_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::referendum_info_for::ReferendumInfoFor,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"ReferendumInfoFor",
						(),
						[
							141u8, 184u8, 126u8, 61u8, 215u8, 190u8, 148u8, 93u8, 186u8, 72u8,
							110u8, 37u8, 82u8, 237u8, 65u8, 197u8, 69u8, 83u8, 173u8, 114u8, 117u8,
							72u8, 146u8, 28u8, 235u8, 60u8, 188u8, 247u8, 80u8, 240u8, 16u8, 194u8,
						],
					)
				}
				#[doc = " Information concerning any given referendum."]
				pub fn referendum_info_for(
					&self,
					_0: types::referendum_info_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::referendum_info_for::Param0,
					>,
					types::referendum_info_for::ReferendumInfoFor,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"ReferendumInfoFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							141u8, 184u8, 126u8, 61u8, 215u8, 190u8, 148u8, 93u8, 186u8, 72u8,
							110u8, 37u8, 82u8, 237u8, 65u8, 197u8, 69u8, 83u8, 173u8, 114u8, 117u8,
							72u8, 146u8, 28u8, 235u8, 60u8, 188u8, 247u8, 80u8, 240u8, 16u8, 194u8,
						],
					)
				}
				#[doc = " The sorted list of referenda ready to be decided but not yet being decided, ordered by"]
				#[doc = " conviction-weighted approvals."]
				#[doc = ""]
				#[doc = " This should be empty if `DecidingCount` is less than `TrackInfo::max_deciding`."]
				pub fn track_queue_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::track_queue::TrackQueue,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"TrackQueue",
						(),
						[
							125u8, 59u8, 111u8, 68u8, 27u8, 236u8, 82u8, 55u8, 83u8, 159u8, 105u8,
							20u8, 241u8, 118u8, 58u8, 141u8, 103u8, 60u8, 246u8, 49u8, 121u8,
							183u8, 7u8, 203u8, 225u8, 67u8, 132u8, 79u8, 150u8, 107u8, 71u8, 89u8,
						],
					)
				}
				#[doc = " The sorted list of referenda ready to be decided but not yet being decided, ordered by"]
				#[doc = " conviction-weighted approvals."]
				#[doc = ""]
				#[doc = " This should be empty if `DecidingCount` is less than `TrackInfo::max_deciding`."]
				pub fn track_queue(
					&self,
					_0: types::track_queue::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::track_queue::Param0,
					>,
					types::track_queue::TrackQueue,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"TrackQueue",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							125u8, 59u8, 111u8, 68u8, 27u8, 236u8, 82u8, 55u8, 83u8, 159u8, 105u8,
							20u8, 241u8, 118u8, 58u8, 141u8, 103u8, 60u8, 246u8, 49u8, 121u8,
							183u8, 7u8, 203u8, 225u8, 67u8, 132u8, 79u8, 150u8, 107u8, 71u8, 89u8,
						],
					)
				}
				#[doc = " The number of referenda being decided currently."]
				pub fn deciding_count_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::deciding_count::DecidingCount,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"DecidingCount",
						(),
						[
							203u8, 89u8, 158u8, 179u8, 194u8, 82u8, 248u8, 162u8, 93u8, 140u8,
							146u8, 51u8, 110u8, 232u8, 51u8, 1u8, 128u8, 212u8, 199u8, 14u8, 182u8,
							103u8, 47u8, 252u8, 126u8, 108u8, 166u8, 69u8, 252u8, 179u8, 126u8,
							245u8,
						],
					)
				}
				#[doc = " The number of referenda being decided currently."]
				pub fn deciding_count(
					&self,
					_0: types::deciding_count::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::deciding_count::Param0,
					>,
					types::deciding_count::DecidingCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"DecidingCount",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							203u8, 89u8, 158u8, 179u8, 194u8, 82u8, 248u8, 162u8, 93u8, 140u8,
							146u8, 51u8, 110u8, 232u8, 51u8, 1u8, 128u8, 212u8, 199u8, 14u8, 182u8,
							103u8, 47u8, 252u8, 126u8, 108u8, 166u8, 69u8, 252u8, 179u8, 126u8,
							245u8,
						],
					)
				}
				#[doc = " The metadata is a general information concerning the referendum."]
				#[doc = " The `Hash` refers to the preimage of the `Preimages` provider which can be a JSON"]
				#[doc = " dump or IPFS hash of a JSON file."]
				#[doc = ""]
				#[doc = " Consider a garbage collection for a metadata of finished referendums to `unrequest` (remove)"]
				#[doc = " large preimages."]
				pub fn metadata_of_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::metadata_of::MetadataOf,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"MetadataOf",
						(),
						[
							159u8, 250u8, 56u8, 189u8, 247u8, 165u8, 206u8, 166u8, 91u8, 139u8,
							124u8, 164u8, 25u8, 246u8, 199u8, 36u8, 159u8, 56u8, 227u8, 136u8, 4u8,
							45u8, 193u8, 72u8, 200u8, 164u8, 39u8, 207u8, 224u8, 124u8, 191u8,
							110u8,
						],
					)
				}
				#[doc = " The metadata is a general information concerning the referendum."]
				#[doc = " The `Hash` refers to the preimage of the `Preimages` provider which can be a JSON"]
				#[doc = " dump or IPFS hash of a JSON file."]
				#[doc = ""]
				#[doc = " Consider a garbage collection for a metadata of finished referendums to `unrequest` (remove)"]
				#[doc = " large preimages."]
				pub fn metadata_of(
					&self,
					_0: types::metadata_of::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::metadata_of::Param0,
					>,
					types::metadata_of::MetadataOf,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Referenda",
						"MetadataOf",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							159u8, 250u8, 56u8, 189u8, 247u8, 165u8, 206u8, 166u8, 91u8, 139u8,
							124u8, 164u8, 25u8, 246u8, 199u8, 36u8, 159u8, 56u8, 227u8, 136u8, 4u8,
							45u8, 193u8, 72u8, 200u8, 164u8, 39u8, 207u8, 224u8, 124u8, 191u8,
							110u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The minimum amount to be used as a deposit for a public referendum proposal."]
				pub fn submission_deposit(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Referenda",
						"SubmissionDeposit",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " Maximum size of the referendum queue for a single track."]
				pub fn max_queued(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Referenda",
						"MaxQueued",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The number of blocks after submission that a referendum must begin being decided by."]
				#[doc = " Once this passes, then anyone may cancel the referendum."]
				pub fn undeciding_timeout(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Referenda",
						"UndecidingTimeout",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Quantization level for the referendum wakeup scheduler. A higher number will result in"]
				#[doc = " fewer storage reads/writes needed for smaller voters, but also result in delays to the"]
				#[doc = " automatic referendum status changes. Explicit servicing instructions are unaffected."]
				pub fn alarm_interval(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Referenda",
						"AlarmInterval",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " A list of tracks."]
				#[doc = ""]
				#[doc = " Note: if the tracks are dynamic, the value in the static metadata might be inaccurate."]
				pub fn tracks(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::subxt::ext::subxt_core::alloc::vec::Vec<(
						::core::primitive::u16,
						runtime_types::pallet_referenda::types::TrackDetails<
							::core::primitive::u128,
							::core::primitive::u32,
							::subxt::ext::subxt_core::alloc::string::String,
						>,
					)>,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Referenda",
						"Tracks",
						[
							35u8, 226u8, 207u8, 234u8, 184u8, 139u8, 187u8, 184u8, 128u8, 199u8,
							227u8, 15u8, 31u8, 196u8, 5u8, 207u8, 138u8, 174u8, 130u8, 201u8,
							200u8, 113u8, 86u8, 93u8, 221u8, 243u8, 229u8, 24u8, 18u8, 150u8, 56u8,
							159u8,
						],
					)
				}
			}
		}
	}
	pub mod reversible_transfers {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_reversible_transfers::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_reversible_transfers::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Enable high-security for the calling account with a specified"]
				#[doc = "reversibility delay."]
				#[doc = ""]
				#[doc = "Recoverer and interceptor (aka guardian) could be the same account or"]
				#[doc = "different accounts."]
				#[doc = ""]
				#[doc = "Once an account is set as high security it can only make reversible"]
				#[doc = "transfers. It is not allowed any other calls."]
				#[doc = ""]
				#[doc = "- `delay`: The reversibility time for any transfer made by the high"]
				#[doc = "security account."]
				#[doc = "- interceptor: The account that can intercept transctions from the"]
				#[doc = "high security account."]
				#[doc = "- recoverer: Account that can recover (act as proxy to) the high security"]
				#[doc = "account"]
				pub struct SetHighSecurity {
					pub delay: set_high_security::Delay,
					pub interceptor: set_high_security::Interceptor,
				}
				pub mod set_high_security {
					use super::runtime_types;
					pub type Delay = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
					pub type Interceptor = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetHighSecurity {
					const PALLET: &'static str = "ReversibleTransfers";
					const CALL: &'static str = "set_high_security";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel a pending reversible transaction scheduled by the caller."]
				#[doc = ""]
				#[doc = "- `tx_id`: The unique identifier of the transaction to cancel."]
				pub struct Cancel {
					pub tx_id: cancel::TxId,
				}
				pub mod cancel {
					use super::runtime_types;
					pub type TxId = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Cancel {
					const PALLET: &'static str = "ReversibleTransfers";
					const CALL: &'static str = "cancel";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Called by the Scheduler to finalize the scheduled task/call"]
				#[doc = ""]
				#[doc = "- `tx_id`: The unique id of the transaction to finalize and dispatch."]
				pub struct ExecuteTransfer {
					pub tx_id: execute_transfer::TxId,
				}
				pub mod execute_transfer {
					use super::runtime_types;
					pub type TxId = ::subxt::ext::subxt_core::utils::H256;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ExecuteTransfer {
					const PALLET: &'static str = "ReversibleTransfers";
					const CALL: &'static str = "execute_transfer";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Schedule a transaction for delayed execution."]
				pub struct ScheduleTransfer {
					pub dest: schedule_transfer::Dest,
					pub amount: schedule_transfer::Amount,
				}
				pub mod schedule_transfer {
					use super::runtime_types;
					pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Amount = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ScheduleTransfer {
					const PALLET: &'static str = "ReversibleTransfers";
					const CALL: &'static str = "schedule_transfer";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Schedule a transaction for delayed execution with a custom, one-time delay."]
				#[doc = ""]
				#[doc = "This can only be used by accounts that have *not* set up a persistent"]
				#[doc = "reversibility configuration with `set_reversibility`."]
				#[doc = ""]
				#[doc = "- `delay`: The time (in blocks or milliseconds) before the transaction executes."]
				pub struct ScheduleTransferWithDelay {
					pub dest: schedule_transfer_with_delay::Dest,
					pub amount: schedule_transfer_with_delay::Amount,
					pub delay: schedule_transfer_with_delay::Delay,
				}
				pub mod schedule_transfer_with_delay {
					use super::runtime_types;
					pub type Dest = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Amount = ::core::primitive::u128;
					pub type Delay = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ScheduleTransferWithDelay {
					const PALLET: &'static str = "ReversibleTransfers";
					const CALL: &'static str = "schedule_transfer_with_delay";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Enable high-security for the calling account with a specified"]
				#[doc = "reversibility delay."]
				#[doc = ""]
				#[doc = "Recoverer and interceptor (aka guardian) could be the same account or"]
				#[doc = "different accounts."]
				#[doc = ""]
				#[doc = "Once an account is set as high security it can only make reversible"]
				#[doc = "transfers. It is not allowed any other calls."]
				#[doc = ""]
				#[doc = "- `delay`: The reversibility time for any transfer made by the high"]
				#[doc = "security account."]
				#[doc = "- interceptor: The account that can intercept transctions from the"]
				#[doc = "high security account."]
				#[doc = "- recoverer: Account that can recover (act as proxy to) the high security"]
				#[doc = "account"]
				pub fn set_high_security(
					&self,
					delay: types::set_high_security::Delay,
					interceptor: types::set_high_security::Interceptor,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetHighSecurity>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ReversibleTransfers",
						"set_high_security",
						types::SetHighSecurity { delay, interceptor },
						[
							202u8, 17u8, 43u8, 37u8, 215u8, 198u8, 42u8, 183u8, 53u8, 124u8, 140u8,
							34u8, 112u8, 230u8, 55u8, 168u8, 242u8, 249u8, 91u8, 185u8, 244u8,
							81u8, 40u8, 231u8, 121u8, 155u8, 202u8, 76u8, 137u8, 7u8, 225u8, 184u8,
						],
					)
				}
				#[doc = "Cancel a pending reversible transaction scheduled by the caller."]
				#[doc = ""]
				#[doc = "- `tx_id`: The unique identifier of the transaction to cancel."]
				pub fn cancel(
					&self,
					tx_id: types::cancel::TxId,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Cancel> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ReversibleTransfers",
						"cancel",
						types::Cancel { tx_id },
						[
							228u8, 150u8, 194u8, 119u8, 243u8, 126u8, 112u8, 227u8, 70u8, 160u8,
							132u8, 82u8, 146u8, 162u8, 195u8, 149u8, 236u8, 98u8, 18u8, 44u8,
							151u8, 249u8, 193u8, 176u8, 186u8, 98u8, 224u8, 103u8, 191u8, 165u8,
							37u8, 47u8,
						],
					)
				}
				#[doc = "Called by the Scheduler to finalize the scheduled task/call"]
				#[doc = ""]
				#[doc = "- `tx_id`: The unique id of the transaction to finalize and dispatch."]
				pub fn execute_transfer(
					&self,
					tx_id: types::execute_transfer::TxId,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ExecuteTransfer>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ReversibleTransfers",
						"execute_transfer",
						types::ExecuteTransfer { tx_id },
						[
							164u8, 38u8, 166u8, 81u8, 63u8, 235u8, 167u8, 178u8, 97u8, 80u8, 62u8,
							147u8, 3u8, 163u8, 129u8, 25u8, 98u8, 59u8, 17u8, 137u8, 6u8, 183u8,
							189u8, 51u8, 24u8, 211u8, 157u8, 108u8, 229u8, 253u8, 37u8, 78u8,
						],
					)
				}
				#[doc = "Schedule a transaction for delayed execution."]
				pub fn schedule_transfer(
					&self,
					dest: types::schedule_transfer::Dest,
					amount: types::schedule_transfer::Amount,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ScheduleTransfer>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ReversibleTransfers",
						"schedule_transfer",
						types::ScheduleTransfer { dest, amount },
						[
							38u8, 219u8, 206u8, 56u8, 252u8, 195u8, 52u8, 74u8, 113u8, 125u8,
							107u8, 35u8, 236u8, 39u8, 31u8, 18u8, 250u8, 177u8, 174u8, 154u8,
							149u8, 122u8, 183u8, 50u8, 45u8, 111u8, 100u8, 249u8, 102u8, 82u8,
							72u8, 130u8,
						],
					)
				}
				#[doc = "Schedule a transaction for delayed execution with a custom, one-time delay."]
				#[doc = ""]
				#[doc = "This can only be used by accounts that have *not* set up a persistent"]
				#[doc = "reversibility configuration with `set_reversibility`."]
				#[doc = ""]
				#[doc = "- `delay`: The time (in blocks or milliseconds) before the transaction executes."]
				pub fn schedule_transfer_with_delay(
					&self,
					dest: types::schedule_transfer_with_delay::Dest,
					amount: types::schedule_transfer_with_delay::Amount,
					delay: types::schedule_transfer_with_delay::Delay,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::ScheduleTransferWithDelay,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ReversibleTransfers",
						"schedule_transfer_with_delay",
						types::ScheduleTransferWithDelay { dest, amount, delay },
						[
							254u8, 158u8, 173u8, 217u8, 107u8, 80u8, 229u8, 252u8, 123u8, 46u8,
							177u8, 40u8, 25u8, 15u8, 32u8, 22u8, 224u8, 52u8, 242u8, 48u8, 242u8,
							84u8, 242u8, 143u8, 111u8, 12u8, 82u8, 161u8, 129u8, 86u8, 161u8,
							216u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_reversible_transfers::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A user has enabled their high-security settings."]
			#[doc = "[who, interceptor, recoverer, delay]"]
			pub struct HighSecuritySet {
				pub who: high_security_set::Who,
				pub interceptor: high_security_set::Interceptor,
				pub delay: high_security_set::Delay,
			}
			pub mod high_security_set {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Interceptor = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Delay = runtime_types::qp_scheduler::BlockNumberOrTimestamp<
					::core::primitive::u32,
					::core::primitive::u64,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for HighSecuritySet {
				const PALLET: &'static str = "ReversibleTransfers";
				const EVENT: &'static str = "HighSecuritySet";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A transaction has been intercepted and scheduled for delayed execution."]
			#[doc = "[from, to, interceptor, amount, tx_id, execute_at_moment]"]
			pub struct TransactionScheduled {
				pub from: transaction_scheduled::From,
				pub to: transaction_scheduled::To,
				pub interceptor: transaction_scheduled::Interceptor,
				pub amount: transaction_scheduled::Amount,
				pub tx_id: transaction_scheduled::TxId,
				pub execute_at: transaction_scheduled::ExecuteAt,
			}
			pub mod transaction_scheduled {
				use super::runtime_types;
				pub type From = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type To = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Interceptor = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
				pub type TxId = ::subxt::ext::subxt_core::utils::H256;
				pub type ExecuteAt = runtime_types::qp_scheduler::DispatchTime<
					::core::primitive::u32,
					::core::primitive::u64,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TransactionScheduled {
				const PALLET: &'static str = "ReversibleTransfers";
				const EVENT: &'static str = "TransactionScheduled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A scheduled transaction has been successfully cancelled by the owner."]
			#[doc = "[who, tx_id]"]
			pub struct TransactionCancelled {
				pub who: transaction_cancelled::Who,
				pub tx_id: transaction_cancelled::TxId,
			}
			pub mod transaction_cancelled {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type TxId = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TransactionCancelled {
				const PALLET: &'static str = "ReversibleTransfers";
				const EVENT: &'static str = "TransactionCancelled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A scheduled transaction was executed by the scheduler."]
			#[doc = "[tx_id, dispatch_result]"]
			pub struct TransactionExecuted {
				pub tx_id: transaction_executed::TxId,
				pub result: transaction_executed::Result,
			}
			pub mod transaction_executed {
				use super::runtime_types;
				pub type TxId = ::subxt::ext::subxt_core::utils::H256;
				pub type Result = ::core::result::Result<
					runtime_types::frame_support::dispatch::PostDispatchInfo,
					runtime_types::sp_runtime::DispatchErrorWithPostInfo<
						runtime_types::frame_support::dispatch::PostDispatchInfo,
					>,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TransactionExecuted {
				const PALLET: &'static str = "ReversibleTransfers";
				const EVENT: &'static str = "TransactionExecuted";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod high_security_accounts {
					use super::runtime_types;
					pub type HighSecurityAccounts =
						runtime_types::pallet_reversible_transfers::HighSecurityAccountData<
							::subxt::ext::subxt_core::utils::AccountId32,
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
						>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod pending_transfers {
					use super::runtime_types;
					pub type PendingTransfers =
						runtime_types::pallet_reversible_transfers::PendingTransfer<
							::subxt::ext::subxt_core::utils::AccountId32,
							::core::primitive::u128,
							runtime_types::frame_support::traits::preimages::Bounded<
								runtime_types::quantus_runtime::RuntimeCall,
								runtime_types::poseidon_resonance::PoseidonHasher,
							>,
						>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::H256;
				}
				pub mod account_pending_index {
					use super::runtime_types;
					pub type AccountPendingIndex = ::core::primitive::u32;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod pending_transfers_by_sender {
					use super::runtime_types;
					pub type PendingTransfersBySender =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::subxt::ext::subxt_core::utils::H256,
						>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod pending_transfers_by_recipient {
					use super::runtime_types;
					pub type PendingTransfersByRecipient =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::subxt::ext::subxt_core::utils::H256,
						>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod interceptor_index {
					use super::runtime_types;
					pub type InterceptorIndex =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::subxt::ext::subxt_core::utils::AccountId32,
						>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod global_nonce {
					use super::runtime_types;
					pub type GlobalNonce = ::core::primitive::u64;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " Maps accounts to their chosen reversibility delay period (in milliseconds)."]
				#[doc = " Accounts present in this map have reversibility enabled."]
				pub fn high_security_accounts_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::high_security_accounts::HighSecurityAccounts,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"HighSecurityAccounts",
						(),
						[
							11u8, 143u8, 95u8, 23u8, 55u8, 163u8, 22u8, 238u8, 88u8, 24u8, 50u8,
							162u8, 72u8, 98u8, 32u8, 219u8, 231u8, 199u8, 118u8, 150u8, 84u8,
							126u8, 225u8, 88u8, 129u8, 200u8, 236u8, 214u8, 187u8, 8u8, 252u8,
							120u8,
						],
					)
				}
				#[doc = " Maps accounts to their chosen reversibility delay period (in milliseconds)."]
				#[doc = " Accounts present in this map have reversibility enabled."]
				pub fn high_security_accounts(
					&self,
					_0: types::high_security_accounts::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::high_security_accounts::Param0,
					>,
					types::high_security_accounts::HighSecurityAccounts,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"HighSecurityAccounts",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							11u8, 143u8, 95u8, 23u8, 55u8, 163u8, 22u8, 238u8, 88u8, 24u8, 50u8,
							162u8, 72u8, 98u8, 32u8, 219u8, 231u8, 199u8, 118u8, 150u8, 84u8,
							126u8, 225u8, 88u8, 129u8, 200u8, 236u8, 214u8, 187u8, 8u8, 252u8,
							120u8,
						],
					)
				}
				#[doc = " Stores the details of pending transactions scheduled for delayed execution."]
				#[doc = " Keyed by the unique transaction ID."]
				pub fn pending_transfers_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::pending_transfers::PendingTransfers,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"PendingTransfers",
						(),
						[
							226u8, 148u8, 100u8, 60u8, 9u8, 160u8, 164u8, 177u8, 53u8, 236u8, 65u8,
							38u8, 207u8, 31u8, 170u8, 79u8, 15u8, 237u8, 127u8, 189u8, 203u8,
							147u8, 4u8, 146u8, 13u8, 87u8, 158u8, 163u8, 159u8, 87u8, 98u8, 211u8,
						],
					)
				}
				#[doc = " Stores the details of pending transactions scheduled for delayed execution."]
				#[doc = " Keyed by the unique transaction ID."]
				pub fn pending_transfers(
					&self,
					_0: types::pending_transfers::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::pending_transfers::Param0,
					>,
					types::pending_transfers::PendingTransfers,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"PendingTransfers",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							226u8, 148u8, 100u8, 60u8, 9u8, 160u8, 164u8, 177u8, 53u8, 236u8, 65u8,
							38u8, 207u8, 31u8, 170u8, 79u8, 15u8, 237u8, 127u8, 189u8, 203u8,
							147u8, 4u8, 146u8, 13u8, 87u8, 158u8, 163u8, 159u8, 87u8, 98u8, 211u8,
						],
					)
				}
				#[doc = " Indexes pending transaction IDs per account for efficient lookup and cancellation."]
				#[doc = " Also enforces the maximum pending transactions limit per account."]
				pub fn account_pending_index_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::account_pending_index::AccountPendingIndex,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"AccountPendingIndex",
						(),
						[
							142u8, 255u8, 15u8, 41u8, 210u8, 84u8, 93u8, 230u8, 194u8, 31u8, 164u8,
							88u8, 155u8, 106u8, 130u8, 110u8, 199u8, 137u8, 153u8, 99u8, 154u8,
							210u8, 108u8, 136u8, 70u8, 141u8, 242u8, 255u8, 246u8, 19u8, 247u8,
							136u8,
						],
					)
				}
				#[doc = " Indexes pending transaction IDs per account for efficient lookup and cancellation."]
				#[doc = " Also enforces the maximum pending transactions limit per account."]
				pub fn account_pending_index(
					&self,
					_0: types::account_pending_index::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::account_pending_index::Param0,
					>,
					types::account_pending_index::AccountPendingIndex,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"AccountPendingIndex",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							142u8, 255u8, 15u8, 41u8, 210u8, 84u8, 93u8, 230u8, 194u8, 31u8, 164u8,
							88u8, 155u8, 106u8, 130u8, 110u8, 199u8, 137u8, 153u8, 99u8, 154u8,
							210u8, 108u8, 136u8, 70u8, 141u8, 242u8, 255u8, 246u8, 19u8, 247u8,
							136u8,
						],
					)
				}
				#[doc = " Maps sender accounts to their list of pending transaction IDs."]
				#[doc = " This allows users to query all their outgoing pending transfers."]
				pub fn pending_transfers_by_sender_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::pending_transfers_by_sender::PendingTransfersBySender,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"PendingTransfersBySender",
						(),
						[
							183u8, 43u8, 139u8, 203u8, 182u8, 219u8, 60u8, 129u8, 67u8, 30u8, 65u8,
							47u8, 105u8, 196u8, 228u8, 154u8, 26u8, 74u8, 84u8, 72u8, 154u8, 220u8,
							216u8, 134u8, 207u8, 240u8, 7u8, 190u8, 236u8, 242u8, 184u8, 224u8,
						],
					)
				}
				#[doc = " Maps sender accounts to their list of pending transaction IDs."]
				#[doc = " This allows users to query all their outgoing pending transfers."]
				pub fn pending_transfers_by_sender(
					&self,
					_0: types::pending_transfers_by_sender::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::pending_transfers_by_sender::Param0,
					>,
					types::pending_transfers_by_sender::PendingTransfersBySender,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"PendingTransfersBySender",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							183u8, 43u8, 139u8, 203u8, 182u8, 219u8, 60u8, 129u8, 67u8, 30u8, 65u8,
							47u8, 105u8, 196u8, 228u8, 154u8, 26u8, 74u8, 84u8, 72u8, 154u8, 220u8,
							216u8, 134u8, 207u8, 240u8, 7u8, 190u8, 236u8, 242u8, 184u8, 224u8,
						],
					)
				}
				#[doc = " Maps recipient accounts to their list of pending incoming transaction IDs."]
				#[doc = " This allows users to query all their incoming pending transfers."]
				pub fn pending_transfers_by_recipient_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::pending_transfers_by_recipient::PendingTransfersByRecipient,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"PendingTransfersByRecipient",
						(),
						[
							63u8, 141u8, 24u8, 239u8, 201u8, 143u8, 36u8, 152u8, 35u8, 110u8,
							112u8, 157u8, 29u8, 61u8, 221u8, 79u8, 209u8, 192u8, 183u8, 29u8,
							145u8, 166u8, 238u8, 156u8, 131u8, 203u8, 124u8, 233u8, 210u8, 201u8,
							91u8, 212u8,
						],
					)
				}
				#[doc = " Maps recipient accounts to their list of pending incoming transaction IDs."]
				#[doc = " This allows users to query all their incoming pending transfers."]
				pub fn pending_transfers_by_recipient(
					&self,
					_0: types::pending_transfers_by_recipient::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::pending_transfers_by_recipient::Param0,
					>,
					types::pending_transfers_by_recipient::PendingTransfersByRecipient,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"PendingTransfersByRecipient",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							63u8, 141u8, 24u8, 239u8, 201u8, 143u8, 36u8, 152u8, 35u8, 110u8,
							112u8, 157u8, 29u8, 61u8, 221u8, 79u8, 209u8, 192u8, 183u8, 29u8,
							145u8, 166u8, 238u8, 156u8, 131u8, 203u8, 124u8, 233u8, 210u8, 201u8,
							91u8, 212u8,
						],
					)
				}
				#[doc = " Maps interceptor accounts to the list of accounts they can intercept for."]
				#[doc = " This allows the UI to efficiently query all accounts for which a given account is an"]
				#[doc = " interceptor."]
				pub fn interceptor_index_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::interceptor_index::InterceptorIndex,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"InterceptorIndex",
						(),
						[
							7u8, 184u8, 75u8, 107u8, 42u8, 84u8, 188u8, 86u8, 2u8, 227u8, 4u8,
							136u8, 109u8, 69u8, 64u8, 123u8, 253u8, 28u8, 174u8, 121u8, 183u8,
							154u8, 135u8, 91u8, 125u8, 0u8, 58u8, 132u8, 164u8, 236u8, 182u8,
							133u8,
						],
					)
				}
				#[doc = " Maps interceptor accounts to the list of accounts they can intercept for."]
				#[doc = " This allows the UI to efficiently query all accounts for which a given account is an"]
				#[doc = " interceptor."]
				pub fn interceptor_index(
					&self,
					_0: types::interceptor_index::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::interceptor_index::Param0,
					>,
					types::interceptor_index::InterceptorIndex,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"InterceptorIndex",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							7u8, 184u8, 75u8, 107u8, 42u8, 84u8, 188u8, 86u8, 2u8, 227u8, 4u8,
							136u8, 109u8, 69u8, 64u8, 123u8, 253u8, 28u8, 174u8, 121u8, 183u8,
							154u8, 135u8, 91u8, 125u8, 0u8, 58u8, 132u8, 164u8, 236u8, 182u8,
							133u8,
						],
					)
				}
				#[doc = " Global nonce for generating unique transaction IDs."]
				pub fn global_nonce(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::global_nonce::GlobalNonce,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"GlobalNonce",
						(),
						[
							119u8, 119u8, 84u8, 141u8, 83u8, 67u8, 42u8, 83u8, 51u8, 196u8, 185u8,
							39u8, 227u8, 125u8, 142u8, 154u8, 107u8, 62u8, 127u8, 13u8, 54u8,
							114u8, 201u8, 6u8, 100u8, 28u8, 202u8, 152u8, 246u8, 202u8, 9u8, 29u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " Maximum pending reversible transactions allowed per account. Used for BoundedVec."]
				pub fn max_pending_per_account(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"MaxPendingPerAccount",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Maximum number of accounts an interceptor can intercept for. Used for BoundedVec."]
				pub fn max_interceptor_accounts(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"MaxInterceptorAccounts",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The default delay period for reversible transactions if none is specified."]
				#[doc = ""]
				#[doc = " NOTE: default delay is always in blocks."]
				pub fn default_delay(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<
						::core::primitive::u32,
						::core::primitive::u64,
					>,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"DefaultDelay",
						[
							245u8, 29u8, 3u8, 65u8, 154u8, 12u8, 172u8, 71u8, 67u8, 134u8, 71u8,
							180u8, 4u8, 9u8, 54u8, 89u8, 6u8, 19u8, 3u8, 168u8, 67u8, 122u8, 197u8,
							109u8, 1u8, 228u8, 44u8, 243u8, 228u8, 194u8, 241u8, 227u8,
						],
					)
				}
				#[doc = " The minimum delay period allowed for reversible transactions, in blocks."]
				pub fn min_delay_period_blocks(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"MinDelayPeriodBlocks",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The minimum delay period allowed for reversible transactions, in milliseconds."]
				pub fn min_delay_period_moment(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u64,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ReversibleTransfers",
						"MinDelayPeriodMoment",
						[
							128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8,
							59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8,
							103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8,
							246u8,
						],
					)
				}
			}
		}
	}
	pub mod conviction_voting {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_conviction_voting::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_conviction_voting::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Vote in a poll. If `vote.is_aye()`, the vote is to enact the proposal;"]
				#[doc = "otherwise it is a vote to keep the status quo."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `poll_index`: The index of the poll to vote for."]
				#[doc = "- `vote`: The vote configuration."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` where R is the number of polls the voter has voted on."]
				pub struct Vote {
					#[codec(compact)]
					pub poll_index: vote::PollIndex,
					pub vote: vote::Vote,
				}
				pub mod vote {
					use super::runtime_types;
					pub type PollIndex = ::core::primitive::u32;
					pub type Vote = runtime_types::pallet_conviction_voting::vote::AccountVote<
						::core::primitive::u128,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Vote {
					const PALLET: &'static str = "ConvictionVoting";
					const CALL: &'static str = "vote";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Delegate the voting power (with some given conviction) of the sending account for a"]
				#[doc = "particular class of polls."]
				#[doc = ""]
				#[doc = "The balance delegated is locked for as long as it's delegated, and thereafter for the"]
				#[doc = "time appropriate for the conviction's lock period."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_, and the signing account must either:"]
				#[doc = "  - be delegating already; or"]
				#[doc = "  - have no voting activity (if there is, then it will need to be removed through"]
				#[doc = "    `remove_vote`)."]
				#[doc = ""]
				#[doc = "- `to`: The account whose voting the `target` account's voting power will follow."]
				#[doc = "- `class`: The class of polls to delegate. To delegate multiple classes, multiple calls"]
				#[doc = "  to this function are required."]
				#[doc = "- `conviction`: The conviction that will be attached to the delegated votes. When the"]
				#[doc = "  account is undelegated, the funds will be locked for the corresponding period."]
				#[doc = "- `balance`: The amount of the account's balance to be used in delegating. This must not"]
				#[doc = "  be more than the account's current balance."]
				#[doc = ""]
				#[doc = "Emits `Delegated`."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` where R is the number of polls the voter delegating to has"]
				#[doc = "  voted on. Weight is initially charged as if maximum votes, but is refunded later."]
				pub struct Delegate {
					pub class: delegate::Class,
					pub to: delegate::To,
					pub conviction: delegate::Conviction,
					pub balance: delegate::Balance,
				}
				pub mod delegate {
					use super::runtime_types;
					pub type Class = ::core::primitive::u16;
					pub type To = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Conviction =
						runtime_types::pallet_conviction_voting::conviction::Conviction;
					pub type Balance = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Delegate {
					const PALLET: &'static str = "ConvictionVoting";
					const CALL: &'static str = "delegate";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Undelegate the voting power of the sending account for a particular class of polls."]
				#[doc = ""]
				#[doc = "Tokens may be unlocked following once an amount of time consistent with the lock period"]
				#[doc = "of the conviction with which the delegation was issued has passed."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_ and the signing account must be"]
				#[doc = "currently delegating."]
				#[doc = ""]
				#[doc = "- `class`: The class of polls to remove the delegation from."]
				#[doc = ""]
				#[doc = "Emits `Undelegated`."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` where R is the number of polls the voter delegating to has"]
				#[doc = "  voted on. Weight is initially charged as if maximum votes, but is refunded later."]
				pub struct Undelegate {
					pub class: undelegate::Class,
				}
				pub mod undelegate {
					use super::runtime_types;
					pub type Class = ::core::primitive::u16;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Undelegate {
					const PALLET: &'static str = "ConvictionVoting";
					const CALL: &'static str = "undelegate";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Remove the lock caused by prior voting/delegating which has expired within a particular"]
				#[doc = "class."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `class`: The class of polls to unlock."]
				#[doc = "- `target`: The account to remove the lock on."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` with R number of vote of target."]
				pub struct Unlock {
					pub class: unlock::Class,
					pub target: unlock::Target,
				}
				pub mod unlock {
					use super::runtime_types;
					pub type Class = ::core::primitive::u16;
					pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Unlock {
					const PALLET: &'static str = "ConvictionVoting";
					const CALL: &'static str = "unlock";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Remove a vote for a poll."]
				#[doc = ""]
				#[doc = "If:"]
				#[doc = "- the poll was cancelled, or"]
				#[doc = "- the poll is ongoing, or"]
				#[doc = "- the poll has ended such that"]
				#[doc = "  - the vote of the account was in opposition to the result; or"]
				#[doc = "  - there was no conviction to the account's vote; or"]
				#[doc = "  - the account made a split vote"]
				#[doc = "...then the vote is removed cleanly and a following call to `unlock` may result in more"]
				#[doc = "funds being available."]
				#[doc = ""]
				#[doc = "If, however, the poll has ended and:"]
				#[doc = "- it finished corresponding to the vote of the account, and"]
				#[doc = "- the account made a standard vote with conviction, and"]
				#[doc = "- the lock period of the conviction is not over"]
				#[doc = "...then the lock will be aggregated into the overall account's lock, which may involve"]
				#[doc = "*overlocking* (where the two locks are combined into a single lock that is the maximum"]
				#[doc = "of both the amount locked and the time is it locked for)."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_, and the signer must have a vote"]
				#[doc = "registered for poll `index`."]
				#[doc = ""]
				#[doc = "- `index`: The index of poll of the vote to be removed."]
				#[doc = "- `class`: Optional parameter, if given it indicates the class of the poll. For polls"]
				#[doc = "  which have finished or are cancelled, this must be `Some`."]
				#[doc = ""]
				#[doc = "Weight: `O(R + log R)` where R is the number of polls that `target` has voted on."]
				#[doc = "  Weight is calculated for the maximum number of vote."]
				pub struct RemoveVote {
					pub class: remove_vote::Class,
					pub index: remove_vote::Index,
				}
				pub mod remove_vote {
					use super::runtime_types;
					pub type Class = ::core::option::Option<::core::primitive::u16>;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveVote {
					const PALLET: &'static str = "ConvictionVoting";
					const CALL: &'static str = "remove_vote";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Remove a vote for a poll."]
				#[doc = ""]
				#[doc = "If the `target` is equal to the signer, then this function is exactly equivalent to"]
				#[doc = "`remove_vote`. If not equal to the signer, then the vote must have expired,"]
				#[doc = "either because the poll was cancelled, because the voter lost the poll or"]
				#[doc = "because the conviction period is over."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `target`: The account of the vote to be removed; this account must have voted for poll"]
				#[doc = "  `index`."]
				#[doc = "- `index`: The index of poll of the vote to be removed."]
				#[doc = "- `class`: The class of the poll."]
				#[doc = ""]
				#[doc = "Weight: `O(R + log R)` where R is the number of polls that `target` has voted on."]
				#[doc = "  Weight is calculated for the maximum number of vote."]
				pub struct RemoveOtherVote {
					pub target: remove_other_vote::Target,
					pub class: remove_other_vote::Class,
					pub index: remove_other_vote::Index,
				}
				pub mod remove_other_vote {
					use super::runtime_types;
					pub type Target = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Class = ::core::primitive::u16;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveOtherVote {
					const PALLET: &'static str = "ConvictionVoting";
					const CALL: &'static str = "remove_other_vote";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Vote in a poll. If `vote.is_aye()`, the vote is to enact the proposal;"]
				#[doc = "otherwise it is a vote to keep the status quo."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `poll_index`: The index of the poll to vote for."]
				#[doc = "- `vote`: The vote configuration."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` where R is the number of polls the voter has voted on."]
				pub fn vote(
					&self,
					poll_index: types::vote::PollIndex,
					vote: types::vote::Vote,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Vote> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ConvictionVoting",
						"vote",
						types::Vote { poll_index, vote },
						[
							57u8, 170u8, 177u8, 168u8, 158u8, 43u8, 87u8, 242u8, 176u8, 85u8,
							230u8, 64u8, 103u8, 239u8, 190u8, 6u8, 228u8, 165u8, 248u8, 77u8,
							231u8, 221u8, 186u8, 107u8, 249u8, 201u8, 226u8, 52u8, 129u8, 90u8,
							142u8, 159u8,
						],
					)
				}
				#[doc = "Delegate the voting power (with some given conviction) of the sending account for a"]
				#[doc = "particular class of polls."]
				#[doc = ""]
				#[doc = "The balance delegated is locked for as long as it's delegated, and thereafter for the"]
				#[doc = "time appropriate for the conviction's lock period."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_, and the signing account must either:"]
				#[doc = "  - be delegating already; or"]
				#[doc = "  - have no voting activity (if there is, then it will need to be removed through"]
				#[doc = "    `remove_vote`)."]
				#[doc = ""]
				#[doc = "- `to`: The account whose voting the `target` account's voting power will follow."]
				#[doc = "- `class`: The class of polls to delegate. To delegate multiple classes, multiple calls"]
				#[doc = "  to this function are required."]
				#[doc = "- `conviction`: The conviction that will be attached to the delegated votes. When the"]
				#[doc = "  account is undelegated, the funds will be locked for the corresponding period."]
				#[doc = "- `balance`: The amount of the account's balance to be used in delegating. This must not"]
				#[doc = "  be more than the account's current balance."]
				#[doc = ""]
				#[doc = "Emits `Delegated`."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` where R is the number of polls the voter delegating to has"]
				#[doc = "  voted on. Weight is initially charged as if maximum votes, but is refunded later."]
				pub fn delegate(
					&self,
					class: types::delegate::Class,
					to: types::delegate::To,
					conviction: types::delegate::Conviction,
					balance: types::delegate::Balance,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Delegate> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ConvictionVoting",
						"delegate",
						types::Delegate { class, to, conviction, balance },
						[
							223u8, 143u8, 33u8, 94u8, 32u8, 156u8, 43u8, 40u8, 142u8, 134u8, 209u8,
							134u8, 255u8, 179u8, 97u8, 46u8, 8u8, 140u8, 5u8, 29u8, 76u8, 22u8,
							36u8, 7u8, 108u8, 190u8, 220u8, 151u8, 10u8, 47u8, 89u8, 55u8,
						],
					)
				}
				#[doc = "Undelegate the voting power of the sending account for a particular class of polls."]
				#[doc = ""]
				#[doc = "Tokens may be unlocked following once an amount of time consistent with the lock period"]
				#[doc = "of the conviction with which the delegation was issued has passed."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_ and the signing account must be"]
				#[doc = "currently delegating."]
				#[doc = ""]
				#[doc = "- `class`: The class of polls to remove the delegation from."]
				#[doc = ""]
				#[doc = "Emits `Undelegated`."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` where R is the number of polls the voter delegating to has"]
				#[doc = "  voted on. Weight is initially charged as if maximum votes, but is refunded later."]
				pub fn undelegate(
					&self,
					class: types::undelegate::Class,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Undelegate> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ConvictionVoting",
						"undelegate",
						types::Undelegate { class },
						[
							140u8, 232u8, 6u8, 53u8, 228u8, 8u8, 131u8, 144u8, 65u8, 66u8, 245u8,
							247u8, 147u8, 135u8, 198u8, 57u8, 82u8, 212u8, 89u8, 46u8, 236u8,
							168u8, 200u8, 220u8, 93u8, 168u8, 101u8, 29u8, 110u8, 76u8, 67u8,
							181u8,
						],
					)
				}
				#[doc = "Remove the lock caused by prior voting/delegating which has expired within a particular"]
				#[doc = "class."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `class`: The class of polls to unlock."]
				#[doc = "- `target`: The account to remove the lock on."]
				#[doc = ""]
				#[doc = "Weight: `O(R)` with R number of vote of target."]
				pub fn unlock(
					&self,
					class: types::unlock::Class,
					target: types::unlock::Target,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Unlock> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ConvictionVoting",
						"unlock",
						types::Unlock { class, target },
						[
							79u8, 5u8, 252u8, 237u8, 109u8, 238u8, 157u8, 237u8, 125u8, 171u8,
							65u8, 160u8, 102u8, 192u8, 5u8, 141u8, 179u8, 249u8, 253u8, 213u8,
							105u8, 251u8, 241u8, 145u8, 186u8, 177u8, 244u8, 139u8, 71u8, 140u8,
							173u8, 108u8,
						],
					)
				}
				#[doc = "Remove a vote for a poll."]
				#[doc = ""]
				#[doc = "If:"]
				#[doc = "- the poll was cancelled, or"]
				#[doc = "- the poll is ongoing, or"]
				#[doc = "- the poll has ended such that"]
				#[doc = "  - the vote of the account was in opposition to the result; or"]
				#[doc = "  - there was no conviction to the account's vote; or"]
				#[doc = "  - the account made a split vote"]
				#[doc = "...then the vote is removed cleanly and a following call to `unlock` may result in more"]
				#[doc = "funds being available."]
				#[doc = ""]
				#[doc = "If, however, the poll has ended and:"]
				#[doc = "- it finished corresponding to the vote of the account, and"]
				#[doc = "- the account made a standard vote with conviction, and"]
				#[doc = "- the lock period of the conviction is not over"]
				#[doc = "...then the lock will be aggregated into the overall account's lock, which may involve"]
				#[doc = "*overlocking* (where the two locks are combined into a single lock that is the maximum"]
				#[doc = "of both the amount locked and the time is it locked for)."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_, and the signer must have a vote"]
				#[doc = "registered for poll `index`."]
				#[doc = ""]
				#[doc = "- `index`: The index of poll of the vote to be removed."]
				#[doc = "- `class`: Optional parameter, if given it indicates the class of the poll. For polls"]
				#[doc = "  which have finished or are cancelled, this must be `Some`."]
				#[doc = ""]
				#[doc = "Weight: `O(R + log R)` where R is the number of polls that `target` has voted on."]
				#[doc = "  Weight is calculated for the maximum number of vote."]
				pub fn remove_vote(
					&self,
					class: types::remove_vote::Class,
					index: types::remove_vote::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveVote> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ConvictionVoting",
						"remove_vote",
						types::RemoveVote { class, index },
						[
							255u8, 108u8, 211u8, 146u8, 168u8, 231u8, 207u8, 44u8, 76u8, 24u8,
							235u8, 60u8, 23u8, 79u8, 192u8, 192u8, 46u8, 40u8, 134u8, 27u8, 125u8,
							114u8, 125u8, 247u8, 85u8, 102u8, 76u8, 159u8, 34u8, 167u8, 152u8,
							148u8,
						],
					)
				}
				#[doc = "Remove a vote for a poll."]
				#[doc = ""]
				#[doc = "If the `target` is equal to the signer, then this function is exactly equivalent to"]
				#[doc = "`remove_vote`. If not equal to the signer, then the vote must have expired,"]
				#[doc = "either because the poll was cancelled, because the voter lost the poll or"]
				#[doc = "because the conviction period is over."]
				#[doc = ""]
				#[doc = "The dispatch origin of this call must be _Signed_."]
				#[doc = ""]
				#[doc = "- `target`: The account of the vote to be removed; this account must have voted for poll"]
				#[doc = "  `index`."]
				#[doc = "- `index`: The index of poll of the vote to be removed."]
				#[doc = "- `class`: The class of the poll."]
				#[doc = ""]
				#[doc = "Weight: `O(R + log R)` where R is the number of polls that `target` has voted on."]
				#[doc = "  Weight is calculated for the maximum number of vote."]
				pub fn remove_other_vote(
					&self,
					target: types::remove_other_vote::Target,
					class: types::remove_other_vote::Class,
					index: types::remove_other_vote::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveOtherVote>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"ConvictionVoting",
						"remove_other_vote",
						types::RemoveOtherVote { target, class, index },
						[
							165u8, 26u8, 166u8, 37u8, 10u8, 174u8, 243u8, 10u8, 73u8, 93u8, 213u8,
							69u8, 200u8, 16u8, 48u8, 146u8, 160u8, 92u8, 28u8, 26u8, 158u8, 55u8,
							6u8, 251u8, 36u8, 132u8, 46u8, 195u8, 107u8, 34u8, 0u8, 100u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_conviction_voting::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An account has delegated their vote to another account. \\[who, target\\]"]
			pub struct Delegated(pub delegated::Field0, pub delegated::Field1);
			pub mod delegated {
				use super::runtime_types;
				pub type Field0 = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Field1 = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Delegated {
				const PALLET: &'static str = "ConvictionVoting";
				const EVENT: &'static str = "Delegated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An \\[account\\] has cancelled a previous delegation operation."]
			pub struct Undelegated(pub undelegated::Field0);
			pub mod undelegated {
				use super::runtime_types;
				pub type Field0 = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Undelegated {
				const PALLET: &'static str = "ConvictionVoting";
				const EVENT: &'static str = "Undelegated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An account has voted"]
			pub struct Voted {
				pub who: voted::Who,
				pub vote: voted::Vote,
			}
			pub mod voted {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Vote = runtime_types::pallet_conviction_voting::vote::AccountVote<
					::core::primitive::u128,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Voted {
				const PALLET: &'static str = "ConvictionVoting";
				const EVENT: &'static str = "Voted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A vote has been removed"]
			pub struct VoteRemoved {
				pub who: vote_removed::Who,
				pub vote: vote_removed::Vote,
			}
			pub mod vote_removed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Vote = runtime_types::pallet_conviction_voting::vote::AccountVote<
					::core::primitive::u128,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for VoteRemoved {
				const PALLET: &'static str = "ConvictionVoting";
				const EVENT: &'static str = "VoteRemoved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The lockup period of a conviction vote expired, and the funds have been unlocked."]
			pub struct VoteUnlocked {
				pub who: vote_unlocked::Who,
				pub class: vote_unlocked::Class,
			}
			pub mod vote_unlocked {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Class = ::core::primitive::u16;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for VoteUnlocked {
				const PALLET: &'static str = "ConvictionVoting";
				const EVENT: &'static str = "VoteUnlocked";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod voting_for {
					use super::runtime_types;
					pub type VotingFor = runtime_types::pallet_conviction_voting::vote::Voting<
						::core::primitive::u128,
						::subxt::ext::subxt_core::utils::AccountId32,
						::core::primitive::u32,
						::core::primitive::u32,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
					pub type Param1 = ::core::primitive::u16;
				}
				pub mod class_locks_for {
					use super::runtime_types;
					pub type ClassLocksFor =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<(
							::core::primitive::u16,
							::core::primitive::u128,
						)>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " All voting for a particular voter in a particular voting class. We store the balance for the"]
				#[doc = " number of votes that we have recorded."]
				pub fn voting_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::voting_for::VotingFor,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ConvictionVoting",
						"VotingFor",
						(),
						[
							76u8, 63u8, 153u8, 193u8, 39u8, 137u8, 186u8, 29u8, 202u8, 56u8, 169u8,
							56u8, 103u8, 138u8, 192u8, 18u8, 179u8, 114u8, 56u8, 121u8, 197u8,
							12u8, 29u8, 239u8, 220u8, 231u8, 24u8, 46u8, 134u8, 99u8, 53u8, 206u8,
						],
					)
				}
				#[doc = " All voting for a particular voter in a particular voting class. We store the balance for the"]
				#[doc = " number of votes that we have recorded."]
				pub fn voting_for_iter1(
					&self,
					_0: types::voting_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::voting_for::Param0,
					>,
					types::voting_for::VotingFor,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ConvictionVoting",
						"VotingFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							76u8, 63u8, 153u8, 193u8, 39u8, 137u8, 186u8, 29u8, 202u8, 56u8, 169u8,
							56u8, 103u8, 138u8, 192u8, 18u8, 179u8, 114u8, 56u8, 121u8, 197u8,
							12u8, 29u8, 239u8, 220u8, 231u8, 24u8, 46u8, 134u8, 99u8, 53u8, 206u8,
						],
					)
				}
				#[doc = " All voting for a particular voter in a particular voting class. We store the balance for the"]
				#[doc = " number of votes that we have recorded."]
				pub fn voting_for(
					&self,
					_0: types::voting_for::Param0,
					_1: types::voting_for::Param1,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::voting_for::Param0,
						>,
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::voting_for::Param1,
						>,
					),
					types::voting_for::VotingFor,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ConvictionVoting",
						"VotingFor",
						(
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1),
						),
						[
							76u8, 63u8, 153u8, 193u8, 39u8, 137u8, 186u8, 29u8, 202u8, 56u8, 169u8,
							56u8, 103u8, 138u8, 192u8, 18u8, 179u8, 114u8, 56u8, 121u8, 197u8,
							12u8, 29u8, 239u8, 220u8, 231u8, 24u8, 46u8, 134u8, 99u8, 53u8, 206u8,
						],
					)
				}
				#[doc = " The voting classes which have a non-zero lock requirement and the lock amounts which they"]
				#[doc = " require. The actual amount locked on behalf of this pallet should always be the maximum of"]
				#[doc = " this list."]
				pub fn class_locks_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::class_locks_for::ClassLocksFor,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ConvictionVoting",
						"ClassLocksFor",
						(),
						[
							74u8, 74u8, 8u8, 82u8, 215u8, 61u8, 13u8, 9u8, 44u8, 222u8, 33u8,
							245u8, 195u8, 124u8, 6u8, 174u8, 65u8, 245u8, 71u8, 42u8, 47u8, 46u8,
							164u8, 231u8, 11u8, 245u8, 115u8, 207u8, 209u8, 137u8, 90u8, 6u8,
						],
					)
				}
				#[doc = " The voting classes which have a non-zero lock requirement and the lock amounts which they"]
				#[doc = " require. The actual amount locked on behalf of this pallet should always be the maximum of"]
				#[doc = " this list."]
				pub fn class_locks_for(
					&self,
					_0: types::class_locks_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::class_locks_for::Param0,
					>,
					types::class_locks_for::ClassLocksFor,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"ConvictionVoting",
						"ClassLocksFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							74u8, 74u8, 8u8, 82u8, 215u8, 61u8, 13u8, 9u8, 44u8, 222u8, 33u8,
							245u8, 195u8, 124u8, 6u8, 174u8, 65u8, 245u8, 71u8, 42u8, 47u8, 46u8,
							164u8, 231u8, 11u8, 245u8, 115u8, 207u8, 209u8, 137u8, 90u8, 6u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The maximum number of concurrent votes an account may have."]
				#[doc = ""]
				#[doc = " Also used to compute weight, an overly large value can lead to extrinsics with large"]
				#[doc = " weight estimation: see `delegate` for instance."]
				pub fn max_votes(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ConvictionVoting",
						"MaxVotes",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The minimum period of vote locking."]
				#[doc = ""]
				#[doc = " It should be no shorter than enactment period to ensure that in the case of an approval,"]
				#[doc = " those successful voters are locked into the consequences that their votes entail."]
				pub fn vote_locking_period(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"ConvictionVoting",
						"VoteLockingPeriod",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
			}
		}
	}
	pub mod tech_collective {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_ranked_collective::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_ranked_collective::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Introduce a new member."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `AddOrigin`."]
				#[doc = "- `who`: Account of non-member which will become a member."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`"]
				pub struct AddMember {
					pub who: add_member::Who,
				}
				pub mod add_member {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AddMember {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "add_member";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Increment the rank of an existing member by one."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `PromoteOrigin`."]
				#[doc = "- `who`: Account of existing member."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`"]
				pub struct PromoteMember {
					pub who: promote_member::Who,
				}
				pub mod promote_member {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for PromoteMember {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "promote_member";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Decrement the rank of an existing member by one. If the member is already at rank zero,"]
				#[doc = "then they are removed entirely."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `DemoteOrigin`."]
				#[doc = "- `who`: Account of existing member of rank greater than zero."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`, less if the member's index is highest in its rank."]
				pub struct DemoteMember {
					pub who: demote_member::Who,
				}
				pub mod demote_member {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for DemoteMember {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "demote_member";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Remove the member entirely."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `RemoveOrigin`."]
				#[doc = "- `who`: Account of existing member of rank greater than zero."]
				#[doc = "- `min_rank`: The rank of the member or greater."]
				#[doc = ""]
				#[doc = "Weight: `O(min_rank)`."]
				pub struct RemoveMember {
					pub who: remove_member::Who,
					pub min_rank: remove_member::MinRank,
				}
				pub mod remove_member {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type MinRank = ::core::primitive::u16;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveMember {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "remove_member";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Add an aye or nay vote for the sender to the given proposal."]
				#[doc = ""]
				#[doc = "- `origin`: Must be `Signed` by a member account."]
				#[doc = "- `poll`: Index of a poll which is ongoing."]
				#[doc = "- `aye`: `true` if the vote is to approve the proposal, `false` otherwise."]
				#[doc = ""]
				#[doc = "Transaction fees are be waived if the member is voting on any particular proposal"]
				#[doc = "for the first time and the call is successful. Subsequent vote changes will charge a"]
				#[doc = "fee."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`, less if there was no previous vote on the poll by the member."]
				pub struct Vote {
					pub poll: vote::Poll,
					pub aye: vote::Aye,
				}
				pub mod vote {
					use super::runtime_types;
					pub type Poll = ::core::primitive::u32;
					pub type Aye = ::core::primitive::bool;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Vote {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "vote";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Remove votes from the given poll. It must have ended."]
				#[doc = ""]
				#[doc = "- `origin`: Must be `Signed` by any account."]
				#[doc = "- `poll_index`: Index of a poll which is completed and for which votes continue to"]
				#[doc = "  exist."]
				#[doc = "- `max`: Maximum number of vote items from remove in this call."]
				#[doc = ""]
				#[doc = "Transaction fees are waived if the operation is successful."]
				#[doc = ""]
				#[doc = "Weight `O(max)` (less if there are fewer items to remove than `max`)."]
				pub struct CleanupPoll {
					pub poll_index: cleanup_poll::PollIndex,
					pub max: cleanup_poll::Max,
				}
				pub mod cleanup_poll {
					use super::runtime_types;
					pub type PollIndex = ::core::primitive::u32;
					pub type Max = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CleanupPoll {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "cleanup_poll";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Exchanges a member with a new account and the same existing rank."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `ExchangeOrigin`."]
				#[doc = "- `who`: Account of existing member of rank greater than zero to be exchanged."]
				#[doc = "- `new_who`: New Account of existing member of rank greater than zero to exchanged to."]
				pub struct ExchangeMember {
					pub who: exchange_member::Who,
					pub new_who: exchange_member::NewWho,
				}
				pub mod exchange_member {
					use super::runtime_types;
					pub type Who = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type NewWho = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ExchangeMember {
					const PALLET: &'static str = "TechCollective";
					const CALL: &'static str = "exchange_member";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Introduce a new member."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `AddOrigin`."]
				#[doc = "- `who`: Account of non-member which will become a member."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`"]
				pub fn add_member(
					&self,
					who: types::add_member::Who,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AddMember> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"add_member",
						types::AddMember { who },
						[
							2u8, 131u8, 37u8, 217u8, 112u8, 46u8, 86u8, 165u8, 248u8, 244u8, 33u8,
							236u8, 155u8, 28u8, 163u8, 169u8, 213u8, 32u8, 70u8, 217u8, 97u8,
							194u8, 138u8, 77u8, 133u8, 97u8, 188u8, 49u8, 49u8, 31u8, 177u8, 206u8,
						],
					)
				}
				#[doc = "Increment the rank of an existing member by one."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `PromoteOrigin`."]
				#[doc = "- `who`: Account of existing member."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`"]
				pub fn promote_member(
					&self,
					who: types::promote_member::Who,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::PromoteMember>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"promote_member",
						types::PromoteMember { who },
						[
							169u8, 155u8, 9u8, 50u8, 144u8, 133u8, 230u8, 60u8, 216u8, 147u8, 3u8,
							236u8, 94u8, 185u8, 106u8, 139u8, 235u8, 143u8, 189u8, 135u8, 208u8,
							176u8, 126u8, 124u8, 85u8, 140u8, 189u8, 125u8, 87u8, 56u8, 57u8,
							246u8,
						],
					)
				}
				#[doc = "Decrement the rank of an existing member by one. If the member is already at rank zero,"]
				#[doc = "then they are removed entirely."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `DemoteOrigin`."]
				#[doc = "- `who`: Account of existing member of rank greater than zero."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`, less if the member's index is highest in its rank."]
				pub fn demote_member(
					&self,
					who: types::demote_member::Who,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::DemoteMember> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"demote_member",
						types::DemoteMember { who },
						[
							21u8, 185u8, 71u8, 166u8, 106u8, 88u8, 74u8, 251u8, 78u8, 28u8, 205u8,
							171u8, 199u8, 195u8, 97u8, 149u8, 175u8, 229u8, 25u8, 113u8, 96u8,
							25u8, 240u8, 64u8, 109u8, 246u8, 203u8, 45u8, 110u8, 205u8, 115u8,
							178u8,
						],
					)
				}
				#[doc = "Remove the member entirely."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `RemoveOrigin`."]
				#[doc = "- `who`: Account of existing member of rank greater than zero."]
				#[doc = "- `min_rank`: The rank of the member or greater."]
				#[doc = ""]
				#[doc = "Weight: `O(min_rank)`."]
				pub fn remove_member(
					&self,
					who: types::remove_member::Who,
					min_rank: types::remove_member::MinRank,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveMember> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"remove_member",
						types::RemoveMember { who, min_rank },
						[
							23u8, 156u8, 32u8, 64u8, 158u8, 50u8, 64u8, 199u8, 108u8, 67u8, 133u8,
							128u8, 138u8, 241u8, 14u8, 238u8, 192u8, 173u8, 250u8, 11u8, 124u8,
							119u8, 177u8, 190u8, 152u8, 116u8, 134u8, 42u8, 216u8, 49u8, 113u8,
							49u8,
						],
					)
				}
				#[doc = "Add an aye or nay vote for the sender to the given proposal."]
				#[doc = ""]
				#[doc = "- `origin`: Must be `Signed` by a member account."]
				#[doc = "- `poll`: Index of a poll which is ongoing."]
				#[doc = "- `aye`: `true` if the vote is to approve the proposal, `false` otherwise."]
				#[doc = ""]
				#[doc = "Transaction fees are be waived if the member is voting on any particular proposal"]
				#[doc = "for the first time and the call is successful. Subsequent vote changes will charge a"]
				#[doc = "fee."]
				#[doc = ""]
				#[doc = "Weight: `O(1)`, less if there was no previous vote on the poll by the member."]
				pub fn vote(
					&self,
					poll: types::vote::Poll,
					aye: types::vote::Aye,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Vote> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"vote",
						types::Vote { poll, aye },
						[
							54u8, 116u8, 81u8, 239u8, 223u8, 35u8, 11u8, 244u8, 245u8, 94u8, 23u8,
							241u8, 125u8, 231u8, 56u8, 150u8, 105u8, 125u8, 100u8, 171u8, 182u8,
							186u8, 134u8, 40u8, 4u8, 121u8, 119u8, 11u8, 93u8, 158u8, 59u8, 209u8,
						],
					)
				}
				#[doc = "Remove votes from the given poll. It must have ended."]
				#[doc = ""]
				#[doc = "- `origin`: Must be `Signed` by any account."]
				#[doc = "- `poll_index`: Index of a poll which is completed and for which votes continue to"]
				#[doc = "  exist."]
				#[doc = "- `max`: Maximum number of vote items from remove in this call."]
				#[doc = ""]
				#[doc = "Transaction fees are waived if the operation is successful."]
				#[doc = ""]
				#[doc = "Weight `O(max)` (less if there are fewer items to remove than `max`)."]
				pub fn cleanup_poll(
					&self,
					poll_index: types::cleanup_poll::PollIndex,
					max: types::cleanup_poll::Max,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CleanupPoll> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"cleanup_poll",
						types::CleanupPoll { poll_index, max },
						[
							157u8, 109u8, 86u8, 253u8, 62u8, 107u8, 235u8, 255u8, 171u8, 68u8,
							103u8, 92u8, 245u8, 25u8, 252u8, 158u8, 174u8, 137u8, 77u8, 251u8,
							105u8, 113u8, 165u8, 46u8, 39u8, 55u8, 166u8, 79u8, 103u8, 81u8, 121u8,
							37u8,
						],
					)
				}
				#[doc = "Exchanges a member with a new account and the same existing rank."]
				#[doc = ""]
				#[doc = "- `origin`: Must be the `ExchangeOrigin`."]
				#[doc = "- `who`: Account of existing member of rank greater than zero to be exchanged."]
				#[doc = "- `new_who`: New Account of existing member of rank greater than zero to exchanged to."]
				pub fn exchange_member(
					&self,
					who: types::exchange_member::Who,
					new_who: types::exchange_member::NewWho,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ExchangeMember>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechCollective",
						"exchange_member",
						types::ExchangeMember { who, new_who },
						[
							240u8, 208u8, 76u8, 147u8, 117u8, 23u8, 91u8, 37u8, 22u8, 101u8, 53u8,
							247u8, 161u8, 94u8, 109u8, 233u8, 104u8, 129u8, 67u8, 31u8, 223u8,
							182u8, 50u8, 233u8, 120u8, 129u8, 224u8, 135u8, 52u8, 162u8, 26u8,
							189u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_ranked_collective::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A member `who` has been added."]
			pub struct MemberAdded {
				pub who: member_added::Who,
			}
			pub mod member_added {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MemberAdded {
				const PALLET: &'static str = "TechCollective";
				const EVENT: &'static str = "MemberAdded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The member `who`se rank has been changed to the given `rank`."]
			pub struct RankChanged {
				pub who: rank_changed::Who,
				pub rank: rank_changed::Rank,
			}
			pub mod rank_changed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Rank = ::core::primitive::u16;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RankChanged {
				const PALLET: &'static str = "TechCollective";
				const EVENT: &'static str = "RankChanged";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The member `who` of given `rank` has been removed from the collective."]
			pub struct MemberRemoved {
				pub who: member_removed::Who,
				pub rank: member_removed::Rank,
			}
			pub mod member_removed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Rank = ::core::primitive::u16;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MemberRemoved {
				const PALLET: &'static str = "TechCollective";
				const EVENT: &'static str = "MemberRemoved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The member `who` has voted for the `poll` with the given `vote` leading to an updated"]
			#[doc = "`tally`."]
			pub struct Voted {
				pub who: voted::Who,
				pub poll: voted::Poll,
				pub vote: voted::Vote,
				pub tally: voted::Tally,
			}
			pub mod voted {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Poll = ::core::primitive::u32;
				pub type Vote = runtime_types::pallet_ranked_collective::VoteRecord;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Voted {
				const PALLET: &'static str = "TechCollective";
				const EVENT: &'static str = "Voted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The member `who` had their `AccountId` changed to `new_who`."]
			pub struct MemberExchanged {
				pub who: member_exchanged::Who,
				pub new_who: member_exchanged::NewWho,
			}
			pub mod member_exchanged {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type NewWho = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MemberExchanged {
				const PALLET: &'static str = "TechCollective";
				const EVENT: &'static str = "MemberExchanged";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod member_count {
					use super::runtime_types;
					pub type MemberCount = ::core::primitive::u32;
					pub type Param0 = ::core::primitive::u16;
				}
				pub mod members {
					use super::runtime_types;
					pub type Members = runtime_types::pallet_ranked_collective::MemberRecord;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod id_to_index {
					use super::runtime_types;
					pub type IdToIndex = ::core::primitive::u32;
					pub type Param0 = ::core::primitive::u16;
					pub type Param1 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod index_to_id {
					use super::runtime_types;
					pub type IndexToId = ::subxt::ext::subxt_core::utils::AccountId32;
					pub type Param0 = ::core::primitive::u16;
					pub type Param1 = ::core::primitive::u32;
				}
				pub mod voting {
					use super::runtime_types;
					pub type Voting = runtime_types::pallet_ranked_collective::VoteRecord;
					pub type Param0 = ::core::primitive::u32;
					pub type Param1 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod voting_cleanup {
					use super::runtime_types;
					pub type VotingCleanup =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::core::primitive::u8,
						>;
					pub type Param0 = ::core::primitive::u32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The number of members in the collective who have at least the rank according to the index"]
				#[doc = " of the vec."]
				pub fn member_count_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::member_count::MemberCount,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"MemberCount",
						(),
						[
							0u8, 141u8, 66u8, 91u8, 155u8, 74u8, 17u8, 191u8, 143u8, 41u8, 231u8,
							56u8, 123u8, 219u8, 145u8, 27u8, 197u8, 62u8, 118u8, 237u8, 30u8, 7u8,
							107u8, 96u8, 95u8, 17u8, 242u8, 206u8, 246u8, 79u8, 53u8, 214u8,
						],
					)
				}
				#[doc = " The number of members in the collective who have at least the rank according to the index"]
				#[doc = " of the vec."]
				pub fn member_count(
					&self,
					_0: types::member_count::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::member_count::Param0,
					>,
					types::member_count::MemberCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"MemberCount",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							0u8, 141u8, 66u8, 91u8, 155u8, 74u8, 17u8, 191u8, 143u8, 41u8, 231u8,
							56u8, 123u8, 219u8, 145u8, 27u8, 197u8, 62u8, 118u8, 237u8, 30u8, 7u8,
							107u8, 96u8, 95u8, 17u8, 242u8, 206u8, 246u8, 79u8, 53u8, 214u8,
						],
					)
				}
				#[doc = " The current members of the collective."]
				pub fn members_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::members::Members,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"Members",
						(),
						[
							101u8, 183u8, 36u8, 241u8, 67u8, 8u8, 252u8, 116u8, 110u8, 153u8,
							117u8, 210u8, 128u8, 80u8, 130u8, 163u8, 38u8, 76u8, 230u8, 107u8,
							112u8, 90u8, 102u8, 24u8, 217u8, 2u8, 244u8, 197u8, 103u8, 215u8,
							247u8, 133u8,
						],
					)
				}
				#[doc = " The current members of the collective."]
				pub fn members(
					&self,
					_0: types::members::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::members::Param0,
					>,
					types::members::Members,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"Members",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							101u8, 183u8, 36u8, 241u8, 67u8, 8u8, 252u8, 116u8, 110u8, 153u8,
							117u8, 210u8, 128u8, 80u8, 130u8, 163u8, 38u8, 76u8, 230u8, 107u8,
							112u8, 90u8, 102u8, 24u8, 217u8, 2u8, 244u8, 197u8, 103u8, 215u8,
							247u8, 133u8,
						],
					)
				}
				#[doc = " The index of each ranks's member into the group of members who have at least that rank."]
				pub fn id_to_index_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::id_to_index::IdToIndex,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"IdToIndex",
						(),
						[
							121u8, 225u8, 69u8, 131u8, 194u8, 3u8, 82u8, 27u8, 129u8, 152u8, 157u8,
							45u8, 39u8, 47u8, 166u8, 28u8, 42u8, 92u8, 217u8, 189u8, 160u8, 102u8,
							153u8, 196u8, 94u8, 48u8, 248u8, 113u8, 164u8, 111u8, 27u8, 9u8,
						],
					)
				}
				#[doc = " The index of each ranks's member into the group of members who have at least that rank."]
				pub fn id_to_index_iter1(
					&self,
					_0: types::id_to_index::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::id_to_index::Param0,
					>,
					types::id_to_index::IdToIndex,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"IdToIndex",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							121u8, 225u8, 69u8, 131u8, 194u8, 3u8, 82u8, 27u8, 129u8, 152u8, 157u8,
							45u8, 39u8, 47u8, 166u8, 28u8, 42u8, 92u8, 217u8, 189u8, 160u8, 102u8,
							153u8, 196u8, 94u8, 48u8, 248u8, 113u8, 164u8, 111u8, 27u8, 9u8,
						],
					)
				}
				#[doc = " The index of each ranks's member into the group of members who have at least that rank."]
				pub fn id_to_index(
					&self,
					_0: types::id_to_index::Param0,
					_1: types::id_to_index::Param1,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::id_to_index::Param0,
						>,
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::id_to_index::Param1,
						>,
					),
					types::id_to_index::IdToIndex,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"IdToIndex",
						(
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1),
						),
						[
							121u8, 225u8, 69u8, 131u8, 194u8, 3u8, 82u8, 27u8, 129u8, 152u8, 157u8,
							45u8, 39u8, 47u8, 166u8, 28u8, 42u8, 92u8, 217u8, 189u8, 160u8, 102u8,
							153u8, 196u8, 94u8, 48u8, 248u8, 113u8, 164u8, 111u8, 27u8, 9u8,
						],
					)
				}
				#[doc = " The members in the collective by index. All indices in the range `0..MemberCount` will"]
				#[doc = " return `Some`, however a member's index is not guaranteed to remain unchanged over time."]
				pub fn index_to_id_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::index_to_id::IndexToId,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"IndexToId",
						(),
						[
							110u8, 48u8, 214u8, 224u8, 56u8, 195u8, 186u8, 24u8, 111u8, 37u8, 15u8,
							153u8, 245u8, 101u8, 229u8, 149u8, 216u8, 185u8, 7u8, 242u8, 196u8,
							29u8, 205u8, 243u8, 162u8, 92u8, 71u8, 253u8, 102u8, 152u8, 137u8,
							70u8,
						],
					)
				}
				#[doc = " The members in the collective by index. All indices in the range `0..MemberCount` will"]
				#[doc = " return `Some`, however a member's index is not guaranteed to remain unchanged over time."]
				pub fn index_to_id_iter1(
					&self,
					_0: types::index_to_id::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::index_to_id::Param0,
					>,
					types::index_to_id::IndexToId,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"IndexToId",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							110u8, 48u8, 214u8, 224u8, 56u8, 195u8, 186u8, 24u8, 111u8, 37u8, 15u8,
							153u8, 245u8, 101u8, 229u8, 149u8, 216u8, 185u8, 7u8, 242u8, 196u8,
							29u8, 205u8, 243u8, 162u8, 92u8, 71u8, 253u8, 102u8, 152u8, 137u8,
							70u8,
						],
					)
				}
				#[doc = " The members in the collective by index. All indices in the range `0..MemberCount` will"]
				#[doc = " return `Some`, however a member's index is not guaranteed to remain unchanged over time."]
				pub fn index_to_id(
					&self,
					_0: types::index_to_id::Param0,
					_1: types::index_to_id::Param1,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::index_to_id::Param0,
						>,
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::index_to_id::Param1,
						>,
					),
					types::index_to_id::IndexToId,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"IndexToId",
						(
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1),
						),
						[
							110u8, 48u8, 214u8, 224u8, 56u8, 195u8, 186u8, 24u8, 111u8, 37u8, 15u8,
							153u8, 245u8, 101u8, 229u8, 149u8, 216u8, 185u8, 7u8, 242u8, 196u8,
							29u8, 205u8, 243u8, 162u8, 92u8, 71u8, 253u8, 102u8, 152u8, 137u8,
							70u8,
						],
					)
				}
				#[doc = " Votes on a given proposal, if it is ongoing."]
				pub fn voting_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::voting::Voting,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"Voting",
						(),
						[
							180u8, 146u8, 236u8, 178u8, 30u8, 50u8, 161u8, 50u8, 140u8, 110u8,
							220u8, 1u8, 109u8, 209u8, 17u8, 94u8, 234u8, 223u8, 222u8, 177u8,
							243u8, 194u8, 246u8, 48u8, 178u8, 86u8, 30u8, 185u8, 56u8, 206u8,
							175u8, 18u8,
						],
					)
				}
				#[doc = " Votes on a given proposal, if it is ongoing."]
				pub fn voting_iter1(
					&self,
					_0: types::voting::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::voting::Param0,
					>,
					types::voting::Voting,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"Voting",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							180u8, 146u8, 236u8, 178u8, 30u8, 50u8, 161u8, 50u8, 140u8, 110u8,
							220u8, 1u8, 109u8, 209u8, 17u8, 94u8, 234u8, 223u8, 222u8, 177u8,
							243u8, 194u8, 246u8, 48u8, 178u8, 86u8, 30u8, 185u8, 56u8, 206u8,
							175u8, 18u8,
						],
					)
				}
				#[doc = " Votes on a given proposal, if it is ongoing."]
				pub fn voting(
					&self,
					_0: types::voting::Param0,
					_1: types::voting::Param1,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::voting::Param0,
						>,
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::voting::Param1,
						>,
					),
					types::voting::Voting,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"Voting",
						(
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1),
						),
						[
							180u8, 146u8, 236u8, 178u8, 30u8, 50u8, 161u8, 50u8, 140u8, 110u8,
							220u8, 1u8, 109u8, 209u8, 17u8, 94u8, 234u8, 223u8, 222u8, 177u8,
							243u8, 194u8, 246u8, 48u8, 178u8, 86u8, 30u8, 185u8, 56u8, 206u8,
							175u8, 18u8,
						],
					)
				}
				pub fn voting_cleanup_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::voting_cleanup::VotingCleanup,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"VotingCleanup",
						(),
						[
							223u8, 130u8, 79u8, 104u8, 94u8, 221u8, 222u8, 72u8, 187u8, 95u8,
							231u8, 59u8, 28u8, 119u8, 191u8, 63u8, 40u8, 186u8, 58u8, 254u8, 14u8,
							233u8, 152u8, 36u8, 2u8, 231u8, 120u8, 13u8, 120u8, 211u8, 232u8, 11u8,
						],
					)
				}
				pub fn voting_cleanup(
					&self,
					_0: types::voting_cleanup::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::voting_cleanup::Param0,
					>,
					types::voting_cleanup::VotingCleanup,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechCollective",
						"VotingCleanup",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							223u8, 130u8, 79u8, 104u8, 94u8, 221u8, 222u8, 72u8, 187u8, 95u8,
							231u8, 59u8, 28u8, 119u8, 191u8, 63u8, 40u8, 186u8, 58u8, 254u8, 14u8,
							233u8, 152u8, 36u8, 2u8, 231u8, 120u8, 13u8, 120u8, 211u8, 232u8, 11u8,
						],
					)
				}
			}
		}
	}
	pub mod tech_referenda {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_referenda::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_referenda::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Propose a referendum on a privileged action."]
				#[doc = ""]
				#[doc = "- `origin`: must be `SubmitOrigin` and the account must have `SubmissionDeposit` funds"]
				#[doc = "  available."]
				#[doc = "- `proposal_origin`: The origin from which the proposal should be executed."]
				#[doc = "- `proposal`: The proposal."]
				#[doc = "- `enactment_moment`: The moment that the proposal should be enacted."]
				#[doc = ""]
				#[doc = "Emits `Submitted`."]
				pub struct Submit {
					pub proposal_origin:
						::subxt::ext::subxt_core::alloc::boxed::Box<submit::ProposalOrigin>,
					pub proposal: submit::Proposal,
					pub enactment_moment: submit::EnactmentMoment,
				}
				pub mod submit {
					use super::runtime_types;
					pub type ProposalOrigin = runtime_types::quantus_runtime::OriginCaller;
					pub type Proposal = runtime_types::frame_support::traits::preimages::Bounded<
						runtime_types::quantus_runtime::RuntimeCall,
						runtime_types::poseidon_resonance::PoseidonHasher,
					>;
					pub type EnactmentMoment =
						runtime_types::frame_support::traits::schedule::DispatchTime<
							::core::primitive::u32,
						>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Submit {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "submit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Post the Decision Deposit for a referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` and the account must have funds available for the"]
				#[doc = "  referendum's track's Decision Deposit."]
				#[doc = "- `index`: The index of the submitted referendum whose Decision Deposit is yet to be"]
				#[doc = "  posted."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositPlaced`."]
				pub struct PlaceDecisionDeposit {
					pub index: place_decision_deposit::Index,
				}
				pub mod place_decision_deposit {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for PlaceDecisionDeposit {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "place_decision_deposit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Refund the Decision Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Decision Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositRefunded`."]
				pub struct RefundDecisionDeposit {
					pub index: refund_decision_deposit::Index,
				}
				pub mod refund_decision_deposit {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RefundDecisionDeposit {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "refund_decision_deposit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel an ongoing referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `CancelOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Cancelled`."]
				pub struct Cancel {
					pub index: cancel::Index,
				}
				pub mod cancel {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Cancel {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "cancel";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel an ongoing referendum and slash the deposits."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `KillOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Killed` and `DepositSlashed`."]
				pub struct Kill {
					pub index: kill::Index,
				}
				pub mod kill {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Kill {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "kill";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Advance a referendum onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `index`: the referendum to be advanced."]
				pub struct NudgeReferendum {
					pub index: nudge_referendum::Index,
				}
				pub mod nudge_referendum {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for NudgeReferendum {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "nudge_referendum";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Advance a track onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `track`: the track to be advanced."]
				#[doc = ""]
				#[doc = "Action item for when there is now one fewer referendum in the deciding phase and the"]
				#[doc = "`DecidingCount` is not yet updated. This means that we should either:"]
				#[doc = "- begin deciding another referendum (and leave `DecidingCount` alone); or"]
				#[doc = "- decrement `DecidingCount`."]
				pub struct OneFewerDeciding {
					pub track: one_fewer_deciding::Track,
				}
				pub mod one_fewer_deciding {
					use super::runtime_types;
					pub type Track = ::core::primitive::u16;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for OneFewerDeciding {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "one_fewer_deciding";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Refund the Submission Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Submission Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `SubmissionDepositRefunded`."]
				pub struct RefundSubmissionDeposit {
					pub index: refund_submission_deposit::Index,
				}
				pub mod refund_submission_deposit {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RefundSubmissionDeposit {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "refund_submission_deposit";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Set or clear metadata of a referendum."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `origin`: Must be `Signed` by a creator of a referendum or by anyone to clear a"]
				#[doc = "  metadata of a finished referendum."]
				#[doc = "- `index`:  The index of a referendum to set or clear metadata for."]
				#[doc = "- `maybe_hash`: The hash of an on-chain stored preimage. `None` to clear a metadata."]
				pub struct SetMetadata {
					pub index: set_metadata::Index,
					pub maybe_hash: set_metadata::MaybeHash,
				}
				pub mod set_metadata {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
					pub type MaybeHash =
						::core::option::Option<::subxt::ext::subxt_core::utils::H256>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetMetadata {
					const PALLET: &'static str = "TechReferenda";
					const CALL: &'static str = "set_metadata";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Propose a referendum on a privileged action."]
				#[doc = ""]
				#[doc = "- `origin`: must be `SubmitOrigin` and the account must have `SubmissionDeposit` funds"]
				#[doc = "  available."]
				#[doc = "- `proposal_origin`: The origin from which the proposal should be executed."]
				#[doc = "- `proposal`: The proposal."]
				#[doc = "- `enactment_moment`: The moment that the proposal should be enacted."]
				#[doc = ""]
				#[doc = "Emits `Submitted`."]
				pub fn submit(
					&self,
					proposal_origin: types::submit::ProposalOrigin,
					proposal: types::submit::Proposal,
					enactment_moment: types::submit::EnactmentMoment,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Submit> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"submit",
						types::Submit {
							proposal_origin: ::subxt::ext::subxt_core::alloc::boxed::Box::new(
								proposal_origin,
							),
							proposal,
							enactment_moment,
						},
						[
							30u8, 232u8, 132u8, 0u8, 199u8, 166u8, 49u8, 94u8, 238u8, 61u8, 236u8,
							207u8, 2u8, 136u8, 37u8, 81u8, 67u8, 133u8, 2u8, 147u8, 177u8, 176u8,
							178u8, 113u8, 155u8, 180u8, 104u8, 176u8, 215u8, 255u8, 240u8, 100u8,
						],
					)
				}
				#[doc = "Post the Decision Deposit for a referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` and the account must have funds available for the"]
				#[doc = "  referendum's track's Decision Deposit."]
				#[doc = "- `index`: The index of the submitted referendum whose Decision Deposit is yet to be"]
				#[doc = "  posted."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositPlaced`."]
				pub fn place_decision_deposit(
					&self,
					index: types::place_decision_deposit::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::PlaceDecisionDeposit>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"place_decision_deposit",
						types::PlaceDecisionDeposit { index },
						[
							247u8, 158u8, 55u8, 191u8, 188u8, 200u8, 3u8, 47u8, 20u8, 175u8, 86u8,
							203u8, 52u8, 253u8, 91u8, 131u8, 21u8, 213u8, 56u8, 68u8, 40u8, 84u8,
							184u8, 30u8, 9u8, 193u8, 63u8, 182u8, 178u8, 241u8, 247u8, 220u8,
						],
					)
				}
				#[doc = "Refund the Decision Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Decision Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `DecisionDepositRefunded`."]
				pub fn refund_decision_deposit(
					&self,
					index: types::refund_decision_deposit::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::RefundDecisionDeposit,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"refund_decision_deposit",
						types::RefundDecisionDeposit { index },
						[
							159u8, 19u8, 35u8, 216u8, 114u8, 105u8, 18u8, 42u8, 148u8, 151u8,
							136u8, 92u8, 117u8, 30u8, 29u8, 41u8, 238u8, 58u8, 195u8, 91u8, 115u8,
							135u8, 96u8, 99u8, 154u8, 233u8, 8u8, 249u8, 145u8, 165u8, 77u8, 164u8,
						],
					)
				}
				#[doc = "Cancel an ongoing referendum."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `CancelOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Cancelled`."]
				pub fn cancel(
					&self,
					index: types::cancel::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Cancel> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"cancel",
						types::Cancel { index },
						[
							55u8, 206u8, 119u8, 156u8, 238u8, 165u8, 193u8, 73u8, 242u8, 13u8,
							212u8, 75u8, 136u8, 156u8, 151u8, 14u8, 35u8, 41u8, 156u8, 107u8, 60u8,
							190u8, 39u8, 216u8, 8u8, 74u8, 213u8, 130u8, 160u8, 131u8, 237u8,
							122u8,
						],
					)
				}
				#[doc = "Cancel an ongoing referendum and slash the deposits."]
				#[doc = ""]
				#[doc = "- `origin`: must be the `KillOrigin`."]
				#[doc = "- `index`: The index of the referendum to be cancelled."]
				#[doc = ""]
				#[doc = "Emits `Killed` and `DepositSlashed`."]
				pub fn kill(
					&self,
					index: types::kill::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Kill> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"kill",
						types::Kill { index },
						[
							50u8, 89u8, 57u8, 0u8, 87u8, 129u8, 113u8, 140u8, 179u8, 178u8, 126u8,
							198u8, 92u8, 92u8, 189u8, 64u8, 123u8, 232u8, 57u8, 227u8, 223u8,
							219u8, 73u8, 217u8, 179u8, 44u8, 210u8, 125u8, 180u8, 10u8, 143u8,
							48u8,
						],
					)
				}
				#[doc = "Advance a referendum onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `index`: the referendum to be advanced."]
				pub fn nudge_referendum(
					&self,
					index: types::nudge_referendum::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::NudgeReferendum>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"nudge_referendum",
						types::NudgeReferendum { index },
						[
							75u8, 99u8, 172u8, 30u8, 170u8, 150u8, 211u8, 229u8, 249u8, 128u8,
							194u8, 246u8, 100u8, 142u8, 193u8, 184u8, 232u8, 81u8, 29u8, 17u8,
							99u8, 91u8, 236u8, 85u8, 230u8, 226u8, 57u8, 115u8, 45u8, 170u8, 54u8,
							213u8,
						],
					)
				}
				#[doc = "Advance a track onto its next logical state. Only used internally."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Root`."]
				#[doc = "- `track`: the track to be advanced."]
				#[doc = ""]
				#[doc = "Action item for when there is now one fewer referendum in the deciding phase and the"]
				#[doc = "`DecidingCount` is not yet updated. This means that we should either:"]
				#[doc = "- begin deciding another referendum (and leave `DecidingCount` alone); or"]
				#[doc = "- decrement `DecidingCount`."]
				pub fn one_fewer_deciding(
					&self,
					track: types::one_fewer_deciding::Track,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::OneFewerDeciding>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"one_fewer_deciding",
						types::OneFewerDeciding { track },
						[
							15u8, 84u8, 79u8, 231u8, 21u8, 239u8, 244u8, 143u8, 183u8, 215u8,
							181u8, 25u8, 225u8, 195u8, 95u8, 171u8, 17u8, 156u8, 182u8, 128u8,
							111u8, 40u8, 151u8, 102u8, 196u8, 55u8, 36u8, 212u8, 89u8, 190u8,
							131u8, 167u8,
						],
					)
				}
				#[doc = "Refund the Submission Deposit for a closed referendum back to the depositor."]
				#[doc = ""]
				#[doc = "- `origin`: must be `Signed` or `Root`."]
				#[doc = "- `index`: The index of a closed referendum whose Submission Deposit has not yet been"]
				#[doc = "  refunded."]
				#[doc = ""]
				#[doc = "Emits `SubmissionDepositRefunded`."]
				pub fn refund_submission_deposit(
					&self,
					index: types::refund_submission_deposit::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<
					types::RefundSubmissionDeposit,
				> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"refund_submission_deposit",
						types::RefundSubmissionDeposit { index },
						[
							20u8, 217u8, 115u8, 6u8, 1u8, 60u8, 54u8, 136u8, 35u8, 41u8, 38u8,
							23u8, 85u8, 100u8, 141u8, 126u8, 30u8, 160u8, 61u8, 46u8, 134u8, 98u8,
							82u8, 38u8, 211u8, 124u8, 208u8, 222u8, 210u8, 10u8, 155u8, 122u8,
						],
					)
				}
				#[doc = "Set or clear metadata of a referendum."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `origin`: Must be `Signed` by a creator of a referendum or by anyone to clear a"]
				#[doc = "  metadata of a finished referendum."]
				#[doc = "- `index`:  The index of a referendum to set or clear metadata for."]
				#[doc = "- `maybe_hash`: The hash of an on-chain stored preimage. `None` to clear a metadata."]
				pub fn set_metadata(
					&self,
					index: types::set_metadata::Index,
					maybe_hash: types::set_metadata::MaybeHash,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetMetadata> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TechReferenda",
						"set_metadata",
						types::SetMetadata { index, maybe_hash },
						[
							207u8, 29u8, 146u8, 233u8, 219u8, 205u8, 88u8, 118u8, 106u8, 61u8,
							124u8, 101u8, 2u8, 41u8, 169u8, 70u8, 114u8, 189u8, 162u8, 118u8, 1u8,
							108u8, 234u8, 98u8, 245u8, 245u8, 183u8, 126u8, 89u8, 13u8, 112u8,
							88u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_referenda::pallet::Event2;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been submitted."]
			pub struct Submitted {
				pub index: submitted::Index,
				pub track: submitted::Track,
				pub proposal: submitted::Proposal,
			}
			pub mod submitted {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Track = ::core::primitive::u16;
				pub type Proposal = runtime_types::frame_support::traits::preimages::Bounded<
					runtime_types::quantus_runtime::RuntimeCall,
					runtime_types::poseidon_resonance::PoseidonHasher,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Submitted {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "Submitted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The decision deposit has been placed."]
			pub struct DecisionDepositPlaced {
				pub index: decision_deposit_placed::Index,
				pub who: decision_deposit_placed::Who,
				pub amount: decision_deposit_placed::Amount,
			}
			pub mod decision_deposit_placed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DecisionDepositPlaced {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "DecisionDepositPlaced";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The decision deposit has been refunded."]
			pub struct DecisionDepositRefunded {
				pub index: decision_deposit_refunded::Index,
				pub who: decision_deposit_refunded::Who,
				pub amount: decision_deposit_refunded::Amount,
			}
			pub mod decision_deposit_refunded {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DecisionDepositRefunded {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "DecisionDepositRefunded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A deposit has been slashed."]
			pub struct DepositSlashed {
				pub who: deposit_slashed::Who,
				pub amount: deposit_slashed::Amount,
			}
			pub mod deposit_slashed {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DepositSlashed {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "DepositSlashed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has moved into the deciding phase."]
			pub struct DecisionStarted {
				pub index: decision_started::Index,
				pub track: decision_started::Track,
				pub proposal: decision_started::Proposal,
				pub tally: decision_started::Tally,
			}
			pub mod decision_started {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Track = ::core::primitive::u16;
				pub type Proposal = runtime_types::frame_support::traits::preimages::Bounded<
					runtime_types::quantus_runtime::RuntimeCall,
					runtime_types::poseidon_resonance::PoseidonHasher,
				>;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DecisionStarted {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "DecisionStarted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ConfirmStarted {
				pub index: confirm_started::Index,
			}
			pub mod confirm_started {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ConfirmStarted {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "ConfirmStarted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ConfirmAborted {
				pub index: confirm_aborted::Index,
			}
			pub mod confirm_aborted {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for ConfirmAborted {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "ConfirmAborted";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has ended its confirmation phase and is ready for approval."]
			pub struct Confirmed {
				pub index: confirmed::Index,
				pub tally: confirmed::Tally,
			}
			pub mod confirmed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Confirmed {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "Confirmed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been approved and its proposal has been scheduled."]
			pub struct Approved {
				pub index: approved::Index,
			}
			pub mod approved {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Approved {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "Approved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A proposal has been rejected by referendum."]
			pub struct Rejected {
				pub index: rejected::Index,
				pub tally: rejected::Tally,
			}
			pub mod rejected {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Rejected {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "Rejected";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been timed out without being decided."]
			pub struct TimedOut {
				pub index: timed_out::Index,
				pub tally: timed_out::Tally,
			}
			pub mod timed_out {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for TimedOut {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "TimedOut";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been cancelled."]
			pub struct Cancelled {
				pub index: cancelled::Index,
				pub tally: cancelled::Tally,
			}
			pub mod cancelled {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Cancelled {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "Cancelled";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A referendum has been killed."]
			pub struct Killed {
				pub index: killed::Index,
				pub tally: killed::Tally,
			}
			pub mod killed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Tally = runtime_types::pallet_ranked_collective::Tally;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Killed {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "Killed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The submission deposit has been refunded."]
			pub struct SubmissionDepositRefunded {
				pub index: submission_deposit_refunded::Index,
				pub who: submission_deposit_refunded::Who,
				pub amount: submission_deposit_refunded::Amount,
			}
			pub mod submission_deposit_refunded {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for SubmissionDepositRefunded {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "SubmissionDepositRefunded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Metadata for a referendum has been set."]
			pub struct MetadataSet {
				pub index: metadata_set::Index,
				pub hash: metadata_set::Hash,
			}
			pub mod metadata_set {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MetadataSet {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "MetadataSet";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Metadata for a referendum has been cleared."]
			pub struct MetadataCleared {
				pub index: metadata_cleared::Index,
				pub hash: metadata_cleared::Hash,
			}
			pub mod metadata_cleared {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type Hash = ::subxt::ext::subxt_core::utils::H256;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for MetadataCleared {
				const PALLET: &'static str = "TechReferenda";
				const EVENT: &'static str = "MetadataCleared";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod referendum_count {
					use super::runtime_types;
					pub type ReferendumCount = ::core::primitive::u32;
				}
				pub mod referendum_info_for {
					use super::runtime_types;
					pub type ReferendumInfoFor =
						runtime_types::pallet_referenda::types::ReferendumInfo<
							::core::primitive::u16,
							runtime_types::quantus_runtime::OriginCaller,
							::core::primitive::u32,
							runtime_types::frame_support::traits::preimages::Bounded<
								runtime_types::quantus_runtime::RuntimeCall,
								runtime_types::poseidon_resonance::PoseidonHasher,
							>,
							::core::primitive::u128,
							runtime_types::pallet_ranked_collective::Tally,
							::subxt::ext::subxt_core::utils::AccountId32,
							(
								runtime_types::qp_scheduler::BlockNumberOrTimestamp<
									::core::primitive::u32,
									::core::primitive::u64,
								>,
								::core::primitive::u32,
							),
						>;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod track_queue {
					use super::runtime_types;
					pub type TrackQueue =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<(
							::core::primitive::u32,
							::core::primitive::u32,
						)>;
					pub type Param0 = ::core::primitive::u16;
				}
				pub mod deciding_count {
					use super::runtime_types;
					pub type DecidingCount = ::core::primitive::u32;
					pub type Param0 = ::core::primitive::u16;
				}
				pub mod metadata_of {
					use super::runtime_types;
					pub type MetadataOf = ::subxt::ext::subxt_core::utils::H256;
					pub type Param0 = ::core::primitive::u32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The next free referendum index, aka the number of referenda started so far."]
				pub fn referendum_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::referendum_count::ReferendumCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"ReferendumCount",
						(),
						[
							64u8, 145u8, 232u8, 153u8, 121u8, 87u8, 128u8, 253u8, 170u8, 192u8,
							139u8, 18u8, 0u8, 33u8, 243u8, 11u8, 238u8, 222u8, 244u8, 5u8, 247u8,
							198u8, 149u8, 31u8, 122u8, 208u8, 86u8, 179u8, 166u8, 167u8, 93u8,
							67u8,
						],
					)
				}
				#[doc = " Information concerning any given referendum."]
				pub fn referendum_info_for_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::referendum_info_for::ReferendumInfoFor,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"ReferendumInfoFor",
						(),
						[
							12u8, 160u8, 226u8, 48u8, 96u8, 127u8, 60u8, 27u8, 37u8, 158u8, 31u8,
							162u8, 106u8, 183u8, 90u8, 169u8, 244u8, 35u8, 25u8, 121u8, 84u8,
							120u8, 20u8, 206u8, 137u8, 42u8, 139u8, 47u8, 62u8, 73u8, 157u8, 182u8,
						],
					)
				}
				#[doc = " Information concerning any given referendum."]
				pub fn referendum_info_for(
					&self,
					_0: types::referendum_info_for::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::referendum_info_for::Param0,
					>,
					types::referendum_info_for::ReferendumInfoFor,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"ReferendumInfoFor",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							12u8, 160u8, 226u8, 48u8, 96u8, 127u8, 60u8, 27u8, 37u8, 158u8, 31u8,
							162u8, 106u8, 183u8, 90u8, 169u8, 244u8, 35u8, 25u8, 121u8, 84u8,
							120u8, 20u8, 206u8, 137u8, 42u8, 139u8, 47u8, 62u8, 73u8, 157u8, 182u8,
						],
					)
				}
				#[doc = " The sorted list of referenda ready to be decided but not yet being decided, ordered by"]
				#[doc = " conviction-weighted approvals."]
				#[doc = ""]
				#[doc = " This should be empty if `DecidingCount` is less than `TrackInfo::max_deciding`."]
				pub fn track_queue_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::track_queue::TrackQueue,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"TrackQueue",
						(),
						[
							187u8, 113u8, 225u8, 99u8, 159u8, 207u8, 182u8, 41u8, 116u8, 136u8,
							119u8, 196u8, 152u8, 50u8, 192u8, 22u8, 171u8, 182u8, 237u8, 228u8,
							80u8, 255u8, 227u8, 141u8, 155u8, 83u8, 71u8, 131u8, 118u8, 109u8,
							186u8, 65u8,
						],
					)
				}
				#[doc = " The sorted list of referenda ready to be decided but not yet being decided, ordered by"]
				#[doc = " conviction-weighted approvals."]
				#[doc = ""]
				#[doc = " This should be empty if `DecidingCount` is less than `TrackInfo::max_deciding`."]
				pub fn track_queue(
					&self,
					_0: types::track_queue::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::track_queue::Param0,
					>,
					types::track_queue::TrackQueue,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"TrackQueue",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							187u8, 113u8, 225u8, 99u8, 159u8, 207u8, 182u8, 41u8, 116u8, 136u8,
							119u8, 196u8, 152u8, 50u8, 192u8, 22u8, 171u8, 182u8, 237u8, 228u8,
							80u8, 255u8, 227u8, 141u8, 155u8, 83u8, 71u8, 131u8, 118u8, 109u8,
							186u8, 65u8,
						],
					)
				}
				#[doc = " The number of referenda being decided currently."]
				pub fn deciding_count_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::deciding_count::DecidingCount,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"DecidingCount",
						(),
						[
							203u8, 89u8, 158u8, 179u8, 194u8, 82u8, 248u8, 162u8, 93u8, 140u8,
							146u8, 51u8, 110u8, 232u8, 51u8, 1u8, 128u8, 212u8, 199u8, 14u8, 182u8,
							103u8, 47u8, 252u8, 126u8, 108u8, 166u8, 69u8, 252u8, 179u8, 126u8,
							245u8,
						],
					)
				}
				#[doc = " The number of referenda being decided currently."]
				pub fn deciding_count(
					&self,
					_0: types::deciding_count::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::deciding_count::Param0,
					>,
					types::deciding_count::DecidingCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"DecidingCount",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							203u8, 89u8, 158u8, 179u8, 194u8, 82u8, 248u8, 162u8, 93u8, 140u8,
							146u8, 51u8, 110u8, 232u8, 51u8, 1u8, 128u8, 212u8, 199u8, 14u8, 182u8,
							103u8, 47u8, 252u8, 126u8, 108u8, 166u8, 69u8, 252u8, 179u8, 126u8,
							245u8,
						],
					)
				}
				#[doc = " The metadata is a general information concerning the referendum."]
				#[doc = " The `Hash` refers to the preimage of the `Preimages` provider which can be a JSON"]
				#[doc = " dump or IPFS hash of a JSON file."]
				#[doc = ""]
				#[doc = " Consider a garbage collection for a metadata of finished referendums to `unrequest` (remove)"]
				#[doc = " large preimages."]
				pub fn metadata_of_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::metadata_of::MetadataOf,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"MetadataOf",
						(),
						[
							159u8, 250u8, 56u8, 189u8, 247u8, 165u8, 206u8, 166u8, 91u8, 139u8,
							124u8, 164u8, 25u8, 246u8, 199u8, 36u8, 159u8, 56u8, 227u8, 136u8, 4u8,
							45u8, 193u8, 72u8, 200u8, 164u8, 39u8, 207u8, 224u8, 124u8, 191u8,
							110u8,
						],
					)
				}
				#[doc = " The metadata is a general information concerning the referendum."]
				#[doc = " The `Hash` refers to the preimage of the `Preimages` provider which can be a JSON"]
				#[doc = " dump or IPFS hash of a JSON file."]
				#[doc = ""]
				#[doc = " Consider a garbage collection for a metadata of finished referendums to `unrequest` (remove)"]
				#[doc = " large preimages."]
				pub fn metadata_of(
					&self,
					_0: types::metadata_of::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::metadata_of::Param0,
					>,
					types::metadata_of::MetadataOf,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TechReferenda",
						"MetadataOf",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							159u8, 250u8, 56u8, 189u8, 247u8, 165u8, 206u8, 166u8, 91u8, 139u8,
							124u8, 164u8, 25u8, 246u8, 199u8, 36u8, 159u8, 56u8, 227u8, 136u8, 4u8,
							45u8, 193u8, 72u8, 200u8, 164u8, 39u8, 207u8, 224u8, 124u8, 191u8,
							110u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The minimum amount to be used as a deposit for a public referendum proposal."]
				pub fn submission_deposit(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TechReferenda",
						"SubmissionDeposit",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " Maximum size of the referendum queue for a single track."]
				pub fn max_queued(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TechReferenda",
						"MaxQueued",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The number of blocks after submission that a referendum must begin being decided by."]
				#[doc = " Once this passes, then anyone may cancel the referendum."]
				pub fn undeciding_timeout(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TechReferenda",
						"UndecidingTimeout",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Quantization level for the referendum wakeup scheduler. A higher number will result in"]
				#[doc = " fewer storage reads/writes needed for smaller voters, but also result in delays to the"]
				#[doc = " automatic referendum status changes. Explicit servicing instructions are unaffected."]
				pub fn alarm_interval(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TechReferenda",
						"AlarmInterval",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " A list of tracks."]
				#[doc = ""]
				#[doc = " Note: if the tracks are dynamic, the value in the static metadata might be inaccurate."]
				pub fn tracks(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::subxt::ext::subxt_core::alloc::vec::Vec<(
						::core::primitive::u16,
						runtime_types::pallet_referenda::types::TrackDetails<
							::core::primitive::u128,
							::core::primitive::u32,
							::subxt::ext::subxt_core::alloc::string::String,
						>,
					)>,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TechReferenda",
						"Tracks",
						[
							35u8, 226u8, 207u8, 234u8, 184u8, 139u8, 187u8, 184u8, 128u8, 199u8,
							227u8, 15u8, 31u8, 196u8, 5u8, 207u8, 138u8, 174u8, 130u8, 201u8,
							200u8, 113u8, 86u8, 93u8, 221u8, 243u8, 229u8, 24u8, 18u8, 150u8, 56u8,
							159u8,
						],
					)
				}
			}
		}
	}
	pub mod merkle_airdrop {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_merkle_airdrop::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_merkle_airdrop::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Create a new airdrop with a Merkle root."]
				#[doc = ""]
				#[doc = "The Merkle root is a cryptographic hash that represents all valid claims"]
				#[doc = "for this airdrop. Users will later provide Merkle proofs to verify their"]
				#[doc = "eligibility to claim tokens."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call (must be signed)"]
				#[doc = "* `merkle_root` - The Merkle root hash representing all valid claims"]
				#[doc = "* `vesting_period` - Optional vesting period for the airdrop"]
				#[doc = "* `vesting_delay` - Optional delay before vesting starts"]
				pub struct CreateAirdrop {
					pub merkle_root: create_airdrop::MerkleRoot,
					pub vesting_period: create_airdrop::VestingPeriod,
					pub vesting_delay: create_airdrop::VestingDelay,
				}
				pub mod create_airdrop {
					use super::runtime_types;
					pub type MerkleRoot = [::core::primitive::u8; 32usize];
					pub type VestingPeriod = ::core::option::Option<::core::primitive::u32>;
					pub type VestingDelay = ::core::option::Option<::core::primitive::u32>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CreateAirdrop {
					const PALLET: &'static str = "MerkleAirdrop";
					const CALL: &'static str = "create_airdrop";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Fund an existing airdrop with tokens."]
				#[doc = ""]
				#[doc = "This function transfers tokens from the caller to the airdrop's account,"]
				#[doc = "making them available for users to claim."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call (must be signed)"]
				#[doc = "* `airdrop_id` - The ID of the airdrop to fund"]
				#[doc = "* `amount` - The amount of tokens to add to the airdrop"]
				#[doc = ""]
				#[doc = "# Errors"]
				#[doc = ""]
				#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
				pub struct FundAirdrop {
					pub airdrop_id: fund_airdrop::AirdropId,
					pub amount: fund_airdrop::Amount,
				}
				pub mod fund_airdrop {
					use super::runtime_types;
					pub type AirdropId = ::core::primitive::u32;
					pub type Amount = ::core::primitive::u128;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for FundAirdrop {
					const PALLET: &'static str = "MerkleAirdrop";
					const CALL: &'static str = "fund_airdrop";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Claim tokens from an airdrop by providing a Merkle proof."]
				#[doc = ""]
				#[doc = "Users can claim their tokens by providing a proof of their eligibility."]
				#[doc = "The proof is verified against the airdrop's Merkle root."]
				#[doc = "Anyone can trigger a claim for any eligible recipient."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call"]
				#[doc = "* `airdrop_id` - The ID of the airdrop to claim from"]
				#[doc = "* `amount` - The amount of tokens to claim"]
				#[doc = "* `merkle_proof` - The Merkle proof verifying eligibility"]
				#[doc = ""]
				#[doc = "# Errors"]
				#[doc = ""]
				#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
				#[doc = "* `AlreadyClaimed` - If the recipient has already claimed from this airdrop"]
				#[doc = "* `InvalidProof` - If the provided Merkle proof is invalid"]
				#[doc = "* `InsufficientAirdropBalance` - If the airdrop doesn't have enough tokens"]
				pub struct Claim {
					pub airdrop_id: claim::AirdropId,
					pub recipient: claim::Recipient,
					pub amount: claim::Amount,
					pub merkle_proof: claim::MerkleProof,
				}
				pub mod claim {
					use super::runtime_types;
					pub type AirdropId = ::core::primitive::u32;
					pub type Recipient = ::subxt::ext::subxt_core::utils::AccountId32;
					pub type Amount = ::core::primitive::u128;
					pub type MerkleProof =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							[::core::primitive::u8; 32usize],
						>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Claim {
					const PALLET: &'static str = "MerkleAirdrop";
					const CALL: &'static str = "claim";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Delete an airdrop and reclaim any remaining funds."]
				#[doc = ""]
				#[doc = "This function allows the creator of an airdrop to delete it and reclaim"]
				#[doc = "any remaining tokens that haven't been claimed."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call (must be the airdrop creator)"]
				#[doc = "* `airdrop_id` - The ID of the airdrop to delete"]
				#[doc = ""]
				#[doc = "# Errors"]
				#[doc = ""]
				#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
				#[doc = "* `NotAirdropCreator` - If the caller is not the creator of the airdrop"]
				pub struct DeleteAirdrop {
					pub airdrop_id: delete_airdrop::AirdropId,
				}
				pub mod delete_airdrop {
					use super::runtime_types;
					pub type AirdropId = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for DeleteAirdrop {
					const PALLET: &'static str = "MerkleAirdrop";
					const CALL: &'static str = "delete_airdrop";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Create a new airdrop with a Merkle root."]
				#[doc = ""]
				#[doc = "The Merkle root is a cryptographic hash that represents all valid claims"]
				#[doc = "for this airdrop. Users will later provide Merkle proofs to verify their"]
				#[doc = "eligibility to claim tokens."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call (must be signed)"]
				#[doc = "* `merkle_root` - The Merkle root hash representing all valid claims"]
				#[doc = "* `vesting_period` - Optional vesting period for the airdrop"]
				#[doc = "* `vesting_delay` - Optional delay before vesting starts"]
				pub fn create_airdrop(
					&self,
					merkle_root: types::create_airdrop::MerkleRoot,
					vesting_period: types::create_airdrop::VestingPeriod,
					vesting_delay: types::create_airdrop::VestingDelay,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CreateAirdrop>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"MerkleAirdrop",
						"create_airdrop",
						types::CreateAirdrop { merkle_root, vesting_period, vesting_delay },
						[
							18u8, 201u8, 105u8, 56u8, 66u8, 207u8, 57u8, 177u8, 133u8, 38u8, 185u8,
							19u8, 205u8, 119u8, 177u8, 206u8, 188u8, 88u8, 138u8, 33u8, 246u8,
							179u8, 148u8, 0u8, 79u8, 201u8, 89u8, 229u8, 46u8, 77u8, 42u8, 117u8,
						],
					)
				}
				#[doc = "Fund an existing airdrop with tokens."]
				#[doc = ""]
				#[doc = "This function transfers tokens from the caller to the airdrop's account,"]
				#[doc = "making them available for users to claim."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call (must be signed)"]
				#[doc = "* `airdrop_id` - The ID of the airdrop to fund"]
				#[doc = "* `amount` - The amount of tokens to add to the airdrop"]
				#[doc = ""]
				#[doc = "# Errors"]
				#[doc = ""]
				#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
				pub fn fund_airdrop(
					&self,
					airdrop_id: types::fund_airdrop::AirdropId,
					amount: types::fund_airdrop::Amount,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::FundAirdrop> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"MerkleAirdrop",
						"fund_airdrop",
						types::FundAirdrop { airdrop_id, amount },
						[
							11u8, 155u8, 135u8, 152u8, 19u8, 196u8, 79u8, 68u8, 24u8, 46u8, 27u8,
							63u8, 202u8, 242u8, 166u8, 160u8, 81u8, 44u8, 115u8, 247u8, 110u8,
							49u8, 11u8, 204u8, 70u8, 39u8, 7u8, 43u8, 103u8, 78u8, 39u8, 131u8,
						],
					)
				}
				#[doc = "Claim tokens from an airdrop by providing a Merkle proof."]
				#[doc = ""]
				#[doc = "Users can claim their tokens by providing a proof of their eligibility."]
				#[doc = "The proof is verified against the airdrop's Merkle root."]
				#[doc = "Anyone can trigger a claim for any eligible recipient."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call"]
				#[doc = "* `airdrop_id` - The ID of the airdrop to claim from"]
				#[doc = "* `amount` - The amount of tokens to claim"]
				#[doc = "* `merkle_proof` - The Merkle proof verifying eligibility"]
				#[doc = ""]
				#[doc = "# Errors"]
				#[doc = ""]
				#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
				#[doc = "* `AlreadyClaimed` - If the recipient has already claimed from this airdrop"]
				#[doc = "* `InvalidProof` - If the provided Merkle proof is invalid"]
				#[doc = "* `InsufficientAirdropBalance` - If the airdrop doesn't have enough tokens"]
				pub fn claim(
					&self,
					airdrop_id: types::claim::AirdropId,
					recipient: types::claim::Recipient,
					amount: types::claim::Amount,
					merkle_proof: types::claim::MerkleProof,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Claim> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"MerkleAirdrop",
						"claim",
						types::Claim { airdrop_id, recipient, amount, merkle_proof },
						[
							137u8, 9u8, 80u8, 195u8, 157u8, 215u8, 158u8, 30u8, 26u8, 104u8, 183u8,
							55u8, 102u8, 100u8, 41u8, 40u8, 26u8, 193u8, 255u8, 95u8, 201u8, 240u8,
							18u8, 253u8, 71u8, 117u8, 88u8, 250u8, 192u8, 67u8, 127u8, 159u8,
						],
					)
				}
				#[doc = "Delete an airdrop and reclaim any remaining funds."]
				#[doc = ""]
				#[doc = "This function allows the creator of an airdrop to delete it and reclaim"]
				#[doc = "any remaining tokens that haven't been claimed."]
				#[doc = ""]
				#[doc = "# Parameters"]
				#[doc = ""]
				#[doc = "* `origin` - The origin of the call (must be the airdrop creator)"]
				#[doc = "* `airdrop_id` - The ID of the airdrop to delete"]
				#[doc = ""]
				#[doc = "# Errors"]
				#[doc = ""]
				#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
				#[doc = "* `NotAirdropCreator` - If the caller is not the creator of the airdrop"]
				pub fn delete_airdrop(
					&self,
					airdrop_id: types::delete_airdrop::AirdropId,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::DeleteAirdrop>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"MerkleAirdrop",
						"delete_airdrop",
						types::DeleteAirdrop { airdrop_id },
						[
							34u8, 88u8, 199u8, 36u8, 214u8, 19u8, 124u8, 24u8, 29u8, 222u8, 138u8,
							174u8, 47u8, 199u8, 59u8, 155u8, 118u8, 157u8, 82u8, 96u8, 81u8, 186u8,
							27u8, 96u8, 116u8, 99u8, 185u8, 8u8, 100u8, 34u8, 179u8, 185u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_merkle_airdrop::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A new airdrop has been created."]
			#[doc = ""]
			#[doc = "Parameters: [airdrop_id, merkle_root]"]
			pub struct AirdropCreated {
				pub airdrop_id: airdrop_created::AirdropId,
				pub airdrop_metadata: airdrop_created::AirdropMetadata,
			}
			pub mod airdrop_created {
				use super::runtime_types;
				pub type AirdropId = ::core::primitive::u32;
				pub type AirdropMetadata = runtime_types::pallet_merkle_airdrop::AirdropMetadata<
					::core::primitive::u32,
					::core::primitive::u128,
					::subxt::ext::subxt_core::utils::AccountId32,
				>;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for AirdropCreated {
				const PALLET: &'static str = "MerkleAirdrop";
				const EVENT: &'static str = "AirdropCreated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An airdrop has been funded with tokens."]
			#[doc = ""]
			#[doc = "Parameters: [airdrop_id, amount]"]
			pub struct AirdropFunded {
				pub airdrop_id: airdrop_funded::AirdropId,
				pub amount: airdrop_funded::Amount,
			}
			pub mod airdrop_funded {
				use super::runtime_types;
				pub type AirdropId = ::core::primitive::u32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for AirdropFunded {
				const PALLET: &'static str = "MerkleAirdrop";
				const EVENT: &'static str = "AirdropFunded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A user has claimed tokens from an airdrop."]
			#[doc = ""]
			#[doc = "Parameters: [airdrop_id, account, amount]"]
			pub struct Claimed {
				pub airdrop_id: claimed::AirdropId,
				pub account: claimed::Account,
				pub amount: claimed::Amount,
			}
			pub mod claimed {
				use super::runtime_types;
				pub type AirdropId = ::core::primitive::u32;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Amount = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Claimed {
				const PALLET: &'static str = "MerkleAirdrop";
				const EVENT: &'static str = "Claimed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An airdrop has been deleted."]
			#[doc = ""]
			#[doc = "Parameters: [airdrop_id]"]
			pub struct AirdropDeleted {
				pub airdrop_id: airdrop_deleted::AirdropId,
			}
			pub mod airdrop_deleted {
				use super::runtime_types;
				pub type AirdropId = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for AirdropDeleted {
				const PALLET: &'static str = "MerkleAirdrop";
				const EVENT: &'static str = "AirdropDeleted";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod airdrop_info {
					use super::runtime_types;
					pub type AirdropInfo = runtime_types::pallet_merkle_airdrop::AirdropMetadata<
						::core::primitive::u32,
						::core::primitive::u128,
						::subxt::ext::subxt_core::utils::AccountId32,
					>;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod claimed {
					use super::runtime_types;
					pub type Claimed = ();
					pub type Param0 = ::core::primitive::u32;
					pub type Param1 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod next_airdrop_id {
					use super::runtime_types;
					pub type NextAirdropId = ::core::primitive::u32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " Stores general info about an airdrop"]
				pub fn airdrop_info_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::airdrop_info::AirdropInfo,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"AirdropInfo",
						(),
						[
							38u8, 176u8, 25u8, 251u8, 80u8, 201u8, 118u8, 175u8, 89u8, 80u8, 227u8,
							241u8, 250u8, 0u8, 112u8, 71u8, 133u8, 50u8, 137u8, 13u8, 255u8, 24u8,
							253u8, 237u8, 195u8, 1u8, 192u8, 177u8, 167u8, 248u8, 11u8, 160u8,
						],
					)
				}
				#[doc = " Stores general info about an airdrop"]
				pub fn airdrop_info(
					&self,
					_0: types::airdrop_info::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::airdrop_info::Param0,
					>,
					types::airdrop_info::AirdropInfo,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"AirdropInfo",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							38u8, 176u8, 25u8, 251u8, 80u8, 201u8, 118u8, 175u8, 89u8, 80u8, 227u8,
							241u8, 250u8, 0u8, 112u8, 71u8, 133u8, 50u8, 137u8, 13u8, 255u8, 24u8,
							253u8, 237u8, 195u8, 1u8, 192u8, 177u8, 167u8, 248u8, 11u8, 160u8,
						],
					)
				}
				#[doc = " Storage for claimed status"]
				pub fn claimed_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::claimed::Claimed,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"Claimed",
						(),
						[
							214u8, 178u8, 109u8, 48u8, 230u8, 120u8, 107u8, 211u8, 179u8, 251u8,
							164u8, 29u8, 197u8, 154u8, 160u8, 230u8, 112u8, 212u8, 14u8, 157u8,
							248u8, 207u8, 101u8, 159u8, 203u8, 82u8, 199u8, 102u8, 99u8, 239u8,
							162u8, 10u8,
						],
					)
				}
				#[doc = " Storage for claimed status"]
				pub fn claimed_iter1(
					&self,
					_0: types::claimed::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::claimed::Param0,
					>,
					types::claimed::Claimed,
					(),
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"Claimed",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							214u8, 178u8, 109u8, 48u8, 230u8, 120u8, 107u8, 211u8, 179u8, 251u8,
							164u8, 29u8, 197u8, 154u8, 160u8, 230u8, 112u8, 212u8, 14u8, 157u8,
							248u8, 207u8, 101u8, 159u8, 203u8, 82u8, 199u8, 102u8, 99u8, 239u8,
							162u8, 10u8,
						],
					)
				}
				#[doc = " Storage for claimed status"]
				pub fn claimed(
					&self,
					_0: types::claimed::Param0,
					_1: types::claimed::Param1,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::claimed::Param0,
						>,
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::claimed::Param1,
						>,
					),
					types::claimed::Claimed,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"Claimed",
						(
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1),
						),
						[
							214u8, 178u8, 109u8, 48u8, 230u8, 120u8, 107u8, 211u8, 179u8, 251u8,
							164u8, 29u8, 197u8, 154u8, 160u8, 230u8, 112u8, 212u8, 14u8, 157u8,
							248u8, 207u8, 101u8, 159u8, 203u8, 82u8, 199u8, 102u8, 99u8, 239u8,
							162u8, 10u8,
						],
					)
				}
				#[doc = " Counter for airdrop IDs"]
				pub fn next_airdrop_id(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::next_airdrop_id::NextAirdropId,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"NextAirdropId",
						(),
						[
							79u8, 145u8, 145u8, 158u8, 86u8, 58u8, 102u8, 216u8, 133u8, 34u8,
							252u8, 224u8, 222u8, 51u8, 170u8, 3u8, 135u8, 29u8, 99u8, 143u8, 93u8,
							176u8, 69u8, 231u8, 74u8, 214u8, 94u8, 126u8, 227u8, 166u8, 242u8,
							98u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The maximum number of proof elements allowed in a Merkle proof."]
				pub fn max_proofs(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"MaxProofs",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The pallet id, used for deriving its sovereign account ID."]
				pub fn pallet_id(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::frame_support::PalletId,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"PalletId",
						[
							56u8, 243u8, 53u8, 83u8, 154u8, 179u8, 170u8, 80u8, 133u8, 173u8, 61u8,
							161u8, 47u8, 225u8, 146u8, 21u8, 50u8, 229u8, 248u8, 27u8, 104u8, 58u8,
							129u8, 197u8, 102u8, 160u8, 168u8, 205u8, 154u8, 42u8, 217u8, 53u8,
						],
					)
				}
				#[doc = " Priority for unsigned claim transactions."]
				pub fn unsigned_claim_priority(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u64,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"MerkleAirdrop",
						"UnsignedClaimPriority",
						[
							128u8, 214u8, 205u8, 242u8, 181u8, 142u8, 124u8, 231u8, 190u8, 146u8,
							59u8, 226u8, 157u8, 101u8, 103u8, 117u8, 249u8, 65u8, 18u8, 191u8,
							103u8, 119u8, 53u8, 85u8, 81u8, 96u8, 220u8, 42u8, 184u8, 239u8, 42u8,
							246u8,
						],
					)
				}
			}
		}
	}
	pub mod treasury_pallet {
		use super::{root_mod, runtime_types};
		#[doc = "Error for the treasury pallet."]
		pub type Error = runtime_types::pallet_treasury::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_treasury::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Propose and approve a spend of treasury funds."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::SpendOrigin`] with the `Success` value being at least `amount`."]
				#[doc = ""]
				#[doc = "### Details"]
				#[doc = "NOTE: For record-keeping purposes, the proposer is deemed to be equivalent to the"]
				#[doc = "beneficiary."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `amount`: The amount to be transferred from the treasury to the `beneficiary`."]
				#[doc = "- `beneficiary`: The destination account for the transfer."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::SpendApproved`] if successful."]
				pub struct SpendLocal {
					#[codec(compact)]
					pub amount: spend_local::Amount,
					pub beneficiary: spend_local::Beneficiary,
				}
				pub mod spend_local {
					use super::runtime_types;
					pub type Amount = ::core::primitive::u128;
					pub type Beneficiary = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SpendLocal {
					const PALLET: &'static str = "TreasuryPallet";
					const CALL: &'static str = "spend_local";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Force a previously approved proposal to be removed from the approval queue."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::RejectOrigin`]."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "The original deposit will no longer be returned."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `proposal_id`: The index of a proposal"]
				#[doc = ""]
				#[doc = "### Complexity"]
				#[doc = "- O(A) where `A` is the number of approvals"]
				#[doc = ""]
				#[doc = "### Errors"]
				#[doc = "- [`Error::ProposalNotApproved`]: The `proposal_id` supplied was not found in the"]
				#[doc = "  approval queue, i.e., the proposal has not been approved. This could also mean the"]
				#[doc = "  proposal does not exist altogether, thus there is no way it would have been approved"]
				#[doc = "  in the first place."]
				pub struct RemoveApproval {
					#[codec(compact)]
					pub proposal_id: remove_approval::ProposalId,
				}
				pub mod remove_approval {
					use super::runtime_types;
					pub type ProposalId = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveApproval {
					const PALLET: &'static str = "TreasuryPallet";
					const CALL: &'static str = "remove_approval";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Propose and approve a spend of treasury funds."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::SpendOrigin`] with the `Success` value being at least"]
				#[doc = "`amount` of `asset_kind` in the native asset. The amount of `asset_kind` is converted"]
				#[doc = "for assertion using the [`Config::BalanceConverter`]."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "Create an approved spend for transferring a specific `amount` of `asset_kind` to a"]
				#[doc = "designated beneficiary. The spend must be claimed using the `payout` dispatchable within"]
				#[doc = "the [`Config::PayoutPeriod`]."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `asset_kind`: An indicator of the specific asset class to be spent."]
				#[doc = "- `amount`: The amount to be transferred from the treasury to the `beneficiary`."]
				#[doc = "- `beneficiary`: The beneficiary of the spend."]
				#[doc = "- `valid_from`: The block number from which the spend can be claimed. It can refer to"]
				#[doc = "  the past if the resulting spend has not yet expired according to the"]
				#[doc = "  [`Config::PayoutPeriod`]. If `None`, the spend can be claimed immediately after"]
				#[doc = "  approval."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::AssetSpendApproved`] if successful."]
				pub struct Spend {
					pub asset_kind: ::subxt::ext::subxt_core::alloc::boxed::Box<spend::AssetKind>,
					#[codec(compact)]
					pub amount: spend::Amount,
					pub beneficiary:
						::subxt::ext::subxt_core::alloc::boxed::Box<spend::Beneficiary>,
					pub valid_from: spend::ValidFrom,
				}
				pub mod spend {
					use super::runtime_types;
					pub type AssetKind = ();
					pub type Amount = ::core::primitive::u128;
					pub type Beneficiary = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type ValidFrom = ::core::option::Option<::core::primitive::u32>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Spend {
					const PALLET: &'static str = "TreasuryPallet";
					const CALL: &'static str = "spend";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Claim a spend."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be signed"]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "Spends must be claimed within some temporal bounds. A spend may be claimed within one"]
				#[doc = "[`Config::PayoutPeriod`] from the `valid_from` block."]
				#[doc = "In case of a payout failure, the spend status must be updated with the `check_status`"]
				#[doc = "dispatchable before retrying with the current function."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `index`: The spend index."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::Paid`] if successful."]
				pub struct Payout {
					pub index: payout::Index,
				}
				pub mod payout {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for Payout {
					const PALLET: &'static str = "TreasuryPallet";
					const CALL: &'static str = "payout";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Check the status of the spend and remove it from the storage if processed."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be signed."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "The status check is a prerequisite for retrying a failed payout."]
				#[doc = "If a spend has either succeeded or expired, it is removed from the storage by this"]
				#[doc = "function. In such instances, transaction fees are refunded."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `index`: The spend index."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::PaymentFailed`] if the spend payout has failed."]
				#[doc = "Emits [`Event::SpendProcessed`] if the spend payout has succeed."]
				pub struct CheckStatus {
					pub index: check_status::Index,
				}
				pub mod check_status {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CheckStatus {
					const PALLET: &'static str = "TreasuryPallet";
					const CALL: &'static str = "check_status";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Void previously approved spend."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::RejectOrigin`]."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "A spend void is only possible if the payout has not been attempted yet."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `index`: The spend index."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::AssetSpendVoided`] if successful."]
				pub struct VoidSpend {
					pub index: void_spend::Index,
				}
				pub mod void_spend {
					use super::runtime_types;
					pub type Index = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for VoidSpend {
					const PALLET: &'static str = "TreasuryPallet";
					const CALL: &'static str = "void_spend";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Propose and approve a spend of treasury funds."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::SpendOrigin`] with the `Success` value being at least `amount`."]
				#[doc = ""]
				#[doc = "### Details"]
				#[doc = "NOTE: For record-keeping purposes, the proposer is deemed to be equivalent to the"]
				#[doc = "beneficiary."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `amount`: The amount to be transferred from the treasury to the `beneficiary`."]
				#[doc = "- `beneficiary`: The destination account for the transfer."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::SpendApproved`] if successful."]
				pub fn spend_local(
					&self,
					amount: types::spend_local::Amount,
					beneficiary: types::spend_local::Beneficiary,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SpendLocal> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TreasuryPallet",
						"spend_local",
						types::SpendLocal { amount, beneficiary },
						[
							137u8, 171u8, 83u8, 247u8, 245u8, 212u8, 152u8, 127u8, 210u8, 71u8,
							254u8, 134u8, 189u8, 26u8, 249u8, 41u8, 214u8, 175u8, 24u8, 64u8, 33u8,
							90u8, 23u8, 134u8, 44u8, 110u8, 63u8, 46u8, 46u8, 146u8, 222u8, 79u8,
						],
					)
				}
				#[doc = "Force a previously approved proposal to be removed from the approval queue."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::RejectOrigin`]."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "The original deposit will no longer be returned."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `proposal_id`: The index of a proposal"]
				#[doc = ""]
				#[doc = "### Complexity"]
				#[doc = "- O(A) where `A` is the number of approvals"]
				#[doc = ""]
				#[doc = "### Errors"]
				#[doc = "- [`Error::ProposalNotApproved`]: The `proposal_id` supplied was not found in the"]
				#[doc = "  approval queue, i.e., the proposal has not been approved. This could also mean the"]
				#[doc = "  proposal does not exist altogether, thus there is no way it would have been approved"]
				#[doc = "  in the first place."]
				pub fn remove_approval(
					&self,
					proposal_id: types::remove_approval::ProposalId,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveApproval>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TreasuryPallet",
						"remove_approval",
						types::RemoveApproval { proposal_id },
						[
							180u8, 20u8, 39u8, 227u8, 29u8, 228u8, 234u8, 36u8, 155u8, 114u8,
							197u8, 135u8, 185u8, 31u8, 56u8, 247u8, 224u8, 168u8, 254u8, 233u8,
							250u8, 134u8, 186u8, 155u8, 108u8, 84u8, 94u8, 226u8, 207u8, 130u8,
							196u8, 100u8,
						],
					)
				}
				#[doc = "Propose and approve a spend of treasury funds."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::SpendOrigin`] with the `Success` value being at least"]
				#[doc = "`amount` of `asset_kind` in the native asset. The amount of `asset_kind` is converted"]
				#[doc = "for assertion using the [`Config::BalanceConverter`]."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "Create an approved spend for transferring a specific `amount` of `asset_kind` to a"]
				#[doc = "designated beneficiary. The spend must be claimed using the `payout` dispatchable within"]
				#[doc = "the [`Config::PayoutPeriod`]."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `asset_kind`: An indicator of the specific asset class to be spent."]
				#[doc = "- `amount`: The amount to be transferred from the treasury to the `beneficiary`."]
				#[doc = "- `beneficiary`: The beneficiary of the spend."]
				#[doc = "- `valid_from`: The block number from which the spend can be claimed. It can refer to"]
				#[doc = "  the past if the resulting spend has not yet expired according to the"]
				#[doc = "  [`Config::PayoutPeriod`]. If `None`, the spend can be claimed immediately after"]
				#[doc = "  approval."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::AssetSpendApproved`] if successful."]
				pub fn spend(
					&self,
					asset_kind: types::spend::AssetKind,
					amount: types::spend::Amount,
					beneficiary: types::spend::Beneficiary,
					valid_from: types::spend::ValidFrom,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Spend> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TreasuryPallet",
						"spend",
						types::Spend {
							asset_kind: ::subxt::ext::subxt_core::alloc::boxed::Box::new(
								asset_kind,
							),
							amount,
							beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box::new(
								beneficiary,
							),
							valid_from,
						},
						[
							64u8, 121u8, 249u8, 219u8, 22u8, 188u8, 167u8, 85u8, 45u8, 27u8, 200u8,
							219u8, 138u8, 17u8, 230u8, 106u8, 145u8, 39u8, 43u8, 161u8, 69u8, 10u8,
							202u8, 251u8, 127u8, 131u8, 0u8, 194u8, 25u8, 153u8, 169u8, 206u8,
						],
					)
				}
				#[doc = "Claim a spend."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be signed"]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "Spends must be claimed within some temporal bounds. A spend may be claimed within one"]
				#[doc = "[`Config::PayoutPeriod`] from the `valid_from` block."]
				#[doc = "In case of a payout failure, the spend status must be updated with the `check_status`"]
				#[doc = "dispatchable before retrying with the current function."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `index`: The spend index."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::Paid`] if successful."]
				pub fn payout(
					&self,
					index: types::payout::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::Payout> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TreasuryPallet",
						"payout",
						types::Payout { index },
						[
							179u8, 254u8, 82u8, 94u8, 248u8, 26u8, 6u8, 34u8, 93u8, 244u8, 186u8,
							199u8, 163u8, 32u8, 110u8, 220u8, 78u8, 11u8, 168u8, 182u8, 169u8,
							56u8, 53u8, 194u8, 168u8, 218u8, 131u8, 38u8, 46u8, 156u8, 93u8, 234u8,
						],
					)
				}
				#[doc = "Check the status of the spend and remove it from the storage if processed."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be signed."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "The status check is a prerequisite for retrying a failed payout."]
				#[doc = "If a spend has either succeeded or expired, it is removed from the storage by this"]
				#[doc = "function. In such instances, transaction fees are refunded."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `index`: The spend index."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::PaymentFailed`] if the spend payout has failed."]
				#[doc = "Emits [`Event::SpendProcessed`] if the spend payout has succeed."]
				pub fn check_status(
					&self,
					index: types::check_status::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CheckStatus> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TreasuryPallet",
						"check_status",
						types::CheckStatus { index },
						[
							164u8, 111u8, 10u8, 11u8, 104u8, 237u8, 112u8, 240u8, 104u8, 130u8,
							179u8, 221u8, 54u8, 18u8, 8u8, 172u8, 148u8, 245u8, 110u8, 174u8, 75u8,
							38u8, 46u8, 143u8, 101u8, 232u8, 65u8, 252u8, 36u8, 152u8, 29u8, 209u8,
						],
					)
				}
				#[doc = "Void previously approved spend."]
				#[doc = ""]
				#[doc = "## Dispatch Origin"]
				#[doc = ""]
				#[doc = "Must be [`Config::RejectOrigin`]."]
				#[doc = ""]
				#[doc = "## Details"]
				#[doc = ""]
				#[doc = "A spend void is only possible if the payout has not been attempted yet."]
				#[doc = ""]
				#[doc = "### Parameters"]
				#[doc = "- `index`: The spend index."]
				#[doc = ""]
				#[doc = "## Events"]
				#[doc = ""]
				#[doc = "Emits [`Event::AssetSpendVoided`] if successful."]
				pub fn void_spend(
					&self,
					index: types::void_spend::Index,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::VoidSpend> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"TreasuryPallet",
						"void_spend",
						types::VoidSpend { index },
						[
							9u8, 212u8, 174u8, 92u8, 43u8, 102u8, 224u8, 124u8, 247u8, 239u8,
							196u8, 68u8, 132u8, 171u8, 116u8, 206u8, 52u8, 23u8, 92u8, 31u8, 156u8,
							160u8, 25u8, 16u8, 125u8, 60u8, 9u8, 109u8, 145u8, 139u8, 102u8, 224u8,
						],
					)
				}
			}
		}
		#[doc = "The `Event` enum of this pallet"]
		pub type Event = runtime_types::pallet_treasury::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "We have ended a spend period and will now allocate funds."]
			pub struct Spending {
				pub budget_remaining: spending::BudgetRemaining,
			}
			pub mod spending {
				use super::runtime_types;
				pub type BudgetRemaining = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Spending {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "Spending";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some funds have been allocated."]
			pub struct Awarded {
				pub proposal_index: awarded::ProposalIndex,
				pub award: awarded::Award,
				pub account: awarded::Account,
			}
			pub mod awarded {
				use super::runtime_types;
				pub type ProposalIndex = ::core::primitive::u32;
				pub type Award = ::core::primitive::u128;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Awarded {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "Awarded";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some of our funds have been burnt."]
			pub struct Burnt {
				pub burnt_funds: burnt::BurntFunds,
			}
			pub mod burnt {
				use super::runtime_types;
				pub type BurntFunds = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Burnt {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "Burnt";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Spending has finished; this is the amount that rolls over until next spend."]
			pub struct Rollover {
				pub rollover_balance: rollover::RolloverBalance,
			}
			pub mod rollover {
				use super::runtime_types;
				pub type RolloverBalance = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Rollover {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "Rollover";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Some funds have been deposited."]
			pub struct Deposit {
				pub value: deposit::Value,
			}
			pub mod deposit {
				use super::runtime_types;
				pub type Value = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Deposit {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "Deposit";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A new spend proposal has been approved."]
			pub struct SpendApproved {
				pub proposal_index: spend_approved::ProposalIndex,
				pub amount: spend_approved::Amount,
				pub beneficiary: spend_approved::Beneficiary,
			}
			pub mod spend_approved {
				use super::runtime_types;
				pub type ProposalIndex = ::core::primitive::u32;
				pub type Amount = ::core::primitive::u128;
				pub type Beneficiary = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for SpendApproved {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "SpendApproved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "The inactive funds of the pallet have been updated."]
			pub struct UpdatedInactive {
				pub reactivated: updated_inactive::Reactivated,
				pub deactivated: updated_inactive::Deactivated,
			}
			pub mod updated_inactive {
				use super::runtime_types;
				pub type Reactivated = ::core::primitive::u128;
				pub type Deactivated = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for UpdatedInactive {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "UpdatedInactive";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A new asset spend proposal has been approved."]
			pub struct AssetSpendApproved {
				pub index: asset_spend_approved::Index,
				pub asset_kind: asset_spend_approved::AssetKind,
				pub amount: asset_spend_approved::Amount,
				pub beneficiary: asset_spend_approved::Beneficiary,
				pub valid_from: asset_spend_approved::ValidFrom,
				pub expire_at: asset_spend_approved::ExpireAt,
			}
			pub mod asset_spend_approved {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type AssetKind = ();
				pub type Amount = ::core::primitive::u128;
				pub type Beneficiary = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type ValidFrom = ::core::primitive::u32;
				pub type ExpireAt = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for AssetSpendApproved {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "AssetSpendApproved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "An approved spend was voided."]
			pub struct AssetSpendVoided {
				pub index: asset_spend_voided::Index,
			}
			pub mod asset_spend_voided {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for AssetSpendVoided {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "AssetSpendVoided";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A payment happened."]
			pub struct Paid {
				pub index: paid::Index,
				pub payment_id: paid::PaymentId,
			}
			pub mod paid {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type PaymentId = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for Paid {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "Paid";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A payment failed and can be retried."]
			pub struct PaymentFailed {
				pub index: payment_failed::Index,
				pub payment_id: payment_failed::PaymentId,
			}
			pub mod payment_failed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
				pub type PaymentId = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for PaymentFailed {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "PaymentFailed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A spend was processed and removed from the storage. It might have been successfully"]
			#[doc = "paid or it may have expired."]
			pub struct SpendProcessed {
				pub index: spend_processed::Index,
			}
			pub mod spend_processed {
				use super::runtime_types;
				pub type Index = ::core::primitive::u32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for SpendProcessed {
				const PALLET: &'static str = "TreasuryPallet";
				const EVENT: &'static str = "SpendProcessed";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod proposal_count {
					use super::runtime_types;
					pub type ProposalCount = ::core::primitive::u32;
				}
				pub mod proposals {
					use super::runtime_types;
					pub type Proposals = runtime_types::pallet_treasury::Proposal<
						::subxt::ext::subxt_core::utils::AccountId32,
						::core::primitive::u128,
					>;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod deactivated {
					use super::runtime_types;
					pub type Deactivated = ::core::primitive::u128;
				}
				pub mod approvals {
					use super::runtime_types;
					pub type Approvals =
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::core::primitive::u32,
						>;
				}
				pub mod spend_count {
					use super::runtime_types;
					pub type SpendCount = ::core::primitive::u32;
				}
				pub mod spends {
					use super::runtime_types;
					pub type Spends = runtime_types::pallet_treasury::SpendStatus<
						(),
						::core::primitive::u128,
						::subxt::ext::subxt_core::utils::AccountId32,
						::core::primitive::u32,
						::core::primitive::u32,
					>;
					pub type Param0 = ::core::primitive::u32;
				}
				pub mod last_spend_period {
					use super::runtime_types;
					pub type LastSpendPeriod = ::core::primitive::u32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " DEPRECATED: associated with `spend_local` call and will be removed in May 2025."]
				#[doc = " Refer to <https://github.com/paritytech/polkadot-sdk/pull/5961> for migration to `spend`."]
				#[doc = ""]
				#[doc = " Number of proposals that have been made."]
				pub fn proposal_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::proposal_count::ProposalCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"ProposalCount",
						(),
						[
							91u8, 238u8, 246u8, 106u8, 95u8, 66u8, 83u8, 134u8, 1u8, 225u8, 164u8,
							216u8, 113u8, 101u8, 203u8, 200u8, 113u8, 97u8, 246u8, 228u8, 140u8,
							29u8, 29u8, 48u8, 176u8, 137u8, 93u8, 230u8, 56u8, 75u8, 51u8, 149u8,
						],
					)
				}
				#[doc = " DEPRECATED: associated with `spend_local` call and will be removed in May 2025."]
				#[doc = " Refer to <https://github.com/paritytech/polkadot-sdk/pull/5961> for migration to `spend`."]
				#[doc = ""]
				#[doc = " Proposals that have been made."]
				pub fn proposals_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::proposals::Proposals,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Proposals",
						(),
						[
							207u8, 135u8, 145u8, 146u8, 48u8, 10u8, 252u8, 40u8, 20u8, 115u8,
							205u8, 41u8, 173u8, 83u8, 115u8, 46u8, 106u8, 40u8, 130u8, 157u8,
							213u8, 87u8, 45u8, 23u8, 14u8, 167u8, 99u8, 208u8, 153u8, 163u8, 141u8,
							55u8,
						],
					)
				}
				#[doc = " DEPRECATED: associated with `spend_local` call and will be removed in May 2025."]
				#[doc = " Refer to <https://github.com/paritytech/polkadot-sdk/pull/5961> for migration to `spend`."]
				#[doc = ""]
				#[doc = " Proposals that have been made."]
				pub fn proposals(
					&self,
					_0: types::proposals::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::proposals::Param0,
					>,
					types::proposals::Proposals,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Proposals",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							207u8, 135u8, 145u8, 146u8, 48u8, 10u8, 252u8, 40u8, 20u8, 115u8,
							205u8, 41u8, 173u8, 83u8, 115u8, 46u8, 106u8, 40u8, 130u8, 157u8,
							213u8, 87u8, 45u8, 23u8, 14u8, 167u8, 99u8, 208u8, 153u8, 163u8, 141u8,
							55u8,
						],
					)
				}
				#[doc = " The amount which has been reported as inactive to Currency."]
				pub fn deactivated(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::deactivated::Deactivated,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Deactivated",
						(),
						[
							120u8, 221u8, 159u8, 56u8, 161u8, 44u8, 54u8, 233u8, 47u8, 114u8,
							170u8, 150u8, 52u8, 24u8, 137u8, 212u8, 122u8, 247u8, 40u8, 17u8,
							208u8, 130u8, 42u8, 154u8, 33u8, 222u8, 59u8, 116u8, 0u8, 15u8, 79u8,
							123u8,
						],
					)
				}
				#[doc = " DEPRECATED: associated with `spend_local` call and will be removed in May 2025."]
				#[doc = " Refer to <https://github.com/paritytech/polkadot-sdk/pull/5961> for migration to `spend`."]
				#[doc = ""]
				#[doc = " Proposal indices that have been approved but not yet awarded."]
				pub fn approvals(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::approvals::Approvals,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Approvals",
						(),
						[
							78u8, 147u8, 186u8, 235u8, 17u8, 40u8, 247u8, 235u8, 67u8, 222u8, 3u8,
							14u8, 248u8, 17u8, 67u8, 180u8, 93u8, 161u8, 64u8, 35u8, 119u8, 194u8,
							187u8, 226u8, 135u8, 162u8, 147u8, 174u8, 139u8, 72u8, 99u8, 212u8,
						],
					)
				}
				#[doc = " The count of spends that have been made."]
				pub fn spend_count(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::spend_count::SpendCount,
					::subxt::ext::subxt_core::utils::Yes,
					::subxt::ext::subxt_core::utils::Yes,
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"SpendCount",
						(),
						[
							220u8, 74u8, 248u8, 52u8, 243u8, 209u8, 42u8, 236u8, 27u8, 98u8, 76u8,
							153u8, 129u8, 176u8, 34u8, 177u8, 33u8, 132u8, 21u8, 71u8, 206u8,
							146u8, 222u8, 44u8, 232u8, 246u8, 205u8, 92u8, 240u8, 136u8, 182u8,
							30u8,
						],
					)
				}
				#[doc = " Spends that have been approved and being processed."]
				pub fn spends_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::spends::Spends,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Spends",
						(),
						[
							140u8, 4u8, 241u8, 80u8, 4u8, 219u8, 107u8, 152u8, 206u8, 175u8, 107u8,
							172u8, 208u8, 71u8, 174u8, 99u8, 198u8, 52u8, 142u8, 126u8, 145u8,
							171u8, 254u8, 9u8, 235u8, 158u8, 186u8, 101u8, 140u8, 200u8, 96u8,
							168u8,
						],
					)
				}
				#[doc = " Spends that have been approved and being processed."]
				pub fn spends(
					&self,
					_0: types::spends::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::spends::Param0,
					>,
					types::spends::Spends,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Spends",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							140u8, 4u8, 241u8, 80u8, 4u8, 219u8, 107u8, 152u8, 206u8, 175u8, 107u8,
							172u8, 208u8, 71u8, 174u8, 99u8, 198u8, 52u8, 142u8, 126u8, 145u8,
							171u8, 254u8, 9u8, 235u8, 158u8, 186u8, 101u8, 140u8, 200u8, 96u8,
							168u8,
						],
					)
				}
				#[doc = " The blocknumber for the last triggered spend period."]
				pub fn last_spend_period(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::last_spend_period::LastSpendPeriod,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"TreasuryPallet",
						"LastSpendPeriod",
						(),
						[
							6u8, 200u8, 107u8, 132u8, 60u8, 31u8, 24u8, 196u8, 108u8, 227u8, 5u8,
							63u8, 249u8, 139u8, 82u8, 140u8, 169u8, 242u8, 118u8, 93u8, 83u8,
							155u8, 120u8, 175u8, 224u8, 227u8, 39u8, 39u8, 255u8, 247u8, 79u8,
							30u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " Period between successive spends."]
				pub fn spend_period(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TreasuryPallet",
						"SpendPeriod",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Percentage of spare funds (if any) that are burnt per spend period."]
				pub fn burn(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::sp_arithmetic::per_things::Permill,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TreasuryPallet",
						"Burn",
						[
							65u8, 93u8, 120u8, 165u8, 204u8, 81u8, 159u8, 163u8, 93u8, 135u8,
							114u8, 121u8, 147u8, 35u8, 215u8, 213u8, 4u8, 223u8, 83u8, 37u8, 225u8,
							200u8, 189u8, 156u8, 140u8, 36u8, 58u8, 46u8, 42u8, 232u8, 155u8, 0u8,
						],
					)
				}
				#[doc = " The treasury's pallet id, used for deriving its sovereign account ID."]
				pub fn pallet_id(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					runtime_types::frame_support::PalletId,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TreasuryPallet",
						"PalletId",
						[
							56u8, 243u8, 53u8, 83u8, 154u8, 179u8, 170u8, 80u8, 133u8, 173u8, 61u8,
							161u8, 47u8, 225u8, 146u8, 21u8, 50u8, 229u8, 248u8, 27u8, 104u8, 58u8,
							129u8, 197u8, 102u8, 160u8, 168u8, 205u8, 154u8, 42u8, 217u8, 53u8,
						],
					)
				}
				#[doc = " DEPRECATED: associated with `spend_local` call and will be removed in May 2025."]
				#[doc = " Refer to <https://github.com/paritytech/polkadot-sdk/pull/5961> for migration to `spend`."]
				#[doc = ""]
				#[doc = " The maximum number of approvals that can wait in the spending queue."]
				#[doc = ""]
				#[doc = " NOTE: This parameter is also used within the Bounties Pallet extension if enabled."]
				pub fn max_approvals(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TreasuryPallet",
						"MaxApprovals",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The period during which an approved treasury spend has to be claimed."]
				pub fn payout_period(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TreasuryPallet",
						"PayoutPeriod",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " Gets this pallet's derived pot account."]
				pub fn pot_account(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::subxt::ext::subxt_core::utils::AccountId32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"TreasuryPallet",
						"pot_account",
						[
							115u8, 233u8, 13u8, 223u8, 88u8, 20u8, 202u8, 139u8, 153u8, 28u8,
							155u8, 157u8, 224u8, 66u8, 3u8, 250u8, 23u8, 53u8, 88u8, 168u8, 211u8,
							204u8, 122u8, 166u8, 248u8, 23u8, 174u8, 225u8, 99u8, 108u8, 89u8,
							135u8,
						],
					)
				}
			}
		}
	}
	pub mod origins {
		use super::{root_mod, runtime_types};
	}
	pub mod recovery {
		use super::{root_mod, runtime_types};
		#[doc = "The `Error` enum of this pallet."]
		pub type Error = runtime_types::pallet_recovery::pallet::Error;
		#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
		pub type Call = runtime_types::pallet_recovery::pallet::Call;
		pub mod calls {
			use super::{root_mod, runtime_types};
			type DispatchError = runtime_types::sp_runtime::DispatchError;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Send a call through a recovered account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and registered to"]
				#[doc = "be able to make calls on behalf of the recovered account."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The recovered account you want to make a call on-behalf-of."]
				#[doc = "- `call`: The call you want to make with the recovered account."]
				pub struct AsRecovered {
					pub account: as_recovered::Account,
					pub call: ::subxt::ext::subxt_core::alloc::boxed::Box<as_recovered::Call>,
				}
				pub mod as_recovered {
					use super::runtime_types;
					pub type Account = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Call = runtime_types::quantus_runtime::RuntimeCall;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for AsRecovered {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "as_recovered";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Allow ROOT to bypass the recovery process and set a rescuer account"]
				#[doc = "for a lost account directly."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _ROOT_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `lost`: The \"lost account\" to be recovered."]
				#[doc = "- `rescuer`: The \"rescuer account\" which can call as the lost account."]
				pub struct SetRecovered {
					pub lost: set_recovered::Lost,
					pub rescuer: set_recovered::Rescuer,
				}
				pub mod set_recovered {
					use super::runtime_types;
					pub type Lost = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Rescuer = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for SetRecovered {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "set_recovered";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Create a recovery configuration for your account. This makes your account recoverable."]
				#[doc = ""]
				#[doc = "Payment: `ConfigDepositBase` + `FriendDepositFactor` * #_of_friends balance"]
				#[doc = "will be reserved for storing the recovery configuration. This deposit is returned"]
				#[doc = "in full when the user calls `remove_recovery`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `friends`: A list of friends you trust to vouch for recovery attempts. Should be"]
				#[doc = "  ordered and contain no duplicate values."]
				#[doc = "- `threshold`: The number of friends that must vouch for a recovery attempt before the"]
				#[doc = "  account can be recovered. Should be less than or equal to the length of the list of"]
				#[doc = "  friends."]
				#[doc = "- `delay_period`: The number of blocks after a recovery attempt is initialized that"]
				#[doc = "  needs to pass before the account can be recovered."]
				pub struct CreateRecovery {
					pub friends: create_recovery::Friends,
					pub threshold: create_recovery::Threshold,
					pub delay_period: create_recovery::DelayPeriod,
				}
				pub mod create_recovery {
					use super::runtime_types;
					pub type Friends = ::subxt::ext::subxt_core::alloc::vec::Vec<
						::subxt::ext::subxt_core::utils::AccountId32,
					>;
					pub type Threshold = ::core::primitive::u16;
					pub type DelayPeriod = ::core::primitive::u32;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CreateRecovery {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "create_recovery";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Initiate the process for recovering a recoverable account."]
				#[doc = ""]
				#[doc = "Payment: `RecoveryDeposit` balance will be reserved for initiating the"]
				#[doc = "recovery process. This deposit will always be repatriated to the account"]
				#[doc = "trying to be recovered. See `close_recovery`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The lost account that you want to recover. This account needs to be"]
				#[doc = "  recoverable (i.e. have a recovery configuration)."]
				pub struct InitiateRecovery {
					pub account: initiate_recovery::Account,
				}
				pub mod initiate_recovery {
					use super::runtime_types;
					pub type Account = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for InitiateRecovery {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "initiate_recovery";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Allow a \"friend\" of a recoverable account to vouch for an active recovery"]
				#[doc = "process for that account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a \"friend\""]
				#[doc = "for the recoverable account."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `lost`: The lost account that you want to recover."]
				#[doc = "- `rescuer`: The account trying to rescue the lost account that you want to vouch for."]
				#[doc = ""]
				#[doc = "The combination of these two parameters must point to an active recovery"]
				#[doc = "process."]
				pub struct VouchRecovery {
					pub lost: vouch_recovery::Lost,
					pub rescuer: vouch_recovery::Rescuer,
				}
				pub mod vouch_recovery {
					use super::runtime_types;
					pub type Lost = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
					pub type Rescuer = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for VouchRecovery {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "vouch_recovery";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Allow a successful rescuer to claim their recovered account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a \"rescuer\""]
				#[doc = "who has successfully completed the account recovery process: collected"]
				#[doc = "`threshold` or more vouches, waited `delay_period` blocks since initiation."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The lost account that you want to claim has been successfully recovered by"]
				#[doc = "  you."]
				pub struct ClaimRecovery {
					pub account: claim_recovery::Account,
				}
				pub mod claim_recovery {
					use super::runtime_types;
					pub type Account = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for ClaimRecovery {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "claim_recovery";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "As the controller of a recoverable account, close an active recovery"]
				#[doc = "process for your account."]
				#[doc = ""]
				#[doc = "Payment: By calling this function, the recoverable account will receive"]
				#[doc = "the recovery deposit `RecoveryDeposit` placed by the rescuer."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a"]
				#[doc = "recoverable account with an active recovery process for it."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `rescuer`: The account trying to rescue this recoverable account."]
				pub struct CloseRecovery {
					pub rescuer: close_recovery::Rescuer,
				}
				pub mod close_recovery {
					use super::runtime_types;
					pub type Rescuer = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CloseRecovery {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "close_recovery";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Remove the recovery process for your account. Recovered accounts are still accessible."]
				#[doc = ""]
				#[doc = "NOTE: The user must make sure to call `close_recovery` on all active"]
				#[doc = "recovery attempts before calling this function else it will fail."]
				#[doc = ""]
				#[doc = "Payment: By calling this function the recoverable account will unreserve"]
				#[doc = "their recovery configuration deposit."]
				#[doc = "(`ConfigDepositBase` + `FriendDepositFactor` * #_of_friends)"]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a"]
				#[doc = "recoverable account (i.e. has a recovery configuration)."]
				pub struct RemoveRecovery;
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for RemoveRecovery {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "remove_recovery";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Cancel the ability to use `as_recovered` for `account`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and registered to"]
				#[doc = "be able to make calls on behalf of the recovered account."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The recovered account you are able to call on-behalf-of."]
				pub struct CancelRecovered {
					pub account: cancel_recovered::Account,
				}
				pub mod cancel_recovered {
					use super::runtime_types;
					pub type Account = ::subxt::ext::subxt_core::utils::MultiAddress<
						::subxt::ext::subxt_core::utils::AccountId32,
						(),
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for CancelRecovered {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "cancel_recovered";
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Poke deposits for recovery configurations and / or active recoveries."]
				#[doc = ""]
				#[doc = "This can be used by accounts to possibly lower their locked amount."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `maybe_account`: Optional recoverable account for which you have an active recovery"]
				#[doc = "and want to adjust the deposit for the active recovery."]
				#[doc = ""]
				#[doc = "This function checks both recovery configuration deposit and active recovery deposits"]
				#[doc = "of the caller:"]
				#[doc = "- If the caller has created a recovery configuration, checks and adjusts its deposit"]
				#[doc = "- If the caller has initiated any active recoveries, and provides the account in"]
				#[doc = "`maybe_account`, checks and adjusts those deposits"]
				#[doc = ""]
				#[doc = "If any deposit is updated, the difference will be reserved/unreserved from the caller's"]
				#[doc = "account."]
				#[doc = ""]
				#[doc = "The transaction is made free if any deposit is updated and paid otherwise."]
				#[doc = ""]
				#[doc = "Emits `DepositPoked` if any deposit is updated."]
				#[doc = "Multiple events may be emitted in case both types of deposits are updated."]
				pub struct PokeDeposit {
					pub maybe_account: poke_deposit::MaybeAccount,
				}
				pub mod poke_deposit {
					use super::runtime_types;
					pub type MaybeAccount = ::core::option::Option<
						::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					>;
				}
				impl ::subxt::ext::subxt_core::blocks::StaticExtrinsic for PokeDeposit {
					const PALLET: &'static str = "Recovery";
					const CALL: &'static str = "poke_deposit";
				}
			}
			pub struct TransactionApi;
			impl TransactionApi {
				#[doc = "Send a call through a recovered account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and registered to"]
				#[doc = "be able to make calls on behalf of the recovered account."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The recovered account you want to make a call on-behalf-of."]
				#[doc = "- `call`: The call you want to make with the recovered account."]
				pub fn as_recovered(
					&self,
					account: types::as_recovered::Account,
					call: types::as_recovered::Call,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::AsRecovered> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"as_recovered",
						types::AsRecovered {
							account,
							call: ::subxt::ext::subxt_core::alloc::boxed::Box::new(call),
						},
						[
							45u8, 40u8, 208u8, 166u8, 146u8, 29u8, 213u8, 156u8, 75u8, 53u8, 244u8,
							220u8, 122u8, 44u8, 151u8, 109u8, 175u8, 181u8, 66u8, 52u8, 25u8,
							157u8, 43u8, 168u8, 32u8, 222u8, 85u8, 64u8, 68u8, 52u8, 22u8, 224u8,
						],
					)
				}
				#[doc = "Allow ROOT to bypass the recovery process and set a rescuer account"]
				#[doc = "for a lost account directly."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _ROOT_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `lost`: The \"lost account\" to be recovered."]
				#[doc = "- `rescuer`: The \"rescuer account\" which can call as the lost account."]
				pub fn set_recovered(
					&self,
					lost: types::set_recovered::Lost,
					rescuer: types::set_recovered::Rescuer,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::SetRecovered> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"set_recovered",
						types::SetRecovered { lost, rescuer },
						[
							194u8, 147u8, 14u8, 197u8, 132u8, 185u8, 122u8, 81u8, 61u8, 14u8, 10u8,
							177u8, 74u8, 184u8, 150u8, 217u8, 246u8, 149u8, 26u8, 165u8, 196u8,
							83u8, 230u8, 195u8, 213u8, 40u8, 51u8, 180u8, 23u8, 90u8, 3u8, 14u8,
						],
					)
				}
				#[doc = "Create a recovery configuration for your account. This makes your account recoverable."]
				#[doc = ""]
				#[doc = "Payment: `ConfigDepositBase` + `FriendDepositFactor` * #_of_friends balance"]
				#[doc = "will be reserved for storing the recovery configuration. This deposit is returned"]
				#[doc = "in full when the user calls `remove_recovery`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `friends`: A list of friends you trust to vouch for recovery attempts. Should be"]
				#[doc = "  ordered and contain no duplicate values."]
				#[doc = "- `threshold`: The number of friends that must vouch for a recovery attempt before the"]
				#[doc = "  account can be recovered. Should be less than or equal to the length of the list of"]
				#[doc = "  friends."]
				#[doc = "- `delay_period`: The number of blocks after a recovery attempt is initialized that"]
				#[doc = "  needs to pass before the account can be recovered."]
				pub fn create_recovery(
					&self,
					friends: types::create_recovery::Friends,
					threshold: types::create_recovery::Threshold,
					delay_period: types::create_recovery::DelayPeriod,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CreateRecovery>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"create_recovery",
						types::CreateRecovery { friends, threshold, delay_period },
						[
							36u8, 175u8, 11u8, 85u8, 95u8, 170u8, 58u8, 193u8, 102u8, 18u8, 117u8,
							27u8, 199u8, 214u8, 70u8, 47u8, 129u8, 130u8, 109u8, 242u8, 240u8,
							255u8, 120u8, 176u8, 40u8, 243u8, 175u8, 71u8, 3u8, 91u8, 186u8, 220u8,
						],
					)
				}
				#[doc = "Initiate the process for recovering a recoverable account."]
				#[doc = ""]
				#[doc = "Payment: `RecoveryDeposit` balance will be reserved for initiating the"]
				#[doc = "recovery process. This deposit will always be repatriated to the account"]
				#[doc = "trying to be recovered. See `close_recovery`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The lost account that you want to recover. This account needs to be"]
				#[doc = "  recoverable (i.e. have a recovery configuration)."]
				pub fn initiate_recovery(
					&self,
					account: types::initiate_recovery::Account,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::InitiateRecovery>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"initiate_recovery",
						types::InitiateRecovery { account },
						[
							60u8, 243u8, 229u8, 176u8, 221u8, 52u8, 44u8, 224u8, 233u8, 14u8, 89u8,
							100u8, 174u8, 74u8, 38u8, 32u8, 97u8, 48u8, 53u8, 74u8, 30u8, 242u8,
							19u8, 114u8, 145u8, 74u8, 69u8, 125u8, 227u8, 214u8, 144u8, 58u8,
						],
					)
				}
				#[doc = "Allow a \"friend\" of a recoverable account to vouch for an active recovery"]
				#[doc = "process for that account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a \"friend\""]
				#[doc = "for the recoverable account."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `lost`: The lost account that you want to recover."]
				#[doc = "- `rescuer`: The account trying to rescue the lost account that you want to vouch for."]
				#[doc = ""]
				#[doc = "The combination of these two parameters must point to an active recovery"]
				#[doc = "process."]
				pub fn vouch_recovery(
					&self,
					lost: types::vouch_recovery::Lost,
					rescuer: types::vouch_recovery::Rescuer,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::VouchRecovery>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"vouch_recovery",
						types::VouchRecovery { lost, rescuer },
						[
							97u8, 190u8, 60u8, 15u8, 191u8, 117u8, 1u8, 217u8, 62u8, 40u8, 210u8,
							1u8, 237u8, 111u8, 48u8, 196u8, 180u8, 154u8, 198u8, 12u8, 108u8, 42u8,
							6u8, 234u8, 2u8, 113u8, 163u8, 111u8, 80u8, 146u8, 6u8, 73u8,
						],
					)
				}
				#[doc = "Allow a successful rescuer to claim their recovered account."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a \"rescuer\""]
				#[doc = "who has successfully completed the account recovery process: collected"]
				#[doc = "`threshold` or more vouches, waited `delay_period` blocks since initiation."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The lost account that you want to claim has been successfully recovered by"]
				#[doc = "  you."]
				pub fn claim_recovery(
					&self,
					account: types::claim_recovery::Account,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::ClaimRecovery>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"claim_recovery",
						types::ClaimRecovery { account },
						[
							41u8, 47u8, 162u8, 88u8, 13u8, 166u8, 130u8, 146u8, 218u8, 162u8,
							166u8, 33u8, 89u8, 129u8, 177u8, 178u8, 68u8, 128u8, 161u8, 229u8,
							207u8, 3u8, 57u8, 35u8, 211u8, 208u8, 74u8, 155u8, 183u8, 173u8, 74u8,
							56u8,
						],
					)
				}
				#[doc = "As the controller of a recoverable account, close an active recovery"]
				#[doc = "process for your account."]
				#[doc = ""]
				#[doc = "Payment: By calling this function, the recoverable account will receive"]
				#[doc = "the recovery deposit `RecoveryDeposit` placed by the rescuer."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a"]
				#[doc = "recoverable account with an active recovery process for it."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `rescuer`: The account trying to rescue this recoverable account."]
				pub fn close_recovery(
					&self,
					rescuer: types::close_recovery::Rescuer,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CloseRecovery>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"close_recovery",
						types::CloseRecovery { rescuer },
						[
							161u8, 178u8, 117u8, 209u8, 119u8, 164u8, 135u8, 41u8, 25u8, 108u8,
							194u8, 175u8, 221u8, 65u8, 184u8, 137u8, 171u8, 97u8, 204u8, 61u8,
							159u8, 39u8, 192u8, 53u8, 246u8, 69u8, 113u8, 16u8, 170u8, 232u8,
							163u8, 10u8,
						],
					)
				}
				#[doc = "Remove the recovery process for your account. Recovered accounts are still accessible."]
				#[doc = ""]
				#[doc = "NOTE: The user must make sure to call `close_recovery` on all active"]
				#[doc = "recovery attempts before calling this function else it will fail."]
				#[doc = ""]
				#[doc = "Payment: By calling this function the recoverable account will unreserve"]
				#[doc = "their recovery configuration deposit."]
				#[doc = "(`ConfigDepositBase` + `FriendDepositFactor` * #_of_friends)"]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and must be a"]
				#[doc = "recoverable account (i.e. has a recovery configuration)."]
				pub fn remove_recovery(
					&self,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::RemoveRecovery>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"remove_recovery",
						types::RemoveRecovery {},
						[
							11u8, 38u8, 133u8, 172u8, 212u8, 252u8, 57u8, 216u8, 42u8, 202u8,
							206u8, 91u8, 115u8, 91u8, 242u8, 123u8, 95u8, 196u8, 172u8, 243u8,
							164u8, 1u8, 69u8, 180u8, 40u8, 68u8, 208u8, 221u8, 161u8, 250u8, 8u8,
							72u8,
						],
					)
				}
				#[doc = "Cancel the ability to use `as_recovered` for `account`."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_ and registered to"]
				#[doc = "be able to make calls on behalf of the recovered account."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `account`: The recovered account you are able to call on-behalf-of."]
				pub fn cancel_recovered(
					&self,
					account: types::cancel_recovered::Account,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::CancelRecovered>
				{
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"cancel_recovered",
						types::CancelRecovered { account },
						[
							100u8, 222u8, 80u8, 226u8, 187u8, 188u8, 111u8, 58u8, 190u8, 5u8,
							178u8, 144u8, 37u8, 98u8, 71u8, 145u8, 28u8, 248u8, 222u8, 188u8, 53u8,
							21u8, 127u8, 176u8, 249u8, 166u8, 250u8, 59u8, 170u8, 33u8, 251u8,
							239u8,
						],
					)
				}
				#[doc = "Poke deposits for recovery configurations and / or active recoveries."]
				#[doc = ""]
				#[doc = "This can be used by accounts to possibly lower their locked amount."]
				#[doc = ""]
				#[doc = "The dispatch origin for this call must be _Signed_."]
				#[doc = ""]
				#[doc = "Parameters:"]
				#[doc = "- `maybe_account`: Optional recoverable account for which you have an active recovery"]
				#[doc = "and want to adjust the deposit for the active recovery."]
				#[doc = ""]
				#[doc = "This function checks both recovery configuration deposit and active recovery deposits"]
				#[doc = "of the caller:"]
				#[doc = "- If the caller has created a recovery configuration, checks and adjusts its deposit"]
				#[doc = "- If the caller has initiated any active recoveries, and provides the account in"]
				#[doc = "`maybe_account`, checks and adjusts those deposits"]
				#[doc = ""]
				#[doc = "If any deposit is updated, the difference will be reserved/unreserved from the caller's"]
				#[doc = "account."]
				#[doc = ""]
				#[doc = "The transaction is made free if any deposit is updated and paid otherwise."]
				#[doc = ""]
				#[doc = "Emits `DepositPoked` if any deposit is updated."]
				#[doc = "Multiple events may be emitted in case both types of deposits are updated."]
				pub fn poke_deposit(
					&self,
					maybe_account: types::poke_deposit::MaybeAccount,
				) -> ::subxt::ext::subxt_core::tx::payload::StaticPayload<types::PokeDeposit> {
					::subxt::ext::subxt_core::tx::payload::StaticPayload::new_static(
						"Recovery",
						"poke_deposit",
						types::PokeDeposit { maybe_account },
						[
							177u8, 98u8, 53u8, 15u8, 228u8, 36u8, 173u8, 55u8, 125u8, 3u8, 234u8,
							70u8, 147u8, 147u8, 124u8, 86u8, 31u8, 101u8, 171u8, 56u8, 148u8,
							180u8, 87u8, 149u8, 11u8, 113u8, 195u8, 35u8, 56u8, 32u8, 251u8, 56u8,
						],
					)
				}
			}
		}
		#[doc = "Events type."]
		pub type Event = runtime_types::pallet_recovery::pallet::Event;
		pub mod events {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A recovery process has been set up for an account."]
			pub struct RecoveryCreated {
				pub account: recovery_created::Account,
			}
			pub mod recovery_created {
				use super::runtime_types;
				pub type Account = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RecoveryCreated {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "RecoveryCreated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A recovery process has been initiated for lost account by rescuer account."]
			pub struct RecoveryInitiated {
				pub lost_account: recovery_initiated::LostAccount,
				pub rescuer_account: recovery_initiated::RescuerAccount,
			}
			pub mod recovery_initiated {
				use super::runtime_types;
				pub type LostAccount = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type RescuerAccount = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RecoveryInitiated {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "RecoveryInitiated";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A recovery process for lost account by rescuer account has been vouched for by sender."]
			pub struct RecoveryVouched {
				pub lost_account: recovery_vouched::LostAccount,
				pub rescuer_account: recovery_vouched::RescuerAccount,
				pub sender: recovery_vouched::Sender,
			}
			pub mod recovery_vouched {
				use super::runtime_types;
				pub type LostAccount = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type RescuerAccount = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Sender = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RecoveryVouched {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "RecoveryVouched";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A recovery process for lost account by rescuer account has been closed."]
			pub struct RecoveryClosed {
				pub lost_account: recovery_closed::LostAccount,
				pub rescuer_account: recovery_closed::RescuerAccount,
			}
			pub mod recovery_closed {
				use super::runtime_types;
				pub type LostAccount = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type RescuerAccount = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RecoveryClosed {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "RecoveryClosed";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "Lost account has been successfully recovered by rescuer account."]
			pub struct AccountRecovered {
				pub lost_account: account_recovered::LostAccount,
				pub rescuer_account: account_recovered::RescuerAccount,
			}
			pub mod account_recovered {
				use super::runtime_types;
				pub type LostAccount = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type RescuerAccount = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for AccountRecovered {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "AccountRecovered";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A recovery process has been removed for an account."]
			pub struct RecoveryRemoved {
				pub lost_account: recovery_removed::LostAccount,
			}
			pub mod recovery_removed {
				use super::runtime_types;
				pub type LostAccount = ::subxt::ext::subxt_core::utils::AccountId32;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for RecoveryRemoved {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "RecoveryRemoved";
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			#[doc = "A deposit has been updated."]
			pub struct DepositPoked {
				pub who: deposit_poked::Who,
				pub kind: deposit_poked::Kind,
				pub old_deposit: deposit_poked::OldDeposit,
				pub new_deposit: deposit_poked::NewDeposit,
			}
			pub mod deposit_poked {
				use super::runtime_types;
				pub type Who = ::subxt::ext::subxt_core::utils::AccountId32;
				pub type Kind = runtime_types::pallet_recovery::DepositKind<
					runtime_types::quantus_runtime::Runtime,
				>;
				pub type OldDeposit = ::core::primitive::u128;
				pub type NewDeposit = ::core::primitive::u128;
			}
			impl ::subxt::ext::subxt_core::events::StaticEvent for DepositPoked {
				const PALLET: &'static str = "Recovery";
				const EVENT: &'static str = "DepositPoked";
			}
		}
		pub mod storage {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				pub mod recoverable {
					use super::runtime_types;
					pub type Recoverable = runtime_types::pallet_recovery::RecoveryConfig<
						::core::primitive::u32,
						::core::primitive::u128,
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::subxt::ext::subxt_core::utils::AccountId32,
						>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod active_recoveries {
					use super::runtime_types;
					pub type ActiveRecoveries = runtime_types::pallet_recovery::ActiveRecovery<
						::core::primitive::u32,
						::core::primitive::u128,
						runtime_types::bounded_collections::bounded_vec::BoundedVec<
							::subxt::ext::subxt_core::utils::AccountId32,
						>,
					>;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
					pub type Param1 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
				pub mod proxy {
					use super::runtime_types;
					pub type Proxy = ::subxt::ext::subxt_core::utils::AccountId32;
					pub type Param0 = ::subxt::ext::subxt_core::utils::AccountId32;
				}
			}
			pub struct StorageApi;
			impl StorageApi {
				#[doc = " The set of recoverable accounts and their recovery configuration."]
				pub fn recoverable_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::recoverable::Recoverable,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"Recoverable",
						(),
						[
							112u8, 7u8, 56u8, 46u8, 138u8, 197u8, 63u8, 234u8, 140u8, 123u8, 145u8,
							106u8, 189u8, 190u8, 247u8, 61u8, 250u8, 67u8, 107u8, 42u8, 170u8,
							79u8, 54u8, 168u8, 33u8, 214u8, 91u8, 227u8, 5u8, 107u8, 38u8, 26u8,
						],
					)
				}
				#[doc = " The set of recoverable accounts and their recovery configuration."]
				pub fn recoverable(
					&self,
					_0: types::recoverable::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::recoverable::Param0,
					>,
					types::recoverable::Recoverable,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"Recoverable",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							112u8, 7u8, 56u8, 46u8, 138u8, 197u8, 63u8, 234u8, 140u8, 123u8, 145u8,
							106u8, 189u8, 190u8, 247u8, 61u8, 250u8, 67u8, 107u8, 42u8, 170u8,
							79u8, 54u8, 168u8, 33u8, 214u8, 91u8, 227u8, 5u8, 107u8, 38u8, 26u8,
						],
					)
				}
				#[doc = " Active recovery attempts."]
				#[doc = ""]
				#[doc = " First account is the account to be recovered, and the second account"]
				#[doc = " is the user trying to recover the account."]
				pub fn active_recoveries_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::active_recoveries::ActiveRecoveries,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"ActiveRecoveries",
						(),
						[
							104u8, 252u8, 28u8, 142u8, 48u8, 26u8, 91u8, 201u8, 184u8, 163u8,
							180u8, 197u8, 189u8, 71u8, 144u8, 88u8, 225u8, 13u8, 183u8, 84u8,
							244u8, 41u8, 164u8, 212u8, 153u8, 247u8, 191u8, 25u8, 162u8, 25u8,
							91u8, 123u8,
						],
					)
				}
				#[doc = " Active recovery attempts."]
				#[doc = ""]
				#[doc = " First account is the account to be recovered, and the second account"]
				#[doc = " is the user trying to recover the account."]
				pub fn active_recoveries_iter1(
					&self,
					_0: types::active_recoveries::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::active_recoveries::Param0,
					>,
					types::active_recoveries::ActiveRecoveries,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"ActiveRecoveries",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							104u8, 252u8, 28u8, 142u8, 48u8, 26u8, 91u8, 201u8, 184u8, 163u8,
							180u8, 197u8, 189u8, 71u8, 144u8, 88u8, 225u8, 13u8, 183u8, 84u8,
							244u8, 41u8, 164u8, 212u8, 153u8, 247u8, 191u8, 25u8, 162u8, 25u8,
							91u8, 123u8,
						],
					)
				}
				#[doc = " Active recovery attempts."]
				#[doc = ""]
				#[doc = " First account is the account to be recovered, and the second account"]
				#[doc = " is the user trying to recover the account."]
				pub fn active_recoveries(
					&self,
					_0: types::active_recoveries::Param0,
					_1: types::active_recoveries::Param1,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::active_recoveries::Param0,
						>,
						::subxt::ext::subxt_core::storage::address::StaticStorageKey<
							types::active_recoveries::Param1,
						>,
					),
					types::active_recoveries::ActiveRecoveries,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"ActiveRecoveries",
						(
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
							::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_1),
						),
						[
							104u8, 252u8, 28u8, 142u8, 48u8, 26u8, 91u8, 201u8, 184u8, 163u8,
							180u8, 197u8, 189u8, 71u8, 144u8, 88u8, 225u8, 13u8, 183u8, 84u8,
							244u8, 41u8, 164u8, 212u8, 153u8, 247u8, 191u8, 25u8, 162u8, 25u8,
							91u8, 123u8,
						],
					)
				}
				#[doc = " The list of allowed proxy accounts."]
				#[doc = ""]
				#[doc = " Map from the user who can access it to the recovered account."]
				pub fn proxy_iter(
					&self,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					(),
					types::proxy::Proxy,
					(),
					(),
					::subxt::ext::subxt_core::utils::Yes,
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"Proxy",
						(),
						[
							161u8, 242u8, 17u8, 183u8, 161u8, 47u8, 87u8, 110u8, 201u8, 177u8,
							199u8, 157u8, 30u8, 131u8, 49u8, 89u8, 182u8, 86u8, 152u8, 19u8, 199u8,
							33u8, 12u8, 138u8, 51u8, 215u8, 130u8, 5u8, 251u8, 115u8, 69u8, 159u8,
						],
					)
				}
				#[doc = " The list of allowed proxy accounts."]
				#[doc = ""]
				#[doc = " Map from the user who can access it to the recovered account."]
				pub fn proxy(
					&self,
					_0: types::proxy::Param0,
				) -> ::subxt::ext::subxt_core::storage::address::StaticAddress<
					::subxt::ext::subxt_core::storage::address::StaticStorageKey<
						types::proxy::Param0,
					>,
					types::proxy::Proxy,
					::subxt::ext::subxt_core::utils::Yes,
					(),
					(),
				> {
					::subxt::ext::subxt_core::storage::address::StaticAddress::new_static(
						"Recovery",
						"Proxy",
						::subxt::ext::subxt_core::storage::address::StaticStorageKey::new(_0),
						[
							161u8, 242u8, 17u8, 183u8, 161u8, 47u8, 87u8, 110u8, 201u8, 177u8,
							199u8, 157u8, 30u8, 131u8, 49u8, 89u8, 182u8, 86u8, 152u8, 19u8, 199u8,
							33u8, 12u8, 138u8, 51u8, 215u8, 130u8, 5u8, 251u8, 115u8, 69u8, 159u8,
						],
					)
				}
			}
		}
		pub mod constants {
			use super::runtime_types;
			pub struct ConstantsApi;
			impl ConstantsApi {
				#[doc = " The base amount of currency needed to reserve for creating a recovery configuration."]
				#[doc = ""]
				#[doc = " This is held for an additional storage item whose value size is"]
				#[doc = " `2 + sizeof(BlockNumber, Balance)` bytes."]
				pub fn config_deposit_base(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Recovery",
						"ConfigDepositBase",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " The amount of currency needed per additional user when creating a recovery"]
				#[doc = " configuration."]
				#[doc = ""]
				#[doc = " This is held for adding `sizeof(AccountId)` bytes more into a pre-existing storage"]
				#[doc = " value."]
				pub fn friend_deposit_factor(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Recovery",
						"FriendDepositFactor",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
				#[doc = " The maximum amount of friends allowed in a recovery configuration."]
				#[doc = ""]
				#[doc = " NOTE: The threshold programmed in this Pallet uses u16, so it does"]
				#[doc = " not really make sense to have a limit here greater than u16::MAX."]
				#[doc = " But also, that is a lot more than you should probably set this value"]
				#[doc = " to anyway..."]
				pub fn max_friends(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u32,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Recovery",
						"MaxFriends",
						[
							98u8, 252u8, 116u8, 72u8, 26u8, 180u8, 225u8, 83u8, 200u8, 157u8,
							125u8, 151u8, 53u8, 76u8, 168u8, 26u8, 10u8, 9u8, 98u8, 68u8, 9u8,
							178u8, 197u8, 113u8, 31u8, 79u8, 200u8, 90u8, 203u8, 100u8, 41u8,
							145u8,
						],
					)
				}
				#[doc = " The base amount of currency needed to reserve for starting a recovery."]
				#[doc = ""]
				#[doc = " This is primarily held for deterring malicious recovery attempts, and should"]
				#[doc = " have a value large enough that a bad actor would choose not to place this"]
				#[doc = " deposit. It also acts to fund additional storage item whose value size is"]
				#[doc = " `sizeof(BlockNumber, Balance + T * AccountId)` bytes. Where T is a configurable"]
				#[doc = " threshold."]
				pub fn recovery_deposit(
					&self,
				) -> ::subxt::ext::subxt_core::constants::address::StaticAddress<
					::core::primitive::u128,
				> {
					::subxt::ext::subxt_core::constants::address::StaticAddress::new_static(
						"Recovery",
						"RecoveryDeposit",
						[
							84u8, 157u8, 140u8, 4u8, 93u8, 57u8, 29u8, 133u8, 105u8, 200u8, 214u8,
							27u8, 144u8, 208u8, 218u8, 160u8, 130u8, 109u8, 101u8, 54u8, 210u8,
							136u8, 71u8, 63u8, 49u8, 237u8, 234u8, 15u8, 178u8, 98u8, 148u8, 156u8,
						],
					)
				}
			}
		}
	}
	pub mod runtime_types {
		use super::runtime_types;
		pub mod bounded_collections {
			use super::runtime_types;
			pub mod bounded_vec {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct BoundedVec<_0>(pub ::subxt::ext::subxt_core::alloc::vec::Vec<_0>);
			}
			pub mod weak_bounded_vec {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct WeakBoundedVec<_0>(pub ::subxt::ext::subxt_core::alloc::vec::Vec<_0>);
			}
		}
		pub mod dilithium_crypto {
			use super::runtime_types;
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum DilithiumSignatureScheme {
					#[codec(index = 0)]
					Dilithium(runtime_types::dilithium_crypto::types::DilithiumSignatureWithPublic),
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct DilithiumSignatureWithPublic {
					pub bytes: [::core::primitive::u8; 7219usize],
				}
			}
		}
		pub mod frame_metadata_hash_extension {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct CheckMetadataHash {
				pub mode: runtime_types::frame_metadata_hash_extension::Mode,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum Mode {
				#[codec(index = 0)]
				Disabled,
				#[codec(index = 1)]
				Enabled,
			}
		}
		pub mod frame_support {
			use super::runtime_types;
			pub mod dispatch {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum DispatchClass {
					#[codec(index = 0)]
					Normal,
					#[codec(index = 1)]
					Operational,
					#[codec(index = 2)]
					Mandatory,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum Pays {
					#[codec(index = 0)]
					Yes,
					#[codec(index = 1)]
					No,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct PerDispatchClass<_0> {
					pub normal: _0,
					pub operational: _0,
					pub mandatory: _0,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct PostDispatchInfo {
					pub actual_weight:
						::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
					pub pays_fee: runtime_types::frame_support::dispatch::Pays,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum RawOrigin<_0> {
					#[codec(index = 0)]
					Root,
					#[codec(index = 1)]
					Signed(_0),
					#[codec(index = 2)]
					None,
					#[codec(index = 3)]
					Authorized,
				}
			}
			pub mod traits {
				use super::runtime_types;
				pub mod preimages {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub enum Bounded<_0, _1> {
						#[codec(index = 0)]
						Legacy {
							hash: ::subxt::ext::subxt_core::utils::H256,
						},
						#[codec(index = 1)]
						Inline(
							runtime_types::bounded_collections::bounded_vec::BoundedVec<
								::core::primitive::u8,
							>,
						),
						#[codec(index = 2)]
						Lookup {
							hash: ::subxt::ext::subxt_core::utils::H256,
							len: ::core::primitive::u32,
						},
						__Ignore(::core::marker::PhantomData<(_0, _1)>),
					}
				}
				pub mod schedule {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub enum DispatchTime<_0> {
						#[codec(index = 0)]
						At(_0),
						#[codec(index = 1)]
						After(_0),
					}
				}
				pub mod tokens {
					use super::runtime_types;
					pub mod misc {
						use super::runtime_types;
						#[derive(
							:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
							:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
							Debug,
						)]
						#[decode_as_type(
							crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
						)]
						#[encode_as_type(
							crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
						)]
						pub enum BalanceStatus {
							#[codec(index = 0)]
							Free,
							#[codec(index = 1)]
							Reserved,
						}
						#[derive(
							:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
							:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
							Debug,
						)]
						#[decode_as_type(
							crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
						)]
						#[encode_as_type(
							crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
						)]
						pub struct IdAmount<_0, _1> {
							pub id: _0,
							pub amount: _1,
						}
					}
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct PalletId(pub [::core::primitive::u8; 8usize]);
		}
		pub mod frame_system {
			use super::runtime_types;
			pub mod extensions {
				use super::runtime_types;
				pub mod check_genesis {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckGenesis;
				}
				pub mod check_mortality {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckMortality(pub runtime_types::sp_runtime::generic::era::Era);
				}
				pub mod check_non_zero_sender {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckNonZeroSender;
				}
				pub mod check_nonce {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckNonce(#[codec(compact)] pub ::core::primitive::u32);
				}
				pub mod check_spec_version {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckSpecVersion;
				}
				pub mod check_tx_version {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckTxVersion;
				}
				pub mod check_weight {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct CheckWeight;
				}
			}
			pub mod limits {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct BlockLength {
					pub max: runtime_types::frame_support::dispatch::PerDispatchClass<
						::core::primitive::u32,
					>,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct BlockWeights {
					pub base_block: runtime_types::sp_weights::weight_v2::Weight,
					pub max_block: runtime_types::sp_weights::weight_v2::Weight,
					pub per_class: runtime_types::frame_support::dispatch::PerDispatchClass<
						runtime_types::frame_system::limits::WeightsPerClass,
					>,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct WeightsPerClass {
					pub base_extrinsic: runtime_types::sp_weights::weight_v2::Weight,
					pub max_extrinsic:
						::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
					pub max_total:
						::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
					pub reserved:
						::core::option::Option<runtime_types::sp_weights::weight_v2::Weight>,
				}
			}
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Make some on-chain remark."]
					#[doc = ""]
					#[doc = "Can be executed by every `origin`."]
					remark {
						remark: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					},
					#[codec(index = 1)]
					#[doc = "Set the number of pages in the WebAssembly environment's heap."]
					set_heap_pages { pages: ::core::primitive::u64 },
					#[codec(index = 2)]
					#[doc = "Set the new runtime code."]
					set_code {
						code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					},
					#[codec(index = 3)]
					#[doc = "Set the new runtime code without doing any checks of the given `code`."]
					#[doc = ""]
					#[doc = "Note that runtime upgrades will not run if this is called with a not-increasing spec"]
					#[doc = "version!"]
					set_code_without_checks {
						code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					},
					#[codec(index = 4)]
					#[doc = "Set some items of storage."]
					set_storage {
						items: ::subxt::ext::subxt_core::alloc::vec::Vec<(
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						)>,
					},
					#[codec(index = 5)]
					#[doc = "Kill some items from storage."]
					kill_storage {
						keys: ::subxt::ext::subxt_core::alloc::vec::Vec<
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						>,
					},
					#[codec(index = 6)]
					#[doc = "Kill all storage items with a key that starts with the given prefix."]
					#[doc = ""]
					#[doc = "**NOTE:** We rely on the Root origin to provide us the number of subkeys under"]
					#[doc = "the prefix we are removing to accurately calculate the weight of this function."]
					kill_prefix {
						prefix: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						subkeys: ::core::primitive::u32,
					},
					#[codec(index = 7)]
					#[doc = "Make some on-chain remark and emit event."]
					remark_with_event {
						remark: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					},
					#[codec(index = 9)]
					#[doc = "Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied"]
					#[doc = "later."]
					#[doc = ""]
					#[doc = "This call requires Root origin."]
					authorize_upgrade { code_hash: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 10)]
					#[doc = "Authorize an upgrade to a given `code_hash` for the runtime. The runtime can be supplied"]
					#[doc = "later."]
					#[doc = ""]
					#[doc = "WARNING: This authorizes an upgrade that will take place without any safety checks, for"]
					#[doc = "example that the spec name remains the same and that the version number increases. Not"]
					#[doc = "recommended for normal use. Use `authorize_upgrade` instead."]
					#[doc = ""]
					#[doc = "This call requires Root origin."]
					authorize_upgrade_without_checks {
						code_hash: ::subxt::ext::subxt_core::utils::H256,
					},
					#[codec(index = 11)]
					#[doc = "Provide the preimage (runtime binary) `code` for an upgrade that has been authorized."]
					#[doc = ""]
					#[doc = "If the authorization required a version check, this call will ensure the spec name"]
					#[doc = "remains unchanged and that the spec version has increased."]
					#[doc = ""]
					#[doc = "Depending on the runtime's `OnSetCode` configuration, this function may directly apply"]
					#[doc = "the new `code` in the same block or attempt to schedule the upgrade."]
					#[doc = ""]
					#[doc = "All origins are allowed."]
					apply_authorized_upgrade {
						code: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Error for the System pallet"]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "The name of specification does not match between the current runtime"]
					#[doc = "and the new runtime."]
					InvalidSpecName,
					#[codec(index = 1)]
					#[doc = "The specification version is not allowed to decrease between the current runtime"]
					#[doc = "and the new runtime."]
					SpecVersionNeedsToIncrease,
					#[codec(index = 2)]
					#[doc = "Failed to extract the runtime version from the new runtime."]
					#[doc = ""]
					#[doc = "Either calling `Core_version` or decoding `RuntimeVersion` failed."]
					FailedToExtractRuntimeVersion,
					#[codec(index = 3)]
					#[doc = "Suicide called when the account has non-default composite data."]
					NonDefaultComposite,
					#[codec(index = 4)]
					#[doc = "There is a non-zero reference count preventing the account from being purged."]
					NonZeroRefCount,
					#[codec(index = 5)]
					#[doc = "The origin filter prevent the call to be dispatched."]
					CallFiltered,
					#[codec(index = 6)]
					#[doc = "A multi-block migration is ongoing and prevents the current code from being replaced."]
					MultiBlockMigrationsOngoing,
					#[codec(index = 7)]
					#[doc = "No upgrade authorized."]
					NothingAuthorized,
					#[codec(index = 8)]
					#[doc = "The submitted code is not authorized."]
					Unauthorized,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Event for the System pallet."]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "An extrinsic completed successfully."]
					ExtrinsicSuccess {
						dispatch_info: runtime_types::frame_system::DispatchEventInfo,
					},
					#[codec(index = 1)]
					#[doc = "An extrinsic failed."]
					ExtrinsicFailed {
						dispatch_error: runtime_types::sp_runtime::DispatchError,
						dispatch_info: runtime_types::frame_system::DispatchEventInfo,
					},
					#[codec(index = 2)]
					#[doc = "`:code` was updated."]
					CodeUpdated,
					#[codec(index = 3)]
					#[doc = "A new account was created."]
					NewAccount { account: ::subxt::ext::subxt_core::utils::AccountId32 },
					#[codec(index = 4)]
					#[doc = "An account was reaped."]
					KilledAccount { account: ::subxt::ext::subxt_core::utils::AccountId32 },
					#[codec(index = 5)]
					#[doc = "On on-chain remark happened."]
					Remarked {
						sender: ::subxt::ext::subxt_core::utils::AccountId32,
						hash: ::subxt::ext::subxt_core::utils::H256,
					},
					#[codec(index = 6)]
					#[doc = "An upgrade was authorized."]
					UpgradeAuthorized {
						code_hash: ::subxt::ext::subxt_core::utils::H256,
						check_version: ::core::primitive::bool,
					},
					#[codec(index = 7)]
					#[doc = "An invalid authorized upgrade was rejected while trying to apply it."]
					RejectedInvalidAuthorizedUpgrade {
						code_hash: ::subxt::ext::subxt_core::utils::H256,
						error: runtime_types::sp_runtime::DispatchError,
					},
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct AccountInfo<_0, _1> {
				pub nonce: _0,
				pub consumers: ::core::primitive::u32,
				pub providers: ::core::primitive::u32,
				pub sufficients: ::core::primitive::u32,
				pub data: _1,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct CodeUpgradeAuthorization {
				pub code_hash: ::subxt::ext::subxt_core::utils::H256,
				pub check_version: ::core::primitive::bool,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct DispatchEventInfo {
				pub weight: runtime_types::sp_weights::weight_v2::Weight,
				pub class: runtime_types::frame_support::dispatch::DispatchClass,
				pub pays_fee: runtime_types::frame_support::dispatch::Pays,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct EventRecord<_0, _1> {
				pub phase: runtime_types::frame_system::Phase,
				pub event: _0,
				pub topics: ::subxt::ext::subxt_core::alloc::vec::Vec<_1>,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct LastRuntimeUpgradeInfo {
				#[codec(compact)]
				pub spec_version: ::core::primitive::u32,
				pub spec_name: ::subxt::ext::subxt_core::alloc::string::String,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum Phase {
				#[codec(index = 0)]
				ApplyExtrinsic(::core::primitive::u32),
				#[codec(index = 1)]
				Finalization,
				#[codec(index = 2)]
				Initialization,
			}
		}
		pub mod pallet_balances {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Transfer some liquid free balance to another account."]
					#[doc = ""]
					#[doc = "`transfer_allow_death` will set the `FreeBalance` of the sender and receiver."]
					#[doc = "If the sender's account is below the existential deposit as a result"]
					#[doc = "of the transfer, the account will be reaped."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be `Signed` by the transactor."]
					transfer_allow_death {
						dest: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						#[codec(compact)]
						value: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "Exactly as `transfer_allow_death`, except the origin must be root and the source account"]
					#[doc = "may be specified."]
					force_transfer {
						source: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						dest: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						#[codec(compact)]
						value: ::core::primitive::u128,
					},
					#[codec(index = 3)]
					#[doc = "Same as the [`transfer_allow_death`] call, but with a check that the transfer will not"]
					#[doc = "kill the origin account."]
					#[doc = ""]
					#[doc = "99% of the time you want [`transfer_allow_death`] instead."]
					#[doc = ""]
					#[doc = "[`transfer_allow_death`]: struct.Pallet.html#method.transfer"]
					transfer_keep_alive {
						dest: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						#[codec(compact)]
						value: ::core::primitive::u128,
					},
					#[codec(index = 4)]
					#[doc = "Transfer the entire transferable balance from the caller account."]
					#[doc = ""]
					#[doc = "NOTE: This function only attempts to transfer _transferable_ balances. This means that"]
					#[doc = "any locked, reserved, or existential deposits (when `keep_alive` is `true`), will not be"]
					#[doc = "transferred by this function. To ensure that this function results in a killed account,"]
					#[doc = "you might need to prepare the account by removing any reference counters, storage"]
					#[doc = "deposits, etc..."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be Signed."]
					#[doc = ""]
					#[doc = "- `dest`: The recipient of the transfer."]
					#[doc = "- `keep_alive`: A boolean to determine if the `transfer_all` operation should send all"]
					#[doc = "  of the funds the account has, causing the sender account to be killed (false), or"]
					#[doc = "  transfer everything except at least the existential deposit, which will guarantee to"]
					#[doc = "  keep the sender account alive (true)."]
					transfer_all {
						dest: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						keep_alive: ::core::primitive::bool,
					},
					#[codec(index = 5)]
					#[doc = "Unreserve some balance from a user by force."]
					#[doc = ""]
					#[doc = "Can only be called by ROOT."]
					force_unreserve {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 6)]
					#[doc = "Upgrade a specified account."]
					#[doc = ""]
					#[doc = "- `origin`: Must be `Signed`."]
					#[doc = "- `who`: The account to be upgraded."]
					#[doc = ""]
					#[doc = "This will waive the transaction fee if at least all but 10% of the accounts needed to"]
					#[doc = "be upgraded. (We let some not have to be upgraded just in order to allow for the"]
					#[doc = "possibility of churn)."]
					upgrade_accounts {
						who: ::subxt::ext::subxt_core::alloc::vec::Vec<
							::subxt::ext::subxt_core::utils::AccountId32,
						>,
					},
					#[codec(index = 8)]
					#[doc = "Set the regular balance of a given account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call is `root`."]
					force_set_balance {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						#[codec(compact)]
						new_free: ::core::primitive::u128,
					},
					#[codec(index = 9)]
					#[doc = "Adjust the total issuance in a saturating way."]
					#[doc = ""]
					#[doc = "Can only be called by root and always needs a positive `delta`."]
					#[doc = ""]
					#[doc = "# Example"]
					force_adjust_total_issuance {
						direction: runtime_types::pallet_balances::types::AdjustmentDirection,
						#[codec(compact)]
						delta: ::core::primitive::u128,
					},
					#[codec(index = 10)]
					#[doc = "Burn the specified liquid free balance from the origin account."]
					#[doc = ""]
					#[doc = "If the origin's account ends up below the existential deposit as a result"]
					#[doc = "of the burn and `keep_alive` is false, the account will be reaped."]
					#[doc = ""]
					#[doc = "Unlike sending funds to a _burn_ address, which merely makes the funds inaccessible,"]
					#[doc = "this `burn` operation will reduce total issuance by the amount _burned_."]
					burn {
						#[codec(compact)]
						value: ::core::primitive::u128,
						keep_alive: ::core::primitive::bool,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Vesting balance too high to send value."]
					VestingBalance,
					#[codec(index = 1)]
					#[doc = "Account liquidity restrictions prevent withdrawal."]
					LiquidityRestrictions,
					#[codec(index = 2)]
					#[doc = "Balance too low to send value."]
					InsufficientBalance,
					#[codec(index = 3)]
					#[doc = "Value too low to create account due to existential deposit."]
					ExistentialDeposit,
					#[codec(index = 4)]
					#[doc = "Transfer/payment would kill account."]
					Expendability,
					#[codec(index = 5)]
					#[doc = "A vesting schedule already exists for this account."]
					ExistingVestingSchedule,
					#[codec(index = 6)]
					#[doc = "Beneficiary account must pre-exist."]
					DeadAccount,
					#[codec(index = 7)]
					#[doc = "Number of named reserves exceed `MaxReserves`."]
					TooManyReserves,
					#[codec(index = 8)]
					#[doc = "Number of holds exceed `VariantCountOf<T::RuntimeHoldReason>`."]
					TooManyHolds,
					#[codec(index = 9)]
					#[doc = "Number of freezes exceed `MaxFreezes`."]
					TooManyFreezes,
					#[codec(index = 10)]
					#[doc = "The issuance cannot be modified since it is already deactivated."]
					IssuanceDeactivated,
					#[codec(index = 11)]
					#[doc = "The delta cannot be zero."]
					DeltaZero,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "An account was created with some free balance."]
					Endowed {
						account: ::subxt::ext::subxt_core::utils::AccountId32,
						free_balance: ::core::primitive::u128,
					},
					#[codec(index = 1)]
					#[doc = "An account was removed whose balance was non-zero but below ExistentialDeposit,"]
					#[doc = "resulting in an outright loss."]
					DustLost {
						account: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "Transfer succeeded."]
					Transfer {
						from: ::subxt::ext::subxt_core::utils::AccountId32,
						to: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 3)]
					#[doc = "A balance was set by root."]
					BalanceSet {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						free: ::core::primitive::u128,
					},
					#[codec(index = 4)]
					#[doc = "Some balance was reserved (moved from free to reserved)."]
					Reserved {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 5)]
					#[doc = "Some balance was unreserved (moved from reserved to free)."]
					Unreserved {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 6)]
					#[doc = "Some balance was moved from the reserve of the first account to the second account."]
					#[doc = "Final argument indicates the destination balance type."]
					ReserveRepatriated {
						from: ::subxt::ext::subxt_core::utils::AccountId32,
						to: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
						destination_status:
							runtime_types::frame_support::traits::tokens::misc::BalanceStatus,
					},
					#[codec(index = 7)]
					#[doc = "Some amount was deposited (e.g. for transaction fees)."]
					Deposit {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 8)]
					#[doc = "Some amount was withdrawn from the account (e.g. for transaction fees)."]
					Withdraw {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 9)]
					#[doc = "Some amount was removed from the account (e.g. for misbehavior)."]
					Slashed {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 10)]
					#[doc = "Some amount was minted into an account."]
					Minted {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 11)]
					#[doc = "Some amount was burned from an account."]
					Burned {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 12)]
					#[doc = "Some amount was suspended from an account (it can be restored later)."]
					Suspended {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 13)]
					#[doc = "Some amount was restored into an account."]
					Restored {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 14)]
					#[doc = "An account was upgraded."]
					Upgraded { who: ::subxt::ext::subxt_core::utils::AccountId32 },
					#[codec(index = 15)]
					#[doc = "Total issuance was increased by `amount`, creating a credit to be balanced."]
					Issued { amount: ::core::primitive::u128 },
					#[codec(index = 16)]
					#[doc = "Total issuance was decreased by `amount`, creating a debt to be balanced."]
					Rescinded { amount: ::core::primitive::u128 },
					#[codec(index = 17)]
					#[doc = "Some balance was locked."]
					Locked {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 18)]
					#[doc = "Some balance was unlocked."]
					Unlocked {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 19)]
					#[doc = "Some balance was frozen."]
					Frozen {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 20)]
					#[doc = "Some balance was thawed."]
					Thawed {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 21)]
					#[doc = "The `TotalIssuance` was forcefully changed."]
					TotalIssuanceForced {
						old: ::core::primitive::u128,
						new: ::core::primitive::u128,
					},
				}
			}
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct AccountData<_0> {
					pub free: _0,
					pub reserved: _0,
					pub frozen: _0,
					pub flags: runtime_types::pallet_balances::types::ExtraFlags,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum AdjustmentDirection {
					#[codec(index = 0)]
					Increase,
					#[codec(index = 1)]
					Decrease,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct BalanceLock<_0> {
					pub id: [::core::primitive::u8; 8usize],
					pub amount: _0,
					pub reasons: runtime_types::pallet_balances::types::Reasons,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ExtraFlags(pub ::core::primitive::u128);
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum Reasons {
					#[codec(index = 0)]
					Fee,
					#[codec(index = 1)]
					Misc,
					#[codec(index = 2)]
					All,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ReserveData<_0, _1> {
					pub id: _0,
					pub amount: _1,
				}
			}
		}
		pub mod pallet_conviction_voting {
			use super::runtime_types;
			pub mod conviction {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum Conviction {
					#[codec(index = 0)]
					None,
					#[codec(index = 1)]
					Locked1x,
					#[codec(index = 2)]
					Locked2x,
					#[codec(index = 3)]
					Locked3x,
					#[codec(index = 4)]
					Locked4x,
					#[codec(index = 5)]
					Locked5x,
					#[codec(index = 6)]
					Locked6x,
				}
			}
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Vote in a poll. If `vote.is_aye()`, the vote is to enact the proposal;"]
					#[doc = "otherwise it is a vote to keep the status quo."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be _Signed_."]
					#[doc = ""]
					#[doc = "- `poll_index`: The index of the poll to vote for."]
					#[doc = "- `vote`: The vote configuration."]
					#[doc = ""]
					#[doc = "Weight: `O(R)` where R is the number of polls the voter has voted on."]
					vote {
						#[codec(compact)]
						poll_index: ::core::primitive::u32,
						vote: runtime_types::pallet_conviction_voting::vote::AccountVote<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 1)]
					#[doc = "Delegate the voting power (with some given conviction) of the sending account for a"]
					#[doc = "particular class of polls."]
					#[doc = ""]
					#[doc = "The balance delegated is locked for as long as it's delegated, and thereafter for the"]
					#[doc = "time appropriate for the conviction's lock period."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be _Signed_, and the signing account must either:"]
					#[doc = "  - be delegating already; or"]
					#[doc = "  - have no voting activity (if there is, then it will need to be removed through"]
					#[doc = "    `remove_vote`)."]
					#[doc = ""]
					#[doc = "- `to`: The account whose voting the `target` account's voting power will follow."]
					#[doc = "- `class`: The class of polls to delegate. To delegate multiple classes, multiple calls"]
					#[doc = "  to this function are required."]
					#[doc = "- `conviction`: The conviction that will be attached to the delegated votes. When the"]
					#[doc = "  account is undelegated, the funds will be locked for the corresponding period."]
					#[doc = "- `balance`: The amount of the account's balance to be used in delegating. This must not"]
					#[doc = "  be more than the account's current balance."]
					#[doc = ""]
					#[doc = "Emits `Delegated`."]
					#[doc = ""]
					#[doc = "Weight: `O(R)` where R is the number of polls the voter delegating to has"]
					#[doc = "  voted on. Weight is initially charged as if maximum votes, but is refunded later."]
					delegate {
						class: ::core::primitive::u16,
						to: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						conviction: runtime_types::pallet_conviction_voting::conviction::Conviction,
						balance: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "Undelegate the voting power of the sending account for a particular class of polls."]
					#[doc = ""]
					#[doc = "Tokens may be unlocked following once an amount of time consistent with the lock period"]
					#[doc = "of the conviction with which the delegation was issued has passed."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be _Signed_ and the signing account must be"]
					#[doc = "currently delegating."]
					#[doc = ""]
					#[doc = "- `class`: The class of polls to remove the delegation from."]
					#[doc = ""]
					#[doc = "Emits `Undelegated`."]
					#[doc = ""]
					#[doc = "Weight: `O(R)` where R is the number of polls the voter delegating to has"]
					#[doc = "  voted on. Weight is initially charged as if maximum votes, but is refunded later."]
					undelegate { class: ::core::primitive::u16 },
					#[codec(index = 3)]
					#[doc = "Remove the lock caused by prior voting/delegating which has expired within a particular"]
					#[doc = "class."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be _Signed_."]
					#[doc = ""]
					#[doc = "- `class`: The class of polls to unlock."]
					#[doc = "- `target`: The account to remove the lock on."]
					#[doc = ""]
					#[doc = "Weight: `O(R)` with R number of vote of target."]
					unlock {
						class: ::core::primitive::u16,
						target: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 4)]
					#[doc = "Remove a vote for a poll."]
					#[doc = ""]
					#[doc = "If:"]
					#[doc = "- the poll was cancelled, or"]
					#[doc = "- the poll is ongoing, or"]
					#[doc = "- the poll has ended such that"]
					#[doc = "  - the vote of the account was in opposition to the result; or"]
					#[doc = "  - there was no conviction to the account's vote; or"]
					#[doc = "  - the account made a split vote"]
					#[doc = "...then the vote is removed cleanly and a following call to `unlock` may result in more"]
					#[doc = "funds being available."]
					#[doc = ""]
					#[doc = "If, however, the poll has ended and:"]
					#[doc = "- it finished corresponding to the vote of the account, and"]
					#[doc = "- the account made a standard vote with conviction, and"]
					#[doc = "- the lock period of the conviction is not over"]
					#[doc = "...then the lock will be aggregated into the overall account's lock, which may involve"]
					#[doc = "*overlocking* (where the two locks are combined into a single lock that is the maximum"]
					#[doc = "of both the amount locked and the time is it locked for)."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be _Signed_, and the signer must have a vote"]
					#[doc = "registered for poll `index`."]
					#[doc = ""]
					#[doc = "- `index`: The index of poll of the vote to be removed."]
					#[doc = "- `class`: Optional parameter, if given it indicates the class of the poll. For polls"]
					#[doc = "  which have finished or are cancelled, this must be `Some`."]
					#[doc = ""]
					#[doc = "Weight: `O(R + log R)` where R is the number of polls that `target` has voted on."]
					#[doc = "  Weight is calculated for the maximum number of vote."]
					remove_vote {
						class: ::core::option::Option<::core::primitive::u16>,
						index: ::core::primitive::u32,
					},
					#[codec(index = 5)]
					#[doc = "Remove a vote for a poll."]
					#[doc = ""]
					#[doc = "If the `target` is equal to the signer, then this function is exactly equivalent to"]
					#[doc = "`remove_vote`. If not equal to the signer, then the vote must have expired,"]
					#[doc = "either because the poll was cancelled, because the voter lost the poll or"]
					#[doc = "because the conviction period is over."]
					#[doc = ""]
					#[doc = "The dispatch origin of this call must be _Signed_."]
					#[doc = ""]
					#[doc = "- `target`: The account of the vote to be removed; this account must have voted for poll"]
					#[doc = "  `index`."]
					#[doc = "- `index`: The index of poll of the vote to be removed."]
					#[doc = "- `class`: The class of the poll."]
					#[doc = ""]
					#[doc = "Weight: `O(R + log R)` where R is the number of polls that `target` has voted on."]
					#[doc = "  Weight is calculated for the maximum number of vote."]
					remove_other_vote {
						target: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						class: ::core::primitive::u16,
						index: ::core::primitive::u32,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Poll is not ongoing."]
					NotOngoing,
					#[codec(index = 1)]
					#[doc = "The given account did not vote on the poll."]
					NotVoter,
					#[codec(index = 2)]
					#[doc = "The actor has no permission to conduct the action."]
					NoPermission,
					#[codec(index = 3)]
					#[doc = "The actor has no permission to conduct the action right now but will do in the future."]
					NoPermissionYet,
					#[codec(index = 4)]
					#[doc = "The account is already delegating."]
					AlreadyDelegating,
					#[codec(index = 5)]
					#[doc = "The account currently has votes attached to it and the operation cannot succeed until"]
					#[doc = "these are removed through `remove_vote`."]
					AlreadyVoting,
					#[codec(index = 6)]
					#[doc = "Too high a balance was provided that the account cannot afford."]
					InsufficientFunds,
					#[codec(index = 7)]
					#[doc = "The account is not currently delegating."]
					NotDelegating,
					#[codec(index = 8)]
					#[doc = "Delegation to oneself makes no sense."]
					Nonsense,
					#[codec(index = 9)]
					#[doc = "Maximum number of votes reached."]
					MaxVotesReached,
					#[codec(index = 10)]
					#[doc = "The class must be supplied since it is not easily determinable from the state."]
					ClassNeeded,
					#[codec(index = 11)]
					#[doc = "The class ID supplied is invalid."]
					BadClass,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "An account has delegated their vote to another account. \\[who, target\\]"]
					Delegated(
						::subxt::ext::subxt_core::utils::AccountId32,
						::subxt::ext::subxt_core::utils::AccountId32,
					),
					#[codec(index = 1)]
					#[doc = "An \\[account\\] has cancelled a previous delegation operation."]
					Undelegated(::subxt::ext::subxt_core::utils::AccountId32),
					#[codec(index = 2)]
					#[doc = "An account has voted"]
					Voted {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						vote: runtime_types::pallet_conviction_voting::vote::AccountVote<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 3)]
					#[doc = "A vote has been removed"]
					VoteRemoved {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						vote: runtime_types::pallet_conviction_voting::vote::AccountVote<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 4)]
					#[doc = "The lockup period of a conviction vote expired, and the funds have been unlocked."]
					VoteUnlocked {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						class: ::core::primitive::u16,
					},
				}
			}
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Delegations<_0> {
					pub votes: _0,
					pub capital: _0,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Tally<_0> {
					pub ayes: _0,
					pub nays: _0,
					pub support: _0,
				}
			}
			pub mod vote {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum AccountVote<_0> {
					#[codec(index = 0)]
					Standard {
						vote: runtime_types::pallet_conviction_voting::vote::Vote,
						balance: _0,
					},
					#[codec(index = 1)]
					Split { aye: _0, nay: _0 },
					#[codec(index = 2)]
					SplitAbstain { aye: _0, nay: _0, abstain: _0 },
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Casting<_0, _1, _2> {
					pub votes: runtime_types::bounded_collections::bounded_vec::BoundedVec<(
						_1,
						runtime_types::pallet_conviction_voting::vote::AccountVote<_0>,
					)>,
					pub delegations:
						runtime_types::pallet_conviction_voting::types::Delegations<_0>,
					pub prior: runtime_types::pallet_conviction_voting::vote::PriorLock<_1, _0>,
					#[codec(skip)]
					pub __ignore: ::core::marker::PhantomData<_2>,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Delegating<_0, _1, _2> {
					pub balance: _0,
					pub target: _1,
					pub conviction: runtime_types::pallet_conviction_voting::conviction::Conviction,
					pub delegations:
						runtime_types::pallet_conviction_voting::types::Delegations<_0>,
					pub prior: runtime_types::pallet_conviction_voting::vote::PriorLock<_2, _0>,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct PriorLock<_0, _1>(pub _0, pub _1);
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Vote(pub ::core::primitive::u8);
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum Voting<_0, _1, _2, _3> {
					#[codec(index = 0)]
					Casting(runtime_types::pallet_conviction_voting::vote::Casting<_0, _2, _2>),
					#[codec(index = 1)]
					Delegating(
						runtime_types::pallet_conviction_voting::vote::Delegating<_0, _1, _2>,
					),
					__Ignore(::core::marker::PhantomData<_3>),
				}
			}
		}
		pub mod pallet_merkle_airdrop {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Create a new airdrop with a Merkle root."]
					#[doc = ""]
					#[doc = "The Merkle root is a cryptographic hash that represents all valid claims"]
					#[doc = "for this airdrop. Users will later provide Merkle proofs to verify their"]
					#[doc = "eligibility to claim tokens."]
					#[doc = ""]
					#[doc = "# Parameters"]
					#[doc = ""]
					#[doc = "* `origin` - The origin of the call (must be signed)"]
					#[doc = "* `merkle_root` - The Merkle root hash representing all valid claims"]
					#[doc = "* `vesting_period` - Optional vesting period for the airdrop"]
					#[doc = "* `vesting_delay` - Optional delay before vesting starts"]
					create_airdrop {
						merkle_root: [::core::primitive::u8; 32usize],
						vesting_period: ::core::option::Option<::core::primitive::u32>,
						vesting_delay: ::core::option::Option<::core::primitive::u32>,
					},
					#[codec(index = 1)]
					#[doc = "Fund an existing airdrop with tokens."]
					#[doc = ""]
					#[doc = "This function transfers tokens from the caller to the airdrop's account,"]
					#[doc = "making them available for users to claim."]
					#[doc = ""]
					#[doc = "# Parameters"]
					#[doc = ""]
					#[doc = "* `origin` - The origin of the call (must be signed)"]
					#[doc = "* `airdrop_id` - The ID of the airdrop to fund"]
					#[doc = "* `amount` - The amount of tokens to add to the airdrop"]
					#[doc = ""]
					#[doc = "# Errors"]
					#[doc = ""]
					#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
					fund_airdrop {
						airdrop_id: ::core::primitive::u32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "Claim tokens from an airdrop by providing a Merkle proof."]
					#[doc = ""]
					#[doc = "Users can claim their tokens by providing a proof of their eligibility."]
					#[doc = "The proof is verified against the airdrop's Merkle root."]
					#[doc = "Anyone can trigger a claim for any eligible recipient."]
					#[doc = ""]
					#[doc = "# Parameters"]
					#[doc = ""]
					#[doc = "* `origin` - The origin of the call"]
					#[doc = "* `airdrop_id` - The ID of the airdrop to claim from"]
					#[doc = "* `amount` - The amount of tokens to claim"]
					#[doc = "* `merkle_proof` - The Merkle proof verifying eligibility"]
					#[doc = ""]
					#[doc = "# Errors"]
					#[doc = ""]
					#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
					#[doc = "* `AlreadyClaimed` - If the recipient has already claimed from this airdrop"]
					#[doc = "* `InvalidProof` - If the provided Merkle proof is invalid"]
					#[doc = "* `InsufficientAirdropBalance` - If the airdrop doesn't have enough tokens"]
					claim {
						airdrop_id: ::core::primitive::u32,
						recipient: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
						merkle_proof: runtime_types::bounded_collections::bounded_vec::BoundedVec<
							[::core::primitive::u8; 32usize],
						>,
					},
					#[codec(index = 3)]
					#[doc = "Delete an airdrop and reclaim any remaining funds."]
					#[doc = ""]
					#[doc = "This function allows the creator of an airdrop to delete it and reclaim"]
					#[doc = "any remaining tokens that haven't been claimed."]
					#[doc = ""]
					#[doc = "# Parameters"]
					#[doc = ""]
					#[doc = "* `origin` - The origin of the call (must be the airdrop creator)"]
					#[doc = "* `airdrop_id` - The ID of the airdrop to delete"]
					#[doc = ""]
					#[doc = "# Errors"]
					#[doc = ""]
					#[doc = "* `AirdropNotFound` - If the specified airdrop does not exist"]
					#[doc = "* `NotAirdropCreator` - If the caller is not the creator of the airdrop"]
					delete_airdrop { airdrop_id: ::core::primitive::u32 },
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "The specified airdrop does not exist."]
					AirdropNotFound,
					#[codec(index = 1)]
					#[doc = "The airdrop does not have sufficient balance for this operation."]
					InsufficientAirdropBalance,
					#[codec(index = 2)]
					#[doc = "The user has already claimed from this airdrop."]
					AlreadyClaimed,
					#[codec(index = 3)]
					#[doc = "The provided Merkle proof is invalid."]
					InvalidProof,
					#[codec(index = 4)]
					#[doc = "Only the creator of an airdrop can delete it."]
					NotAirdropCreator,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A new airdrop has been created."]
					#[doc = ""]
					#[doc = "Parameters: [airdrop_id, merkle_root]"]
					AirdropCreated {
						airdrop_id: ::core::primitive::u32,
						airdrop_metadata: runtime_types::pallet_merkle_airdrop::AirdropMetadata<
							::core::primitive::u32,
							::core::primitive::u128,
							::subxt::ext::subxt_core::utils::AccountId32,
						>,
					},
					#[codec(index = 1)]
					#[doc = "An airdrop has been funded with tokens."]
					#[doc = ""]
					#[doc = "Parameters: [airdrop_id, amount]"]
					AirdropFunded {
						airdrop_id: ::core::primitive::u32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "A user has claimed tokens from an airdrop."]
					#[doc = ""]
					#[doc = "Parameters: [airdrop_id, account, amount]"]
					Claimed {
						airdrop_id: ::core::primitive::u32,
						account: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 3)]
					#[doc = "An airdrop has been deleted."]
					#[doc = ""]
					#[doc = "Parameters: [airdrop_id]"]
					AirdropDeleted { airdrop_id: ::core::primitive::u32 },
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct AirdropMetadata<_0, _1, _2> {
				pub merkle_root: [::core::primitive::u8; 32usize],
				pub creator: _2,
				pub balance: _1,
				pub vesting_period: ::core::option::Option<_0>,
				pub vesting_delay: ::core::option::Option<_0>,
			}
		}
		pub mod pallet_mining_rewards {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A miner has been identified for a block"]
					MinerRewarded {
						miner: ::subxt::ext::subxt_core::utils::AccountId32,
						reward: ::core::primitive::u128,
					},
					#[codec(index = 1)]
					#[doc = "Transaction fees were collected for later distribution"]
					FeesCollected {
						amount: ::core::primitive::u128,
						total: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "Rewards were sent to Treasury when no miner was specified"]
					TreasuryRewarded { reward: ::core::primitive::u128 },
				}
			}
		}
		pub mod pallet_preimage {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Register a preimage on-chain."]
					#[doc = ""]
					#[doc = "If the preimage was previously requested, no fees or deposits are taken for providing"]
					#[doc = "the preimage. Otherwise, a deposit is taken proportional to the size of the preimage."]
					note_preimage {
						bytes: ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					},
					#[codec(index = 1)]
					#[doc = "Clear an unrequested preimage from the runtime storage."]
					#[doc = ""]
					#[doc = "If `len` is provided, then it will be a much cheaper operation."]
					#[doc = ""]
					#[doc = "- `hash`: The hash of the preimage to be removed from the store."]
					#[doc = "- `len`: The length of the preimage of `hash`."]
					unnote_preimage { hash: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 2)]
					#[doc = "Request a preimage be uploaded to the chain without paying any fees or deposits."]
					#[doc = ""]
					#[doc = "If the preimage requests has already been provided on-chain, we unreserve any deposit"]
					#[doc = "a user may have paid, and take the control of the preimage out of their hands."]
					request_preimage { hash: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 3)]
					#[doc = "Clear a previously made request for a preimage."]
					#[doc = ""]
					#[doc = "NOTE: THIS MUST NOT BE CALLED ON `hash` MORE TIMES THAN `request_preimage`."]
					unrequest_preimage { hash: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 4)]
					#[doc = "Ensure that the bulk of pre-images is upgraded."]
					#[doc = ""]
					#[doc = "The caller pays no fee if at least 90% of pre-images were successfully updated."]
					ensure_updated {
						hashes: ::subxt::ext::subxt_core::alloc::vec::Vec<
							::subxt::ext::subxt_core::utils::H256,
						>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Preimage is too large to store on-chain."]
					TooBig,
					#[codec(index = 1)]
					#[doc = "Preimage has already been noted on-chain."]
					AlreadyNoted,
					#[codec(index = 2)]
					#[doc = "The user is not authorized to perform this action."]
					NotAuthorized,
					#[codec(index = 3)]
					#[doc = "The preimage cannot be removed since it has not yet been noted."]
					NotNoted,
					#[codec(index = 4)]
					#[doc = "A preimage may not be removed when there are outstanding requests."]
					Requested,
					#[codec(index = 5)]
					#[doc = "The preimage request cannot be removed since no outstanding requests exist."]
					NotRequested,
					#[codec(index = 6)]
					#[doc = "More than `MAX_HASH_UPGRADE_BULK_COUNT` hashes were requested to be upgraded at once."]
					TooMany,
					#[codec(index = 7)]
					#[doc = "Too few hashes were requested to be upgraded (i.e. zero)."]
					TooFew,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A preimage has been noted."]
					Noted { hash: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 1)]
					#[doc = "A preimage has been requested."]
					Requested { hash: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 2)]
					#[doc = "A preimage has ben cleared."]
					Cleared { hash: ::subxt::ext::subxt_core::utils::H256 },
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum HoldReason {
					#[codec(index = 0)]
					Preimage,
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum OldRequestStatus<_0, _1> {
				#[codec(index = 0)]
				Unrequested { deposit: (_0, _1), len: ::core::primitive::u32 },
				#[codec(index = 1)]
				Requested {
					deposit: ::core::option::Option<(_0, _1)>,
					count: ::core::primitive::u32,
					len: ::core::option::Option<::core::primitive::u32>,
				},
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum RequestStatus<_0, _1> {
				#[codec(index = 0)]
				Unrequested { ticket: (_0, _1), len: ::core::primitive::u32 },
				#[codec(index = 1)]
				Requested {
					maybe_ticket: ::core::option::Option<(_0, _1)>,
					count: ::core::primitive::u32,
					maybe_len: ::core::option::Option<::core::primitive::u32>,
				},
			}
		}
		pub mod pallet_qpow {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					InvalidSolution,
					#[codec(index = 1)]
					ArithmeticOverflow,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					ProofSubmitted {
						nonce: [::core::primitive::u8; 64usize],
						difficulty: runtime_types::primitive_types::U512,
						distance_achieved: runtime_types::primitive_types::U512,
					},
					#[codec(index = 1)]
					DistanceThresholdAdjusted {
						old_distance_threshold: runtime_types::primitive_types::U512,
						new_distance_threshold: runtime_types::primitive_types::U512,
						observed_block_time: ::core::primitive::u64,
					},
				}
			}
		}
		pub mod pallet_ranked_collective {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Introduce a new member."]
					#[doc = ""]
					#[doc = "- `origin`: Must be the `AddOrigin`."]
					#[doc = "- `who`: Account of non-member which will become a member."]
					#[doc = ""]
					#[doc = "Weight: `O(1)`"]
					add_member {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 1)]
					#[doc = "Increment the rank of an existing member by one."]
					#[doc = ""]
					#[doc = "- `origin`: Must be the `PromoteOrigin`."]
					#[doc = "- `who`: Account of existing member."]
					#[doc = ""]
					#[doc = "Weight: `O(1)`"]
					promote_member {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 2)]
					#[doc = "Decrement the rank of an existing member by one. If the member is already at rank zero,"]
					#[doc = "then they are removed entirely."]
					#[doc = ""]
					#[doc = "- `origin`: Must be the `DemoteOrigin`."]
					#[doc = "- `who`: Account of existing member of rank greater than zero."]
					#[doc = ""]
					#[doc = "Weight: `O(1)`, less if the member's index is highest in its rank."]
					demote_member {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 3)]
					#[doc = "Remove the member entirely."]
					#[doc = ""]
					#[doc = "- `origin`: Must be the `RemoveOrigin`."]
					#[doc = "- `who`: Account of existing member of rank greater than zero."]
					#[doc = "- `min_rank`: The rank of the member or greater."]
					#[doc = ""]
					#[doc = "Weight: `O(min_rank)`."]
					remove_member {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						min_rank: ::core::primitive::u16,
					},
					#[codec(index = 4)]
					#[doc = "Add an aye or nay vote for the sender to the given proposal."]
					#[doc = ""]
					#[doc = "- `origin`: Must be `Signed` by a member account."]
					#[doc = "- `poll`: Index of a poll which is ongoing."]
					#[doc = "- `aye`: `true` if the vote is to approve the proposal, `false` otherwise."]
					#[doc = ""]
					#[doc = "Transaction fees are be waived if the member is voting on any particular proposal"]
					#[doc = "for the first time and the call is successful. Subsequent vote changes will charge a"]
					#[doc = "fee."]
					#[doc = ""]
					#[doc = "Weight: `O(1)`, less if there was no previous vote on the poll by the member."]
					vote { poll: ::core::primitive::u32, aye: ::core::primitive::bool },
					#[codec(index = 5)]
					#[doc = "Remove votes from the given poll. It must have ended."]
					#[doc = ""]
					#[doc = "- `origin`: Must be `Signed` by any account."]
					#[doc = "- `poll_index`: Index of a poll which is completed and for which votes continue to"]
					#[doc = "  exist."]
					#[doc = "- `max`: Maximum number of vote items from remove in this call."]
					#[doc = ""]
					#[doc = "Transaction fees are waived if the operation is successful."]
					#[doc = ""]
					#[doc = "Weight `O(max)` (less if there are fewer items to remove than `max`)."]
					cleanup_poll { poll_index: ::core::primitive::u32, max: ::core::primitive::u32 },
					#[codec(index = 6)]
					#[doc = "Exchanges a member with a new account and the same existing rank."]
					#[doc = ""]
					#[doc = "- `origin`: Must be the `ExchangeOrigin`."]
					#[doc = "- `who`: Account of existing member of rank greater than zero to be exchanged."]
					#[doc = "- `new_who`: New Account of existing member of rank greater than zero to exchanged to."]
					exchange_member {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						new_who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Account is already a member."]
					AlreadyMember,
					#[codec(index = 1)]
					#[doc = "Account is not a member."]
					NotMember,
					#[codec(index = 2)]
					#[doc = "The given poll index is unknown or has closed."]
					NotPolling,
					#[codec(index = 3)]
					#[doc = "The given poll is still ongoing."]
					Ongoing,
					#[codec(index = 4)]
					#[doc = "There are no further records to be removed."]
					NoneRemaining,
					#[codec(index = 5)]
					#[doc = "Unexpected error in state."]
					Corruption,
					#[codec(index = 6)]
					#[doc = "The member's rank is too low to vote."]
					RankTooLow,
					#[codec(index = 7)]
					#[doc = "The information provided is incorrect."]
					InvalidWitness,
					#[codec(index = 8)]
					#[doc = "The origin is not sufficiently privileged to do the operation."]
					NoPermission,
					#[codec(index = 9)]
					#[doc = "The new member to exchange is the same as the old member"]
					SameMember,
					#[codec(index = 10)]
					#[doc = "The max member count for the rank has been reached."]
					TooManyMembers,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A member `who` has been added."]
					MemberAdded { who: ::subxt::ext::subxt_core::utils::AccountId32 },
					#[codec(index = 1)]
					#[doc = "The member `who`se rank has been changed to the given `rank`."]
					RankChanged {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						rank: ::core::primitive::u16,
					},
					#[codec(index = 2)]
					#[doc = "The member `who` of given `rank` has been removed from the collective."]
					MemberRemoved {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						rank: ::core::primitive::u16,
					},
					#[codec(index = 3)]
					#[doc = "The member `who` has voted for the `poll` with the given `vote` leading to an updated"]
					#[doc = "`tally`."]
					Voted {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						poll: ::core::primitive::u32,
						vote: runtime_types::pallet_ranked_collective::VoteRecord,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 4)]
					#[doc = "The member `who` had their `AccountId` changed to `new_who`."]
					MemberExchanged {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						new_who: ::subxt::ext::subxt_core::utils::AccountId32,
					},
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct MemberRecord {
				pub rank: ::core::primitive::u16,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct Tally {
				pub bare_ayes: ::core::primitive::u32,
				pub ayes: ::core::primitive::u32,
				pub nays: ::core::primitive::u32,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum VoteRecord {
				#[codec(index = 0)]
				Aye(::core::primitive::u32),
				#[codec(index = 1)]
				Nay(::core::primitive::u32),
			}
		}
		pub mod pallet_recovery {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Send a call through a recovered account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and registered to"]
					#[doc = "be able to make calls on behalf of the recovered account."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `account`: The recovered account you want to make a call on-behalf-of."]
					#[doc = "- `call`: The call you want to make with the recovered account."]
					as_recovered {
						account: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 1)]
					#[doc = "Allow ROOT to bypass the recovery process and set a rescuer account"]
					#[doc = "for a lost account directly."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _ROOT_."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `lost`: The \"lost account\" to be recovered."]
					#[doc = "- `rescuer`: The \"rescuer account\" which can call as the lost account."]
					set_recovered {
						lost: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						rescuer: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 2)]
					#[doc = "Create a recovery configuration for your account. This makes your account recoverable."]
					#[doc = ""]
					#[doc = "Payment: `ConfigDepositBase` + `FriendDepositFactor` * #_of_friends balance"]
					#[doc = "will be reserved for storing the recovery configuration. This deposit is returned"]
					#[doc = "in full when the user calls `remove_recovery`."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `friends`: A list of friends you trust to vouch for recovery attempts. Should be"]
					#[doc = "  ordered and contain no duplicate values."]
					#[doc = "- `threshold`: The number of friends that must vouch for a recovery attempt before the"]
					#[doc = "  account can be recovered. Should be less than or equal to the length of the list of"]
					#[doc = "  friends."]
					#[doc = "- `delay_period`: The number of blocks after a recovery attempt is initialized that"]
					#[doc = "  needs to pass before the account can be recovered."]
					create_recovery {
						friends: ::subxt::ext::subxt_core::alloc::vec::Vec<
							::subxt::ext::subxt_core::utils::AccountId32,
						>,
						threshold: ::core::primitive::u16,
						delay_period: ::core::primitive::u32,
					},
					#[codec(index = 3)]
					#[doc = "Initiate the process for recovering a recoverable account."]
					#[doc = ""]
					#[doc = "Payment: `RecoveryDeposit` balance will be reserved for initiating the"]
					#[doc = "recovery process. This deposit will always be repatriated to the account"]
					#[doc = "trying to be recovered. See `close_recovery`."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `account`: The lost account that you want to recover. This account needs to be"]
					#[doc = "  recoverable (i.e. have a recovery configuration)."]
					initiate_recovery {
						account: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 4)]
					#[doc = "Allow a \"friend\" of a recoverable account to vouch for an active recovery"]
					#[doc = "process for that account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and must be a \"friend\""]
					#[doc = "for the recoverable account."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `lost`: The lost account that you want to recover."]
					#[doc = "- `rescuer`: The account trying to rescue the lost account that you want to vouch for."]
					#[doc = ""]
					#[doc = "The combination of these two parameters must point to an active recovery"]
					#[doc = "process."]
					vouch_recovery {
						lost: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						rescuer: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 5)]
					#[doc = "Allow a successful rescuer to claim their recovered account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and must be a \"rescuer\""]
					#[doc = "who has successfully completed the account recovery process: collected"]
					#[doc = "`threshold` or more vouches, waited `delay_period` blocks since initiation."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `account`: The lost account that you want to claim has been successfully recovered by"]
					#[doc = "  you."]
					claim_recovery {
						account: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 6)]
					#[doc = "As the controller of a recoverable account, close an active recovery"]
					#[doc = "process for your account."]
					#[doc = ""]
					#[doc = "Payment: By calling this function, the recoverable account will receive"]
					#[doc = "the recovery deposit `RecoveryDeposit` placed by the rescuer."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and must be a"]
					#[doc = "recoverable account with an active recovery process for it."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `rescuer`: The account trying to rescue this recoverable account."]
					close_recovery {
						rescuer: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 7)]
					#[doc = "Remove the recovery process for your account. Recovered accounts are still accessible."]
					#[doc = ""]
					#[doc = "NOTE: The user must make sure to call `close_recovery` on all active"]
					#[doc = "recovery attempts before calling this function else it will fail."]
					#[doc = ""]
					#[doc = "Payment: By calling this function the recoverable account will unreserve"]
					#[doc = "their recovery configuration deposit."]
					#[doc = "(`ConfigDepositBase` + `FriendDepositFactor` * #_of_friends)"]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and must be a"]
					#[doc = "recoverable account (i.e. has a recovery configuration)."]
					remove_recovery,
					#[codec(index = 8)]
					#[doc = "Cancel the ability to use `as_recovered` for `account`."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and registered to"]
					#[doc = "be able to make calls on behalf of the recovered account."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `account`: The recovered account you are able to call on-behalf-of."]
					cancel_recovered {
						account: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 9)]
					#[doc = "Poke deposits for recovery configurations and / or active recoveries."]
					#[doc = ""]
					#[doc = "This can be used by accounts to possibly lower their locked amount."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `maybe_account`: Optional recoverable account for which you have an active recovery"]
					#[doc = "and want to adjust the deposit for the active recovery."]
					#[doc = ""]
					#[doc = "This function checks both recovery configuration deposit and active recovery deposits"]
					#[doc = "of the caller:"]
					#[doc = "- If the caller has created a recovery configuration, checks and adjusts its deposit"]
					#[doc = "- If the caller has initiated any active recoveries, and provides the account in"]
					#[doc = "`maybe_account`, checks and adjusts those deposits"]
					#[doc = ""]
					#[doc = "If any deposit is updated, the difference will be reserved/unreserved from the caller's"]
					#[doc = "account."]
					#[doc = ""]
					#[doc = "The transaction is made free if any deposit is updated and paid otherwise."]
					#[doc = ""]
					#[doc = "Emits `DepositPoked` if any deposit is updated."]
					#[doc = "Multiple events may be emitted in case both types of deposits are updated."]
					poke_deposit {
						maybe_account: ::core::option::Option<
							::subxt::ext::subxt_core::utils::MultiAddress<
								::subxt::ext::subxt_core::utils::AccountId32,
								(),
							>,
						>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "User is not allowed to make a call on behalf of this account"]
					NotAllowed,
					#[codec(index = 1)]
					#[doc = "Threshold must be greater than zero"]
					ZeroThreshold,
					#[codec(index = 2)]
					#[doc = "Friends list must be greater than zero and threshold"]
					NotEnoughFriends,
					#[codec(index = 3)]
					#[doc = "Friends list must be less than max friends"]
					MaxFriends,
					#[codec(index = 4)]
					#[doc = "Friends list must be sorted and free of duplicates"]
					NotSorted,
					#[codec(index = 5)]
					#[doc = "This account is not set up for recovery"]
					NotRecoverable,
					#[codec(index = 6)]
					#[doc = "This account is already set up for recovery"]
					AlreadyRecoverable,
					#[codec(index = 7)]
					#[doc = "A recovery process has already started for this account"]
					AlreadyStarted,
					#[codec(index = 8)]
					#[doc = "A recovery process has not started for this rescuer"]
					NotStarted,
					#[codec(index = 9)]
					#[doc = "This account is not a friend who can vouch"]
					NotFriend,
					#[codec(index = 10)]
					#[doc = "The friend must wait until the delay period to vouch for this recovery"]
					DelayPeriod,
					#[codec(index = 11)]
					#[doc = "This user has already vouched for this recovery"]
					AlreadyVouched,
					#[codec(index = 12)]
					#[doc = "The threshold for recovering this account has not been met"]
					Threshold,
					#[codec(index = 13)]
					#[doc = "There are still active recovery attempts that need to be closed"]
					StillActive,
					#[codec(index = 14)]
					#[doc = "This account is already set up for recovery"]
					AlreadyProxy,
					#[codec(index = 15)]
					#[doc = "Some internal state is broken."]
					BadState,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Events type."]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A recovery process has been set up for an account."]
					RecoveryCreated { account: ::subxt::ext::subxt_core::utils::AccountId32 },
					#[codec(index = 1)]
					#[doc = "A recovery process has been initiated for lost account by rescuer account."]
					RecoveryInitiated {
						lost_account: ::subxt::ext::subxt_core::utils::AccountId32,
						rescuer_account: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 2)]
					#[doc = "A recovery process for lost account by rescuer account has been vouched for by sender."]
					RecoveryVouched {
						lost_account: ::subxt::ext::subxt_core::utils::AccountId32,
						rescuer_account: ::subxt::ext::subxt_core::utils::AccountId32,
						sender: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 3)]
					#[doc = "A recovery process for lost account by rescuer account has been closed."]
					RecoveryClosed {
						lost_account: ::subxt::ext::subxt_core::utils::AccountId32,
						rescuer_account: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 4)]
					#[doc = "Lost account has been successfully recovered by rescuer account."]
					AccountRecovered {
						lost_account: ::subxt::ext::subxt_core::utils::AccountId32,
						rescuer_account: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 5)]
					#[doc = "A recovery process has been removed for an account."]
					RecoveryRemoved { lost_account: ::subxt::ext::subxt_core::utils::AccountId32 },
					#[codec(index = 6)]
					#[doc = "A deposit has been updated."]
					DepositPoked {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						kind: runtime_types::pallet_recovery::DepositKind<
							runtime_types::quantus_runtime::Runtime,
						>,
						old_deposit: ::core::primitive::u128,
						new_deposit: ::core::primitive::u128,
					},
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ActiveRecovery<_0, _1, _2> {
				pub created: _0,
				pub deposit: _1,
				pub friends: _2,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum DepositKind<_0> {
				#[codec(index = 0)]
				RecoveryConfig,
				#[codec(index = 1)]
				ActiveRecoveryFor(::subxt::ext::subxt_core::utils::AccountId32),
				__Ignore(::core::marker::PhantomData<_0>),
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct RecoveryConfig<_0, _1, _2> {
				pub delay_period: _0,
				pub deposit: _1,
				pub friends: _2,
				pub threshold: ::core::primitive::u16,
			}
		}
		pub mod pallet_referenda {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Propose a referendum on a privileged action."]
					#[doc = ""]
					#[doc = "- `origin`: must be `SubmitOrigin` and the account must have `SubmissionDeposit` funds"]
					#[doc = "  available."]
					#[doc = "- `proposal_origin`: The origin from which the proposal should be executed."]
					#[doc = "- `proposal`: The proposal."]
					#[doc = "- `enactment_moment`: The moment that the proposal should be enacted."]
					#[doc = ""]
					#[doc = "Emits `Submitted`."]
					submit {
						proposal_origin: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::OriginCaller,
						>,
						proposal: runtime_types::frame_support::traits::preimages::Bounded<
							runtime_types::quantus_runtime::RuntimeCall,
							runtime_types::poseidon_resonance::PoseidonHasher,
						>,
						enactment_moment:
							runtime_types::frame_support::traits::schedule::DispatchTime<
								::core::primitive::u32,
							>,
					},
					#[codec(index = 1)]
					#[doc = "Post the Decision Deposit for a referendum."]
					#[doc = ""]
					#[doc = "- `origin`: must be `Signed` and the account must have funds available for the"]
					#[doc = "  referendum's track's Decision Deposit."]
					#[doc = "- `index`: The index of the submitted referendum whose Decision Deposit is yet to be"]
					#[doc = "  posted."]
					#[doc = ""]
					#[doc = "Emits `DecisionDepositPlaced`."]
					place_decision_deposit { index: ::core::primitive::u32 },
					#[codec(index = 2)]
					#[doc = "Refund the Decision Deposit for a closed referendum back to the depositor."]
					#[doc = ""]
					#[doc = "- `origin`: must be `Signed` or `Root`."]
					#[doc = "- `index`: The index of a closed referendum whose Decision Deposit has not yet been"]
					#[doc = "  refunded."]
					#[doc = ""]
					#[doc = "Emits `DecisionDepositRefunded`."]
					refund_decision_deposit { index: ::core::primitive::u32 },
					#[codec(index = 3)]
					#[doc = "Cancel an ongoing referendum."]
					#[doc = ""]
					#[doc = "- `origin`: must be the `CancelOrigin`."]
					#[doc = "- `index`: The index of the referendum to be cancelled."]
					#[doc = ""]
					#[doc = "Emits `Cancelled`."]
					cancel { index: ::core::primitive::u32 },
					#[codec(index = 4)]
					#[doc = "Cancel an ongoing referendum and slash the deposits."]
					#[doc = ""]
					#[doc = "- `origin`: must be the `KillOrigin`."]
					#[doc = "- `index`: The index of the referendum to be cancelled."]
					#[doc = ""]
					#[doc = "Emits `Killed` and `DepositSlashed`."]
					kill { index: ::core::primitive::u32 },
					#[codec(index = 5)]
					#[doc = "Advance a referendum onto its next logical state. Only used internally."]
					#[doc = ""]
					#[doc = "- `origin`: must be `Root`."]
					#[doc = "- `index`: the referendum to be advanced."]
					nudge_referendum { index: ::core::primitive::u32 },
					#[codec(index = 6)]
					#[doc = "Advance a track onto its next logical state. Only used internally."]
					#[doc = ""]
					#[doc = "- `origin`: must be `Root`."]
					#[doc = "- `track`: the track to be advanced."]
					#[doc = ""]
					#[doc = "Action item for when there is now one fewer referendum in the deciding phase and the"]
					#[doc = "`DecidingCount` is not yet updated. This means that we should either:"]
					#[doc = "- begin deciding another referendum (and leave `DecidingCount` alone); or"]
					#[doc = "- decrement `DecidingCount`."]
					one_fewer_deciding { track: ::core::primitive::u16 },
					#[codec(index = 7)]
					#[doc = "Refund the Submission Deposit for a closed referendum back to the depositor."]
					#[doc = ""]
					#[doc = "- `origin`: must be `Signed` or `Root`."]
					#[doc = "- `index`: The index of a closed referendum whose Submission Deposit has not yet been"]
					#[doc = "  refunded."]
					#[doc = ""]
					#[doc = "Emits `SubmissionDepositRefunded`."]
					refund_submission_deposit { index: ::core::primitive::u32 },
					#[codec(index = 8)]
					#[doc = "Set or clear metadata of a referendum."]
					#[doc = ""]
					#[doc = "Parameters:"]
					#[doc = "- `origin`: Must be `Signed` by a creator of a referendum or by anyone to clear a"]
					#[doc = "  metadata of a finished referendum."]
					#[doc = "- `index`:  The index of a referendum to set or clear metadata for."]
					#[doc = "- `maybe_hash`: The hash of an on-chain stored preimage. `None` to clear a metadata."]
					set_metadata {
						index: ::core::primitive::u32,
						maybe_hash: ::core::option::Option<::subxt::ext::subxt_core::utils::H256>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Referendum is not ongoing."]
					NotOngoing,
					#[codec(index = 1)]
					#[doc = "Referendum's decision deposit is already paid."]
					HasDeposit,
					#[codec(index = 2)]
					#[doc = "The track identifier given was invalid."]
					BadTrack,
					#[codec(index = 3)]
					#[doc = "There are already a full complement of referenda in progress for this track."]
					Full,
					#[codec(index = 4)]
					#[doc = "The queue of the track is empty."]
					QueueEmpty,
					#[codec(index = 5)]
					#[doc = "The referendum index provided is invalid in this context."]
					BadReferendum,
					#[codec(index = 6)]
					#[doc = "There was nothing to do in the advancement."]
					NothingToDo,
					#[codec(index = 7)]
					#[doc = "No track exists for the proposal origin."]
					NoTrack,
					#[codec(index = 8)]
					#[doc = "Any deposit cannot be refunded until after the decision is over."]
					Unfinished,
					#[codec(index = 9)]
					#[doc = "The deposit refunder is not the depositor."]
					NoPermission,
					#[codec(index = 10)]
					#[doc = "The deposit cannot be refunded since none was made."]
					NoDeposit,
					#[codec(index = 11)]
					#[doc = "The referendum status is invalid for this operation."]
					BadStatus,
					#[codec(index = 12)]
					#[doc = "The preimage does not exist."]
					PreimageNotExist,
					#[codec(index = 13)]
					#[doc = "The preimage is stored with a different length than the one provided."]
					PreimageStoredWithDifferentLength,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event1 {
					#[codec(index = 0)]
					#[doc = "A referendum has been submitted."]
					Submitted {
						index: ::core::primitive::u32,
						track: ::core::primitive::u16,
						proposal: runtime_types::frame_support::traits::preimages::Bounded<
							runtime_types::quantus_runtime::RuntimeCall,
							runtime_types::poseidon_resonance::PoseidonHasher,
						>,
					},
					#[codec(index = 1)]
					#[doc = "The decision deposit has been placed."]
					DecisionDepositPlaced {
						index: ::core::primitive::u32,
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "The decision deposit has been refunded."]
					DecisionDepositRefunded {
						index: ::core::primitive::u32,
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 3)]
					#[doc = "A deposit has been slashed."]
					DepositSlashed {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 4)]
					#[doc = "A referendum has moved into the deciding phase."]
					DecisionStarted {
						index: ::core::primitive::u32,
						track: ::core::primitive::u16,
						proposal: runtime_types::frame_support::traits::preimages::Bounded<
							runtime_types::quantus_runtime::RuntimeCall,
							runtime_types::poseidon_resonance::PoseidonHasher,
						>,
						tally: runtime_types::pallet_conviction_voting::types::Tally<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 5)]
					ConfirmStarted { index: ::core::primitive::u32 },
					#[codec(index = 6)]
					ConfirmAborted { index: ::core::primitive::u32 },
					#[codec(index = 7)]
					#[doc = "A referendum has ended its confirmation phase and is ready for approval."]
					Confirmed {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_conviction_voting::types::Tally<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 8)]
					#[doc = "A referendum has been approved and its proposal has been scheduled."]
					Approved { index: ::core::primitive::u32 },
					#[codec(index = 9)]
					#[doc = "A proposal has been rejected by referendum."]
					Rejected {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_conviction_voting::types::Tally<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 10)]
					#[doc = "A referendum has been timed out without being decided."]
					TimedOut {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_conviction_voting::types::Tally<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 11)]
					#[doc = "A referendum has been cancelled."]
					Cancelled {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_conviction_voting::types::Tally<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 12)]
					#[doc = "A referendum has been killed."]
					Killed {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_conviction_voting::types::Tally<
							::core::primitive::u128,
						>,
					},
					#[codec(index = 13)]
					#[doc = "The submission deposit has been refunded."]
					SubmissionDepositRefunded {
						index: ::core::primitive::u32,
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 14)]
					#[doc = "Metadata for a referendum has been set."]
					MetadataSet {
						index: ::core::primitive::u32,
						hash: ::subxt::ext::subxt_core::utils::H256,
					},
					#[codec(index = 15)]
					#[doc = "Metadata for a referendum has been cleared."]
					MetadataCleared {
						index: ::core::primitive::u32,
						hash: ::subxt::ext::subxt_core::utils::H256,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event2 {
					#[codec(index = 0)]
					#[doc = "A referendum has been submitted."]
					Submitted {
						index: ::core::primitive::u32,
						track: ::core::primitive::u16,
						proposal: runtime_types::frame_support::traits::preimages::Bounded<
							runtime_types::quantus_runtime::RuntimeCall,
							runtime_types::poseidon_resonance::PoseidonHasher,
						>,
					},
					#[codec(index = 1)]
					#[doc = "The decision deposit has been placed."]
					DecisionDepositPlaced {
						index: ::core::primitive::u32,
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "The decision deposit has been refunded."]
					DecisionDepositRefunded {
						index: ::core::primitive::u32,
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 3)]
					#[doc = "A deposit has been slashed."]
					DepositSlashed {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 4)]
					#[doc = "A referendum has moved into the deciding phase."]
					DecisionStarted {
						index: ::core::primitive::u32,
						track: ::core::primitive::u16,
						proposal: runtime_types::frame_support::traits::preimages::Bounded<
							runtime_types::quantus_runtime::RuntimeCall,
							runtime_types::poseidon_resonance::PoseidonHasher,
						>,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 5)]
					ConfirmStarted { index: ::core::primitive::u32 },
					#[codec(index = 6)]
					ConfirmAborted { index: ::core::primitive::u32 },
					#[codec(index = 7)]
					#[doc = "A referendum has ended its confirmation phase and is ready for approval."]
					Confirmed {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 8)]
					#[doc = "A referendum has been approved and its proposal has been scheduled."]
					Approved { index: ::core::primitive::u32 },
					#[codec(index = 9)]
					#[doc = "A proposal has been rejected by referendum."]
					Rejected {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 10)]
					#[doc = "A referendum has been timed out without being decided."]
					TimedOut {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 11)]
					#[doc = "A referendum has been cancelled."]
					Cancelled {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 12)]
					#[doc = "A referendum has been killed."]
					Killed {
						index: ::core::primitive::u32,
						tally: runtime_types::pallet_ranked_collective::Tally,
					},
					#[codec(index = 13)]
					#[doc = "The submission deposit has been refunded."]
					SubmissionDepositRefunded {
						index: ::core::primitive::u32,
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 14)]
					#[doc = "Metadata for a referendum has been set."]
					MetadataSet {
						index: ::core::primitive::u32,
						hash: ::subxt::ext::subxt_core::utils::H256,
					},
					#[codec(index = 15)]
					#[doc = "Metadata for a referendum has been cleared."]
					MetadataCleared {
						index: ::core::primitive::u32,
						hash: ::subxt::ext::subxt_core::utils::H256,
					},
				}
			}
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum Curve {
					#[codec(index = 0)]
					LinearDecreasing {
						length: runtime_types::sp_arithmetic::per_things::Perbill,
						floor: runtime_types::sp_arithmetic::per_things::Perbill,
						ceil: runtime_types::sp_arithmetic::per_things::Perbill,
					},
					#[codec(index = 1)]
					SteppedDecreasing {
						begin: runtime_types::sp_arithmetic::per_things::Perbill,
						end: runtime_types::sp_arithmetic::per_things::Perbill,
						step: runtime_types::sp_arithmetic::per_things::Perbill,
						period: runtime_types::sp_arithmetic::per_things::Perbill,
					},
					#[codec(index = 2)]
					Reciprocal {
						factor: runtime_types::sp_arithmetic::fixed_point::FixedI64,
						x_offset: runtime_types::sp_arithmetic::fixed_point::FixedI64,
						y_offset: runtime_types::sp_arithmetic::fixed_point::FixedI64,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct DecidingStatus<_0> {
					pub since: _0,
					pub confirming: ::core::option::Option<_0>,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Deposit<_0, _1> {
					pub who: _0,
					pub amount: _1,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum ReferendumInfo<_0, _1, _2, _3, _4, _5, _6, _7> {
					#[codec(index = 0)]
					Ongoing(
						runtime_types::pallet_referenda::types::ReferendumStatus<
							_0,
							_1,
							_2,
							_3,
							_4,
							_5,
							_6,
							_7,
						>,
					),
					#[codec(index = 1)]
					Approved(
						_2,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
					),
					#[codec(index = 2)]
					Rejected(
						_2,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
					),
					#[codec(index = 3)]
					Cancelled(
						_2,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
					),
					#[codec(index = 4)]
					TimedOut(
						_2,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
						::core::option::Option<
							runtime_types::pallet_referenda::types::Deposit<_6, _4>,
						>,
					),
					#[codec(index = 5)]
					Killed(_2),
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ReferendumStatus<_0, _1, _2, _3, _4, _5, _6, _7> {
					pub track: _0,
					pub origin: _1,
					pub proposal: _3,
					pub enactment: runtime_types::frame_support::traits::schedule::DispatchTime<_2>,
					pub submitted: _2,
					pub submission_deposit: runtime_types::pallet_referenda::types::Deposit<_6, _4>,
					pub decision_deposit: ::core::option::Option<
						runtime_types::pallet_referenda::types::Deposit<_6, _4>,
					>,
					pub deciding: ::core::option::Option<
						runtime_types::pallet_referenda::types::DecidingStatus<_2>,
					>,
					pub tally: _5,
					pub in_queue: ::core::primitive::bool,
					pub alarm: ::core::option::Option<(_2, _7)>,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct TrackDetails<_0, _1, _2> {
					pub name: _2,
					pub max_deciding: ::core::primitive::u32,
					pub decision_deposit: _0,
					pub prepare_period: _1,
					pub decision_period: _1,
					pub confirm_period: _1,
					pub min_enactment_period: _1,
					pub min_approval: runtime_types::pallet_referenda::types::Curve,
					pub min_support: runtime_types::pallet_referenda::types::Curve,
				}
			}
		}
		pub mod pallet_reversible_transfers {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Enable high-security for the calling account with a specified"]
					#[doc = "reversibility delay."]
					#[doc = ""]
					#[doc = "Recoverer and interceptor (aka guardian) could be the same account or"]
					#[doc = "different accounts."]
					#[doc = ""]
					#[doc = "Once an account is set as high security it can only make reversible"]
					#[doc = "transfers. It is not allowed any other calls."]
					#[doc = ""]
					#[doc = "- `delay`: The reversibility time for any transfer made by the high"]
					#[doc = "security account."]
					#[doc = "- interceptor: The account that can intercept transctions from the"]
					#[doc = "high security account."]
					#[doc = "- recoverer: Account that can recover (act as proxy to) the high security"]
					#[doc = "account"]
					set_high_security {
						delay: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						interceptor: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 1)]
					#[doc = "Cancel a pending reversible transaction scheduled by the caller."]
					#[doc = ""]
					#[doc = "- `tx_id`: The unique identifier of the transaction to cancel."]
					cancel { tx_id: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 2)]
					#[doc = "Called by the Scheduler to finalize the scheduled task/call"]
					#[doc = ""]
					#[doc = "- `tx_id`: The unique id of the transaction to finalize and dispatch."]
					execute_transfer { tx_id: ::subxt::ext::subxt_core::utils::H256 },
					#[codec(index = 3)]
					#[doc = "Schedule a transaction for delayed execution."]
					schedule_transfer {
						dest: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						amount: ::core::primitive::u128,
					},
					#[codec(index = 4)]
					#[doc = "Schedule a transaction for delayed execution with a custom, one-time delay."]
					#[doc = ""]
					#[doc = "This can only be used by accounts that have *not* set up a persistent"]
					#[doc = "reversibility configuration with `set_reversibility`."]
					#[doc = ""]
					#[doc = "- `delay`: The time (in blocks or milliseconds) before the transaction executes."]
					schedule_transfer_with_delay {
						dest: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						amount: ::core::primitive::u128,
						delay: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "The account attempting to enable reversibility is already marked as reversible."]
					AccountAlreadyHighSecurity,
					#[codec(index = 1)]
					#[doc = "The account attempting the action is not marked as high security."]
					AccountNotHighSecurity,
					#[codec(index = 2)]
					#[doc = "Interceptor can not be the account itself, because it is redundant."]
					InterceptorCannotBeSelf,
					#[codec(index = 3)]
					#[doc = "Recoverer cannot be the account itself, because it is redundant."]
					RecovererCannotBeSelf,
					#[codec(index = 4)]
					#[doc = "The specified pending transaction ID was not found."]
					PendingTxNotFound,
					#[codec(index = 5)]
					#[doc = "The caller is not the original submitter of the transaction they are trying to cancel."]
					NotOwner,
					#[codec(index = 6)]
					#[doc = "The account has reached the maximum number of pending reversible transactions."]
					TooManyPendingTransactions,
					#[codec(index = 7)]
					#[doc = "The specified delay period is below the configured minimum."]
					DelayTooShort,
					#[codec(index = 8)]
					#[doc = "Failed to schedule the transaction execution with the scheduler pallet."]
					SchedulingFailed,
					#[codec(index = 9)]
					#[doc = "Failed to cancel the scheduled task with the scheduler pallet."]
					CancellationFailed,
					#[codec(index = 10)]
					#[doc = "Failed to decode the OpaqueCall back into a RuntimeCall."]
					CallDecodingFailed,
					#[codec(index = 11)]
					#[doc = "Call is invalid."]
					InvalidCall,
					#[codec(index = 12)]
					#[doc = "Invalid scheduler origin"]
					InvalidSchedulerOrigin,
					#[codec(index = 13)]
					#[doc = "Reverser is invalid"]
					InvalidReverser,
					#[codec(index = 14)]
					#[doc = "Cannot schedule one time reversible transaction when account is reversible (theft"]
					#[doc = "deterrence)"]
					AccountAlreadyReversibleCannotScheduleOneTime,
					#[codec(index = 15)]
					#[doc = "The interceptor has reached the maximum number of accounts they can intercept for."]
					TooManyInterceptorAccounts,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A user has enabled their high-security settings."]
					#[doc = "[who, interceptor, recoverer, delay]"]
					HighSecuritySet {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						interceptor: ::subxt::ext::subxt_core::utils::AccountId32,
						delay: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
					},
					#[codec(index = 1)]
					#[doc = "A transaction has been intercepted and scheduled for delayed execution."]
					#[doc = "[from, to, interceptor, amount, tx_id, execute_at_moment]"]
					TransactionScheduled {
						from: ::subxt::ext::subxt_core::utils::AccountId32,
						to: ::subxt::ext::subxt_core::utils::AccountId32,
						interceptor: ::subxt::ext::subxt_core::utils::AccountId32,
						amount: ::core::primitive::u128,
						tx_id: ::subxt::ext::subxt_core::utils::H256,
						execute_at: runtime_types::qp_scheduler::DispatchTime<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
					},
					#[codec(index = 2)]
					#[doc = "A scheduled transaction has been successfully cancelled by the owner."]
					#[doc = "[who, tx_id]"]
					TransactionCancelled {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						tx_id: ::subxt::ext::subxt_core::utils::H256,
					},
					#[codec(index = 3)]
					#[doc = "A scheduled transaction was executed by the scheduler."]
					#[doc = "[tx_id, dispatch_result]"]
					TransactionExecuted {
						tx_id: ::subxt::ext::subxt_core::utils::H256,
						result: ::core::result::Result<
							runtime_types::frame_support::dispatch::PostDispatchInfo,
							runtime_types::sp_runtime::DispatchErrorWithPostInfo<
								runtime_types::frame_support::dispatch::PostDispatchInfo,
							>,
						>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum HoldReason {
					#[codec(index = 0)]
					ScheduledTransfer,
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct HighSecurityAccountData<_0, _1> {
				pub interceptor: _0,
				pub delay: _1,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct PendingTransfer<_0, _1, _2> {
				pub from: _0,
				pub to: _0,
				pub interceptor: _0,
				pub call: _2,
				pub amount: _1,
			}
		}
		pub mod pallet_scheduler {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Anonymously schedule a task."]
					schedule {
						when: ::core::primitive::u32,
						maybe_periodic: ::core::option::Option<(
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						)>,
						priority: ::core::primitive::u8,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 1)]
					#[doc = "Cancel an anonymously scheduled task."]
					cancel {
						when: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						index: ::core::primitive::u32,
					},
					#[codec(index = 2)]
					#[doc = "Schedule a named task."]
					schedule_named {
						id: [::core::primitive::u8; 32usize],
						when: ::core::primitive::u32,
						maybe_periodic: ::core::option::Option<(
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						)>,
						priority: ::core::primitive::u8,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 3)]
					#[doc = "Cancel a named scheduled task."]
					cancel_named { id: [::core::primitive::u8; 32usize] },
					#[codec(index = 4)]
					#[doc = "Anonymously schedule a task after a delay."]
					schedule_after {
						after: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						maybe_periodic: ::core::option::Option<(
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						)>,
						priority: ::core::primitive::u8,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 5)]
					#[doc = "Schedule a named task after a delay."]
					schedule_named_after {
						id: [::core::primitive::u8; 32usize],
						after: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						maybe_periodic: ::core::option::Option<(
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						)>,
						priority: ::core::primitive::u8,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 6)]
					#[doc = "Set a retry configuration for a task so that, in case its scheduled run fails, it will"]
					#[doc = "be retried after `period` blocks, for a total amount of `retries` retries or until it"]
					#[doc = "succeeds."]
					#[doc = ""]
					#[doc = "Tasks which need to be scheduled for a retry are still subject to weight metering and"]
					#[doc = "agenda space, same as a regular task. If a periodic task fails, it will be scheduled"]
					#[doc = "normally while the task is retrying."]
					#[doc = ""]
					#[doc = "Tasks scheduled as a result of a retry for a periodic task are unnamed, non-periodic"]
					#[doc = "clones of the original task. Their retry configuration will be derived from the"]
					#[doc = "original task's configuration, but will have a lower value for `remaining` than the"]
					#[doc = "original `total_retries`."]
					set_retry {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						retries: ::core::primitive::u8,
						period: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
					},
					#[codec(index = 7)]
					#[doc = "Set a retry configuration for a named task so that, in case its scheduled run fails, it"]
					#[doc = "will be retried after `period` blocks, for a total amount of `retries` retries or until"]
					#[doc = "it succeeds."]
					#[doc = ""]
					#[doc = "Tasks which need to be scheduled for a retry are still subject to weight metering and"]
					#[doc = "agenda space, same as a regular task. If a periodic task fails, it will be scheduled"]
					#[doc = "normally while the task is retrying."]
					#[doc = ""]
					#[doc = "Tasks scheduled as a result of a retry for a periodic task are unnamed, non-periodic"]
					#[doc = "clones of the original task. Their retry configuration will be derived from the"]
					#[doc = "original task's configuration, but will have a lower value for `remaining` than the"]
					#[doc = "original `total_retries`."]
					set_retry_named {
						id: [::core::primitive::u8; 32usize],
						retries: ::core::primitive::u8,
						period: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
					},
					#[codec(index = 8)]
					#[doc = "Removes the retry configuration of a task."]
					cancel_retry {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
					},
					#[codec(index = 9)]
					#[doc = "Cancel the retry configuration of a named task."]
					cancel_retry_named { id: [::core::primitive::u8; 32usize] },
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Failed to schedule a call"]
					FailedToSchedule,
					#[codec(index = 1)]
					#[doc = "Cannot find the scheduled call."]
					NotFound,
					#[codec(index = 2)]
					#[doc = "Given target block number is in the past."]
					TargetBlockNumberInPast,
					#[codec(index = 3)]
					#[doc = "Given target timestamp is in the past."]
					TargetTimestampInPast,
					#[codec(index = 4)]
					#[doc = "Reschedule failed because it does not change scheduled time."]
					RescheduleNoChange,
					#[codec(index = 5)]
					#[doc = "Attempt to use a non-named function on a named task."]
					Named,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Events type."]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "Scheduled some task."]
					Scheduled {
						when: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						index: ::core::primitive::u32,
					},
					#[codec(index = 1)]
					#[doc = "Canceled some task."]
					Canceled {
						when: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						index: ::core::primitive::u32,
					},
					#[codec(index = 2)]
					#[doc = "Dispatched some task."]
					Dispatched {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
						result:
							::core::result::Result<(), runtime_types::sp_runtime::DispatchError>,
					},
					#[codec(index = 3)]
					#[doc = "Set a retry configuration for some task."]
					RetrySet {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
						period: runtime_types::qp_scheduler::BlockNumberOrTimestamp<
							::core::primitive::u32,
							::core::primitive::u64,
						>,
						retries: ::core::primitive::u8,
					},
					#[codec(index = 4)]
					#[doc = "Cancel a retry configuration for some task."]
					RetryCancelled {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
					},
					#[codec(index = 5)]
					#[doc = "The call for the provided hash was not found so the task has been aborted."]
					CallUnavailable {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
					},
					#[codec(index = 6)]
					#[doc = "The given task was unable to be renewed since the agenda is full at that block."]
					PeriodicFailed {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
					},
					#[codec(index = 7)]
					#[doc = "The given task was unable to be retried since the agenda is full at that block or there"]
					#[doc = "was not enough weight to reschedule it."]
					RetryFailed {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
					},
					#[codec(index = 8)]
					#[doc = "The given task can never be executed since it is overweight."]
					PermanentlyOverweight {
						task: (
							runtime_types::qp_scheduler::BlockNumberOrTimestamp<
								::core::primitive::u32,
								::core::primitive::u64,
							>,
							::core::primitive::u32,
						),
						id: ::core::option::Option<[::core::primitive::u8; 32usize]>,
					},
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct RetryConfig<_0> {
				pub total_retries: ::core::primitive::u8,
				pub remaining: ::core::primitive::u8,
				pub period: _0,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct Scheduled<_0, _1, _2, _3, _4, _5> {
				pub maybe_id: ::core::option::Option<_0>,
				pub priority: ::core::primitive::u8,
				pub call: _1,
				pub maybe_periodic: ::core::option::Option<(
					runtime_types::qp_scheduler::BlockNumberOrTimestamp<_2, _5>,
					_2,
				)>,
				pub origin: _3,
				#[codec(skip)]
				pub __ignore: ::core::marker::PhantomData<_4>,
			}
		}
		pub mod pallet_sudo {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Authenticates the sudo key and dispatches a function call with `Root` origin."]
					sudo {
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 1)]
					#[doc = "Authenticates the sudo key and dispatches a function call with `Root` origin."]
					#[doc = "This function does not check the weight of the call, and instead allows the"]
					#[doc = "Sudo user to specify the weight of the call."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					sudo_unchecked_weight {
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
						weight: runtime_types::sp_weights::weight_v2::Weight,
					},
					#[codec(index = 2)]
					#[doc = "Authenticates the current sudo key and sets the given AccountId (`new`) as the new sudo"]
					#[doc = "key."]
					set_key {
						new: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 3)]
					#[doc = "Authenticates the sudo key and dispatches a function call with `Signed` origin from"]
					#[doc = "a given account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					sudo_as {
						who: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 4)]
					#[doc = "Permanently removes the sudo key."]
					#[doc = ""]
					#[doc = "**This cannot be un-done.**"]
					remove_key,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Error for the Sudo pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Sender must be the Sudo account."]
					RequireSudo,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A sudo call just took place."]
					Sudid {
						sudo_result:
							::core::result::Result<(), runtime_types::sp_runtime::DispatchError>,
					},
					#[codec(index = 1)]
					#[doc = "The sudo key has been updated."]
					KeyChanged {
						old: ::core::option::Option<::subxt::ext::subxt_core::utils::AccountId32>,
						new: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 2)]
					#[doc = "The key was permanently removed."]
					KeyRemoved,
					#[codec(index = 3)]
					#[doc = "A [sudo_as](Pallet::sudo_as) call just took place."]
					SudoAsDone {
						sudo_result:
							::core::result::Result<(), runtime_types::sp_runtime::DispatchError>,
					},
				}
			}
		}
		pub mod pallet_timestamp {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Set the current time."]
					#[doc = ""]
					#[doc = "This call should be invoked exactly once per block. It will panic at the finalization"]
					#[doc = "phase, if this call hasn't been invoked by that time."]
					#[doc = ""]
					#[doc = "The timestamp should be greater than the previous one by the amount specified by"]
					#[doc = "[`Config::MinimumPeriod`]."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _None_."]
					#[doc = ""]
					#[doc = "This dispatch class is _Mandatory_ to ensure it gets executed in the block. Be aware"]
					#[doc = "that changing the complexity of this call could result exhausting the resources in a"]
					#[doc = "block to execute any other calls."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- `O(1)` (Note that implementations of `OnTimestampSet` must also be `O(1)`)"]
					#[doc = "- 1 storage read and 1 storage mutation (codec `O(1)` because of `DidUpdate::take` in"]
					#[doc = "  `on_finalize`)"]
					#[doc = "- 1 event handler `on_timestamp_set`. Must be `O(1)`."]
					set {
						#[codec(compact)]
						now: ::core::primitive::u64,
					},
				}
			}
		}
		pub mod pallet_transaction_payment {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A transaction fee `actual_fee`, of which `tip` was added to the minimum inclusion fee,"]
					#[doc = "has been paid by `who`."]
					TransactionFeePaid {
						who: ::subxt::ext::subxt_core::utils::AccountId32,
						actual_fee: ::core::primitive::u128,
						tip: ::core::primitive::u128,
					},
				}
			}
			pub mod types {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct FeeDetails<_0> {
					pub inclusion_fee: ::core::option::Option<
						runtime_types::pallet_transaction_payment::types::InclusionFee<_0>,
					>,
					pub tip: _0,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct InclusionFee<_0> {
					pub base_fee: _0,
					pub len_fee: _0,
					pub adjusted_weight_fee: _0,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct RuntimeDispatchInfo<_0, _1> {
					pub weight: _1,
					pub class: runtime_types::frame_support::dispatch::DispatchClass,
					pub partial_fee: _0,
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ChargeTransactionPayment(#[codec(compact)] pub ::core::primitive::u128);
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum Releases {
				#[codec(index = 0)]
				V1Ancient,
				#[codec(index = 1)]
				V2,
			}
		}
		pub mod pallet_treasury {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 3)]
					#[doc = "Propose and approve a spend of treasury funds."]
					#[doc = ""]
					#[doc = "## Dispatch Origin"]
					#[doc = ""]
					#[doc = "Must be [`Config::SpendOrigin`] with the `Success` value being at least `amount`."]
					#[doc = ""]
					#[doc = "### Details"]
					#[doc = "NOTE: For record-keeping purposes, the proposer is deemed to be equivalent to the"]
					#[doc = "beneficiary."]
					#[doc = ""]
					#[doc = "### Parameters"]
					#[doc = "- `amount`: The amount to be transferred from the treasury to the `beneficiary`."]
					#[doc = "- `beneficiary`: The destination account for the transfer."]
					#[doc = ""]
					#[doc = "## Events"]
					#[doc = ""]
					#[doc = "Emits [`Event::SpendApproved`] if successful."]
					spend_local {
						#[codec(compact)]
						amount: ::core::primitive::u128,
						beneficiary: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 4)]
					#[doc = "Force a previously approved proposal to be removed from the approval queue."]
					#[doc = ""]
					#[doc = "## Dispatch Origin"]
					#[doc = ""]
					#[doc = "Must be [`Config::RejectOrigin`]."]
					#[doc = ""]
					#[doc = "## Details"]
					#[doc = ""]
					#[doc = "The original deposit will no longer be returned."]
					#[doc = ""]
					#[doc = "### Parameters"]
					#[doc = "- `proposal_id`: The index of a proposal"]
					#[doc = ""]
					#[doc = "### Complexity"]
					#[doc = "- O(A) where `A` is the number of approvals"]
					#[doc = ""]
					#[doc = "### Errors"]
					#[doc = "- [`Error::ProposalNotApproved`]: The `proposal_id` supplied was not found in the"]
					#[doc = "  approval queue, i.e., the proposal has not been approved. This could also mean the"]
					#[doc = "  proposal does not exist altogether, thus there is no way it would have been approved"]
					#[doc = "  in the first place."]
					remove_approval {
						#[codec(compact)]
						proposal_id: ::core::primitive::u32,
					},
					#[codec(index = 5)]
					#[doc = "Propose and approve a spend of treasury funds."]
					#[doc = ""]
					#[doc = "## Dispatch Origin"]
					#[doc = ""]
					#[doc = "Must be [`Config::SpendOrigin`] with the `Success` value being at least"]
					#[doc = "`amount` of `asset_kind` in the native asset. The amount of `asset_kind` is converted"]
					#[doc = "for assertion using the [`Config::BalanceConverter`]."]
					#[doc = ""]
					#[doc = "## Details"]
					#[doc = ""]
					#[doc = "Create an approved spend for transferring a specific `amount` of `asset_kind` to a"]
					#[doc = "designated beneficiary. The spend must be claimed using the `payout` dispatchable within"]
					#[doc = "the [`Config::PayoutPeriod`]."]
					#[doc = ""]
					#[doc = "### Parameters"]
					#[doc = "- `asset_kind`: An indicator of the specific asset class to be spent."]
					#[doc = "- `amount`: The amount to be transferred from the treasury to the `beneficiary`."]
					#[doc = "- `beneficiary`: The beneficiary of the spend."]
					#[doc = "- `valid_from`: The block number from which the spend can be claimed. It can refer to"]
					#[doc = "  the past if the resulting spend has not yet expired according to the"]
					#[doc = "  [`Config::PayoutPeriod`]. If `None`, the spend can be claimed immediately after"]
					#[doc = "  approval."]
					#[doc = ""]
					#[doc = "## Events"]
					#[doc = ""]
					#[doc = "Emits [`Event::AssetSpendApproved`] if successful."]
					spend {
						asset_kind: ::subxt::ext::subxt_core::alloc::boxed::Box<()>,
						#[codec(compact)]
						amount: ::core::primitive::u128,
						beneficiary: ::subxt::ext::subxt_core::alloc::boxed::Box<
							::subxt::ext::subxt_core::utils::MultiAddress<
								::subxt::ext::subxt_core::utils::AccountId32,
								(),
							>,
						>,
						valid_from: ::core::option::Option<::core::primitive::u32>,
					},
					#[codec(index = 6)]
					#[doc = "Claim a spend."]
					#[doc = ""]
					#[doc = "## Dispatch Origin"]
					#[doc = ""]
					#[doc = "Must be signed"]
					#[doc = ""]
					#[doc = "## Details"]
					#[doc = ""]
					#[doc = "Spends must be claimed within some temporal bounds. A spend may be claimed within one"]
					#[doc = "[`Config::PayoutPeriod`] from the `valid_from` block."]
					#[doc = "In case of a payout failure, the spend status must be updated with the `check_status`"]
					#[doc = "dispatchable before retrying with the current function."]
					#[doc = ""]
					#[doc = "### Parameters"]
					#[doc = "- `index`: The spend index."]
					#[doc = ""]
					#[doc = "## Events"]
					#[doc = ""]
					#[doc = "Emits [`Event::Paid`] if successful."]
					payout { index: ::core::primitive::u32 },
					#[codec(index = 7)]
					#[doc = "Check the status of the spend and remove it from the storage if processed."]
					#[doc = ""]
					#[doc = "## Dispatch Origin"]
					#[doc = ""]
					#[doc = "Must be signed."]
					#[doc = ""]
					#[doc = "## Details"]
					#[doc = ""]
					#[doc = "The status check is a prerequisite for retrying a failed payout."]
					#[doc = "If a spend has either succeeded or expired, it is removed from the storage by this"]
					#[doc = "function. In such instances, transaction fees are refunded."]
					#[doc = ""]
					#[doc = "### Parameters"]
					#[doc = "- `index`: The spend index."]
					#[doc = ""]
					#[doc = "## Events"]
					#[doc = ""]
					#[doc = "Emits [`Event::PaymentFailed`] if the spend payout has failed."]
					#[doc = "Emits [`Event::SpendProcessed`] if the spend payout has succeed."]
					check_status { index: ::core::primitive::u32 },
					#[codec(index = 8)]
					#[doc = "Void previously approved spend."]
					#[doc = ""]
					#[doc = "## Dispatch Origin"]
					#[doc = ""]
					#[doc = "Must be [`Config::RejectOrigin`]."]
					#[doc = ""]
					#[doc = "## Details"]
					#[doc = ""]
					#[doc = "A spend void is only possible if the payout has not been attempted yet."]
					#[doc = ""]
					#[doc = "### Parameters"]
					#[doc = "- `index`: The spend index."]
					#[doc = ""]
					#[doc = "## Events"]
					#[doc = ""]
					#[doc = "Emits [`Event::AssetSpendVoided`] if successful."]
					void_spend { index: ::core::primitive::u32 },
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Error for the treasury pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "No proposal, bounty or spend at that index."]
					InvalidIndex,
					#[codec(index = 1)]
					#[doc = "Too many approvals in the queue."]
					TooManyApprovals,
					#[codec(index = 2)]
					#[doc = "The spend origin is valid but the amount it is allowed to spend is lower than the"]
					#[doc = "amount to be spent."]
					InsufficientPermission,
					#[codec(index = 3)]
					#[doc = "Proposal has not been approved."]
					ProposalNotApproved,
					#[codec(index = 4)]
					#[doc = "The balance of the asset kind is not convertible to the balance of the native asset."]
					FailedToConvertBalance,
					#[codec(index = 5)]
					#[doc = "The spend has expired and cannot be claimed."]
					SpendExpired,
					#[codec(index = 6)]
					#[doc = "The spend is not yet eligible for payout."]
					EarlyPayout,
					#[codec(index = 7)]
					#[doc = "The payment has already been attempted."]
					AlreadyAttempted,
					#[codec(index = 8)]
					#[doc = "There was some issue with the mechanism of payment."]
					PayoutError,
					#[codec(index = 9)]
					#[doc = "The payout was not yet attempted/claimed."]
					NotAttempted,
					#[codec(index = 10)]
					#[doc = "The payment has neither failed nor succeeded yet."]
					Inconclusive,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "We have ended a spend period and will now allocate funds."]
					Spending { budget_remaining: ::core::primitive::u128 },
					#[codec(index = 1)]
					#[doc = "Some funds have been allocated."]
					Awarded {
						proposal_index: ::core::primitive::u32,
						award: ::core::primitive::u128,
						account: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 2)]
					#[doc = "Some of our funds have been burnt."]
					Burnt { burnt_funds: ::core::primitive::u128 },
					#[codec(index = 3)]
					#[doc = "Spending has finished; this is the amount that rolls over until next spend."]
					Rollover { rollover_balance: ::core::primitive::u128 },
					#[codec(index = 4)]
					#[doc = "Some funds have been deposited."]
					Deposit { value: ::core::primitive::u128 },
					#[codec(index = 5)]
					#[doc = "A new spend proposal has been approved."]
					SpendApproved {
						proposal_index: ::core::primitive::u32,
						amount: ::core::primitive::u128,
						beneficiary: ::subxt::ext::subxt_core::utils::AccountId32,
					},
					#[codec(index = 6)]
					#[doc = "The inactive funds of the pallet have been updated."]
					UpdatedInactive {
						reactivated: ::core::primitive::u128,
						deactivated: ::core::primitive::u128,
					},
					#[codec(index = 7)]
					#[doc = "A new asset spend proposal has been approved."]
					AssetSpendApproved {
						index: ::core::primitive::u32,
						asset_kind: (),
						amount: ::core::primitive::u128,
						beneficiary: ::subxt::ext::subxt_core::utils::AccountId32,
						valid_from: ::core::primitive::u32,
						expire_at: ::core::primitive::u32,
					},
					#[codec(index = 8)]
					#[doc = "An approved spend was voided."]
					AssetSpendVoided { index: ::core::primitive::u32 },
					#[codec(index = 9)]
					#[doc = "A payment happened."]
					Paid { index: ::core::primitive::u32, payment_id: ::core::primitive::u32 },
					#[codec(index = 10)]
					#[doc = "A payment failed and can be retried."]
					PaymentFailed {
						index: ::core::primitive::u32,
						payment_id: ::core::primitive::u32,
					},
					#[codec(index = 11)]
					#[doc = "A spend was processed and removed from the storage. It might have been successfully"]
					#[doc = "paid or it may have expired."]
					SpendProcessed { index: ::core::primitive::u32 },
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum PaymentState<_0> {
				#[codec(index = 0)]
				Pending,
				#[codec(index = 1)]
				Attempted { id: _0 },
				#[codec(index = 2)]
				Failed,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct Proposal<_0, _1> {
				pub proposer: _0,
				pub value: _1,
				pub beneficiary: _0,
				pub bond: _1,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct SpendStatus<_0, _1, _2, _3, _4> {
				pub asset_kind: _0,
				pub amount: _1,
				pub beneficiary: _2,
				pub valid_from: _3,
				pub expire_at: _3,
				pub status: runtime_types::pallet_treasury::PaymentState<_3>,
				#[codec(skip)]
				pub __ignore: ::core::marker::PhantomData<_4>,
			}
		}
		pub mod pallet_utility {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Send a batch of dispatch calls."]
					#[doc = ""]
					#[doc = "May be called from any origin except `None`."]
					#[doc = ""]
					#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
					#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
					#[doc = ""]
					#[doc = "If origin is root then the calls are dispatched without checking origin filter. (This"]
					#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- O(C) where C is the number of calls to be batched."]
					#[doc = ""]
					#[doc = "This will return `Ok` in all circumstances. To determine the success of the batch, an"]
					#[doc = "event is deposited. If a call failed and the batch was interrupted, then the"]
					#[doc = "`BatchInterrupted` event is deposited, along with the number of successful calls made"]
					#[doc = "and the error of the failed call. If all were successful, then the `BatchCompleted`"]
					#[doc = "event is deposited."]
					batch {
						calls: ::subxt::ext::subxt_core::alloc::vec::Vec<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 1)]
					#[doc = "Send a call through an indexed pseudonym of the sender."]
					#[doc = ""]
					#[doc = "Filter from origin are passed along. The call will be dispatched with an origin which"]
					#[doc = "use the same filter as the origin of this call."]
					#[doc = ""]
					#[doc = "NOTE: If you need to ensure that any account-based filtering is not honored (i.e."]
					#[doc = "because you expect `proxy` to have been used prior in the call stack and you do not want"]
					#[doc = "the call restrictions to apply to any sub-accounts), then use `as_multi_threshold_1`"]
					#[doc = "in the Multisig pallet instead."]
					#[doc = ""]
					#[doc = "NOTE: Prior to version *12, this was called `as_limited_sub`."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					as_derivative {
						index: ::core::primitive::u16,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 2)]
					#[doc = "Send a batch of dispatch calls and atomically execute them."]
					#[doc = "The whole transaction will rollback and fail if any of the calls failed."]
					#[doc = ""]
					#[doc = "May be called from any origin except `None`."]
					#[doc = ""]
					#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
					#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
					#[doc = ""]
					#[doc = "If origin is root then the calls are dispatched without checking origin filter. (This"]
					#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- O(C) where C is the number of calls to be batched."]
					batch_all {
						calls: ::subxt::ext::subxt_core::alloc::vec::Vec<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 3)]
					#[doc = "Dispatches a function call with a provided origin."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Root_."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- O(1)."]
					dispatch_as {
						as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::OriginCaller,
						>,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 4)]
					#[doc = "Send a batch of dispatch calls."]
					#[doc = "Unlike `batch`, it allows errors and won't interrupt."]
					#[doc = ""]
					#[doc = "May be called from any origin except `None`."]
					#[doc = ""]
					#[doc = "- `calls`: The calls to be dispatched from the same origin. The number of call must not"]
					#[doc = "  exceed the constant: `batched_calls_limit` (available in constant metadata)."]
					#[doc = ""]
					#[doc = "If origin is root then the calls are dispatch without checking origin filter. (This"]
					#[doc = "includes bypassing `frame_system::Config::BaseCallFilter`)."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- O(C) where C is the number of calls to be batched."]
					force_batch {
						calls: ::subxt::ext::subxt_core::alloc::vec::Vec<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 5)]
					#[doc = "Dispatch a function call with a specified weight."]
					#[doc = ""]
					#[doc = "This function does not check the weight of the call, and instead allows the"]
					#[doc = "Root origin to specify the weight of the call."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Root_."]
					with_weight {
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
						weight: runtime_types::sp_weights::weight_v2::Weight,
					},
					#[codec(index = 6)]
					#[doc = "Dispatch a fallback call in the event the main call fails to execute."]
					#[doc = "May be called from any origin except `None`."]
					#[doc = ""]
					#[doc = "This function first attempts to dispatch the `main` call."]
					#[doc = "If the `main` call fails, the `fallback` is attemted."]
					#[doc = "if the fallback is successfully dispatched, the weights of both calls"]
					#[doc = "are accumulated and an event containing the main call error is deposited."]
					#[doc = ""]
					#[doc = "In the event of a fallback failure the whole call fails"]
					#[doc = "with the weights returned."]
					#[doc = ""]
					#[doc = "- `main`: The main call to be dispatched. This is the primary action to execute."]
					#[doc = "- `fallback`: The fallback call to be dispatched in case the `main` call fails."]
					#[doc = ""]
					#[doc = "## Dispatch Logic"]
					#[doc = "- If the origin is `root`, both the main and fallback calls are executed without"]
					#[doc = "  applying any origin filters."]
					#[doc = "- If the origin is not `root`, the origin filter is applied to both the `main` and"]
					#[doc = "  `fallback` calls."]
					#[doc = ""]
					#[doc = "## Use Case"]
					#[doc = "- Some use cases might involve submitting a `batch` type call in either main, fallback"]
					#[doc = "  or both."]
					if_else {
						main: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
						fallback: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
					#[codec(index = 7)]
					#[doc = "Dispatches a function call with a provided origin."]
					#[doc = ""]
					#[doc = "Almost the same as [`Pallet::dispatch_as`] but forwards any error of the inner call."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Root_."]
					dispatch_as_fallible {
						as_origin: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::OriginCaller,
						>,
						call: ::subxt::ext::subxt_core::alloc::boxed::Box<
							runtime_types::quantus_runtime::RuntimeCall,
						>,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "Too many calls batched."]
					TooManyCalls,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "Batch of dispatches did not complete fully. Index of first failing dispatch given, as"]
					#[doc = "well as the error."]
					BatchInterrupted {
						index: ::core::primitive::u32,
						error: runtime_types::sp_runtime::DispatchError,
					},
					#[codec(index = 1)]
					#[doc = "Batch of dispatches completed fully with no error."]
					BatchCompleted,
					#[codec(index = 2)]
					#[doc = "Batch of dispatches completed but has errors."]
					BatchCompletedWithErrors,
					#[codec(index = 3)]
					#[doc = "A single item within a Batch of dispatches has completed with no error."]
					ItemCompleted,
					#[codec(index = 4)]
					#[doc = "A single item within a Batch of dispatches has completed with error."]
					ItemFailed { error: runtime_types::sp_runtime::DispatchError },
					#[codec(index = 5)]
					#[doc = "A call was dispatched."]
					DispatchedAs {
						result:
							::core::result::Result<(), runtime_types::sp_runtime::DispatchError>,
					},
					#[codec(index = 6)]
					#[doc = "Main call was dispatched."]
					IfElseMainSuccess,
					#[codec(index = 7)]
					#[doc = "The fallback call was dispatched."]
					IfElseFallbackCalled { main_error: runtime_types::sp_runtime::DispatchError },
				}
			}
		}
		pub mod pallet_vesting {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					#[doc = "Unlock any vested funds of the sender account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_ and the sender must have funds still"]
					#[doc = "locked under this pallet."]
					#[doc = ""]
					#[doc = "Emits either `VestingCompleted` or `VestingUpdated`."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- `O(1)`."]
					vest,
					#[codec(index = 1)]
					#[doc = "Unlock any vested funds of a `target` account."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					#[doc = ""]
					#[doc = "- `target`: The account whose vested funds should be unlocked. Must have funds still"]
					#[doc = "locked under this pallet."]
					#[doc = ""]
					#[doc = "Emits either `VestingCompleted` or `VestingUpdated`."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- `O(1)`."]
					vest_other {
						target: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
					},
					#[codec(index = 2)]
					#[doc = "Create a vested transfer."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					#[doc = ""]
					#[doc = "- `target`: The account receiving the vested funds."]
					#[doc = "- `schedule`: The vesting schedule attached to the transfer."]
					#[doc = ""]
					#[doc = "Emits `VestingCreated`."]
					#[doc = ""]
					#[doc = "NOTE: This will unlock all schedules through the current block."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- `O(1)`."]
					vested_transfer {
						target: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						schedule: runtime_types::pallet_vesting::vesting_info::VestingInfo<
							::core::primitive::u128,
							::core::primitive::u32,
						>,
					},
					#[codec(index = 3)]
					#[doc = "Force a vested transfer."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Root_."]
					#[doc = ""]
					#[doc = "- `source`: The account whose funds should be transferred."]
					#[doc = "- `target`: The account that should be transferred the vested funds."]
					#[doc = "- `schedule`: The vesting schedule attached to the transfer."]
					#[doc = ""]
					#[doc = "Emits `VestingCreated`."]
					#[doc = ""]
					#[doc = "NOTE: This will unlock all schedules through the current block."]
					#[doc = ""]
					#[doc = "## Complexity"]
					#[doc = "- `O(1)`."]
					force_vested_transfer {
						source: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						target: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						schedule: runtime_types::pallet_vesting::vesting_info::VestingInfo<
							::core::primitive::u128,
							::core::primitive::u32,
						>,
					},
					#[codec(index = 4)]
					#[doc = "Merge two vesting schedules together, creating a new vesting schedule that unlocks over"]
					#[doc = "the highest possible start and end blocks. If both schedules have already started the"]
					#[doc = "current block will be used as the schedule start; with the caveat that if one schedule"]
					#[doc = "is finished by the current block, the other will be treated as the new merged schedule,"]
					#[doc = "unmodified."]
					#[doc = ""]
					#[doc = "NOTE: If `schedule1_index == schedule2_index` this is a no-op."]
					#[doc = "NOTE: This will unlock all schedules through the current block prior to merging."]
					#[doc = "NOTE: If both schedules have ended by the current block, no new schedule will be created"]
					#[doc = "and both will be removed."]
					#[doc = ""]
					#[doc = "Merged schedule attributes:"]
					#[doc = "- `starting_block`: `MAX(schedule1.starting_block, scheduled2.starting_block,"]
					#[doc = "  current_block)`."]
					#[doc = "- `ending_block`: `MAX(schedule1.ending_block, schedule2.ending_block)`."]
					#[doc = "- `locked`: `schedule1.locked_at(current_block) + schedule2.locked_at(current_block)`."]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Signed_."]
					#[doc = ""]
					#[doc = "- `schedule1_index`: index of the first schedule to merge."]
					#[doc = "- `schedule2_index`: index of the second schedule to merge."]
					merge_schedules {
						schedule1_index: ::core::primitive::u32,
						schedule2_index: ::core::primitive::u32,
					},
					#[codec(index = 5)]
					#[doc = "Force remove a vesting schedule"]
					#[doc = ""]
					#[doc = "The dispatch origin for this call must be _Root_."]
					#[doc = ""]
					#[doc = "- `target`: An account that has a vesting schedule"]
					#[doc = "- `schedule_index`: The vesting schedule index that should be removed"]
					force_remove_vesting_schedule {
						target: ::subxt::ext::subxt_core::utils::MultiAddress<
							::subxt::ext::subxt_core::utils::AccountId32,
							(),
						>,
						schedule_index: ::core::primitive::u32,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Error for the vesting pallet."]
				pub enum Error {
					#[codec(index = 0)]
					#[doc = "The account given is not vesting."]
					NotVesting,
					#[codec(index = 1)]
					#[doc = "The account already has `MaxVestingSchedules` count of schedules and thus"]
					#[doc = "cannot add another one. Consider merging existing schedules in order to add another."]
					AtMaxVestingSchedules,
					#[codec(index = 2)]
					#[doc = "Amount being transferred is too low to create a vesting schedule."]
					AmountLow,
					#[codec(index = 3)]
					#[doc = "An index was out of bounds of the vesting schedules."]
					ScheduleIndexOutOfBounds,
					#[codec(index = 4)]
					#[doc = "Failed to create a new schedule because some parameter was invalid."]
					InvalidScheduleParams,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					#[doc = "A vesting schedule has been created."]
					VestingCreated {
						account: ::subxt::ext::subxt_core::utils::AccountId32,
						schedule_index: ::core::primitive::u32,
					},
					#[codec(index = 1)]
					#[doc = "The amount vested has been updated. This could indicate a change in funds available."]
					#[doc = "The balance given is the amount which is left unvested (and thus locked)."]
					VestingUpdated {
						account: ::subxt::ext::subxt_core::utils::AccountId32,
						unvested: ::core::primitive::u128,
					},
					#[codec(index = 2)]
					#[doc = "An \\[account\\] has become fully vested."]
					VestingCompleted { account: ::subxt::ext::subxt_core::utils::AccountId32 },
				}
			}
			pub mod vesting_info {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct VestingInfo<_0, _1> {
					pub locked: _0,
					pub per_block: _0,
					pub starting_block: _1,
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum Releases {
				#[codec(index = 0)]
				V0,
				#[codec(index = 1)]
				V1,
			}
		}
		pub mod pallet_wormhole {
			use super::runtime_types;
			pub mod pallet {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "Contains a variant per dispatchable extrinsic that this pallet has."]
				pub enum Call {
					#[codec(index = 0)]
					verify_wormhole_proof {
						proof_bytes:
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						block_number: ::core::primitive::u32,
					},
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Error` enum of this pallet."]
				pub enum Error {
					#[codec(index = 0)]
					InvalidProof,
					#[codec(index = 1)]
					ProofDeserializationFailed,
					#[codec(index = 2)]
					VerificationFailed,
					#[codec(index = 3)]
					InvalidPublicInputs,
					#[codec(index = 4)]
					NullifierAlreadyUsed,
					#[codec(index = 5)]
					VerifierNotAvailable,
					#[codec(index = 6)]
					InvalidStorageRoot,
					#[codec(index = 7)]
					StorageRootMismatch,
					#[codec(index = 8)]
					BlockNotFound,
					#[codec(index = 9)]
					InvalidBlockNumber,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				#[doc = "The `Event` enum of this pallet"]
				pub enum Event {
					#[codec(index = 0)]
					ProofVerified { exit_amount: ::core::primitive::u128 },
				}
			}
		}
		pub mod poseidon_resonance {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct PoseidonHasher;
		}
		pub mod primitive_types {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct U512(pub [::core::primitive::u64; 8usize]);
		}
		pub mod qp_scheduler {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum BlockNumberOrTimestamp<_0, _1> {
				#[codec(index = 0)]
				BlockNumber(_0),
				#[codec(index = 1)]
				Timestamp(_1),
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum DispatchTime<_0, _1> {
				#[codec(index = 0)]
				At(_0),
				#[codec(index = 1)]
				After(runtime_types::qp_scheduler::BlockNumberOrTimestamp<_0, _1>),
			}
		}
		pub mod quantus_runtime {
			use super::runtime_types;
			pub mod governance {
				use super::runtime_types;
				pub mod definitions {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct PreimageDeposit {
						pub amount: ::core::primitive::u128,
					}
				}
				pub mod origins {
					use super::runtime_types;
					pub mod pallet_custom_origins {
						use super::runtime_types;
						#[derive(
							:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
							:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
							Debug,
						)]
						#[decode_as_type(
							crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
						)]
						#[encode_as_type(
							crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
						)]
						pub enum Origin {
							#[codec(index = 0)]
							Treasurer,
							#[codec(index = 1)]
							SmallSpender,
							#[codec(index = 2)]
							MediumSpender,
							#[codec(index = 3)]
							BigSpender,
						}
					}
				}
			}
			pub mod transaction_extensions {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ReversibleTransactionExtension;
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum OriginCaller {
				# [codec (index = 0)] system (runtime_types :: frame_support :: dispatch :: RawOrigin < :: subxt :: ext :: subxt_core :: utils :: AccountId32 > ,) , # [codec (index = 19)] Origins (runtime_types :: quantus_runtime :: governance :: origins :: pallet_custom_origins :: Origin ,) , }
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct Runtime;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum RuntimeCall {
				#[codec(index = 0)]
				System(runtime_types::frame_system::pallet::Call),
				#[codec(index = 1)]
				Timestamp(runtime_types::pallet_timestamp::pallet::Call),
				#[codec(index = 2)]
				Balances(runtime_types::pallet_balances::pallet::Call),
				#[codec(index = 4)]
				Sudo(runtime_types::pallet_sudo::pallet::Call),
				#[codec(index = 6)]
				Wormhole(runtime_types::pallet_wormhole::pallet::Call),
				#[codec(index = 8)]
				Vesting(runtime_types::pallet_vesting::pallet::Call),
				#[codec(index = 9)]
				Preimage(runtime_types::pallet_preimage::pallet::Call),
				#[codec(index = 10)]
				Scheduler(runtime_types::pallet_scheduler::pallet::Call),
				#[codec(index = 11)]
				Utility(runtime_types::pallet_utility::pallet::Call),
				#[codec(index = 12)]
				Referenda(runtime_types::pallet_referenda::pallet::Call),
				#[codec(index = 13)]
				ReversibleTransfers(runtime_types::pallet_reversible_transfers::pallet::Call),
				#[codec(index = 14)]
				ConvictionVoting(runtime_types::pallet_conviction_voting::pallet::Call),
				#[codec(index = 15)]
				TechCollective(runtime_types::pallet_ranked_collective::pallet::Call),
				#[codec(index = 16)]
				TechReferenda(runtime_types::pallet_referenda::pallet::Call),
				#[codec(index = 17)]
				MerkleAirdrop(runtime_types::pallet_merkle_airdrop::pallet::Call),
				#[codec(index = 18)]
				TreasuryPallet(runtime_types::pallet_treasury::pallet::Call),
				#[codec(index = 20)]
				Recovery(runtime_types::pallet_recovery::pallet::Call),
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum RuntimeError {
				#[codec(index = 0)]
				System(runtime_types::frame_system::pallet::Error),
				#[codec(index = 2)]
				Balances(runtime_types::pallet_balances::pallet::Error),
				#[codec(index = 4)]
				Sudo(runtime_types::pallet_sudo::pallet::Error),
				#[codec(index = 5)]
				QPoW(runtime_types::pallet_qpow::pallet::Error),
				#[codec(index = 6)]
				Wormhole(runtime_types::pallet_wormhole::pallet::Error),
				#[codec(index = 8)]
				Vesting(runtime_types::pallet_vesting::pallet::Error),
				#[codec(index = 9)]
				Preimage(runtime_types::pallet_preimage::pallet::Error),
				#[codec(index = 10)]
				Scheduler(runtime_types::pallet_scheduler::pallet::Error),
				#[codec(index = 11)]
				Utility(runtime_types::pallet_utility::pallet::Error),
				#[codec(index = 12)]
				Referenda(runtime_types::pallet_referenda::pallet::Error),
				#[codec(index = 13)]
				ReversibleTransfers(runtime_types::pallet_reversible_transfers::pallet::Error),
				#[codec(index = 14)]
				ConvictionVoting(runtime_types::pallet_conviction_voting::pallet::Error),
				#[codec(index = 15)]
				TechCollective(runtime_types::pallet_ranked_collective::pallet::Error),
				#[codec(index = 16)]
				TechReferenda(runtime_types::pallet_referenda::pallet::Error),
				#[codec(index = 17)]
				MerkleAirdrop(runtime_types::pallet_merkle_airdrop::pallet::Error),
				#[codec(index = 18)]
				TreasuryPallet(runtime_types::pallet_treasury::pallet::Error),
				#[codec(index = 20)]
				Recovery(runtime_types::pallet_recovery::pallet::Error),
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum RuntimeEvent {
				#[codec(index = 0)]
				System(runtime_types::frame_system::pallet::Event),
				#[codec(index = 2)]
				Balances(runtime_types::pallet_balances::pallet::Event),
				#[codec(index = 3)]
				TransactionPayment(runtime_types::pallet_transaction_payment::pallet::Event),
				#[codec(index = 4)]
				Sudo(runtime_types::pallet_sudo::pallet::Event),
				#[codec(index = 5)]
				QPoW(runtime_types::pallet_qpow::pallet::Event),
				#[codec(index = 6)]
				Wormhole(runtime_types::pallet_wormhole::pallet::Event),
				#[codec(index = 7)]
				MiningRewards(runtime_types::pallet_mining_rewards::pallet::Event),
				#[codec(index = 8)]
				Vesting(runtime_types::pallet_vesting::pallet::Event),
				#[codec(index = 9)]
				Preimage(runtime_types::pallet_preimage::pallet::Event),
				#[codec(index = 10)]
				Scheduler(runtime_types::pallet_scheduler::pallet::Event),
				#[codec(index = 11)]
				Utility(runtime_types::pallet_utility::pallet::Event),
				#[codec(index = 12)]
				Referenda(runtime_types::pallet_referenda::pallet::Event1),
				#[codec(index = 13)]
				ReversibleTransfers(runtime_types::pallet_reversible_transfers::pallet::Event),
				#[codec(index = 14)]
				ConvictionVoting(runtime_types::pallet_conviction_voting::pallet::Event),
				#[codec(index = 15)]
				TechCollective(runtime_types::pallet_ranked_collective::pallet::Event),
				#[codec(index = 16)]
				TechReferenda(runtime_types::pallet_referenda::pallet::Event2),
				#[codec(index = 17)]
				MerkleAirdrop(runtime_types::pallet_merkle_airdrop::pallet::Event),
				#[codec(index = 18)]
				TreasuryPallet(runtime_types::pallet_treasury::pallet::Event),
				#[codec(index = 20)]
				Recovery(runtime_types::pallet_recovery::pallet::Event),
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum RuntimeFreezeReason {}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum RuntimeHoldReason {
				#[codec(index = 9)]
				Preimage(runtime_types::pallet_preimage::pallet::HoldReason),
				#[codec(index = 13)]
				ReversibleTransfers(runtime_types::pallet_reversible_transfers::pallet::HoldReason),
			}
		}
		pub mod sp_arithmetic {
			use super::runtime_types;
			pub mod fixed_point {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct FixedI64(pub ::core::primitive::i64);
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct FixedU128(pub ::core::primitive::u128);
			}
			pub mod per_things {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Perbill(pub ::core::primitive::u32);
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Permill(pub ::core::primitive::u32);
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum ArithmeticError {
				#[codec(index = 0)]
				Underflow,
				#[codec(index = 1)]
				Overflow,
				#[codec(index = 2)]
				DivisionByZero,
			}
		}
		pub mod sp_core {
			use super::runtime_types;
			pub mod crypto {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct KeyTypeId(pub [::core::primitive::u8; 4usize]);
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct OpaqueMetadata(
				pub ::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
			);
		}
		pub mod sp_inherents {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct CheckInherentsResult {
				pub okay: ::core::primitive::bool,
				pub fatal_error: ::core::primitive::bool,
				pub errors: runtime_types::sp_inherents::InherentData,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct InherentData {
				pub data: ::subxt::ext::subxt_core::utils::KeyedVec<
					[::core::primitive::u8; 8usize],
					::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
				>,
			}
		}
		pub mod sp_runtime {
			use super::runtime_types;
			pub mod generic {
				use super::runtime_types;
				pub mod block {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct Block<_0, _1> {
						pub header: _0,
						pub extrinsics: ::subxt::ext::subxt_core::alloc::vec::Vec<_1>,
					}
				}
				pub mod digest {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct Digest {
						pub logs: ::subxt::ext::subxt_core::alloc::vec::Vec<
							runtime_types::sp_runtime::generic::digest::DigestItem,
						>,
					}
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub enum DigestItem {
						#[codec(index = 6)]
						PreRuntime(
							[::core::primitive::u8; 4usize],
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						),
						#[codec(index = 4)]
						Consensus(
							[::core::primitive::u8; 4usize],
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						),
						#[codec(index = 5)]
						Seal(
							[::core::primitive::u8; 4usize],
							::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
						),
						#[codec(index = 0)]
						Other(::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>),
						#[codec(index = 8)]
						RuntimeEnvironmentUpdated,
					}
				}
				pub mod era {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub enum Era {
						#[codec(index = 0)]
						Immortal,
						#[codec(index = 1)]
						Mortal1(::core::primitive::u8),
						#[codec(index = 2)]
						Mortal2(::core::primitive::u8),
						#[codec(index = 3)]
						Mortal3(::core::primitive::u8),
						#[codec(index = 4)]
						Mortal4(::core::primitive::u8),
						#[codec(index = 5)]
						Mortal5(::core::primitive::u8),
						#[codec(index = 6)]
						Mortal6(::core::primitive::u8),
						#[codec(index = 7)]
						Mortal7(::core::primitive::u8),
						#[codec(index = 8)]
						Mortal8(::core::primitive::u8),
						#[codec(index = 9)]
						Mortal9(::core::primitive::u8),
						#[codec(index = 10)]
						Mortal10(::core::primitive::u8),
						#[codec(index = 11)]
						Mortal11(::core::primitive::u8),
						#[codec(index = 12)]
						Mortal12(::core::primitive::u8),
						#[codec(index = 13)]
						Mortal13(::core::primitive::u8),
						#[codec(index = 14)]
						Mortal14(::core::primitive::u8),
						#[codec(index = 15)]
						Mortal15(::core::primitive::u8),
						#[codec(index = 16)]
						Mortal16(::core::primitive::u8),
						#[codec(index = 17)]
						Mortal17(::core::primitive::u8),
						#[codec(index = 18)]
						Mortal18(::core::primitive::u8),
						#[codec(index = 19)]
						Mortal19(::core::primitive::u8),
						#[codec(index = 20)]
						Mortal20(::core::primitive::u8),
						#[codec(index = 21)]
						Mortal21(::core::primitive::u8),
						#[codec(index = 22)]
						Mortal22(::core::primitive::u8),
						#[codec(index = 23)]
						Mortal23(::core::primitive::u8),
						#[codec(index = 24)]
						Mortal24(::core::primitive::u8),
						#[codec(index = 25)]
						Mortal25(::core::primitive::u8),
						#[codec(index = 26)]
						Mortal26(::core::primitive::u8),
						#[codec(index = 27)]
						Mortal27(::core::primitive::u8),
						#[codec(index = 28)]
						Mortal28(::core::primitive::u8),
						#[codec(index = 29)]
						Mortal29(::core::primitive::u8),
						#[codec(index = 30)]
						Mortal30(::core::primitive::u8),
						#[codec(index = 31)]
						Mortal31(::core::primitive::u8),
						#[codec(index = 32)]
						Mortal32(::core::primitive::u8),
						#[codec(index = 33)]
						Mortal33(::core::primitive::u8),
						#[codec(index = 34)]
						Mortal34(::core::primitive::u8),
						#[codec(index = 35)]
						Mortal35(::core::primitive::u8),
						#[codec(index = 36)]
						Mortal36(::core::primitive::u8),
						#[codec(index = 37)]
						Mortal37(::core::primitive::u8),
						#[codec(index = 38)]
						Mortal38(::core::primitive::u8),
						#[codec(index = 39)]
						Mortal39(::core::primitive::u8),
						#[codec(index = 40)]
						Mortal40(::core::primitive::u8),
						#[codec(index = 41)]
						Mortal41(::core::primitive::u8),
						#[codec(index = 42)]
						Mortal42(::core::primitive::u8),
						#[codec(index = 43)]
						Mortal43(::core::primitive::u8),
						#[codec(index = 44)]
						Mortal44(::core::primitive::u8),
						#[codec(index = 45)]
						Mortal45(::core::primitive::u8),
						#[codec(index = 46)]
						Mortal46(::core::primitive::u8),
						#[codec(index = 47)]
						Mortal47(::core::primitive::u8),
						#[codec(index = 48)]
						Mortal48(::core::primitive::u8),
						#[codec(index = 49)]
						Mortal49(::core::primitive::u8),
						#[codec(index = 50)]
						Mortal50(::core::primitive::u8),
						#[codec(index = 51)]
						Mortal51(::core::primitive::u8),
						#[codec(index = 52)]
						Mortal52(::core::primitive::u8),
						#[codec(index = 53)]
						Mortal53(::core::primitive::u8),
						#[codec(index = 54)]
						Mortal54(::core::primitive::u8),
						#[codec(index = 55)]
						Mortal55(::core::primitive::u8),
						#[codec(index = 56)]
						Mortal56(::core::primitive::u8),
						#[codec(index = 57)]
						Mortal57(::core::primitive::u8),
						#[codec(index = 58)]
						Mortal58(::core::primitive::u8),
						#[codec(index = 59)]
						Mortal59(::core::primitive::u8),
						#[codec(index = 60)]
						Mortal60(::core::primitive::u8),
						#[codec(index = 61)]
						Mortal61(::core::primitive::u8),
						#[codec(index = 62)]
						Mortal62(::core::primitive::u8),
						#[codec(index = 63)]
						Mortal63(::core::primitive::u8),
						#[codec(index = 64)]
						Mortal64(::core::primitive::u8),
						#[codec(index = 65)]
						Mortal65(::core::primitive::u8),
						#[codec(index = 66)]
						Mortal66(::core::primitive::u8),
						#[codec(index = 67)]
						Mortal67(::core::primitive::u8),
						#[codec(index = 68)]
						Mortal68(::core::primitive::u8),
						#[codec(index = 69)]
						Mortal69(::core::primitive::u8),
						#[codec(index = 70)]
						Mortal70(::core::primitive::u8),
						#[codec(index = 71)]
						Mortal71(::core::primitive::u8),
						#[codec(index = 72)]
						Mortal72(::core::primitive::u8),
						#[codec(index = 73)]
						Mortal73(::core::primitive::u8),
						#[codec(index = 74)]
						Mortal74(::core::primitive::u8),
						#[codec(index = 75)]
						Mortal75(::core::primitive::u8),
						#[codec(index = 76)]
						Mortal76(::core::primitive::u8),
						#[codec(index = 77)]
						Mortal77(::core::primitive::u8),
						#[codec(index = 78)]
						Mortal78(::core::primitive::u8),
						#[codec(index = 79)]
						Mortal79(::core::primitive::u8),
						#[codec(index = 80)]
						Mortal80(::core::primitive::u8),
						#[codec(index = 81)]
						Mortal81(::core::primitive::u8),
						#[codec(index = 82)]
						Mortal82(::core::primitive::u8),
						#[codec(index = 83)]
						Mortal83(::core::primitive::u8),
						#[codec(index = 84)]
						Mortal84(::core::primitive::u8),
						#[codec(index = 85)]
						Mortal85(::core::primitive::u8),
						#[codec(index = 86)]
						Mortal86(::core::primitive::u8),
						#[codec(index = 87)]
						Mortal87(::core::primitive::u8),
						#[codec(index = 88)]
						Mortal88(::core::primitive::u8),
						#[codec(index = 89)]
						Mortal89(::core::primitive::u8),
						#[codec(index = 90)]
						Mortal90(::core::primitive::u8),
						#[codec(index = 91)]
						Mortal91(::core::primitive::u8),
						#[codec(index = 92)]
						Mortal92(::core::primitive::u8),
						#[codec(index = 93)]
						Mortal93(::core::primitive::u8),
						#[codec(index = 94)]
						Mortal94(::core::primitive::u8),
						#[codec(index = 95)]
						Mortal95(::core::primitive::u8),
						#[codec(index = 96)]
						Mortal96(::core::primitive::u8),
						#[codec(index = 97)]
						Mortal97(::core::primitive::u8),
						#[codec(index = 98)]
						Mortal98(::core::primitive::u8),
						#[codec(index = 99)]
						Mortal99(::core::primitive::u8),
						#[codec(index = 100)]
						Mortal100(::core::primitive::u8),
						#[codec(index = 101)]
						Mortal101(::core::primitive::u8),
						#[codec(index = 102)]
						Mortal102(::core::primitive::u8),
						#[codec(index = 103)]
						Mortal103(::core::primitive::u8),
						#[codec(index = 104)]
						Mortal104(::core::primitive::u8),
						#[codec(index = 105)]
						Mortal105(::core::primitive::u8),
						#[codec(index = 106)]
						Mortal106(::core::primitive::u8),
						#[codec(index = 107)]
						Mortal107(::core::primitive::u8),
						#[codec(index = 108)]
						Mortal108(::core::primitive::u8),
						#[codec(index = 109)]
						Mortal109(::core::primitive::u8),
						#[codec(index = 110)]
						Mortal110(::core::primitive::u8),
						#[codec(index = 111)]
						Mortal111(::core::primitive::u8),
						#[codec(index = 112)]
						Mortal112(::core::primitive::u8),
						#[codec(index = 113)]
						Mortal113(::core::primitive::u8),
						#[codec(index = 114)]
						Mortal114(::core::primitive::u8),
						#[codec(index = 115)]
						Mortal115(::core::primitive::u8),
						#[codec(index = 116)]
						Mortal116(::core::primitive::u8),
						#[codec(index = 117)]
						Mortal117(::core::primitive::u8),
						#[codec(index = 118)]
						Mortal118(::core::primitive::u8),
						#[codec(index = 119)]
						Mortal119(::core::primitive::u8),
						#[codec(index = 120)]
						Mortal120(::core::primitive::u8),
						#[codec(index = 121)]
						Mortal121(::core::primitive::u8),
						#[codec(index = 122)]
						Mortal122(::core::primitive::u8),
						#[codec(index = 123)]
						Mortal123(::core::primitive::u8),
						#[codec(index = 124)]
						Mortal124(::core::primitive::u8),
						#[codec(index = 125)]
						Mortal125(::core::primitive::u8),
						#[codec(index = 126)]
						Mortal126(::core::primitive::u8),
						#[codec(index = 127)]
						Mortal127(::core::primitive::u8),
						#[codec(index = 128)]
						Mortal128(::core::primitive::u8),
						#[codec(index = 129)]
						Mortal129(::core::primitive::u8),
						#[codec(index = 130)]
						Mortal130(::core::primitive::u8),
						#[codec(index = 131)]
						Mortal131(::core::primitive::u8),
						#[codec(index = 132)]
						Mortal132(::core::primitive::u8),
						#[codec(index = 133)]
						Mortal133(::core::primitive::u8),
						#[codec(index = 134)]
						Mortal134(::core::primitive::u8),
						#[codec(index = 135)]
						Mortal135(::core::primitive::u8),
						#[codec(index = 136)]
						Mortal136(::core::primitive::u8),
						#[codec(index = 137)]
						Mortal137(::core::primitive::u8),
						#[codec(index = 138)]
						Mortal138(::core::primitive::u8),
						#[codec(index = 139)]
						Mortal139(::core::primitive::u8),
						#[codec(index = 140)]
						Mortal140(::core::primitive::u8),
						#[codec(index = 141)]
						Mortal141(::core::primitive::u8),
						#[codec(index = 142)]
						Mortal142(::core::primitive::u8),
						#[codec(index = 143)]
						Mortal143(::core::primitive::u8),
						#[codec(index = 144)]
						Mortal144(::core::primitive::u8),
						#[codec(index = 145)]
						Mortal145(::core::primitive::u8),
						#[codec(index = 146)]
						Mortal146(::core::primitive::u8),
						#[codec(index = 147)]
						Mortal147(::core::primitive::u8),
						#[codec(index = 148)]
						Mortal148(::core::primitive::u8),
						#[codec(index = 149)]
						Mortal149(::core::primitive::u8),
						#[codec(index = 150)]
						Mortal150(::core::primitive::u8),
						#[codec(index = 151)]
						Mortal151(::core::primitive::u8),
						#[codec(index = 152)]
						Mortal152(::core::primitive::u8),
						#[codec(index = 153)]
						Mortal153(::core::primitive::u8),
						#[codec(index = 154)]
						Mortal154(::core::primitive::u8),
						#[codec(index = 155)]
						Mortal155(::core::primitive::u8),
						#[codec(index = 156)]
						Mortal156(::core::primitive::u8),
						#[codec(index = 157)]
						Mortal157(::core::primitive::u8),
						#[codec(index = 158)]
						Mortal158(::core::primitive::u8),
						#[codec(index = 159)]
						Mortal159(::core::primitive::u8),
						#[codec(index = 160)]
						Mortal160(::core::primitive::u8),
						#[codec(index = 161)]
						Mortal161(::core::primitive::u8),
						#[codec(index = 162)]
						Mortal162(::core::primitive::u8),
						#[codec(index = 163)]
						Mortal163(::core::primitive::u8),
						#[codec(index = 164)]
						Mortal164(::core::primitive::u8),
						#[codec(index = 165)]
						Mortal165(::core::primitive::u8),
						#[codec(index = 166)]
						Mortal166(::core::primitive::u8),
						#[codec(index = 167)]
						Mortal167(::core::primitive::u8),
						#[codec(index = 168)]
						Mortal168(::core::primitive::u8),
						#[codec(index = 169)]
						Mortal169(::core::primitive::u8),
						#[codec(index = 170)]
						Mortal170(::core::primitive::u8),
						#[codec(index = 171)]
						Mortal171(::core::primitive::u8),
						#[codec(index = 172)]
						Mortal172(::core::primitive::u8),
						#[codec(index = 173)]
						Mortal173(::core::primitive::u8),
						#[codec(index = 174)]
						Mortal174(::core::primitive::u8),
						#[codec(index = 175)]
						Mortal175(::core::primitive::u8),
						#[codec(index = 176)]
						Mortal176(::core::primitive::u8),
						#[codec(index = 177)]
						Mortal177(::core::primitive::u8),
						#[codec(index = 178)]
						Mortal178(::core::primitive::u8),
						#[codec(index = 179)]
						Mortal179(::core::primitive::u8),
						#[codec(index = 180)]
						Mortal180(::core::primitive::u8),
						#[codec(index = 181)]
						Mortal181(::core::primitive::u8),
						#[codec(index = 182)]
						Mortal182(::core::primitive::u8),
						#[codec(index = 183)]
						Mortal183(::core::primitive::u8),
						#[codec(index = 184)]
						Mortal184(::core::primitive::u8),
						#[codec(index = 185)]
						Mortal185(::core::primitive::u8),
						#[codec(index = 186)]
						Mortal186(::core::primitive::u8),
						#[codec(index = 187)]
						Mortal187(::core::primitive::u8),
						#[codec(index = 188)]
						Mortal188(::core::primitive::u8),
						#[codec(index = 189)]
						Mortal189(::core::primitive::u8),
						#[codec(index = 190)]
						Mortal190(::core::primitive::u8),
						#[codec(index = 191)]
						Mortal191(::core::primitive::u8),
						#[codec(index = 192)]
						Mortal192(::core::primitive::u8),
						#[codec(index = 193)]
						Mortal193(::core::primitive::u8),
						#[codec(index = 194)]
						Mortal194(::core::primitive::u8),
						#[codec(index = 195)]
						Mortal195(::core::primitive::u8),
						#[codec(index = 196)]
						Mortal196(::core::primitive::u8),
						#[codec(index = 197)]
						Mortal197(::core::primitive::u8),
						#[codec(index = 198)]
						Mortal198(::core::primitive::u8),
						#[codec(index = 199)]
						Mortal199(::core::primitive::u8),
						#[codec(index = 200)]
						Mortal200(::core::primitive::u8),
						#[codec(index = 201)]
						Mortal201(::core::primitive::u8),
						#[codec(index = 202)]
						Mortal202(::core::primitive::u8),
						#[codec(index = 203)]
						Mortal203(::core::primitive::u8),
						#[codec(index = 204)]
						Mortal204(::core::primitive::u8),
						#[codec(index = 205)]
						Mortal205(::core::primitive::u8),
						#[codec(index = 206)]
						Mortal206(::core::primitive::u8),
						#[codec(index = 207)]
						Mortal207(::core::primitive::u8),
						#[codec(index = 208)]
						Mortal208(::core::primitive::u8),
						#[codec(index = 209)]
						Mortal209(::core::primitive::u8),
						#[codec(index = 210)]
						Mortal210(::core::primitive::u8),
						#[codec(index = 211)]
						Mortal211(::core::primitive::u8),
						#[codec(index = 212)]
						Mortal212(::core::primitive::u8),
						#[codec(index = 213)]
						Mortal213(::core::primitive::u8),
						#[codec(index = 214)]
						Mortal214(::core::primitive::u8),
						#[codec(index = 215)]
						Mortal215(::core::primitive::u8),
						#[codec(index = 216)]
						Mortal216(::core::primitive::u8),
						#[codec(index = 217)]
						Mortal217(::core::primitive::u8),
						#[codec(index = 218)]
						Mortal218(::core::primitive::u8),
						#[codec(index = 219)]
						Mortal219(::core::primitive::u8),
						#[codec(index = 220)]
						Mortal220(::core::primitive::u8),
						#[codec(index = 221)]
						Mortal221(::core::primitive::u8),
						#[codec(index = 222)]
						Mortal222(::core::primitive::u8),
						#[codec(index = 223)]
						Mortal223(::core::primitive::u8),
						#[codec(index = 224)]
						Mortal224(::core::primitive::u8),
						#[codec(index = 225)]
						Mortal225(::core::primitive::u8),
						#[codec(index = 226)]
						Mortal226(::core::primitive::u8),
						#[codec(index = 227)]
						Mortal227(::core::primitive::u8),
						#[codec(index = 228)]
						Mortal228(::core::primitive::u8),
						#[codec(index = 229)]
						Mortal229(::core::primitive::u8),
						#[codec(index = 230)]
						Mortal230(::core::primitive::u8),
						#[codec(index = 231)]
						Mortal231(::core::primitive::u8),
						#[codec(index = 232)]
						Mortal232(::core::primitive::u8),
						#[codec(index = 233)]
						Mortal233(::core::primitive::u8),
						#[codec(index = 234)]
						Mortal234(::core::primitive::u8),
						#[codec(index = 235)]
						Mortal235(::core::primitive::u8),
						#[codec(index = 236)]
						Mortal236(::core::primitive::u8),
						#[codec(index = 237)]
						Mortal237(::core::primitive::u8),
						#[codec(index = 238)]
						Mortal238(::core::primitive::u8),
						#[codec(index = 239)]
						Mortal239(::core::primitive::u8),
						#[codec(index = 240)]
						Mortal240(::core::primitive::u8),
						#[codec(index = 241)]
						Mortal241(::core::primitive::u8),
						#[codec(index = 242)]
						Mortal242(::core::primitive::u8),
						#[codec(index = 243)]
						Mortal243(::core::primitive::u8),
						#[codec(index = 244)]
						Mortal244(::core::primitive::u8),
						#[codec(index = 245)]
						Mortal245(::core::primitive::u8),
						#[codec(index = 246)]
						Mortal246(::core::primitive::u8),
						#[codec(index = 247)]
						Mortal247(::core::primitive::u8),
						#[codec(index = 248)]
						Mortal248(::core::primitive::u8),
						#[codec(index = 249)]
						Mortal249(::core::primitive::u8),
						#[codec(index = 250)]
						Mortal250(::core::primitive::u8),
						#[codec(index = 251)]
						Mortal251(::core::primitive::u8),
						#[codec(index = 252)]
						Mortal252(::core::primitive::u8),
						#[codec(index = 253)]
						Mortal253(::core::primitive::u8),
						#[codec(index = 254)]
						Mortal254(::core::primitive::u8),
						#[codec(index = 255)]
						Mortal255(::core::primitive::u8),
					}
				}
				pub mod header {
					use super::runtime_types;
					#[derive(
						:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
						:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
						Debug,
					)]
					#[decode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
					)]
					#[encode_as_type(
						crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
					)]
					pub struct Header<_0> {
						pub parent_hash: ::subxt::ext::subxt_core::utils::H256,
						#[codec(compact)]
						pub number: _0,
						pub state_root: ::subxt::ext::subxt_core::utils::H256,
						pub extrinsics_root: ::subxt::ext::subxt_core::utils::H256,
						pub digest: runtime_types::sp_runtime::generic::digest::Digest,
					}
				}
			}
			pub mod proving_trie {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum TrieError {
					#[codec(index = 0)]
					InvalidStateRoot,
					#[codec(index = 1)]
					IncompleteDatabase,
					#[codec(index = 2)]
					ValueAtIncompleteKey,
					#[codec(index = 3)]
					DecoderError,
					#[codec(index = 4)]
					InvalidHash,
					#[codec(index = 5)]
					DuplicateKey,
					#[codec(index = 6)]
					ExtraneousNode,
					#[codec(index = 7)]
					ExtraneousValue,
					#[codec(index = 8)]
					ExtraneousHashReference,
					#[codec(index = 9)]
					InvalidChildReference,
					#[codec(index = 10)]
					ValueMismatch,
					#[codec(index = 11)]
					IncompleteProof,
					#[codec(index = 12)]
					RootMismatch,
					#[codec(index = 13)]
					DecodeError,
				}
			}
			pub mod transaction_validity {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum InvalidTransaction {
					#[codec(index = 0)]
					Call,
					#[codec(index = 1)]
					Payment,
					#[codec(index = 2)]
					Future,
					#[codec(index = 3)]
					Stale,
					#[codec(index = 4)]
					BadProof,
					#[codec(index = 5)]
					AncientBirthBlock,
					#[codec(index = 6)]
					ExhaustsResources,
					#[codec(index = 7)]
					Custom(::core::primitive::u8),
					#[codec(index = 8)]
					BadMandatory,
					#[codec(index = 9)]
					MandatoryValidation,
					#[codec(index = 10)]
					BadSigner,
					#[codec(index = 11)]
					IndeterminateImplicit,
					#[codec(index = 12)]
					UnknownOrigin,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum TransactionSource {
					#[codec(index = 0)]
					InBlock,
					#[codec(index = 1)]
					Local,
					#[codec(index = 2)]
					External,
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum TransactionValidityError {
					#[codec(index = 0)]
					Invalid(runtime_types::sp_runtime::transaction_validity::InvalidTransaction),
					#[codec(index = 1)]
					Unknown(runtime_types::sp_runtime::transaction_validity::UnknownTransaction),
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub enum UnknownTransaction {
					#[codec(index = 0)]
					CannotLookup,
					#[codec(index = 1)]
					NoUnsignedValidator,
					#[codec(index = 2)]
					Custom(::core::primitive::u8),
				}
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct ValidTransaction {
					pub priority: ::core::primitive::u64,
					pub requires: ::subxt::ext::subxt_core::alloc::vec::Vec<
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					>,
					pub provides: ::subxt::ext::subxt_core::alloc::vec::Vec<
						::subxt::ext::subxt_core::alloc::vec::Vec<::core::primitive::u8>,
					>,
					pub longevity: ::core::primitive::u64,
					pub propagate: ::core::primitive::bool,
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum DispatchError {
				#[codec(index = 0)]
				Other,
				#[codec(index = 1)]
				CannotLookup,
				#[codec(index = 2)]
				BadOrigin,
				#[codec(index = 3)]
				Module(runtime_types::sp_runtime::ModuleError),
				#[codec(index = 4)]
				ConsumerRemaining,
				#[codec(index = 5)]
				NoProviders,
				#[codec(index = 6)]
				TooManyConsumers,
				#[codec(index = 7)]
				Token(runtime_types::sp_runtime::TokenError),
				#[codec(index = 8)]
				Arithmetic(runtime_types::sp_arithmetic::ArithmeticError),
				#[codec(index = 9)]
				Transactional(runtime_types::sp_runtime::TransactionalError),
				#[codec(index = 10)]
				Exhausted,
				#[codec(index = 11)]
				Corruption,
				#[codec(index = 12)]
				Unavailable,
				#[codec(index = 13)]
				RootNotAllowed,
				#[codec(index = 14)]
				Trie(runtime_types::sp_runtime::proving_trie::TrieError),
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct DispatchErrorWithPostInfo<_0> {
				pub post_info: _0,
				pub error: runtime_types::sp_runtime::DispatchError,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum ExtrinsicInclusionMode {
				#[codec(index = 0)]
				AllExtrinsics,
				#[codec(index = 1)]
				OnlyInherents,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct ModuleError {
				pub index: ::core::primitive::u8,
				pub error: [::core::primitive::u8; 4usize],
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum TokenError {
				#[codec(index = 0)]
				FundsUnavailable,
				#[codec(index = 1)]
				OnlyProvider,
				#[codec(index = 2)]
				BelowMinimum,
				#[codec(index = 3)]
				CannotCreate,
				#[codec(index = 4)]
				UnknownAsset,
				#[codec(index = 5)]
				Frozen,
				#[codec(index = 6)]
				Unsupported,
				#[codec(index = 7)]
				CannotCreateHold,
				#[codec(index = 8)]
				NotExpendable,
				#[codec(index = 9)]
				Blocked,
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub enum TransactionalError {
				#[codec(index = 0)]
				LimitReached,
				#[codec(index = 1)]
				NoLayer,
			}
		}
		pub mod sp_version {
			use super::runtime_types;
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct RuntimeVersion {
				pub spec_name: ::subxt::ext::subxt_core::alloc::string::String,
				pub impl_name: ::subxt::ext::subxt_core::alloc::string::String,
				pub authoring_version: ::core::primitive::u32,
				pub spec_version: ::core::primitive::u32,
				pub impl_version: ::core::primitive::u32,
				pub apis: ::subxt::ext::subxt_core::alloc::vec::Vec<(
					[::core::primitive::u8; 8usize],
					::core::primitive::u32,
				)>,
				pub transaction_version: ::core::primitive::u32,
				pub system_version: ::core::primitive::u8,
			}
		}
		pub mod sp_weights {
			use super::runtime_types;
			pub mod weight_v2 {
				use super::runtime_types;
				#[derive(
					:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
					:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
					Debug,
				)]
				#[decode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode"
				)]
				#[encode_as_type(
					crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode"
				)]
				pub struct Weight {
					#[codec(compact)]
					pub ref_time: ::core::primitive::u64,
					#[codec(compact)]
					pub proof_size: ::core::primitive::u64,
				}
			}
			#[derive(
				:: subxt :: ext :: subxt_core :: ext :: scale_decode :: DecodeAsType,
				:: subxt :: ext :: subxt_core :: ext :: scale_encode :: EncodeAsType,
				Debug,
			)]
			#[decode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_decode")]
			#[encode_as_type(crate_path = ":: subxt :: ext :: subxt_core :: ext :: scale_encode")]
			pub struct RuntimeDbWeight {
				pub read: ::core::primitive::u64,
				pub write: ::core::primitive::u64,
			}
		}
	}
}
