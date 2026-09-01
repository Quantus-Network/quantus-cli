//! FIPS 204 context binding for Quantus extrinsic signatures.
//!
//! The runtime signs and verifies extrinsics under [`EXTRINSIC`]. `sp_core::Pair::sign` in the
//! published `qp-dilithium-crypto` still passes no context, and the chain rejects what it
//! produces as "Transaction has a bad signature". Every extrinsic signature the CLI makes or
//! checks goes through this module instead.

use qp_dilithium_crypto::types::{
	Dilithium65Pair, Dilithium65Signature, Dilithium65SignatureWithPublic, Dilithium87Pair,
	Dilithium87Signature, Dilithium87SignatureWithPublic,
};
use sp_core::{ByteArray, Pair};

/// The FIPS 204 context the runtime binds extrinsic signatures to. Mirrors
/// `qp_dilithium_crypto::signing_context::EXTRINSIC` in the chain.
pub const EXTRINSIC: &[u8] = b"QUANTUS_EXTRINSIC";

macro_rules! context_sign {
	($sign:ident, $pair:ty, $signature:ty, $sig_with_public:ty, $module:ident) => {
		/// Sign `message` under [`EXTRINSIC`], the way the runtime expects.
		pub fn $sign(pair: &$pair, message: &[u8]) -> $sig_with_public {
			let secret =
				qp_rusty_crystals_dilithium::$module::SecretKey::from_bytes(pair.secret_bytes())
					.expect("wallet secret key must parse");
			let signature = secret
				.sign(message, Some(EXTRINSIC), None)
				.expect("EXTRINSIC context is well-formed");
			let signature = <$signature as TryFrom<&[u8]>>::try_from(signature.as_ref())
				.expect("signature length is fixed");
			<$sig_with_public>::new(signature, pair.public())
		}
	};
}

context_sign!(
	sign_ml_dsa_87,
	Dilithium87Pair,
	Dilithium87Signature,
	Dilithium87SignatureWithPublic,
	ml_dsa_87
);
context_sign!(
	sign_ml_dsa_65,
	Dilithium65Pair,
	Dilithium65Signature,
	Dilithium65SignatureWithPublic,
	ml_dsa_65
);

/// Whether `sig_with_public` signs `message` under [`EXTRINSIC`]. Cold wallets sign ML-DSA-87
/// only, so that is the only response the CLI checks.
pub fn verify_ml_dsa_87(sig_with_public: &Dilithium87SignatureWithPublic, message: &[u8]) -> bool {
	let Ok(public) = qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(
		sig_with_public.public().as_slice(),
	) else {
		return false;
	};
	public.verify(message, sig_with_public.signature().as_slice(), Some(EXTRINSIC))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn ml_dsa_87_signature_verifies_under_the_extrinsic_context() {
		let alice = qp_dilithium_crypto::crystal_alice();
		let signature = sign_ml_dsa_87(&alice, b"payload");
		assert!(verify_ml_dsa_87(&signature, b"payload"));
		assert!(!verify_ml_dsa_87(&signature, b"a different payload"));
	}

	#[test]
	fn ml_dsa_65_signature_verifies_under_the_extrinsic_context() {
		let pair = Dilithium65Pair::from_seed(&[7u8; 32]).expect("seed is well-formed");
		let signature = sign_ml_dsa_65(&pair, b"payload");
		let public = qp_rusty_crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(
			signature.public().as_slice(),
		)
		.expect("public key must parse");
		let sig = signature.signature();
		assert!(public.verify(b"payload", sig.as_slice(), Some(EXTRINSIC)));
		assert!(!public.verify(b"payload", sig.as_slice(), None));
	}

	/// The context is what the chain checks. A signature made the old way, with no context, is
	/// what a node rejects as "Transaction has a bad signature".
	#[test]
	fn an_empty_context_signature_is_not_a_valid_extrinsic_signature() {
		let alice = qp_dilithium_crypto::crystal_alice();
		let empty_context = <Dilithium87Pair as Pair>::sign(&alice, b"payload");
		assert!(!verify_ml_dsa_87(&empty_context, b"payload"));
		assert_ne!(
			empty_context.to_bytes(),
			sign_ml_dsa_87(&alice, b"payload").to_bytes(),
			"signing must not fall back to the empty context"
		);
	}
}
