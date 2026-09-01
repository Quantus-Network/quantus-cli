//! FIPS 204 context binding for Quantus extrinsic signatures.
//!
//! Runtimes from spec 148 on sign and verify extrinsics under [`EXTRINSIC`]. `sp_core::Pair::sign`
//! in the published `qp-dilithium-crypto` still passes no context, and those runtimes reject what
//! it produces as "Transaction has a bad signature". Every extrinsic signature the CLI makes or
//! checks goes through this module instead.
//!
//! FIPS 204 contexts are domain separated, so the context is not a free upgrade: signing under
//! [`EXTRINSIC`] for a pre-148 runtime is rejected just as surely. [`context_for_runtime`] picks
//! the one the connected runtime actually verifies with.

use qp_dilithium_crypto::types::{
	Dilithium65Pair, Dilithium65Signature, Dilithium65SignatureWithPublic, Dilithium87Pair,
	Dilithium87Signature, Dilithium87SignatureWithPublic,
};
use sp_core::{ByteArray, Pair};

/// The FIPS 204 context runtimes from spec 148 bind extrinsic signatures to. Mirrors
/// `qp_dilithium_crypto::signing_context::EXTRINSIC` in the chain.
pub const EXTRINSIC: &[u8] = b"QUANTUS_EXTRINSIC";

/// The context a given runtime verifies extrinsic signatures under. `None` for the pre-148
/// runtimes, which verify with no context at all.
pub fn context_for_runtime(spec_version: u32, transaction_version: u32) -> Option<&'static [u8]> {
	crate::config::runtime_binds_signing_context(spec_version, transaction_version)
		.then_some(EXTRINSIC)
}

macro_rules! context_sign {
	($sign:ident, $pair:ty, $signature:ty, $sig_with_public:ty, $module:ident) => {
		/// Sign `message` under `context`, the way the connected runtime expects.
		pub fn $sign(pair: &$pair, message: &[u8], context: Option<&[u8]>) -> $sig_with_public {
			let secret =
				qp_rusty_crystals_dilithium::$module::SecretKey::from_bytes(pair.secret_bytes())
					.expect("wallet secret key must parse");
			let signature =
				secret.sign(message, context, None).expect("the context is well-formed");
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

/// Whether `sig_with_public` signs `message` under `context`. Cold wallets sign ML-DSA-87 only,
/// so that is the only response the CLI checks.
pub fn verify_ml_dsa_87(
	sig_with_public: &Dilithium87SignatureWithPublic,
	message: &[u8],
	context: Option<&[u8]>,
) -> bool {
	let Ok(public) = qp_rusty_crystals_dilithium::ml_dsa_87::PublicKey::from_bytes(
		sig_with_public.public().as_slice(),
	) else {
		return false;
	};
	public.verify(message, sig_with_public.signature().as_slice(), context)
}

#[cfg(test)]
mod tests {
	use super::*;

	const CTX: Option<&[u8]> = Some(EXTRINSIC);

	#[test]
	fn ml_dsa_87_signature_verifies_under_the_context_it_was_made_with() {
		let alice = qp_dilithium_crypto::crystal_alice();
		let signature = sign_ml_dsa_87(&alice, b"payload", CTX);
		assert!(verify_ml_dsa_87(&signature, b"payload", CTX));
		assert!(!verify_ml_dsa_87(&signature, b"a different payload", CTX));
	}

	#[test]
	fn ml_dsa_65_signature_verifies_under_the_context_it_was_made_with() {
		let pair = Dilithium65Pair::from_seed(&[7u8; 32]).expect("seed is well-formed");
		let signature = sign_ml_dsa_65(&pair, b"payload", CTX);
		let public = qp_rusty_crystals_dilithium::ml_dsa_65::PublicKey::from_bytes(
			signature.public().as_slice(),
		)
		.expect("public key must parse");
		let sig = signature.signature();
		assert!(public.verify(b"payload", sig.as_slice(), CTX));
		assert!(!public.verify(b"payload", sig.as_slice(), None));
	}

	/// FIPS 204 contexts are domain separated, so this cuts both ways: a spec-148 node rejects a
	/// contextless signature, and a pre-148 node rejects a contextful one. Either mismatch is the
	/// "Transaction has a bad signature" pool rejection.
	#[test]
	fn a_signature_does_not_verify_under_the_other_context() {
		let alice = qp_dilithium_crypto::crystal_alice();
		let with_context = sign_ml_dsa_87(&alice, b"payload", CTX);
		let without_context = sign_ml_dsa_87(&alice, b"payload", None);

		assert!(!verify_ml_dsa_87(&with_context, b"payload", None));
		assert!(!verify_ml_dsa_87(&without_context, b"payload", CTX));
		assert_ne!(with_context.to_bytes(), without_context.to_bytes());
	}

	/// The pre-148 runtimes verify with no context at all, so the CLI must keep signing for them
	/// the old way. `sp_core::Pair::sign` in the published `qp-dilithium-crypto` is that old way.
	#[test]
	fn pre_148_runtimes_get_the_contextless_signature_pair_sign_makes() {
		let alice = qp_dilithium_crypto::crystal_alice();
		assert_eq!(
			sign_ml_dsa_87(&alice, b"payload", None).to_bytes(),
			<Dilithium87Pair as Pair>::sign(&alice, b"payload").to_bytes()
		);
	}

	#[test]
	fn the_context_follows_the_runtime() {
		assert_eq!(context_for_runtime(147, 6), None, "spec 147 verifies with no context");
		assert_eq!(context_for_runtime(145, 4), None, "spec 145 verifies with no context");
		assert_eq!(context_for_runtime(134, 2), None, "the oldest listed pair predates it too");
		assert_eq!(context_for_runtime(148, 6), Some(EXTRINSIC), "spec 148 introduced it");
		assert_eq!(
			context_for_runtime(149, 7),
			Some(EXTRINSIC),
			"newer unlisted runtimes are assumed to keep it"
		);
	}

	/// A signature made for the runtime the CLI is talking to verifies for that runtime, whichever
	/// side of the spec-148 boundary it sits on.
	#[test]
	fn signing_for_a_runtime_verifies_for_that_runtime() {
		let alice = qp_dilithium_crypto::crystal_alice();
		for (spec, tx) in [(147u32, 6u32), (148, 6)] {
			let context = context_for_runtime(spec, tx);
			let signature = sign_ml_dsa_87(&alice, b"payload", context);
			assert!(
				verify_ml_dsa_87(&signature, b"payload", context),
				"spec {spec} signature must verify under its own context"
			);
			let other = context_for_runtime(if spec == 148 { 147 } else { 148 }, tx);
			assert!(
				!verify_ml_dsa_87(&signature, b"payload", other),
				"spec {spec} signature must not verify across the boundary"
			);
		}
	}
}
