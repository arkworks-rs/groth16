//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(
    warnings,
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate bench_utils;

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub(crate) mod r1cs_to_qap;

/// Padding the R1CS instance to enable an *Augmented Quadratic Arithmetic Program* instance.
pub(crate) mod augmented_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

#[cfg(test)]
mod test;

pub use self::data_structures::*;
pub use self::{generator::*, prover::*, verifier::*};

use ark_ec::PairingEngine;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::{marker::PhantomData, vec::Vec};
use rand::RngCore;

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<E: PairingEngine> {
    e_phantom: PhantomData<E>,
}

/// Define the randomness used in commitments.
pub type CommitRandomness<F> = Option<F>;

impl<E: PairingEngine> Groth16<E> {
    /// Do a circuit-specific setup
    pub fn circuit_specific_setup<C: ConstraintSynthesizer<E::Fr>, R: RngCore>(
        circuit: C,
        hiding: bool,
        rng: &mut R,
    ) -> Result<(ProvingKey<E>, VerifyingKey<E>), SynthesisError> {
        let pk = generate_random_parameters::<E, C, R>(circuit, hiding, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    /// Compute a proof
    pub fn prove<C: ConstraintSynthesizer<E::Fr>, R: RngCore>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
    ) -> Result<(Proof<E>, CommitRandomness<E::Fr>), SynthesisError> {
        create_random_proof::<E, _, _>(circuit, pk, rng)
    }

    /// Process the verifying key
    pub fn process_vk(
        circuit_vk: &VerifyingKey<E>,
    ) -> Result<PreparedVerifyingKey<E>, SynthesisError> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    /// Verify the proof with a processed verifying key
    pub fn verify_with_processed_vk(
        circuit_pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
    ) -> Result<bool, SynthesisError> {
        Ok(verify_proof(&circuit_pvk, proof)?)
    }

    /// Verify the proof with a verifying key
    pub fn verify(circuit_vk: &VerifyingKey<E>, proof: &Proof<E>) -> Result<bool, SynthesisError> {
        let pvk = Self::process_vk(circuit_vk)?;
        Ok(Self::verify_with_processed_vk(&pvk, proof)?)
    }
}
