//! An implementation of the [`Groth16`] zkSNARK.
//!
//! Groth16 is a preprocessing zkSNARK with the shortest proof size (3 group
//! elements) and fastest verification (a single pairing equation check) among
//! known pairing-based zkSNARKs. It requires a per-circuit trusted setup.
//!
//! # Overview
//!
//! The Groth16 proving system has three phases:
//!
//! 1. **Setup** ([`generator`]): A one-time trusted setup that produces a
//!    [`ProvingKey`] and a [`VerifyingKey`] for a given circuit. The toxic
//!    waste generated during setup must be securely discarded.
//!
//! 2. **Proving** ([`prover`]): Given a [`ProvingKey`] and a satisfied circuit
//!    (with both public inputs and private witness), produce a [`Proof`].
//!
//! 3. **Verification** ([`verifier`]): Given a [`VerifyingKey`] (or
//!    [`PreparedVerifyingKey`]), public inputs, and a [`Proof`], check whether
//!    the proof is valid.
//!
//! # Quick start
//!
//! ```ignore
//! use ark_groth16::Groth16;
//! use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
//! use ark_bls12_381::Bls12_381;
//!
//! // 1. Setup
//! let (pk, vk) = Groth16::<Bls12_381>::setup(circuit_for_setup, &mut rng)?;
//!
//! // 2. Prove
//! let proof = Groth16::<Bls12_381>::prove(&pk, circuit_with_witness, &mut rng)?;
//!
//! // 3. Verify
//! let valid = Groth16::<Bls12_381>::verify(&vk, &public_inputs, &proof)?;
//! ```
//!
//! # QAP reductions
//!
//! Groth16 operates over Quadratic Arithmetic Programs (QAPs), not R1CS
//! directly. The [`r1cs_to_qap`] module defines the [`R1CSToQAP`] trait,
//! which abstracts the reduction. The default is [`LibsnarkReduction`], but
//! custom reductions can be plugged in by specifying the second type parameter
//! of [`Groth16`].
//!
//! # Features
//!
//! - **`std`** (default via `parallel`): Enables standard library support.
//! - **`parallel`** (default): Enables parallel computation via Rayon.
//! - **`r1cs`**: Enables the [`constraints`] module for recursive proof
//!   verification inside a circuit.
//! - **`print-trace`**: Enables detailed timing traces during setup and
//!   proving.
//!
//! # References
//!
//! - [\[Groth16\]](https://eprint.iacr.org/2016/260.pdf): On the Size of
//!   Pairing-based Non-interactive Arguments.
//! - [\[BKSV20\]](https://eprint.iacr.org/2020/811): On the (In)security of
//!   SNARKs in the Presence of Oracles (proof rerandomization).
//!
//! [`R1CSToQAP`]: r1cs_to_qap::R1CSToQAP
//! [`LibsnarkReduction`]: r1cs_to_qap::LibsnarkReduction
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// Constraints for the Groth16 verifier.
///
/// This module provides R1CS gadgets for verifying a Groth16 proof inside
/// another SNARK circuit, enabling recursive proof composition.
#[cfg(feature = "r1cs")]
pub mod constraints;

#[cfg(test)]
mod test;

pub use self::{data_structures::*, verifier::*};

use ark_ec::pairing::Pairing;
use ark_relations::gr1cs::{ConstraintSynthesizer, SynthesisError};
use ark_snark::*;
use ark_std::{marker::PhantomData, rand::RngCore, vec::Vec};
use r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
///
/// This struct is parameterized by:
/// - `E`: A pairing-friendly elliptic curve (e.g., `Bls12_381`, `BN254`).
/// - `QAP`: The R1CS-to-QAP reduction to use. Defaults to
///   [`LibsnarkReduction`].
pub struct Groth16<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}

impl<E: Pairing, QAP: R1CSToQAP> SNARK<E::ScalarField> for Groth16<E, QAP> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
        R: RngCore,
    {
        let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_random_proof_with_reduction(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &[E::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(Self::verify_proof(&circuit_pvk, proof, &x)?)
    }
}

impl<E: Pairing, QAP: R1CSToQAP> CircuitSpecificSetupSNARK<E::ScalarField> for Groth16<E, QAP> {}