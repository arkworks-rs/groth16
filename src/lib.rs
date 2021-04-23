//! An implementation of the [`Groth16`] zkSNARK.
//!
//! [`Groth16`]: https://eprint.iacr.org/2016/260.pdf
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

#[cfg(feature = "r1cs")]
#[macro_use]
extern crate derivative;

/// Reduce an R1CS instance to a *Quadratic Arithmetic Program* instance.
pub(crate) mod r1cs_to_qap;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Groth16 zkSNARK construction.
pub mod generator;

/// Create proofs for the Groth16 zkSNARK construction.
pub mod prover;

/// Verify proofs for the Groth16 zkSNARK construction.
pub mod verifier;

/// Constraints for the Groth16 verifier.
#[cfg(feature = "r1cs")]
pub mod constraints;

#[cfg(test)]
mod test;

pub use self::data_structures::*;
pub use self::{generator::*, prover::*, verifier::*};

use ark_crypto_primitives::snark::*;
use ark_ec::PairingEngine;
use ark_snark::{SNARK, r1cs::SNARKForR1CS};
use ark_relations::r1cs::{
    R1CS, ConstraintSystem, ConstraintGenerator, InstanceGenerator, WitnessGenerator, SynthesisError, ConstraintMatrices,
    OptimizationGoal, Instance, Witness, SynthesisMode};
use ark_std::rand::{RngCore, CryptoRng};
use ark_std::{marker::PhantomData, vec::Vec};

/// The SNARK of [[Groth16]](https://eprint.iacr.org/2016/260.pdf).
pub struct Groth16<E: PairingEngine> {
    e_phantom: PhantomData<E>,
}

impl<E: PairingEngine> SNARK<R1CS<E::Fr>> for Groth16<E> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    /// Generates a proof of satisfaction of the arithmetic circuit C (specified
    /// as R1CS constraints).
    fn prove<Rng: RngCore + CryptoRng>(
        pk: &Self::ProvingKey,
        index: &Option<ConstraintMatrices<E::Fr>>,
        instance: &Instance<E::Fr>,
        witness: &Witness<E::Fr>,
        rng: &mut Rng,
    ) -> Result<Self::Proof, Self::Error> {
        create_random_proof(pk, index.as_ref().unwrap(), instance, witness, rng)
    }


    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &Instance<E::Fr>,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(verify_proof(&circuit_pvk, proof, &x.0)?)
    }
}

impl<E: PairingEngine> CircuitSpecificSetupSNARK<R1CS<E::Fr>> for Groth16<E> {
    fn circuit_specific_setup<R: RngCore + CryptoRng>(
        matrices: &ConstraintMatrices<E::Fr>,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = generate_random_parameters::<E, R>(matrices, rng)?;
        let vk = pk.vk.clone();

        Ok((pk, vk))
    }
}

impl<E: PairingEngine> SNARKForR1CS<E::Fr> for Groth16<E> {
    const PROVING_REQUIRES_MATRICES: bool = true;

    fn indexer_inputs<CG: ConstraintGenerator<E::Fr>>(circuit: &CG) -> Result<ConstraintMatrices<E::Fr>, Self::Error> {
        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.make_constraints(cs.clone())?;
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.optimize();
        end_timer!(lc_time);
        Ok(cs.to_matrices().expect("matrices should exist in setup mode"))
    }

    /// Generate inputs for the SNARK prover from [`cs`].
    /// These inputs consist of the instance and witness. Additionally,
    /// if `Self::PROVING_REQUIRES_MATRICES == true`, then this method returns 
    /// `Some(index)` as well.
    fn prover_inputs<WG: WitnessGenerator<E::Fr>>(circuit: &WG) -> Result<(Option<ConstraintMatrices<E::Fr>>, Instance<E::Fr>, Witness<E::Fr>), Self::Error> {
        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Prove { construct_matrices: true });
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.make_witness(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.optimize();
        end_timer!(lc_time);
        let matrices = cs.to_matrices();
        let instance = cs.instance_assignment();
        let witness = cs.witness_assignment();
        Ok((matrices, instance.unwrap(), witness.unwrap()))
    }

    /// Generate inputs for the SNARK verifier from [`cs`].
    /// This input consists of the instance.
    fn verifier_inputs<IG: InstanceGenerator<E::Fr>>(circuit: &IG) -> Result<Instance<E::Fr>, Self::Error> {
        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Verify);
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.make_instance(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.optimize();
        end_timer!(lc_time);
        cs.instance_assignment().ok_or(SynthesisError::AssignmentMissing)
    }
}
