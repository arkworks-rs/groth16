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
    missing_docs,
)]
#![allow(clippy::many_single_char_names)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate bench_utils;

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

#[cfg(test)]
mod test;

use ark_std::vec::Vec;

pub use self::{generator::*, prover::*, verifier::*};
pub use self::data_structures::*;
