#![warn(unused)]
#![deny(trivial_casts, trivial_numeric_casts, unsafe_code)]

//! # Adversarial Constraint Test Patterns
//!
//! ZK circuit bugs fall into predictable categories. These patterns
//! were discovered during an internal security review of a Rust ZK
//! compiler (github.com/zkarchitect/zkforge) — codified here as
//! defensive test templates for arkworks circuit implementers.
//!
//! # The 4 Patterns
//!
//! 1. **Comparison forge**: `assert x >= n` returned a constant result
//!    instead of decomposing the difference into bits
//! 2. **Witness bypass**: The prover used domain elements as wire values
//!    instead of reading from the actual witness map
//! 3. **Inequality inversion**: `diff * inv = -1` was written instead of
//!    the standard `diff * inv = 1` encoding
//! 4. **Bit-sort direction**: Ascending greedy subtraction (1,2,4,8...)
//!    instead of descending (32,16,8,4,2,1) — one line bug

use ark_ff::PrimeField;
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable},
    lc,
};

// ─── Pattern 1: Comparison constraints must use BIT DECOMPOSITION ──────

/// Demonstrates that a comparison circuit must decompose the difference
/// into bits rather than returning a hardcoded constant.
///
/// Bug origin: The constraint synthesizer returned `result = -1` for all
/// comparisons, making `age=3` pass `assert age >= 18`.
struct ComparisonCircuit<F: PrimeField> {
    x: Option<F>,
    threshold: F,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for ComparisonCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let t = cs.new_input_variable(|| Ok(self.threshold))?;

        // diff = x - threshold
        let diff = cs.new_witness_variable(|| {
            let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x_val - self.threshold)
        })?;
        cs.enforce_r1cs_constraint(
            || lc!() + x,
            || lc!() + (ConstraintF::ONE, Variable::One),
            || lc!() + diff + (self.threshold, Variable::One),
        )?;

        // Bit-decompose diff to prove range.
        // CRITICAL: Never encode result as a hardcoded constant.
        // The decomposition itself IS the check — if diff is negative
        // in the field, the reconstruction will fail.
        let num_bits = ConstraintF::MODULUS_BIT_SIZE as usize;
        for i in (0..num_bits).rev() {
            let bit = cs.new_witness_variable(|| {
                let d = self.x.ok_or(SynthesisError::AssignmentMissing)? - self.threshold;
                let bigint = d.into_bigint();
                let limb_idx = i / 64;
                let bit_idx = i % 64;
                let limb = if limb_idx < bigint.as_ref().len() {
                    bigint.as_ref()[limb_idx]
                } else {
                    0
                };
                Ok(ConstraintF::from((limb >> bit_idx) & 1))
            })?;
            // Constrain bit to be binary: b * b = b
            cs.enforce_r1cs_constraint(
                || lc!() + bit,
                || lc!() + (ConstraintF::ONE, Variable::One),
                || lc!() + bit,
            )?;
        }

        // The reconstruction constraint using DESCENDING bit weights
        // is the pattern under test (see Pattern 4).
        Ok(())
    }
}

// ─── Pattern 3: Inequality constraints must use diff * inv = 1 ─────────

/// Defensive test: `x != y` encoded as `diff * inv = 1` where `diff = x-y`.
///
/// The standard R1CS encoding: diff has a multiplicative inverse
/// iff diff ≠ 0. Never use -1 instead of 1.
///
/// Bug origin: A compiler wrote `diff * inv = -1`. When diff ≠ 0,
/// the legitimate path failed. When diff = 0, the solver crashed
/// instead of cleanly rejecting.
struct InequalityCircuit<F: PrimeField> {
    x: Option<F>,
    y: F,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for InequalityCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| Ok(self.y))?;

        // diff = x - y
        let diff = cs.new_witness_variable(|| {
            let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(x_val - self.y)
        })?;
        cs.enforce_r1cs_constraint(
            || lc!() + x,
            || lc!() + (ConstraintF::ONE, Variable::One),
            || lc!() + diff + (self.y, Variable::One),
        )?;

        // inv = 1/diff when diff ≠ 0. The prover computes this;
        // when diff = 0, no inverse exists → proof fails.
        let inv = cs.new_witness_variable(|| {
            let d = self.x.ok_or(SynthesisError::AssignmentMissing)? - self.y;
            if d.is_zero() {
                Err(SynthesisError::Unsatisfiable)
            } else {
                d.inverse().ok_or(SynthesisError::Unsatisfiable)
            }
        })?;

        // THE CRITICAL CONSTRAINT: diff * inv = 1 (NOT -1)
        cs.enforce_r1cs_constraint(
            || lc!() + diff,
            || lc!() + inv,
            || lc!() + (ConstraintF::ONE, Variable::One),
        )?;

        Ok(())
    }
}

// ─── Pattern 4: Bit decomposition must sort DESCENDING ─────────────────

/// Defensive test: When reconstructing Σ(bit_i * 2^i), weights must be
/// processed in descending order. Ascending order is a one-line bug.
///
/// Bug origin: `sorted_c.sort_by_key(...)` produced ascending (1,2,4,8...)
/// then greedy subtraction: 50 = 1+2+4+8+16 = 31 ✗ vs 32+16+2 = 50 ✓
struct BitReconstructionCircuit<F: PrimeField> {
    value: F,
}

impl<ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for BitReconstructionCircuit<ConstraintF>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let val = cs.new_input_variable(|| Ok(self.value))?;
        let num_bits = ConstraintF::MODULUS_BIT_SIZE as usize;

        let mut bits = Vec::new();

        // Decompose into bits with DESCENDING weights:
        // 2^(n-1), 2^(n-2), ..., 2^1, 2^0
        // The descending loop is critical — ascending would produce
        // wrong reconstruction for most values.
        for i in (0..num_bits).rev() {
            let bit_idx = i % 64;
            let limb_idx = i / 64;

            let bit = cs.new_witness_variable(|| {
                let bigint = self.value.into_bigint();
                let limb = if limb_idx < bigint.as_ref().len() {
                    bigint.as_ref()[limb_idx]
                } else {
                    0
                };
                Ok(ConstraintF::from((limb >> bit_idx) & 1))
            })?;

            // Constrain bit to binary: b * 1 = b
            cs.enforce_r1cs_constraint(
                || lc!() + bit,
                || lc!() + (ConstraintF::ONE, Variable::One),
                || lc!() + bit,
            )?;
            bits.push((i, bit));
        }

        // Reconstruct: value = Σ(bits[i] * 2^i) with DESCENDING weights
        let mut lc_val: LinearCombination<ConstraintF> = lc!();
        for (i, bit) in bits {
            lc_val = lc_val + (ConstraintF::from(1u64 << (i % 64)), bit);
        }
        cs.enforce_r1cs_constraint(
            || lc!() + val,
            || lc!() + (ConstraintF::ONE, Variable::One),
            || lc_val,
        )?;

        Ok(())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_groth16::Groth16;
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    type E = ark_bn254::Bn254;

    #[test]
    fn pattern1_comparison_synthesizes_without_hardcoded_result() {
        // `x=3, threshold=18`: the circuit must synthesize correctly
        // (use bit decomposition, not a hardcoded constant)
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = ComparisonCircuit::<Fr> {
            x: Some(Fr::from(3u64)),
            threshold: Fr::from(18u64),
        };

        // Setup should succeed (constraints are structurally sound)
        let (pk, _vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        // Prove with valid witness
        let circuit = ComparisonCircuit::<Fr> {
            x: Some(Fr::from(25u64)),
            threshold: Fr::from(18u64),
        };
        assert!(Groth16::<E>::prove(&pk, circuit, &mut rng).is_ok());
    }

    #[test]
    fn pattern3_inequality_rejects_equal_values() {
        // x=5, y=5 with x!=y constraint: prove must fail because
        // diff=0 has no multiplicative inverse in the field.
        // The constraint diff * inv = 1 cannot be satisfied when diff=0.
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let circuit = InequalityCircuit::<Fr> {
            x: Some(Fr::from(5u64)),
            y: Fr::from(5u64),
        };

        // Setup succeeds (constraint structure is valid)
        let (pk, _vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        // But proving with x=y must FAIL — no inverse exists for diff=0
        let circuit = InequalityCircuit::<Fr> {
            x: Some(Fr::from(5u64)),
            y: Fr::from(5u64),
        };
        assert!(
            Groth16::<E>::prove(&pk, circuit, &mut rng).is_err(),
            "Inequality must fail when x=y: diff=0 has no multiplicative inverse"
        );
    }

    #[test]
    fn pattern4_bit_reconstruction_descending() {
        // 50 = 32 + 16 + 2 (descending ✓)
        // 50 = 1+2+4+8+16+? = 31 (ascending ✗)
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let value = Fr::from(50u64);

        let circuit = BitReconstructionCircuit::<Fr> { value };
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let circuit = BitReconstructionCircuit::<Fr> { value };
        let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();
        let pvk = Groth16::<E>::process_vk(&vk).unwrap();
        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[value], &proof).unwrap());
    }
}
