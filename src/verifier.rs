use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::PrimeField;

use crate::{r1cs_to_qap::R1CSToQAP, Groth16};

use super::{PreparedVerifyingKey, Proof, VerifyingKey};

use ark_relations::gr1cs::Result as R1CSResult;

use core::ops::{AddAssign, Neg};

/// Prepare the verifying key `vk` for use in proof verification.
///
/// Preprocessing the verification key precomputes the following:
/// - The pairing `e(alpha_g1, beta_g2)` — the target value for valid proofs.
/// - Negated and prepared versions of `gamma_g2` and `delta_g2` — so the
///   multi-Miller loop can be computed in a single pass.
///
/// This is a one-time cost that amortizes over multiple verifications with the
/// same key.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2).0,
        gamma_g2_neg_pc: vk.gamma_g2.into_group().neg().into_affine().into(),
        delta_g2_neg_pc: vk.delta_g2.into_group().neg().into_affine().into(),
    }
}

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Compute the prepared public inputs for use with
    /// [`verify_proof_with_prepared_inputs`](Self::verify_proof_with_prepared_inputs).
    ///
    /// This computes the linear combination:
    ///
    /// ```text
    /// g_ic = gamma_abc_g1[0] + sum_{i=1}^{l} public_inputs[i-1] * gamma_abc_g1[i]
    /// ```
    ///
    /// where `l` is the number of public inputs. Precomputing this is useful
    /// when the same public inputs are verified against multiple proofs.
    ///
    /// # Arguments
    ///
    /// * `pvk` - The prepared verification key.
    /// * `public_inputs` - The public input values (excluding the leading
    ///   constant `1`).
    pub fn prepare_inputs(
        pvk: &PreparedVerifyingKey<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<E::G1> {
        let mut g_ic = pvk.vk.gamma_abc_g1[0].into_group();
        for (i, b) in public_inputs.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
            g_ic.add_assign(&b.mul_bigint(i.into_bigint()));
        }

        Ok(g_ic)
    }

    /// Verify a Groth16 proof against a prepared verification key and
    /// precomputed public inputs.
    ///
    /// This is the most efficient verification path when both the verification
    /// key and the public inputs have been preprocessed. It performs a
    /// 3-pairing multi-Miller loop followed by a final exponentiation, then
    /// checks:
    ///
    /// ```text
    /// e(A, B) = e(alpha, beta) · e(g_ic, -gamma) · e(C, -delta)
    /// ```
    ///
    /// (where `g_ic` encodes the public inputs).
    ///
    /// # Arguments
    ///
    /// * `pvk` - The prepared verification key.
    /// * `proof` - The proof to verify.
    /// * `prepared_inputs` - The precomputed public-input accumulator from
    ///   [`prepare_inputs`](Self::prepare_inputs).
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, `Ok(false)` otherwise.
    pub fn verify_proof_with_prepared_inputs(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        prepared_inputs: &E::G1,
    ) -> R1CSResult<bool> {
        let qap = E::multi_miller_loop(
            [
                <E::G1Affine as Into<E::G1Prepared>>::into(proof.a),
                prepared_inputs.into_affine().into(),
                proof.c.into(),
            ],
            [
                proof.b.into(),
                pvk.gamma_g2_neg_pc.clone(),
                pvk.delta_g2_neg_pc.clone(),
            ],
        );

        let test = E::final_exponentiation(qap).unwrap();

        Ok(test.0 == pvk.alpha_g1_beta_g2)
    }

    /// Verify a Groth16 proof against a prepared verification key and
    /// raw public inputs.
    ///
    /// This is the standard verification entry point. It first computes the
    /// public-input accumulator via [`prepare_inputs`](Self::prepare_inputs),
    /// then delegates to
    /// [`verify_proof_with_prepared_inputs`](Self::verify_proof_with_prepared_inputs).
    ///
    /// # Arguments
    ///
    /// * `pvk` - The prepared verification key.
    /// * `proof` - The proof to verify.
    /// * `public_inputs` - The public input values (excluding the leading
    ///   constant `1`).
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the proof is valid, `Ok(false)` otherwise.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> R1CSResult<bool> {
        let prepared_inputs = Self::prepare_inputs(pvk, public_inputs)?;
        Self::verify_proof_with_prepared_inputs(pvk, proof, &prepared_inputs)
    }
}