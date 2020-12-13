use super::{PreparedVerifyingKey, Proof, VerifyingKey};
use ark_ec::PairingEngine;

use ark_relations::r1cs::{Result as R1CSResult, SynthesisError};
use ark_std::ops::Neg;

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: PairingEngine>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey {
        vk: vk.clone(),
        alpha_g1_beta_g2: E::pairing(vk.alpha_g1, vk.beta_g2),
        gamma_g2_neg_pc: vk.gamma_g2.neg().into(),
        delta_g2_neg_pc: vk.delta_g2.neg().into(),
    }
}

/// Verify a Groth16 proof `proof` against the prepared verification key `pvk`,
/// with respect to the instance `public_inputs`.
pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
) -> R1CSResult<bool> {
    let qap = E::miller_loop(
        [
            (proof.a.into(), proof.b.into()),
            (proof.d.into(), pvk.gamma_g2_neg_pc.clone()),
            (proof.c.into(), pvk.delta_g2_neg_pc.clone()),
        ]
        .iter(),
    );

    let test = E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == pvk.alpha_g1_beta_g2)
}
