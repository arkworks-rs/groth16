use ark_crypto_primitives::sponge::Absorb;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_serialize::*;
use ark_std::vec::Vec;

/// A proof in the Groth16 SNARK.
///
/// A Groth16 proof consists of three group elements `(A, B, C)` that satisfy
/// a specific pairing equation when combined with the verification key and
/// public inputs. The proof is succinct — its size is constant regardless of
/// the size of the statement being proved.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// The `A` element in `G1`.
    pub a: E::G1Affine,
    /// The `B` element in `G2`.
    pub b: E::G2Affine,
    /// The `C` element in `G1`.
    pub c: E::G1Affine,
}

impl<E: Pairing> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// A verification key in the Groth16 SNARK.
///
/// The verification key is generated during the trusted setup phase and is used
/// to verify proofs. It contains the minimal set of group elements needed to
/// check the pairing equation that a valid proof must satisfy.
///
/// For faster repeated verification, convert this into a
/// [`PreparedVerifyingKey`] via [`prepare_verifying_key`](crate::prepare_verifying_key),
/// which precomputes the pairing inputs.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// The element `alpha * G`, where `G` is the generator of `E::G1`.
    pub alpha_g1: E::G1Affine,
    /// The element `beta * H`, where `H` is the generator of `E::G2`.
    pub beta_g2: E::G2Affine,
    /// The element `gamma * H`, where `H` is the generator of `E::G2`.
    pub gamma_g2: E::G2Affine,
    /// The element `delta * H`, where `H` is the generator of `E::G2`.
    pub delta_g2: E::G2Affine,
    /// The elements used for verifying public inputs.
    ///
    /// Specifically, the `i`-th element is
    /// `gamma^{-1} * (beta * a_i + alpha * b_i + c_i) * G`,
    /// where `G` is the generator of `E::G1`, and `a_i`, `b_i`, `c_i` are the
    /// QAP polynomials evaluated at the toxic waste point `t`.
    ///
    /// The length of this vector is `num_instance_variables + 1` (including
    /// the constant term `1`).
    pub gamma_abc_g1: Vec<E::G1Affine>,
}

impl<E: Pairing> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            alpha_g1: E::G1Affine::default(),
            beta_g2: E::G2Affine::default(),
            gamma_g2: E::G2Affine::default(),
            delta_g2: E::G2Affine::default(),
            gamma_abc_g1: Vec::new(),
        }
    }
}

impl<E> Absorb for VerifyingKey<E>
where
    E: Pairing,
    E::G1Affine: Absorb,
    E::G2Affine: Absorb,
{
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        self.alpha_g1.to_sponge_bytes(dest);
        self.beta_g2.to_sponge_bytes(dest);
        self.gamma_g2.to_sponge_bytes(dest);
        self.delta_g2.to_sponge_bytes(dest);
        self.gamma_abc_g1
            .iter()
            .for_each(|g| g.to_sponge_bytes(dest));
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.alpha_g1.to_sponge_field_elements(dest);
        self.beta_g2.to_sponge_field_elements(dest);
        self.gamma_g2.to_sponge_field_elements(dest);
        self.delta_g2.to_sponge_field_elements(dest);
        self.gamma_abc_g1
            .iter()
            .for_each(|g| g.to_sponge_field_elements(dest));
    }
}

/// Preprocessed verification key parameters that enable faster verification
/// at the expense of larger size in memory.
///
/// This struct precomputes certain pairing inputs from the [`VerifyingKey`] so
/// that each call to [`Groth16::verify_proof`](crate::Groth16::verify_proof)
/// requires fewer pairing operations. Use this when the same verification key
/// is reused across multiple proof verifications.
///
/// Construct via [`prepare_verifying_key`](crate::prepare_verifying_key) or
/// via the `From<VerifyingKey<E>>` implementation.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
    /// The precomputed pairing `e(alpha * G, beta * H)` in `E::GT`.
    ///
    /// This is the target value that a valid proof's pairing equation must equal.
    pub alpha_g1_beta_g2: E::TargetField,
    /// The element `- gamma * H` in `E::G2`, prepared for use in pairings.
    ///
    /// Negated so it can be directly used in the multi-Miller loop during verification.
    pub gamma_g2_neg_pc: E::G2Prepared,
    /// The element `- delta * H` in `E::G2`, prepared for use in pairings.
    ///
    /// Negated so it can be directly used in the multi-Miller loop during verification.
    pub delta_g2_neg_pc: E::G2Prepared,
}

impl<E: Pairing> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: Pairing> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        crate::prepare_verifying_key(&other)
    }
}

impl<E: Pairing> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            alpha_g1_beta_g2: E::TargetField::default(),
            gamma_g2_neg_pc: E::G2Prepared::default(),
            delta_g2_neg_pc: E::G2Prepared::default(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////

/// The prover key for the Groth16 zkSNARK.
///
/// Generated during the trusted setup phase, this key contains all the
/// precomputed group elements needed to create a proof. It includes the
/// verification key as a subfield, so a separate [`VerifyingKey`] can be
/// extracted from it via `pk.vk.clone()`.
///
/// # Size
///
/// The proving key is significantly larger than the verification key. Its size
/// is proportional to the number of variables and constraints in the R1CS instance.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// The element `beta * G` in `E::G1`.
    pub beta_g1: E::G1Affine,
    /// The element `delta * G` in `E::G1`.
    pub delta_g1: E::G1Affine,
    /// The A-query: elements `a_i(t) * G` in `E::G1` for each QAP variable.
    ///
    /// Used by the prover to compute the `A` component of the proof via a
    /// multi-scalar multiplication with the full variable assignment.
    pub a_query: Vec<E::G1Affine>,
    /// The B-query in G1: elements `b_i(t) * G` in `E::G1` for each QAP
    /// variable.
    ///
    /// Used by the prover to compute part of the `C` component of the proof
    /// when the randomness `r` is non-zero.
    pub b_g1_query: Vec<E::G1Affine>,
    /// The B-query in G2: elements `b_i(t) * H` in `E::G2` for each QAP
    /// variable.
    ///
    /// Used by the prover to compute the `B` component of the proof.
    pub b_g2_query: Vec<E::G2Affine>,
    /// The H-query: elements encoding `t^i * z(t) / delta` in `E::G1`.
    ///
    /// Used by the prover to encode the quotient polynomial `h(x) = (A*B -
    /// C)/Z` in the proof's `C` component.
    pub h_query: Vec<E::G1Affine>,
    /// The L-query: elements encoding the witness-related QAP polynomials
    /// divided by `delta` in `E::G1`.
    ///
    /// Used by the prover to incorporate the witness assignment into the `C`
    /// component of the proof.
    pub l_query: Vec<E::G1Affine>,
}