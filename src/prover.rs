use crate::{r1cs_to_qap::R1CSToQAP, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::{
    gr1cs::{
        ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult,
        SynthesisMode,
    },
    utils::matrix::Matrix,
};
use ark_std::{
    cfg_into_iter, cfg_iter,
    ops::{AddAssign, Mul},
    rand::Rng,
    vec::Vec,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

type D<F> = GeneralEvaluationDomain<F>;

impl<E: Pairing, QAP: R1CSToQAP> Groth16<E, QAP> {
    /// Create a Groth16 proof using randomness `r` and `s` and
    /// the provided R1CS-to-QAP reduction, using the provided
    /// R1CS constraint matrices.
    ///
    /// This is the lowest-level proving interface: it takes pre-extracted
    /// matrices and the full variable assignment directly, bypassing
    /// constraint synthesis. Use this when you already have the R1CS matrices
    /// and assignments available (e.g., from a previous synthesis step).
    ///
    /// For most use cases, prefer
    /// [`create_random_proof_with_reduction`](Self::create_random_proof_with_reduction)
    /// which handles constraint synthesis and random blinding factor
    /// generation automatically.
    ///
    /// # Arguments
    ///
    /// * `pk` - The proving key from the trusted setup.
    /// * `r`, `s` - Blinding factors for zero-knowledge. Set both to zero for
    ///   a non-zero-knowledge proof.
    /// * `matrices` - The R1CS constraint matrices `[A, B, C]`.
    /// * `num_inputs` - Number of public input variables (including the
    ///   constant `1`).
    /// * `num_constraints` - Number of R1CS constraints.
    /// * `full_assignment` - The complete variable assignment: instance
    ///   (public) variables followed by witness (private) variables.
    #[inline]
    pub fn create_proof_with_reduction_and_matrices(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        matrices: &[Matrix<E::ScalarField>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map_from_matrices::<E::ScalarField, D<E::ScalarField>>(
            matrices,
            num_inputs,
            num_constraints,
            full_assignment,
        )?;
        end_timer!(witness_map_time);
        let input_assignment = &full_assignment[1..num_inputs];
        let aux_assignment = &full_assignment[num_inputs..];
        let proof =
            Self::create_proof_with_assignment(pk, r, s, &h, input_assignment, aux_assignment)?;
        end_timer!(prover_time);

        Ok(proof)
    }

    /// Assembles a Groth16 proof from the QAP witness polynomial `h` and
    /// the split variable assignments.
    ///
    /// This is the core proof construction routine. It computes the three
    /// proof elements `(A, B, C)` using multi-scalar multiplications
    /// against the proving key queries:
    ///
    /// - `A = alpha + sum(a_i * u_i) + r * delta`
    /// - `B = beta  + sum(a_i * v_i) + s * delta`
    /// - `C = sum(a_i * w_i)/delta + h(t)*z(t)/delta + s*A + r*B - r*s*delta`
    ///
    /// where `a_i` is the full assignment and `u_i, v_i, w_i` are the QAP
    /// polynomials encoded in the proving key.
    ///
    /// # Arguments
    ///
    /// * `pk` - The proving key.
    /// * `r`, `s` - Blinding factors for zero-knowledge.
    /// * `h` - Coefficients of the quotient polynomial `h(x)`.
    /// * `input_assignment` - Public input values (excluding the leading `1`).
    /// * `aux_assignment` - Witness (private) variable values.
    #[inline]
    fn create_proof_with_assignment(
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        h: &[E::ScalarField],
        input_assignment: &[E::ScalarField],
        aux_assignment: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        let c_acc_time = start_timer!(|| "Compute C");
        let h_assignment = cfg_into_iter!(h)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();
        let h_acc = E::G1::msm_bigint(&pk.h_query, &h_assignment);
        drop(h_assignment);

        // Compute C
        let aux_assignment = cfg_iter!(aux_assignment)
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        let l_aux_acc = E::G1::msm_bigint(&pk.l_query, &aux_assignment);

        let r_s_delta_g1 = pk.delta_g1 * (r * s);

        end_timer!(c_acc_time);

        let input_assignment = input_assignment
            .iter()
            .map(|s| s.into_bigint())
            .collect::<Vec<_>>();

        let assignment = [&input_assignment[..], &aux_assignment[..]].concat();
        drop(aux_assignment);

        // Compute A
        let a_acc_time = start_timer!(|| "Compute A");
        let r_g1 = pk.delta_g1.mul(r);

        let g_a = Self::calculate_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);

        let s_g_a = g_a * &s;
        end_timer!(a_acc_time);

        // Compute B in G1 if needed
        let g1_b = if !r.is_zero() {
            let b_g1_acc_time = start_timer!(|| "Compute B in G1");
            let s_g1 = pk.delta_g1.mul(s);
            let g1_b = Self::calculate_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);

            end_timer!(b_g1_acc_time);

            g1_b
        } else {
            E::G1::zero()
        };

        // Compute B in G2
        let b_g2_acc_time = start_timer!(|| "Compute B in G2");
        let s_g2 = pk.vk.delta_g2.mul(s);
        let g2_b = Self::calculate_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
        let r_g1_b = g1_b * &r;
        drop(assignment);

        end_timer!(b_g2_acc_time);

        let c_time = start_timer!(|| "Finish C");
        let mut g_c = s_g_a;
        g_c += &r_g1_b;
        g_c -= &r_s_delta_g1;
        g_c += &l_aux_acc;
        g_c += &h_acc;
        end_timer!(c_time);

        Ok(Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        })
    }

    /// Create a Groth16 proof that is zero-knowledge using the provided
    /// R1CS-to-QAP reduction.
    ///
    /// This is the recommended high-level proving interface. It synthesizes
    /// the circuit, computes the QAP witness, and constructs the proof using
    /// freshly sampled blinding factors `r` and `s` for zero-knowledge.
    ///
    /// # Arguments
    ///
    /// * `circuit` - The circuit (constraint synthesizer) encoding the
    ///   statement and witness.
    /// * `pk` - The proving key from the trusted setup.
    /// * `rng` - A random number generator for sampling blinding factors.
    #[inline]
    pub fn create_random_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut impl Rng,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        let r = E::ScalarField::rand(rng);
        let s = E::ScalarField::rand(rng);

        Self::create_proof_with_reduction(circuit, pk, r, s)
    }

    /// Create a Groth16 proof that is *not* zero-knowledge with the provided
    /// R1CS-to-QAP reduction.
    ///
    /// **Warning:** The resulting proof reveals information about the witness.
    /// Use [`create_random_proof_with_reduction`](Self::create_random_proof_with_reduction)
    /// for zero-knowledge proofs in production.
    ///
    /// This sets the blinding factors `r` and `s` to zero, which removes the
    /// zero-knowledge property but may be useful for testing or in contexts
    /// where privacy is not required.
    #[inline]
    pub fn create_proof_with_reduction_no_zk<C>(
        circuit: C,
        pk: &ProvingKey<E>,
    ) -> R1CSResult<Proof<E>>
    where
        C: ConstraintSynthesizer<E::ScalarField>,
    {
        Self::create_proof_with_reduction(
            circuit,
            pk,
            E::ScalarField::zero(),
            E::ScalarField::zero(),
        )
    }

    /// Create a Groth16 proof using the specified blinding factors `r` and `s`
    /// and the provided R1CS-to-QAP reduction.
    ///
    /// This method performs the full proving pipeline:
    /// 1. Synthesizes the circuit into an R1CS constraint system.
    /// 2. Converts the R1CS witness to a QAP witness via the `QAP` reduction.
    /// 3. Assembles the proof using
    ///    [`create_proof_with_assignment`](Self::create_proof_with_assignment).
    ///
    /// # Arguments
    ///
    /// * `circuit` - The circuit to prove.
    /// * `pk` - The proving key.
    /// * `r`, `s` - Blinding factors. Use non-zero random values for
    ///   zero-knowledge.
    #[inline]
    pub fn create_proof_with_reduction<C>(
        circuit: C,
        pk: &ProvingKey<E>,
        r: E::ScalarField,
        s: E::ScalarField,
    ) -> R1CSResult<Proof<E>>
    where
        E: Pairing,
        C: ConstraintSynthesizer<E::ScalarField>,
        QAP: R1CSToQAP,
    {
        let prover_time = start_timer!(|| "Groth16::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: true,
            generate_lc_assignments: false,
        });

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        debug_assert!(cs.is_satisfied().unwrap());

        let witness_map_time = start_timer!(|| "R1CS to QAP witness map");
        let h = QAP::witness_map::<E::ScalarField, D<E::ScalarField>>(cs.clone())?;
        end_timer!(witness_map_time);

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            r,
            s,
            &h,
            &prover.instance_assignment().unwrap()[1..],
            &prover.witness_assignment().unwrap(),
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    /// Rerandomize an existing Groth16 proof to produce a fresh, unlinkable
    /// proof of the same statement.
    ///
    /// Given a valid proof `π` of a statement `S`, the output is
    /// statistically indistinguishable from a freshly generated honest proof
    /// of `S`. This is useful for privacy — it prevents linking two
    /// verifications as being for the "same" proof.
    ///
    /// The rerandomization follows the construction in Theorem 3 of
    /// [\[BKSV20\]](https://eprint.iacr.org/2020/811):
    ///
    /// - `A' = (1/r₁) * A`
    /// - `B' = r₁ * B + r₁ * r₂ * (delta * H)`
    /// - `C' = C + r₂ * A`
    ///
    /// where `r₁` and `r₂` are freshly sampled non-zero random scalars.
    ///
    /// # Arguments
    ///
    /// * `vk` - The verification key (needed for the `delta_g2` element).
    /// * `proof` - The proof to rerandomize.
    /// * `rng` - A random number generator for sampling `r₁` and `r₂`.
    pub fn rerandomize_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        rng: &mut impl Rng,
    ) -> Proof<E> {
        // These are our rerandomization factors. They must be nonzero and uniformly
        // sampled.
        let (mut r1, mut r2) = (E::ScalarField::zero(), E::ScalarField::zero());
        while r1.is_zero() || r2.is_zero() {
            r1 = E::ScalarField::rand(rng);
            r2 = E::ScalarField::rand(rng);
        }

        // See figure 1 in the paper referenced above:
        //   A' = (1/r₁)A
        //   B' = r₁B + r₁r₂(δG₂)
        //   C' = C + r₂A

        // We can unwrap() this because r₁ is guaranteed to be nonzero
        let new_a = proof.a.mul(r1.inverse().unwrap());
        let new_b = proof.b.mul(r1) + &vk.delta_g2.mul(r1 * &r2);
        let new_c = proof.c + proof.a.mul(r2).into_affine();

        Proof {
            a: new_a.into_affine(),
            b: new_b.into_affine(),
            c: new_c.into_affine(),
        }
    }

    /// Computes a linear combination of group elements from the proving key.
    ///
    /// Calculates: `initial + vk_param + query[0] + MSM(query[1..],
    /// assignment)`
    ///
    /// This helper is used internally to compute the `A` and `B` components
    /// of the proof. The `query[0]` term corresponds to the constant `1`
    /// variable in the R1CS assignment.
    fn calculate_coeff<G: AffineRepr>(
        initial: G::Group,
        query: &[G],
        vk_param: G,
        assignment: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group
    where
        G::Group: VariableBaseMSM<MulBase = G>,
    {
        let el = query[0];
        let acc = G::Group::msm_bigint(&query[1..], assignment);

        let mut res = initial;
        res.add_assign(&el);
        res += &acc;
        res.add_assign(&vk_param);

        res
    }
}