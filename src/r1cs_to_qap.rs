use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_std::{cfg_iter_mut, vec};

use crate::Vec;
use ark_relations::gr1cs::{
    ConstraintSystemRef, Matrix, Result as R1CSResult, SynthesisError, R1CS_PREDICATE_LABEL,
};
use core::ops::Deref;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
/// Computes the inner product of `terms` with `assignment`.
///
/// Evaluates a single R1CS constraint row by computing
/// `sum_i (coeff_i * assignment[index_i])`. This is the core operation in the
/// R1CS-to-QAP witness map.
///
/// # Implementation details
///
/// - In **parallel** mode (with the `parallel` feature), inputs with fewer
///   than 100 terms fall back to sequential execution to avoid thread overhead.
///   Larger inputs use Rayon's parallel iterator.
/// - In **sequential** mode, elements are processed in chunks of 4 for better
///   CPU vectorization.
///
/// # Performance
///
/// - Time complexity: O(n) where n = `terms.len()`
/// - Space complexity: O(1) sequentially, O(log n) in parallel due to
///   work-splitting
///
/// # Arguments
///
/// * `terms` - Sparse representation of a constraint row: each entry
///   `(coeff, index)` means "multiply `coeff` by `assignment[index]`."
/// * `assignment` - The full variable assignment (instance + witness).
pub fn evaluate_constraint<F: PrimeField>(terms: &[(F, usize)], assignment: &[F]) -> F {
    #[cfg(feature = "parallel")]
    if terms.len() < 100 {
        serial_evaluate_constraint(terms, assignment)
    } else {
        terms
            .par_iter()
            .map(|(coeff, index)| {
                let val = assignment[*index];
                if coeff.is_one() {
                    val
                } else {
                    val * coeff
                }
            })
            .sum()
    }
    #[cfg(not(feature = "parallel"))]
    serial_evaluate_constraint(terms, assignment)
}

/// Sequential implementation of [`evaluate_constraint`].
///
/// Processes terms in chunks of 4 to help the compiler auto-vectorize the
/// inner loop. Each chunk is summed independently, then accumulated into the
/// running total.
fn serial_evaluate_constraint<F: PrimeField>(terms: &[(F, usize)], assignment: &[F]) -> F {
    let mut sum = F::zero();
    // Process elements in chunks for better CPU vectorization
    for chunk in terms.chunks(4) {
        let chunk_sum = chunk
            .iter()
            .map(|(coeff, index)| {
                let val = assignment[*index];
                if coeff.is_one() {
                    val
                } else {
                    val * coeff
                }
            })
            .sum::<F>();
        sum += chunk_sum;
    }
    sum
}

/// Defines how an R1CS instance is reduced to a Quadratic Arithmetic Program
/// (QAP).
///
/// The Groth16 SNARK operates over QAP instances, not R1CS directly. This
/// trait abstracts the reduction so that different QAP constructions can be
/// plugged in. The default implementation is [`LibsnarkReduction`], which
/// follows the reduction used in
/// [`libsnark`](https://github.com/scipr-lab/libsnark).
///
/// A QAP instance consists of polynomials `{u_i(x), v_i(x), w_i(x)}` and a
/// target polynomial `t(x)` such that a valid assignment `(a_0, ..., a_m)`
/// satisfies:
///
/// ```text
/// (sum_i a_i * u_i(x)) * (sum_i a_i * v_i(x)) = sum_i a_i * w_i(x)  mod t(x)
/// ```
pub trait R1CSToQAP {
    /// Computes a QAP instance by evaluating the QAP polynomials at a point
    /// `t`.
    ///
    /// This is used during the **setup** phase. It evaluates `u_i(t)`,
    /// `v_i(t)`, `w_i(t)` for all variables and returns them along with the
    /// vanishing polynomial evaluation `z(t)`.
    ///
    /// # Returns
    ///
    /// A tuple `(a, b, c, zt, qap_num_variables, domain_size)` where:
    /// - `a[i]` = `u_i(t)` (A-polynomial evaluations)
    /// - `b[i]` = `v_i(t)` (B-polynomial evaluations)
    /// - `c[i]` = `w_i(t)` (C-polynomial evaluations)
    /// - `zt` = `z(t)` (vanishing polynomial at `t`)
    /// - `qap_num_variables` = number of QAP variables (excluding constant)
    /// - `domain_size` = size of the evaluation domain (a power of two)
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError>;

    #[inline]
    /// Computes a QAP witness from a satisfied R1CS constraint system.
    ///
    /// This is used during the **proving** phase. Given a constraint system
    /// with a valid assignment, it computes the quotient polynomial
    /// `h(x) = (A(x) * B(x) - C(x)) / Z(x)` in evaluation form.
    ///
    /// This method extracts the matrices and assignment from `prover` and
    /// delegates to
    /// [`witness_map_from_matrices`](Self::witness_map_from_matrices).
    fn witness_map<F: PrimeField, D: EvaluationDomain<F>>(
        prover: ConstraintSystemRef<F>,
    ) -> Result<Vec<F>, SynthesisError> {
        let matrices = &prover.to_matrices().unwrap()[R1CS_PREDICATE_LABEL];
        let num_inputs = prover.num_instance_variables();
        let num_constraints = prover.num_constraints();

        let cs = prover.borrow().unwrap();
        let prover = cs.deref();

        let full_assignment = [
            prover.instance_assignment().unwrap(),
            prover.witness_assignment().unwrap(),
        ]
        .concat();

        Self::witness_map_from_matrices::<F, D>(
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }

    /// Computes a QAP witness from explicit R1CS matrices and assignment.
    ///
    /// This is the core witness computation. It computes the quotient
    /// polynomial `h(x)` whose coefficients the prover needs to construct
    /// the proof.
    ///
    /// The computation uses an FFT-based approach:
    /// 1. Evaluate `A(x)` and `B(x)` at the constraint rows.
    /// 2. Interpolate via inverse FFT (IFFT).
    /// 3. Evaluate on a coset via FFT.
    /// 4. Compute `(A * B - C) / Z` on the coset.
    /// 5. Interpolate back via coset IFFT.
    ///
    /// # Arguments
    ///
    /// * `matrices` - The R1CS constraint matrices `[A, B, C]`.
    /// * `num_inputs` - Number of public input variables (including constant
    ///   `1`).
    /// * `num_constraints` - Number of R1CS constraints.
    /// * `full_assignment` - Complete variable assignment (instance + witness).
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>>;

    /// Computes the scalar exponents for the H-query in the proving key.
    ///
    /// During setup, the generator needs to encode powers of `t` scaled by
    /// `z(t) / delta` into group elements. This method computes the scalars:
    ///
    /// ```text
    /// h_i = z(t) * delta^{-1} * t^i,  for i = 0, ..., max_power - 1
    /// ```
    ///
    /// # Arguments
    ///
    /// * `max_power` - Number of scalars to compute (degree bound of `h(x)`).
    /// * `t` - The evaluation point chosen during setup.
    /// * `zt` - The vanishing polynomial evaluated at `t`: `z(t)`.
    /// * `delta_inverse` - The inverse of the toxic waste parameter `delta`.
    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError>;
}

/// The R1CS-to-QAP reduction used in
/// [`libsnark`](https://github.com/scipr-lab/libsnark/blob/2af440246fa2c3d0b1b0a425fb6abd8cc8b9c54d/libsnark/reductions/r1cs_to_qap/r1cs_to_qap.tcc).
///
/// This is the default QAP reduction for Groth16. It constructs the QAP
/// polynomials by treating each R1CS constraint as an evaluation point,
/// with additional points for the public-input identity constraints.
pub struct LibsnarkReduction;

impl R1CSToQAP for LibsnarkReduction {
    #[inline]
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> R1CSResult<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize)> {
        let matrices = &cs.to_matrices().unwrap()[R1CS_PREDICATE_LABEL];
        let domain_size = cs.num_constraints() + cs.num_instance_variables();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(*t);

        // Evaluate all Lagrange polynomials at the point t
        let coefficients_time = start_timer!(|| "Evaluate Lagrange coefficients");
        let u = domain.evaluate_all_lagrange_coefficients(*t);
        end_timer!(coefficients_time);

        let qap_num_variables = (cs.num_instance_variables() - 1) + cs.num_witness_variables();

        let mut a = vec![F::zero(); qap_num_variables + 1];
        let mut b = vec![F::zero(); qap_num_variables + 1];
        let mut c = vec![F::zero(); qap_num_variables + 1];

        // The public-input identity constraints occupy the last
        // `num_instance_variables` positions in the domain. Copy their
        // Lagrange coefficients into the A-polynomial evaluations.
        {
            let start = 0;
            let end = cs.num_instance_variables();
            let num_constraints = cs.num_constraints();
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

        // Accumulate contributions from each R1CS constraint into the QAP
        // polynomial evaluations.
        for (i, u_i) in u.iter().enumerate().take(cs.num_constraints()) {
            for &(ref coeff, index) in &matrices[0][i] {
                a[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[1][i] {
                b[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices[2][i] {
                c[index] += &(*u_i * coeff);
            }
        }

        Ok((a, b, c, zt, qap_num_variables, domain_size))
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>> {
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();
        let zero = F::zero();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        // Step 1: Evaluate each constraint row against the full assignment
        // to get A(x) and B(x) at the constraint evaluation points.
        cfg_iter_mut!(a[..num_constraints])
            .zip(&mut b[..num_constraints])
            .zip(&matrices[0])
            .zip(&matrices[1])
            .for_each(|(((a, b), at_i), bt_i)| {
                *a = evaluate_constraint(&at_i, &full_assignment);
                *b = evaluate_constraint(&bt_i, &full_assignment);
            });

        // The identity constraints for public inputs: a[num_constraints + i] =
        // assignment[i].
        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        // Step 2: Interpolate A and B from evaluation form to coefficient form.
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        // Step 3: Evaluate on a coset to prepare for polynomial multiplication.
        let coset_domain = domain.get_coset(F::GENERATOR).unwrap();

        coset_domain.fft_in_place(&mut a);
        coset_domain.fft_in_place(&mut b);

        // Step 4: Compute A * B on the coset.
        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        // Step 5: Evaluate C on the coset and subtract from A * B.
        let mut c = vec![zero; domain_size];
        cfg_iter_mut!(c[..num_constraints])
            .enumerate()
            .for_each(|(i, c)| {
                *c = evaluate_constraint(&matrices[2][i], &full_assignment);
            });

        domain.ifft_in_place(&mut c);
        coset_domain.fft_in_place(&mut c);

        // Step 6: Divide by the vanishing polynomial on the coset to get h(x).
        let vanishing_polynomial_over_coset = domain
            .evaluate_vanishing_polynomial(F::GENERATOR)
            .inverse()
            .unwrap();
        cfg_iter_mut!(ab).zip(c).for_each(|(ab_i, c_i)| {
            *ab_i -= &c_i;
            *ab_i *= &vanishing_polynomial_over_coset;
        });

        // Step 7: Interpolate h(x) back to coefficient form.
        coset_domain.ifft_in_place(&mut ab);

        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        let scalars = cfg_into_iter!(0..max_power)
            .map(|i| zt * &delta_inverse * &t.pow([i as u64]))
            .collect::<Vec<_>>();
        Ok(scalars)
    }
}