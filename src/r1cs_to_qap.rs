use ark_ff::PrimeField;
use ark_poly::EvaluationDomain;
use ark_std::{cfg_iter_mut, cfg_join, vec};

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
/// This implementation is optimized for both parallel and sequential execution:
/// - In parallel mode, it uses Rayon's parallel iterator for efficient
///   multi-threading
/// - In sequential mode, it processes elements in chunks for better
///   vectorization
///
/// # Performance characteristics
/// - Time complexity: O(n) where n is the number of terms
/// - Space complexity: O(1) in sequential mode, O(log n) in parallel mode due
///   to work splitting
///
/// # Arguments
/// * `terms` - Slice of tuples containing coefficients and their indices
/// * `assignment` - Slice of values to be multiplied with coefficients
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

/// Computes instance and witness reductions from R1CS to
/// Quadratic Arithmetic Programs (QAPs).
pub trait R1CSToQAP {
    /// Computes a QAP instance corresponding to the R1CS instance defined by
    /// `cs`.
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError>;

    #[inline]
    /// Computes a QAP witness corresponding to the R1CS witness defined by
    /// `cs`.
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

    /// Computes a QAP witness corresponding to the R1CS witness defined by
    /// `cs`.
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &[Matrix<F>],
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> R1CSResult<Vec<F>>;

    /// Computes the exponents that the generator uses to calculate base
    /// elements which the prover later uses to compute `h(x)t(x)/delta`.
    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        zt: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError>;
}

/// Computes the R1CS-to-QAP reduction defined in [`libsnark`](https://github.com/scipr-lab/libsnark/blob/2af440246fa2c3d0b1b0a425fb6abd8cc8b9c54d/libsnark/reductions/r1cs_to_qap/r1cs_to_qap.tcc).
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

        // Evaluate all Lagrange polynomials
        let coefficients_time = start_timer!(|| "Evaluate Lagrange coefficients");
        let u = domain.evaluate_all_lagrange_coefficients(*t);
        end_timer!(coefficients_time);

        let qap_num_variables = (cs.num_instance_variables() - 1) + cs.num_witness_variables();

        let mut a = vec![F::zero(); qap_num_variables + 1];
        let mut b = vec![F::zero(); qap_num_variables + 1];
        let mut c = vec![F::zero(); qap_num_variables + 1];

        {
            let start = 0;
            let end = cs.num_instance_variables();
            let num_constraints = cs.num_constraints();
            a[start..end].copy_from_slice(&u[(start + num_constraints)..(end + num_constraints)]);
        }

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
        let coset_domain = domain.get_coset(F::GENERATOR).unwrap();

        // Runs the A, B, and C transforms concurrently.
        let public_inputs = &full_assignment[..num_inputs];
        let evaluate = |matrix: &Matrix<F>, extra: &[F]| {
            coset_evaluations::<F, D>(domain_size, num_constraints, matrix, extra, full_assignment)
        };
        let evaluate_a = || evaluate(&matrices[0], public_inputs);
        let evaluate_b = || evaluate(&matrices[1], &[]);
        let evaluate_c = || evaluate(&matrices[2], &[]);
        let (mut a, (b, c)) = cfg_join!(evaluate_a, || cfg_join!(evaluate_b, evaluate_c));

        let vanishing_polynomial_over_coset = domain
            .evaluate_vanishing_polynomial(F::GENERATOR)
            .inverse()
            .unwrap();

        cfg_iter_mut!(a)
            .zip(b)
            .zip(c)
            .for_each(|((a_i, b_i), c_i)| {
                *a_i *= &b_i;
                *a_i -= &c_i;
                *a_i *= &vanishing_polynomial_over_coset;
            });

        coset_domain.ifft_in_place(&mut a);

        Ok(a)
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

fn coset_evaluations<F: PrimeField, D: EvaluationDomain<F>>(
    domain_size: usize,
    num_constraints: usize,
    matrix: &Matrix<F>,
    extra: &[F],
    full_assignment: &[F],
) -> Vec<F> {
    // This same domain is being unwrapped in `witness_map_from_matrices`, so
    // is guaranteed to be valid by now. Can't send EvaluationDomain across
    // threads because it isn't Send/Sync.
    let domain = D::new(domain_size).unwrap();
    debug_assert_eq!(domain.size(), domain_size);

    let zero = F::zero();

    let mut evals = vec![zero; domain_size];
    cfg_iter_mut!(evals[..num_constraints])
        .zip(matrix)
        .for_each(|(e, row)| *e = evaluate_constraint(row, full_assignment));
    evals[num_constraints..num_constraints + extra.len()].clone_from_slice(extra);

    domain.ifft_in_place(&mut evals);
    domain
        .get_coset(F::GENERATOR)
        .unwrap()
        .fft_in_place(&mut evals);
    evals
}
