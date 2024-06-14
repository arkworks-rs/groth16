use ark_ff::{One, PrimeField, Zero};
use ark_poly::EvaluationDomain;
use ark_std::{cfg_iter, cfg_iter_mut, vec};

use crate::Vec;
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSystemRef, Result as R1CSResult, SynthesisError,
};
use core::ops::{AddAssign, Deref};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[inline]
/// Computes the inner product of `terms` with `assignment`.
pub fn evaluate_constraint<'a, LHS, RHS, R>(terms: &'a [(LHS, usize)], assignment: &'a [RHS]) -> R
where
    LHS: One + Send + Sync + PartialEq,
    RHS: Send + Sync + core::ops::Mul<&'a LHS, Output = RHS> + Copy,
    R: Zero + Send + Sync + AddAssign<RHS> + core::iter::Sum,
{
    // Need to wrap in a closure when using Rayon
    #[cfg(feature = "parallel")]
    let zero = || R::zero();
    #[cfg(not(feature = "parallel"))]
    let zero = R::zero();

    let res = cfg_iter!(terms).fold(zero, |mut sum, (coeff, index)| {
        let val = &assignment[*index];

        if coeff.is_one() {
            sum += *val;
        } else {
            sum += val.mul(coeff);
        }

        sum
    });

    // Need to explicitly call `.sum()` when using Rayon
    #[cfg(feature = "parallel")]
    return res.sum();
    #[cfg(not(feature = "parallel"))]
    return res;
}

/// Computes instance and witness reductions from R1CS to
/// Quadratic Arithmetic Programs (QAPs).
pub trait R1CSToQAP {
    /// Computes a QAP instance corresponding to the R1CS instance defined by `cs`.
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError>;

    #[inline]
    /// Computes a QAP witness corresponding to the R1CS witness defined by `cs`.
    fn witness_map<F: PrimeField, D: EvaluationDomain<F>>(
        prover: ConstraintSystemRef<F>,
    ) -> Result<Vec<F>, SynthesisError> {
        let matrices = prover.to_matrices().unwrap();
        let num_inputs = prover.num_instance_variables();
        let num_constraints = prover.num_constraints();

        let cs = prover.borrow().unwrap();
        let prover = cs.deref();

        let full_assignment = [
            prover.instance_assignment.as_slice(),
            prover.witness_assignment.as_slice(),
        ]
        .concat();

        Self::witness_map_from_matrices::<F, D>(
            &matrices,
            num_inputs,
            num_constraints,
            &full_assignment,
        )
    }

    /// Computes a QAP witness corresponding to the R1CS witness defined by `cs`.
    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
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
        let matrices = cs.to_matrices().unwrap();
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
            for &(ref coeff, index) in &matrices.a[i] {
                a[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices.b[i] {
                b[index] += &(*u_i * coeff);
            }
            for &(ref coeff, index) in &matrices.c[i] {
                c[index] += &(*u_i * coeff);
            }
        }

        Ok((a, b, c, zt, qap_num_variables, domain_size))
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
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
        let mut c = vec![zero; domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter!(&matrices.a))
            .for_each(|(a, at_i)| {
                *a = evaluate_constraint(&at_i, &full_assignment);
            });

        cfg_iter_mut!(b[..num_constraints])
            .zip(cfg_iter!(&matrices.b))
            .for_each(|(b, bt_i)| {
                *b = evaluate_constraint(&bt_i, &full_assignment);
            });

        cfg_iter_mut!(c[..num_constraints])
            .enumerate()
            .for_each(|(i, c)| {
                *c = evaluate_constraint(&matrices.c[i], &full_assignment);
            });

        {
            let start = num_constraints;
            let end = start + num_inputs;
            a[start..end].clone_from_slice(&full_assignment[..num_inputs]);
        }

        // TODO: May be optimised because all even terms are the same and the odd terms are gamma

        // Each costs two fft's... can we do with one?

        let mut a_prime = domain.ifft(&a);
        let mut b_prime = domain.ifft(&b);
        let mut c_prime = domain.ifft(&c);

        formal_derivative_in_place(&mut a_prime);
        formal_derivative_in_place(&mut b_prime);
        formal_derivative_in_place(&mut c_prime);

        domain.fft_in_place(&mut a_prime);
        domain.fft_in_place(&mut b_prime);
        domain.fft_in_place(&mut c_prime);

        let mut result = domain.mul_polynomials_in_evaluation_domain(&a, &b_prime);
        cfg_iter_mut!(result).zip(domain.mul_polynomials_in_evaluation_domain(&a_prime, &b)).for_each(|(ab_i, a_prime_b_i)| {
            *ab_i += &a_prime_b_i;
        });
        cfg_iter_mut!(result).zip(c_prime).for_each(|(ab_i, c_prime_i)| {
            *ab_i -= &c_prime_i;
        });

        let t = vanishing_polynomial_prime(domain_size, domain.group_gen());

        let mut q: Vec<F> = Vec::with_capacity(domain_size);
        for i in 0..domain_size {
            q.push(result[i].div(t[i]));
        }

        domain.ifft_in_place(&mut q);

        Ok(q)
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

/// Extend a FT over `from` to an FT over `to` in `n` multiplications. This assumes that `2*from.size() = to.size()`
/// and that the generator of `from` is the square of the generator of `to`.
fn extend_ft<F: PrimeField, D: EvaluationDomain<F>>(a: &Vec<F>, from: &D, to: &D) -> Vec<F> {
    assert_eq!(2 * from.size(), to.size());
    let n = a.len();
    assert_eq!(n, from.size());

    to.fft(&from.ifft(&a))
}

fn formal_derivative_in_place<F: PrimeField>(a: &mut Vec<F>) {
    let n = a.len();
    let mut s = F::one();
    for i in 0..(n - 1) {
        a[i] = a[i+1].mul(s);
        s += F::one();
    }
    a[n - 1] = F::zero();
}

fn vanishing_polynomial_prime<F: PrimeField>(n: usize, omega: F) -> Vec<F> {
    // TODO: Optimise or pre-compute
    let mut t: Vec<F> = Vec::with_capacity(n);
    let mut power = F::one();
    for _ in 0..n {
        let entry = F::from(n as u128).div(power);
        t.push(entry);
        power *= omega;
    }
    t
}

