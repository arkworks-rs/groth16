// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_crypto_primitives::snark::SNARK;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{r1cs_to_qap::evaluate_constraint, Groth16};
use ark_mnt4_298::{Fr as MNT4Fr, MNT4_298};
use ark_mnt6_298::{Fr as MNT6Fr, MNT6_298};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::{Rng, SeedableRng};

const NUM_PROVE_REPETITIONS: usize = 1;
const NUM_VERIFY_REPETITIONS: usize = 50;
const NUM_CONSTRAINTS: usize = (1 << 20) - 100;
const NUM_VARIABLES: usize = (1 << 20) - 100;

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a.clone(),
            b: self.b.clone(),
            num_variables: self.num_variables.clone(),
            num_constraints: self.num_constraints.clone(),
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

macro_rules! groth16_prove_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
        let c = DummyCircuit::<$bench_field> {
            a: Some(<$bench_field>::rand(rng)),
            b: Some(<$bench_field>::rand(rng)),
            num_variables: NUM_VARIABLES,
            num_constraints: NUM_CONSTRAINTS,
        };

        let (pk, _) = Groth16::<$bench_pairing_engine>::circuit_specific_setup(c, rng).unwrap();

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_PROVE_REPETITIONS {
            let _ = Groth16::<$bench_pairing_engine>::prove(&pk, c.clone(), rng).unwrap();
        }

        println!(
            "per-constraint proving time for {}: {} ns/constraint",
            stringify!($bench_pairing_engine),
            start.elapsed().as_nanos() / (NUM_PROVE_REPETITIONS as u128 * NUM_CONSTRAINTS as u128)
        );
        println!(
            "wall-clock proving time for {}: {} s",
            stringify!($bench_pairing_engine),
            start.elapsed().as_secs_f64() / NUM_PROVE_REPETITIONS as f64
        );
    };
}

macro_rules! groth16_verify_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty) => {
        let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
        let c = DummyCircuit::<$bench_field> {
            a: Some(<$bench_field>::rand(rng)),
            b: Some(<$bench_field>::rand(rng)),
            num_variables: 10,
            num_constraints: NUM_CONSTRAINTS,
        };

        let (pk, vk) = Groth16::<$bench_pairing_engine>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<$bench_pairing_engine>::prove(&pk, c.clone(), rng).unwrap();

        let v = c.a.unwrap() * c.b.unwrap();

        let start = ark_std::time::Instant::now();

        for _ in 0..NUM_VERIFY_REPETITIONS {
            let _ = Groth16::<$bench_pairing_engine>::verify(&vk, &vec![v], &proof).unwrap();
        }

        println!(
            "verifying time for {}: {} ns",
            stringify!($bench_pairing_engine),
            start.elapsed().as_nanos() / NUM_VERIFY_REPETITIONS as u128
        );
    };
}

fn create_evaluate_constraint_test_data(size: usize) -> (Vec<(BlsFr, usize)>, Vec<BlsFr>) {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let terms = (0..10)
        .map(|_| (BlsFr::rand(&mut rng), rng.gen_range(0..size)))
        .collect();
    let assignment = (0..size).map(|_| BlsFr::rand(&mut rng)).collect();
    (terms, assignment)
}

fn bench_evaluate_constraint() {
    println!("\nBenchmarking evaluate_constraint:");

    for size in [100, 1000, 10000, 100000].iter() {
        let (terms, assignment) = create_evaluate_constraint_test_data(*size);

        // Benchmark sequential version
        let start = ark_std::time::Instant::now();
        for _ in 0..100 {
            let _ = evaluate_constraint(&terms, &assignment);
        }
        let seq_time = start.elapsed();

        println!("Size {}: {} ns/iteration", size, seq_time.as_nanos() / 100);
    }
}

fn bench_prove() {
    groth16_prove_bench!(bls, BlsFr, Bls12_381);
    groth16_prove_bench!(mnt4, MNT4Fr, MNT4_298);
    groth16_prove_bench!(mnt6, MNT6Fr, MNT6_298);
}

fn bench_verify() {
    groth16_verify_bench!(bls, BlsFr, Bls12_381);
    groth16_verify_bench!(mnt4, MNT4Fr, MNT4_298);
    groth16_verify_bench!(mnt6, MNT6Fr, MNT6_298);
}

fn main() {
    bench_prove();
    bench_verify();
    bench_evaluate_constraint();
}
