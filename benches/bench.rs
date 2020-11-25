#[macro_use]
extern crate criterion;

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_crypto_primitives::SNARK;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_mnt4_298::{Fr as MNT4Fr, MNT4_298};
use ark_mnt4_753::{Fr as MNT4BigFr, MNT4_753};
use ark_mnt6_298::{Fr as MNT6Fr, MNT6_298};
use ark_mnt6_753::{Fr as MNT6BigFr, MNT6_753};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use core::ops::Mul;
use criterion::Criterion;

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
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty, $cr:ident) => {
        let rng = &mut ark_ff::test_rng();
        let c = DummyCircuit::<$bench_field> {
            a: Some(<$bench_field>::rand(rng)),
            b: Some(<$bench_field>::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let (pk, _) = Groth16::<$bench_pairing_engine>::circuit_specific_setup(c, rng).unwrap();

        $cr.bench_function(&format!("prove_{}", stringify!($bench_name)), |b| {
            b.iter(|| Groth16::<$bench_pairing_engine>::prove(&pk, c.clone(), rng).unwrap())
        });
    };
}

macro_rules! groth16_verify_bench {
    ($bench_name:ident, $bench_field:ty, $bench_pairing_engine:ty, $cr:ident) => {
        let rng = &mut ark_ff::test_rng();
        let c = DummyCircuit::<$bench_field> {
            a: Some(<$bench_field>::rand(rng)),
            b: Some(<$bench_field>::rand(rng)),
            num_variables: 10,
            num_constraints: 65536,
        };

        let (pk, vk) = Groth16::<$bench_pairing_engine>::circuit_specific_setup(c, rng).unwrap();
        let proof = Groth16::<$bench_pairing_engine>::prove(&pk, c.clone(), rng).unwrap();

        let v = c.a.unwrap().mul(c.b.unwrap());

        $cr.bench_function(&format!("verify_{}", stringify!($bench_name)), |b| {
            b.iter(|| Groth16::<$bench_pairing_engine>::verify(&vk, &vec![v], &proof).unwrap())
        });
    };
}

fn bench_prove(cr: &mut Criterion) {
    groth16_prove_bench!(bls, BlsFr, Bls12_381, cr);
    groth16_prove_bench!(mnt4, MNT4Fr, MNT4_298, cr);
    groth16_prove_bench!(mnt6, MNT6Fr, MNT6_298, cr);
    groth16_prove_bench!(mnt4big, MNT4BigFr, MNT4_753, cr);
    groth16_prove_bench!(mnt6big, MNT6BigFr, MNT6_753, cr);
}

fn bench_verify(cr: &mut Criterion) {
    groth16_verify_bench!(bls, BlsFr, Bls12_381, cr);
    groth16_verify_bench!(mnt4, MNT4Fr, MNT4_298, cr);
    groth16_verify_bench!(mnt6, MNT6Fr, MNT6_298, cr);
    groth16_verify_bench!(mnt4big, MNT4BigFr, MNT4_753, cr);
    groth16_verify_bench!(mnt6big, MNT6BigFr, MNT6_753, cr);
}

criterion_group! {
    name = groth16_prove;
    config = Criterion::default().sample_size(50);
    targets = bench_prove
}

criterion_group! {
    name = groth16_verify;
    config = Criterion::default().sample_size(50);
    targets = bench_verify
}

criterion_main!(groth16_prove, groth16_verify);
