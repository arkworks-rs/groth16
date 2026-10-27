// For benchmark, run:
//     cargo bench --bench groth16-criterion --no-default-features --features std 
// This statistics takes more time.

mod dummycircuit;

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_crypto_primitives::snark::SNARK;
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{r1cs_to_qap::evaluate_constraint, Groth16};
use ark_mnt4_298::MNT4_298;
use ark_std::rand::{Rng, SeedableRng};
use criterion::{criterion_group, criterion_main, Criterion};
use dummycircuit::DummyCircuit;
use std::hint::black_box;
use std::time::Duration;

const NUM_CONSTRAINTS: usize = (1 << 20) - 100;
const NUM_VARIABLES: usize = (1 << 20) - 100;

fn benchmark_prove<E: Pairing>(criterion: &mut Criterion, name: &str)
where
    E::ScalarField: PrimeField + UniformRand,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);
    let circuit = DummyCircuit::<E::ScalarField> {
        a: Some(E::ScalarField::rand(&mut rng)),
        b: Some(E::ScalarField::rand(&mut rng)),
        num_variables: NUM_VARIABLES,
        num_constraints: NUM_CONSTRAINTS,
    };
    let (proving_key, _) = Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();

    criterion.bench_function(name, |bencher| {
        bencher.iter(|| {
            black_box(Groth16::<E>::prove(&proving_key, circuit.clone(), &mut rng).unwrap())
        })
    });
}

fn benchmark_verify<E: Pairing>(criterion: &mut Criterion, name: &str)
where
    E::ScalarField: PrimeField + UniformRand,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);
    let circuit = DummyCircuit::<E::ScalarField> {
        a: Some(E::ScalarField::rand(&mut rng)),
        b: Some(E::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: NUM_CONSTRAINTS,
    };
    let (proving_key, verifying_key) =
        Groth16::<E>::circuit_specific_setup(circuit, &mut rng).unwrap();
    let proof = Groth16::<E>::prove(&proving_key, circuit.clone(), &mut rng).unwrap();
    let public_input = circuit.a.unwrap() * circuit.b.unwrap();

    criterion.bench_function(name, |bencher| {
        bencher.iter(|| {
            black_box(
                Groth16::<E>::verify(
                    &verifying_key,
                    black_box(&[public_input]),
                    black_box(&proof),
                )
                .unwrap(),
            )
        })
    });
}

fn bench_prove(criterion: &mut Criterion) {
    benchmark_prove::<Bls12_381>(criterion, "Groth16 prove/BLS12-381");
    benchmark_prove::<MNT4_298>(criterion, "Groth16 prove/MNT4-298");
}

fn bench_verify(criterion: &mut Criterion) {
    benchmark_verify::<Bls12_381>(criterion, "Groth16 verify/BLS12-381");
    benchmark_verify::<MNT4_298>(criterion, "Groth16 verify/MNT4-298");
}

fn bench_evaluate_constraint(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("evaluate_constraint");

    for size in [100, 1_000, 10_000, 100_000] {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(0);
        let terms: Vec<_> = (0..10)
            .map(|_| (BlsFr::rand(&mut rng), rng.gen_range(0..size)))
            .collect();
        let assignment: Vec<_> = (0..size).map(|_| BlsFr::rand(&mut rng)).collect();

        group.bench_function(size.to_string(), |bencher| {
            bencher.iter(|| evaluate_constraint(black_box(&terms), black_box(&assignment)))
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(30));
    targets = bench_prove, bench_verify, bench_evaluate_constraint
}
criterion_main!(benches);
