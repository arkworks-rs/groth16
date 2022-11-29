#![warn(unused)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    variant_size_differences,
    stable_features,
    non_shorthand_field_patterns,
    renamed_and_removed_lints,
    private_in_public,
    unsafe_code
)]

use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{Field, ToConstraintField};
use ark_mnt4_298::MNT4_298;
use ark_r1cs_std::pairing::PairingVar as PG;
use ark_std::{
    env,
    error::Error,
    fs::OpenOptions,
    ops::MulAssign,
    path::PathBuf,
    process, test_rng,
    time::{Duration, Instant},
    UniformRand,
};
use csv;

use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};

type BasePrimeField<E> = <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

mod constraints;
use crate::constraints::{CurvePair, InnerCircuit, MiddleCircuit, OuterCircuit};

struct MNT46;
impl CurvePair for MNT46 {
    type TickGroup = ark_mnt4_298::MNT4_298;
    type TockGroup = ark_mnt6_298::MNT6_298;
    const TICK_CURVE: &'static str = "MNT4_298";
    const TOCK_CURVE: &'static str = "MNT6_298";
}
struct MNT64;
impl CurvePair for MNT64 {
    type TickGroup = ark_mnt6_298::MNT6_298;
    type TockGroup = ark_mnt4_298::MNT4_298;
    const TICK_CURVE: &'static str = "MNT6_298";
    const TOCK_CURVE: &'static str = "MNT4_298";
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args[1] == "-h" || args[1] == "--help" {
        println!(
            "\nHelp: Invoke this as <program> <num_constraints> <output_file_path> [<order>]\n"
        );
        println!("<order> defines the order in which the MNT4/6 curves should be used:");
        println!("46 (default) uses the MNT4_298 curve for the inner and outer circuit;");
        println!("64 uses the MNT6_298 curve for the inner and outer circuit.");
        return Ok(());
    }
    let num_constraints: usize = args[1].parse().unwrap();
    let output_file_path = PathBuf::from(args[2].clone());

    if args.len() < 4 || args[3] == "46" {
        run::<MNT46, ark_mnt4_298::constraints::PairingVar, ark_mnt6_298::constraints::PairingVar>(
            num_constraints,
            output_file_path,
        )
    } else {
        run::<MNT64, ark_mnt6_298::constraints::PairingVar, ark_mnt4_298::constraints::PairingVar>(
            num_constraints,
            output_file_path,
        )
    }
}

fn run<C: CurvePair, TickPairing: PG<C::TickGroup>, TockPairing: PG<C::TockGroup>>(
    num_constraints: usize,
    output_file_path: PathBuf,
) -> Result<(), Box<dyn Error>>
where
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    let mut wtr = if !output_file_path.exists() {
        println!("Creating output file");
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_file_path)?;
        let mut wtr = csv::Writer::from_writer(f);
        wtr.write_record(&[
            "num_constraints",
            "setup_inner",
            "prover_inner",
            "setup_middle",
            "prover_middle",
            "setup_outer",
            "prover_outer",
            "verifier_outer",
        ])?;
        wtr
    } else if output_file_path.is_file() {
        let f = OpenOptions::new().append(true).open(output_file_path)?;
        csv::Writer::from_writer(f)
    } else {
        println!("Path to output file does not point to a file.");
        process::exit(1);
    };
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut test_rng();

    // Let's benchmark stuff!
    let samples = 1;
    let mut total_setup_inner = Duration::new(0, 0);
    let mut total_proving_inner = Duration::new(0, 0);
    let mut total_setup_middle = Duration::new(0, 0);
    let mut total_proving_middle = Duration::new(0, 0);
    let mut total_setup_outer = Duration::new(0, 0);
    let mut total_proving_outer = Duration::new(0, 0);
    let mut total_verifying_outer = Duration::new(0, 0);

    // Just a place to put the proof data, so we can
    // benchmark deserialization.
    // let mut proof_vec = vec![];

    for sample in 0..samples {
        println!("Running sample {}/{}", sample + 1, samples);
        let mut inputs: Vec<<C::TickGroup as Pairing>::ScalarField> =
            Vec::with_capacity(num_constraints);
        for _ in 0..num_constraints {
            inputs.push(UniformRand::rand(rng));
        }

        // Create parameters for our inner circuit
        println!("|-- Generating inner parameters ({})", C::TICK_CURVE);
        let start = Instant::now();
        let params_inner = {
            let c = InnerCircuit::<<C::TickGroup as Pairing>::ScalarField>::new(
                num_constraints,
                inputs.clone(),
            );
            generate_random_parameters(c, rng)?
        };
        total_setup_inner += start.elapsed();

        // proof_vec.truncate(0);
        println!("|-- Generating inner proof ({})", C::TICK_CURVE);
        let start = Instant::now();
        let proof_inner = {
            // Create an instance of our inner circuit (with the witness)
            let c = InnerCircuit::new(num_constraints, inputs.clone());
            // Create a proof with our parameters.
            create_random_proof(c, &params_inner, rng)?
        };
        total_proving_inner += start.elapsed();

        // Verify inner proof.
        let pvk = prepare_verifying_key(&params_inner.vk);
        assert!(verify_proof(&pvk, &proof_inner, &inputs).unwrap());

        // Create parameters for our middle circuit
        println!("|-- Generating middle parameters ({})", C::TOCK_CURVE);
        let start = Instant::now();
        let params_middle = {
            let c = MiddleCircuit::<C, TickPairing>::new(
                inputs.clone(),
                params_inner.clone(),
                proof_inner.clone(),
            );
            generate_random_parameters(c, rng)?
        };
        total_setup_middle += start.elapsed();

        // proof_vec.truncate(0);
        println!("|-- Generating middle proof ({})", C::TOCK_CURVE);
        let start = Instant::now();
        let proof_middle = {
            // Create an instance of our middle circuit (with the witness)
            let c = MiddleCircuit::<C, TickPairing>::new(
                inputs.clone(),
                params_inner.clone(),
                proof_inner.clone(),
            );
            // Create a proof with our parameters.
            create_random_proof(c, &params_middle, rng)?
        };
        total_proving_middle += start.elapsed();

        {
            let pvk = prepare_verifying_key(&params_middle.vk);
            assert!(verify_proof(
                &pvk,
                &proof_middle,
                &MiddleCircuit::<C, TickPairing>::inputs(&inputs)
            )
            .unwrap());
        }

        // Create parameters for our outer circuit
        println!("|-- Generating outer parameters ({})", C::TICK_CURVE);
        let start = Instant::now();
        let params_outer = {
            let c = OuterCircuit::<C, TockPairing, TickPairing>::new(
                inputs.clone(),
                params_middle.clone(),
                proof_middle.clone(),
            );
            generate_random_parameters::<C::TickGroup, _, _>(c, rng)?
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params_outer.vk);
        total_setup_outer += start.elapsed();

        // proof_vec.truncate(0);
        println!("|-- Generating outer proof ({})", C::TICK_CURVE);
        let start = Instant::now();
        let proof_outer = {
            // Create an instance of our outer circuit (with the witness)
            let c = OuterCircuit::<C, TockPairing, TickPairing>::new(
                inputs.clone(),
                params_middle.clone(),
                proof_middle.clone(),
            );
            // Create a proof with our parameters.
            create_random_proof(c, &params_outer, rng)?
        };
        total_proving_outer += start.elapsed();

        println!("|-- Verify outer proof ({})", C::TICK_CURVE);
        let start = Instant::now();
        // let proof = Proof::read(&proof_vec[..]).unwrap();
        // Check the proof
        let r = verify_proof(&pvk, &proof_outer, &inputs).unwrap();
        assert!(r);
        total_verifying_outer += start.elapsed();
    }

    let setup_inner_avg = total_setup_inner / samples;
    let setup_inner_avg = setup_inner_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (setup_inner_avg.as_secs() as f64);

    let proving_inner_avg = total_proving_inner / samples;
    let proving_inner_avg = proving_inner_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (proving_inner_avg.as_secs() as f64);

    let setup_middle_avg = total_setup_middle / samples;
    let setup_middle_avg = setup_middle_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (setup_middle_avg.as_secs() as f64);

    let proving_middle_avg = total_proving_middle / samples;
    let proving_middle_avg = proving_middle_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (proving_middle_avg.as_secs() as f64);

    let setup_outer_avg = total_setup_outer / samples;
    let setup_outer_avg = setup_outer_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (setup_outer_avg.as_secs() as f64);

    let proving_outer_avg = total_proving_outer / samples;
    let proving_outer_avg = proving_outer_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (proving_outer_avg.as_secs() as f64);

    let verifying_outer_avg = total_verifying_outer / samples;
    let verifying_outer_avg = verifying_outer_avg.subsec_nanos() as f64 / 1_000_000_000f64
        + (verifying_outer_avg.as_secs() as f64);

    println!(
        "=== Benchmarking recursive Groth16 with {} constraints on inner circuit: ====",
        num_constraints
    );
    println!(
        "Average setup time (inner circuit): {:?} seconds",
        setup_inner_avg
    );
    println!(
        "Average proving time (inner circuit): {:?} seconds",
        proving_inner_avg
    );
    println!(
        "Average setup time (middle circuit): {:?} seconds",
        setup_middle_avg
    );
    println!(
        "Average proving time (middle circuit): {:?} seconds",
        proving_middle_avg
    );
    println!(
        "Average setup time (outer circuit): {:?} seconds",
        setup_outer_avg
    );
    println!(
        "Average proving time (outer circuit): {:?} seconds",
        proving_outer_avg
    );
    println!(
        "Average verifying time (outer circuit): {:?} seconds",
        verifying_outer_avg
    );

    wtr.write_record(&[
        format!("{}", num_constraints),
        format!("{}", setup_inner_avg),
        format!("{}", proving_inner_avg),
        format!("{}", setup_middle_avg),
        format!("{}", proving_middle_avg),
        format!("{}", setup_outer_avg),
        format!("{}", proving_outer_avg),
        format!("{}", verifying_outer_avg),
    ])?;
    wtr.flush()?;
    Ok(())
}
