use crate::{rerandomize_proof, Groth16};
use ark_ec::PairingEngine;
use ark_ff::UniformRand;
use ark_std::test_rng;

use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintGenerator, ConstraintSystemRef, Instance, SynthesisError},
};
use ark_snark::{r1cs::SNARKForR1CS, SNARK};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintGenerator<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints_and_variable_assignments(
        &self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }

    fn generate_instance_assignment(
        &self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let _ = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;
        Ok(())
    }
}

fn test_prove_and_verify<E>(n_iters: usize)
where
    E: PairingEngine,
{
    let rng = &mut test_rng();

    let (pk, vk) =
        Groth16::<E>::circuit_specific_setup_with_cs(&MySillyCircuit { a: None, b: None }, rng)
            .unwrap();

    let pvk = Groth16::process_vk(&vk).unwrap();

    for _ in 0..n_iters {
        let a = E::Fr::rand(rng);
        let b = E::Fr::rand(rng);
        let c = a * b;

        let circ = MySillyCircuit {
            a: Some(a),
            b: Some(b),
        };
        let proof = Groth16::prove_with_cs(&pk, &circ, rng).unwrap();

        assert!(Groth16::verify_with_processed_vk(&pvk, &Instance(vec![c]), &proof,).unwrap());
        assert!(!Groth16::verify_with_processed_vk(&pvk, &Instance(vec![a]), &proof,).unwrap());
        assert!(Groth16::verify_with_cs_and_processed_vk(&pvk, &circ, &proof).unwrap());
    }
}

fn test_rerandomize<E>()
where
    E: PairingEngine,
{
    // First create an arbitrary Groth16 in the normal way

    let rng = &mut test_rng();

    let (pk, vk) =
        Groth16::<E>::circuit_specific_setup_with_cs(&MySillyCircuit { a: None, b: None }, rng)
            .unwrap();

    let a = E::Fr::rand(rng);
    let b = E::Fr::rand(rng);

    // Create the initial proof
    let circ = MySillyCircuit {
        a: Some(a),
        b: Some(b),
    };
    let proof1 = Groth16::prove_with_cs(&pk, &circ, rng).unwrap();

    // Rerandomize the proof, then rerandomize that
    let proof2 = rerandomize_proof(rng, &vk, &proof1);
    let proof3 = rerandomize_proof(rng, &vk, &proof2);

    // Check correctness: a rerandomized proof validates when the original validates
    assert!(Groth16::verify_with_cs(&vk, &circ, &proof1).unwrap());
    assert!(Groth16::verify_with_cs(&vk, &circ, &proof2).unwrap());
    assert!(Groth16::verify_with_cs(&vk, &circ, &proof3).unwrap());

    // Check soundness: a rerandomized proof fails to validate when the original fails to validate
    let bad_circ = MySillyCircuit {
        a: Some(E::Fr::rand(rng)),
        b: Some(E::Fr::rand(rng)),
    };
    assert!(!Groth16::verify_with_cs(&vk, &bad_circ, &proof1).unwrap());
    assert!(!Groth16::verify_with_cs(&vk, &bad_circ, &proof2).unwrap());
    assert!(!Groth16::verify_with_cs(&vk, &bad_circ, &proof3).unwrap());

    // Check that the proofs are not equal as group elements
    assert!(proof1 != proof2);
    assert!(proof1 != proof3);
    assert!(proof2 != proof3);
}

mod bls12_377 {
    use super::{test_prove_and_verify, test_rerandomize};
    use ark_bls12_377::Bls12_377;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<Bls12_377>(100);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<Bls12_377>();
    }
}

mod cp6_782 {
    use super::{test_prove_and_verify, test_rerandomize};

    use ark_cp6_782::CP6_782;

    #[test]
    fn prove_and_verify() {
        test_prove_and_verify::<CP6_782>(1);
    }

    #[test]
    fn rerandomize() {
        test_rerandomize::<CP6_782>();
    }
}
