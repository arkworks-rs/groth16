use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

mod bls12_377 {
    use super::*;
    use crate::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use ark_ff::{test_rng, UniformRand};

    use ark_bls12_377::{Bls12_377, Fr};

    #[test]
    fn prove_and_verify_hiding() {
        let rng = &mut test_rng();

        let params = generate_random_parameters::<Bls12_377, _, _>(
            MySillyCircuit { a: None, b: None },
            true,
            rng,
        )
        .unwrap();

        let pvk = prepare_verifying_key::<Bls12_377>(&params.vk);

        for _ in 0..100 {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);

            let (proof, _) = create_random_proof(
                MySillyCircuit {
                    a: Some(a),
                    b: Some(b),
                },
                &params,
                rng,
            )
            .unwrap();

            assert!(verify_proof(&pvk, &proof).unwrap());
        }
    }

    #[test]
    fn prove_and_verify_no_hiding() {
        let rng = &mut test_rng();

        let params = generate_random_parameters::<Bls12_377, _, _>(
            MySillyCircuit { a: None, b: None },
            false,
            rng,
        )
        .unwrap();

        let pvk = prepare_verifying_key::<Bls12_377>(&params.vk);

        for _ in 0..100 {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);

            let (proof, _) = create_random_proof(
                MySillyCircuit {
                    a: Some(a),
                    b: Some(b),
                },
                &params,
                rng,
            )
            .unwrap();

            assert!(verify_proof(&pvk, &proof).unwrap());
        }
    }
}

mod cp6_782 {
    use super::*;
    use crate::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };

    use ark_cp6_782::{Fr, CP6_782};
    use ark_ff::{test_rng, UniformRand};

    #[test]
    fn prove_and_verify_hiding() {
        let rng = &mut test_rng();

        let params = generate_random_parameters::<CP6_782, _, _>(
            MySillyCircuit { a: None, b: None },
            true,
            rng,
        )
        .unwrap();

        let pvk = prepare_verifying_key::<CP6_782>(&params.vk);

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);

        let (proof, _) = create_random_proof(
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &params,
            rng,
        )
        .unwrap();

        assert!(verify_proof(&pvk, &proof).unwrap());
    }

    #[test]
    fn prove_and_verify_no_hiding() {
        let rng = &mut test_rng();

        let params = generate_random_parameters::<CP6_782, _, _>(
            MySillyCircuit { a: None, b: None },
            false,
            rng,
        )
        .unwrap();

        let pvk = prepare_verifying_key::<CP6_782>(&params.vk);

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);

        let (proof, _) = create_random_proof(
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &params,
            rng,
        )
        .unwrap();

        assert!(verify_proof(&pvk, &proof).unwrap());
    }
}
