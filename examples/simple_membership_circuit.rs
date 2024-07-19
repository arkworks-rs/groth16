use std::ops::BitOr;

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};

struct SecretIsPartOfPublicInputsCircuit<'a, const N_PUBLIC_INPUTS: usize> {
    secret_value: Option<u8>,
    public_inputs: Option<&'a [u8; N_PUBLIC_INPUTS]>,
}

// Those constraints make sure the that secret is present in the public input
// values, wihout revealing it's actual value to the verifier
impl<'a, const N_PUBLIC_INPUTS: usize, ConstraintF: PrimeField> ConstraintSynthesizer<ConstraintF>
    for SecretIsPartOfPublicInputsCircuit<'a, N_PUBLIC_INPUTS>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let secret_value = UInt8::new_witness(cs.clone(), || {
            self.secret_value
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut is_found = Boolean::new_constant(cs.clone(), false)?;

        for i in 0..N_PUBLIC_INPUTS {
            let public_inputs = self
                .public_inputs
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let public_input = UInt8::new_input(cs.clone(), || {
                public_inputs
                    .get(i)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let is_eq = public_input.is_eq(&secret_value)?;

            is_found = is_found.bitor(&is_eq);
        }

        is_found.enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}

/// Setup, proove and verify the `SecretIsPartOfPublicInputsCircuit`.
///
/// * Args
/// 1) `secret`: the value you want to prove is part of the public input without
///    revealing it
/// ..) `public_inputs`: some numbers that will be used as the public inputs to
/// the circuit
///
/// * Usase
/// ```shell
/// cargo run --example simple_membership_circuit 42 1 21 42
/// ```
///
/// In order to be able to generate a proof, the secret should be part of the
/// public inputs. The number of public input is constrained by the
/// `N_PUB_INPUTS` constant and should be respected.
fn main() {
    // Edit this const to change the number of public inputs
    const N_PUB_INPUTS: usize = 3;

    // Read args
    let (secret_value, public_inputs) = {
        let mut args = std::env::args();
        let secret = str::parse::<u8>(&args.nth(1).expect("arguments should be given"))
            .expect("all arguments should be valid u8");

        let mut public_inputs = [0u8; N_PUB_INPUTS];
        let mut n_inputs = 0;
        for (i, arg) in args.enumerate() {
            public_inputs[i] = str::parse::<u8>(&arg).expect("all arguments should be valid u8");
            n_inputs += 1;
        }
        assert_eq!(
            n_inputs, N_PUB_INPUTS,
            "exactly N_PUB_INPUTS public inputs should be given"
        );

        (secret, public_inputs)
    };

    // Setup circuit and generate keys
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(
        SecretIsPartOfPublicInputsCircuit::<N_PUB_INPUTS> {
            secret_value: None,
            public_inputs: Some(&[0u8; N_PUB_INPUTS]),
        },
        &mut rng,
    )
    .unwrap();
    let pvk = prepare_verifying_key::<ark_bn254::Bn254>(&vk);

    // Generate proof
    let proof = Groth16::<ark_bn254::Bn254>::prove(
        &pk,
        SecretIsPartOfPublicInputsCircuit::<N_PUB_INPUTS> {
            secret_value: Some(secret_value),
            public_inputs: Some(&public_inputs),
        },
        &mut rng,
    )
    .unwrap();

    // We use `Uint8` as inputs, each one is represented as a sequence of 8
    // bigendian `Boolean`. Therfore we have to feed the verifier 8 times more
    // values than our number of public inputs.
    let mut verifier_inputs = Vec::with_capacity(public_inputs.len() * 8);
    for input in public_inputs {
        for i in 0..8 {
            let mask = 1 << i;
            verifier_inputs.push(<ark_bn254::Bn254 as Pairing>::ScalarField::from(
                mask & input != 0,
            ));
        }
    }

    // Verify proof
    assert!(
        Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(&pvk, &verifier_inputs, &proof)
            .unwrap()
    );
}
