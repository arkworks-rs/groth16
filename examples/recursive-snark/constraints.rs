use ark_crypto_primitives::nizk::constraints::NIZKVerifierGadget;
use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField, ToConstraintField};
use ark_groth16::{
    constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar},
    Groth16, Parameters, Proof,
};
use ark_r1cs_std::{
    boolean::Boolean, fields::fp::FpVar, pairing::PairingVar as PG, prelude::*, uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;
use ark_std::ops::MulAssign;

type BasePrimeField<E> = <<<E as Pairing>::G1 as CurveGroup>::BaseField as Field>::BasePrimeField;

pub trait CurvePair
where
    <Self::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<Self::TockGroup>>,
    <Self::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<Self::TockGroup>>,
    <Self::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<Self::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <Self::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<Self::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    type TickGroup: Pairing<
        Fq = <Self::TockGroup as Pairing>::ScalarField,
        Fr = <Self::TockGroup as Pairing>::Fq,
    >;
    type TockGroup: Pairing;

    const TICK_CURVE: &'static str;
    const TOCK_CURVE: &'static str;
}

// Verifying InnerCircuit in MiddleCircuit
type InnerProofSystem<C> = Groth16<<C as CurvePair>::TickGroup>;

type InnerVerifierGadget<C, PV> = Groth16VerifierGadget<<C as CurvePair>::TickGroup, PV>;
type InnerProofVar<C, PV> = ProofVar<<C as CurvePair>::TickGroup, PV>;
type InnerVkVar<C, PV> = VerifyingKeyVar<<C as CurvePair>::TickGroup, PV>;

// Verifying MiddleCircuit in OuterCircuit
type MiddleProofSystem<C, PV> = Groth16<<C as CurvePair>::TockGroup>;
type MiddleVerifierGadget<C, PV> = Groth16VerifierGadget<<C as CurvePair>::TockGroup, PV>;
type MiddleProofVar<C, PV> = ProofVar<<C as CurvePair>::TockGroup, PV>;
type MiddleVkVar<C, PV> = VerifyingKeyVar<<C as CurvePair>::TockGroup, PV>;

pub struct InnerCircuit<F: PrimeField> {
    num_constraints: usize,
    inputs: Vec<F>,
}

impl<F: PrimeField> InnerCircuit<F> {
    pub fn new(num_constraints: usize, inputs: Vec<F>) -> Self {
        Self {
            num_constraints,
            inputs,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for InnerCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        assert!(self.inputs.len() >= 2);
        assert!(self.num_constraints >= self.inputs.len());

        let mut variables: Vec<_> = Vec::with_capacity(self.inputs.len());
        for input in self.inputs.into_iter() {
            let input_var = cs.new_input_variable(|| Ok(input))?;
            variables.push((input, input_var));
        }

        for i in 0..self.num_constraints {
            let new_entry = {
                let (input_1_val, input_1_var) = variables[i];
                let (input_2_val, input_2_var) = variables[i + 1];
                let result_val = input_1_val * input_2_val;
                let result_var = cs.new_witness_variable(|| Ok(result_val))?;
                cs.enforce_constraint(
                    lc!() + input_1_var,
                    lc!() + input_2_var,
                    lc!() + result_var,
                )?;
                (result_val, result_var)
            };
            variables.push(new_entry);
        }
        Ok(())
    }
}

pub struct MiddleCircuit<C: CurvePair, TickPairing: PG<C::TickGroup>>
where
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    inputs: Vec<<C::TickGroup as Pairing>::ScalarField>,
    params: Parameters<C::TickGroup>,
    proof: Proof<C::TickGroup>,
    _curve_pair: PhantomData<C>,
    _tick_pairing: PhantomData<TickPairing>,
}

impl<C: CurvePair, TickPairing: PG<C::TickGroup>> MiddleCircuit<C, TickPairing>
where
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    pub fn new(
        inputs: Vec<<C::TickGroup as Pairing>::ScalarField>,
        params: Parameters<C::TickGroup>,
        proof: Proof<C::TickGroup>,
    ) -> Self {
        Self {
            inputs,
            params,
            proof,
            _curve_pair: PhantomData,
            _tick_pairing: PhantomData,
        }
    }

    pub fn inputs(
        inputs: &[<C::TickGroup as Pairing>::ScalarField],
    ) -> Vec<<C::TockGroup as Pairing>::ScalarField> {
        let input_bytes = inputs
            .iter()
            .flat_map(|input| {
                input
                    .into_repr()
                    .as_ref()
                    .iter()
                    .flat_map(|l| l.to_le_bytes().to_vec())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        input_bytes[..].to_field_elements().unwrap()
    }
}

impl<C, TickPairing> ConstraintSynthesizer<<C::TockGroup as Pairing>::ScalarField>
    for MiddleCircuit<C, TickPairing>
where
    C: CurvePair,
    TickPairing: PG<C::TickGroup>,
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<C::TockGroup as Pairing>::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let params = self.params;
        let proof = self.proof;
        let inputs = self.inputs;
        let input_gadgets;

        {
            let ns = ark_relations::ns!(cs, "Allocate Input");
            let cs = ns.cs();
            // Chain all input values in one large byte array.
            let input_bytes = inputs
                .into_iter()
                .flat_map(|input| {
                    input
                        .into_repr()
                        .as_ref()
                        .iter()
                        .flat_map(|l| l.to_le_bytes().to_vec())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            // Allocate this byte array as input packed into field elements.
            let input_bytes =
                UInt8::new_input_vec(ark_relations::ns!(cs, "Input"), &input_bytes[..])?;
            // 40 byte
            let element_size =
                <<C::TickGroup as Pairing>::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 8;
            input_gadgets = input_bytes
                .chunks(element_size)
                .map(|chunk| {
                    chunk
                        .iter()
                        .flat_map(|byte| byte.to_bits_le().unwrap())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
        }
        println!("|---- Num inputs for sub-SNARK: {}", input_gadgets.len());
        let num_constraints = cs.num_constraints();
        println!(
            "|---- Num constraints to prepare inputs: {}",
            num_constraints
        );

        let vk_var =
            InnerVkVar::<C, TickPairing>::new_witness(ark_relations::ns!(cs, "Vk"), || {
                Ok(&params.vk)
            })?;
        let proof_var =
            InnerProofVar::<C, TickPairing>::new_witness(ark_relations::ns!(cs, "Proof"), || {
                Ok(proof.clone())
            })?;
        <InnerVerifierGadget<C, TickPairing> as NIZKVerifierGadget<
            InnerProofSystem<C>,
            <C::TockGroup as Pairing>::ScalarField,
        >>::verify(&vk_var, input_gadgets.iter(), &proof_var)?
        .enforce_equal(&Boolean::TRUE)?;
        println!(
            "|---- Num constraints for sub-SNARK verification: {}",
            cs.num_constraints() - num_constraints
        );
        Ok(())
    }
}

pub struct OuterCircuit<C: CurvePair, TockPairing: PG<C::TockGroup>, TickPairing: PG<C::TickGroup>>
where
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    inputs: Vec<<C::TickGroup as Pairing>::ScalarField>,
    params: Parameters<C::TockGroup>,
    proof: Proof<C::TockGroup>,
    _curve_pair: PhantomData<C>,
    _tock_pairing: PhantomData<TockPairing>,
    _tick_pairing: PhantomData<TickPairing>,
}

impl<C: CurvePair, TockPairing: PG<C::TockGroup>, TickPairing: PG<C::TickGroup>>
    OuterCircuit<C, TockPairing, TickPairing>
where
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    pub fn new(
        inputs: Vec<<C::TickGroup as Pairing>::ScalarField>,
        params: Parameters<C::TockGroup>,
        proof: Proof<C::TockGroup>,
    ) -> Self {
        Self {
            inputs,
            params,
            proof,
            _curve_pair: PhantomData,
            _tock_pairing: PhantomData,
            _tick_pairing: PhantomData,
        }
    }
}

impl<C: CurvePair, TockPairing: PG<C::TockGroup>, TickPairing: PG<C::TickGroup>>
    ConstraintSynthesizer<<C::TickGroup as Pairing>::ScalarField>
    for OuterCircuit<C, TockPairing, TickPairing>
where
    <C::TickGroup as Pairing>::G1: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G2: MulAssign<BasePrimeField<C::TockGroup>>,
    <C::TickGroup as Pairing>::G1Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
    <C::TickGroup as Pairing>::G2Affine:
        ToConstraintField<<<C::TockGroup as Pairing>::ScalarField as Field>::BasePrimeField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<<C::TickGroup as Pairing>::ScalarField>,
    ) -> Result<(), SynthesisError> {
        let params = self.params;
        let proof = self.proof;
        let inputs = self.inputs;
        let mut input_gadgets = Vec::new();

        {
            let bigint_size =
                <<C::TickGroup as Pairing>::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 64;
            let mut input_bits = Vec::new();
            let ns = ark_relations::ns!(cs, "Allocate Input");
            let cs = ns.cs();

            for input in inputs.into_iter() {
                let input_gadget = FpVar::new_input(ark_relations::ns!(cs, "Input"), || Ok(input))?;
                let mut fp_bits = input_gadget.to_bits_le()?;

                // Use 320 bits per element.
                for _ in fp_bits.len()..bigint_size {
                    fp_bits.push(Boolean::constant(false));
                }
                input_bits.extend_from_slice(&fp_bits);
            }

            // Pack input bits into field elements of the underlying circuit.
            let max_size = 8
                * ((<<C::TockGroup as Pairing>::ScalarField as PrimeField>::MODULUS_BIT_SIZE - 1)
                    / 8) as usize;
            let bigint_size =
                <<C::TockGroup as Pairing>::ScalarField as PrimeField>::BigInt::NUM_LIMBS * 64;
            for chunk in input_bits.chunks(max_size) {
                let mut chunk = chunk.to_vec();
                let len = chunk.len();
                for _ in len..bigint_size {
                    chunk.push(Boolean::constant(false));
                }
                input_gadgets.push(chunk);
            }
        }
        println!("|---- Num inputs for sub-SNARK: {}", input_gadgets.len());
        let num_constraints = cs.num_constraints();
        println!(
            "|---- Num constraints to prepare inputs: {}",
            num_constraints
        );

        let vk_var =
            MiddleVkVar::<C, TockPairing>::new_witness(ark_relations::ns!(cs, "Vk"), || {
                Ok(&params.vk)
            })?;
        let proof_var =
            MiddleProofVar::<C, TockPairing>::new_witness(r1cs_core::ns!(cs, "Proof"), || {
                Ok(proof.clone())
            })?;
        <MiddleVerifierGadget<C, TockPairing> as NIZKVerifierGadget<
            MiddleProofSystem<C, TickPairing>,
            <C::TickGroup as Pairing>::ScalarField,
        >>::verify(&vk_var, &input_gadgets, &proof_var)?
        .enforce_equal(&Boolean::TRUE)?;
        println!(
            "|---- Num constraints for sub-SNARK verification: {}",
            cs.num_constraints() - num_constraints
        );
        Ok(())
    }
}
