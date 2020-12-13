/// `AugmentedQAP` uses most straightforward way for non-degeneracy in [BCTV14](https://eprint.iacr.org/2013/879)
/// This property is not necessary for standard Groth16, but it is needed when we want Groth16 to be commit-carrying,
/// as defined in [LegoSNARK](https://eprint.iacr.org/2019/142)
///
/// `AugmentedQAP` simply adds n+1 constraints, where n is the number of input elements.
/// In most situations, we don't need n+1 constraints. Indeed, as discussed in [BCTV14],
/// one can compute the rank of a submatrix (denoted by r) and only need to add n+1-r
/// constraints, each corresponding to an input value that does not show up in the
/// submatrix after the Gaussian elimination.
///
/// We don't implement this n+1-r version because computing the rank of the submatrix
/// may contribute to a lot of computation.
///
use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{ConstraintSystemRef, Variable},
};

pub(crate) struct AugmentedQAP;

impl AugmentedQAP {
    /// Augment the R1CS system so that its augmented version would satisfy non-degeneracy.
    pub fn augment<F: PrimeField>(cs: ConstraintSystemRef<F>) -> ark_relations::r1cs::Result<()> {
        let input_size = cs.num_instance_variables();
        cs.enforce_constraint(lc!() + (F::one(), Variable::One), lc!(), lc!())?;
        for i in 1..input_size {
            cs.enforce_constraint(lc!() + (F::one(), Variable::Instance(i)), lc!(), lc!())?;
        }
        Ok(())
    }
}
