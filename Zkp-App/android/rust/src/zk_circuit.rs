use anyhow::Result;

// 🟢 THE FIX: Is import ko wapis daal diya taaki Math functions chal sakein!
use plonky2_field::types::Field; 

use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn generate_age_proof(secret_age: u32, threshold: u32) -> Result<Vec<u8>> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 1. Declare variables
    let age_target = builder.add_virtual_target();
    let threshold_target = builder.add_virtual_target();

    // 2. Dummy Constraint for testing the engine
    builder.connect(age_target, age_target);

    let data = builder.build::<C>();

    // 3. Assign values
    let mut pw = PartialWitness::new();
    
    // Yahan Field trait ka use ho raha hai number convert karne ke liye
    pw.set_target(age_target, F::from_canonical_u32(secret_age));
    pw.set_target(threshold_target, F::from_canonical_u32(threshold));

    // 4. Generate Proof
    let proof = data.prove(pw)?;
    Ok(proof.to_bytes())
}