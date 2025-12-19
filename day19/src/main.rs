use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use anyhow::Result;

fn main() -> Result<()> {
    // 1. Configuration (Speed settings)
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // 2. Circuit Builder (Robot Arm)
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 3. Define Logic (Proof: I know a number 'x')
    let x = builder.add_virtual_target(); // Input wire
    
    // Constraint: Hum x ko circuit mein register kar rahe hain
    builder.register_public_input(x);

    // 4. Build the Circuit (Finalize)
    let data = builder.build::<C>();

    // 5. Assign Secret Value (Witness)
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(42)); // Secret is 42

    // 6. Generate Proof
    println!("Generating proof...");
    let proof = data.prove(pw)?;
    println!("Proof generated successfully!");

    // 7. Verify Proof
    data.verify(proof)?;
    println!("Verification successful! ✅");

    Ok(())
}