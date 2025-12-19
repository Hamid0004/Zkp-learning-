use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

// 👇 YEH DO NAYI LINES ZAROORI HAIN
use plonky2::hash::poseidon::PoseidonHash; // Hashing Engine
use plonky2::plonk::config::Hasher;        // Calculation Tool

fn main() -> Result<()> {
    // 1. Setup: Engine start kar rahe hain
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // --- Circuit Design Shuru ---

    // 2. Private Input (Witness)
    let pin_target = builder.add_virtual_target();
    builder.register_public_input(pin_target); 

    // 3. Hashing Logic (FIXED HERE 🛠️)
    // Humne explicitly bataya ke "PoseidonHash" use karna hai
    let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![pin_target]);

    // 4. Public Input (Target Hash)
    let expected_hash_target = builder.add_virtual_hash();
    
    // (Sirf demo ke liye pehla hissa public kar rahe hain)
    builder.register_public_input(expected_hash_target.elements[0]); 

    // 5. The Constraint
    builder.connect_hashes(computed_hash, expected_hash_target);

    // --- Circuit Build Complete ---
    let data = builder.build::<C>();
    println!("Circuit design ready hai. Ab proof generate karte hain...");

    // --- Proof Generation (User Side) ---
    
    // Secret PIN '786'
    let my_secret_pin = F::from_canonical_u64(786);

    // Hashing Outside Circuit (FIXED HERE 🛠️)
    // 'HashOut' nahi, balki 'PoseidonHash' use hoga calculate karne ke liye
    let correct_hash = PoseidonHash::hash_no_pad(&[my_secret_pin]);

    // Ab Witness (Saboot) bharte hain
    let mut pw = PartialWitness::new();
    pw.set_target(pin_target, my_secret_pin);       
    pw.set_hash_target(expected_hash_target, correct_hash); 

    println!("Proof bana raha hoon... (Poseidon Hash calculate ho raha hai)");
    let proof = data.prove(pw)?;
    
    println!("Proof ban gaya! 🎉");

    // --- Verification (Server Side) ---
    data.verify(proof)?;
    
    println!("Verification Passed! 🟢 System maan gaya ke PIN sahi hai.");

    Ok(())
}