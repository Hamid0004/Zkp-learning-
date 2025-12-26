use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

// 👇 Note: Yahan 'main' nahi hai. Yeh ek normal function hai.
// Hum isay kal JNI (Android) se connect karenge.
pub fn generate_identity_proof() -> Result<()> {
    
    println!("🦀 Rust: Circuit banana shuru kar raha hoon...");

    // 1. Setup Engine
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ---------------------------------------------------------
    // 🧠 CIRCUIT LOGIC (Same as Day 22)
    // ---------------------------------------------------------

    // A. Balance Input
    let balance_target = builder.add_virtual_target();

    // B. Hash Check (Identity)
    let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![balance_target]);
    let expected_hash_target = builder.add_virtual_hash();
    builder.register_public_input(expected_hash_target.elements[0]);
    builder.connect_hashes(computed_hash, expected_hash_target);

    // C. Range Check (Balance >= 10,000) with 32-bit safety
    let min_required = builder.constant(F::from_canonical_u64(10000));
    let diff = builder.sub(balance_target, min_required);
    builder.range_check(diff, 32); // 🔒 Secure check

    // ---------------------------------------------------------
    // 🏗️ BUILD & PROVE
    // ---------------------------------------------------------
    let data = builder.build::<C>();
    println!("🦀 Rust: Circuit Ready! Proof generate kar raha hoon...");

    // --- Inputs ---
    let my_real_balance = F::from_canonical_u64(50000);
    let my_balance_hash = PoseidonHash::hash_no_pad(&[my_real_balance]);

    // --- Witness ---
    let mut pw = PartialWitness::new();
    pw.set_target(balance_target, my_real_balance);
    pw.set_hash_target(expected_hash_target, my_balance_hash);

    let proof = data.prove(pw)?;
    
    // Important: Proof verify karke dekhte hain ke sab sahi hai ya nahi
    data.verify(proof)?;
    
    println!("🦀 Rust: Proof Generated & Verified Successfully! ✅");

    Ok(())
}
