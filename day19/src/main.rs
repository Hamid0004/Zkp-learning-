use plonky2::plonk::config::Hasher;
use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::hash::poseidon::PoseidonHash; // Hashing Engine

fn main() -> Result<()> {
    // 1. Setup Engine
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ---------------------------------------------------------
    // 🧠 CIRCUIT LOGIC (The Brain)
    // ---------------------------------------------------------

    // Step A: Private Input (User's Secret Balance)
    let balance_target = builder.add_virtual_target();
    // NOTE: Humne isay 'register_public_input' NAHI kiya, kyunki balance secret rakhna hai! 🤫

    // Step B: Logic 1 - Ownership Check (Hash) 🔐
    // Circuit balance ka Hash calculate karega
    let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![balance_target]);

    // Public Input: Wo hash jo Bank/Server ke paas saved hai
    let expected_hash_target = builder.add_virtual_hash();
    builder.register_public_input(expected_hash_target.elements[0]); // Public ko batao ke kis hash se compare karna hai

    // Constraint: Computed Hash == Public Hash
    builder.connect_hashes(computed_hash, expected_hash_target);

    // Step C: Logic 2 - Validity Check (Range) 💰
    // Rule: Balance must be >= 10,000
    let min_required = builder.constant(F::from_canonical_u64(10000));
    
    // Math Trick: Diff = Balance - 10,000
    let diff = builder.sub(balance_target, min_required);

    // Constraint: Diff must be a small positive number (Non-negative)
    // Agar balance < 10,000 hua, to diff wrap-around hoke huge number ban jayega aur fail hoga.
    builder.range_check(diff, 32); // 👈 Yeh Sahi hai (Tight security)
    //builder.range_check(diff, 64);  👈 Yeh Ghalat hai (Loose security)
    // ---------------------------------------------------------
    // 🏗️ BUILD & PROVE
    // ---------------------------------------------------------
    let data = builder.build::<C>();
    println!("Circuit Ready! (Hash + Range Check combined) 🔗");

    // --- Scenario: User ke paas 50,000 hain (Valid) ---
    let my_real_balance = F::from_canonical_u64(50000);
    
    // Server ke liye Hash calculate karte hain (Simulation)
    let my_balance_hash = PoseidonHash::hash_no_pad(&[my_real_balance]);

    // Witness (Saboot) bharna
    let mut pw = PartialWitness::new();
    pw.set_target(balance_target, my_real_balance);        // Secret Balance (50k)
    pw.set_hash_target(expected_hash_target, my_balance_hash); // Public Hash

    println!("Generating Proof... (Proving I own >10k without revealing 50k)");
    let proof = data.prove(pw)?;
    println!("Proof Generated! 🎉");

    // --- Verify ---
    data.verify(proof)?;
    println!("Verification Passed! 🟢 User owns the account AND has sufficient funds.");

    Ok(())
}