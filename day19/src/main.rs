use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

fn main() -> Result<()> {
    // 1. Setup Engine (Standard)
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Recursion ke liye 'standard_recursion_config' zaroori hai
    let config = CircuitConfig::standard_recursion_config();

    // =========================================================
    // 🔵 PART 1: THE INNER CIRCUIT (Worker) 👷
    // Logic: Prove I know x, such that x * x = 16
    // =========================================================
    println!("Step 1: Inner Circuit (Worker) bana rahe hain...");
    
    // Note: Hum config.clone() use kar rahe hain kyunki config dobara chahiye hoga
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    let x = builder.add_virtual_target();
    let x_squared = builder.mul(x, x);

    // Result ko Public banana zaroori hai taaki Manager dekh sake
    builder.register_public_input(x_squared); 

    let inner_data = builder.build::<C>();

    // --- Generate Inner Proof ---
    // Secret Input: 4
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(4)); 
    
    println!("   -> Inner Proof generate ho raha hai...");
    let inner_proof = inner_data.prove(pw)?;
    println!("   -> Worker ne Proof de diya! ✅");

    // =========================================================
    // 🔴 PART 2: THE OUTER CIRCUIT (Manager) 🤵
    // Logic: Verify that the Worker's Proof is valid
    // =========================================================
    println!("Step 2: Outer Circuit (Manager) bana rahe hain...");

    let mut outer_builder = CircuitBuilder::<F, D>::new(config);

    // 1. Manager ko batao ke Worker ka "Verify Key" kya hai
    let inner_verifier_data = outer_builder.constant_verifier_data(&inner_data.verifier_only);
    
    // 2. Manager ke circuit mein ek "Placeholder Proof" banao
    let inner_proof_target = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
    
    // 3. THE MAGIC LINE: Circuit ke andar Circuit verify karo! 🌀
   outer_builder.verify_proof::<C>(&inner_proof_target, &inner_verifier_data, &inner_data.common);

    let outer_data = outer_builder.build::<C>();

    // --- Generate Outer Proof ---
    println!("   -> Manager apna 'Super Proof' bana raha hai...");
    
    let mut outer_pw = PartialWitness::new();
    // Hum Manager ko bata rahe hain ke "Yeh lo Worker ka asli proof"
    outer_pw.set_proof_with_pis_target(&inner_proof_target, &inner_proof);

    let outer_proof = outer_data.prove(outer_pw)?;
    println!("   -> Super Proof Generated! 🚀");

    // =========================================================
    // 🟢 PART 3: FINAL VERIFICATION (CEO / Blockchain) 🤴
    // =========================================================
    println!("Step 3: Checking the Super Proof...");
    
    // Agar Outer Proof sahi hai, iska matlab Inner Proof bhi 100% sahi tha
    outer_data.verify(outer_proof)?;
    
    println!("RECURSION SUCCESSFUL! 🌀✅");
    println!("Proof of a Proof verify ho gaya.");

    Ok(())
}