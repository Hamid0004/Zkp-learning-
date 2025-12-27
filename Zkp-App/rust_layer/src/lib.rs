use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

// 👇 JNI Tools Import kiye (Android se baat karne ke liye)
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use std::ffi::CString;

// =============================================================
// 🌉 THE BRIDGE (JNI FUNCTION)
// Android sidha is function ko call karega via "runZkp()"
// =============================================================
#[no_mangle] // Rust ko bola: "Naam mat badalna please"
pub extern "system" fn Java_com_example_zkpapp_MainActivity_runZkp(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    
    // 1. Rust Logic Call karo
    let result = generate_identity_proof();

    // 2. Result ke hisaab se message decide karo
    let output_message = match result {
        Ok(_) => "SUCCESS: Proof Generated & Verified on Rust Layer! 🦀",
        Err(e) => {
            // Agar error aaye to usay string mein convert karo
            let error_msg = format!("ERROR: {}", e);
            // Rust string ko C-String mein badlo (memory leak se bachne ke liye safe way)
            Box::leak(error_msg.into_boxed_str()) 
        }
    };

    // 3. Rust String -> Java String convert karo
    let output = env.new_string(output_message).expect("Couldn't create java string!");
    
    // 4. Android ko wapis bhejo
    output.into_raw()
}

// =============================================================
// 🧠 CORE LOGIC (Jo kal likha tha - Same hai)
// =============================================================
fn generate_identity_proof() -> Result<()> {
    
    // 1. Setup Engine
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 2. Logic (Identity + Balance)
    let balance_target = builder.add_virtual_target();
    let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![balance_target]);
    let expected_hash_target = builder.add_virtual_hash();
    builder.register_public_input(expected_hash_target.elements[0]);
    builder.connect_hashes(computed_hash, expected_hash_target);

    let min_required = builder.constant(F::from_canonical_u64(10000));
    let diff = builder.sub(balance_target, min_required);
    builder.range_check(diff, 32); 

    let data = builder.build::<C>();

    // 3. Witness
    let my_real_balance = F::from_canonical_u64(50000);
    let my_balance_hash = PoseidonHash::hash_no_pad(&[my_real_balance]);

    let mut pw = PartialWitness::new();
    pw.set_target(balance_target, my_real_balance);
    pw.set_hash_target(expected_hash_target, my_balance_hash);

    let proof = data.prove(pw)?;
    data.verify(proof)?;

    Ok(())
}