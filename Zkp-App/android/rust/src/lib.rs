use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jstring, jobject};
use android_logger::Config;
use log::{LevelFilter, info};

// 1. Logger Setup
fn init_logger() {
    let _ = android_logger::init_once(
        Config::default().with_max_level(LevelFilter::Debug).with_tag("RustZKP_Main"),
    );
}

// 2. Module Declarations
pub mod offline_identity;
pub mod passport_security;
pub mod zk_auth;
pub mod proof_bench;   // ← NEW: Test Proof benchmark module

// =========================================================
// 🦁 JNI EXPORTS (The Bridge)
// Note: Function names MUST match your Java/Kotlin package
// =========================================================

// ─── EXISTING — BILKUL TOUCH NAHI KIYA ───────────────────────────────────────

#[no_mangle]
pub extern "C" fn Java_com_example_zkpapp_ZkAuthManager_initRust(
    _env: JNIEnv,
    _class: JClass,
) {
    init_logger();
    info!("🦁 Rust ZKP Engine Initialized!");
}

#[no_mangle]
pub extern "C" fn Java_com_example_zkpapp_ZkAuthManager_generateZkpProof(
    mut env: JNIEnv,
    _class: JClass,
    identity_json: JString,
) -> jstring {
    // 🦁 Yeh line Plonky2 ko link karegi
    // Hum zk_auth module se function call kar rahe hain
    let input: String = env.get_string(&identity_json).expect("Invalid JSON").into();
    
    info!("Generating Proof for: {}", input);

    // Placeholder for calling your actual ZK logic
    // let proof = zk_auth::prove_identity(input); 
    
    let response = format!("Proof Generated for {}", input);
    env.new_string(response).expect("Failed to create string").into_raw()
}

// ─── NEW — TEST PROOF BENCHMARK ───────────────────────────────────────────────
//
// TestProofActivity → ZkpJni.kt → yahan aata hai → proof_bench.rs

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkpJni_runProofBenchmark(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    init_logger();
    info!("🧪 Test Proof Benchmark Started!");

    // proof_bench.rs se actual Plonky2 benchmark run karo
    let result = proof_bench::run_benchmark();

    info!(
        "✅ Done → proof={}ms  verify={}ms  size={}bytes  valid={}",
        result.proof_gen_ms,
        result.verify_ms,
        result.proof_size_bytes,
        result.is_valid
    );

    // Kotlin ProofBenchmarkResult object banao
    match build_benchmark_result(&mut env, result) {
        Ok(obj) => obj,
        Err(e) => {
            log::error!("JNI object build failed: {}", e);
            *JObject::null()
        }
    }
}

// ── Helper: Rust BenchmarkResult → Kotlin ProofBenchmarkResult ───────────────
fn build_benchmark_result(
    env: &mut JNIEnv,
    result: proof_bench::BenchmarkResult,
) -> Result<jobject, jni::errors::Error> {

    // Kotlin class: com.example.zkpapp.ProofBenchmarkResult
    let class = env.find_class("com/example/zkpapp/ProofBenchmarkResult")?;

    let error_jstring = env.new_string(&result.error_msg)?;

    // Constructor signature Kotlin data class se match karta hai:
    // ProofBenchmarkResult(Long, Long, Long, Long, Long, Int, Boolean, String)
    let obj = env.new_object(
        class,
        "(JJJJJIZLjava/lang/String;)V",
        &[
            JValue::Long(result.circuit_setup_ms as i64),  // circuitSetupMs
            JValue::Long(result.witness_gen_ms   as i64),  // witnessGenMs
            JValue::Long(result.proof_gen_ms     as i64),  // proofGenMs
            JValue::Long(result.verify_ms        as i64),  // verifyMs
            JValue::Long(result.proof_size_bytes as i64),  // proofSizeBytes
            JValue::Int(result.constraint_count  as i32),  // constraintCount
            JValue::Bool(result.is_valid         as u8),   // isValid
            JValue::Object(&error_jstring),                // errorMsg
        ],
    )?;

    Ok(*obj)
}