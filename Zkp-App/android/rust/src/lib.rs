use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
// 🟢 NEW: Added jbyteArray to the imports safely
use jni::sys::{jstring, jobject, jbyteArray}; 
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
pub mod proof_bench;   // Test Proof benchmark module
// 🟢 NEW: Day 89 Secure Vault module declaration
pub mod secure_vault;
//day 89 
pub mod zk_circuit;  

// =========================================================
// 🦁 JNI EXPORTS
// =========================================================

// ─── EXISTING — TOUCH NAHI KIYA ──────────────────────────────────────────────

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
    let input: String = env.get_string(&identity_json).expect("Invalid JSON").into();
    info!("Generating Proof for: {}", input);
    // let proof = zk_auth::prove_identity(input);
    let response = format!("Proof Generated for {}", input);
    env.new_string(response).expect("Failed to create string").into_raw()
}

// ─── NEW: Single run benchmark ────────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkpJni_runProofBenchmark(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    init_logger();
    info!("🧪 Test Proof Benchmark (single run) started");

    let result = proof_bench::run_benchmark();

    info!(
        "✅ Done → proof={}ms verify={}ms witness={}µs size={}bytes memory={}KB valid={}",
        result.proof_gen_ms, result.verify_ms,
        result.witness_gen_us, result.proof_size_bytes,
        result.memory_kb, result.is_valid
    );

    match build_result(&mut env, result) {
        Ok(obj) => obj,
        Err(e)  => { log::error!("JNI build failed: {}", e); *JObject::null() }
    }
}

// ─── NEW: Median of 3 runs (spike filter) ────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkpJni_runProofBenchmarkMedian(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    init_logger();
    info!("🧪 Test Proof Benchmark (median 3 runs) started");

    let result = proof_bench::run_benchmark_median();

    info!(
        "✅ Median Done → proof={}ms verify={}ms witness={}µs size={}bytes memory={}KB valid={}",
        result.proof_gen_ms, result.verify_ms,
        result.witness_gen_us, result.proof_size_bytes,
        result.memory_kb, result.is_valid
    );

    match build_result(&mut env, result) {
        Ok(obj) => obj,
        Err(e)  => { log::error!("JNI build failed: {}", e); *JObject::null() }
    }
}

// ── Helper: Rust BenchmarkResult → Kotlin ProofBenchmarkResult ───────────────
// Constructor signature:
// ProofBenchmarkResult(Long, Long, Long, Long, Long, Int, Boolean, String, Long, Long)
fn build_result(
    env: &mut JNIEnv,
    r: proof_bench::BenchmarkResult,
) -> Result<jobject, jni::errors::Error> {

    let class        = env.find_class("com/example/zkpapp/ProofBenchmarkResult")?;
    let error_jstr   = env.new_string(&r.error_msg)?;

    let obj = env.new_object(
        class,
        "(JJJJJIZLjava/lang/String;JJ)V",
        &[
            JValue::Long(r.circuit_setup_ms   as i64),  // circuitSetupMs
            JValue::Long(r.witness_gen_us      as i64),  // witnessGenUs  ✅
            JValue::Long(r.proof_gen_ms        as i64),  // proofGenMs
            JValue::Long(r.verify_ms           as i64),  // verifyMs
            JValue::Long(r.proof_size_bytes    as i64),  // proofSizeBytes
            JValue::Int(r.constraint_count     as i32),  // constraintCount
            JValue::Bool(r.is_valid            as u8),   // isValid
            JValue::Object(&error_jstr),                 // errorMsg
            JValue::Long(r.memory_kb           as i64),  // memoryKb      ✅
            JValue::Long(r.peak_memory_kb      as i64),  // peakMemoryKb  ✅
        ],
    )?;

    Ok(*obj)
}

// =========================================================
// 🟢 DAY 89: SECURE IDENTITY PROOF BRIDGE (CLEAN SEPARATION)
// =========================================================

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_SecureVaultJni_generateSecureIdentityProof<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    unlocked_seed: JString<'local>,
) -> jbyteArray { // 👈 FIX 1: Removed <'local> from jbyteArray
    
    init_logger(); 
    
    let seed_str: String = env
        .get_string(&unlocked_seed)
        .expect("JNI Panic: Failed to extract secure seed from Android!")
        .into();

    let output_bytes = secure_vault::process_secure_seed(seed_str);

    let byte_array = env.byte_array_from_slice(&output_bytes)
        .expect("JNI Panic: Failed to create output byte array");

    byte_array.into_raw() // 👈 FIX 2: Converted safe wrapper to raw C-pointer

}