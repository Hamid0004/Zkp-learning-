use jni::JNIEnv;
use jni::objects::{JClass, JObject, JValue, JByteArray}; // JString removed
use jni::sys::{jobject, jbyteArray};                     // jstring removed
#[cfg(target_os = "android")]
use android_logger::Config;
use log::{info, error, warn};
#[cfg(target_os = "android")]
use log::LevelFilter;
use std::sync::Once;

static LOGGER_INIT: Once = Once::new();

fn init_logger() {
    LOGGER_INIT.call_once(|| {
        #[cfg(target_os = "android")]
        let _ = android_logger::init_once(
            Config::default()
                .with_max_level(LevelFilter::Debug)
                .with_tag("RustZKP_Main"),
        );
    });
}

// ── Modules ───────────────────────────────────────────────────────────────────
// passport_security.rs defines its OWN #[no_mangle] JNI functions directly:
//   Java_com_example_zkpapp_SecurityGate_warmupCircuit
//   Java_com_example_zkpapp_SecurityGate_generateProof
//   Java_com_example_zkpapp_SecurityGate_generateSimulatedProof
//   Java_com_example_zkpapp_SecurityGate_generateClaimProof
//   Java_com_example_zkpapp_SecurityGate_generateSimulatedClaimProof
//
// device_tier.rs defines its OWN #[no_mangle] JNI functions directly:
//   Java_com_example_zkpapp_DeviceTierGate_warmupDeviceCircuit
//   Java_com_example_zkpapp_DeviceTierGate_generateDeviceProof
//   Java_com_example_zkpapp_DeviceTierGate_generateSimulatedDeviceProof

pub mod offline_identity;
pub mod passport_security;
pub mod device_tier;       // Tier 3 — Device + Biometric
pub mod proof_bench;
pub mod secure_vault;

// ══════════════════════════════════════════════════════════════════════════════
// ZkAuthManager — app init
// ══════════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn Java_com_example_zkpapp_ZkAuthManager_initRust(
    _env: JNIEnv,
    _class: JClass,
) {
    init_logger();
    info!("Rust ZKP Engine v5.1 | Tier 1 ✅ | Tier 3 ✅ Initialized");
}

// ══════════════════════════════════════════════════════════════════════════════
// ZkpJni — Benchmark functions
// ══════════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkpJni_runProofBenchmark(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    init_logger();
    info!("Benchmark (single run) started");
    let result = proof_bench::run_benchmark();
    info!(
        "Done proof={}ms verify={}ms witness={}us size={}bytes memory={}KB valid={}",
        result.proof_gen_ms, result.verify_ms, result.witness_gen_us,
        result.proof_size_bytes, result.memory_kb, result.is_valid
    );
    match build_benchmark_result(&mut env, result) {
        Ok(obj) => obj,
        Err(e)  => { error!("JNI build failed: {}", e); *JObject::null() }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkpJni_runProofBenchmarkMedian(
    mut env: JNIEnv,
    _class: JClass,
) -> jobject {
    init_logger();
    info!("Benchmark (median 3 runs) started");
    let result = proof_bench::run_benchmark_median();
    info!(
        "Median Done proof={}ms verify={}ms witness={}us size={}bytes memory={}KB valid={}",
        result.proof_gen_ms, result.verify_ms, result.witness_gen_us,
        result.proof_size_bytes, result.memory_kb, result.is_valid
    );
    match build_benchmark_result(&mut env, result) {
        Ok(obj) => obj,
        Err(e)  => { error!("JNI build failed: {}", e); *JObject::null() }
    }
}

fn build_benchmark_result(
    env: &mut JNIEnv,
    r: proof_bench::BenchmarkResult,
) -> Result<jobject, jni::errors::Error> {
    let class      = env.find_class("com/example/zkpapp/ProofBenchmarkResult")?;
    let error_jstr = env.new_string(&r.error_msg)?;
    let obj = env.new_object(
        class,
        "(JJJJJIZLjava/lang/String;JJ)V",
        &[
            JValue::Long(r.circuit_setup_ms as i64),
            JValue::Long(r.witness_gen_us   as i64),
            JValue::Long(r.proof_gen_ms     as i64),
            JValue::Long(r.verify_ms        as i64),
            JValue::Long(r.proof_size_bytes as i64),
            JValue::Int(r.constraint_count  as i32),
            JValue::Bool(r.is_valid         as u8),
            JValue::Object(&error_jstr),
            JValue::Long(r.memory_kb        as i64),
            JValue::Long(r.peak_memory_kb   as i64),
        ],
    )?;
    Ok(*obj)
}

// ══════════════════════════════════════════════════════════════════════════════
// SecureVaultJni
// ══════════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_SecureVaultJni_generateSecureIdentityProof<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    unlocked_seed_bytes: JByteArray<'local>,
) -> jbyteArray {
    init_logger();
    let seed_bytes: Vec<u8> = match env.convert_byte_array(&unlocked_seed_bytes) {
        Ok(b)  => b,
        Err(e) => {
            error!("generateSecureIdentityProof: seed extract failed: {}", e);
            return return_error_bytes(&mut env, b"JNI_ERROR:seed_read_failed");
        }
    };
    if seed_bytes.is_empty() {
        warn!("generateSecureIdentityProof: empty seed");
        return return_error_bytes(&mut env, b"JNI_ERROR:empty_seed");
    }
    let output_bytes = secure_vault::process_secure_seed(seed_bytes);
    match env.byte_array_from_slice(&output_bytes) {
        Ok(arr) => arr.into_raw(),
        Err(e)  => {
            error!("generateSecureIdentityProof: output array failed: {}", e);
            std::ptr::null_mut()
        }
    }
}

fn return_error_bytes(env: &mut JNIEnv, msg: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(msg)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}