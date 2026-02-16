use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use std::panic;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use android_logger::Config;
use log::{LevelFilter, info, error}; // 🦁 Removed unused 'warn'

use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::iop::target::Target;

use base64::{Engine as _, engine::general_purpose};
use once_cell::sync::Lazy;
use serde::Serialize;
use sha2::{Sha256, Digest};

// --- CONSTANTS ---
const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

const MAX_INPUT_LENGTH: usize = 1024;
const CIRCUIT_VERSION: &str = "1.0.0";

// --- GLOBAL COUNTER ---
static PROOF_COUNTER: AtomicU64 = AtomicU64::new(0);

// --- STRUCTS ---
// 🦁 CRITICAL STRUCT: Holds Data AND Targets
struct AuthCircuit {
    data: CircuitData<F, C, D>,
    t_secret: Target,
    t_domain: Target,
    t_challenge: Target,
    t_nullifier: Target,
    circuit_hash: String,
}

// 🦁 Safety Wrappers for Lazy Static
unsafe impl Sync for AuthCircuit {}
unsafe impl Send for AuthCircuit {}

// --- LAZY INITIALIZATION ---
static APP_CIRCUIT: Lazy<AuthCircuit> = Lazy::new(|| {
    info!("🦁 Initializing ZK Circuit...");
    
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 1. Define Input Targets
    let t_secret = builder.add_virtual_target();
    let t_domain = builder.add_virtual_target();
    let t_challenge = builder.add_virtual_target();

    // 2. Logic: Hash(Secret + Domain + Challenge) -> Nullifier
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        vec![t_secret, t_domain, t_challenge],
    );
    let t_nullifier = hash_out.elements[0];

    // 3. Public Inputs
    builder.register_public_input(t_domain);
    builder.register_public_input(t_challenge);
    builder.register_public_input(t_nullifier);

    let data = builder.build::<C>();

    // 🦁 FIX: 'num_gates' field does not exist. Use 'gates.len()'
    let num_gates = data.common.gates.len();

    // Compute Circuit Hash
    let mut hasher = Sha256::new();
    hasher.update(b"zkauth_v1");
    hasher.update(&num_gates.to_le_bytes()); 
    let hash_res = hasher.finalize();
    let hash_hex = hex::encode(&hash_res[..8]);

    info!("✅ Circuit Built! Gates: {}", num_gates);

    AuthCircuit {
        data,
        t_secret,
        t_domain,
        t_challenge,
        t_nullifier,
        circuit_hash: hash_hex,
    }
});

// --- JSON RESPONSE STRUCTS ---
#[derive(Serialize)]
struct ProofResponse {
    nullifier: String,
    proof: String,
    metadata: ProofMetadata,
}

#[derive(Serialize)]
struct ProofMetadata {
    generation_time_ms: u64,
    proof_size_bytes: usize,
    circuit_version: &'static str,
    circuit_hash: String,
    proof_id: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    error_code: &'static str,
}

#[derive(Serialize)]
struct CircuitInfoResponse {
    version: &'static str,
    circuit_hash: String,
    num_gates: usize,
    total_proofs: u64,
}

// --- HELPER FUNCTIONS ---

fn init_logger() {
    let _ = android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("ZkAuth"),
    );
}

fn string_to_field(input: &str) -> F {
    let bytes = input.as_bytes();
    let mut inputs = Vec::new();
    for b in bytes {
        inputs.push(F::from_canonical_u8(*b));
    }
    PoseidonHash::hash_no_pad(&inputs).elements[0]
}

// 🦁 FIX: Added 'static lifetime to 'code' to match Struct definition
fn create_error_json(msg: &str, code: &'static str) -> String {
    let err = ErrorResponse {
        error: msg.to_string(),
        error_code: code,
    };
    serde_json::to_string(&err).unwrap_or_default()
}

// --- CORE LOGIC ---

fn generate_proof_internal(
    secret: String,
    domain: String,
    challenge: String,
) -> Result<String, String> {
    
    // 1. Validation
    if secret.is_empty() { return Err(create_error_json("Secret empty", "INVALID_SECRET")); }
    if domain.len() > MAX_INPUT_LENGTH { return Err(create_error_json("Domain too long", "INVALID_DOMAIN")); }

    let proof_id = PROOF_COUNTER.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();
    
    // 2. Circuit Access
    let circuit = &*APP_CIRCUIT;

    // 3. Prepare Inputs
    let secret_f = string_to_field(&secret);
    let domain_f = string_to_field(&domain);
    let challenge_f = string_to_field(&challenge);

    // 🦁 FIX: Using stored targets ensures wires are connected correctly
    let mut pw = PartialWitness::new();
    pw.set_target(circuit.t_secret, secret_f);
    pw.set_target(circuit.t_domain, domain_f);
    pw.set_target(circuit.t_challenge, challenge_f);

    // 4. Prove
    let proof = circuit.data.prove(pw)
        .map_err(|e| {
            error!("Proving Error: {:?}", e);
            create_error_json("Internal Proving Failed", "PROOF_FAILED")
        })?;

    // 5. Serialize
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|_| create_error_json("Serialize Failed", "SERIALIZE_ERROR"))?;
    
    let proof_b64 = general_purpose::STANDARD.encode(&proof_bytes);
    
    // Extract Nullifier (Index 2: Domain, Challenge, Nullifier)
    let nullifier = proof.public_inputs[2].to_string();

    let duration = start.elapsed().as_millis() as u64;

    // 6. Final JSON Response
    let response = ProofResponse {
        nullifier,
        proof: proof_b64,
        metadata: ProofMetadata {
            generation_time_ms: duration,
            proof_size_bytes: proof_bytes.len(),
            circuit_version: CIRCUIT_VERSION,
            circuit_hash: circuit.circuit_hash.clone(),
            proof_id,
        }
    };

    info!("⚡ Proof #{} generated in {}ms", proof_id, duration);
    
    serde_json::to_string(&response)
        .map_err(|_| create_error_json("JSON Error", "JSON_ERROR"))
}


// --- JNI EXPORTS ---

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkAuth_generateSecureNullifier(
    mut env: JNIEnv,
    _class: JClass,
    secret_input: JString,
    domain_input: JString,
    challenge_input: JString,
) -> jstring {
    init_logger();

    // Safely Extract Strings
    let secret: String = match env.get_string(&secret_input) {
        Ok(v) => v.into(),
        Err(_) => return env.new_string(create_error_json("Bad Secret", "JNI_ERROR")).unwrap().into_raw(),
    };
    let domain: String = match env.get_string(&domain_input) {
        Ok(v) => v.into(),
        Err(_) => return env.new_string(create_error_json("Bad Domain", "JNI_ERROR")).unwrap().into_raw(),
    };
    let challenge: String = match env.get_string(&challenge_input) {
        Ok(v) => v.into(),
        Err(_) => return env.new_string(create_error_json("Bad Challenge", "JNI_ERROR")).unwrap().into_raw(),
    };

    // Panic Safe Execution
    let result = panic::catch_unwind(|| {
        generate_proof_internal(secret, domain, challenge)
    });

    // Handle Result
    let output_json = match result {
        Ok(Ok(json)) => json,
        Ok(Err(json_err)) => json_err,
        Err(_) => {
            error!("🔥 Rust Panic Occurred!");
            create_error_json("Internal Crash", "RUST_PANIC")
        }
    };

    env.new_string(output_json).unwrap().into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_ZkAuth_getCircuitInfo(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logger();

    let circuit = &*APP_CIRCUIT;
    
    // 🦁 FIX: Correct field access for gates length
    let info = CircuitInfoResponse {
        version: CIRCUIT_VERSION,
        circuit_hash: circuit.circuit_hash.clone(),
        num_gates: circuit.data.common.gates.len(), 
        total_proofs: PROOF_COUNTER.load(Ordering::Relaxed),
    };

    let json = serde_json::to_string(&info).unwrap_or_default();
    env.new_string(json).unwrap().into_raw()
}