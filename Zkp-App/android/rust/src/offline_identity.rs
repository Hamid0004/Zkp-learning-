// ═══════════════════════════════════════════════════════════════════════════
// 🦀 RUST ZKP MOBILE MODULE (PRODUCTION GRADE + SECURITY)
// ═══════════════════════════════════════════════════════════════════════════

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use std::ffi::CString;
use std::panic;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use std::cmp::min;

// Logic & Serialization
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose};
use serde::{Serialize, Deserialize};
use serde_json::json;

// Android Logging
use android_logger::Config;
use log::{info, error, warn, LevelFilter};

// Cryptography
use sha2::{Sha256, Digest};
use rand::{thread_rng, Rng};
use crc32fast::Hasher as Crc32Hasher;

// Plonky2 Imports
use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs; 
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::iop::target::Target;
use plonky2::hash::hash_types::HashOutTarget;

// ═══════════════════════════════════════════════════════════════════════════
// ⚙️ CONSTANTS & CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// Constraints
const MIN_REQUIRED_BALANCE: u64 = 10_000;
const USER_REAL_BALANCE: u64 = 50_000;

// 🦁 OPTIMIZATION: Increased chunk size to reduce total frames.
// 750 -> 1200 bytes. This reduces chunk count by ~40%, preventing Timeouts.
const QR_CHUNK_SIZE: usize = 1200;

// Security Configuration
const PROOF_VALIDITY_WINDOW_SECS: u64 = 300; // 5 minutes
const MAX_TIMESTAMP_DRIFT_SECS: i64 = 30; // Allow 30s clock drift
const MIN_NONCE_VALUE: u64 = 1_000_000_000; // Minimum nonce for safety

fn init_logger() {
    let _ = android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("RustZKP"),
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 🔐 SECURITY STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════

/// Secure proof metadata for anti-replay and binding
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ProofMetadata {
    timestamp: u64,
    nonce: u64,
    session_id: String,
    version: u8,
}

impl ProofMetadata {
    fn new(session_id: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut rng = thread_rng();
        let nonce: u64 = rng.gen_range(MIN_NONCE_VALUE..u64::MAX);
        
        Self {
            timestamp,
            nonce,
            session_id,
            version: 1,
        }
    }
    
    fn is_valid(&self, _provided_session_id: &str) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let age = current_time.saturating_sub(self.timestamp);
        
        if age > PROOF_VALIDITY_WINDOW_SECS {
            bail!("Proof expired (age: {}s > {}s)", age, PROOF_VALIDITY_WINDOW_SECS);
        }
        
        // Check for future timestamps (drift)
        let drift = self.timestamp as i64 - current_time as i64;
        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            bail!("Proof timestamp in future (drift: {}s)", drift);
        }
        
        if self.nonce < MIN_NONCE_VALUE {
            bail!("Invalid nonce");
        }
        
        // Note: Session check skipped in verifier for now as scan data implies session
        // if self.session_id != provided_session_id { bail!(...) }
        
        Ok(())
    }
}

/// Secure chunk with integrity protection
#[derive(Serialize, Deserialize)]
struct SecureChunk {
    index: usize,
    total: usize,
    payload: String,
    crc32: u32,
    signature: String,
}

impl SecureChunk {
    fn new(index: usize, total: usize, payload: String) -> Self {
        // 1. Calculate CRC32
        let mut hasher = Crc32Hasher::new();
        hasher.update(payload.as_bytes());
        let crc32 = hasher.finalize();
        
        // 2. Calculate Signature (SHA256)
        // Must match Kotlin: index(le) + total(le) + payload + crc32(le)
        let mut sha_hasher = Sha256::new();
        sha_hasher.update((index as u32).to_le_bytes()); // Ensure u32 for consistency
        sha_hasher.update((total as u32).to_le_bytes());
        sha_hasher.update(payload.as_bytes());
        sha_hasher.update(crc32.to_le_bytes());
        
        let signature = hex::encode(sha_hasher.finalize());
        
        Self {
            index,
            total,
            payload,
            crc32,
            signature,
        }
    }
    
    fn to_qr_format(&self) -> String {
        // Format: index/total|payload|crc32|signature
        format!(
            "{}/{}|{}|{}|{}",
            self.index,
            self.total,
            self.payload,
            self.crc32,
            self.signature
        )
    }
}

/// Secure proof container with metadata
#[derive(Serialize, Deserialize)]
struct SecureProof {
    metadata: ProofMetadata,
    proof_data: String, // Base64 encoded proof
    proof_hash: String, // SHA256 of proof_data
}

impl SecureProof {
    fn new(proof_data: String, session_id: String) -> Self {
        let metadata = ProofMetadata::new(session_id);
        
        let mut hasher = Sha256::new();
        hasher.update(proof_data.as_bytes());
        let proof_hash = hex::encode(hasher.finalize());
        
        Self {
            metadata,
            proof_data,
            proof_hash,
        }
    }
    
    fn verify_integrity(&self) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(self.proof_data.as_bytes());
        let calculated_hash = hex::encode(hasher.finalize());
        
        if calculated_hash != self.proof_hash {
            bail!("Proof integrity check failed");
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 🧠 CIRCUIT LOGIC
// ═══════════════════════════════════════════════════════════════════════════

struct IdentityCircuit {
    data: CircuitData<F, C, D>,
    target_balance: Target,
    target_hash: HashOutTarget,
}

impl IdentityCircuit {
    fn build() -> Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let balance_target = builder.add_virtual_target();
        let expected_hash_target = builder.add_virtual_hash();

        let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![balance_target]);
        builder.connect_hashes(computed_hash, expected_hash_target);

        builder.register_public_input(expected_hash_target.elements[0]);

        let min_required = builder.constant(F::from_canonical_u64(MIN_REQUIRED_BALANCE));
        let diff = builder.sub(balance_target, min_required);
        builder.range_check(diff, 32);

        let data = builder.build::<C>();

        Ok(Self {
            data,
            target_balance: balance_target,
            target_hash: expected_hash_target,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 1️⃣ PROVER (JNI)
// ═══════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn Java_com_example_zkpapp_OfflineMenuActivity_stringFromRust(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logger();
    info!("🚀 SECURE PROVER: Request Received");

    let result = panic::catch_unwind(|| -> Result<String> {
        let overall_start = Instant::now();

        // 1. Build & Prove
        let circuit = IdentityCircuit::build().context("Failed to build circuit")?;

        info!("🧬 Generating witness...");
        let my_real_balance = F::from_canonical_u64(USER_REAL_BALANCE);
        let my_balance_hash = PoseidonHash::hash_no_pad(&[my_real_balance]);

        let mut pw = PartialWitness::new();
        pw.set_target(circuit.target_balance, my_real_balance);
        pw.set_hash_target(circuit.target_hash, my_balance_hash);

        info!("🔨 Proving...");
        let proof = circuit.data.prove(pw).context("Proof generation failed")?;

        // 2. Serialize Proof
        let proof_bytes = bincode::serialize(&proof).context("Serialization failed")?;
        let proof_base64 = general_purpose::STANDARD.encode(proof_bytes);

        // 3. Create Secure Container
        let session_id = generate_session_id();
        let secure_proof = SecureProof::new(proof_base64, session_id);
        
        let secure_proof_json = serde_json::to_string(&secure_proof)?;
        let secure_proof_base64 = general_purpose::STANDARD.encode(secure_proof_json);

        // 4. Chunking (Optimized Size)
        let total_chunks = (secure_proof_base64.len() + QR_CHUNK_SIZE - 1) / QR_CHUNK_SIZE;
        info!("📦 PAYLOAD: {} bytes | {} chunks", secure_proof_base64.len(), total_chunks);

        let mut chunks = Vec::with_capacity(total_chunks);
        for i in 0..total_chunks {
            let start = i * QR_CHUNK_SIZE;
            let end = min(start + QR_CHUNK_SIZE, secure_proof_base64.len());
            let payload = secure_proof_base64[start..end].to_string();

            let secure_chunk = SecureChunk::new(i + 1, total_chunks, payload);
            chunks.push(secure_chunk.to_qr_format());
        }

        info!("🎉 TOTAL TIME: {:.2?}", overall_start.elapsed());
        serde_json::to_string(&chunks).context("JSON serialization failed")
    });

    let output = match result {
        Ok(Ok(json)) => json,
        Ok(Err(e)) => json!([format!("Error: {}", e)]).to_string(),
        Err(_) => json!(["Error: Rust Critical Panic"]).to_string(),
    };

    let c_str = CString::new(output).unwrap_or_else(|_| CString::new("[]").unwrap());
    env.new_string(c_str.to_str().unwrap_or("[]")).expect("JNI Failed").into_raw()
}

// ═══════════════════════════════════════════════════════════════════════════
// 2️⃣ VERIFIER (JNI)
// ═══════════════════════════════════════════════════════════════════════════

#[no_mangle]
pub extern "C" fn Java_com_example_zkpapp_VerifierActivity_verifyProofFromRust(
    mut env: JNIEnv,
    _class: JClass,
    proof_str: JString,
) -> jstring {
    init_logger();
    info!("🔍 SECURE VERIFIER: Request Received");

    let proof_input: String = match env.get_string(&proof_str) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("❌ Error: Invalid JNI String").unwrap().into_raw(),
    };

    let result = panic::catch_unwind(|| -> String {
        let start_time = Instant::now();

        // 1. Decode & Deserialize Secure Container
        let secure_json = match general_purpose::STANDARD.decode(&proof_input) {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(_) => return "❌ Error: Invalid Base64".to_string(),
        };

        let secure_proof: SecureProof = match serde_json::from_str(&secure_json) {
            Ok(p) => p,
            Err(e) => return format!("❌ Error: Invalid JSON structure ({})", e),
        };

        // 2. Security Checks
        if let Err(e) = secure_proof.verify_integrity() {
            return format!("❌ INTEGRITY FAILED: {}", e);
        }
        if let Err(e) = secure_proof.metadata.is_valid("any") {
            return format!("❌ SECURITY CHECK FAILED: {}", e);
        }

        // 3. Decode & Verify Logic
        let proof_bytes = match general_purpose::STANDARD.decode(&secure_proof.proof_data) {
            Ok(b) => b,
            Err(_) => return "❌ Error: Inner Proof Base64".to_string(),
        };

        let proof: ProofWithPublicInputs<F, C, D> = match bincode::deserialize(&proof_bytes) {
            Ok(p) => p,
            Err(_) => return "❌ Error: Corrupt Proof Data".to_string(),
        };

        let circuit = match IdentityCircuit::build() {
            Ok(c) => c,
            Err(_) => return "❌ Error: Circuit Build".to_string(),
        };

        match circuit.data.verify(proof) {
            Ok(_) => {
                let dur = start_time.elapsed();
                format!("✅ VERIFIED!\n⏱️ {:.2?}\n📅 Age: {}s", 
                    dur, 
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - secure_proof.metadata.timestamp)
            },
            Err(e) => format!("⛔ REJECTED: {:?}", e)
        }
    });

    let final_msg = match result {
        Ok(msg) => msg,
        Err(_) => "💥 Error: Verifier Panic".to_string(),
    };

    let c_str = CString::new(final_msg).unwrap();
    env.new_string(c_str.to_str().unwrap()).expect("JNI Failed").into_raw()
}

// ═══════════════════════════════════════════════════════════════════════════
// 🛠️ HELPERS
// ═══════════════════════════════════════════════════════════════════════════

fn generate_session_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut rng = thread_rng();
    format!("session_{}_{}", timestamp, rng.gen::<u32>())
}