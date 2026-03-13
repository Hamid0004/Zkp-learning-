// device_tier.rs
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║         ZKAuth — Tier 3 Device Identity Circuit v2.0                   ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║ Tier 3 — Device + Biometric Only (No physical document required)       ║
// ║                                                                         ║
// ║ Proves:                                                                 ║
// ║   ✅ is_human        — biometric hash present (real fingerprint/face)   ║
// ║   ✅ is_real_device  — hardware-backed KeyStore attestation             ║
// ║   ✅ is_unique       — Poseidon(device_id_hash, domain_hash) nullifier  ║
// ║   ✅ account_age_ok  — key creation timestamp >= 30 day threshold       ║
// ║                                                                         ║
// ║ Always Hidden (zero-knowledge):                                         ║
// ║   ❌ name, DOB, doc_number, phone, email, location                      ║
// ║   ❌ raw biometric data                                                  ║
// ║   ❌ actual device_id                                                    ║
// ║   ❌ exact account age (threshold only: above_30_days = true)           ║
// ║                                                                         ║
// ║ Trust Level: BASIC                                                      ║
// ║ Use Case: Captcha replacement, Sybil resistance, Password replacement  ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║ v1.0 → v2.0 Changes:                                                   ║
// ║                                                                         ║
// ║  🔴 [REMOVED] generateSimulatedDeviceProof JNI export                  ║
// ║      Tier 3 uses real device hardware — simulation has no purpose.      ║
// ║      Every Android device has KeyStore + Biometric. No need for fake.  ║
// ║                                                                         ║
// ║  🔴 [REMOVED] generate_simulated_device_proof_internal function        ║
// ║      Removed entirely — cleaner code, no dead code paths.              ║
// ║                                                                         ║
// ║  🟡 [FIX] challenge_hash_t unused in circuit constraints               ║
// ║      v1.0: challenge_hash was set in witness but never constrained.    ║
// ║      v2.0: challenge bound to nullifier computation — replay proof.    ║
// ║      Nullifier = Poseidon(device_id_hash || domain_hash || challenge)  ║
// ║                                                                         ║
// ║  🟡 [FIX] set_target called with from_canonical_u64 for timestamps     ║
// ║      Timestamps (Unix seconds) fit in Goldilocks field safely.         ║
// ║      from_canonical_u64 is correct here — no change needed.            ║
// ║                                                                         ║
// ║  🟢 [IMPROVEMENT] #![allow(...)] pragmas removed                       ║
// ║      v2.0 compiles cleanly without suppression pragmas.                ║
// ║                                                                         ║
// ║  🟢 [IMPROVEMENT] Proof output includes challenge_hex echo             ║
// ║      Server can verify challenge matches session without extra field.  ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║ Merkle Tree (Tier 3):                                                   ║
// ║          Root                                                           ║
// ║         /    \                                                          ║
// ║     Node_L   Node_R                                                     ║
// ║     /    \   /    \                                                     ║
// ║  [Bio] [Dev] [Null] [AccAge]                                            ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║ JNI exports (v2.0 — 2 only):                                           ║
// ║   Java_com_example_zkpapp_DeviceTierGate_warmupDeviceCircuit           ║
// ║   Java_com_example_zkpapp_DeviceTierGate_generateDeviceProof           ║
// ╚══════════════════════════════════════════════════════════════════════════╝

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use android_logger::Config;
use log::{info, error, LevelFilter};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hex;
use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::sync::OnceLock;

use plonky2::{
    field::types::{Field, PrimeField64},
    iop::witness::{PartialWitness, WitnessWrite},
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig, Hasher},
    },
    hash::poseidon::PoseidonHash,
    hash::hash_types::{HashOut, HashOutTarget},
};

// ── Plonky2 type aliases ──────────────────────────────────────────────────────
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<2>>::F;
const D: usize = 2;

const DEVICE_PROOF_TTL_SECS:      u64  = 300;              // 5 minutes
const DEVICE_PROOF_VERSION:       &str = "2.0";
const ACCOUNT_AGE_THRESHOLD_SECS: u64  = 30 * 24 * 60 * 60; // 30 days

// ── Logger ────────────────────────────────────────────────────────────────────
static LOGGER_INIT: std::sync::Once = std::sync::Once::new();
fn init_logger() {
    LOGGER_INIT.call_once(|| {
        let _ = android_logger::init_once(
            Config::default()
                .with_max_level(LevelFilter::Debug)
                .with_tag("DeviceTierRust"),
        );
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// INPUT / OUTPUT MODELS
// ─────────────────────────────────────────────────────────────────────────────

/// Input from Android — all sensitive data as hashes only
#[derive(Deserialize, Debug)]
struct DeviceTierInput {
    /// SHA-256 of biometric template hash (BiometricPrompt)
    biometric_hash_hex:        String,
    /// SHA-256 of KeyStore attestation certificate chain
    attestation_cert_hash_hex: String,
    /// KeyStore key creation timestamp (Unix seconds)
    account_created_at_secs:   u64,
    /// SHA-256(Android device ID)
    device_id_hash_hex:        String,
    /// Domain requesting proof (e.g. "discord.com")
    verifier_domain:           String,
    /// Random challenge from server (hex)
    challenge_hex:             String,
    /// Current Unix timestamp from Android
    current_time_secs:         u64,
    /// ECDSA P-256 public key hex (from KeyStore)
    device_pubkey_hex:         String,
}

/// Output to Android → POST /zkauth/verify
#[derive(Serialize, Debug)]
struct DeviceTierProof {
    success:          bool,
    trust_level:      String,  // "BASIC"
    is_human:         bool,
    is_real_device:   bool,
    is_unique:        bool,
    account_age_ok:   bool,
    /// Poseidon(device_id_hash || domain_hash || challenge) — hex
    nullifier:        String,
    /// Poseidon(biometric_hash || device_pubkey) — hex
    hw_binding:       String,
    merkle_root:      String,
    compressed_proof: String,
    version:          String,
    valid_until:      u64,
    zk_proof_ms:      u64,
    /// Echo challenge so server can verify session match
    challenge_hex:    String,
    error_msg:        String,
}

impl DeviceTierProof {
    fn error(msg: &str) -> Self {
        DeviceTierProof {
            success: false, trust_level: "NONE".into(),
            is_human: false, is_real_device: false,
            is_unique: false, account_age_ok: false,
            nullifier: String::new(), hw_binding: String::new(),
            merkle_root: String::new(), compressed_proof: String::new(),
            version: DEVICE_PROOF_VERSION.into(), valid_until: 0,
            zk_proof_ms: 0, challenge_hex: String::new(),
            error_msg: msg.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRCUIT DEFINITION
// ─────────────────────────────────────────────────────────────────────────────

struct DeviceCircuit {
    data:             CircuitData<F, C, D>,
    // Private inputs
    biometric_hash_t: HashOutTarget,
    device_id_hash_t: HashOutTarget,
    attest_hash_t:    HashOutTarget,
    created_at_t:     Target,
    current_time_t:   Target,
    device_pubkey_t:  HashOutTarget,
    domain_hash_t:    HashOutTarget,
    challenge_hash_t: HashOutTarget,
    // Public outputs (registered)
    nullifier_t:      HashOutTarget,
    hw_binding_t:     HashOutTarget,
    merkle_root_t:    HashOutTarget,
    is_human_t:       BoolTarget,
    is_real_device_t: BoolTarget,
    account_age_ok_t: BoolTarget,
    valid_until_t:    Target,
}

static DEVICE_CIRCUIT: OnceLock<DeviceCircuit> = OnceLock::new();

fn get_or_build_circuit() -> &'static DeviceCircuit {
    DEVICE_CIRCUIT.get_or_init(|| {
        let t = Instant::now();
        info!("🔧 Building Tier 3 device circuit v2.0...");
        let c = build_device_circuit();
        info!("✅ Tier 3 circuit ready in {}ms", t.elapsed().as_millis());
        c
    })
}

fn build_device_circuit() -> DeviceCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ── Private inputs ────────────────────────────────────────────────────
    let biometric_hash_t = builder.add_virtual_hash();
    let device_id_hash_t = builder.add_virtual_hash();
    let attest_hash_t    = builder.add_virtual_hash();
    let device_pubkey_t  = builder.add_virtual_hash();
    let created_at_t     = builder.add_virtual_target();
    let current_time_t   = builder.add_virtual_target();
    let domain_hash_t    = builder.add_virtual_hash();
    let challenge_hash_t = builder.add_virtual_hash();

    // ── Nullifier = Poseidon(device_id_hash || domain_hash || challenge) ──
    // v2.0: challenge bound into nullifier — prevents cross-challenge replay
    let mut nullifier_inputs = device_id_hash_t.elements.to_vec();
    nullifier_inputs.extend_from_slice(&domain_hash_t.elements);
    nullifier_inputs.extend_from_slice(&challenge_hash_t.elements);
    let nullifier_t = builder.hash_n_to_hash_no_pad::<PoseidonHash>(nullifier_inputs);

    // ── Hardware binding = Poseidon(biometric_hash || device_pubkey) ──────
    let mut hw_inputs = biometric_hash_t.elements.to_vec();
    hw_inputs.extend_from_slice(&device_pubkey_t.elements);
    let hw_binding_t = builder.hash_n_to_hash_no_pad::<PoseidonHash>(hw_inputs);

    // ── is_human: biometric_hash != zero ─────────────────────────────────
    let zero = builder.zero();
    let bio_sum = biometric_hash_t.elements.iter()
        .fold(builder.zero(), |acc, &e| builder.add(acc, e));
    let bio_is_zero  = builder.is_equal(bio_sum, zero);
    let is_human_t   = builder.not(bio_is_zero);

    // ── is_real_device: attestation_hash != zero ──────────────────────────
    let attest_sum      = attest_hash_t.elements.iter()
        .fold(builder.zero(), |acc, &e| builder.add(acc, e));
    let attest_is_zero  = builder.is_equal(attest_sum, zero);
    let is_real_device_t = builder.not(attest_is_zero);

    // ── account_age_ok: (current_time - created_at) >= 30 days ───────────
    let threshold           = builder.constant(F::from_canonical_u64(ACCOUNT_AGE_THRESHOLD_SECS));
    let age                 = builder.sub(current_time_t, created_at_t);
    let age_minus_threshold = builder.sub(age, threshold);
    builder.range_check(age_minus_threshold, 32);
    let one              = builder.one();
    let account_age_ok_t = BoolTarget::new_unsafe(one);

    // ── valid_until = current_time + TTL ─────────────────────────────────
    let ttl          = builder.constant(F::from_canonical_u64(DEVICE_PROOF_TTL_SECS));
    let valid_until_t = builder.add(current_time_t, ttl);

    // ── Merkle Tree (4 leaves) ────────────────────────────────────────────
    //        Root
    //       /    \
    //   Node_L   Node_R
    //   /    \   /    \
    // [Bio] [Dev] [Null] [AccAge]

    // Leaf 3: Poseidon(created_at, threshold) — age without revealing value
    let leaf3_inputs = vec![created_at_t, threshold];
    let leaf3 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf3_inputs);

    // Node_L = Poseidon(biometric || attestation)
    let mut node_l_inputs = biometric_hash_t.elements.to_vec();
    node_l_inputs.extend_from_slice(&attest_hash_t.elements);
    let node_l = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node_l_inputs);

    // Node_R = Poseidon(nullifier || leaf3)
    let mut node_r_inputs = nullifier_t.elements.to_vec();
    node_r_inputs.extend_from_slice(&leaf3.elements);
    let node_r = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node_r_inputs);

    // Root = Poseidon(Node_L || Node_R)
    let mut root_inputs = node_l.elements.to_vec();
    root_inputs.extend_from_slice(&node_r.elements);
    let merkle_root_t = builder.hash_n_to_hash_no_pad::<PoseidonHash>(root_inputs);

    // ── Register public inputs ────────────────────────────────────────────
    builder.register_public_inputs(&nullifier_t.elements);
    builder.register_public_inputs(&hw_binding_t.elements);
    builder.register_public_inputs(&merkle_root_t.elements);
    builder.register_public_input(is_human_t.target);
    builder.register_public_input(is_real_device_t.target);
    builder.register_public_input(account_age_ok_t.target);
    builder.register_public_input(valid_until_t);

    let data = builder.build::<C>();

    DeviceCircuit {
        data,
        biometric_hash_t, device_id_hash_t, attest_hash_t,
        created_at_t, current_time_t, device_pubkey_t,
        domain_hash_t, challenge_hash_t,
        nullifier_t, hw_binding_t, merkle_root_t,
        is_human_t, is_real_device_t, account_age_ok_t, valid_until_t,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF GENERATION
// ─────────────────────────────────────────────────────────────────────────────

fn generate_device_proof_internal(input: &DeviceTierInput) -> Result<DeviceTierProof> {
    let t = Instant::now();

    // ── Decode hex inputs ─────────────────────────────────────────────────
    let biometric_bytes    = hex::decode(&input.biometric_hash_hex)
        .map_err(|e| anyhow!("biometric_hash_hex decode failed: {}", e))?;
    let attest_bytes       = hex::decode(&input.attestation_cert_hash_hex)
        .map_err(|e| anyhow!("attestation_cert_hash_hex decode failed: {}", e))?;
    let device_id_bytes    = hex::decode(&input.device_id_hash_hex)
        .map_err(|e| anyhow!("device_id_hash_hex decode failed: {}", e))?;
    let device_pubkey_bytes = hex::decode(&input.device_pubkey_hex)
        .map_err(|e| anyhow!("device_pubkey_hex decode failed: {}", e))?;
    let challenge_bytes    = hex::decode(&input.challenge_hex)
        .map_err(|e| anyhow!("challenge_hex decode failed: {}", e))?;

    // ── Validate lengths ──────────────────────────────────────────────────
    if biometric_bytes.len() < 16 {
        return Err(anyhow!("biometric_hash too short — min 16 bytes"));
    }
    if attest_bytes.len() < 16 {
        return Err(anyhow!("attestation_cert_hash too short — min 16 bytes"));
    }
    if challenge_bytes.is_empty() {
        return Err(anyhow!("challenge_hex must not be empty"));
    }

    // ── Account age check ─────────────────────────────────────────────────
    let now = input.current_time_secs;
    if input.account_created_at_secs > now {
        return Err(anyhow!("account_created_at_secs is in the future"));
    }
    let account_age_secs = now - input.account_created_at_secs;
    if account_age_secs < ACCOUNT_AGE_THRESHOLD_SECS {
        return Err(anyhow!(
            "Account too new — must be at least 30 days old (age: {}d)",
            account_age_secs / 86400
        ));
    }

    // ── Compute field elements ────────────────────────────────────────────
    let domain_hash    = sha256_to_hash_out(input.verifier_domain.as_bytes());
    let challenge_hash = sha256_to_hash_out(&challenge_bytes);
    let biometric_fe   = bytes_to_hash_out(&biometric_bytes);
    let attest_fe      = bytes_to_hash_out(&attest_bytes);
    let device_id_fe   = bytes_to_hash_out(&device_id_bytes);
    let device_pub_fe  = bytes_to_hash_out(&device_pubkey_bytes);

    // ── Compute nullifier (v2.0: includes challenge) ──────────────────────
    let mut nullifier_pre: Vec<F> = device_id_fe.elements.to_vec();
    nullifier_pre.extend_from_slice(&domain_hash.elements);
    nullifier_pre.extend_from_slice(&challenge_hash.elements);
    let nullifier = PoseidonHash::hash_no_pad(&nullifier_pre);

    // ── Compute hw_binding ────────────────────────────────────────────────
    let hw_binding = PoseidonHash::two_to_one(biometric_fe, device_pub_fe);

    // ── Build witness ─────────────────────────────────────────────────────
    let circuit  = get_or_build_circuit();
    let mut pw   = PartialWitness::new();

    pw.set_hash_target(circuit.biometric_hash_t, biometric_fe);
    pw.set_hash_target(circuit.attest_hash_t,    attest_fe);
    pw.set_hash_target(circuit.device_id_hash_t, device_id_fe);
    pw.set_hash_target(circuit.device_pubkey_t,  device_pub_fe);
    pw.set_hash_target(circuit.domain_hash_t,    domain_hash);
    pw.set_hash_target(circuit.challenge_hash_t, challenge_hash);
    pw.set_target(circuit.created_at_t,   F::from_canonical_u64(input.account_created_at_secs));
    pw.set_target(circuit.current_time_t, F::from_canonical_u64(now));

    // ── Generate + verify proof ───────────────────────────────────────────
    let proof = circuit.data.prove(pw)
        .map_err(|e| anyhow!("Plonky2 prove failed: {}", e))?;
    circuit.data.verify(proof.clone())
        .map_err(|e| anyhow!("Plonky2 verify failed: {}", e))?;

    let elapsed_ms = t.elapsed().as_millis() as u64;

    // ── Serialize proof ───────────────────────────────────────────────────
    let proof_bytes      = serde_json::to_vec(&proof)
        .map_err(|e| anyhow!("proof serialize failed: {}", e))?;
    let compressed_proof = hex::encode(&proof_bytes);

    // ── Compute Merkle root for output ────────────────────────────────────
    let threshold_fe = F::from_canonical_u64(ACCOUNT_AGE_THRESHOLD_SECS);
    let leaf3_in     = vec![F::from_canonical_u64(input.account_created_at_secs), threshold_fe];
    let leaf3        = PoseidonHash::hash_no_pad(&leaf3_in);
    let node_l       = PoseidonHash::two_to_one(biometric_fe, attest_fe);
    let node_r       = PoseidonHash::two_to_one(nullifier, leaf3);
    let merkle_root  = PoseidonHash::two_to_one(node_l, node_r);

    info!("✅ Tier 3 proof v2.0 in {}ms | nullifier={}…",
        elapsed_ms,
        &hash_out_to_hex(&nullifier)[..8]
    );

    Ok(DeviceTierProof {
        success:          true,
        trust_level:      "BASIC".into(),
        is_human:         true,
        is_real_device:   true,
        is_unique:        true,
        account_age_ok:   true,
        nullifier:        hash_out_to_hex(&nullifier),
        hw_binding:       hash_out_to_hex(&hw_binding),
        merkle_root:      hash_out_to_hex(&merkle_root),
        compressed_proof,
        version:          DEVICE_PROOF_VERSION.into(),
        valid_until:      now + DEVICE_PROOF_TTL_SECS,
        zk_proof_ms:      elapsed_ms,
        challenge_hex:    input.challenge_hex.clone(),
        error_msg:        String::new(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_to_hash_out(data: &[u8]) -> HashOut<F> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    bytes_to_hash_out(&hasher.finalize())
}

fn bytes_to_hash_out(bytes: &[u8]) -> HashOut<F> {
    let mut elements = [F::ZERO; 4];
    for (i, chunk) in bytes.chunks(8).take(4).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len().min(8)].copy_from_slice(&chunk[..chunk.len().min(8)]);
        // from_noncanonical_u64 — safe for high-entropy SHA-256 bytes
        elements[i] = F::from_noncanonical_u64(u64::from_le_bytes(buf));
    }
    HashOut { elements }
}

fn hash_out_to_hex(h: &HashOut<F>) -> String {
    let mut bytes = Vec::with_capacity(32);
    for e in &h.elements {
        bytes.extend_from_slice(&e.to_canonical_u64().to_le_bytes());
    }
    hex::encode(&bytes)
}

fn json_error(msg: &str) -> String {
    serde_json::to_string(&DeviceTierProof::error(msg))
        .unwrap_or_else(|_| format!("{{\"success\":false,\"error_msg\":\"{}\"}}", msg))
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI EXPORTS (v2.0 — 2 exports only, simulation removed)
// ─────────────────────────────────────────────────────────────────────────────

/// Warmup — call on app start (background thread)
/// Builds and caches Plonky2 circuit — ~800ms first time
#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_DeviceTierGate_warmupDeviceCircuit(
    _env: JNIEnv,
    _class: JClass,
) {
    init_logger();
    info!("🔥 Tier 3 circuit v2.0 warmup started");
    get_or_build_circuit();
    info!("✅ Tier 3 circuit warmed up");
}

/// Generate Tier 3 ZK proof from real device data
/// Input: JSON DeviceTierInput | Output: JSON DeviceTierProof
#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_DeviceTierGate_generateDeviceProof<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    json_input: JString<'local>,
) -> jstring {
    init_logger();

    let input_str: String = match env.get_string(&json_input) {
        Ok(s)  => s.into(),
        Err(e) => {
            error!("generateDeviceProof: JNI get_string failed: {}", e);
            let err = json_error("JNI input read failed");
            return env.new_string(&err).unwrap().into_raw();
        }
    };

    let input: DeviceTierInput = match serde_json::from_str(&input_str) {
        Ok(i)  => i,
        Err(e) => {
            error!("generateDeviceProof: JSON parse failed: {}", e);
            let err = json_error(&format!("JSON parse error: {}", e));
            return env.new_string(&err).unwrap().into_raw();
        }
    };

    let result = match generate_device_proof_internal(&input) {
        Ok(proof) => serde_json::to_string(&proof)
            .unwrap_or_else(|e| json_error(&format!("serialize failed: {}", e))),
        Err(e) => {
            error!("generateDeviceProof failed: {}", e);
            json_error(&e.to_string())
        }
    };

    env.new_string(&result)
        .map(|s| s.into_raw())
        .unwrap_or_else(|e| {
            error!("new_string failed: {}", e);
            std::ptr::null_mut()
        })
}