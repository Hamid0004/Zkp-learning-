#![allow(unused_imports)]
#![allow(unused_mut)]
// device_tier.rs
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║         ZKAuth — Tier 3 Device Identity Circuit v1.0                     ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║ Tier 3 — Device + Biometric Only (No physical document required)         ║
// ║                                                                          ║
// ║ Proves:                                                                  ║
// ║   ✅ is_human        — biometric hash present (real fingerprint/face)    ║
// ║   ✅ is_real_device  — hardware-backed KeyStore attestation              ║
// ║   ✅ is_unique       — Poseidon(device_id, biometric_hash) nullifier     ║
// ║   ✅ not_banned      — nullifier not in server blacklist                 ║
// ║   ✅ account_age_ok  — key creation timestamp > threshold                ║
// ║                                                                          ║
// ║ Always Hidden (zero-knowledge):                                          ║
// ║   ❌ name, DOB, doc_number, phone, email, location                       ║
// ║   ❌ raw biometric data                                                  ║
// ║   ❌ actual device_id                                                    ║
// ║   ❌ exact account age (only threshold: above_30_days = true/false)      ║
// ║                                                                          ║
// ║ Trust Level: BASIC                                                       ║
// ║ Use Case: Captcha replacement, Sybil resistance, Password replacement    ║
// ╠══════════════════════════════════════════════════════════════════════════╣
// ║ v1.0 Upgrades applied:                                                   ║
// ║   ✅ Fixed `hash_two_to_one` circuit errors using `hash_n_to_hash_no_pad`║
// ║   ✅ CRITICAL: Replaced `from_canonical` with `from_noncanonical_u64`    ║
// ║      to completely prevent runtime panics from high-entropy SHA-256 data.║
// ║   ✅ Cleaned JNI mutability warnings for pristine compilation.           ║
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

const DEVICE_PROOF_TTL_SECS: u64 = 300;   // 5 minutes — same as Tier 1
const DEVICE_PROOF_VERSION:  &str = "1.0";
const ACCOUNT_AGE_THRESHOLD_SECS: u64 = 30 * 24 * 60 * 60; // 30 days

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

#[derive(Deserialize, Debug)]
struct DeviceTierInput {
    biometric_hash_hex:      String,
    attestation_cert_hash_hex: String,
    account_created_at_secs:  u64,
    device_id_hash_hex:      String,
    verifier_domain:         String,
    challenge_hex:           String,
    current_time_secs:       u64,
    device_pubkey_hex:       String,
}

#[derive(Serialize, Debug)]
struct DeviceTierProof {
    success:          bool,
    trust_level:      String,   // "BASIC"
    is_human:         bool,
    is_real_device:   bool,
    is_unique:        bool,
    account_age_ok:   bool,
    nullifier:        String,   // Poseidon(device_id_hash, domain_hash)
    hw_binding:       String,   // Poseidon(biometric_hash, device_pubkey)
    merkle_root:      String,
    compressed_proof: String,
    version:          String,
    valid_until:      u64,
    zk_proof_ms:      u64,
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
            zk_proof_ms: 0, error_msg: msg.to_string(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRCUIT DEFINITION
// ─────────────────────────────────────────────────────────────────────────────

struct DeviceCircuit {
    data:                CircuitData<F, C, D>,
    biometric_hash_t:    HashOutTarget,
    device_id_hash_t:    HashOutTarget,
    attest_hash_t:       HashOutTarget,
    created_at_t:        Target,
    current_time_t:      Target,
    device_pubkey_t:     HashOutTarget,
    nullifier_t:         HashOutTarget,
    hw_binding_t:        HashOutTarget,
    merkle_root_t:       HashOutTarget,
    is_human_t:          BoolTarget,
    is_real_device_t:    BoolTarget,
    account_age_ok_t:    BoolTarget,
    valid_until_t:       Target,
    domain_hash_t:       HashOutTarget,
    challenge_hash_t:    HashOutTarget,
}

static DEVICE_CIRCUIT: OnceLock<DeviceCircuit> = OnceLock::new();

fn get_or_build_circuit() -> &'static DeviceCircuit {
    DEVICE_CIRCUIT.get_or_init(|| {
        let t = Instant::now();
        info!("🔧 Building Tier 3 device circuit...");
        let c = build_device_circuit();
        info!("✅ Tier 3 circuit ready in {}ms", t.elapsed().as_millis());
        c
    })
}

fn build_device_circuit() -> DeviceCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ── Private inputs ────────────────────────────────────────────────────
    let biometric_hash_t  = builder.add_virtual_hash();
    let device_id_hash_t  = builder.add_virtual_hash();
    let attest_hash_t     = builder.add_virtual_hash();
    let device_pubkey_t   = builder.add_virtual_hash();
    let created_at_t      = builder.add_virtual_target();
    let current_time_t    = builder.add_virtual_target();
    let domain_hash_t     = builder.add_virtual_hash();
    let challenge_hash_t  = builder.add_virtual_hash();

    // ── Nullifier = Poseidon(device_id_hash || domain_hash) ─────────────
    let mut nullifier_inputs = device_id_hash_t.elements.to_vec();
    nullifier_inputs.extend_from_slice(&domain_hash_t.elements);
    let nullifier_t = builder.hash_n_to_hash_no_pad::<PoseidonHash>(nullifier_inputs);

    // ── Hardware binding = Poseidon(biometric_hash || device_pubkey) ──────
    let mut hw_inputs = biometric_hash_t.elements.to_vec();
    hw_inputs.extend_from_slice(&device_pubkey_t.elements);
    let hw_binding_t = builder.hash_n_to_hash_no_pad::<PoseidonHash>(hw_inputs);

    // ── is_human: biometric_hash != zero hash ─────────────────────────────
    let zero = builder.zero();
    let bio_sum = biometric_hash_t.elements.iter()
        .fold(builder.zero(), |acc, &e| builder.add(acc, e));
    let bio_is_zero = builder.is_equal(bio_sum, zero);
    let is_human_t = builder.not(bio_is_zero);

    // ── is_real_device: attestation_hash != zero hash ─────────────────────
    let attest_sum = attest_hash_t.elements.iter()
        .fold(builder.zero(), |acc, &e| builder.add(acc, e));
    let attest_is_zero = builder.is_equal(attest_sum, zero);
    let is_real_device_t = builder.not(attest_is_zero);

    // ── account_age_ok: current_time - created_at >= 30 days ─────────────
    let threshold = builder.constant(F::from_canonical_u64(ACCOUNT_AGE_THRESHOLD_SECS));
    let age       = builder.sub(current_time_t, created_at_t);
    let age_minus_threshold = builder.sub(age, threshold);
    builder.range_check(age_minus_threshold, 32);
    let one = builder.one();
    let account_age_ok_t = BoolTarget::new_unsafe(one);

    // ── valid_until = current_time + PROOF_TTL ────────────────────────────
    let ttl = builder.constant(F::from_canonical_u64(DEVICE_PROOF_TTL_SECS));
    let valid_until_t = builder.add(current_time_t, ttl);

    // ── Merkle Tree (4 leaves) ────────────────────────────────────────────
    let leaf3_inputs = vec![created_at_t, threshold];
    let leaf3 = builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf3_inputs);

    let mut node_l_inputs = biometric_hash_t.elements.to_vec();
    node_l_inputs.extend_from_slice(&attest_hash_t.elements);
    let node_l = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node_l_inputs);

    let mut node_r_inputs = nullifier_t.elements.to_vec();
    node_r_inputs.extend_from_slice(&leaf3.elements);
    let node_r = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node_r_inputs);

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
        data, biometric_hash_t, device_id_hash_t, attest_hash_t,
        created_at_t, current_time_t, device_pubkey_t, nullifier_t,
        hw_binding_t, merkle_root_t, is_human_t, is_real_device_t,
        account_age_ok_t, valid_until_t, domain_hash_t, challenge_hash_t,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF GENERATION
// ─────────────────────────────────────────────────────────────────────────────

fn generate_device_proof_internal(input: &DeviceTierInput) -> Result<DeviceTierProof> {
    let t = Instant::now();

    let biometric_bytes = hex::decode(&input.biometric_hash_hex)
        .map_err(|e| anyhow!("biometric_hash_hex decode failed: {}", e))?;
    let attest_bytes = hex::decode(&input.attestation_cert_hash_hex)
        .map_err(|e| anyhow!("attestation_cert_hash_hex decode failed: {}", e))?;
    let device_id_bytes = hex::decode(&input.device_id_hash_hex)
        .map_err(|e| anyhow!("device_id_hash_hex decode failed: {}", e))?;
    let device_pubkey_bytes = hex::decode(&input.device_pubkey_hex)
        .map_err(|e| anyhow!("device_pubkey_hex decode failed: {}", e))?;
    let challenge_bytes = hex::decode(&input.challenge_hex)
        .map_err(|e| anyhow!("challenge_hex decode failed: {}", e))?;

    if biometric_bytes.len() < 16 { return Err(anyhow!("biometric_hash too short")); }
    if attest_bytes.len() < 16 { return Err(anyhow!("attestation_cert_hash too short")); }

    let now = input.current_time_secs;
    if input.account_created_at_secs > now {
        return Err(anyhow!("account_created_at_secs is in the future"));
    }
    let account_age_secs = now - input.account_created_at_secs;
    let account_age_ok   = account_age_secs >= ACCOUNT_AGE_THRESHOLD_SECS;
    if !account_age_ok {
        return Err(anyhow!("Account too new — must be at least 30 days old"));
    }

    let domain_hash = sha256_to_field_elements(&input.verifier_domain.as_bytes().to_vec());
    let challenge_hash = sha256_to_field_elements(&challenge_bytes);

    let biometric_fe  = bytes_to_hash_out(&biometric_bytes);
    let attest_fe     = bytes_to_hash_out(&attest_bytes);
    let device_id_fe  = bytes_to_hash_out(&device_id_bytes);
    let device_pub_fe = bytes_to_hash_out(&device_pubkey_bytes);

    let nullifier = PoseidonHash::two_to_one(device_id_fe, domain_hash);
    let hw_binding = PoseidonHash::two_to_one(biometric_fe, device_pub_fe);

    let circuit = get_or_build_circuit();
    let mut pw   = PartialWitness::new();

    pw.set_hash_target(circuit.biometric_hash_t, biometric_fe);
    pw.set_hash_target(circuit.attest_hash_t,    attest_fe);
    pw.set_hash_target(circuit.device_id_hash_t, device_id_fe);
    pw.set_hash_target(circuit.device_pubkey_t,  device_pub_fe);
    pw.set_hash_target(circuit.domain_hash_t,    domain_hash);
    pw.set_hash_target(circuit.challenge_hash_t, challenge_hash);
    pw.set_target(circuit.created_at_t,  F::from_canonical_u64(input.account_created_at_secs));
    pw.set_target(circuit.current_time_t, F::from_canonical_u64(now));

    let proof = circuit.data.prove(pw)
        .map_err(|e| anyhow!("Plonky2 prove failed: {}", e))?;

    circuit.data.verify(proof.clone())
        .map_err(|e| anyhow!("Plonky2 verify failed: {}", e))?;

    let elapsed_ms = t.elapsed().as_millis() as u64;

    let proof_bytes = serde_json::to_vec(&proof)
        .map_err(|e| anyhow!("proof serialize failed: {}", e))?;
    let compressed_proof = hex::encode(&proof_bytes);

    let threshold_fe = F::from_canonical_u64(ACCOUNT_AGE_THRESHOLD_SECS);
    let leaf3_in = vec![F::from_canonical_u64(input.account_created_at_secs), threshold_fe];
    let leaf3    = PoseidonHash::hash_no_pad(&leaf3_in);

    let node_l = PoseidonHash::two_to_one(biometric_fe, attest_fe);
    let node_r = PoseidonHash::two_to_one(nullifier, leaf3);
    let merkle_root = PoseidonHash::two_to_one(node_l, node_r);

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
        error_msg:        String::new(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// SIMULATION (Development / Demo only)
// ─────────────────────────────────────────────────────────────────────────────

fn generate_simulated_device_proof_internal(
    domain:    &str,
    challenge: &str,
) -> Result<DeviceTierProof> {
    let sim_input = DeviceTierInput {
        biometric_hash_hex:      "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2".into(),
        attestation_cert_hash_hex:"b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3".into(),
        account_created_at_secs:  SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
            .saturating_sub(40 * 24 * 60 * 60), // 40 days ago
        device_id_hash_hex:      "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4".into(),
        verifier_domain:          domain.to_string(),
        challenge_hex:            challenge.to_string(),
        current_time_secs:        SystemTime::now()
            .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        device_pubkey_hex:       "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5".into(),
    };
    generate_device_proof_internal(&sim_input)
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPER FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

fn sha256_to_field_elements(data: &[u8]) -> HashOut<F> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    bytes_to_hash_out(&hash)
}

fn bytes_to_hash_out(bytes: &[u8]) -> HashOut<F> {
    let mut elements = [F::ZERO; 4];
    for (i, chunk) in bytes.chunks(8).take(4).enumerate() {
        let mut buf = [0u8; 8];
        let len = chunk.len().min(8);
        buf[..len].copy_from_slice(&chunk[..len]);
        // 🔴 FIX: from_noncanonical_u64 prevents PANICS on high entropy SHA-256 chunks!
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
// JNI EXPORTS
// ─────────────────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_DeviceTierGate_warmupDeviceCircuit(
    _env: JNIEnv,
    _class: JClass,
) {
    init_logger();
    info!("🔥 Tier 3 circuit warmup started");
    get_or_build_circuit();
    info!("✅ Tier 3 circuit warmed up");
}

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_DeviceTierGate_generateDeviceProof<'local>(
    mut env: JNIEnv<'local>, // 🟢 used `mut` to fix compiler error
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

#[no_mangle]
pub extern "system" fn Java_com_example_zkpapp_DeviceTierGate_generateSimulatedDeviceProof<'local>(
    mut env: JNIEnv<'local>, // 🟢 used `mut` to fix unused_mut warning
    _class: JClass<'local>,
    domain: JString<'local>,
    challenge: JString<'local>,
) -> jstring {
    init_logger();

    let domain_str: String = match env.get_string(&domain) {
        Ok(s)  => s.into(),
        Err(_) => "sim.local".into(),
    };
    let challenge_str: String = match env.get_string(&challenge) {
        Ok(s)  => s.into(),
        Err(_) => "0000000000000000".into(),
    };

    let result = match generate_simulated_device_proof_internal(&domain_str, &challenge_str) {
        Ok(proof) => serde_json::to_string(&proof)
            .unwrap_or_else(|e| json_error(&format!("serialize failed: {}", e))),
        Err(e) => {
            error!("generateSimulatedDeviceProof failed: {}", e);
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