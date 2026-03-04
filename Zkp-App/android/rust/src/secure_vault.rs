use hkdf::Hkdf;
use log::{info, warn};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use plonky2_field::goldilocks_field::GoldilocksField as F;
use plonky2_field::types::Field;
use plonky2_field::types::PrimeField64;  // 
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ZKP_APP_SALT: &[u8] = b"Mariana_Trench_ZKP_Vault_Salt_v2";
const MASTER_KEY_INFO: &[u8] = b"Plonky2_Circuit_Master_Key";
const MASTER_KEY_LEN: usize = 32;

/// Goldilocks field elements safely fit 56 bits (7 bytes) of payload.
const BYTES_PER_FIELD_ELEMENT: usize = 7;

// ---------------------------------------------------------------------------
// Attribute context IDs — extend as the identity schema grows.
// ---------------------------------------------------------------------------

mod attr {
    pub const NAME: u64 = 101;
    pub const AGE: u64 = 102;
    pub const NATIONALITY: u64 = 103;
    pub const PADDING: u64 = 104;
}

// ---------------------------------------------------------------------------
// Field packing
// ---------------------------------------------------------------------------

/// Packs arbitrary bytes into Goldilocks field elements (7 bytes → 1 element).
/// This reduces Plonky2 circuit constraints by ~7× compared to byte-per-element
/// encoding.
fn pack_bytes_to_field(data: &[u8]) -> Vec<F> {
    data.chunks(BYTES_PER_FIELD_ELEMENT)
        .map(|chunk| {
            let val = chunk
                .iter()
                .enumerate()
                .fold(0u64, |acc, (i, &b)| acc | ((b as u64) << (i * 8)));
            F::from_canonical_u64(val)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Per-attribute blinding
// ---------------------------------------------------------------------------

/// Derives a unique per-leaf blinding salt from the master key and an attribute
/// context ID via Poseidon. This prevents cross-attribute correlation.
fn derive_leaf_salt(master_key: &[F], context_id: u64) -> Vec<F> {
    let mut input = master_key.to_vec();
    input.push(F::from_canonical_u64(context_id));
    PoseidonHash::hash_no_pad(&input).elements.to_vec()
}

/// Produces a SNARK-friendly blinded leaf: H_poseidon(leaf_salt || data).
fn blinded_leaf(salt: &[F], data: &[F]) -> HashOut<F> {
    let mut input = salt.to_vec();
    input.extend_from_slice(data);
    PoseidonHash::hash_no_pad(&input)
}

// ---------------------------------------------------------------------------
// Merkle tree construction (depth-2, 4-leaf balanced binary tree)
// ---------------------------------------------------------------------------

/// Uses Plonky2's dedicated Merkle node hasher so off-circuit and on-circuit
/// (`builder.hash_two_to_one`) produce identical digests.
fn hash_pair(left: &HashOut<F>, right: &HashOut<F>) -> HashOut<F> {
    PoseidonHash::two_to_one(*left, *right)
}

/// Builds a 4-leaf Poseidon Merkle tree and returns the 32-byte root.
///
/// Tree layout:
/// ```
///         root
///        /    \
///     node_l  node_r
///     /    \  /    \
///   name  age nat  pad
/// ```
fn build_merkle_root(master_key: &[F]) -> Vec<u8> {
    // Attribute payloads — replace with runtime identity data in production.
    let leaves_raw: &[(&[u8], u64)] = &[
        (b"Name: Ali",       attr::NAME),
        (b"Age: 22",           attr::AGE),
        (b"Nationality: PK",   attr::NATIONALITY),
        (b"Random_Padding_123",attr::PADDING),
    ];

    let leaves: Vec<HashOut<F>> = leaves_raw
        .iter()
        .map(|(payload, ctx_id)| {
            let data = pack_bytes_to_field(payload);
            let salt = derive_leaf_salt(master_key, *ctx_id);
            blinded_leaf(&salt, &data)
        })
        .collect();

    let node_l = hash_pair(&leaves[0], &leaves[1]);
    let node_r = hash_pair(&leaves[2], &leaves[3]);
    let root   = hash_pair(&node_l, &node_r);

    root.elements
        .iter()
        .flat_map(|e| e.to_canonical_u64().to_le_bytes())
        .collect()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derives a ZKP-ready Poseidon Merkle root from a raw seed.
///
/// # Pipeline
/// 1. **Off-circuit KDF** — HKDF-SHA256 stretches the seed into a 256-bit
///    master key.
/// 2. **Memory hygiene** — the raw seed is zeroized immediately after KDF
///    extraction.
/// 3. **Field encoding** — the master key is packed into Goldilocks field
///    elements (7-bytes-per-element, ~7× constraint reduction).
/// 4. **Blinded Merkle tree** — per-attribute Poseidon salts are derived from
///    the master key, preventing cross-attribute correlation. A depth-2 binary
///    Merkle tree is constructed and its 32-byte root returned for JNI
///    consumption.
///
/// # Returns
/// 32 bytes of Merkle root on success; 32 zero bytes on KDF failure.
pub fn process_secure_seed(mut seed_bytes: Vec<u8>) -> Vec<u8> {
    // Log only a safe prefix — never the full seed.
    let preview = seed_bytes
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    info!("[vault] seed accepted (preview={preview}…)");

    // --- Step 1: Off-circuit key derivation ---
    let hkdf = Hkdf::<Sha256>::new(Some(ZKP_APP_SALT), &seed_bytes);
    seed_bytes.zeroize();
    info!("[vault] raw seed zeroized");

    let mut raw_master_key = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    if hkdf.expand(MASTER_KEY_INFO, raw_master_key.as_mut()).is_err() {
        warn!("[vault] HKDF expansion failed — aborting");
        return vec![0u8; MASTER_KEY_LEN];
    }
    info!("[kdf] master key derived");

    // --- Step 2: Pack into field elements ---
    let master_key_f = pack_bytes_to_field(&*raw_master_key);

    // --- Step 3: Build blinded Poseidon Merkle tree ---
    info!("[merkle] constructing blinded Poseidon tree");
    let root_bytes = build_merkle_root(&master_key_f);
    info!("[merkle] root generated ({} bytes)", root_bytes.len());

    root_bytes
}