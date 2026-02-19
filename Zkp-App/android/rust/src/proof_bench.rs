// proof_bench.rs
//
// Plonky2 ZK Proof Benchmark Engine
//
// Kya karta hai:
// 1. Dummy circuit banata hai (fibonacci sequence)
// 2. Witness generate karta hai
// 3. Proof generate karta hai
// 4. Proof verify karta hai
// 5. Har step ka time measure karta hai
//
// Ye sab measurements TestProofActivity ko JNI se return hoti hain

use anyhow::Result;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
// ✅ Fix 1: Field trait import — from_canonical_u64 ke liye zaroori
use plonky2::field::types::Field;
use std::time::Instant;

// ── Config ────────────────────────────────────────────────────────────────────
// D=2 standard Plonky2 config
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<2>>::F;
const D: usize = 2;

// ── Result struct (JNI ko ye return hoga) ─────────────────────────────────────
#[derive(Debug)]
pub struct BenchmarkResult {
    pub circuit_setup_ms:   u64,
    pub witness_gen_ms:     u64,
    pub proof_gen_ms:       u64,
    pub verify_ms:          u64,
    pub proof_size_bytes:   usize,
    pub constraint_count:   usize,
    pub is_valid:           bool,
    pub error_msg:          String,
}

impl Default for BenchmarkResult {
    fn default() -> Self {
        BenchmarkResult {
            circuit_setup_ms:  0,
            witness_gen_ms:    0,
            proof_gen_ms:      0,
            verify_ms:         0,
            proof_size_bytes:  0,
            constraint_count:  0,
            is_valid:          false,
            error_msg:         String::new(),
        }
    }
}

// ── Main Benchmark Function ────────────────────────────────────────────────────
pub fn run_benchmark() -> BenchmarkResult {
    match run_benchmark_inner() {
        Ok(result) => result,
        Err(e) => BenchmarkResult {
            error_msg: e.to_string(),
            ..Default::default()
        },
    }
}

fn run_benchmark_inner() -> Result<BenchmarkResult> {
    let mut result = BenchmarkResult::default();

    // ── Step 1: Circuit Setup ─────────────────────────────────────────────────
    //
    // Hum ek simple Fibonacci circuit banate hain:
    // Prove karta hai ke hum jaante hain 2 numbers (a, b) jaise:
    //   a + b = c  (publicly)
    //
    // Ye ek dummy circuit hai — real use mein
    // passport data verify karne wala circuit hoga
    let setup_start = Instant::now();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // ── Circuit definition ────────────────────────────────────────────────────
    // Private inputs (witness)
    let a_target: Target = builder.add_virtual_target();
    let b_target: Target = builder.add_virtual_target();

    // Constraint: a + b = c
    let c_target = builder.add(a_target, b_target);

    // c public input ke tor pe register karo
    builder.register_public_input(c_target);

    // Build circuit
    let circuit_data: CircuitData<F, C, D> = builder.build();

    result.circuit_setup_ms  = setup_start.elapsed().as_millis() as u64;
    result.constraint_count  = circuit_data.common.degree();  // gate count

    // ── Step 2: Witness Generation ────────────────────────────────────────────
    //
    // Dummy values: a=3, b=7 → c=10
    // Real use mein ye values passport data se aati hain
    let witness_start = Instant::now();

    let mut pw = PartialWitness::new();
    // ✅ Fix 2: set_target () return karta hai, ? operator nahi lagta
    pw.set_target(a_target, F::from_canonical_u64(3));
    pw.set_target(b_target, F::from_canonical_u64(7));

    result.witness_gen_ms = witness_start.elapsed().as_millis() as u64;

    // ── Step 3: Proof Generation ──────────────────────────────────────────────
    let proof_start = Instant::now();

    let proof: ProofWithPublicInputs<F, C, D> = circuit_data.prove(pw)?;

    result.proof_gen_ms = proof_start.elapsed().as_millis() as u64;

    // Proof size measure karo (serialize karke bytes count karo)
    let proof_bytes = serde_proof_size(&proof);
    result.proof_size_bytes = proof_bytes;

    // ── Step 4: Verification ──────────────────────────────────────────────────
    let verify_start = Instant::now();

    let verify_result = circuit_data.verify(proof);

    result.verify_ms = verify_start.elapsed().as_millis() as u64;
    result.is_valid  = verify_result.is_ok();

    if let Err(e) = verify_result {
        result.error_msg = e.to_string();
    }

    Ok(result)
}

// ── Helper: Proof size estimate ───────────────────────────────────────────────
//
// Plonky2 proof ko directly serialize karna complex hai
// Isliye hum ek rough size estimate karte hain
// field elements count se
fn serde_proof_size<F, C, const D: usize>(
    proof: &ProofWithPublicInputs<F, C, D>
) -> usize
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    // Wires polynomial commitments + openings + fri proof
    // Har field element = 8 bytes (u64)
    let wire_count    = proof.proof.wires_cap.0.len() * 4 * 8;
    let opening_count = proof.proof.openings.constants.len() * 8;
    let public_count  = proof.public_inputs.len() * 8;

    wire_count + opening_count + public_count + 256 // 256 = FRI proof overhead estimate
}