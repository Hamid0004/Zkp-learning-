package com.example.zkpapp

// ─────────────────────────────────────────────────────────────────────────────
// ZkpJni.kt
//
// Kotlin ↔ Rust JNI Bridge
//
// Usage in TestProofActivity:
//   val result = ZkpJni.runProofBenchmark()
//   Log.d("ZKP", "Proof: ${result.proofGenMs}ms")
// ─────────────────────────────────────────────────────────────────────────────

object ZkpJni {

    // Rust .so library load karo
    // Library naam Cargo.toml ke [lib] name se match karna chahiye
    init {
        System.loadLibrary("zkp_mobile")
    }

    /**
     * Rust se ZK Proof benchmark run karta hai
     * Returns ProofBenchmarkResult with all measurements
     */
    external fun runProofBenchmark(): ProofBenchmarkResult
}

// ─────────────────────────────────────────────────────────────────────────────
// ProofBenchmarkResult.kt
//
// Rust se aane wala data class
// lib.rs mein isi class ka object banana hota hai
// ─────────────────────────────────────────────────────────────────────────────

data class ProofBenchmarkResult(
    // 🔴 MUST
    val circuitSetupMs  : Long,     // Circuit initialize hone ka time
    val witnessGenMs    : Long,     // Witness generate karne ka time
    val proofGenMs      : Long,     // ZK Proof generate karne ka time
    val verifyMs        : Long,     // Proof verify karne ka time
    val proofSizeBytes  : Long,     // Proof ka size bytes mein
    val constraintCount : Int,      // Circuit constraints count
    val isValid         : Boolean,  // Verification pass hua ya nahi
    val errorMsg        : String    // Agar koi error aaya toh
) {
    // ── Computed helpers ──────────────────────────────────────────────────────

    /** Proof size KB mein */
    val proofSizeKb: Double
        get() = proofSizeBytes / 1024.0

    /** Total time = circuit + witness + proof + verify */
    val totalMs: Long
        get() = circuitSetupMs + witnessGenMs + proofGenMs + verifyMs

    /** Human readable status */
    val statusText: String
        get() = if (isValid) "SUCCESS" else "FAILED"
}