package com.example.zkpapp

// ─────────────────────────────────────────────────────────────────────────────
// ZkpJni.kt — Kotlin ↔ Rust JNI Bridge
// ─────────────────────────────────────────────────────────────────────────────

object ZkpJni {
    init {
        System.loadLibrary("zkp_mobile")
    }

    /** Single run — direct result */
    external fun runProofBenchmark(): ProofBenchmarkResult

    /** Median of 3 runs — spike filter (304ms jaise outliers remove) */
    external fun runProofBenchmarkMedian(): ProofBenchmarkResult
}

// ─────────────────────────────────────────────────────────────────────────────
// ProofBenchmarkResult — Rust se aane wala data
//
// CHANGES vs old version:
// ✅ witness_gen_ms → witness_gen_us (microseconds, 0ms fix)
// ✅ memory_kb added (Rust heap, 0MB fix)
// ✅ peak_memory_kb added (proof gen ke waqt peak)
// ─────────────────────────────────────────────────────────────────────────────

data class ProofBenchmarkResult(
    // 🔴 MUST
    val circuitSetupMs  : Long,
    val witnessGenUs    : Long,     // ✅ microseconds now
    val proofGenMs      : Long,
    val verifyMs        : Long,
    val proofSizeBytes  : Long,
    val constraintCount : Int,
    val isValid         : Boolean,
    val errorMsg        : String,
    // 🟡 GOOD — now accurate
    val memoryKb        : Long,     // ✅ Rust heap KB (was 0)
    val peakMemoryKb    : Long,     // ✅ Peak during proof gen
) {
    /** Proof size KB mein */
    val proofSizeKb: Double
        get() = proofSizeBytes / 1024.0

    /** Witness time human readable */
    val witnessGenDisplay: String
        get() = if (witnessGenUs < 1000) "${witnessGenUs} µs"
                else "${witnessGenUs / 1000}.${(witnessGenUs % 1000) / 100} ms"

    /** Memory human readable */
    val memoryDisplay: String
        get() = if (memoryKb < 1024) "${memoryKb} KB"
                else "${memoryKb / 1024} MB"

    /** Status text */
    val statusText: String
        get() = if (isValid) "SUCCESS" else "FAILED"
}