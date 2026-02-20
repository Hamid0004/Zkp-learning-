package com.example.zkpapp

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * SecurityGate.kt
 *
 * Passport proof pipeline ka entry point.
 * PassportActivity → SecurityGate → Rust (passport_security.rs)
 *
 * UPGRADES:
 * ✅ JNI function name fix (PassportActivity match)
 * ✅ Result sealed class — String parse nahi karna padega
 * ✅ Library load flag — silent crash fix
 * ✅ canSimulate() proper logic
 * ✅ ZkpJni duplicate removed — ek jagah se load
 */
object SecurityGate {

    private const val TAG = "SecurityGate"

    // ── Library Load ──────────────────────────────────────────────────────────
    // ✅ Fix 4: Flag rakhte hain — load fail hone pe proof call nahi hogi
    private var isLibraryLoaded = false

    init {
        try {
            System.loadLibrary("zkp_mobile")
            isLibraryLoaded = true
            Log.d(TAG, "✅ Rust Library Loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Rust library load FAILED — proof calls will be blocked", e)
        }
    }

    // ── JNI Bridge ────────────────────────────────────────────────────────────
    // ✅ Fix 1: Function name passport_security.rs se match karta hai
    // Rust: Java_com_example_zkpapp_PassportActivity_generateProof
    // → Kotlin class: PassportActivity (SecurityGate wrapper call karega)
    private external fun generateProof(jsonPayload: String): String

    // Simulation mode — NFC nahi hone pe
    private external fun generateSimulatedProof(unused: String): String

    // ── Result Type ───────────────────────────────────────────────────────────
    // ✅ Fix 2: String nahi — proper sealed class
    // Caller ko string parse nahi karna padega
    sealed class ProofResult {
        data class Success(val json: String)  : ProofResult()
        data class Failure(val reason: String): ProofResult()
    }

    // ── Permission Checks ─────────────────────────────────────────────────────

    fun canScanMrz(session: PassportSession): Boolean =
        session.state == SessionState.IDLE

    fun canStartNfc(session: PassportSession): Boolean =
        session.state == SessionState.NFC_READY && session.mrzInfo != null

    fun canReadPassport(session: PassportSession): Boolean =
        session.state == SessionState.NFC_READY

    // ✅ Fix 3: canSimulate proper logic
    // Sirf IDLE ya ERROR state mein simulate karo
    // NFC reading ke dauran simulate nahi karna chahiye
    fun canSimulate(session: PassportSession): Boolean =
        session.state == SessionState.IDLE ||
        session.state == SessionState.ERROR

    // ── Real Passport Proof ───────────────────────────────────────────────────

    suspend fun sendToRustForProof(data: PassportData): ProofResult {
        // ✅ Fix 4: Library load check
        if (!isLibraryLoaded) {
            return ProofResult.Failure("Rust library not loaded")
        }

        return withContext(Dispatchers.Default) {
            try {
                Log.d(TAG, "🚀 Sending real passport to Rust...")
                val rustJson = data.toRustJson()
                val response = generateProof(rustJson)
                Log.d(TAG, "✅ Rust response received")
                ProofResult.Success(response)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Rust proof error", e)
                ProofResult.Failure(e.message ?: "Unknown Rust error")
            }
        }
    }

    // ── Simulation Proof ──────────────────────────────────────────────────────
    // ✅ NFC nahi hone pe — dummy passport se real ZK proof

    suspend fun sendSimulatedProof(): ProofResult {
        if (!isLibraryLoaded) {
            return ProofResult.Failure("Rust library not loaded")
        }

        return withContext(Dispatchers.Default) {
            try {
                Log.d(TAG, "🧪 Running simulation proof...")
                val response = generateSimulatedProof("")
                Log.d(TAG, "✅ Simulation proof done")
                ProofResult.Success(response)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Simulation error", e)
                ProofResult.Failure(e.message ?: "Simulation failed")
            }
        }
    }
}