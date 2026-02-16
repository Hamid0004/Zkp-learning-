package com.example.zkpapp

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.SerializationException

// --- Data Models ---

@Serializable
data class ProofResult(
    val nullifier: String,
    val proof: String,
    val metadata: ProofMetadata
)

@Serializable
data class ProofMetadata(
    val generation_time_ms: Long,
    val proof_size_bytes: Int,
    val circuit_version: String,
    val circuit_hash: String,
    val num_gates: Int,
    // Note: Rust code might send 'degree_bits' or not, keep it flexible
    val degree_bits: Int = 0, 
    val proof_id: Long
)

@Serializable
data class CircuitInfo(
    val version: String,
    val circuit_hash: String,
    val num_gates: Int,
    // val degree_bits: Int, // Rust might not send this in info, check Rust struct
    val total_proofs: Long // 🦁 FIX: Rust uses 'total_proofs', not 'total_proofs_generated'
)

@Serializable
data class ErrorResponse(
    val error: String,
    val error_code: String
)

// --- Sealed Result Classes ---

sealed class ZkAuthResult {
    data class Success(val result: ProofResult) : ZkAuthResult()
    data class Error(val message: String, val code: String) : ZkAuthResult()
}

sealed class CircuitInfoResult {
    data class Success(val info: CircuitInfo) : CircuitInfoResult()
    data class Error(val message: String, val code: String) : CircuitInfoResult()
}

// --- Main Object ---

object ZkAuth {

    private const val TAG = "ZkAuth"
    private const val MAX_INPUT_LENGTH = 1024

    @Volatile
    private var isLibraryLoaded = false

    // Relaxed JSON parser
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        coerceInputValues = true
    }

    // 1. Load Library
    init {
        try {
            System.loadLibrary("zkp_mobile")
            isLibraryLoaded = true
            Log.i(TAG, "✅ Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            isLibraryLoaded = false
            Log.e(TAG, "❌ CRITICAL: Rust library not found", e)
        } catch (e: Exception) {
            isLibraryLoaded = false
            Log.e(TAG, "❌ Unexpected error loading library", e)
        }
    }

    // 2. Native Functions (JNI)
    // Note: external functions do not have a body
    @JvmStatic
    external fun generateSecureNullifier(
        secret: String,
        domain: String,
        challenge: String
    ): String

    @JvmStatic
    external fun getCircuitInfo(): String


    // 3. Public Helpers
    fun isReady(): Boolean = isLibraryLoaded

    private fun validateInput(input: String, fieldName: String): String? {
        return when {
            input.isEmpty() -> "$fieldName cannot be empty"
            input.length > MAX_INPUT_LENGTH -> "$fieldName exceeds maximum length ($MAX_INPUT_LENGTH)"
            input.isBlank() -> "$fieldName cannot be blank"
            else -> null
        }
    }

    // 4. Main Authentication Function (Suspend)
    suspend fun authenticate(
        secret: String,
        domain: String,
        challenge: String
    ): ZkAuthResult = withContext(Dispatchers.Default) {
        
        // A. Basic Checks
        if (!isLibraryLoaded) {
            return@withContext ZkAuthResult.Error(
                "Native library not loaded",
                "LIBRARY_NOT_LOADED"
            )
        }

        validateInput(secret, "Secret")?.let { return@withContext ZkAuthResult.Error(it, "INVALID_SECRET") }
        validateInput(domain, "Domain")?.let { return@withContext ZkAuthResult.Error(it, "INVALID_DOMAIN") }
        validateInput(challenge, "Challenge")?.let { return@withContext ZkAuthResult.Error(it, "INVALID_CHALLENGE") }

        try {
            // B. Call Rust
            val rawResult = generateSecureNullifier(secret, domain, challenge)
            
            if (rawResult.isEmpty()) {
                return@withContext ZkAuthResult.Error("Empty proof returned", "EMPTY_PROOF")
            }

            // C. Parse Result (Dual Strategy)
            // Strategy: First try to parse as Success. If it fails, try Error. 
            // OR: Check for "error" key string first (simpler).
            
            if (rawResult.contains("\"error\"")) {
                try {
                    val errorResp = json.decodeFromString<ErrorResponse>(rawResult)
                    return@withContext ZkAuthResult.Error(errorResp.error, errorResp.error_code)
                } catch (e: Exception) {
                    // Fallback if parsing fails
                    return@withContext ZkAuthResult.Error(rawResult, "UNKNOWN_ERROR")
                }
            }

            // Assuming Success
            return@withContext try {
                val proofResult = json.decodeFromString<ProofResult>(rawResult)
                Log.i(TAG, "⚡ Proof generated: ${proofResult.metadata.generation_time_ms}ms")
                ZkAuthResult.Success(proofResult)
            } catch (e: SerializationException) {
                Log.e(TAG, "JSON Parse Error", e)
                ZkAuthResult.Error("Invalid JSON from Rust: ${e.message}", "PARSE_ERROR")
            }

        } catch (e: UnsatisfiedLinkError) {
            ZkAuthResult.Error("Native library missing", "LIBRARY_ERROR")
        } catch (e: Exception) {
            ZkAuthResult.Error(e.message ?: "Unknown error", "UNKNOWN_ERROR")
        }
    }

    // 5. Circuit Info Function
    suspend fun getCircuitInformation(): CircuitInfoResult = withContext(Dispatchers.IO) {
        if (!isLibraryLoaded) {
            return@withContext CircuitInfoResult.Error("Library not loaded", "LIBRARY_NOT_LOADED")
        }

        try {
            val rawInfo = getCircuitInfo()

             if (rawInfo.contains("\"error\"")) {
                try {
                    val errorResp = json.decodeFromString<ErrorResponse>(rawInfo)
                    return@withContext CircuitInfoResult.Error(errorResp.error, errorResp.error_code)
                } catch (e: Exception) {
                     return@withContext CircuitInfoResult.Error(rawInfo, "UNKNOWN_ERROR")
                }
            }

            val info = json.decodeFromString<CircuitInfo>(rawInfo)
            Log.i(TAG, "Circuit Info: Gates=${info.num_gates}, Total Proofs=${info.total_proofs}")
            
            CircuitInfoResult.Success(info)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get circuit info", e)
            CircuitInfoResult.Error(e.message ?: "Unknown", "CIRCUIT_INFO_ERROR")
        }
    }

    // 6. Compatibility / Legacy Wrapper
    // Can be used if you haven't migrated all UI code to coroutines yet
    fun safeGenerateNullifier(
        secret: String,
        domain: String,
        challenge: String
    ): String {
        if (!isLibraryLoaded) return "Error: Rust Library Missing"
        return try {
            generateSecureNullifier(secret, domain, challenge)
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }
}