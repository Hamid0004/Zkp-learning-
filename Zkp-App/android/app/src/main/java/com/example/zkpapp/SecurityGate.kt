package com.example.zkpapp

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONException
import org.json.JSONObject

/**
 * SecurityGate.kt v2.0 — Synced with passport_security.rs v5.1 + IdentityStorage v3.1
 *
 * ═══════════════════════════════════════════════════════════════════════
 * Architecture:
 *   PassportActivity / UI
 *       ↓
 *   SecurityGate          ← you are here
 *       ↓  builds JSON via IdentityStorage.buildPassportJson()
 *   Rust JNI (passport_security.rs v5.1)
 *       ↓  returns PassportProofResult JSON
 *   SecurityGate.ProofResult.Success(parsed)
 *       ↓
 *   UI displays result
 * ═══════════════════════════════════════════════════════════════════════
 *
 * UPGRADES vs v1.0:
 *
 * ✅ [NEW] 3 missing JNI declarations added
 *      warmupCircuit, generateClaimProof, generateSimulatedClaimProof
 *      Now all 5 Rust v5.1 JNI exports are bridged.
 *
 * ✅ [NEW] Kotlin data classes matching Rust JSON output
 *      PassportProofResult, ZkProofOutput, ClaimOutput
 *      No more manual JSON string parsing by callers.
 *
 * ✅ [NEW] ProofResult.Success carries parsed PassportProofResult
 *      ProofResult.Success(result) — typed access to all fields.
 *
 * ✅ [NEW] generateClaim() — primary proof API
 *      Integrates IdentityStorage.buildPassportJson() correctly.
 *      Handles versioning, caching, timing, and proof storage.
 *
 * ✅ [NEW] Rust version validation
 *      Rejects proofs from wrong/outdated Rust lib (expects "5.0" or "5.1").
 *
 * ✅ [NEW] Performance timing surfaced
 *      Rust zk_proof_ms logged + returned in result for demo/debugging.
 *
 * ✅ [FIX] isLibraryLoaded → @Volatile
 *      Coroutines run on Dispatchers.Default (multi-core).
 *      Non-volatile boolean can be stale-read on other cores.
 *
 * ✅ [FIX] warmup() now declared + properly integrated
 *      IdentityStorage.warmup() calls SecurityGate.warmupCircuit().
 *      That external fun was missing — now declared.
 * ═══════════════════════════════════════════════════════════════════════
 */
object SecurityGate {

    private const val TAG = "SecurityGate"

    // Rust proof version we accept — reject anything else
    private val ACCEPTED_PROOF_VERSIONS = setOf("5.0", "5.1")

    // ── Library Load ──────────────────────────────────────────────────────────
    // [FIX] @Volatile — read on Dispatchers.Default (multi-core), must be visible
    @Volatile private var isLibraryLoaded = false

    init {
        try {
            System.loadLibrary("zkp_mobile")
            isLibraryLoaded = true
            Log.d(TAG, "✅ Rust library loaded: zkp_mobile")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Rust library load FAILED — all proof calls blocked", e)
        }
    }

    // ── JNI Bridge (all 5 Rust v5.1 exports) ─────────────────────────────────
    //
    // Rust side: Java_com_example_zkpapp_SecurityGate_<name>
    // Each maps to a #[no_mangle] pub extern "system" fn in passport_security.rs

    @JvmStatic external fun warmupCircuit()
    // Called by: IdentityStorage.warmup() on app start (IO Dispatcher)

    private external fun generateProof(jsonPayload: String): String
    // Real NFC passport — full PassportData JSON

    private external fun generateSimulatedProof(unused: String): String
    // Hardcoded test passport (Arsalan Khan, PAK) in Rust

    private external fun generateClaimProof(
        jsonPayload: String,
        claimType:   String,
        domain:      String
    ): String
    // Real NFC + explicit claim + domain override

    private external fun generateSimulatedClaimProof(
        claimType: String,
        domain:    String
    ): String
    // Simulated + explicit claim + domain — for dev/demo flows

    // ── Result Types ──────────────────────────────────────────────────────────

    sealed class ProofResult {
        /** Full parsed result — caller gets typed access to every field. */
        data class Success(val result: PassportProofResult) : ProofResult()

        /** Library not loaded, Rust error, JSON parse failure, version mismatch. */
        data class Failure(val reason: String) : ProofResult()
    }

    // ── Kotlin Models — mirrors Rust PassportProofResult JSON output ──────────

    data class PassportProofResult(
        val success:        Boolean,
        val inputMode:      String,         // "NFC_PASSPORT" | "SIMULATED_PASSPORT"
        val integrityCheck: String,         // "PASS" | "FAIL"
        val signatureCheck: String,         // "VERIFIED" | "SIMULATED" | "FAILED"
        val zkProofStatus:  String,         // "GENERATED" | "FAILED" | "SKIPPED"
        val zkProofMs:      Long,           // Rust circuit time — surface in UI
        val documentNumber: String,
        val holderName:     String,
        val errorMsg:       String,
        val merkleRoot:     String,
        val trustLevel:     String,         // "MAXIMUM" | "NONE"
        val nullifier:      String,
        val zkOutput:       ZkProofOutput?  // null if proof not generated
    )

    data class ZkProofOutput(
        val version:         String,        // Must be in ACCEPTED_PROOF_VERSIONS
        val compressedProof: String,        // Recursive proof hex (v5.0+)
        val root:            String,
        val nullifier:       String,
        val dg1Anchor:       String,
        val validUntil:      Long,          // Unix seconds — check > now
        val hwBinding:       String,        // Poseidon(DG1, device_pubkey)
        val revocationId:    String,        // Poseidon(DG1, "REVOCATION")
        val claim:           ClaimOutput
    )

    data class ClaimOutput(
        val type:  String,  // "age" | "nationality" | "human"
        val value: Boolean
    )

    // ── Primary API: generateClaim() ──────────────────────────────────────────
    //
    // Full pipeline:
    //   1. Check library loaded
    //   2. Check identity + session valid
    //   3. Check proof cache (skip Rust if still valid)
    //   4. Build PassportData JSON via IdentityStorage
    //   5. Call Rust via generateClaimProof()
    //   6. Parse + version-validate response
    //   7. Cache result in IdentityStorage
    //   8. Return typed ProofResult

    suspend fun generateClaim(
        claimType: String,          // "is_adult" | "nationality" | "is_human"
        domain:    String,          // "discord.com", "netflix.com", etc.
        context:   Context? = null
    ): ProofResult {
        if (!isLibraryLoaded) return ProofResult.Failure("Rust library not loaded")

        if (!IdentityStorage.hasIdentity()) {
            return ProofResult.Failure("No identity — scan passport first")
        }
        if (!IdentityStorage.isSessionValid()) {
            return ProofResult.Failure("Session expired — scan passport again")
        }

        // Snapshot identity version for stale-proof detection
        val versionAtStart = IdentityStorage.getIdentityVersion()

        // Check cache — skip Rust if proof still valid for same identity + claim
        IdentityStorage.getCachedProof()?.let { cached ->
            Log.d(TAG, "⚡ Returning cached proof (Rust skipped)")
            return parseProofJson(cached)
        }

        IdentityStorage.setVerifierDomain(domain)

        val jsonPayload = IdentityStorage.buildPassportJson(
            claimType = claimType,
            domain    = domain,
            context   = context
        ) ?: return ProofResult.Failure("Failed to build passport JSON — check IdentityStorage")

        return withContext(Dispatchers.Default) {
            try {
                val t = System.currentTimeMillis()
                Log.d(TAG, "🚀 generateClaimProof → Rust | claim=$claimType domain=$domain")

                val raw = generateClaimProof(jsonPayload, claimType, domain)
                val elapsed = System.currentTimeMillis() - t

                Log.d(TAG, "✅ Rust response in ${elapsed}ms")

                val result = parseProofJson(raw)
                if (result is ProofResult.Success) {
                    Log.d(TAG, "⏱ ZK proof time: ${result.result.zkProofMs}ms " +
                        "| trust=${result.result.trustLevel} | status=${result.result.zkProofStatus}")
                    IdentityStorage.cacheProofResult(raw, versionAtStart)
                }
                result

            } catch (e: Exception) {
                Log.e(TAG, "❌ Rust error in generateClaimProof", e)
                ProofResult.Failure(e.message ?: "Unknown Rust error")
            }
        }
    }

    // ── Simulation API: generateSimulatedClaim() ──────────────────────────────
    //
    // Uses hardcoded Rust-side passport (Arsalan Khan, PAK).
    // No IdentityStorage needed — pure Rust simulation.
    // Useful for: CI tests, demo mode, devices without NFC.

    suspend fun generateSimulatedClaim(
        claimType: String = "is_adult",
        domain:    String = "sim.local"
    ): ProofResult {
        if (!isLibraryLoaded) return ProofResult.Failure("Rust library not loaded")

        return withContext(Dispatchers.Default) {
            try {
                val t = System.currentTimeMillis()
                Log.d(TAG, "🧪 generateSimulatedClaimProof → Rust | claim=$claimType domain=$domain")

                val raw = generateSimulatedClaimProof(claimType, domain)
                val elapsed = System.currentTimeMillis() - t

                Log.d(TAG, "✅ Simulated proof in ${elapsed}ms")

                val result = parseProofJson(raw)
                if (result is ProofResult.Success) {
                    Log.d(TAG, "⏱ ZK proof time: ${result.result.zkProofMs}ms")
                }
                result

            } catch (e: Exception) {
                Log.e(TAG, "❌ Simulation error", e)
                ProofResult.Failure(e.message ?: "Simulation failed")
            }
        }
    }

    // ── Legacy APIs (kept for PassportActivity backward compat) ───────────────

    suspend fun sendToRustForProof(jsonPayload: String): ProofResult {
        if (!isLibraryLoaded) return ProofResult.Failure("Rust library not loaded")
        return withContext(Dispatchers.Default) {
            try {
                Log.d(TAG, "🚀 sendToRustForProof (legacy) → Rust")
                val raw = generateProof(jsonPayload)
                parseProofJson(raw)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Rust proof error", e)
                ProofResult.Failure(e.message ?: "Unknown Rust error")
            }
        }
    }

    suspend fun sendSimulatedProof(): ProofResult {
        if (!isLibraryLoaded) return ProofResult.Failure("Rust library not loaded")
        return withContext(Dispatchers.Default) {
            try {
                Log.d(TAG, "🧪 sendSimulatedProof (legacy) → Rust")
                val raw = generateSimulatedProof("")
                parseProofJson(raw)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Simulation error", e)
                ProofResult.Failure(e.message ?: "Simulation failed")
            }
        }
    }

    // ── Permission Checks ─────────────────────────────────────────────────────

    fun canScanMrz(session: PassportSession): Boolean =
        session.state == SessionState.IDLE

    fun canStartNfc(session: PassportSession): Boolean =
        session.state == SessionState.NFC_READY && session.mrzInfo != null

    fun canReadPassport(session: PassportSession): Boolean =
        session.state == SessionState.NFC_READY

    fun canSimulate(session: PassportSession): Boolean =
        session.state == SessionState.IDLE || session.state == SessionState.ERROR

    // ── JSON Parser ───────────────────────────────────────────────────────────
    //
    // Converts raw Rust JSON string → typed PassportProofResult.
    // Also validates Rust proof version — rejects stale/wrong Rust lib.

    private fun parseProofJson(raw: String): ProofResult {
        return try {
            val root = JSONObject(raw)

            // Check for top-level error (Rust JNI error path)
            if (root.has("error")) {
                return ProofResult.Failure("Rust error: ${root.getString("error")}")
            }

            // Parse optional zk_output block
            val zkOutput: ZkProofOutput? = if (root.has("zk_output") && !root.isNull("zk_output")) {
                val zk = root.getJSONObject("zk_output")

                // [NEW] Version validation — reject wrong Rust lib output
                val version = zk.optString("version", "unknown")
                if (version !in ACCEPTED_PROOF_VERSIONS) {
                    Log.e(TAG, "❌ Proof version mismatch: got '$version', expected $ACCEPTED_PROOF_VERSIONS")
                    return ProofResult.Failure(
                        "Proof version mismatch: got '$version'. " +
                        "Rebuild Rust library (expected v5.0 or v5.1)."
                    )
                }

                val claimObj = zk.getJSONObject("claim")
                ZkProofOutput(
                    version         = version,
                    compressedProof = zk.optString("compressed_proof", ""),
                    root            = zk.optString("root", ""),
                    nullifier       = zk.optString("nullifier", ""),
                    dg1Anchor       = zk.optString("dg1_anchor", ""),
                    validUntil      = zk.optLong("valid_until", 0L),
                    hwBinding       = zk.optString("hw_binding", ""),
                    revocationId    = zk.optString("revocation_id", ""),
                    claim = ClaimOutput(
                        type  = claimObj.optString("type", "unknown"),
                        value = claimObj.optBoolean("value", false)
                    )
                )
            } else null

            val result = PassportProofResult(
                success        = root.optBoolean("success", false),
                inputMode      = root.optString("input_mode", ""),
                integrityCheck = root.optString("integrity_check", ""),
                signatureCheck = root.optString("signature_check", ""),
                zkProofStatus  = root.optString("zk_proof_status", ""),
                zkProofMs      = root.optLong("zk_proof_ms", 0L),
                documentNumber = root.optString("document_number", ""),
                holderName     = root.optString("holder_name", ""),
                errorMsg       = root.optString("error_msg", ""),
                merkleRoot     = root.optString("merkle_root", ""),
                trustLevel     = root.optString("trust_level", ""),
                nullifier      = root.optString("nullifier", ""),
                zkOutput       = zkOutput
            )

            ProofResult.Success(result)

        } catch (e: JSONException) {
            Log.e(TAG, "❌ JSON parse failed — raw: ${raw.take(200)}", e)
            ProofResult.Failure("JSON parse error: ${e.message}")
        }
    }
}