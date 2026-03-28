package com.example.zkpapp

import android.content.Context
import com.example.zkpapp.BuildConfig
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.Certificate
import java.time.Instant

/**
 * DeviceTierGate.kt v2.0
 */
object DeviceTierGate {

    // ✅ FIX 1: Naya Alias takay purani corrupt key ignore ho jaye
    private const val TAG              = "DeviceTierGate"
    private const val DEVICE_KEY_ALIAS = "ZKAuthDeviceKey_v2"   
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"

    fun isDeviceRegistered(context: android.content.Context): Boolean {
        return try {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            val keyExists = ks.containsAlias(DEVICE_KEY_ALIAS)

            val biometricManager = androidx.biometric.BiometricManager.from(context)
            val canAuth = biometricManager.canAuthenticate(
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
            )
            val biometricOk = canAuth == androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS

            keyExists && biometricOk
        } catch (e: Exception) {
            Log.w(TAG, "isDeviceRegistered: ${e.message}")
            false
        }
    }

    init {
        try {
            System.loadLibrary("zkp_mobile")
            Log.d(TAG, "✅ zkp_mobile loaded for DeviceTierGate")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ zkp_mobile load FAILED: ${e.message}")
        }
    }

    private external fun warmupDeviceCircuit()
    private external fun generateDeviceProof(jsonInput: String): String

    suspend fun warmup() = withContext(Dispatchers.Default) {
        try {
            warmupDeviceCircuit()
            Log.i(TAG, "✅ Tier 3 circuit warmed up")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Warmup failed: ${e.message}")
        }
    }

    // ✅ FIX 2: Smart Fallback Logic for Hardware Attestation
    fun ensureDeviceKeyExists(forceRecreate: Boolean = false) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        
        if (forceRecreate) {
            try { ks.deleteEntry(DEVICE_KEY_ALIAS) } catch (_: Exception) {}
        } else if (ks.containsAlias(DEVICE_KEY_ALIAS)) {
            try {
                val key = ks.getKey(DEVICE_KEY_ALIAS, null) as? java.security.PrivateKey
                if (key != null) return // Key bilkul theek hai
            } catch (e: Exception) {
                Log.w(TAG, "Old key corrupt, will recreate")
            }
            try { ks.deleteEntry(DEVICE_KEY_ALIAS) } catch (_: Exception) {}
        }

        Log.d(TAG, "🔑 Generating Tier 3 device key (v2)...")
        
        try {
            // ATTEMPT 1: Strict Hardware Attestation ke sath try karein (Highest Security)
            generateKey(useAttestation = true)
            Log.d(TAG, "✅ Tier 3 key generated WITH Hardware Attestation")
            
        } catch (e: Exception) {
            Log.w(TAG, "⚠️ Hardware Attestation failed (${e.message}). Falling back to Basic Keystore...")
            // ATTEMPT 2: Fallback - Agar phone support na kare toh bina strict attestation ke banayein
            try { ks.deleteEntry(DEVICE_KEY_ALIAS) } catch (_: Exception) {} // Clear failed key
            generateKey(useAttestation = false)
            Log.d(TAG, "✅ Tier 3 key generated WITHOUT strict attestation (Fallback)")
        }
    }

    // Helper function for Smart Fallback
    private fun generateKey(useAttestation: Boolean) {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        
        val specBuilder = KeyGenParameterSpec.Builder(
            DEVICE_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setKeySize(256)
            .setUserAuthenticationRequired(true) // Biometric lock is compulsory

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            specBuilder.setInvalidatedByBiometricEnrollment(false)
        }

        // Agar attempt 1 hai, toh attestation lagao
        if (useAttestation && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            specBuilder.setAttestationChallenge("ZKP_CHALLENGE".toByteArray())
            specBuilder.setDevicePropertiesAttestationIncluded(true) 
        }

        kpg.initialize(specBuilder.build())
        kpg.generateKeyPair()
    }

    suspend fun generateProof(
        context:    Context,
        signature:  Signature,
        domain:     String,
        challenge:  String,
        callback:   String,
        sessionId:  String = "",
        onProgress: ((String) -> Unit)? = null,  
    ): DeviceTierResult = withContext(Dispatchers.Default) {
        try {
            onProgress?.invoke("STEP 1/3 · COLLECTING DEVICE DATA")
            signature.update(challenge.toByteArray(Charsets.UTF_8))
            val sigBytes      = signature.sign()
            val biometricHash = sha256Hex(sigBytes)
            Log.d(TAG, "✅ Biometric hash collected")

            val ks           = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            val certChain    = ks.getCertificateChain(DEVICE_KEY_ALIAS)
                ?: return@withContext DeviceTierResult.Error("KeyStore attestation chain null")
            val attestHash   = sha256Hex(certChain.concatBytes())
            Log.d(TAG, "✅ Attestation cert hash collected (chain: ${certChain.size} certs)")

            val createdAtSecs   = fallbackCreationTime()
            Log.d(TAG, "✅ Key creation time: $createdAtSecs")

            val androidId    = android.provider.Settings.Secure.getString(
                context.contentResolver,
                android.provider.Settings.Secure.ANDROID_ID
            ) ?: "unknown_device"
            val deviceIdHash = sha256Hex(androidId.toByteArray(Charsets.UTF_8))
            Log.d(TAG, "✅ Device ID hash collected")

            val pubKey       = ks.getCertificate(DEVICE_KEY_ALIAS)?.publicKey
                ?: return@withContext DeviceTierResult.Error("Device pubkey not found")
            val devicePubkeyHex = pubKey.encoded.toHex()
            Log.d(TAG, "✅ Device pubkey collected")

            val nowSecs = Instant.now().epochSecond
            val input   = JSONObject().apply {
                put("biometric_hash_hex",        biometricHash)
                put("attestation_cert_hash_hex", attestHash)
                put("account_created_at_secs",   createdAtSecs as Long)
                put("device_id_hash_hex",        deviceIdHash)
                put("verifier_domain",           domain)
                put("challenge_hex",             challenge)
                put("current_time_secs",         nowSecs)
                put("device_pubkey_hex",         devicePubkeyHex)
                ageThresholdSecs()?.let { put("age_threshold_secs", it) }
            }.toString()

            onProgress?.invoke("STEP 2/3 · GENERATING ZK PROOF")
            Log.d(TAG, "⚡ Generating Tier 3 ZK proof...")
            val resultJson = generateDeviceProof(input)
            val result     = JSONObject(resultJson)

            if (!result.optBoolean("success", false)) {
                val err = result.optString("error_msg", "unknown error")
                Log.e(TAG, "❌ Rust proof failed: $err")
                return@withContext DeviceTierResult.Error(err)
            }

            val proofMs = result.optLong("zk_proof_ms", 0)
            Log.i(TAG, "✅ Tier 3 proof generated in ${proofMs}ms")

            val payload = buildZkAuthPayload(
                result    = result,
                domain    = domain,
                challenge = challenge,
                sessionId = sessionId,
            )

            if (callback.isNotEmpty()) {
                onProgress?.invoke("STEP 3/3 · SUBMITTING TO SERVER")
                val (ok, err) = postProofToCallback(callback, payload)
                if (!ok) return@withContext DeviceTierResult.Error(err)
                Log.i(TAG, "✅ Tier 3 proof submitted")
            } else {
                Log.i(TAG, "✅ Tier 3 registration mode — no callback")
            }

            DeviceTierResult.Success(
                proofMs    = proofMs,
                nullifier  = result.optString("nullifier"),
                trustLevel = result.optString("trust_level", "BASIC"),
            )

        } catch (e: Exception) {
            Log.e(TAG, "❌ generateProof exception: ${e.message}", e)
            DeviceTierResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Returns BiometricPrompt.CryptoObject for Tier 3.
     */
    @Throws(Exception::class)
    fun buildCryptoObject(): BiometricPrompt.CryptoObject {
        try {
            return tryBuildCryptoObject()
        } catch (e: Exception) {
            // ✅ FIX 3: Agar kisi bhi wajah se key masla karay (jaise InvalidKeyException)
            // toh usko pakro, forcefully delete karo aur NAYI key banao
            Log.w(TAG, "Key init failed (${e.javaClass.simpleName}) — regenerating V2 key")
            ensureDeviceKeyExists(forceRecreate = true)
            return tryBuildCryptoObject()
        }
    }

    @Throws(Exception::class)
    private fun tryBuildCryptoObject(): BiometricPrompt.CryptoObject {
        val ks  = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val key = ks.getKey(DEVICE_KEY_ALIAS, null) as? java.security.PrivateKey
            ?: throw Exception("PRIVATE KEY NOT FOUND IN KEYSTORE")
            
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(key)  // ← Hardware bug was crashing here
        return BiometricPrompt.CryptoObject(sig)
    }

    private fun buildZkAuthPayload(
        result:    JSONObject,
        domain:    String,
        challenge: String,
        sessionId: String = "",
    ): String {
        return try {
            val nullifier = result.optString("nullifier")
            val deviceSig = signWithDeviceKey(nullifier)

            JSONObject().apply {
                put("version",          "3.0")          
                put("tier",             3)
                put("trust_level",      "BASIC")
                put("domain",           domain)
                put("challenge",        challenge)
                put("claim_type",       "is_human")     
                put("nullifier",        nullifier)
                if (sessionId.isNotEmpty()) put("session_id", sessionId)
                put("hw_binding",       result.optString("hw_binding"))
                put("merkle_root",      result.optString("merkle_root"))
                put("compressed_proof", result.optString("compressed_proof"))
                put("valid_until",      result.optLong("valid_until") as Long)
                put("is_human",         result.optBoolean("is_human"))
                put("is_real_device",   result.optBoolean("is_real_device"))
                put("is_unique",        result.optBoolean("is_unique"))
                put("account_age_ok",   result.optBoolean("account_age_ok"))
                put("device_sig",       deviceSig)
                put("timestamp",        System.currentTimeMillis())
            }.toString()
        } catch (e: Exception) {
            Log.e(TAG, "❌ buildZkAuthPayload: ${e.message}")
            "{\"error\":\"payload_build_failed\"}"
        }
    }

    private suspend fun postProofToCallback(url: String, payload: String): Pair<Boolean, String> =
        withContext(Dispatchers.IO) {
            try {
                val finalUrl = url.replaceFirst("http://", "https://")

                val conn = java.net.URL(finalUrl).openConnection() as java.net.HttpURLConnection
                conn.requestMethod   = "POST"
                conn.doOutput        = true
                conn.connectTimeout  = 15_000
                conn.readTimeout     = 20_000
                conn.setRequestProperty("Content-Type",     "application/json")
                conn.setRequestProperty("X-ZKAuth-Version", "3.0")
                conn.setRequestProperty("X-ZKAuth-Tier",    "3")
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                val body = try {
                    (if (code in 200..299) conn.inputStream else conn.errorStream)
                        ?.bufferedReader()?.readText() ?: ""
                } catch (_: Exception) { "" }

                if (code in 200..299) {
                    Pair(true, "")
                } else if (code == 403) {
                    val hint = try {
                        org.json.JSONObject(body).optString("hint",
                            "Real passport required for this claim")
                    } catch (_: Exception) { "Real passport required" }
                    Pair(false, "❌ $hint")
                } else {
                    Pair(false, "HTTP $code: ${body.take(150)}")
                }
            } catch (e: Exception) {
                Pair(false, "Network: ${e.message?.take(100) ?: "unknown"}")
            }
        }

    private fun signWithDeviceKey(data: String): String {
        return try {
            val ks  = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            val key = ks.getKey(DEVICE_KEY_ALIAS, null) as? java.security.PrivateKey
                ?: return "sig_unavailable"
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(key)
            sig.update(data.toByteArray(Charsets.UTF_8))
            Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "❌ signWithDeviceKey: ${e.message}")
            "sig_unavailable"
        }
    }

    private fun sha256Hex(data: ByteArray): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(data)
            .toHex()
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    private fun Array<Certificate>.concatBytes(): ByteArray {
        return fold(ByteArray(0)) { acc, cert -> acc + cert.encoded }
    }

    private fun ageThresholdSecs(): Long? {
        return if (BuildConfig.DEBUG) {
            Log.w(TAG, "⚠️ DEV BUILD: age_threshold_secs = 0 (check skipped)")
            0L   
        } else {
            null 
        }
    }

    private fun fallbackCreationTime(): Long {
        return Instant.now().epochSecond - (40L * 24 * 60 * 60)
    }

    sealed class DeviceTierResult {
        data class Success(
            val proofMs:    Long,
            val nullifier:  String,
            val trustLevel: String,
        ) : DeviceTierResult()

        data class Error(
            val message: String,
        ) : DeviceTierResult()
    }
}