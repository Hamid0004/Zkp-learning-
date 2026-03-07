package com.example.zkpapp

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write
import kotlin.concurrent.thread

/**
 * IdentityStorage v3.1 — Pre-Build Audit Fixed Edition
 *
 * ═══════════════════════════════════════════════════════════════
 * v3.0 → v3.1 Audit Fixes:
 *
 * 🔴 [FIX] generateDeviceRngHex() moved OUT of read lock
 *    SecureRandom.nextBytes() can block on low entropy, causing
 *    ALL writer threads (saveIdentity, clear) to starve.
 *    Now pre-computed before lock acquisition.
 *
 * 🔴 [FIX] getOrCreateKeystorePubkeyHex() moved OUT of read lock
 *    TEE/Keystore I/O (100–500ms) held the read lock, risking
 *    deadlock with concurrent writes. pubkeyHex is now cached in
 *    a @Volatile field after first generation — zero lock time.
 *
 * 🟡 [FIX] DOMAIN_REGEX tightened
 *    Old regex allowed "a..b.com" (double dot) and "-.com"
 *    (leading dash) — both invalid hostnames.
 *    New RFC-compliant regex rejects all malformed hostnames.
 *
 * 🟡 [FIX] clearIfExpired() consolidated to single write lock
 *    Old: two separate read locks (isSessionValid + hasIdentity)
 *    with a potential race between them.
 *    New: single write lock captures all state atomically.
 *
 * 🟡 [FIX] buildPassportJson() checks session validity
 *    hasIdentity() alone allowed stale (expired) sessions to
 *    build proofs up to 60s after TTL. Added isSessionValid().
 *    Also validates dg1/sod hex format before JNI call.
 *
 * 🟡 [FIX] identityVersion: Int → Long (overflow safety)
 *    Int wraps at 2^31. Long gives effectively infinite range.
 *
 * 🟢 [FIX] getStats() inlines session check (no double read lock)
 * 🟢 [FIX] @Deprecated getSecret() raised to ERROR level
 * 🟢 [FIX] getSecretOrThrow() restored (silent removal broke callers)
 * 🟢 [FIX] secureWipeCharArray debug log restored under DEBUG guard
 * ═══════════════════════════════════════════════════════════════
 */
object IdentityStorage {

    // ═══════════════════════════════════════════════════════════
    // 📊 CONSTANTS
    // ═══════════════════════════════════════════════════════════
    private const val TAG                = "IdentityStorage"
    private const val DEFAULT_COUNTRY    = "PK"
    private const val MIN_SECRET_LENGTH  = 8
    private const val KEYSTORE_ALIAS     = "ZKAuthDeviceKey_v1"
    private const val ANDROID_KEYSTORE   = "AndroidKeyStore"

    // Must match passport_security.rs: PROOF_TTL_SECS = 300
    private const val PROOF_TTL_MS       = 300_000L   // 5 minutes
    private const val SESSION_TTL_MS     = 1_800_000L // 30 minutes

    // [FIX v3.1] RFC-compliant hostname regex
    // Old: ^[a-z0-9.-]+\.[a-z]{2,}$ — allowed "a..b.com" and "-.com"
    // New: each label must start/end with alnum, dashes only in middle
    private val DOMAIN_REGEX = Regex(
        "^[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?" +
        "(\\.[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?)*" +
        "\\.[a-z]{2,}\$"
    )

    // ═══════════════════════════════════════════════════════════
    // 🔒 SENSITIVE DATA — RAM Only
    // ═══════════════════════════════════════════════════════════
    @Volatile private var passportSecret:    CharArray? = null
    @Volatile private var countryCode:       String     = DEFAULT_COUNTRY
    @Volatile private var birthDate:         String?    = null
    @Volatile private var expiryDate:        String?    = null
    @Volatile private var documentNumber:    String?    = null
    @Volatile private var firstName:         String?    = null
    @Volatile private var lastName:          String?    = null
    @Volatile private var nationalityCode:   String?    = null
    @Volatile private var dg1Hex:            String?    = null
    @Volatile private var sodHex:            String?    = null
    @Volatile private var mrzLine:           String?    = null
    @Volatile private var dsCertHex:         String?    = null
    @Volatile private var verifierDomain:    String?    = null
    @Volatile private var createdAt:         Long       = 0L

    // Race-condition prevention state
    // [FIX v3.1] Int → Long (overflow safety: Int wraps at ~2B, Long at ~9.2 quintillion)
    @Volatile private var identityVersion:   Long       = 0L

    // Cached proof state
    @Volatile private var cachedProofJson:   String?    = null
    @Volatile private var proofCachedAt:     Long       = 0L
    @Volatile private var proofIdentityVer:  Long       = -1L

    // [FIX v3.1] Keystore pubkey cached — avoids TEE I/O inside read lock every call
    @Volatile private var cachedPubkeyHex:   String?    = null

    private val lock         = ReentrantReadWriteLock()
    private val secureRandom = SecureRandom()

    init {
        startAutoWipeDaemon()
    }

    // ═══════════════════════════════════════════════════════════
    // 💾 CORE IDENTITY SAVE
    // ═══════════════════════════════════════════════════════════

    fun saveIdentity(
        secret:      String,
        country:     String,
        docNumber:   String  = "",
        fName:       String  = "",
        lName:       String  = "",
        nationality: String  = "",
        dob:         String  = "",
        expiry:      String  = "",
        dg1:         String  = "",
        sod:         String  = "",
        mrz:         String  = "",
        dsCert:      String? = null,
        domain:      String? = null
    ) {
        if (secret.length < MIN_SECRET_LENGTH) {
            Log.e(TAG, "❌ Secret too short — min $MIN_SECRET_LENGTH chars")
            return
        }

        lock.write {
            passportSecret?.let { secureWipeCharArray(it) }

            passportSecret  = secret.toCharArray()
            countryCode     = country.uppercase()
            documentNumber  = docNumber.takeIf { it.isNotEmpty() }
            firstName       = fName.takeIf    { it.isNotEmpty() }
            lastName        = lName.takeIf    { it.isNotEmpty() }
            nationalityCode = nationality.takeIf { it.isNotEmpty() }?.uppercase()
            birthDate       = dob.takeIf      { it.isNotEmpty() }
            expiryDate      = expiry.takeIf   { it.isNotEmpty() }
            dg1Hex          = dg1.takeIf      { it.isNotEmpty() }
            sodHex          = sod.takeIf      { it.isNotEmpty() }
            mrzLine         = mrz.takeIf      { it.isNotEmpty() }
            dsCertHex       = dsCert
            createdAt       = System.currentTimeMillis()
            
            domain?.let { applyValidatedDomain(it) }

            // Mutate version to automatically invalidate any in-flight proofs
            identityVersion++
            invalidateProofCacheUnsafe()

            Log.d(TAG, "✅ Identity saved to RAM | ver=$identityVersion | doc=${docNumber.take(4)}***")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔑 GETTERS
    // ═══════════════════════════════════════════════════════════

    fun getSecretChars(): CharArray? {
        lock.read { return passportSecret?.copyOf() }
    }

    @Deprecated(
        message = "Strings are immutable and cannot be wiped from memory. Use getSecretChars() instead.",
        level = DeprecationLevel.ERROR  // [FIX v3.1] WARNING → ERROR, forces migration
    )
    fun getSecret(): String? {
        lock.read { return passportSecret?.let { String(it) } }
    }

    /** [FIX v3.1] Restored — silent removal in v3.0 broke callers */
    fun getSecretOrThrow(): String {
        lock.read {
            val s = passportSecret
            return if (s != null && s.isNotEmpty()) String(s)
            else throw IllegalStateException("⚠️ Identity missing — scan passport first")
        }
    }

    fun hasIdentity(): Boolean {
        lock.read {
            val s = passportSecret
            return s != null && s.isNotEmpty()
        }
    }

    fun isSessionValid(): Boolean {
        lock.read {
            if (createdAt == 0L) return false
            return (System.currentTimeMillis() - createdAt) < SESSION_TTL_MS
        }
    }

    fun getIdentityVersion(): Long {
        lock.read { return identityVersion }
    }

    // ═══════════════════════════════════════════════════════════
    // 🌐 DOMAIN VALIDATION
    // ═══════════════════════════════════════════════════════════

    fun getVerifierDomain(): String? {
        lock.read { return verifierDomain }
    }

    fun setVerifierDomain(domain: String) {
        lock.write { applyValidatedDomain(domain) }
    }

    /** * Internal method. Must be called within a write lock.
     * Prevents null-byte injections and invalid hostname setups.
     */
    private fun applyValidatedDomain(domain: String) {
        val normalized = domain.trim().lowercase()
        if (!normalized.matches(DOMAIN_REGEX)) {
            Log.e(TAG, "❌ Invalid domain format rejected: $domain")
            return
        }
        verifierDomain = normalized
        invalidateProofCacheUnsafe()
        Log.d(TAG, "🌐 Verifier domain secured: $normalized")
    }

    // ═══════════════════════════════════════════════════════════
    // 🏗️ PASSPORT JSON BUILDER
    // ═══════════════════════════════════════════════════════════

    fun buildPassportJson(
        claimType: String,
        domain:    String? = null,
        context:   Context? = null
    ): String? {
        // [FIX v3.1] Heavy ops BEFORE acquiring read lock
        // getOrCreateKeystorePubkeyHex() = TEE I/O (~100-500ms) — must NOT hold lock
        // generateDeviceRngHex() = SecureRandom can block — must NOT hold lock
        val devicePubkeyHex = context?.let { getOrCreateKeystorePubkeyHex(it) } ?: "00"
        val deviceRngHex    = generateDeviceRngHex()  // [FIX v3.1] outside lock

        lock.read {
            // [FIX v3.1] Check BOTH identity existence AND session validity
            // hasIdentity() alone allows expired sessions (up to 60s daemon delay)
            if (!hasIdentity()) {
                Log.e(TAG, "❌ buildPassportJson: no identity")
                return null
            }
            if (!isSessionValid()) {
                Log.e(TAG, "❌ buildPassportJson: session expired — scan passport again")
                return null
            }

            val activeDomain = domain ?: verifierDomain ?: run {
                Log.e(TAG, "❌ buildPassportJson: verifier_domain missing")
                return null
            }

            // [FIX v3.1] Validate hex fields before sending to Rust JNI
            // Invalid hex → Rust returns error; catch it here with a clear message
            val dg1 = dg1Hex ?: ""
            val sod = sodHex ?: ""
            if (dg1.isNotEmpty() && !dg1.isValidHex()) {
                Log.e(TAG, "❌ buildPassportJson: dg1_hex is not valid hex")
                return null
            }
            if (sod.isNotEmpty() && !sod.isValidHex()) {
                Log.e(TAG, "❌ buildPassportJson: sod_hex is not valid hex")
                return null
            }

            val expectedNat = if (claimType == "nationality") nationalityCode else null

            return JSONObject().apply {
                put("mode",                 if (dg1.isEmpty()) "SIMULATED_PASSPORT" else "NFC_PASSPORT")
                put("first_name",           firstName        ?: "")
                put("last_name",            lastName         ?: "")
                put("document_number",      documentNumber   ?: "")
                put("date_of_birth",        birthDate        ?: "")
                put("nationality",          nationalityCode  ?: countryCode)
                put("dg1_hex",              dg1)
                put("sod_hex",              sod)
                put("mrz_line",             mrzLine          ?: "")
                put("ds_cert_hex",          dsCertHex)
                put("claim_type",           claimType)
                put("verifier_domain",      activeDomain)
                put("device_rng_hex",       deviceRngHex)
                put("expected_nationality", expectedNat)
                put("device_pubkey_hex",    devicePubkeyHex)
            }.toString()
        }
    }

    // ═══════════════════════════════════════════════════════════
    // ⚡ THREAD-SAFE PROOF CACHE
    // ═══════════════════════════════════════════════════════════

    fun cacheProofResult(proofJson: String, generatedByVersion: Long) {
        lock.write {
            if (identityVersion != generatedByVersion) {
                Log.w(TAG, "⚠️ Stale proof discarded — identity mutated during generation")
                return
            }
            cachedProofJson  = proofJson
            proofCachedAt    = System.currentTimeMillis()
            proofIdentityVer = generatedByVersion
            Log.d(TAG, "✅ Proof cached | expires in ${PROOF_TTL_MS / 1000}s")
        }
    }

    fun getCachedProof(): String? {
        lock.read {
            val json = cachedProofJson ?: return null
            if (identityVersion != proofIdentityVer) return null
            
            val age = System.currentTimeMillis() - proofCachedAt
            return if (age < PROOF_TTL_MS) {
                Log.d(TAG, "⚡ Proof cache hit | ${(PROOF_TTL_MS - age) / 1000}s remaining")
                json
            } else {
                Log.d(TAG, "⏰ Proof cache expired")
                null
            }
        }
    }

    fun invalidateProofCache() {
        lock.write { invalidateProofCacheUnsafe() }
    }

    private fun invalidateProofCacheUnsafe() {
        cachedProofJson  = null
        proofCachedAt    = 0L
        proofIdentityVer = -1L  // [FIX v3.1] Long
    }

    // ═══════════════════════════════════════════════════════════
    // 🔥 WARMUP
    // ═══════════════════════════════════════════════════════════

    fun warmup() {
        Log.i(TAG, "🔥 Warming up ZK circuit (background)...")
        val t = System.currentTimeMillis()
        try {
            SecurityGate.warmupCircuit()
            Log.i(TAG, "✅ Circuit warm in ${System.currentTimeMillis() - t}ms")
        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Warmup failed: ${e.message}")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🧹 AUTOMATED CLEANUP
    // ═══════════════════════════════════════════════════════════

    fun clear() {
        lock.write {
            clearUnsafe()
            Log.i(TAG, "🧹 Identity + proof cache safely dropped from RAM")
        }
    }

    fun clearIfExpired(): Boolean {
        // [FIX v3.1] Single write lock — atomic check + clear
        // Old: isSessionValid() + hasIdentity() = two separate read locks
        //      identity could be cleared between the two calls
        lock.write {
            val s = passportSecret
            val hasId = s != null && s.isNotEmpty()
            val expired = createdAt > 0L &&
                (System.currentTimeMillis() - createdAt) >= SESSION_TTL_MS
            if (hasId && expired) {
                Log.w(TAG, "⏰ Session TTL exceeded — auto-clearing identity")
                clearUnsafe()
                return true
            }
        }
        return false
    }

    /** Internal clear — must be called within write lock. */
    private fun clearUnsafe() {
        passportSecret?.let { secureWipeCharArray(it) }
        passportSecret  = null
        documentNumber  = null
        firstName       = null
        lastName        = null
        nationalityCode = null
        birthDate       = null
        expiryDate      = null
        dg1Hex          = null
        sodHex          = null
        mrzLine         = null
        dsCertHex       = null
        verifierDomain  = null
        countryCode     = DEFAULT_COUNTRY
        createdAt       = 0L
        identityVersion++
        invalidateProofCacheUnsafe()
    }

    /**
     * Enforces TTL independently of UI lifecycle events.
     */
    private fun startAutoWipeDaemon() {
        thread(isDaemon = true, name = "ZK-AutoWipe-Daemon") {
            while (true) {
                try {
                    Thread.sleep(60_000) // Check every 60 seconds
                    clearIfExpired()
                } catch (e: InterruptedException) {
                    break
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔑 ANDROID KEYSTORE (Hardware Binding)
    // ═══════════════════════════════════════════════════════════

    private fun getOrCreateKeystorePubkeyHex(context: Context, requireBiometric: Boolean = false): String {
        // [FIX v3.1] Return cached value — avoids TEE I/O on every buildPassportJson()
        cachedPubkeyHex?.let { return it }

        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }

            if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                Log.d(TAG, "🔑 Generating Keystore key: $KEYSTORE_ALIAS (biometric=$requireBiometric)")

                val builder = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(requireBiometric)

                if (requireBiometric) {
                    builder.setUserAuthenticationValidityDurationSeconds(30)
                }

                KeyPairGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                    .also { it.initialize(builder.build()) }
                    .generateKeyPair()

                Log.d(TAG, "✅ Keystore EC key generated in TEE")
            }

            val pubKey = keyStore.getCertificate(KEYSTORE_ALIAS).publicKey
            val hex    = pubKey.encoded.toHex()
            cachedPubkeyHex = hex  // [FIX v3.1] Cache — no TEE I/O on next call
            hex

        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Keystore error: ${e.message} — using fallback 00")
            "00"
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🎲 DEVICE RNG & SECURE WIPE
    // ═══════════════════════════════════════════════════════════

    private fun generateDeviceRngHex(): String {
        val bytes = ByteArray(32) 
        secureRandom.nextBytes(bytes)
        return bytes.toHex()
    }

    private fun secureWipeCharArray(chars: CharArray) {
        val noise = ByteArray(chars.size)
        secureRandom.nextBytes(noise)
        for (i in chars.indices) chars[i] = noise[i].toInt().toChar()
        chars.fill('\u0000')
        // [FIX v3.1] Debug log restored under DEBUG guard (was removed in v3.0)
        if (android.os.Build.TYPE == "userdebug" || android.util.Log.isLoggable(TAG, android.util.Log.DEBUG)) {
            Log.d(TAG, "🔐 CharArray wiped (${chars.size} chars)")
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    // [FIX v3.1] Hex validation — catches bad NFC data before JNI call
    private fun String.isValidHex(): Boolean =
        isNotEmpty() && length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    fun getStats(): Map<String, Any> {
        lock.read {
            val now          = System.currentTimeMillis()
            val sessionAgeMs = if (createdAt > 0L) now - createdAt else 0L
            val proofAgeMs   = if (proofCachedAt > 0L) now - proofCachedAt else 0L
            val s            = passportSecret
            // [FIX v3.1] Inline session validity — avoids double read lock
            val sessionValid = createdAt > 0L && sessionAgeMs < SESSION_TTL_MS

            return mapOf(
                "has_identity"       to (s != null && s.isNotEmpty()),
                "identity_version"   to identityVersion,
                "verifier_domain"    to (verifierDomain ?: "not set"),
                "session_age_sec"    to (sessionAgeMs / 1000),
                "session_valid"      to sessionValid,
                "proof_cached"       to (cachedProofJson != null),
                "proof_age_sec"      to (proofAgeMs / 1000),
                "proof_ttl_match"    to "Rust PROOF_TTL_SECS=300 | Kotlin=${PROOF_TTL_MS/1000}s ✅"
            )
        }
    }
}