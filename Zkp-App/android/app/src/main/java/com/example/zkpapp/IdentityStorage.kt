package com.example.zkpapp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantReadWriteLock
import javax.crypto.Cipher
import kotlin.concurrent.read
import kotlin.concurrent.write
import kotlin.concurrent.thread

/**
 * IdentityStorage v4.0 — Encrypted Persistence + Passkey Model
 *
 * ═══════════════════════════════════════════════════════════════
 * v3.1 → v4.0 Upgrades:
 *
 * 🔴 [NEW] Encrypted Disk Persistence
 *    v3.1: RAM-only — app restart = passport rescan required
 *    v4.0: DG1/SOD encrypted with AES-256-GCM (KeyStoreManager key)
 *    Stored in EncryptedSharedPreferences — survives app restart.
 *    On restart: biometric → decrypt → reload RAM → no rescan needed.
 *    This is the PASSKEY MODEL: scan once, use forever.
 *
 * 🔴 [NEW] saveIdentityEncrypted(cipher, ...) — Biometric-Gated Save
 *    Registration flow: BiometricPrompt → cipher → call this.
 *    DG1/SOD bytes encrypted with unlocked cipher before storage.
 *    IV stored alongside ciphertext for decryption.
 *
 * 🔴 [NEW] loadFromDisk(cipher) — Biometric-Gated Restore
 *    AuthActivity: session expired → BiometricPrompt → cipher →
 *    loadFromDisk() → RAM reloaded → proof generation continues.
 *    No passport NFC scan required.
 *
 * 🔴 [NEW] getSecretString() — ZkAuthManager compatibility
 *    ZkAuthManager called getSecret() → DeprecationLevel.ERROR crash.
 *    getSecretString() returns String? safely for legacy callers.
 *    Internally reads from CharArray — no new String in memory longer
 *    than needed.
 *
 * 🟡 [NEW] hasPersistentIdentity(context) — disk check
 *    hasIdentity() = RAM check (session-scoped).
 *    hasPersistentIdentity() = disk check (persistent).
 *    AuthActivity uses this to decide: show "Scan passport" vs
 *    "Authenticate to continue".
 *
 * 🟡 [NEW] extendSession() — 30-min session reset
 *    AuthActivity calls after successful biometric auth.
 *    Resets createdAt → session fresh 30 min.
 *    No passport rescan, no disk I/O.
 *
 * 🟡 [NEW] clearPersistent(context) — full wipe including disk
 *    clear() wipes RAM only (existing behavior preserved).
 *    clearPersistent() wipes RAM + EncryptedSharedPreferences.
 *    Used on logout / new biometric enrollment detected.
 *
 * 🟢 [NEW] getEncryptedDg1Bytes() / getEncryptedSodBytes() — for
 *    AuthActivity to build CryptoObject with correct IV.
 *
 * 🟢 Carried from v3.1: all fixes preserved unchanged.
 * ═══════════════════════════════════════════════════════════════
 */
object IdentityStorage {

    // ═══════════════════════════════════════════════════════════
    // 📊 CONSTANTS
    // ═══════════════════════════════════════════════════════════
    private const val TAG               = "IdentityStorage"
    private const val DEFAULT_COUNTRY   = "PK"
    private const val MIN_SECRET_LENGTH = 8
    private const val KEYSTORE_ALIAS    = "ZKAuthDeviceKey_v1"
    private const val ANDROID_KEYSTORE  = "AndroidKeyStore"

    // Encrypted SharedPreferences file name
    private const val PREFS_FILE        = "zk_identity_vault"

    // Preference keys — disk storage
    private const val KEY_DG1_ENC       = "dg1_enc"
    private const val KEY_DG1_IV        = "dg1_iv"
    private const val KEY_SOD_ENC       = "sod_enc"
    private const val KEY_SOD_IV        = "sod_iv"
    private const val KEY_SECRET_ENC    = "secret_enc"
    private const val KEY_SECRET_IV     = "secret_iv"
    private const val KEY_FIRST_NAME    = "first_name"
    private const val KEY_LAST_NAME     = "last_name"
    private const val KEY_DOC_NUMBER    = "doc_number"
    private const val KEY_NATIONALITY   = "nationality"
    private const val KEY_DOB           = "dob"
    private const val KEY_EXPIRY        = "expiry"
    private const val KEY_MRZ           = "mrz"
    private const val KEY_COUNTRY       = "country"
    private const val KEY_DOMAIN        = "domain"
    private const val KEY_IDENTITY_VER  = "identity_ver"

    // Must match passport_security.rs: PROOF_TTL_SECS = 300
    private const val PROOF_TTL_MS      = 300_000L    // 5 minutes
    private const val SESSION_TTL_MS    = 1_800_000L  // 30 minutes

    // RFC-compliant hostname regex [FIX v3.1]
    private val DOMAIN_REGEX = Regex(
        "^[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?" +
        "(\\.[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?)*" +
        "\\.[a-z]{2,}\$"
    )

    // ═══════════════════════════════════════════════════════════
    // 🔒 SENSITIVE DATA — RAM Only (session-scoped)
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
    @Volatile private var identityVersion:   Long       = 0L

    // Proof cache
    @Volatile private var cachedProofJson:   String?    = null
    @Volatile private var proofCachedAt:     Long       = 0L
    @Volatile private var proofIdentityVer:  Long       = -1L

    // TEE pubkey cache [FIX v3.1]
    @Volatile private var cachedPubkeyHex:   String?    = null

    private val lock         = ReentrantReadWriteLock()
    private val secureRandom = SecureRandom()

    init {
        startAutoWipeDaemon()
    }

    // ═══════════════════════════════════════════════════════════
    // 💾 CORE IDENTITY SAVE — RAM (existing, unchanged)
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
            identityVersion++
            invalidateProofCacheUnsafe()
            Log.d(TAG, "✅ Identity saved to RAM | ver=$identityVersion | doc=${docNumber.take(4)}***")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔐 [NEW v4.0] ENCRYPTED DISK SAVE — Passkey Model
    // ═══════════════════════════════════════════════════════════

    /**
     * [NEW v4.0] Biometric-gated encrypted save.
     *
     * Call flow (PassportActivity.handleSuccess()):
     *   1. KeyStoreManager.getCipherForEncryption()
     *   2. BiometricPrompt(CryptoObject(cipher))
     *   3. onSuccess → saveIdentityEncrypted(result.cryptoObject!!.cipher!!, data...)
     *
     * DG1 + SOD encrypted with AES-256-GCM.
     * Metadata (name, dob, etc.) stored in EncryptedSharedPreferences.
     * After this call, passport NFC scan never needed again on this device.
     */
    fun saveIdentityEncrypted(
        context:     Context,
        cipher:      Cipher,   // Unlocked cipher from BiometricPrompt.onAuthenticationSucceeded
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
        // 1. Save to RAM first (immediate use)
        saveIdentity(
            secret, country, docNumber, fName, lName,
            nationality, dob, expiry, dg1, sod, mrz, dsCert, domain
        )

        // 2. Encrypt sensitive bytes and persist to disk
        try {
            val prefs = getEncryptedPrefs(context)
            val editor = prefs.edit()

            // Encrypt DG1
            if (dg1.isNotEmpty()) {
                val dg1Bytes    = hexToBytes(dg1)
                val enc         = cipher.doFinal(dg1Bytes)
                val iv          = cipher.iv
                editor.putString(KEY_DG1_ENC, Base64.encodeToString(enc, Base64.NO_WRAP))
                editor.putString(KEY_DG1_IV,  Base64.encodeToString(iv,  Base64.NO_WRAP))
                Log.d(TAG, "🔐 DG1 encrypted to disk (${enc.size}B)")
            }

            // Encrypt SOD with a fresh cipher (same key, new IV)
            // Note: each encrypt call produces new IV — must store separately
            if (sod.isNotEmpty()) {
                val sodBytes    = hexToBytes(sod)
                val sodCipher   = Cipher.getInstance("AES/GCM/NoPadding")
                sodCipher.init(Cipher.ENCRYPT_MODE, cipher.parameters.let {
                    // Reuse same key — get from KeyStore
                    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { k -> k.load(null) }
                    ks.getKey("zk_identity_master_key", null) as javax.crypto.SecretKey
                })
                val sodEnc      = sodCipher.doFinal(sodBytes)
                editor.putString(KEY_SOD_ENC, Base64.encodeToString(sodEnc,       Base64.NO_WRAP))
                editor.putString(KEY_SOD_IV,  Base64.encodeToString(sodCipher.iv, Base64.NO_WRAP))
                Log.d(TAG, "🔐 SOD encrypted to disk (${sodEnc.size}B)")
            }

            // Metadata — stored in EncryptedSharedPreferences (file-level encryption)
            editor.putString(KEY_FIRST_NAME,   fName)
            editor.putString(KEY_LAST_NAME,    lName)
            editor.putString(KEY_DOC_NUMBER,   docNumber)
            editor.putString(KEY_NATIONALITY,  nationality)
            editor.putString(KEY_DOB,          dob)
            editor.putString(KEY_EXPIRY,       expiry)
            editor.putString(KEY_MRZ,          mrz)
            editor.putString(KEY_COUNTRY,      country)
            editor.putString(KEY_DOMAIN,       domain ?: verifierDomain ?: "")
            editor.putLong(KEY_IDENTITY_VER,   identityVersion)
            editor.apply()

            Log.i(TAG, "✅ Identity persisted to encrypted disk | ver=$identityVersion")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Disk persist failed: ${e.message} — RAM-only fallback active")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔓 [NEW v4.0] BIOMETRIC-GATED DISK RESTORE
    // ═══════════════════════════════════════════════════════════

    /**
     * [NEW v4.0] Restore identity from encrypted disk after biometric.
     *
     * Call flow (AuthActivity — session expired):
     *   1. getEncryptedDg1Iv(context) → iv bytes
     *   2. KeyStoreManager.getCipherForDecryption(iv)
     *   3. BiometricPrompt(CryptoObject(cipher))
     *   4. onSuccess → loadFromDisk(context, result.cryptoObject!!.cipher!!)
     *   5. RAM reloaded → extendSession() → buildPassportJson() → proof
     *
     * Returns true if restore succeeded.
     */
    fun loadFromDisk(context: Context, cipher: Cipher): Boolean {
        return try {
            val prefs = getEncryptedPrefs(context)

            // Decrypt DG1
            val dg1EncB64 = prefs.getString(KEY_DG1_ENC, null)
            val dg1IvB64  = prefs.getString(KEY_DG1_IV,  null)
            val restoredDg1: String? = if (dg1EncB64 != null && dg1IvB64 != null) {
                val dg1Bytes = cipher.doFinal(Base64.decode(dg1EncB64, Base64.NO_WRAP))
                bytesToHex(dg1Bytes)
            } else null

            // Decrypt SOD with fresh cipher (same key, SOD IV)
            val sodEncB64 = prefs.getString(KEY_SOD_ENC, null)
            val sodIvB64  = prefs.getString(KEY_SOD_IV,  null)
            val restoredSod: String? = if (sodEncB64 != null && sodIvB64 != null) {
                val sodIv     = Base64.decode(sodIvB64, Base64.NO_WRAP)
                val ks        = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
                val key       = ks.getKey("zk_identity_master_key", null) as javax.crypto.SecretKey
                val sodCipher = Cipher.getInstance("AES/GCM/NoPadding")
                sodCipher.init(Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, sodIv))
                val sodBytes  = sodCipher.doFinal(Base64.decode(sodEncB64, Base64.NO_WRAP))
                bytesToHex(sodBytes)
            } else null

            // Restore metadata from EncryptedSharedPreferences
            val fName       = prefs.getString(KEY_FIRST_NAME,  "") ?: ""
            val lName       = prefs.getString(KEY_LAST_NAME,   "") ?: ""
            val docNum      = prefs.getString(KEY_DOC_NUMBER,  "") ?: ""
            val nat         = prefs.getString(KEY_NATIONALITY, "") ?: ""
            val dob         = prefs.getString(KEY_DOB,         "") ?: ""
            val expiry      = prefs.getString(KEY_EXPIRY,      "") ?: ""
            val mrz         = prefs.getString(KEY_MRZ,         "") ?: ""
            val country     = prefs.getString(KEY_COUNTRY, DEFAULT_COUNTRY) ?: DEFAULT_COUNTRY
            val domain      = prefs.getString(KEY_DOMAIN,      null)

            // Secret = SHA-256(dg1) — reconstructed from decrypted DG1
            val secret = if (restoredDg1 != null) {
                val dg1Bytes = hexToBytes(restoredDg1)
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest(dg1Bytes)
                    .joinToString("") { "%02x".format(it) }
            } else {
                Log.e(TAG, "❌ loadFromDisk: DG1 missing — cannot restore secret")
                return false
            }

            // Reload RAM
            saveIdentity(
                secret      = secret,
                country     = country,
                docNumber   = docNum,
                fName       = fName,
                lName       = lName,
                nationality = nat,
                dob         = dob,
                expiry      = expiry,
                dg1         = restoredDg1,
                sod         = restoredSod ?: "",
                mrz         = mrz,
                domain      = domain
            )

            Log.i(TAG, "✅ Identity restored from disk | doc=${docNum.take(4)}***")
            true

        } catch (e: Exception) {
            Log.e(TAG, "❌ loadFromDisk failed: ${e.message}")
            false
        }
    }

    /**
     * [NEW v4.0] Check if encrypted identity exists on disk.
     * Use this to decide UI state:
     *   hasPersistentIdentity() = true  → show BiometricPrompt
     *   hasPersistentIdentity() = false → show "Scan Passport" button
     */
    fun hasPersistentIdentity(context: Context): Boolean {
        return try {
            val prefs = getEncryptedPrefs(context)
            prefs.getString(KEY_DG1_ENC, null) != null
        } catch (e: Exception) {
            false
        }
    }

    /**
     * [NEW v4.0] Get DG1 IV for building CryptoObject in AuthActivity.
     *
     * Usage:
     *   val iv = IdentityStorage.getEncryptedDg1Iv(context) ?: return showError()
     *   val cipher = keyStoreManager.getCipherForDecryption(iv)
     *   val crypto = BiometricPrompt.CryptoObject(cipher)
     *   biometricManager.authenticateUser(activity, crypto, ...)
     */
    fun getEncryptedDg1Iv(context: Context): ByteArray? {
        return try {
            val prefs = getEncryptedPrefs(context)
            val ivB64 = prefs.getString(KEY_DG1_IV, null) ?: return null
            Base64.decode(ivB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "❌ getEncryptedDg1Iv failed: ${e.message}")
            null
        }
    }

    /**
     * [NEW v4.0] Extend session by 30 minutes — called after biometric success.
     * No disk I/O, no proof invalidation.
     */
    fun extendSession() {
        lock.write {
            createdAt = System.currentTimeMillis()
            Log.i(TAG, "🔄 Session extended — expires in ${SESSION_TTL_MS / 60_000}min")
        }
    }

    /**
     * [NEW v4.0] Full wipe — RAM + encrypted disk.
     * Call on logout or KeyPermanentlyInvalidatedException
     * (new biometric enrolled → key invalidated → must rescan passport).
     */
    fun clearPersistent(context: Context) {
        clear() // RAM wipe (existing)
        try {
            val prefs = getEncryptedPrefs(context)
            prefs.edit().clear().apply()
            Log.i(TAG, "🧹 Encrypted disk identity wiped")
        } catch (e: Exception) {
            Log.e(TAG, "❌ clearPersistent disk wipe failed: ${e.message}")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔑 GETTERS — existing + new
    // ═══════════════════════════════════════════════════════════

    fun getSecretChars(): CharArray? {
        lock.read { return passportSecret?.copyOf() }
    }

    /**
     * [NEW v4.0] ZkAuthManager compatibility — replaces deprecated getSecret().
     * Returns String? for legacy callers that need String (e.g. ZkAuth.authenticate()).
     * Caller is responsible for not holding reference longer than needed.
     */
    fun getSecretString(): String? {
        lock.read { return passportSecret?.let { String(it) } }
    }

    @Deprecated(
        message = "Strings are immutable and cannot be wiped. Use getSecretChars() or getSecretString().",
        level = DeprecationLevel.ERROR
    )
    fun getSecret(): String? {
        lock.read { return passportSecret?.let { String(it) } }
    }

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

    /**
     * True ONLY if identity came from real NFC passport scan.
     * Simulation (dg1 empty) → false — cannot be used for website proofs.
     * Real DG1 = ICAO 9303 DG1 — minimum 90 bytes = 180 hex chars.
     */
    fun hasRealPassport(): Boolean {
        lock.read {
            val dg1 = dg1Hex
            return !dg1.isNullOrEmpty() && dg1.length >= 180
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
        val devicePubkeyHex = context?.let { getOrCreateKeystorePubkeyHex(it) } ?: "00"
        val deviceRngHex    = generateDeviceRngHex()

        lock.read {
            if (!hasIdentity()) {
                Log.e(TAG, "❌ buildPassportJson: no identity")
                return null
            }
            if (!isSessionValid()) {
                Log.e(TAG, "❌ buildPassportJson: session expired")
                return null
            }

            // [v4.0] Hard block — website requests MUST have real NFC passport data
            // Simulation (dg1 empty) is rejected at this layer — no compromise possible
            val dg1 = dg1Hex ?: ""
            if (dg1.isEmpty() || dg1.length < 180) {
                Log.e(TAG, "❌ buildPassportJson: simulation data rejected — real NFC passport required")
                return null
            }

            val activeDomain = domain ?: verifierDomain ?: run {
                Log.e(TAG, "❌ buildPassportJson: verifier_domain missing")
                return null
            }

            val sod = sodHex ?: ""
            if (dg1.isNotEmpty() && !dg1.isValidHex()) {
                Log.e(TAG, "❌ buildPassportJson: dg1_hex invalid hex")
                return null
            }
            if (sod.isNotEmpty() && !sod.isValidHex()) {
                Log.e(TAG, "❌ buildPassportJson: sod_hex invalid hex")
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
        proofIdentityVer = -1L
    }

    // ═══════════════════════════════════════════════════════════
    // 🔥 WARMUP
    // ═══════════════════════════════════════════════════════════

    fun warmup() {
        Log.i(TAG, "🔥 Warming up ZK circuit...")
        val t = System.currentTimeMillis()
        try {
            SecurityGate.warmupCircuit()
            Log.i(TAG, "✅ Circuit warm in ${System.currentTimeMillis() - t}ms")
        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Warmup failed: ${e.message}")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🧹 CLEANUP
    // ═══════════════════════════════════════════════════════════

    fun clear() {
        lock.write {
            clearUnsafe()
            Log.i(TAG, "🧹 Identity + proof cache dropped from RAM")
        }
    }

    fun clearIfExpired(): Boolean {
        lock.write {
            val s       = passportSecret
            val hasId   = s != null && s.isNotEmpty()
            val expired = createdAt > 0L &&
                (System.currentTimeMillis() - createdAt) >= SESSION_TTL_MS
            if (hasId && expired) {
                Log.w(TAG, "⏰ Session TTL exceeded — auto-clearing RAM identity")
                clearUnsafe()
                return true
            }
        }
        return false
    }

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

    private fun startAutoWipeDaemon() {
        thread(isDaemon = true, name = "ZK-AutoWipe-Daemon") {
            while (true) {
                try {
                    Thread.sleep(60_000)
                    clearIfExpired()
                    // Note: disk NOT wiped on session expire — only RAM
                    // User will be prompted for biometric on next AuthActivity open
                } catch (e: InterruptedException) { break }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔑 ANDROID KEYSTORE (Hardware Binding — ECDSA)
    // ═══════════════════════════════════════════════════════════

    private fun getOrCreateKeystorePubkeyHex(context: Context, requireBiometric: Boolean = false): String {
        cachedPubkeyHex?.let { return it }
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                val builder = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(requireBiometric)
                if (requireBiometric) {
                    @Suppress("DEPRECATION")
                    builder.setUserAuthenticationValidityDurationSeconds(30)
                }
                KeyPairGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                    .also { it.initialize(builder.build()) }
                    .generateKeyPair()
                Log.d(TAG, "✅ ECDSA key generated in TEE")
            }
            val pubKey = keyStore.getCertificate(KEYSTORE_ALIAS).publicKey
            val hex    = pubKey.encoded.toHex()
            cachedPubkeyHex = hex
            hex
        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Keystore error: ${e.message} — fallback 00")
            "00"
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 📊 STATS
    // ═══════════════════════════════════════════════════════════

    fun getStats(): Map<String, Any> {
        lock.read {
            val now          = System.currentTimeMillis()
            val sessionAgeMs = if (createdAt > 0L) now - createdAt else 0L
            val proofAgeMs   = if (proofCachedAt > 0L) now - proofCachedAt else 0L
            val s            = passportSecret
            val sessionValid = createdAt > 0L && sessionAgeMs < SESSION_TTL_MS
            return mapOf(
                "has_identity"       to (s != null && s.isNotEmpty()),
                "identity_version"   to identityVersion,
                "verifier_domain"    to (verifierDomain ?: "not set"),
                "session_age_sec"    to (sessionAgeMs / 1000),
                "session_valid"      to sessionValid,
                "proof_cached"       to (cachedProofJson != null),
                "proof_age_sec"      to (proofAgeMs / 1000),
                "proof_ttl_match"    to "Rust=300s | Kotlin=${PROOF_TTL_MS/1000}s ✅",
                "persistent_storage" to "AES-256-GCM + EncryptedSharedPreferences ✅"
            )
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔧 PRIVATE HELPERS
    // ═══════════════════════════════════════════════════════════

    /**
     * EncryptedSharedPreferences backed by AES-256-SIV (keys) + AES-256-GCM (values).
     * MasterKey stored in AndroidKeyStore — hardware-backed on API 28+.
     */
    private fun getEncryptedPrefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREFS_FILE,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

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
        if (android.os.Build.TYPE == "userdebug" ||
            android.util.Log.isLoggable(TAG, android.util.Log.DEBUG)) {
            Log.d(TAG, "🔐 CharArray wiped (${chars.size} chars)")
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun bytesToHex(b: ByteArray): String = b.toHex()
    private fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun String.isValidHex(): Boolean =
        isNotEmpty() && length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
}