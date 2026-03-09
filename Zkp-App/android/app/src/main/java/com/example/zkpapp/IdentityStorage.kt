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
 */
object IdentityStorage {

    private const val TAG               = "IdentityStorage"
    private const val DEFAULT_COUNTRY   = "PK"
    private const val MIN_SECRET_LENGTH = 8
    private const val KEYSTORE_ALIAS    = "ZKAuthDeviceKey_v1"
    private const val ANDROID_KEYSTORE  = "AndroidKeyStore"
    private const val PREFS_FILE        = "zk_identity_vault"

    private const val KEY_DG1_ENC       = "dg1_enc"
    private const val KEY_DG1_IV        = "dg1_iv"
    private const val KEY_SOD_ENC       = "sod_enc"
    private const val KEY_SOD_IV        = "sod_iv"
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

    private const val PROOF_TTL_MS      = 300_000L
    private const val SESSION_TTL_MS    = 1_800_000L

    private val DOMAIN_REGEX = Regex(
        "^[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?" +
        "(\\.[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?)*" +
        "\\.[a-z]{2,}\$"
    )

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

    @Volatile private var cachedProofJson:   String?    = null
    @Volatile private var proofCachedAt:     Long       = 0L
    @Volatile private var proofIdentityVer:  Long       = -1L
    @Volatile private var cachedPubkeyHex:   String?    = null

    private val lock         = ReentrantReadWriteLock()
    private val secureRandom = SecureRandom()

    init { startAutoWipeDaemon() }

    // ── RAM Save ──────────────────────────────────────────────

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
            Log.e(TAG, "❌ Secret too short — min $MIN_SECRET_LENGTH chars"); return
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

    // ── Encrypted Disk Save ───────────────────────────────────

    fun saveIdentityEncrypted(
        context:     Context,
        cipher:      Cipher,
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
        saveIdentity(secret, country, docNumber, fName, lName,
                     nationality, dob, expiry, dg1, sod, mrz, dsCert, domain)
        try {
            val prefs  = getEncryptedPrefs(context)
            val editor = prefs.edit()

            if (dg1.isNotEmpty()) {
                val enc = cipher.doFinal(hexToBytes(dg1))
                val iv  = cipher.iv
                editor.putString(KEY_DG1_ENC, Base64.encodeToString(enc, Base64.NO_WRAP))
                editor.putString(KEY_DG1_IV,  Base64.encodeToString(iv,  Base64.NO_WRAP))
                Log.d(TAG, "🔐 DG1 encrypted to disk (${enc.size}B)")
            }

            if (sod.isNotEmpty()) {
                val ks        = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
                val key       = ks.getKey("zk_identity_master_key", null) as javax.crypto.SecretKey
                val sodCipher = Cipher.getInstance("AES/GCM/NoPadding")
                sodCipher.init(Cipher.ENCRYPT_MODE, key)
                val sodEnc = sodCipher.doFinal(hexToBytes(sod))
                editor.putString(KEY_SOD_ENC, Base64.encodeToString(sodEnc,       Base64.NO_WRAP))
                editor.putString(KEY_SOD_IV,  Base64.encodeToString(sodCipher.iv, Base64.NO_WRAP))
                Log.d(TAG, "🔐 SOD encrypted to disk (${sodEnc.size}B)")
            }

            editor.putString(KEY_FIRST_NAME,  fName)
            editor.putString(KEY_LAST_NAME,   lName)
            editor.putString(KEY_DOC_NUMBER,  docNumber)
            editor.putString(KEY_NATIONALITY, nationality)
            editor.putString(KEY_DOB,         dob)
            editor.putString(KEY_EXPIRY,      expiry)
            editor.putString(KEY_MRZ,         mrz)
            editor.putString(KEY_COUNTRY,     country)
            editor.putString(KEY_DOMAIN,      domain ?: verifierDomain ?: "")
            editor.putLong(KEY_IDENTITY_VER,  identityVersion)
            editor.apply()

            Log.i(TAG, "✅ Identity persisted to encrypted disk | ver=$identityVersion")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Disk persist failed: ${e.message} — RAM-only fallback active")
        }
    }

    // ── Disk Restore ──────────────────────────────────────────

    fun loadFromDisk(context: Context, cipher: Cipher): Boolean {
        return try {
            val prefs = getEncryptedPrefs(context)

            val dg1EncB64 = prefs.getString(KEY_DG1_ENC, null)
            val dg1IvB64  = prefs.getString(KEY_DG1_IV,  null)
            val restoredDg1: String? = if (dg1EncB64 != null && dg1IvB64 != null) {
                bytesToHex(cipher.doFinal(Base64.decode(dg1EncB64, Base64.NO_WRAP)))
            } else null

            val sodEncB64 = prefs.getString(KEY_SOD_ENC, null)
            val sodIvB64  = prefs.getString(KEY_SOD_IV,  null)
            val restoredSod: String? = if (sodEncB64 != null && sodIvB64 != null) {
                val sodIv     = Base64.decode(sodIvB64, Base64.NO_WRAP)
                val ks        = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
                val key       = ks.getKey("zk_identity_master_key", null) as javax.crypto.SecretKey
                val sodCipher = Cipher.getInstance("AES/GCM/NoPadding")
                sodCipher.init(Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(128, sodIv))
                bytesToHex(sodCipher.doFinal(Base64.decode(sodEncB64, Base64.NO_WRAP)))
            } else null

            val fName   = prefs.getString(KEY_FIRST_NAME,  "") ?: ""
            val lName   = prefs.getString(KEY_LAST_NAME,   "") ?: ""
            val docNum  = prefs.getString(KEY_DOC_NUMBER,  "") ?: ""
            val nat     = prefs.getString(KEY_NATIONALITY, "") ?: ""
            val dob     = prefs.getString(KEY_DOB,         "") ?: ""
            val expiry  = prefs.getString(KEY_EXPIRY,      "") ?: ""
            val mrz     = prefs.getString(KEY_MRZ,         "") ?: ""
            val country = prefs.getString(KEY_COUNTRY, DEFAULT_COUNTRY) ?: DEFAULT_COUNTRY
            val domain  = prefs.getString(KEY_DOMAIN,      null)

            val secret = if (restoredDg1 != null) {
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest(hexToBytes(restoredDg1))
                    .joinToString("") { "%02x".format(it) }
            } else {
                Log.e(TAG, "❌ loadFromDisk: DG1 missing"); return false
            }

            saveIdentity(secret, country, docNum, fName, lName, nat,
                         dob, expiry, restoredDg1, restoredSod ?: "", mrz, domain = domain)

            Log.i(TAG, "✅ Identity restored from disk | doc=${docNum.take(4)}***")
            true
        } catch (e: Exception) {
            Log.e(TAG, "❌ loadFromDisk failed: ${e.message}"); false
        }
    }

    fun hasPersistentIdentity(context: Context): Boolean {
        return try { getEncryptedPrefs(context).getString(KEY_DG1_ENC, null) != null }
        catch (e: Exception) { false }
    }

    fun getEncryptedDg1Iv(context: Context): ByteArray? {
        return try {
            val ivB64 = getEncryptedPrefs(context).getString(KEY_DG1_IV, null) ?: return null
            Base64.decode(ivB64, Base64.NO_WRAP)
        } catch (e: Exception) { Log.e(TAG, "❌ getEncryptedDg1Iv: ${e.message}"); null }
    }

    fun extendSession() {
        lock.write {
            createdAt = System.currentTimeMillis()
            Log.i(TAG, "🔄 Session extended — ${SESSION_TTL_MS / 60_000}min")
        }
    }

    fun clearPersistent(context: Context) {
        clear()
        try { getEncryptedPrefs(context).edit().clear().apply()
              Log.i(TAG, "🧹 Encrypted disk identity wiped") }
        catch (e: Exception) { Log.e(TAG, "❌ clearPersistent: ${e.message}") }
    }

    // ── Getters ───────────────────────────────────────────────

    fun getSecretChars(): CharArray? { lock.read { return passportSecret?.copyOf() } }

    fun getSecretString(): String? { lock.read { return passportSecret?.let { String(it) } } }

    @Deprecated("Use getSecretChars() or getSecretString()", level = DeprecationLevel.ERROR)
    fun getSecret(): String? { lock.read { return passportSecret?.let { String(it) } } }

    fun getSecretOrThrow(): String {
        lock.read {
            val s = passportSecret
            return if (s != null && s.isNotEmpty()) String(s)
            else throw IllegalStateException("⚠️ Identity missing — scan passport first")
        }
    }

    fun hasIdentity(): Boolean {
        lock.read { val s = passportSecret; return s != null && s.isNotEmpty() }
    }

    fun hasRealPassport(): Boolean {
        lock.read { val dg1 = dg1Hex; return !dg1.isNullOrEmpty() && dg1.length >= 180 }
    }

    fun isSessionValid(): Boolean {
        lock.read {
            if (createdAt == 0L) return false
            return (System.currentTimeMillis() - createdAt) < SESSION_TTL_MS
        }
    }

    fun getIdentityVersion(): Long { lock.read { return identityVersion } }

    // ── Domain ────────────────────────────────────────────────

    fun getVerifierDomain(): String? { lock.read { return verifierDomain } }

    fun setVerifierDomain(domain: String) { lock.write { applyValidatedDomain(domain) } }

    private fun applyValidatedDomain(domain: String) {
        val n = domain.trim().lowercase()
        if (!n.matches(DOMAIN_REGEX)) { Log.e(TAG, "❌ Invalid domain: $domain"); return }
        verifierDomain = n
        invalidateProofCacheUnsafe()
        Log.d(TAG, "🌐 Domain: $n")
    }

    // ── buildPassportJson ─────────────────────────────────────

    fun buildPassportJson(
        claimType: String,
        domain:    String? = null,
        context:   Context? = null
    ): String? {
        val devicePubkeyHex = context?.let { getOrCreateKeystorePubkeyHex(it) } ?: "00"
        val deviceRngHex    = generateDeviceRngHex()

        lock.read {
            if (!hasIdentity()) { Log.e(TAG, "❌ buildPassportJson: no identity"); return null }
            if (!isSessionValid()) { Log.e(TAG, "❌ buildPassportJson: session expired"); return null }

            val activeDomain = domain ?: verifierDomain ?: run {
                Log.e(TAG, "❌ buildPassportJson: verifier_domain missing"); return null
            }

            val dg1 = dg1Hex ?: ""
            val sod = sodHex ?: ""
            if (dg1.isNotEmpty() && !dg1.isValidHex()) {
                Log.e(TAG, "❌ buildPassportJson: dg1_hex invalid hex"); return null
            }
            if (sod.isNotEmpty() && !sod.isValidHex()) {
                Log.e(TAG, "❌ buildPassportJson: sod_hex invalid hex"); return null
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

    // ── Proof Cache ───────────────────────────────────────────

    fun cacheProofResult(proofJson: String, generatedByVersion: Long) {
        lock.write {
            if (identityVersion != generatedByVersion) {
                Log.w(TAG, "⚠️ Stale proof discarded"); return
            }
            cachedProofJson  = proofJson
            proofCachedAt    = System.currentTimeMillis()
            proofIdentityVer = generatedByVersion
            Log.d(TAG, "✅ Proof cached | ${PROOF_TTL_MS / 1000}s TTL")
        }
    }

    fun getCachedProof(): String? {
        lock.read {
            val json = cachedProofJson ?: return null
            if (identityVersion != proofIdentityVer) return null
            val age = System.currentTimeMillis() - proofCachedAt
            return if (age < PROOF_TTL_MS) {
                Log.d(TAG, "⚡ Cache hit | ${(PROOF_TTL_MS - age) / 1000}s left"); json
            } else { Log.d(TAG, "⏰ Cache expired"); null }
        }
    }

    fun invalidateProofCache() { lock.write { invalidateProofCacheUnsafe() } }
    private fun invalidateProofCacheUnsafe() { cachedProofJson = null; proofCachedAt = 0L; proofIdentityVer = -1L }

    // ── Warmup ────────────────────────────────────────────────

    fun warmup() {
        Log.i(TAG, "🔥 Warming up ZK circuit...")
        val t = System.currentTimeMillis()
        try { SecurityGate.warmupCircuit(); Log.i(TAG, "✅ Warm in ${System.currentTimeMillis() - t}ms") }
        catch (e: Exception) { Log.e(TAG, "⚠️ Warmup failed: ${e.message}") }
    }

    // ── Cleanup ───────────────────────────────────────────────

    fun clear() { lock.write { clearUnsafe(); Log.i(TAG, "🧹 RAM cleared") } }

    fun clearIfExpired(): Boolean {
        lock.write {
            val s       = passportSecret
            val hasId   = s != null && s.isNotEmpty()
            val expired = createdAt > 0L && (System.currentTimeMillis() - createdAt) >= SESSION_TTL_MS
            if (hasId && expired) { Log.w(TAG, "⏰ Auto-clear RAM"); clearUnsafe(); return true }
        }
        return false
    }

    private fun clearUnsafe() {
        passportSecret?.let { secureWipeCharArray(it) }
        passportSecret = null; documentNumber = null; firstName = null; lastName = null
        nationalityCode = null; birthDate = null; expiryDate = null
        dg1Hex = null; sodHex = null; mrzLine = null; dsCertHex = null
        verifierDomain = null; countryCode = DEFAULT_COUNTRY; createdAt = 0L
        identityVersion++; invalidateProofCacheUnsafe()
    }

    private fun startAutoWipeDaemon() {
        thread(isDaemon = true, name = "ZK-AutoWipe") {
            while (true) { try { Thread.sleep(60_000); clearIfExpired() }
                           catch (e: InterruptedException) { break } }
        }
    }

    // ── Keystore ──────────────────────────────────────────────

    private fun getOrCreateKeystorePubkeyHex(context: Context, requireBiometric: Boolean = false): String {
        cachedPubkeyHex?.let { return it }
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            if (!ks.containsAlias(KEYSTORE_ALIAS)) {
                val spec = KeyGenParameterSpec.Builder(
                    KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(requireBiometric)
                    .build()
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                    .also { it.initialize(spec) }.generateKeyPair()
                Log.d(TAG, "✅ ECDSA key generated in TEE")
            }
            val hex = ks.getCertificate(KEYSTORE_ALIAS).publicKey.encoded.toHex()
            cachedPubkeyHex = hex; hex
        } catch (e: Exception) { Log.e(TAG, "⚠️ Keystore: ${e.message}"); "00" }
    }

    // ── Stats ─────────────────────────────────────────────────

    fun getStats(): Map<String, Any> {
        lock.read {
            val now          = System.currentTimeMillis()
            val sessionAgeMs = if (createdAt > 0L) now - createdAt else 0L
            val proofAgeMs   = if (proofCachedAt > 0L) now - proofCachedAt else 0L
            val s            = passportSecret
            return mapOf(
                "has_identity"     to (s != null && s.isNotEmpty()),
                "identity_version" to identityVersion,
                "verifier_domain"  to (verifierDomain ?: "not set"),
                "session_age_sec"  to (sessionAgeMs / 1000),
                "session_valid"    to (createdAt > 0L && sessionAgeMs < SESSION_TTL_MS),
                "proof_cached"     to (cachedProofJson != null),
                "proof_age_sec"    to (proofAgeMs / 1000),
            )
        }
    }

    // ── Helpers ───────────────────────────────────────────────

    private fun getEncryptedPrefs(context: Context): SharedPreferences {
        val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        return EncryptedSharedPreferences.create(
            context, PREFS_FILE, masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun generateDeviceRngHex(): String {
        val b = ByteArray(32); secureRandom.nextBytes(b); return b.toHex()
    }

    private fun secureWipeCharArray(chars: CharArray) {
        val noise = ByteArray(chars.size); secureRandom.nextBytes(noise)
        for (i in chars.indices) chars[i] = noise[i].toInt().toChar()
        chars.fill('\u0000')
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    private fun bytesToHex(b: ByteArray): String = b.toHex()
    private fun hexToBytes(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun String.isValidHex(): Boolean =
        isNotEmpty() && length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
}