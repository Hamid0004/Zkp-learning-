package com.example.zkpapp

import android.util.Log
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * IdentityStorage - The Fort Knox of your App 🏰
 *
 * UPGRADES vs old version:
 * ✅ passportSecret: String → CharArray (proper secure wipe)
 * ✅ secureWipe: reflection hataya, direct CharArray zero-out
 * ✅ getSecret(): exception nahi, null-safe return
 * ✅ Dead code removed (unused birthDate/expiryDate wipe)
 * ✅ clearCache() alias removed — sirf clear() hai
 * ✅ getStats() mein more useful info
 */
object IdentityStorage {

    // ═══════════════════════════════════════════════════════════
    // 📊 CONSTANTS
    // ═══════════════════════════════════════════════════════════
    private const val TAG               = "IdentityStorage"
    private const val DEFAULT_COUNTRY   = "PK"
    private const val MIN_SECRET_LENGTH = 8

    // ═══════════════════════════════════════════════════════════
    // 🔒 PRIVATE SENSITIVE DATA (RAM Only)
    //
    // ✅ String → CharArray
    // CharArray directly wipe ho sakta hai
    // String immutable hoti hai — wipe impossible tha
    // ═══════════════════════════════════════════════════════════
    @Volatile private var passportSecret: CharArray? = null
    @Volatile private var countryCode:    String     = DEFAULT_COUNTRY
    @Volatile private var birthDate:      String?    = null
    @Volatile private var expiryDate:     String?    = null
    @Volatile private var createdAt:      Long       = 0L

    // 🧵 Thread safety
    private val lock         = ReentrantReadWriteLock()
    private val secureRandom = SecureRandom()

    // ═══════════════════════════════════════════════════════════
    // 💾 CORE OPERATIONS
    // ═══════════════════════════════════════════════════════════

    fun saveIdentity(
        secret: String,
        country: String,
        dob:    String = "",
        expiry: String = ""
    ) {
        if (secret.length < MIN_SECRET_LENGTH) {
            Log.e(TAG, "❌ Secret too short! Min $MIN_SECRET_LENGTH chars.")
            return
        }

        lock.write {
            // Wipe old data before overwriting
            passportSecret?.let { secureWipeCharArray(it) }

            // ✅ String → CharArray direct copy
            passportSecret = secret.toCharArray()
            countryCode    = country.uppercase()
            birthDate      = dob.takeIf    { it.isNotEmpty() }
            expiryDate     = expiry.takeIf { it.isNotEmpty() }
            createdAt      = System.currentTimeMillis()

            Log.d(TAG, "✅ Identity secured in RAM (CharArray)")
        }
    }

    /**
     * ✅ Null-safe — caller check kare hasIdentity() pehle
     * Exception throw nahi karta
     */
    fun getSecret(): String? {
        lock.read {
            return passportSecret?.let { String(it) }
        }
    }

    /**
     * Use karo jab exception chahiye (legacy code ke liye)
     */
    fun getSecretOrThrow(): String {
        return getSecret()
            ?: throw IllegalStateException("⚠️ Identity missing! Scan Passport first.")
    }

    fun getDomain(): String {
        lock.read { return countryCode }
    }

    fun hasIdentity(): Boolean {
        lock.read { return passportSecret != null && passportSecret!!.isNotEmpty() }
    }

    // ═══════════════════════════════════════════════════════════
    // 🧹 SECURITY & CLEANUP
    // ═══════════════════════════════════════════════════════════

    fun clear() {
        lock.write {
            // ✅ Direct CharArray wipe — reflection nahi chahiye
            passportSecret?.let { secureWipeCharArray(it) }
            passportSecret = null

            // String fields nullify
            birthDate  = null
            expiryDate = null
            countryCode = DEFAULT_COUNTRY
            createdAt   = 0L

            // GC hint — guarantee nahi lekin helpful
            System.gc()

            Log.i(TAG, "🧹 Identity wiped from RAM")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔐 SECURE WIPE
    //
    // ✅ Fix: Reflection hataya
    // CharArray direct access hota hai — zero-out guaranteed
    // Android 14+ pe bhi kaam karega
    // ═══════════════════════════════════════════════════════════

    private fun secureWipeCharArray(chars: CharArray) {
        // Pass 1: Random noise
        val noise = ByteArray(chars.size)
        secureRandom.nextBytes(noise)
        for (i in chars.indices) {
            chars[i] = noise[i].toInt().toChar()
        }

        // Pass 2: Zero out
        chars.fill('\u0000')

        Log.d(TAG, "🔐 CharArray wiped (${chars.size} chars)")
    }

    // ═══════════════════════════════════════════════════════════
    // 📈 DEBUG INFO
    // ═══════════════════════════════════════════════════════════

    fun getStats(): Map<String, Any> {
        lock.read {
            return mapOf(
                "has_identity"  to hasIdentity(),
                "country"       to countryCode,
                "created_at"    to createdAt,
                "secret_length" to (passportSecret?.size ?: 0),
                "birth_date"    to (birthDate ?: "not set"),
                "expiry_date"   to (expiryDate ?: "not set")
            )
        }
    }
}