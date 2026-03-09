package com.example.zkpapp.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * KeyStoreManager v2.0
 *
 * ═══════════════════════════════════════════════════════════════
 * v1.0 → v2.0 Fixes:
 *
 * 🔴 [FIX] getCipherForEncryption() auto-generates key if missing
 *    v1.0: getKey() called before generateMasterKey() → NPE crash.
 *    v2.0: ensureKeyReady() called at start of both cipher functions.
 *    Safe to call getCipherForEncryption() without prior setup call.
 *
 * 🔴 [FIX] getCipherForDecryption() auto-generates key if missing
 *    Same NPE risk — same fix applied.
 *
 * 🟡 [FIX] getKey() null-safe — throws clear exception
 *    v1.0: keyStore.getKey() returns null → cast to SecretKey → NPE.
 *    v2.0: explicit null check → IllegalStateException with message.
 *
 * 🟡 [FIX] KeyPermanentlyInvalidatedException handled in cipher fns
 *    New biometric enrolled → key invalidated by Android.
 *    v1.0: exception propagated silently → caller confused.
 *    v2.0: caught + re-thrown as KeyInvalidatedException with message
 *    "New biometric enrolled — rescan passport required".
 *    Caller (AuthActivity/PassportActivity) can show correct UI.
 *
 * 🟢 [FIX] keyStore reloaded after key generation
 *    v1.0: keyStore loaded once in init. After generateKey(), the
 *    in-memory keyStore instance didn't reflect the new entry.
 *    v2.0: keyStore.load(null) called after generation to refresh.
 * ═══════════════════════════════════════════════════════════════
 */
class KeyStoreManager {

    companion object {
        private const val KEY_ALIAS        = "zk_identity_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION   = "AES/GCM/NoPadding"
        private const val TAG              = "KeyStoreManager"
    }

    /**
     * Custom exception — thrown when key is permanently invalidated
     * (new biometric enrolled, or device re-enrolled).
     * Caller must:
     *   1. Call deleteKey()
     *   2. Call IdentityStorage.clearPersistent(context)
     *   3. Show "New biometric detected — please rescan your passport"
     */
    class KeyInvalidatedException(message: String) : Exception(message)

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    // ─────────────────────────────────────────────────────────────
    // KEY GENERATION
    // ─────────────────────────────────────────────────────────────

    /**
     * Generate AES-256-GCM master key in AndroidKeyStore.
     * StrongBox attempted first if available (hardware-isolated chip).
     * Falls back to TEE (Trusted Execution Environment) automatically.
     *
     * Safe to call multiple times — no-op if key already exists.
     */
    fun generateMasterKey(useStrongBox: Boolean = false) {
        if (isKeyReady()) return

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                buildAndGenerateKey(useStrongBox = true)
                keyStore.load(null) // [FIX v2.0] refresh after generation
                Log.d(TAG, "✅ Master Key in StrongBox (hardware-isolated)")
                return
            } catch (e: StrongBoxUnavailableException) {
                Log.w(TAG, "StrongBox unavailable → TEE fallback: ${e.message}")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox failed → TEE fallback: ${e.message}")
            }
        }

        buildAndGenerateKey(useStrongBox = false)
        keyStore.load(null) // [FIX v2.0] refresh after generation
        Log.d(TAG, "✅ Master Key in TEE (AndroidKeyStore)")
    }

    private fun buildAndGenerateKey(useStrongBox: Boolean) {
        try {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            val keySpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .apply {
                    if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        setIsStrongBoxBacked(true)
                    }
                }
                .build()

            keyGenerator.init(keySpec)
            keyGenerator.generateKey()
        } catch (e: Exception) {
            throw RuntimeException("Failed to create Master Key (StrongBox=$useStrongBox)", e)
        }
    }

    // ─────────────────────────────────────────────────────────────
    // CIPHER FUNCTIONS
    // ─────────────────────────────────────────────────────────────

    /**
     * Returns an ENCRYPT_MODE cipher ready for CryptoObject.
     *
     * [FIX v2.0] ensureKeyReady() called first — safe without prior
     * generateMasterKey() call. IV is generated automatically by
     * the cipher — retrieve it AFTER biometric via cipher.iv.
     *
     * @throws KeyInvalidatedException if new biometric was enrolled
     */
    fun getCipherForEncryption(): Cipher {
        ensureKeyReady()
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getKey())
            cipher
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            Log.e(TAG, "🔑 Key permanently invalidated — new biometric enrolled")
            throw KeyInvalidatedException(
                "New biometric enrolled — key invalidated. " +
                "Please rescan your passport to re-register."
            )
        }
    }

    /**
     * Returns a DECRYPT_MODE cipher ready for CryptoObject.
     *
     * [FIX v2.0] ensureKeyReady() + KeyPermanentlyInvalidatedException handling.
     *
     * @param iv The IV stored alongside ciphertext at encryption time
     * @throws KeyInvalidatedException if new biometric was enrolled
     */
    fun getCipherForDecryption(iv: ByteArray): Cipher {
        ensureKeyReady()
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, getKey(), GCMParameterSpec(128, iv))
            cipher
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            Log.e(TAG, "🔑 Key permanently invalidated — new biometric enrolled")
            throw KeyInvalidatedException(
                "New biometric enrolled — key invalidated. " +
                "Please rescan your passport to re-register."
            )
        }
    }

    // ─────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────

    fun isKeyReady(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    fun deleteKey() {
        try {
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
                Log.d(TAG, "🗑️ Master Key deleted")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete key: ${e.message}")
        }
    }

    /**
     * [FIX v2.0] Auto-generate key if not present.
     * Prevents NPE when cipher functions called before generateMasterKey().
     */
    private fun ensureKeyReady() {
        if (!isKeyReady()) {
            Log.w(TAG, "⚠️ Key missing — auto-generating (TEE)")
            generateMasterKey(useStrongBox = false)
        }
    }

    /**
     * [FIX v2.0] Null-safe key retrieval.
     * v1.0 cast null → NPE. Now throws clear IllegalStateException.
     */
    private fun getKey(): SecretKey {
        return keyStore.getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException(
                "AES key '$KEY_ALIAS' missing from AndroidKeyStore. " +
                "Call generateMasterKey() first."
            )
    }
}