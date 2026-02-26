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

class KeyStoreManager {

    companion object {
        private const val KEY_ALIAS        = "zk_identity_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION   = "AES/GCM/NoPadding"
        private const val TAG              = "KeyStoreManager"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    // StrongBox support — hardware-isolated key if available
    fun generateMasterKey(useStrongBox: Boolean = false) {
        if (isKeyReady()) return

        // First attempt: try with StrongBox if requested
        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                buildAndGenerateKey(useStrongBox = true)
                Log.d(TAG, "Master Key generated in StrongBox (hardware-isolated)")
                return
            } catch (e: StrongBoxUnavailableException) {
                Log.w(TAG, "StrongBox unavailable, falling back to TEE: ${e.message}")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox attempt failed, falling back to TEE: ${e.message}")
            }
        }

        // Fallback: normal TEE-backed AndroidKeyStore key
        buildAndGenerateKey(useStrongBox = false)
        Log.d(TAG, "Master Key generated in TEE (AndroidKeyStore)")
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

    fun isKeyReady(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    // Key delete karo — vault wipe ke waqt
    fun deleteKey() {
        try {
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS)
                Log.d(TAG, "Master Key deleted")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete key: ${e.message}")
        }
    }

    fun getCipherForEncryption(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getKey())
        return cipher
    }

    fun getCipherForDecryption(iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec   = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getKey(), spec)
        return cipher
    }

    private fun getKey(): SecretKey {
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }
}