package com.example.zkpapp.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class KeyStoreManager {

    companion object {
        private const val KEY_ALIAS = "zk_identity_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        // AES (Algorithm) / GCM (Mode) / NoPadding (Standard)
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    // 1. Generate Key (Day 87 Logic - Same)
    fun generateMasterKey() {
        if (isKeyReady()) return
        try {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            val keySpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true) // ⚠️ CRITICAL: Needs Fingerprint
                .setInvalidatedByBiometricEnrollment(true)
                .build()
            keyGenerator.init(keySpec)
            keyGenerator.generateKey()
            Log.d("KeyStoreManager", "Master Key Generated ⚓")
        } catch (e: Exception) {
            throw RuntimeException("Failed to create Master Key", e)
        }
    }

    fun isKeyReady(): Boolean = keyStore.containsAlias(KEY_ALIAS)

    // 2. Encryption ke liye Cipher maangna
    fun getCipherForEncryption(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = getKey()
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    // 3. Decryption ke liye Cipher maangna (IV ki zaroorat padegi)
    fun getCipherForDecryption(iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = getKey()
        val spec = GCMParameterSpec(128, iv) // 128-bit Auth Tag length
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        return cipher
    }

    private fun getKey(): SecretKey {
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }
}