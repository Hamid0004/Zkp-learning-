package com.example.zkpapp.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class KeyStoreManager {

    companion object {
        private const val KEY_ALIAS = "zk_identity_master_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    // 1. Check karna ki Master Key pehle se bani hai ya nahi
    fun isKeyReady(): Boolean {
        return keyStore.containsAlias(KEY_ALIAS)
    }

    // 2. Mariana Trench Level Key Generate Karna 🌊
    fun generateMasterKey() {
        try {
            if (isKeyReady()) return // Agar pehle se hai toh dobara mat banao

            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, 
                ANDROID_KEYSTORE
            )

            val keySpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM) // GCM sabse secure mode hai
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256) // AES-256 (Military Grade)
                .setUserAuthenticationRequired(true) // ⚠️ YAHAN HAI JADOO: Bina Fingerprint ke ye key kooda hai
                .setInvalidatedByBiometricEnrollment(true) // Agar naya fingerprint add hua, toh key delete ho jayegi (Anti-Hack)
                .build()

            keyGenerator.init(keySpec)
            keyGenerator.generateKey()
            
            Log.d("KeyStoreManager", "Master Key Generated inside Secure Hardware! ⚓")

        } catch (e: Exception) {
            Log.e("KeyStoreManager", "Key Generation Failed: ${e.message}")
            throw e
        }
    }

    // 3. Cipher (Lock/Unlock Engine) ready karna
    // Ye function hum kal use karenge jab hum data encrypt karenge
    fun getCipher(): Cipher {
        val key = keyStore.getKey(KEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/${KeyProperties.ENCRYPTION_PADDING_NONE}")
        
        // Note: Hum yahan cipher.init() abhi call nahi kar rahe, 
        // kyunki uske liye Biometric Prompt ki zaroorat padegi (CryptoObject)
        return cipher
    }
}