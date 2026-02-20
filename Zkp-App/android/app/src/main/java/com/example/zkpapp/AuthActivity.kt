package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import com.example.zkpapp.security.BiometricManager
import com.example.zkpapp.security.KeyStoreManager
import java.nio.charset.Charset

class AuthActivity : AppCompatActivity() {

    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var biometricManager: BiometricManager
    private val PREFS_NAME = "secure_prefs"
    private val KEY_ENCRYPTED_DATA = "data"
    private val KEY_IV = "iv"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)

        biometricManager = BiometricManager(this)
        keyStoreManager = KeyStoreManager()

        // 1. Initial Checks
        if (!biometricManager.canAuthenticate()) {
            tvStatus.text = "Error: Hardware not secure"
            btnLogin.isEnabled = false
            return
        }
        
        try {
            keyStoreManager.generateMasterKey()
        } catch (e: Exception) {
            tvStatus.text = "Key Error: ${e.message}"
            return
        }

        // 2. Determine Mode (Encrypt New vs Decrypt Existing)
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val existingData = prefs.getString(KEY_ENCRYPTED_DATA, null)
        val existingIv = prefs.getString(KEY_IV, null)

        if (existingData != null && existingIv != null) {
            tvStatus.text = "Locked Data Found 🔒\nAuthenticate to Decrypt"
            btnLogin.text = "Unlock Vault"
        } else {
            tvStatus.text = "No Data Found.\nAuthenticate to Encrypt 'Hello ZK'"
            btnLogin.text = "Create Secret"
        }

        // 3. Button Action
        btnLogin.setOnClickListener {
            try {
                if (existingData != null && existingIv != null) {
                    // --- DECRYPTION FLOW ---
                    val ivBytes = Base64.decode(existingIv, Base64.DEFAULT)
                    val cipher = keyStoreManager.getCipherForDecryption(ivBytes) // Locked Cipher
                    
                    biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                        onSuccess = { result ->
                            try {
                                val unlockedCipher = result.cryptoObject?.cipher
                                val encryptedBytes = Base64.decode(existingData, Base64.DEFAULT)
                                val decryptedBytes = unlockedCipher?.doFinal(encryptedBytes)
                                val message = String(decryptedBytes!!, Charset.defaultCharset())
                                
                                // =========================================================
                                // 🟢 DAY 89: RUST ENGINE BRIDGE INTEGRATION 
                                // =========================================================
                                tvStatus.text = "Decrypted. Handing over to Rust Engine... 🦀"
                                
                                // Send the decrypted secret directly to Rust!
                                val proofBytes = SecureVaultJni.generateSecureIdentityProof(message)
                                val proofResult = String(proofBytes, Charsets.UTF_8)

                                tvStatus.text = "Rust Output: $proofResult ✅"
                                Toast.makeText(this@AuthActivity, "ZKP Engine Connected!", Toast.LENGTH_SHORT).show()
                                
                                // Main Activity par jump abhi ke liye hide kar diya hai 
                                // taaki Rust ka result screen par clearly dikhe.
                                btnLogin.postDelayed({
                                    startActivity(Intent(this@AuthActivity, MainActivity::class.java))
                                    finish()
                                }, 1500)
                                
                                
                            } catch (e: Exception) {
                                tvStatus.text = "Decryption/Rust Failed: ${e.message}"
                            }
                        },
                        onError = { tvStatus.text = "Auth Error: $it" }
                    )

                } else {
                    // --- ENCRYPTION FLOW ---
                    val cipher = keyStoreManager.getCipherForEncryption() // Locked Cipher
                    
                    biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                        onSuccess = { result ->
                            try {
                                val unlockedCipher = result.cryptoObject?.cipher
                                val secretMessage = "Hello ZK World! (Day 88)"
                                val encryptedBytes = unlockedCipher?.doFinal(secretMessage.toByteArray())
                                val ivBytes = unlockedCipher?.iv

                                // Save to Prefs
                                prefs.edit()
                                    .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encryptedBytes, Base64.DEFAULT))
                                    .putString(KEY_IV, Base64.encodeToString(ivBytes, Base64.DEFAULT))
                                    .apply()

                                tvStatus.text = "Data Encrypted & Saved 🛡️"
                                btnLogin.text = "Unlock Vault"
                                Toast.makeText(this@AuthActivity, "Saved Securely!", Toast.LENGTH_SHORT).show()
                                
                            } catch (e: Exception) {
                                tvStatus.text = "Encryption Failed: ${e.message}"
                            }
                        },
                        onError = { tvStatus.text = "Auth Error: $it" }
                    )
                }
            } catch (e: Exception) {
                tvStatus.text = "Cipher Init Error: ${e.message}"
            }
        }
    }
}