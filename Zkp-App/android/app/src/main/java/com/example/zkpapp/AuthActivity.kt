package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import com.example.zkpapp.security.BiometricManager
import com.example.zkpapp.security.KeyStoreManager
import java.nio.charset.Charset
import java.security.SecureRandom

class AuthActivity : AppCompatActivity() {

    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var biometricManager: BiometricManager
    private val PREFS_NAME = "secure_prefs"
    private val KEY_ENCRYPTED_DATA = "data"
    private val KEY_IV = "iv"

    // 🛡️ Bip39 Mock Wordlist (FYP ke liye choti list, production mein 2048 words hote hain)
    private val wordList = listOf(
        "apple", "brave", "ocean", "logic", "tiger", "flame", "globe", "novel",
        "pilot", "quest", "radar", "solar", "token", "urban", "vital", "wired",
        "yacht", "zebra", "alpha", "chaos", "delta", "echo", "forge", "ghost",
        "heavy", "ivory", "juice", "karma", "lemon", "magic", "ninja", "orbit"
    )

    // Helper: Generate 12 Random Words securely
    private fun generate12Words(): String {
        val secureRandom = SecureRandom()
        return (1..12).joinToString(" ") { wordList[secureRandom.nextInt(wordList.size)] }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)

        biometricManager = BiometricManager(this)
        keyStoreManager = KeyStoreManager()

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

        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val existingData = prefs.getString(KEY_ENCRYPTED_DATA, null)
        val existingIv = prefs.getString(KEY_IV, null)

        if (existingData != null && existingIv != null) {
            tvStatus.text = "Locked Vault Found 🔒\nAuthenticate to Decrypt"
            btnLogin.text = "Unlock Vault"
        } else {
            tvStatus.text = "No Identity Found.\nAuthenticate to Create Recovery Seed"
            btnLogin.text = "Create Secret"
        }

        btnLogin.setOnClickListener {
            try {
                if (existingData != null && existingIv != null) {
                    // ==========================================
                    // 🔓 DECRYPTION FLOW (Login)
                    // ==========================================
                    val ivBytes = Base64.decode(existingIv, Base64.DEFAULT)
                    val cipher = keyStoreManager.getCipherForDecryption(ivBytes)
                    
                    biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                        onSuccess = { result ->
                            try {
                                val unlockedCipher = result.cryptoObject?.cipher
                                val encryptedBytes = Base64.decode(existingData, Base64.DEFAULT)
                                val decryptedBytes = unlockedCipher?.doFinal(encryptedBytes)
                                val recoverySeed = String(decryptedBytes!!, Charset.defaultCharset())
                                
                                tvStatus.text = "Seed Decrypted! Handing to Rust... 🦀"
                                
                                // Send the 12-words to Rust HKDF & Merkle Engine
                                val proofBytes = SecureVaultJni.generateSecureIdentityProof(recoverySeed)
                                val proofResult = String(proofBytes, Charsets.UTF_8)

                                tvStatus.text = "Rust Output: $proofResult"
                                Toast.makeText(this@AuthActivity, "Identity Verified!", Toast.LENGTH_SHORT).show()
                                
                                /* Dashboard par jump (Currently disabled for testing)
                                btnLogin.postDelayed({
                                    startActivity(Intent(this@AuthActivity, MainActivity::class.java))
                                    finish()
                                }, 1500)
                                */
                                
                            } catch (e: Exception) {
                                tvStatus.text = "Decryption/Rust Failed: ${e.message}"
                            }
                        },
                        onError = { tvStatus.text = "Auth Error: $it" }
                    )

                } else {
                    // ==========================================
                    // 🔐 ENCRYPTION FLOW (New Account Setup)
                    // ==========================================
                    val cipher = keyStoreManager.getCipherForEncryption()
                    
                    biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                        onSuccess = { result ->
                            try {
                                val unlockedCipher = result.cryptoObject?.cipher
                                
                                // 🟢 NEW: Generate 12-Word Recovery Phrase
                                val secretMessage = generate12Words()
                                val encryptedBytes = unlockedCipher?.doFinal(secretMessage.toByteArray())
                                val ivBytes = unlockedCipher?.iv

                                prefs.edit()
                                    .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encryptedBytes, Base64.DEFAULT))
                                    .putString(KEY_IV, Base64.encodeToString(ivBytes, Base64.DEFAULT))
                                    .apply()

                                tvStatus.text = "Vault Secured 🛡️"
                                btnLogin.text = "Unlock Vault"

                                // 🚨 NEW: Show Alert Dialog to user to write down the seed
                                runOnUiThread {
                                    AlertDialog.Builder(this@AuthActivity)
                                        .setTitle("🚨 SECRET RECOVERY PHRASE")
                                        .setMessage("Write these 12 words down on paper. If you uninstall the app, THIS is the only way to recover your Identity!\n\n$secretMessage")
                                        .setPositiveButton("I WROTE IT DOWN", null)
                                        .setCancelable(false) // User dismiss nahi kar sakta jab tak button na dabaye
                                        .show()
                                }
                                
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