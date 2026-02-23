package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.EditText
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

    private lateinit var btnLogin: Button
    private lateinit var btnRestore: Button
    private lateinit var tvStatus: TextView

    // Bip39 Mock Wordlist
    private val wordList = listOf(
        "apple", "brave", "ocean", "logic", "tiger", "flame", "globe", "novel",
        "pilot", "quest", "radar", "solar", "token", "urban", "vital", "wired",
        "yacht", "zebra", "alpha", "chaos", "delta", "echo", "forge", "ghost",
        "heavy", "ivory", "juice", "karma", "lemon", "magic", "ninja", "orbit"
    )

    private fun generate12Words(): String {
        val secureRandom = SecureRandom()
        return (1..12).joinToString(" ") { wordList[secureRandom.nextInt(wordList.size)] }
    }

    private fun isVaultLocked(): Boolean {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_ENCRYPTED_DATA, null) != null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth)

        btnLogin = findViewById(R.id.btnLogin)
        btnRestore = findViewById(R.id.btnRestore)
        tvStatus = findViewById(R.id.tvStatus)

        biometricManager = BiometricManager(this)
        keyStoreManager = KeyStoreManager()

        if (!biometricManager.canAuthenticate()) {
            tvStatus.text = "Error: Hardware not secure"
            btnLogin.isEnabled = false
            return
        }
        
        try { keyStoreManager.generateMasterKey() } catch (e: Exception) { return }

        // Initial UI Setup
        refreshUIState()

        // 🟢 MAIN BUTTON LOGIC
        btnLogin.setOnClickListener {
            if (isVaultLocked()) {
                unlockVault() // Decrypt existing
            } else {
                val secretMessage = generate12Words()
                encryptAndSaveSeed(secretMessage, false) // Create new
            }
        }

        // 🔵 RESTORE BUTTON LOGIC
        btnRestore.setOnClickListener {
            showRestoreDialog()
        }
    }

    private fun refreshUIState() {
        if (isVaultLocked()) {
            tvStatus.text = "Locked Vault Found 🔒\nAuthenticate to Decrypt"
            btnLogin.text = "Unlock Vault"
            btnRestore.visibility = View.GONE // Hide restore button if vault exists
        } else {
            tvStatus.text = "No Identity Found.\nCreate or Restore Recovery Seed"
            btnLogin.text = "Create Secret"
            btnRestore.visibility = View.VISIBLE // Show restore button for new devices
        }
    }

    // 🔓 DECRYPTION FLOW
    private fun unlockVault() {
        try {
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val ivBytes = Base64.decode(prefs.getString(KEY_IV, ""), Base64.DEFAULT)
            val cipher = keyStoreManager.getCipherForDecryption(ivBytes)
            
            biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                onSuccess = { result ->
                    val unlockedCipher = result.cryptoObject?.cipher
                    val encryptedBytes = Base64.decode(prefs.getString(KEY_ENCRYPTED_DATA, ""), Base64.DEFAULT)
                    val decryptedBytes = unlockedCipher?.doFinal(encryptedBytes)
                    val recoverySeed = String(decryptedBytes!!, Charset.defaultCharset())
                    
                    val proofBytes = SecureVaultJni.generateSecureIdentityProof(recoverySeed)
                    val proofResult = String(proofBytes, Charsets.UTF_8)
                    
                    tvStatus.text = "Rust Output: $proofResult"
                    Toast.makeText(this, "Identity Verified!", Toast.LENGTH_SHORT).show()
                },
                onError = { tvStatus.text = "Auth Error: $it" }
            )
        } catch (e: Exception) { tvStatus.text = "Decryption Error: ${e.message}" }
    }

    // 🔐 ENCRYPTION FLOW (Handles both Create New & Restore)
    private fun encryptAndSaveSeed(seed: String, isRestore: Boolean) {
        try {
            val cipher = keyStoreManager.getCipherForEncryption()
            biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                onSuccess = { result ->
                    val unlockedCipher = result.cryptoObject?.cipher
                    val encryptedBytes = unlockedCipher?.doFinal(seed.toByteArray())
                    val ivBytes = unlockedCipher?.iv

                    getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                        .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encryptedBytes, Base64.DEFAULT))
                        .putString(KEY_IV, Base64.encodeToString(ivBytes, Base64.DEFAULT))
                        .apply()

                    if (!isRestore) {
                        runOnUiThread {
                            AlertDialog.Builder(this)
                                .setTitle("🚨 SECRET RECOVERY PHRASE")
                                .setMessage("Write these 12 words down...\n\n$seed")
                                .setPositiveButton("I WROTE IT DOWN") { _, _ ->
                                    // FIX 1: App Stuck Issue Fixed (Reloads activity to update UI)
                                    recreate() 
                                }
                                .setCancelable(false)
                                .show()
                        }
                    } else {
                        Toast.makeText(this, "Identity Restored Successfully!", Toast.LENGTH_LONG).show()
                        recreate() // Reload to show Unlock state
                    }
                },
                onError = { tvStatus.text = "Auth Error: $it" }
            )
        } catch (e: Exception) { tvStatus.text = "Encryption Error: ${e.message}" }
    }

    // 📥 INPUT DIALOG FOR RESTORE
    private fun showRestoreDialog() {
        val input = EditText(this)
        input.hint = "type your 12 words here separated by spaces"
        
        AlertDialog.Builder(this)
            .setTitle("Restore Identity")
            .setMessage("Enter your 12-word recovery phrase:")
            .setView(input)
            .setPositiveButton("Restore") { _, _ ->
                val typedSeed = input.text.toString().trim()
                // Simple validation check (should be exactly 12 words)
                if (typedSeed.split("\\s+".toRegex()).size == 12) {
                    encryptAndSaveSeed(typedSeed, isRestore = true)
                } else {
                    Toast.makeText(this, "Error: Must be exactly 12 words", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}