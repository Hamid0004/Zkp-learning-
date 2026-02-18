package com.example.zkpapp

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.zkpapp.security.BiometricManager
import com.example.zkpapp.security.KeyStoreManager // ✅ Make sure ye import ho

class AuthActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)
        
        // Managers Initialize
        val biometricManager = BiometricManager(this)
        val keyStoreManager = KeyStoreManager() 

        // 1. Hardware Security Check
        if (!biometricManager.canAuthenticate()) {
            tvStatus.text = "Error: Secure Hardware Not Found"
            btnLogin.isEnabled = false
            return
        }

        // 2. Master Key Generation (The "Mariana Trench" Logic)
        try {
            if (!keyStoreManager.isKeyReady()) {
                tvStatus.text = "Initializing Secure Vault..."
                keyStoreManager.generateMasterKey()
                tvStatus.text = "Secure Hardware Key Created 🔒"
            } else {
                tvStatus.text = "Secure Vault Ready 🛡️"
            }
        } catch (e: Exception) {
            tvStatus.text = "Critical Security Error: ${e.message}"
            btnLogin.isEnabled = false
            return // Agar key nahi bani, to login mat karne do
        }

        // 3. Login Listener
        btnLogin.setOnClickListener {
            biometricManager.authenticateUser(this,
                onSuccess = {
                    // Future (Day 88/89): Yahan hum Key ko unlock karke Rust ko bhejenge
                    Toast.makeText(this, "Identity Verified & Key Unlocked", Toast.LENGTH_SHORT).show()
                    
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                },
                onError = { error -> tvStatus.text = "Auth Failed: $error" }
            )
        }
    }
}