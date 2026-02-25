package com.example.zkpapp

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ProcessLifecycleOwner

/**
 * MainActivity - Dashboard / Entry Screen
 *
 * Flow:
 * 1️⃣ Scan Passport → Generate Identity
 * 2️⃣ Scan QR → LoginActivity (Web login only)
 * 3️⃣ Offline Identity → OfflineMenuActivity (QR Transmit / Verify)
 * 4️⃣ Test Proof → VerifierActivity
 */
class MainActivity : AppCompatActivity() {

    // 🛡️ Tracks if the app was sent to the background
    private var isAppLocked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // ----------------------------------------
        // 🛡️ LAYER 1: Anti-Screenshot & Screen Rec (Mariana Trench)
        // ----------------------------------------
        // Yeh recent apps menu mein bhi app ka preview black kar dega
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_main)

        // ----------------------------------------
        // 🛡️ LAYER 2: App Background/Foreground Tracker
        // ----------------------------------------
        ProcessLifecycleOwner.get().lifecycle.addObserver(LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_STOP -> {
                    // App background mein chali gayi
                    lockAppSession()
                }
                Lifecycle.Event.ON_START -> {
                    // App wapis foreground mein aayi
                    if (isAppLocked) {
                        requireBiometricUnlock()
                    }
                }
                else -> {}
            }
        })

        // ----------------------------------------
        // 🟦 SCAN QR FOR WEB LOGIN
        // ----------------------------------------
        findViewById<Button>(R.id.btnScanQrLogin).setOnClickListener {
            if (IdentityStorage.hasIdentity()) {
                val intent = Intent(this, LoginActivity::class.java).apply {
                    putExtra("MODE", "WEB_LOGIN")
                }
                startActivity(intent)
            } else {
                Toast.makeText(this, "⚠️ Please Scan Passport First!", Toast.LENGTH_SHORT).show()
            }
        }

        // ----------------------------------------
        // 🟧 SCAN PASSPORT TO CREATE IDENTITY
        // ----------------------------------------
        findViewById<Button>(R.id.btnScanPassport).setOnClickListener {
            startActivity(Intent(this, PassportActivity::class.java))
        }

        // ----------------------------------------
        // 🟩 OFFLINE IDENTITY MENU
        // ----------------------------------------
        findViewById<Button>(R.id.btnOfflineIdentity).setOnClickListener {
            if (IdentityStorage.hasIdentity()) {
                val intent = Intent(this, OfflineMenuActivity::class.java)
                startActivity(intent)
            } else {
                Toast.makeText(this, "⚠️ Please Scan Passport First!", Toast.LENGTH_SHORT).show()
            }
        }

        // ----------------------------------------
        // ⬜ TEST PROOF
        // ----------------------------------------
        findViewById<Button>(R.id.btnTestProof).setOnClickListener {
            startActivity(Intent(this, TestProofActivity::class.java))
        }
    }

    // =========================================
    // 🛡️ DAY 91 SECURITY FUNCTIONS
    // =========================================

    private fun lockAppSession() {
        isAppLocked = true
        // 🛡️ LAYER 3: RAM Wipe (Optional placeholder for future)
        // e.g., SecureVaultJni.wipeSensitiveDataFromRAM()
        println("🔒 [SECURITY]: App moved to background. Session Locked.")
    }

    private fun requireBiometricUnlock() {
        println("☝️ [SECURITY]: Requesting Biometric Authentication...")

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    // Agar user cancel kare, app lock hi rahegi
                    Toast.makeText(applicationContext, "Session Locked: $errString", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // 🟢 UNLOCKED!
                    isAppLocked = false 
                    Toast.makeText(applicationContext, "Identity Verified ✅", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Fingerprint not recognized ❌", Toast.LENGTH_SHORT).show()
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Secure Session Locked")
            .setSubtitle("Verify identity to resume Mariana Trench Engine")
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}