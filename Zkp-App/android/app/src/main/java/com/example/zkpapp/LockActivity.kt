package com.example.zkpapp

import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat

class LockActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Anti-Screenshot zaroori hai
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(R.layout.activity_lock)

        findViewById<Button>(R.id.btnGlobalUnlock).setOnClickListener {
            requireBiometricUnlock()
        }

        // Screen khulte hi auto-prompt aa jaye
        requireBiometricUnlock()
    }

    // 🔴 IMPORTANT: Back button disable kar diya taaki user bina unlock kiye wapis na ja sake
    override fun onBackPressed() {
        moveTaskToBack(true) // Yeh app ko wapis minimize kar dega
    }

    private fun requireBiometricUnlock() {
        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    // 🟢 UNLOCKED!
                    ZkpApplication.isAppLocked = false
                    Toast.makeText(applicationContext, "Vault Unlocked ✅", Toast.LENGTH_SHORT).show()
                    finish() // Yeh screen band hogi toh neeche wali asli screen (e.g., TestProof) khud nazar aa jayegi!
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    Toast.makeText(applicationContext, "Fingerprint not recognized ❌", Toast.LENGTH_SHORT).show()
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Mariana Vault Locked")
            .setSubtitle("Verify identity to resume")
            .setNegativeButtonText("Cancel")
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}