package com.example.zkpapp

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // ----------------------------------------
        // 🛡️ Anti-Screenshot & Screen Rec (Mariana Trench)
        // ----------------------------------------
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )

        setContentView(R.layout.activity_main)

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
}