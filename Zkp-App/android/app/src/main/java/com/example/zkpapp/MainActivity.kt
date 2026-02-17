package com.example.zkpapp

import android.content.Intent
import android.os.Bundle
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
        setContentView(R.layout.activity_main)

        // ----------------------------------------
        // 🟦 SCAN QR FOR WEB LOGIN
        // Opens LoginActivity in WEB_LOGIN mode
        // ----------------------------------------
        findViewById<Button>(R.id.btnScanQrLogin).setOnClickListener {
            if (IdentityStorage.hasIdentity()) {
                val intent = Intent(this, LoginActivity::class.java).apply {
                    putExtra("MODE", "WEB_LOGIN")
                }
                startActivity(intent)
            } else {
                Toast.makeText(
                    this,
                    "⚠️ Please Scan Passport First!",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

        // ----------------------------------------
        // 🟧 SCAN PASSPORT TO CREATE IDENTITY
        // Opens PassportActivity
        // ----------------------------------------
        findViewById<Button>(R.id.btnScanPassport).setOnClickListener {
            startActivity(Intent(this, PassportActivity::class.java))
        }

        // ----------------------------------------
        // 🟩 OFFLINE IDENTITY MENU
        // Opens OfflineMenuActivity (QR + Transmit/Verify)
        // ----------------------------------------
        findViewById<Button>(R.id.btnOfflineIdentity).setOnClickListener {
            if (IdentityStorage.hasIdentity()) {
                val intent = Intent(this, OfflineMenuActivity::class.java)
                startActivity(intent)
            } else {
                Toast.makeText(
                    this,
                    "⚠️ Please Scan Passport First!",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

        // ----------------------------------------
        // ⬜ TEST PROOF
        // Directly opens VerifierActivity
        // ----------------------------------------
        findViewById<Button>(R.id.btnTestProof).setOnClickListener {
            startActivity(Intent(this, VerifierActivity::class.java))
        }
    }
}
