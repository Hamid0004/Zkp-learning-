package com.example.zkpapp

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.zkpapp.security.BiometricManager

class AuthActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth)

        val btnLogin = findViewById<Button>(R.id.btnLogin)
        val tvStatus = findViewById<TextView>(R.id.tvStatus)
        val biometricManager = BiometricManager(this)

        if (!biometricManager.canAuthenticate()) {
            tvStatus.text = "Error: Secure Hardware Not Found"
            btnLogin.isEnabled = false
        }

        btnLogin.setOnClickListener {
            biometricManager.authenticateUser(this,
                onSuccess = {
                    Toast.makeText(this, "Access Granted", Toast.LENGTH_SHORT).show()
                    startActivity(Intent(this, MainActivity::class.java))
                    finish()
                },
                onError = { error -> tvStatus.text = "Failed: $error" }
            )
        }
    }
}