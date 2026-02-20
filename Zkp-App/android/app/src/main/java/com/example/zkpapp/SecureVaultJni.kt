package com.example.zkpapp

object SecureVaultJni {
    init {
        // Rust library load karega
        System.loadLibrary("zkp_mobile") 
    }

    // 🔒 DAY 89: Naya clean function jo sirf secure seed handle karega
    external fun generateSecureIdentityProof(unlockedSeed: String): ByteArray
}