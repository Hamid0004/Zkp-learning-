package com.example.zkpapp

object SecureVaultJni {
    init {
        // Rust library load karega
        System.loadLibrary("zkp_mobile") 
    }

    // 🌊 MARIANA TRENCH UPGRADE: 
    // String ki jagah ByteArray use kar rahe hain taaki RAM mein clear-text leak na ho
    // aur use hone ke foran baad isko 0x00 se overwrite kiya ja sake.
    external fun generateSecureIdentityProof(unlockedSeedBytes: ByteArray): ByteArray
}