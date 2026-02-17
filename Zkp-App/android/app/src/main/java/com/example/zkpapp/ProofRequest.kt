package com.example.zkpapp.models

import kotlinx.serialization.Serializable

@Serializable
data class ProofRequest(
    val session_id: String, // QR Code se milega
    val nullifier: String,  // 🦁 ADDED: Ye wo "Short ID" hai jo Dashboard par dikhegi
    val proof: String       // 🦁 RENAMED: 'proof_data' -> 'proof' (Server se match karne ke liye)
)