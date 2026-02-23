package com.example.zkpapp.auth

import android.content.Context
import android.util.Log
import com.example.zkpapp.*
import com.example.zkpapp.models.ProofRequest
import com.example.zkpapp.network.RelayApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Protocol
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object ZkAuthManager {

    // ✅ UPDATED: Railway Production URL (Always Online)
    private const val BASE_URL = "https://zkp-identity-production.up.railway.app/"

    // 🔄 FALLBACK: GitHub Codespaces URL (if Railway fails during development)
    private const val CODESPACES_URL = "https://crispy-dollop-97xj7vjgx4ph9pgg-3000.app.github.dev/"

    @Volatile
    private var running = false

    private val api: RelayApi by lazy {
        val client = OkHttpClient.Builder()
            .protocols(listOf(Protocol.HTTP_1_1))
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()

        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(RelayApi::class.java)
    }

    suspend fun startUniversalLogin(
        context: Context,
        sessionId: String,
        onStatus: (String) -> Unit,
        onSuccess: (ProofMetadata) -> Unit,
        onError: (String) -> Unit,
    ) {
        if (running) return
        running = true

        try {
            // 1. Internet Check
            if (!NetworkUtils.isInternetAvailable(context)) {
                onError("❌ No Internet")
                return
            }

            onStatus("🦁 Fetching Passport Identity...")

            // 2. Data Retrieval (Secure Storage)
            val secret = withContext(Dispatchers.IO) {
                if (!IdentityStorage.hasIdentity()) {
                    throw Exception("⚠️ No Passport Data! Please Scan NFC First.")
                }
                IdentityStorage.getSecret()
                    ?: throw Exception("⚠️ Identity data missing. Please scan passport again.")
            }
            val domain = IdentityStorage.getDomain()

            onStatus("⚙️ Generating ZK Proof...")

            // 3. Generate Proof
            val authResult = ZkAuth.authenticate(
                secret = secret,
                domain = domain,
                challenge = sessionId
            )

            // 4. Handle Result
            when (authResult) {
                is ZkAuthResult.Error -> {
                    Log.e("ZkAuth", "Proof Gen Failed: ${authResult.code}")
                    onError("❌ Proof Error: ${authResult.message}")
                    return
                }

                is ZkAuthResult.Success -> {
                    val proofData = authResult.result
                    val meta = proofData.metadata

                    onStatus("⚡ Proof in ${meta.generation_time_ms}ms\n☁️ Uploading...")

                    // 5. Upload to Server
                    val response = withContext(Dispatchers.IO) {
                        api.uploadProof(
                            ProofRequest(
                                session_id = sessionId,
                                nullifier = proofData.nullifier,
                                proof = proofData.proof,
                                metadata = mapOf(
                                    "generation_time_ms" to meta.generation_time_ms.toString(),
                                    "proof_size_bytes" to meta.proof_size_bytes.toString(),
                                    "circuit_version" to meta.circuit_version,
                                    "circuit_hash" to meta.circuit_hash,
                                    "num_gates" to meta.num_gates.toString(),
                                    "degree_bits" to meta.degree_bits.toString(),
                                    "proof_id" to meta.proof_id.toString()
                                )
                            )
                        )
                    }

                    if (response.isSuccessful) {
                        onSuccess(meta)
                    } else {
                        onError(mapError(response.code()))
                    }
                }
            }

        } catch (e: Exception) {
            Log.e("ZkAuthManager", "Login failed", e)
            onError("⚠️ ${e.message}")
        } finally {
            running = false
        }
    }

    private fun mapError(code: Int) = when (code) {
        401 -> "❌ Server Private"
        404 -> "❌ Session Expired (Try Refreshing Website)"
        502 -> "❌ Invalid QR"
        else -> "❌ Server Error ($code)"
    }
}