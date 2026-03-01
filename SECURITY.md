# 🛡️ ZKP Mobile Identity Vault

> A military-grade, privacy-first mobile identity wallet leveraging Zero-Knowledge Proofs (ZK-STARKs) and Post-Quantum cryptographic primitives.

![Kotlin](https://img.shields.io/badge/Kotlin-1.9-blue.svg?logo=kotlin)
![Rust](https://img.shields.io/badge/Rust-1.75-orange.svg?logo=rust)
![Plonky2](https://img.shields.io/badge/ZKP-Plonky2-purple.svg)
![Security](https://img.shields.io/badge/Security-Mariana_Trench-red.svg)

## 📖 Overview
The **ZKP Mobile Identity Vault** is an advanced mobile architecture designed to shift the paradigm from *Data Sharing* to *Data Proving*. By utilizing Fast Reed-Solomon Interactive Oracle Proofs (FRI) via Plonky2, the application allows users to generate cryptographic proofs of identity directly on their mobile device—without ever exposing the underlying plaintext data.

This project goes beyond standard mobile development by implementing strict, enterprise-level security protocols, mitigating both conventional runtime threats and theoretical quantum-computing attacks.

## ✨ Core Features

### 🔐 1. Cryptographic Identity Generation
* **True BIP39 Standard:** Generates 128-bit entropy with SHA-256 checksum validation for creating standard 12-word recovery phrases.
* **HKDF-SHA256 Derivation:** Securely expands the raw hardware seed into a 32-byte Master ZKP Key.
* **Merkle-Based Selective Disclosure:** Identity attributes are hashed into a salted Merkle Tree, allowing users to prove specific data points without revealing their entire identity.

### 🛑 2. Active Tamper Defense & Hard Blocking
* **Environment Validation:** Actively scans for rooted environments, Magisk/SuperSU binaries, custom ROM test-keys, and emulators.
* **The "Hard Block":** Automatically kills the app process (`finishAffinity()`) and blocks UI rendering upon detecting a compromised OS, preventing memory hooking via Frida or Xposed.
* **Rate Limiting & "Nuclear Option":** Implements strict exponential backoff for biometric failures. Automatically wipes the encrypted vault after 10 consecutive failed attempts.

### 🧹 3. Deep Memory Protection (Zeroization)
* **String-Pool Bypassing:** Critical secrets are never stored in Java/Kotlin `String` objects to prevent garbage-collection latency attacks. Data is handled exclusively as raw `ByteArray` streams.
* **C++ Heap Wiping:** Across the JNI bridge, the Rust engine utilizes the `zeroize` crate to forcefully overwrite the allocated RAM with `0x00` the moment the ZKP generation concludes.

### 🏛️ 4. Hardware-Backed Storage
* **Android StrongBox / Titan M:** Master encryption keys are generated and bound directly to the device's hardware security module (HSM).
* **AES-GCM Encryption:** Data at rest is secured via AES-GCM, gated by Android's `BiometricPrompt` (`CryptoObject`).

## 🧠 System Architecture

The application is built on a high-performance **Kotlin ↔ JNI ↔ Rust** bridge:

1. **Frontend (Kotlin + Jetpack Compose):** Handles reactive UI states via `StateFlow` and securely captures biometric hardware prompts.
2. **The JNI Bridge (C-Bindings):** Safely transports raw byte arrays between the JVM and the native C++ heap, configured with `panic = "unwind"` to prevent JVM crashes.
3. **Backend Engine (Rust):** Executes heavy mathematical operations, including HKDF extraction, Merkle Tree hashing, and Plonky2 ZK-STARK circuit evaluations.

## 🛡️ Threat Model Compliance
This architecture has been rigorously designed against the **STRIDE Threat Model** and complies with the **OWASP MASVS (Mobile Application Security Verification Standard)**:
* **MASVS-STORAGE:** Secure memory wiping and encrypted SharedPreferences.
* **MASVS-CRYPTO:** Domain-separated salts, true entropy generation, and Post-Quantum Resistant (PQR) hash-based cryptography.
* **MASVS-RESILIENCE:** Strict root detection, debug-blocking, and process self-termination.

## 🚀 Getting Started

### Prerequisites
* [Android Studio (Iguana+)](https://developer.android.com/studio)
* [Rust Toolchain (rustup)](https://rustup.rs/)
* Android NDK (Installed via Android Studio SDK Manager)

### Build Instructions
1. Clone the repository:
   ```bash
   git clone [https://github.com/arsalankhann0004/zkp-identity.git](https://github.com/arsalankhann0004/zkp-identity.git)