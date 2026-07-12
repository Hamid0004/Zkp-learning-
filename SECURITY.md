# ZKAuth — Mobile Identity Vault (Security Design)

> A privacy-first mobile identity wallet leveraging Zero-Knowledge Proofs (Plonky2) and hash-based cryptographic primitives.

![Kotlin](https://img.shields.io/badge/Kotlin-1.9-blue.svg?logo=kotlin)
![Rust](https://img.shields.io/badge/Rust-1.75-orange.svg?logo=rust)
![Plonky2](https://img.shields.io/badge/ZKP-Plonky2-purple.svg)

## Overview
ZKAuth's identity vault shifts the paradigm from *data sharing* to *data proving*. Using Fast Reed-Solomon Interactive Oracle Proofs (FRI) via Plonky2, the app generates cryptographic proofs of identity directly on-device — without ever exposing the underlying plaintext data.

This document covers the security design choices made to defend against both conventional runtime threats and the cryptographic assumptions the system deliberately avoids.

## Core Features

### 1. Cryptographic Identity Generation
* **BIP39-standard seed phrases:** 128-bit entropy with SHA-256 checksum validation, generating standard 12-word recovery phrases.
* **HKDF-SHA256 derivation:** Expands the raw hardware seed into a 32-byte master ZKP key.
* **Merkle-based selective disclosure:** Identity attributes are hashed into a salted Merkle tree, allowing proof of specific claims without revealing the full identity.

### 2. Runtime Tamper Defense
* **Environment validation:** Checks for rooted environments, Magisk/SuperSU binaries, custom ROM test-keys, and emulators.
* **Hard block on compromise:** Terminates the app process (`finishAffinity()`) and blocks UI rendering if a compromised OS is detected, to reduce the window for memory hooking via tools like Frida or Xposed.
* **Rate limiting:** Exponential backoff on biometric failures, with the encrypted vault wiped after 10 consecutive failed attempts.

### 3. Memory Protection (Zeroization)
* **Avoids the JVM string pool:** Secrets are handled as raw `ByteArray` rather than `String`, to avoid lingering copies from garbage collection.
* **Heap wiping across the JNI bridge:** The Rust engine uses the `zeroize` crate to overwrite allocated memory once ZKP generation concludes.

### 4. Hardware-Backed Storage
* **Android StrongBox / Titan M (where available):** Master encryption keys are bound to the device's hardware security module.
* **AES-GCM encryption at rest**, gated behind `BiometricPrompt` (`CryptoObject`).

## System Architecture

Built on a **Kotlin ↔ JNI ↔ Rust** bridge:

1. **Frontend (Kotlin + Jetpack Compose):** Reactive UI state via `StateFlow`, captures biometric prompts.
2. **JNI Bridge (C-bindings):** Transports raw byte arrays between the JVM and native heap; configured with `panic = "unwind"` so a Rust panic doesn't crash the JVM.
3. **Backend Engine (Rust):** HKDF extraction, Merkle tree hashing, and Plonky2 ZK circuit evaluation.

## Threat Model Notes
Security design is informed by the **STRIDE threat model** and aligns with several **OWASP MASVS** categories:
* **MASVS-STORAGE:** Memory wiping, encrypted SharedPreferences.
* **MASVS-CRYPTO:** Domain-separated salts, true entropy generation, and hash-based cryptography (Plonky2/Poseidon) instead of elliptic-curve pairings — this avoids the discrete-log/factoring assumptions that quantum algorithms like Shor's are known to break. This is a promising property for post-quantum resistance, though the implementation has not undergone formal post-quantum certification.
* **MASVS-RESILIENCE:** Root detection, debug-blocking, process self-termination on compromise.

## Getting Started

### Prerequisites
* [Android Studio (Iguana+)](https://developer.android.com/studio)
* [Rust Toolchain (rustup)](https://rustup.rs/)
* Android NDK (installed via Android Studio SDK Manager)

### Build Instructions
1. Clone the repository:
```bash
   git clone https://github.com/Hamid0004/zkp-identity.git
```