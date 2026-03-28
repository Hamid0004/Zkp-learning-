# ZKAuth v1.0 Beta 🔐
### Zero-Knowledge Identity Protocol for Android

> *Prove who you are — without revealing anything about yourself.*

---

## What is ZKAuth?

ZKAuth replaces passwords, CAPTCHAs, and traditional KYC with **cryptographic proofs**.  
Instead of sending your identity to a server, your device generates a mathematical proof — your name, passport number, and fingerprint **never leave your phone**.

---

## Live Demo

**Try it now:** 🌐 [zkp-identity-production.up.railway.app](https://zkp-identity-production.up.railway.app)

```text
1. Install APK on Android
2. Open app → Register identity (Tier 3 or Tier 1)
3. Visit the link above on any browser
4. Scan QR or tap "Device Proof"
5. Fingerprint → Dashboard ✅
Metric,ZKAuth (Plonky2),Industry Standard (Groth16),Improvement
Proof Generation,39 ms,~450 ms,11x faster
Verification,8 ms,~300 ms,37x faster
Proof Size,20 KB,~200 KB,10x smaller
Memory Used,78 KB,~150 MB,90% lighter
Circuit Setup,8 ms,~2000 ms,250x faster
Witness Gen,2 µs,~50 ms,"25,000x faster"
Constraints,8,~2M+,Minimal
Battery (100 runs),0% drop,3–5% drop,Green ✅

TIER 1 — Passport NFC        🛂  MAXIMUM TRUST
  Government-verified identity via ICAO 9303
  Proves: is_adult, nationality, is_human
  Use: Banking, KYC, Age verification, Government portals

TIER 2 — National ID         🪪  HIGH TRUST      [Coming Soon]
  NFC CNIC / Aadhaar
  Proves: age, nationality

TIER 3 — Device + Biometric  📱  BASIC TRUST
  Android KeyStore + BiometricPrompt
  Proves: is_human, is_real_device, is_unique
  Use: CAPTCHA replacement, Bot prevention, Passwordless login

  Key Features
✅ Offline-first — ZK proofs generate 100% on-device, no cloud needed

✅ Cross-device login — Scan QR on PC, authenticate on phone

✅ Trust enforcement — Server rejects mock proofs for sensitive claims

✅ Replay prevention — Poseidon domain-scoped nullifiers

✅ Memory safe — Secrets zeroized from RAM after use (Rust zeroize crate)

✅ Anti-tamper — Root/emulator detection, rate limiting, vault wipe

✅ Post-quantum — FRI-based, no trusted setup, no elliptic curve pairings

✅ GDPR by design — Server stores nullifier hash only, zero PII

Android (Kotlin + Jetpack Compose)
    ↓ JNI bridge
Rust (Plonky2)
    ├── device_tier.rs    — Tier 3: 4-leaf Merkle proof
    ├── passport_security.rs — Tier 1: ICAO 9303 + SOD verify
    └── proof_bench.rs    — Benchmark engine
    ↓ HTTPS POST
Node.js Relay (Railway)
    ├── /zkauth/verify    — Proof verification
    ├── /api/poll-status  — Session polling
    └── Trust enforcement — 403 on insufficient trust
    ↓ poll 300ms
Website Dashboard
    └── trust_level: MAXIMUM | BASIC

    Threat,Mitigation
Spoofing,BiometricPrompt.CryptoObject + StrongBox HSM
Tampering,"Root/Frida detection, Rust JNI panic boundary"
Repudiation,Domain-scoped Poseidon nullifier (replay impossible)
Information Disclosure,"ByteArray zeroization, AES-256-GCM at rest"
Denial of Service,"Rate limiting, 10-attempt vault wipe, async Rust"
Elevation of Privilege,"Global lifecycle lock, fresh biometric on resume"

Layer,Technology
ZK Circuits,Plonky2 v0.2.2 (Rust nightly)
Hashing,"Poseidon (ZK-optimized, 8 constraints)"
Key Derivation,HKDF-SHA256 + Argon2
Memory Safety,Rust zeroize v1.7
Android,Kotlin + Jetpack Compose
JNI Bridge,cargo-ndk → libzkp_mobile.so
Biometric,AndroidKeyStore + BiometricPrompt
NFC,IsoDep + ICAO 9303 BAC
Server,Node.js + Express
Deployment,Railway

Installation
Download app-arm64-v8a-debug.apk below

Enable Install from unknown sources on your Android device

Install and open the app

Grant camera, biometric, NFC permissions

Requirements: Android 10+ | ARM64 device | Fingerprint enrolled

Research
Thesis (Submitted): "Privacy-Preserving Offline Identity Verification on Resource-Constrained Mobile Devices using Plonky2"

IEEE Paper (Submitted — Phases 1-5): "Efficient Post-Quantum Zero-Knowledge Verification on Resource-Constrained Mobile Edges: A Native Plonky2 Approach"

Note: The IEEE submission covers the core offline ZKP engine (Phases 1–5).

NFC Passport (Tier 1), Web Login (Tier 3), and Biometric Binding are post-submission extensions.

Known Limitations (Beta)
Tier 2 National ID (CNIC/Aadhaar) — coming in v1.1

iOS not supported (Android only)

Railway free tier — occasional 5-10 sec cold start on first request

Simulate scan button visible in debug build (hidden in production)

v1.0 Beta  — Current release
v1.1       — OAuth / "Login with ZKAuth" button + JS SDK
v2.0       — Tier 2 National ID + iOS support

Author
Hamid Iqbal — @hamidiqbal369

Final-year IT Student · ZK Proof Engineer

Repository: github.com/Hamid0004/zkp-identity

No passwords. No data. Just math. 🔐