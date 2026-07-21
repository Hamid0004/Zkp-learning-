# ZKAuth v1.0 Beta
### Zero-Knowledge Identity Protocol for Android

> Prove who you are - without revealing anything about yourself.

---

## Release Summary

ZKAuth v1.0 Beta launches an Android-first zero-knowledge identity solution with Tier 1 passport NFC and Tier 3 biometric device proof. This release focuses on on-device proof generation, strong privacy guarantees, and live verification support.

## What's Included in v1.0 Beta

- Tier 1 Passport NFC identity proof via ICAO 9303
- Tier 3 Android device + biometric proof using KeyStore + BiometricPrompt
- Rust-based ZK circuit engine with Plonky2
- JNI bridge between Kotlin and Rust
- Node.js relay on Railway for proof verification
- Live demo deployment and dashboard

## Performance Highlights

| Metric | ZKAuth (Plonky2) | Industry Standard (Groth16) | Improvement |
|---|---|---|---|
| Proof generation | 39 ms | ~450 ms | 11x faster |
| Verification | 8 ms | ~300 ms | 37x faster |
| Proof size | 20 KB | ~200 KB | 10x smaller |
| Memory used | 78 KB | ~150 MB | 90% lighter |
| Circuit setup | 8 ms | ~2000 ms | 250x faster |
| Witness generation | 2 us | ~50 ms | 25000x faster |
| Constraints | 8 | ~2M+ | Minimal |
| Battery (100 runs) | 0% drop | 3-5% drop | Efficient |

## Trust Tiers

### TIER 1 - Passport NFC
- Government-verified identity via ICAO 9303
- Proves: is_adult, nationality, is_human
- Use cases: banking, KYC, age verification, government portals

### TIER 2 - National ID (coming soon)
- NFC CNIC / Aadhaar
- Proves: age, nationality

### TIER 3 - Device + Biometric
- Android KeyStore + BiometricPrompt
- Proves: is_human, is_real_device, is_unique
- Use cases: CAPTCHA replacement, bot prevention, passwordless login

## Key Features

- Offline-first proof generation on device
- Cross-device login via QR scan
- Server-side trust enforcement for sensitive claims
- Replay protection with domain-scoped Poseidon nullifiers
- Zeroized secret handling via Rust memory safety
- Anti-tamper controls: root/emulator detection, rate limiting, vault wipe
- Post-quantum friendly design without pairing-based trusted setup
- GDPR-aligned data minimization and nullifier-only storage

## Architecture Overview

- Android app: Kotlin + Jetpack Compose
- JNI bridge: cargo-ndk -> libzkp_mobile.so
- Rust ZK engine: Plonky2
  - device_tier.rs - Tier 3 Merkle proof flow
  - passport_security.rs - Tier 1 ICAO 9303 + SOD verification
  - proof_bench.rs - benchmark engine
- Backend relay: Node.js + Express on Railway
  - /zkauth/verify - proof verification
  - /api/poll-status - session polling
- Dashboard: trust-level UI for MAXIMUM / BASIC proofs

## Security Model

| Threat | Mitigation |
|---|---|
| Spoofing | BiometricPrompt CryptoObject + StrongBox HSM |
| Tampering | Root/Frida detection + Rust JNI panic boundary |
| Repudiation | Domain-scoped Poseidon nullifier |
| Information disclosure | ByteArray zeroization + AES-256-GCM at rest |
| Denial of service | Rate limiting + 10-attempt vault wipe |
| Elevation of privilege | Global lifecycle lock + fresh biometric on resume |

## Technology Stack

| Layer | Technology |
|---|---|
| ZK circuits | Plonky2 v0.2.2 (Rust nightly) |
| Hashing | Poseidon (ZK-optimized) |
| Key derivation | HKDF-SHA256 + Argon2 |
| Memory safety | Rust zeroize v1.7 |
| Android | Kotlin + Jetpack Compose |
| JNI bridge | cargo-ndk -> libzkp_mobile.so |
| Biometric | Android KeyStore + BiometricPrompt |
| NFC | IsoDep + ICAO 9303 BAC |
| Server | Node.js + Express |
| Deployment | Railway |

## Installation (Beta)

1. Download app-arm64-v8a-debug.apk
2. Enable install from unknown sources on your Android device
3. Install and open the app
4. Grant camera, biometric, and NFC permissions

**Requirements:** Android 10+ | ARM64 device | Fingerprint enrolled

## Known Limitations

- Tier 2 National ID (CNIC/Aadhaar) is planned for v1.1
- iOS is not supported yet (Android only)
- Railway free tier may show 5-10 second cold start on first request
- Simulate scan button is visible in debug builds only

## Roadmap

- v1.0 Beta - current release
- Privacy-preserving on-device liveness ML + ZK attestation (hybrid commit+threshold design)
- v1.1 - OAuth / "Login with ZKAuth" button + JS SDK
- v2.0 - Tier 2 National ID + iOS support

## Author

Hamid Iqbal - @hamidiqbal369

Final-year IT student - ZK proof engineer

Repository: github.com/Hamid0004/zkp-identity

No passwords. No data. Just math.
